import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import {
  getSupabaseClient,
  getServiceClient,
  jsonResponse,
  errorResponse,
  corsHeaders,
} from "../_shared/supabase-client.ts";
import { getTenantContext } from "../_shared/tenant-auth.ts";

// ---------------------------------------------------------------------------
// Unicode invisible character detection
// ---------------------------------------------------------------------------

const INVISIBLE_CHARS = [
  "\u200B", // zero-width space
  "\u200C", // zero-width non-joiner
  "\u200D", // zero-width joiner
  "\uFEFF", // zero-width no-break space / BOM
  "\u00AD", // soft hyphen
  "\u2060", // word joiner
  "\u2061", // function application
  "\u2062", // invisible times
  "\u2063", // invisible separator
  "\u2064", // invisible plus
  "\u180E", // Mongolian vowel separator
  "\u00A0", // non-breaking space (can be used to obscure instructions)
];

interface InvisibleCharResult {
  found: boolean;
  count: number;
  types: string[];
}

function detectInvisibleChars(text: string): InvisibleCharResult {
  let count = 0;
  const types: Set<string> = new Set();
  for (const ch of text) {
    if (INVISIBLE_CHARS.includes(ch)) {
      count++;
      types.add(`U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}`);
    }
  }
  return { found: count > 0, count, types: Array.from(types) };
}

// ---------------------------------------------------------------------------
// Hidden instruction patterns (shared with scan-rag)
// ---------------------------------------------------------------------------

const HIDDEN_INSTRUCTION_PATTERNS: RegExp[] = [
  /ignore\s+(?:all\s+)?previous\s+instructions?/i,
  /you\s+are\s+now\s+/i,
  /system\s+prompt/i,
  /\[INST\]/i,
  /<\|[^|]{1,40}\|>/i,
  /disregard\s+(?:all\s+)?(?:previous\s+)?instructions?/i,
  /###\s*human\s*:/i,
  /###\s*assistant\s*:/i,
  /forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?instructions?/i,
  /new\s+instructions?\s*:/i,
  /override\s+(?:your\s+)?(?:safety\s+)?(?:guidelines?|restrictions?)/i,
  /do\s+anything\s+now/i,
  /DAN\s+mode/i,
  /act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbreak)/i,
];

function detectHiddenInstructions(text: string): { found: boolean; match_count: number; matched: string[] } {
  const matched: string[] = [];
  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    const m = text.match(pattern);
    if (m) matched.push(m[0].slice(0, 80));
  }
  return { found: matched.length > 0, match_count: matched.length, matched };
}

// ---------------------------------------------------------------------------
// Base64 pattern detection
// ---------------------------------------------------------------------------

const BASE64_REGEX = /[A-Za-z0-9+/]{40,}={0,2}/g;

function detectBase64(text: string): { found: boolean; count: number } {
  const matches = text.match(BASE64_REGEX) ?? [];
  return { found: matches.length > 0, count: matches.length };
}

// ---------------------------------------------------------------------------
// Schema depth check (recursive nesting)
// ---------------------------------------------------------------------------

const MAX_SCHEMA_DEPTH = 5;

function measureSchemaDepth(obj: unknown, current = 0): number {
  if (current > 20) return current; // guard against circular refs / infinite recursion
  if (obj === null || typeof obj !== "object") return current;
  if (Array.isArray(obj)) {
    return obj.reduce(
      (max: number, item: unknown) => Math.max(max, measureSchemaDepth(item, current + 1)),
      current
    );
  }
  const children = Object.values(obj as Record<string, unknown>);
  if (children.length === 0) return current;
  return children.reduce(
    (max: number, child: unknown) => Math.max(max, measureSchemaDepth(child, current + 1)),
    current
  );
}

// ---------------------------------------------------------------------------
// Parameter count
// ---------------------------------------------------------------------------

function countParameters(parameters: Record<string, unknown>): number {
  const props = (parameters?.properties as Record<string, unknown>) ?? {};
  return Object.keys(props).length;
}

// ---------------------------------------------------------------------------
// Risk scoring
// ---------------------------------------------------------------------------

function computeToolRiskScore(params: {
  descriptionLength: number;
  base64InDesc: number;
  base64InParams: number;
  hiddenInDescCount: number;
  hiddenInParamsCount: number;
  schemaDepth: number;
  paramCount: number;
  invisibleCharCount: number;
}): { score: number; breakdown: Record<string, number> } {
  // Description risk: >2000 chars is suspicious, scale 0-1
  const descSignal = params.descriptionLength > 2000
    ? Math.min(1, (params.descriptionLength - 2000) / 3000)
    : 0;

  // Base64 risk
  const base64Signal = Math.min(1, (params.base64InDesc + params.base64InParams) / 3);

  // Hidden instruction risk
  const hiddenSignal = Math.min(1, (params.hiddenInDescCount + params.hiddenInParamsCount) / 3);

  // Schema risk: depth > 5 or param count > 50
  const depthSignal = params.schemaDepth > MAX_SCHEMA_DEPTH
    ? Math.min(1, (params.schemaDepth - MAX_SCHEMA_DEPTH) / 5)
    : 0;
  const paramSignal = params.paramCount > 50
    ? Math.min(1, (params.paramCount - 50) / 50)
    : 0;
  const schemaSignal = Math.max(depthSignal, paramSignal);

  // Behavioral signal: invisible characters
  const behavioralSignal = Math.min(1, params.invisibleCharCount / 5);

  const score =
    0.30 * descSignal +
    0.25 * base64Signal +
    0.25 * hiddenSignal +
    0.10 * schemaSignal +
    0.10 * behavioralSignal;

  return {
    score: Math.min(1, Math.max(0, score)),
    breakdown: {
      description: descSignal,
      base64: base64Signal,
      hidden_instructions: hiddenSignal,
      schema: schemaSignal,
      behavioral: behavioralSignal,
    },
  };
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

interface AuditToolRequest {
  tool_name: string;
  description: string;
  parameters: Record<string, unknown>;
  tool_version?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  const supabase = getSupabaseClient(req);
  const tenant = await getTenantContext(supabase);
  if (!tenant) return errorResponse("Unauthorized", 401);

  let body: AuditToolRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { tool_name, description, parameters, tool_version, metadata } = body;

  if (!tool_name) return errorResponse("tool_name is required", 400);
  if (typeof description !== "string") return errorResponse("description must be a string", 400);
  if (typeof parameters !== "object" || parameters === null) {
    return errorResponse("parameters must be an object", 400);
  }

  const service = getServiceClient();

  // Create scan record
  const { data: scan, error: scanError } = await service
    .from("scans")
    .insert({
      tenant_id: tenant.tenantId,
      engine: "mcp_tool",
      status: "scanning",
      metadata: { tool_name, tool_version, ...metadata },
    })
    .select()
    .single();

  if (scanError || !scan) {
    console.error("scan insert error:", scanError);
    return errorResponse("Failed to create scan record", 500);
  }

  // Serialize parameters to string for text-based checks
  const paramsText = JSON.stringify(parameters);
  const allParamDescriptions = extractParamDescriptions(parameters);

  // Run checks
  const descLength = description.length;

  const base64InDesc = detectBase64(description);
  const base64InParams = detectBase64(paramsText);

  const hiddenInDesc = detectHiddenInstructions(description);
  const hiddenInParams = detectHiddenInstructions(allParamDescriptions);

  const schemaDepth = measureSchemaDepth(parameters);
  const paramCount = countParameters(parameters);

  const invisibleInDesc = detectInvisibleChars(description);
  const invisibleInParams = detectInvisibleChars(paramsText);
  const totalInvisible = invisibleInDesc.count + invisibleInParams.count;
  const invisibleTypes = Array.from(
    new Set([...invisibleInDesc.types, ...invisibleInParams.types])
  );

  const { score: riskScore, breakdown } = computeToolRiskScore({
    descriptionLength: descLength,
    base64InDesc: base64InDesc.count,
    base64InParams: base64InParams.count,
    hiddenInDescCount: hiddenInDesc.match_count,
    hiddenInParamsCount: hiddenInParams.match_count,
    schemaDepth,
    paramCount,
    invisibleCharCount: totalInvisible,
  });

  const verdict: "clean" | "suspicious" | "malicious" =
    riskScore < 0.2 ? "clean" : riskScore < 0.5 ? "suspicious" : "malicious";

  // Insert into mcp_audits
  const { data: auditRecord, error: auditError } = await service
    .from("mcp_audits")
    .insert({
      scan_id: scan.id,
      tenant_id: tenant.tenantId,
      tool_name,
      tool_version: tool_version ?? null,
      description_length: descLength,
      base64_in_description: base64InDesc.count,
      base64_in_parameters: base64InParams.count,
      hidden_instruction_in_description: hiddenInDesc.match_count,
      hidden_instruction_in_parameters: hiddenInParams.match_count,
      hidden_instruction_matches: [
        ...hiddenInDesc.matched,
        ...hiddenInParams.matched,
      ],
      schema_depth: schemaDepth,
      parameter_count: paramCount,
      invisible_char_count: totalInvisible,
      invisible_char_types: invisibleTypes,
      risk_score: riskScore,
      risk_breakdown: breakdown,
      verdict,
      metadata: metadata ?? null,
    })
    .select()
    .single();

  if (auditError) {
    console.error("mcp_audits insert error:", auditError);
  }

  // Update scan
  await service
    .from("scans")
    .update({
      status: "complete",
      verdict,
      risk_score: riskScore,
      completed_at: new Date().toISOString(),
    })
    .eq("id", scan.id);

  return jsonResponse({
    scan_id: scan.id,
    tool_name,
    verdict,
    risk_score: riskScore,
    risk_breakdown: breakdown,
    checks: {
      description_length: { value: descLength, flagged: descLength > 2000 },
      base64: {
        in_description: base64InDesc,
        in_parameters: base64InParams,
      },
      hidden_instructions: {
        in_description: hiddenInDesc,
        in_parameters: hiddenInParams,
      },
      schema: {
        depth: schemaDepth,
        depth_flagged: schemaDepth > MAX_SCHEMA_DEPTH,
        parameter_count: paramCount,
        param_count_flagged: paramCount > 50,
      },
      invisible_characters: {
        count: totalInvisible,
        types: invisibleTypes,
        found: totalInvisible > 0,
      },
    },
    audit_id: auditRecord?.id ?? null,
  });
});

// ---------------------------------------------------------------------------
// Helper: extract all string description values from parameter schemas
// ---------------------------------------------------------------------------

function extractParamDescriptions(obj: unknown): string {
  if (typeof obj === "string") return obj;
  if (obj === null || typeof obj !== "object") return "";
  if (Array.isArray(obj)) return obj.map(extractParamDescriptions).join(" ");
  return Object.values(obj as Record<string, unknown>)
    .map(extractParamDescriptions)
    .join(" ");
}
