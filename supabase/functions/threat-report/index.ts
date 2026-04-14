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
// Engine weights for unified risk score
// ---------------------------------------------------------------------------

const ENGINE_WEIGHTS = {
  vector: 0.30,
  rag: 0.25,
  mcp: 0.25,
  provenance: 0.20,
} as const;

// ---------------------------------------------------------------------------
// Severity from unified score
// ---------------------------------------------------------------------------

type Severity = "critical" | "high" | "medium" | "low";

function severityFromScore(score: number): Severity {
  if (score >= 0.8) return "critical";
  if (score >= 0.55) return "high";
  if (score >= 0.3) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Recommendation generator
// ---------------------------------------------------------------------------

interface ThreatEntry {
  engine: string;
  score: number;
  verdict: string;
  scan_id?: string;
  record_id?: string;
  detail?: Record<string, unknown>;
}

function generateRecommendations(threats: ThreatEntry[]): string[] {
  const recs: string[] = [];

  for (const t of threats) {
    if (t.score < 0.3) continue;

    switch (t.engine) {
      case "vector":
        if (t.score >= 0.6) {
          recs.push("Re-embed the flagged dataset from a trusted source and invalidate the poisoned index.");
          recs.push("Enable continuous cosine-similarity monitoring on all vector stores.");
        } else {
          recs.push("Audit flagged vectors for potential drift — consider re-validation against ground truth.");
        }
        break;

      case "rag":
        if (t.score >= 0.6) {
          recs.push("Quarantine documents with homoglyph or hidden-instruction detections before retrieval.");
          recs.push("Enable Shannon entropy gating at ingestion time to block anomalous documents.");
        } else {
          recs.push("Review documents flagged for entropy anomalies and validate their original sources.");
        }
        break;

      case "mcp":
        if (t.score >= 0.5) {
          recs.push("Revoke the flagged MCP tool registration and conduct a full schema audit.");
          recs.push("Enforce description-length limits and invisible-char stripping at tool registration.");
        } else {
          recs.push("Review MCP tool descriptions for unexpected instruction-like language.");
        }
        break;

      case "provenance":
        if (t.score >= 0.6) {
          recs.push("Trace contamination blast radius and suspend downstream consumers of flagged nodes.");
          recs.push("Initiate a full provenance graph audit to identify injection entry points.");
        } else {
          recs.push("Monitor provenance graph for newly flagged contamination paths.");
        }
        break;
    }
  }

  // Dedup
  return Array.from(new Set(recs));
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

interface ThreatReportRequest {
  window_hours?: number;
  include_clean?: boolean;
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

  let body: ThreatReportRequest = {};
  try {
    body = await req.json();
  } catch {
    // Body is optional — default to empty object
  }

  const {
    window_hours = 24,
    include_clean = false,
    metadata,
  } = body;

  const since = new Date(Date.now() - window_hours * 60 * 60 * 1000).toISOString();
  const service = getServiceClient();

  // -------------------------------------------------------------------------
  // Query all engine tables in parallel for recent results
  // -------------------------------------------------------------------------

  const [
    vectorResult,
    ragResult,
    mcpResult,
    provenanceResult,
    scansResult,
  ] = await Promise.all([
    // Latest vector analysis for this tenant in the window
    service
      .from("vector_analyses")
      .select("id, scan_id, composite_risk_score, verdict, flagged_count, dispersion_rate, split_view_detected, created_at")
      .eq("tenant_id", tenant.tenantId)
      .gte("created_at", since)
      .order("composite_risk_score", { ascending: false })
      .limit(50),

    // Latest RAG scans
    service
      .from("rag_scans")
      .select("id, scan_id, risk_score, verdict, homoglyph_count, hidden_instruction_count, entropy, created_at")
      .eq("tenant_id", tenant.tenantId)
      .gte("created_at", since)
      .order("risk_score", { ascending: false })
      .limit(50),

    // Latest MCP audits
    service
      .from("mcp_audits")
      .select("id, scan_id, tool_name, risk_score, verdict, risk_breakdown, created_at")
      .eq("tenant_id", tenant.tenantId)
      .gte("created_at", since)
      .order("risk_score", { ascending: false })
      .limit(50),

    // Contamination flags from provenance nodes
    service
      .from("provenance_nodes")
      .select("id, node_type, label, contamination_type, contamination_severity, created_at")
      .eq("tenant_id", tenant.tenantId)
      .gte("created_at", since)
      .not("contamination_type", "is", null)
      .order("created_at", { ascending: false })
      .limit(50),

    // All scans in window
    service
      .from("scans")
      .select("id, engine, verdict, risk_score, created_at")
      .eq("tenant_id", tenant.tenantId)
      .gte("created_at", since)
      .eq("status", "complete"),
  ]);

  // -------------------------------------------------------------------------
  // Build per-engine threat summaries
  // -------------------------------------------------------------------------

  const vectorRecords = vectorResult.data ?? [];
  const ragRecords = ragResult.data ?? [];
  const mcpRecords = mcpResult.data ?? [];
  const provenanceRecords = provenanceResult.data ?? [];

  // Per-engine average score (non-clean only unless include_clean)
  function avgScore(records: Array<{ risk_score?: number; composite_risk_score?: number; verdict?: string; contamination_severity?: string }>): number {
    const relevant = include_clean
      ? records
      : records.filter((r) => (r.verdict !== "clean" && r.contamination_severity !== undefined) || (r.risk_score ?? r.composite_risk_score ?? 0) >= 0.3);
    if (relevant.length === 0) return 0;
    const sum = relevant.reduce((acc, r) => acc + (r.composite_risk_score ?? r.risk_score ?? 0), 0);
    return sum / relevant.length;
  }

  // Provenance score: map severity to numeric
  function provenanceSeverityScore(records: typeof provenanceRecords): number {
    if (records.length === 0) return 0;
    const severityMap: Record<string, number> = { critical: 0.9, high: 0.7, medium: 0.5, low: 0.2 };
    const sum = records.reduce((acc, r) => acc + (severityMap[r.contamination_severity ?? "low"] ?? 0.2), 0);
    return sum / records.length;
  }

  const vectorScore = avgScore(vectorRecords.map((r) => ({ composite_risk_score: r.composite_risk_score, verdict: r.verdict })));
  const ragScore = avgScore(ragRecords.map((r) => ({ risk_score: r.risk_score, verdict: r.verdict })));
  const mcpScore = avgScore(mcpRecords.map((r) => ({ risk_score: r.risk_score, verdict: r.verdict })));
  const provenanceScore = provenanceSeverityScore(provenanceRecords);

  // Weighted unified score
  const unifiedScore =
    ENGINE_WEIGHTS.vector * vectorScore +
    ENGINE_WEIGHTS.rag * ragScore +
    ENGINE_WEIGHTS.mcp * mcpScore +
    ENGINE_WEIGHTS.provenance * provenanceScore;

  // -------------------------------------------------------------------------
  // Build ranked threat list
  // -------------------------------------------------------------------------

  const threats: ThreatEntry[] = [
    {
      engine: "vector",
      score: vectorScore,
      verdict: vectorScore >= 0.6 ? "poisoned" : vectorScore >= 0.3 ? "suspicious" : "clean",
      detail: {
        record_count: vectorRecords.length,
        flagged_count: vectorRecords.filter((r) => r.verdict !== "clean").length,
        top_risk: vectorRecords[0]?.composite_risk_score ?? 0,
        split_view_detected: vectorRecords.some((r) => r.split_view_detected),
      },
    },
    {
      engine: "rag",
      score: ragScore,
      verdict: ragScore >= 0.6 ? "poisoned" : ragScore >= 0.3 ? "suspicious" : "clean",
      detail: {
        record_count: ragRecords.length,
        flagged_count: ragRecords.filter((r) => r.verdict !== "clean").length,
        homoglyph_total: ragRecords.reduce((s, r) => s + (r.homoglyph_count ?? 0), 0),
        hidden_instruction_total: ragRecords.reduce((s, r) => s + (r.hidden_instruction_count ?? 0), 0),
      },
    },
    {
      engine: "mcp",
      score: mcpScore,
      verdict: mcpScore >= 0.5 ? "malicious" : mcpScore >= 0.2 ? "suspicious" : "clean",
      detail: {
        record_count: mcpRecords.length,
        flagged_count: mcpRecords.filter((r) => r.verdict !== "clean").length,
        tools_audited: new Set(mcpRecords.map((r) => r.tool_name)).size,
      },
    },
    {
      engine: "provenance",
      score: provenanceScore,
      verdict: provenanceScore >= 0.6 ? "contaminated" : provenanceScore >= 0.3 ? "suspicious" : "clean",
      detail: {
        contaminated_nodes: provenanceRecords.length,
        critical_nodes: provenanceRecords.filter((r) => r.contamination_severity === "critical").length,
        high_nodes: provenanceRecords.filter((r) => r.contamination_severity === "high").length,
      },
    },
  ].sort((a, b) => b.score - a.score);

  const severity = severityFromScore(unifiedScore);
  const recommendations = generateRecommendations(threats);

  // -------------------------------------------------------------------------
  // Scan summary
  // -------------------------------------------------------------------------

  const scans = scansResult.data ?? [];
  const scanSummary = {
    total: scans.length,
    clean: scans.filter((s) => s.verdict === "clean").length,
    suspicious: scans.filter((s) => s.verdict === "suspicious").length,
    poisoned: scans.filter((s) => ["poisoned", "malicious", "contaminated"].includes(s.verdict ?? "")).length,
    by_type: scans.reduce((acc: Record<string, number>, s) => {
      acc[s.engine] = (acc[s.engine] ?? 0) + 1;
      return acc;
    }, {}),
  };

  // -------------------------------------------------------------------------
  // Store in threat_reports
  // -------------------------------------------------------------------------

  const reportPayload = {
    tenant_id: tenant.tenantId,
    user_id: tenant.userId,
    window_hours,
    since,
    unified_score: unifiedScore,
    severity,
    engine_scores: {
      vector: vectorScore,
      rag: ragScore,
      mcp: mcpScore,
      provenance: provenanceScore,
    },
    threats,
    scan_summary: scanSummary,
    recommendations,
    metadata: metadata ?? null,
  };

  const { data: reportRecord, error: reportError } = await service
    .from("threat_reports")
    .insert(reportPayload)
    .select()
    .single();

  if (reportError) {
    console.error("threat_reports insert error:", reportError);
  }

  return jsonResponse({
    report_id: reportRecord?.id ?? null,
    tenant_id: tenant.tenantId,
    generated_at: new Date().toISOString(),
    window_hours,
    since,
    unified_score: parseFloat(unifiedScore.toFixed(4)),
    severity,
    engine_scores: {
      vector: parseFloat(vectorScore.toFixed(4)),
      rag: parseFloat(ragScore.toFixed(4)),
      mcp: parseFloat(mcpScore.toFixed(4)),
      provenance: parseFloat(provenanceScore.toFixed(4)),
    },
    threats,
    scan_summary: scanSummary,
    recommendations,
  });
});
