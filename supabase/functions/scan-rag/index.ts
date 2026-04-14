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
// Shannon entropy (character frequency distribution)
// ---------------------------------------------------------------------------

function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of text) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  const n = text.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / n;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Typical English text entropy is around 4.0-4.5 bits/char.
// Anomalous: very low (<2.0) or very high (>6.0) is suspicious.
function entropyAnomalyScore(entropy: number): number {
  if (entropy < 2.0) return Math.min(1, (2.0 - entropy) / 2.0);
  if (entropy > 6.0) return Math.min(1, (entropy - 6.0) / 2.0);
  return 0;
}

// ---------------------------------------------------------------------------
// Bigram perplexity
// ---------------------------------------------------------------------------

function computeBigramPerplexity(text: string): number {
  if (text.length < 2) return 0;

  // Build bigram and unigram counts
  const unigram: Record<string, number> = {};
  const bigram: Record<string, number> = {};

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    unigram[ch] = (unigram[ch] ?? 0) + 1;
    if (i + 1 < text.length) {
      const bg = text[i] + text[i + 1];
      bigram[bg] = (bigram[bg] ?? 0) + 1;
    }
  }

  const totalUnigrams = text.length;
  const totalBigrams = text.length - 1;

  // Compute log-probability of each bigram under the model
  let logProbSum = 0;
  let count = 0;

  for (let i = 0; i < text.length - 1; i++) {
    const bg = text[i] + text[i + 1];
    const bgCount = bigram[bg] ?? 0;
    const uniCount = unigram[text[i]] ?? 0;

    // Add-1 (Laplace) smoothing to avoid zero probabilities
    const vocabSize = Object.keys(unigram).length;
    const prob = (bgCount + 1) / (uniCount + vocabSize);
    logProbSum += Math.log2(prob);
    count++;
  }

  if (count === 0) return 0;

  // Perplexity = 2^(-avgLogProb)
  const avgLogProb = logProbSum / count;
  const perplexity = Math.pow(2, -avgLogProb);
  return perplexity;
}

// Normalize perplexity anomaly: typical English ~10-100; adversarial injection
// often has perplexity spikes. Anything above 500 is flagged linearly.
function perplexityAnomalyScore(perplexity: number): number {
  if (perplexity <= 100) return 0;
  if (perplexity >= 600) return 1;
  return (perplexity - 100) / 500;
}

// ---------------------------------------------------------------------------
// Homoglyph detection
// ---------------------------------------------------------------------------

// Maps lookalike Unicode characters → their ASCII equivalent
const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0430": "a", // Cyrillic а → a
  "\u0435": "e", // Cyrillic е → e
  "\u043E": "o", // Cyrillic о → o
  "\u0440": "p", // Cyrillic р → p
  "\u0441": "c", // Cyrillic с → c
  "\u0443": "y", // Cyrillic у → y
  "\u0456": "i", // Cyrillic і → i
  "\u0458": "j", // Cyrillic ј → j
  "\u0455": "s", // Cyrillic ѕ → s
  "\u044C": "b", // Cyrillic Ь → b
  "\u0501": "d", // Cyrillic ԁ → d
  "\u0261": "g", // Latin small letter script g → g
  "\u0410": "A", // Cyrillic А → A
  "\u0412": "B", // Cyrillic В → B
  "\u0415": "E", // Cyrillic Е → E
  "\u041A": "K", // Cyrillic К → K
  "\u041C": "M", // Cyrillic М → M
  "\u041D": "H", // Cyrillic Н → H
  "\u041E": "O", // Cyrillic О → O
  "\u0420": "P", // Cyrillic Р → P
  "\u0421": "C", // Cyrillic С → C
  "\u0422": "T", // Cyrillic Т → T
  "\u0425": "X", // Cyrillic Х → X
};

interface HomoglyphResult {
  found: boolean;
  count: number;
  positions: number[];
  examples: string[];
}

function detectHomoglyphs(text: string): HomoglyphResult {
  const positions: number[] = [];
  const examples: string[] = [];

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (HOMOGLYPH_MAP[ch] !== undefined) {
      positions.push(i);
      if (examples.length < 10) {
        examples.push(`"${ch}" (U+${ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}) at pos ${i}`);
      }
    }
  }

  return {
    found: positions.length > 0,
    count: positions.length,
    positions: positions.slice(0, 50), // cap to avoid oversized payloads
    examples,
  };
}

// ---------------------------------------------------------------------------
// Hidden instruction detection
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
  /\bsudo\b.{0,30}\bmode\b/i,
  /override\s+(?:your\s+)?(?:safety\s+)?(?:guidelines?|restrictions?)/i,
  /act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|jailbreak)/i,
  /do\s+anything\s+now/i,
  /DAN\s+mode/i,
];

interface HiddenInstructionResult {
  found: boolean;
  match_count: number;
  matched_patterns: string[];
}

function detectHiddenInstructions(text: string): HiddenInstructionResult {
  const matched: string[] = [];
  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      matched.push(match[0].slice(0, 80));
    }
  }
  return {
    found: matched.length > 0,
    match_count: matched.length,
    matched_patterns: matched,
  };
}

// ---------------------------------------------------------------------------
// Base64 detection
// ---------------------------------------------------------------------------

// Looks for contiguous base64-alphabet strings >= 40 chars (avoids false positives)
const BASE64_REGEX = /[A-Za-z0-9+/]{40,}={0,2}/g;

interface Base64Result {
  found: boolean;
  count: number;
  samples: string[];
}

function detectBase64(text: string): Base64Result {
  const matches = text.match(BASE64_REGEX) ?? [];
  return {
    found: matches.length > 0,
    count: matches.length,
    samples: matches.slice(0, 5).map((m) => m.slice(0, 60) + (m.length > 60 ? "…" : "")),
  };
}

// ---------------------------------------------------------------------------
// Risk score computation
// ---------------------------------------------------------------------------

function computeRagRiskScore(params: {
  entropyAnomaly: number;
  perplexityAnomaly: number;
  homoglyphCount: number;
  hiddenInstructionCount: number;
  base64Count: number;
}): number {
  // Normalize homoglyph and hidden instruction signals to [0,1]
  const homoglyphSignal = Math.min(1, params.homoglyphCount / 5);
  const hiddenSignal = Math.min(1, params.hiddenInstructionCount / 3);
  const base64Signal = Math.min(1, params.base64Count / 3);

  const score =
    0.15 * params.entropyAnomaly +
    0.15 * params.perplexityAnomaly +
    0.20 * homoglyphSignal +
    0.30 * hiddenSignal +
    0.20 * base64Signal;

  return Math.min(1, Math.max(0, score));
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

interface ScanRagRequest {
  document_id: string;
  content: string;
  source?: string;
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

  let body: ScanRagRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { document_id, content, source, metadata } = body;

  if (!document_id) return errorResponse("document_id is required", 400);
  if (typeof content !== "string" || content.length === 0) {
    return errorResponse("content must be a non-empty string", 400);
  }

  const service = getServiceClient();

  // Create scan record
  const { data: scan, error: scanError } = await service
    .from("scans")
    .insert({
      tenant_id: tenant.tenantId,
      engine: "rag",
      status: "scanning",
      metadata: { document_id, source, content_length: content.length, ...metadata },
    })
    .select()
    .single();

  if (scanError || !scan) {
    console.error("scan insert error:", scanError);
    return errorResponse("Failed to create scan record", 500);
  }

  // Run analysis
  const entropy = shannonEntropy(content);
  const entropyAnomaly = entropyAnomalyScore(entropy);

  const perplexity = computeBigramPerplexity(content);
  const perplexityAnomaly = perplexityAnomalyScore(perplexity);

  const homoglyphs = detectHomoglyphs(content);
  const hiddenInstructions = detectHiddenInstructions(content);
  const base64 = detectBase64(content);

  const riskScore = computeRagRiskScore({
    entropyAnomaly,
    perplexityAnomaly,
    homoglyphCount: homoglyphs.count,
    hiddenInstructionCount: hiddenInstructions.match_count,
    base64Count: base64.count,
  });

  const verdict: "clean" | "suspicious" | "poisoned" =
    riskScore < 0.3 ? "clean" : riskScore < 0.6 ? "suspicious" : "poisoned";

  // Insert into rag_scans
  const { data: ragRecord, error: ragError } = await service
    .from("rag_scans")
    .insert({
      scan_id: scan.id,
      tenant_id: tenant.tenantId,
      document_id,
      source: source ?? null,
      content_length: content.length,
      entropy,
      entropy_anomaly_score: entropyAnomaly,
      perplexity,
      perplexity_anomaly_score: perplexityAnomaly,
      homoglyph_count: homoglyphs.count,
      homoglyph_positions: homoglyphs.positions,
      hidden_instruction_count: hiddenInstructions.match_count,
      hidden_instruction_matches: hiddenInstructions.matched_patterns,
      base64_count: base64.count,
      base64_samples: base64.samples,
      risk_score: riskScore,
      verdict,
      metadata: metadata ?? null,
    })
    .select()
    .single();

  if (ragError) {
    console.error("rag_scans insert error:", ragError);
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
    document_id,
    verdict,
    risk_score: riskScore,
    signals: {
      entropy: { value: entropy, anomaly_score: entropyAnomaly },
      perplexity: { value: perplexity, anomaly_score: perplexityAnomaly },
      homoglyphs,
      hidden_instructions: hiddenInstructions,
      base64,
    },
    rag_scan_id: ragRecord?.id ?? null,
  });
});
