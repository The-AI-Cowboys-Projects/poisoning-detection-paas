import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient, SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2.49.4";

// =============================================================================
// Inlined shared utilities (_shared/ cannot be resolved in edge function runtime)
// =============================================================================

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function getSupabaseClient(req: Request): SupabaseClient {
  const authHeader = req.headers.get("Authorization");
  return createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_ANON_KEY") ?? "",
    { global: { headers: { Authorization: authHeader ?? "" } } }
  );
}

function getServiceClient(): SupabaseClient {
  return createClient(
    Deno.env.get("SUPABASE_URL") ?? "",
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
    { auth: { persistSession: false } }
  );
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function errorResponse(message: string, status = 400): Response {
  return new Response(JSON.stringify({ error: { code: String(status), message } }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

// -----------------------------------------------------------------------------
// Inlined tenant auth (_shared/tenant-auth.ts)
// -----------------------------------------------------------------------------

interface TenantContext {
  tenantId: string;
  tenantName: string;
  tier: string;
  userId: string;
}

async function getTenantContext(supabase: SupabaseClient): Promise<TenantContext | null> {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return null;
  const tenantId = user.user_metadata?.tenant_id;
  if (!tenantId) return null;
  const { data: tenant } = await supabase
    .from("tenants")
    .select("id, name, tier")
    .eq("id", tenantId)
    .eq("is_active", true)
    .single();
  if (!tenant) return null;
  return { tenantId: tenant.id, tenantName: tenant.name, tier: tenant.tier, userId: user.id };
}

// =============================================================================
// Request / response types
// =============================================================================

type TelemetryType = "ml" | "llm" | "infrastructure" | "ground_truth" | "baseline";

interface IngestRequest {
  type: TelemetryType;
  application_id: string;
  records: Array<Record<string, unknown>>;
  auto_scan?: boolean;
  metadata?: Record<string, unknown>;
}

interface IngestResult {
  ingested: number;
  type: TelemetryType;
  application_id: string;
  anomalies_detected: number;
  scan_created: boolean;
  scan_id: string | null;
  alerts_created: number;
}

// =============================================================================
// Field mappers
// =============================================================================

// ML telemetry: map from the synthetic-data-project field names to the
// ml_telemetry table columns defined in migration 00002_telemetry_tables.sql.
function mapMlRecord(
  raw: Record<string, unknown>,
  tenantId: string,
  scanId: string | null
): Record<string, unknown> {
  const confidence = toFloat(raw["confidence_score"]);
  const latency = toFloat(raw["total_latency_ms"]);

  // is_anomalous: confidence below threshold OR latency spiked
  const isAnomalous =
    (confidence !== null && confidence < 0.3) ||
    (latency !== null && latency > 5000);

  // anomaly_score: 0–1 composite. Penalise low confidence and high latency.
  let anomalyScore = 0;
  if (confidence !== null) anomalyScore += Math.max(0, 0.3 - confidence) / 0.3 * 0.6;
  if (latency !== null)    anomalyScore += Math.min(1, latency / 10000) * 0.4;
  anomalyScore = Math.min(1, parseFloat(anomalyScore.toFixed(4)));

  return {
    // Tenant + scan linkage
    tenant_id: tenantId,
    scan_id: scanId,

    // Caller-supplied identity — fall back to auto-generated uuid via DB default
    inference_id: raw["telemetry_id"] ?? undefined,

    application_id: raw["application_id"],
    model_name: raw["model_name"],
    model_version: raw["model_version"] ?? null,

    // Prediction outputs
    prediction_class: raw["prediction_class"] ?? null,
    prediction_score: toFloat(raw["prediction_raw"]) ?? null,
    confidence_score: confidence ?? null,

    // Raw payloads
    raw_input_payload: toJsonb(raw["raw_input_payload"]),
    feature_vector: toFloatArray(raw["feature_vector"]),
    feature_importances: toJsonb(raw["feature_importances"]),

    // Decision
    decision: raw["decision"] ?? null,
    decision_threshold: toFloat(raw["decision_threshold"]) ?? null,

    // Resource utilisation
    cpu_utilization_pct: toFloat(raw["cpu_utilization_pct"]) ?? null,
    gpu_utilization_pct: toFloat(raw["gpu_utilization_pct"]) ?? null,
    memory_used_mb: toFloat(raw["memory_used_mb"]) ?? null,

    // Latency breakdown
    total_latency_ms: latency ?? null,
    queue_wait_ms: toFloat(raw["queue_wait_ms"]) ?? null,
    model_inference_ms: toFloat(raw["model_inference_ms"]) ?? null,

    // Computed anomaly signals
    is_anomalous: isAnomalous,
    anomaly_score: anomalyScore,
  };
}

// LLM telemetry: map from the synthetic-data-project field names to the
// llm_telemetry table columns defined in migration 00002_telemetry_tables.sql.
function mapLlmRecord(
  raw: Record<string, unknown>,
  tenantId: string,
  scanId: string | null
): Record<string, unknown> {
  const hallucinationRisk = toFloat(raw["hallucination_risk"]);
  const toxicityScore     = toFloat(raw["toxicity_score"]);
  const coherence         = toFloat(raw["coherence_score"]);
  const relevance         = toFloat(raw["relevance_score"]);
  const fluency           = toFloat(raw["fluency_score"]);
  const factual           = toFloat(raw["factual_consistency"]);
  const completeness      = toFloat(raw["completeness_score"]);

  // is_anomalous: high hallucination risk or high toxicity
  const isAnomalous =
    (hallucinationRisk !== null && hallucinationRisk > 0.7) ||
    (toxicityScore !== null && toxicityScore > 0.6);

  // poisoning_risk: weighted composite of quality indicators.
  // Higher toxicity / hallucination risk raises the score;
  // higher coherence / factual consistency / completeness lowers it.
  const weights = { hallucination: 0.35, toxicity: 0.25, coherence: 0.15, relevance: 0.10, factual: 0.10, completeness: 0.05 };
  const poisoningRisk = Math.min(1, parseFloat((
    (hallucinationRisk ?? 0)      * weights.hallucination +
    (toxicityScore ?? 0)          * weights.toxicity +
    (1 - (coherence ?? 1))        * weights.coherence +
    (1 - (relevance ?? 1))        * weights.relevance +
    (1 - (factual ?? 1))          * weights.factual +
    (1 - (completeness ?? 1))     * weights.completeness
  ).toFixed(4)));

  // flags: accumulate signal names for anything exceeding safe thresholds
  const flags: string[] = [];
  if (hallucinationRisk !== null && hallucinationRisk > 0.7) flags.push("high_hallucination_risk");
  if (toxicityScore !== null && toxicityScore > 0.6)         flags.push("high_toxicity");
  if (poisoningRisk > 0.5)                                   flags.push("elevated_poisoning_risk");
  if (coherence !== null && coherence < 0.3)                 flags.push("low_coherence");
  if (factual !== null && factual < 0.4)                     flags.push("low_factual_consistency");

  return {
    tenant_id: tenantId,
    scan_id: scanId,

    application_id: raw["application_id"],
    model_name: raw["model_name"],
    model_version: raw["model_version"] ?? null,

    // Prompt content
    system_prompt: raw["system_prompt"] ?? null,
    user_prompt: raw["user_prompt"] ?? "",
    response_text: raw["response_text"] ?? null,

    // Token economics
    input_tokens: toInt(raw["input_tokens"]) ?? null,
    output_tokens: toInt(raw["output_tokens"]) ?? null,
    context_tokens: toInt(raw["context_tokens"]) ?? null,
    tokens_per_second: toFloat(raw["tokens_per_second"]) ?? null,
    estimated_cost_usd: toFloat(raw["estimated_cost_usd"]) ?? null,

    // Quality scores
    coherence_score: coherence ?? null,
    relevance_score: relevance ?? null,
    fluency_score: fluency ?? null,
    toxicity_score: toxicityScore ?? null,
    hallucination_risk: hallucinationRisk ?? null,
    factual_consistency: factual ?? null,
    completeness_score: completeness ?? null,

    // Semantic embeddings
    input_embedding: toFloatArray(raw["input_embedding"]),
    output_embedding: toFloatArray(raw["output_embedding"]),
    semantic_similarity: toFloat(raw["semantic_similarity_score"]) ?? toFloat(raw["semantic_similarity"]) ?? null,

    // Resource utilisation
    gpu_utilization_pct: toFloat(raw["gpu_utilization_pct"]) ?? null,
    gpu_memory_used_gb: toFloat(raw["gpu_memory_used_gb"]) ?? null,

    // Latency
    total_latency_ms: toFloat(raw["total_latency_ms"]) ?? null,
    time_to_first_token_ms: toFloat(raw["time_to_first_token_ms"]) ?? null,

    // Computed anomaly / poisoning signals
    is_anomalous: isAnomalous,
    poisoning_risk: poisoningRisk,
    flags: flags.length > 0 ? flags : null,
  };
}

// Ground truth: map to the ground_truth table
function mapGroundTruthRecord(
  raw: Record<string, unknown>,
  tenantId: string
): Record<string, unknown> {
  return {
    tenant_id: tenantId,
    telemetry_id: raw["telemetry_id"] ?? null,
    telemetry_type: (raw["telemetry_type"] as string) ?? "ml",
    inference_id: raw["inference_id"] ?? null,
    predicted_class: raw["predicted_class"] ?? null,
    predicted_score: toFloat(raw["predicted_score"]) ?? null,
    actual_class: raw["actual_class"] ?? null,
    actual_value: toFloat(raw["actual_value"]) ?? null,
    prediction_correct: raw["prediction_correct"] !== undefined
      ? Boolean(raw["prediction_correct"])
      : null,
    outcome_timestamp: raw["outcome_timestamp"] ?? null,
    label_source: raw["label_source"] ?? null,
    label_confidence: toFloat(raw["label_confidence"]) ?? null,
    metadata: toJsonb(raw["metadata"]),
  };
}

// Drift baselines: each raw record represents one (feature_name, stats) pair.
// The synthetic-data-project format sends per-feature statistics in a flat map.
function mapBaselineRecord(
  raw: Record<string, unknown>,
  tenantId: string,
  applicationId: string
): Record<string, unknown> {
  return {
    tenant_id: tenantId,
    application_id: raw["application_id"] ?? applicationId,
    feature_name: raw["feature_name"] as string,
    mean_value: toFloat(raw["mean"]) ?? null,
    std_dev: toFloat(raw["std"]) ?? null,
    min_value: toFloat(raw["min"]) ?? null,
    max_value: toFloat(raw["max"]) ?? null,
    p25: toFloat(raw["p25"]) ?? null,
    p50: toFloat(raw["p50"]) ?? null,
    p75: toFloat(raw["p75"]) ?? null,
    p95: toFloat(raw["p95"]) ?? null,
    p99: toFloat(raw["p99"]) ?? null,
    distribution_type: (raw["distribution_type"] as string) ?? "normal",
    distribution_params: toJsonb(raw["distribution_params"]),
    psi_warning: toFloat(raw["psi_warning"]) ?? 0.1,
    psi_critical: toFloat(raw["psi_critical"]) ?? 0.2,
    is_active: true,
  };
}

// =============================================================================
// Type-coercion helpers
// =============================================================================

function toFloat(v: unknown): number | null {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return isFinite(n) ? n : null;
}

function toInt(v: unknown): number | null {
  const n = toFloat(v);
  return n !== null ? Math.round(n) : null;
}

function toJsonb(v: unknown): unknown | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "object") return v;
  if (typeof v === "string") {
    try { return JSON.parse(v); } catch { return null; }
  }
  return null;
}

function toFloatArray(v: unknown): number[] | null {
  if (!Array.isArray(v)) return null;
  const result = v.map(toFloat);
  if (result.some((x) => x === null)) return null;
  return result as number[];
}

// =============================================================================
// Auto-scan logic
// =============================================================================

async function runAutoScan(
  service: SupabaseClient,
  tenantId: string,
  type: "ml" | "llm",
  applicationId: string,
  rows: Array<Record<string, unknown>>,
  existingScanId: string | null,
  requestMetadata: Record<string, unknown> | undefined
): Promise<{ scanId: string | null; alertsCreated: number }> {
  let scanId = existingScanId;
  let alertsCreated = 0;

  if (type === "ml") {
    const anomalousCount = rows.filter((r) => r["is_anomalous"] === true).length;
    const anomalyRate = rows.length > 0 ? anomalousCount / rows.length : 0;

    if (anomalyRate > 0.1) {
      const { data: scan } = await service
        .from("scans")
        .insert({
          tenant_id: tenantId,
          engine: "telemetry_simulator",
          status: "complete",
          verdict: "suspicious",
          risk_score: parseFloat(anomalyRate.toFixed(4)),
          findings_count: anomalousCount,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          metadata: {
            trigger: "auto_scan",
            type: "ml",
            application_id: applicationId,
            anomaly_rate: anomalyRate,
            ...(requestMetadata ?? {}),
          },
        })
        .select("id")
        .single();

      if (scan?.id) scanId = scan.id;
    }
  } else {
    const poisoningRisks = rows
      .map((r) => r["poisoning_risk"])
      .filter((v): v is number => typeof v === "number");
    const avgRisk = poisoningRisks.length > 0
      ? poisoningRisks.reduce((a, b) => a + b, 0) / poisoningRisks.length
      : 0;

    if (avgRisk > 0.3) {
      const { data: scan } = await service
        .from("scans")
        .insert({
          tenant_id: tenantId,
          engine: "telemetry_simulator",
          status: "complete",
          verdict: "suspicious",
          risk_score: parseFloat(avgRisk.toFixed(4)),
          findings_count: poisoningRisks.filter((r) => r > 0.3).length,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          metadata: {
            trigger: "auto_scan",
            type: "llm",
            application_id: applicationId,
            avg_poisoning_risk: avgRisk,
            ...(requestMetadata ?? {}),
          },
        })
        .select("id")
        .single();

      if (scan?.id) scanId = scan.id;
    }
  }

  // Create alerts for critical-threshold violations
  const alertRows: Array<Record<string, unknown>> = [];

  for (const row of rows) {
    const hallucinationRisk = typeof row["hallucination_risk"] === "number"
      ? row["hallucination_risk"] as number
      : null;
    const toxicityScore = typeof row["toxicity_score"] === "number"
      ? row["toxicity_score"] as number
      : null;

    if (hallucinationRisk !== null && hallucinationRisk > 0.9) {
      alertRows.push({
        tenant_id: tenantId,
        scan_id: scanId,
        severity: "critical",
        type: "hallucination_risk_critical",
        type_label: "Critical Hallucination Risk",
        message: `LLM inference for application "${applicationId}" has hallucination_risk=${hallucinationRisk.toFixed(3)} (threshold: 0.9).`,
        status: "open",
      });
    }

    if (toxicityScore !== null && toxicityScore > 0.8) {
      alertRows.push({
        tenant_id: tenantId,
        scan_id: scanId,
        severity: "critical",
        type: "toxicity_critical",
        type_label: "Critical Toxicity Score",
        message: `LLM inference for application "${applicationId}" has toxicity_score=${toxicityScore.toFixed(3)} (threshold: 0.8).`,
        status: "open",
      });
    }
  }

  if (alertRows.length > 0) {
    const { error: alertErr } = await service.from("alerts").insert(alertRows);
    if (!alertErr) alertsCreated = alertRows.length;
    else console.error("alerts insert error:", alertErr);
  }

  return { scanId, alertsCreated };
}

// =============================================================================
// Main handler
// =============================================================================

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return errorResponse("Method not allowed", 405);
  }

  // ---- Authentication -------------------------------------------------------
  const supabase = getSupabaseClient(req);
  const tenant = await getTenantContext(supabase);
  if (!tenant) return errorResponse("Unauthorized", 401);

  // ---- Parse body -----------------------------------------------------------
  let body: IngestRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { type, application_id, records, auto_scan = false, metadata } = body;

  // ---- Validate -------------------------------------------------------------
  const VALID_TYPES: TelemetryType[] = ["ml", "llm", "infrastructure", "ground_truth", "baseline"];
  if (!VALID_TYPES.includes(type)) {
    return errorResponse(`Invalid type. Must be one of: ${VALID_TYPES.join(", ")}`, 400);
  }

  if (!application_id || typeof application_id !== "string") {
    return errorResponse("application_id is required and must be a string", 400);
  }

  if (!Array.isArray(records)) {
    return errorResponse("records must be an array", 400);
  }

  if (records.length === 0) {
    return errorResponse("records array must not be empty", 400);
  }

  if (records.length > 100) {
    return errorResponse("Batch size exceeds maximum of 100 records", 400);
  }

  // ---- Insert telemetry data ------------------------------------------------
  const service = getServiceClient();
  const tenantId = tenant.tenantId;

  let ingested = 0;
  let anomaliesDetected = 0;
  let scanId: string | null = null;
  let scanCreated = false;
  let alertsCreated = 0;

  if (type === "ml") {
    const rows = records.map((r) => mapMlRecord(r, tenantId, null));
    const { error } = await service.from("ml_telemetry").insert(rows);
    if (error) {
      console.error("ml_telemetry insert error:", error);
      return errorResponse("Failed to insert ML telemetry records", 500);
    }
    ingested = rows.length;
    anomaliesDetected = rows.filter((r) => r["is_anomalous"] === true).length;

    if (auto_scan) {
      const result = await runAutoScan(
        service, tenantId, "ml", application_id, rows, scanId, metadata
      );
      scanId = result.scanId;
      scanCreated = scanId !== null;
      alertsCreated = result.alertsCreated;
    }
  } else if (type === "llm") {
    const rows = records.map((r) => mapLlmRecord(r, tenantId, null));
    const { error } = await service.from("llm_telemetry").insert(rows);
    if (error) {
      console.error("llm_telemetry insert error:", error);
      return errorResponse("Failed to insert LLM telemetry records", 500);
    }
    ingested = rows.length;
    anomaliesDetected = rows.filter((r) => r["is_anomalous"] === true).length;

    if (auto_scan) {
      const result = await runAutoScan(
        service, tenantId, "llm", application_id, rows, scanId, metadata
      );
      scanId = result.scanId;
      scanCreated = scanId !== null;
      alertsCreated = result.alertsCreated;
    }
  } else if (type === "ground_truth") {
    const rows = records.map((r) => mapGroundTruthRecord(r, tenantId));
    const { error } = await service.from("ground_truth").insert(rows);
    if (error) {
      console.error("ground_truth insert error:", error);
      return errorResponse("Failed to insert ground truth records", 500);
    }
    ingested = rows.length;
  } else if (type === "baseline") {
    // For baseline records, deactivate any existing active baselines first so
    // the unique partial index (tenant, application, feature) WHERE is_active=true
    // doesn't conflict. We do this feature-by-feature.
    const rows = records.map((r) => mapBaselineRecord(r, tenantId, application_id));

    const featureNames = rows
      .map((r) => r["feature_name"])
      .filter((n): n is string => typeof n === "string");

    if (featureNames.length > 0) {
      await service
        .from("drift_baselines")
        .update({ is_active: false })
        .eq("tenant_id", tenantId)
        .eq("application_id", application_id)
        .in("feature_name", featureNames)
        .eq("is_active", true);
    }

    const { error } = await service.from("drift_baselines").insert(rows);
    if (error) {
      console.error("drift_baselines insert error:", error);
      return errorResponse("Failed to insert drift baseline records", 500);
    }
    ingested = rows.length;
  } else {
    // type === "infrastructure" — no dedicated table yet; acknowledged but not persisted
    ingested = records.length;
  }

  // ---- Response -------------------------------------------------------------
  const result: IngestResult = {
    ingested,
    type,
    application_id,
    anomalies_detected: anomaliesDetected,
    scan_created: scanCreated,
    scan_id: scanId,
    alerts_created: alertsCreated,
  };

  return jsonResponse(result, 201);
});
