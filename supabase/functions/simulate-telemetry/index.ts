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
// Seeded LCG PRNG
// ---------------------------------------------------------------------------

class SeededRandom {
  private state: number;

  constructor(seed: number) {
    this.state = seed >>> 0; // ensure unsigned 32-bit
  }

  next(): number {
    this.state = (this.state * 1664525 + 1013904223) & 0xFFFFFFFF;
    return (this.state >>> 0) / 0xFFFFFFFF;
  }

  // Box-Muller transform for roughly normal values
  nextNormal(mean: number, std: number): number {
    const u1 = Math.max(1e-10, this.next());
    const u2 = this.next();
    const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
    return mean + std * z;
  }

  nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  nextChoice<T>(arr: T[]): T {
    return arr[Math.floor(this.next() * arr.length)];
  }
}

// ---------------------------------------------------------------------------
// Span types
// ---------------------------------------------------------------------------

type SpanType =
  | "prompt_submission"
  | "tool_call"
  | "rag_retrieval"
  | "model_inference"
  | "memory_write"
  | "agent_decision";

const ALL_SPAN_TYPES: SpanType[] = [
  "prompt_submission",
  "tool_call",
  "rag_retrieval",
  "model_inference",
  "memory_write",
  "agent_decision",
];

const SPAN_BASELINE_LATENCY: Record<SpanType, { mean: number; std: number }> = {
  prompt_submission: { mean: 50, std: 10 },
  tool_call: { mean: 200, std: 40 },
  rag_retrieval: { mean: 120, std: 30 },
  model_inference: { mean: 800, std: 150 },
  memory_write: { mean: 60, std: 15 },
  agent_decision: { mean: 300, std: 60 },
};

// ---------------------------------------------------------------------------
// Attack scenario types
// ---------------------------------------------------------------------------

type AttackScenario =
  | "clean"
  | "prompt_injection"
  | "rag_poisoning"
  | "tool_hijacking"
  | "memory_corruption"
  | "agent_impersonation"
  | "data_exfiltration";

// ---------------------------------------------------------------------------
// Trace and span interfaces
// ---------------------------------------------------------------------------

interface Span {
  span_id: string;
  span_type: SpanType;
  latency_ms: number;
  risk_score: number;
  anomalous: boolean;
  flags: string[];
  metadata: Record<string, unknown>;
}

interface Trace {
  trace_id: string;
  agent_id: string;
  scenario: string;
  poisoned: boolean;
  overall_risk: number;
  spans: Span[];
  span_count: number;
}

// ---------------------------------------------------------------------------
// Span generators
// ---------------------------------------------------------------------------

function makeSpanId(rng: SeededRandom): string {
  return Array.from({ length: 8 }, () =>
    rng.nextInt(0, 15).toString(16)
  ).join("");
}

function makeTraceId(rng: SeededRandom): string {
  return Array.from({ length: 16 }, () =>
    rng.nextInt(0, 15).toString(16)
  ).join("");
}

function generateCleanSpan(rng: SeededRandom, spanType: SpanType): Span {
  const baseline = SPAN_BASELINE_LATENCY[spanType];
  const latency = Math.max(1, rng.nextNormal(baseline.mean, baseline.std));
  const riskScore = Math.max(0, Math.min(1, rng.nextNormal(0.05, 0.03)));

  return {
    span_id: makeSpanId(rng),
    span_type: spanType,
    latency_ms: Math.round(latency),
    risk_score: parseFloat(riskScore.toFixed(4)),
    anomalous: false,
    flags: [],
    metadata: {},
  };
}

function injectAttackAnomalies(
  span: Span,
  scenario: AttackScenario,
  rng: SeededRandom,
  poisonRatio: number
): Span {
  // Roll whether this span is targeted
  if (rng.next() > poisonRatio) return span;

  const flags: string[] = [];
  let riskDelta = 0;
  let latencyMultiplier = 1;
  const metadata: Record<string, unknown> = { ...span.metadata };

  switch (scenario) {
    case "prompt_injection":
      if (span.span_type === "prompt_submission" || span.span_type === "model_inference") {
        flags.push("hidden_instruction_detected", "jailbreak_attempt");
        riskDelta = rng.nextNormal(0.55, 0.1);
        metadata.injection_pattern = rng.nextChoice([
          "ignore_previous_instructions",
          "dan_mode",
          "role_override",
        ]);
      }
      break;

    case "rag_poisoning":
      if (span.span_type === "rag_retrieval") {
        flags.push("poisoned_document_retrieved", "homoglyph_detected");
        riskDelta = rng.nextNormal(0.6, 0.1);
        latencyMultiplier = rng.nextNormal(1.3, 0.1);
        metadata.poisoned_source = `doc_${rng.nextInt(1000, 9999)}`;
      }
      break;

    case "tool_hijacking":
      if (span.span_type === "tool_call") {
        flags.push("unauthorized_tool_invocation", "parameter_tampering");
        riskDelta = rng.nextNormal(0.7, 0.1);
        latencyMultiplier = rng.nextNormal(2.5, 0.3);
        metadata.hijacked_tool = rng.nextChoice(["file_read", "shell_exec", "network_request"]);
      }
      break;

    case "memory_corruption":
      if (span.span_type === "memory_write") {
        flags.push("memory_integrity_violation", "checksum_mismatch");
        riskDelta = rng.nextNormal(0.65, 0.1);
        metadata.corrupted_keys = rng.nextInt(1, 8);
      }
      break;

    case "agent_impersonation":
      if (span.span_type === "agent_decision") {
        flags.push("identity_spoofing", "unexpected_agent_behavior");
        riskDelta = rng.nextNormal(0.75, 0.1);
        latencyMultiplier = rng.nextNormal(0.3, 0.05); // suspiciously fast
        metadata.claimed_agent = `agent_${rng.nextInt(1, 50)}`;
        metadata.actual_agent = `agent_${rng.nextInt(51, 100)}`;
      }
      break;

    case "data_exfiltration":
      if (span.span_type === "tool_call" || span.span_type === "model_inference") {
        flags.push("data_exfiltration_attempt", "base64_payload_detected");
        riskDelta = rng.nextNormal(0.8, 0.08);
        latencyMultiplier = rng.nextNormal(1.8, 0.2);
        metadata.exfil_bytes = rng.nextInt(1024, 65536);
      }
      break;

    default:
      break;
  }

  const newRisk = Math.min(1, Math.max(0, span.risk_score + riskDelta));
  const newLatency = Math.max(1, Math.round(span.latency_ms * latencyMultiplier));
  const isAnomalous = flags.length > 0;

  return {
    ...span,
    latency_ms: newLatency,
    risk_score: parseFloat(newRisk.toFixed(4)),
    anomalous: isAnomalous,
    flags: [...span.flags, ...flags],
    metadata,
  };
}

// ---------------------------------------------------------------------------
// Trace generator
// ---------------------------------------------------------------------------

function generateTrace(
  rng: SeededRandom,
  agentId: string,
  scenario: AttackScenario,
  poisonRatio: number,
  isPoisoned: boolean
): Trace {
  const traceId = makeTraceId(rng);
  const spanCount = rng.nextInt(3, 8);
  const spanTypes = Array.from({ length: spanCount }, () => rng.nextChoice(ALL_SPAN_TYPES));

  const spans = spanTypes.map((spanType) => {
    let span = generateCleanSpan(rng, spanType);
    if (isPoisoned && scenario !== "clean") {
      span = injectAttackAnomalies(span, scenario, rng, poisonRatio);
    }
    return span;
  });

  const overallRisk = spans.reduce((sum, s) => sum + s.risk_score, 0) / spans.length;

  return {
    trace_id: traceId,
    agent_id: agentId,
    scenario,
    poisoned: isPoisoned,
    overall_risk: parseFloat(overallRisk.toFixed(4)),
    spans,
    span_count: spans.length,
  };
}

// ---------------------------------------------------------------------------
// Statistical helpers
// ---------------------------------------------------------------------------

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, Math.min(sorted.length - 1, idx))];
}

function arrMean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function arrStd(arr: number[], mu: number): number {
  if (arr.length < 2) return 0;
  return Math.sqrt(arr.reduce((a, x) => a + Math.pow(x - mu, 2), 0) / arr.length);
}

// ---------------------------------------------------------------------------
// Request body
// ---------------------------------------------------------------------------

interface SimulateTelemetryRequest {
  scenario: AttackScenario;
  num_traces?: number;
  num_agents?: number;
  poison_ratio?: number;
  seed?: number;
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

  let body: SimulateTelemetryRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const {
    scenario,
    num_traces = 50,
    num_agents = 5,
    poison_ratio = 0.3,
    seed = Date.now(),
    metadata,
  } = body;

  const VALID_SCENARIOS: AttackScenario[] = [
    "clean",
    "prompt_injection",
    "rag_poisoning",
    "tool_hijacking",
    "memory_corruption",
    "agent_impersonation",
    "data_exfiltration",
  ];

  if (!VALID_SCENARIOS.includes(scenario)) {
    return errorResponse(
      `Invalid scenario. Must be one of: ${VALID_SCENARIOS.join(", ")}`,
      400
    );
  }

  if (num_traces < 1 || num_traces > 500) {
    return errorResponse("num_traces must be between 1 and 500", 400);
  }

  const service = getServiceClient();

  // Create scan record
  const { data: scan, error: scanError } = await service
    .from("scans")
    .insert({
      tenant_id: tenant.tenantId,
      engine: "telemetry",
      status: "scanning",
      metadata: { scenario, num_traces, num_agents, poison_ratio, seed, ...metadata },
    })
    .select()
    .single();

  if (scanError || !scan) {
    console.error("scan insert error:", scanError);
    return errorResponse("Failed to create scan record", 500);
  }

  // Build agent pool
  const rng = new SeededRandom(seed);
  const agentIds = Array.from(
    { length: num_agents },
    (_, i) => `agent_${String(i + 1).padStart(3, "0")}`
  );

  // Generate traces
  const traces: Trace[] = [];
  for (let i = 0; i < num_traces; i++) {
    const agentId = rng.nextChoice(agentIds);
    const isPoisoned = scenario !== "clean" && rng.next() < poison_ratio;
    const trace = generateTrace(rng, agentId, scenario, poison_ratio, isPoisoned);
    traces.push(trace);
  }

  // Analyze results
  const allSpans = traces.flatMap((t) => t.spans);
  const anomalousSpans = allSpans.filter((s) => s.anomalous);
  const anomalousRate = allSpans.length > 0 ? anomalousSpans.length / allSpans.length : 0;

  const riskScores = allSpans.map((s) => s.risk_score).sort((a, b) => a - b);
  const riskMean = arrMean(riskScores);
  const riskStd = arrStd(riskScores, riskMean);
  const riskP95 = percentile(riskScores, 95);
  const riskP99 = percentile(riskScores, 99);

  // Tool call denial rate (tool_call spans with risk > 0.5)
  const toolCallSpans = allSpans.filter((s) => s.span_type === "tool_call");
  const deniedToolCalls = toolCallSpans.filter((s) => s.risk_score > 0.5);
  const toolDenialRate =
    toolCallSpans.length > 0 ? deniedToolCalls.length / toolCallSpans.length : 0;

  // Latency stats
  const latencies = allSpans.map((s) => s.latency_ms).sort((a, b) => a - b);
  const latencyMean = arrMean(latencies);
  const latencyP95 = percentile(latencies, 95);
  const latencyP99 = percentile(latencies, 99);

  // Verdict
  const verdict: "clean" | "suspicious" | "poisoned" =
    anomalousRate < 0.05 ? "clean" : anomalousRate < 0.15 ? "suspicious" : "poisoned";

  // Flag aggregation
  const allFlags: Record<string, number> = {};
  for (const span of anomalousSpans) {
    for (const flag of span.flags) {
      allFlags[flag] = (allFlags[flag] ?? 0) + 1;
    }
  }

  const analysis = {
    total_traces: traces.length,
    total_spans: allSpans.length,
    anomalous_spans: anomalousSpans.length,
    anomalous_rate: parseFloat(anomalousRate.toFixed(4)),
    risk_distribution: {
      mean: parseFloat(riskMean.toFixed(4)),
      std: parseFloat(riskStd.toFixed(4)),
      p95: parseFloat(riskP95.toFixed(4)),
      p99: parseFloat(riskP99.toFixed(4)),
    },
    tool_denial_rate: parseFloat(toolDenialRate.toFixed(4)),
    latency_stats_ms: {
      mean: parseFloat(latencyMean.toFixed(1)),
      p95: latencyP95,
      p99: latencyP99,
    },
    top_flags: Object.entries(allFlags)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([flag, count]) => ({ flag, count })),
    verdict,
  };

  // Store in telemetry_simulations
  const { data: simRecord, error: simError } = await service
    .from("telemetry_simulations")
    .insert({
      scan_id: scan.id,
      tenant_id: tenant.tenantId,
      scenario,
      num_traces,
      num_agents,
      poison_ratio,
      seed,
      total_spans: allSpans.length,
      anomalous_rate: anomalousRate,
      risk_mean: riskMean,
      risk_p95: riskP95,
      risk_p99: riskP99,
      tool_denial_rate: toolDenialRate,
      latency_mean_ms: latencyMean,
      latency_p95_ms: latencyP95,
      latency_p99_ms: latencyP99,
      top_flags: analysis.top_flags,
      verdict,
      metadata: metadata ?? null,
    })
    .select()
    .single();

  if (simError) {
    console.error("telemetry_simulations insert error:", simError);
  }

  // Update scan
  await service
    .from("scans")
    .update({
      status: "complete",
      verdict,
      risk_score: riskMean,
      completed_at: new Date().toISOString(),
    })
    .eq("id", scan.id);

  return jsonResponse({
    scan_id: scan.id,
    scenario,
    verdict,
    analysis,
    sample_traces: traces.slice(0, 5),
    simulation_id: simRecord?.id ?? null,
  });
});
