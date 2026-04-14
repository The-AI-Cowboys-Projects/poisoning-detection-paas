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
// Math utilities
// ---------------------------------------------------------------------------

function dotProduct(a: number[], b: number[]): number {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += a[i] * b[i];
  return sum;
}

function magnitude(v: number[]): number {
  return Math.sqrt(v.reduce((acc, x) => acc + x * x, 0));
}

function cosineSimilarity(a: number[], b: number[]): number {
  const magA = magnitude(a);
  const magB = magnitude(b);
  if (magA === 0 || magB === 0) return 0;
  return dotProduct(a, b) / (magA * magB);
}

function computeCentroid(vectors: number[][]): number[] {
  if (vectors.length === 0) return [];
  const dim = vectors[0].length;
  const centroid = new Array(dim).fill(0);
  for (const v of vectors) {
    for (let i = 0; i < dim; i++) centroid[i] += v[i];
  }
  for (let i = 0; i < dim; i++) centroid[i] /= vectors.length;
  return centroid;
}

function mean(arr: number[]): number {
  if (arr.length === 0) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdDev(arr: number[], mu: number): number {
  if (arr.length < 2) return 0;
  const variance = arr.reduce((acc, x) => acc + Math.pow(x - mu, 2), 0) / arr.length;
  return Math.sqrt(variance);
}

function zScore(value: number, mu: number, sigma: number): number {
  if (sigma === 0) return 0;
  return Math.abs((value - mu) / sigma);
}

// ---------------------------------------------------------------------------
// Request body interface
// ---------------------------------------------------------------------------

interface ScanVectorsRequest {
  dataset_id: string;
  vectors: number[][];
  baseline_vectors?: number[][];
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Analysis logic
// ---------------------------------------------------------------------------

interface VectorAnalysisResult {
  total_vectors: number;
  centroid_dim: number;
  similarities: number[];
  flagged_indices: number[];
  flagged_count: number;
  dispersion_rate: number;
  z_outlier_indices: number[];
  z_outlier_rate: number;
  max_deviation: number;
  split_view_detected: boolean;
  composite_risk_score: number;
  verdict: "clean" | "suspicious" | "poisoned";
  per_vector_scores: Array<{ index: number; similarity: number; z_score: number; flagged: boolean }>;
}

function analyzeVectors(vectors: number[][], _baseline?: number[][]): VectorAnalysisResult {
  const total = vectors.length;
  const centroid = computeCentroid(vectors);

  // Cosine similarity of each vector vs centroid
  const similarities = vectors.map((v) => cosineSimilarity(v, centroid));

  // Flag vectors below the 0.85 threshold
  const COSINE_THRESHOLD = 0.85;
  const flaggedIndices = similarities
    .map((s, i) => (s < COSINE_THRESHOLD ? i : -1))
    .filter((i) => i !== -1);
  const flaggedCount = flaggedIndices.length;
  const dispersionRate = total > 0 ? flaggedCount / total : 0;

  // Z-score outlier detection (flag those > 3 sigma away)
  const simMean = mean(similarities);
  const simStd = stdDev(similarities, simMean);
  const zScores = similarities.map((s) => zScore(s, simMean, simStd));
  const Z_THRESHOLD = 3.0;
  const zOutlierIndices = zScores
    .map((z, i) => (z > Z_THRESHOLD ? i : -1))
    .filter((i) => i !== -1);
  const zOutlierRate = total > 0 ? zOutlierIndices.length / total : 0;

  // Max deviation from centroid (1 - max_similarity gives worst offender)
  const minSimilarity = Math.min(...similarities);
  const maxDeviation = 1 - minSimilarity;

  // Split-view check: look for two clear clusters among flagged vectors
  // A simple heuristic: if flagged vectors have a bimodal similarity distribution
  // (i.e. two groups separated by more than 0.15 in similarity space)
  let splitViewDetected = false;
  if (flaggedIndices.length >= 4) {
    const flaggedSims = flaggedIndices.map((i) => similarities[i]).sort((a, b) => a - b);
    const half = Math.floor(flaggedSims.length / 2);
    const lowerGroupMax = flaggedSims[half - 1];
    const upperGroupMin = flaggedSims[half];
    splitViewDetected = upperGroupMin - lowerGroupMax > 0.15;
  }

  // Composite risk score
  const compositeRisk =
    0.4 * maxDeviation +
    0.3 * dispersionRate +
    0.2 * zOutlierRate +
    0.1 * (splitViewDetected ? 1 : 0);

  const clampedRisk = Math.min(1, Math.max(0, compositeRisk));

  const verdict: "clean" | "suspicious" | "poisoned" =
    clampedRisk < 0.3 ? "clean" : clampedRisk < 0.6 ? "suspicious" : "poisoned";

  // Per-vector detail
  const perVectorScores = vectors.map((_, i) => ({
    index: i,
    similarity: similarities[i],
    z_score: zScores[i],
    flagged: flaggedIndices.includes(i) || zOutlierIndices.includes(i),
  }));

  return {
    total_vectors: total,
    centroid_dim: centroid.length,
    similarities,
    flagged_indices: flaggedIndices,
    flagged_count: flaggedCount,
    dispersion_rate: dispersionRate,
    z_outlier_indices: zOutlierIndices,
    z_outlier_rate: zOutlierRate,
    max_deviation: maxDeviation,
    split_view_detected: splitViewDetected,
    composite_risk_score: clampedRisk,
    verdict,
    per_vector_scores: perVectorScores,
  };
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

  // Auth
  const supabase = getSupabaseClient(req);
  const tenant = await getTenantContext(supabase);
  if (!tenant) return errorResponse("Unauthorized", 401);

  // Parse body
  let body: ScanVectorsRequest;
  try {
    body = await req.json();
  } catch {
    return errorResponse("Invalid JSON body", 400);
  }

  const { dataset_id, vectors, baseline_vectors, metadata } = body;

  if (!dataset_id) return errorResponse("dataset_id is required", 400);
  if (!Array.isArray(vectors) || vectors.length === 0) {
    return errorResponse("vectors must be a non-empty array", 400);
  }

  // Validate all vectors have same dimension
  const dim = vectors[0].length;
  for (let i = 1; i < vectors.length; i++) {
    if (vectors[i].length !== dim) {
      return errorResponse(`Vector at index ${i} has dimension ${vectors[i].length}, expected ${dim}`, 400);
    }
  }

  const service = getServiceClient();

  // Create scan record
  const { data: scan, error: scanError } = await service
    .from("scans")
    .insert({
      tenant_id: tenant.tenantId,
      engine: "vector",
      status: "scanning",
      metadata: { dataset_id, vector_count: vectors.length, dim, ...metadata },
    })
    .select()
    .single();

  if (scanError || !scan) {
    console.error("scan insert error:", scanError);
    return errorResponse("Failed to create scan record", 500);
  }

  // Run analysis
  const analysis = analyzeVectors(vectors, baseline_vectors);

  // Insert into vector_analyses
  const { data: analysisRecord, error: analysisError } = await service
    .from("vector_analyses")
    .insert({
      scan_id: scan.id,
      tenant_id: tenant.tenantId,
      dataset_id,
      total_vectors: analysis.total_vectors,
      centroid_dim: analysis.centroid_dim,
      flagged_count: analysis.flagged_count,
      dispersion_rate: analysis.dispersion_rate,
      z_outlier_rate: analysis.z_outlier_rate,
      max_deviation: analysis.max_deviation,
      split_view_detected: analysis.split_view_detected,
      composite_risk_score: analysis.composite_risk_score,
      verdict: analysis.verdict,
      flagged_indices: analysis.flagged_indices,
      z_outlier_indices: analysis.z_outlier_indices,
      per_vector_scores: analysis.per_vector_scores,
      metadata: metadata ?? null,
    })
    .select()
    .single();

  if (analysisError) {
    console.error("vector_analyses insert error:", analysisError);
  }

  // Update scan to complete
  await service
    .from("scans")
    .update({
      status: "complete",
      verdict: analysis.verdict,
      risk_score: analysis.composite_risk_score,
      completed_at: new Date().toISOString(),
    })
    .eq("id", scan.id);

  return jsonResponse({
    scan_id: scan.id,
    dataset_id,
    verdict: analysis.verdict,
    risk_score: analysis.composite_risk_score,
    summary: {
      total_vectors: analysis.total_vectors,
      flagged_count: analysis.flagged_count,
      dispersion_rate: analysis.dispersion_rate,
      z_outlier_rate: analysis.z_outlier_rate,
      max_deviation: analysis.max_deviation,
      split_view_detected: analysis.split_view_detected,
    },
    per_vector_scores: analysis.per_vector_scores,
    analysis_id: analysisRecord?.id ?? null,
  });
});
