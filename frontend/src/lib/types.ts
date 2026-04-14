// ─── Shared enums ───────────────────────────────────────────────────────────

export type ThreatSeverity = 'critical' | 'warning' | 'safe' | 'info'

export type ThreatType =
  | 'RAG_POISONING'
  | 'MCP_BACKDOOR'
  | 'VECTOR_ANOMALY'
  | 'PROVENANCE_ISSUE'
  | 'HIDDEN_INSTRUCTION'
  | 'SCHEMA_MANIPULATION'

export type ScanStatus = 'pending' | 'scanning' | 'complete' | 'failed'

export type VerdictLabel = 'clean' | 'suspicious' | 'malicious' | 'unknown'

// ─── Dashboard metrics ───────────────────────────────────────────────────────

export interface DashboardMetrics {
  totalScans: number
  totalScansChange: number       // percentage delta vs previous period
  threatsDetected: number
  threatsDetectedChange: number
  activeMonitors: number
  activeMonitorsChange: number
  threatVelocity: number         // threats / hour
  threatVelocityChange: number
}

export interface TimeSeriesPoint {
  timestamp: string              // ISO-8601
  scans: number
  threats: number
}

export interface ThreatBreakdown {
  type: ThreatType
  label: string
  count: number
  percentage: number
  color: string
}

export interface RecentAlert {
  id: string
  severity: ThreatSeverity
  type: ThreatType
  typeLabel: string
  message: string
  timestamp: string
  status: 'open' | 'acknowledged' | 'resolved'
  tenantId: string
}

// ─── Vector analysis ─────────────────────────────────────────────────────────

export interface VectorPoint {
  id: string
  x: number
  y: number                      // 2D UMAP projection
  anomalyScore: number           // 0–1
  clusterId: number
  isAnomaly: boolean
  label?: string
}

export interface VectorAnalysisResult {
  id: string
  documentId: string
  vectorId: string
  anomalyScore: number
  baselineDeviation: number
  clusterId: number
  isAnomaly: boolean
  timestamp: string
  model: string
}

export interface VectorBaselineStatus {
  isEstablished: boolean
  documentCount: number
  lastUpdated: string | null
  meanNorm: number
  stdNorm: number
}

export interface AnomalyScoreHistogramBin {
  rangeStart: number
  rangeEnd: number
  count: number
}

// ─── RAG scanning ─────────────────────────────────────────────────────────────

export interface RAGScanResult {
  id: string
  documentId: string
  source: string
  cosineDeviation: number        // 0–1, higher = more suspicious
  verdict: VerdictLabel
  hasHiddenInstructions: boolean
  hiddenInstructionSnippet?: string
  timestamp: string
  scanDurationMs: number
}

export interface CosineDeviationBin {
  rangeStart: number
  rangeEnd: number
  count: number
}

export interface HiddenInstructionFinding {
  id: string
  documentId: string
  snippet: string
  confidence: number
  detectedAt: string
  patternType: 'prompt_injection' | 'jailbreak' | 'data_exfil' | 'role_override'
}

// ─── MCP tool audit ───────────────────────────────────────────────────────────

export interface ToolAuditResult {
  id: string
  toolName: string
  toolVersion: string
  riskScore: number              // 0–100
  severity: ThreatSeverity
  findings: ToolFinding[]
  schemaHash: string
  auditedAt: string
  passedKnownPatterns: boolean
}

export interface ToolFinding {
  id: string
  patternId: string
  description: string
  severity: ThreatSeverity
  field: string
  evidence: string
}

export interface KnownThreatPattern {
  id: string
  name: string
  description: string
  category: 'backdoor' | 'data_exfil' | 'privilege_escalation' | 'lateral_movement'
  matchCount: number
  firstSeen: string
  lastSeen: string
}

// ─── Provenance tracking ──────────────────────────────────────────────────────

export interface ProvenanceNode {
  id: string
  label: string
  type: 'dataset' | 'model' | 'transform' | 'output'
  contaminated: boolean
  depth: number
  parentIds: string[]
  childIds: string[]
  metadata: Record<string, string>
  registeredAt: string
}

export interface ProvenanceEdge {
  source: string
  target: string
  transformType: string
}

export interface ProvenanceGraph {
  nodes: ProvenanceNode[]
  edges: ProvenanceEdge[]
}

export interface ContaminationStatus {
  isContaminated: boolean
  contaminationScore: number     // 0–1
  affectedNodes: string[]
  tracebackDepth: number
  detectedAt: string | null
}

export interface DatasetRegistration {
  name: string
  source: string
  version: string
  hash: string
  parentIds: string[]
  metadata: Record<string, string>
}

// ─── Telemetry simulator ─────────────────────────────────────────────────────

export type TelemetryEventType =
  | 'prompt_submission'
  | 'tool_call'
  | 'tool_response'
  | 'rag_retrieval'
  | 'model_inference'
  | 'memory_write'
  | 'memory_read'
  | 'agent_decision'

export type AnomalyType =
  | 'prompt_risk_spike'
  | 'tool_denial_surge'
  | 'latency_anomaly'
  | 'distribution_shift'
  | 'memory_corruption'
  | 'retrieval_hijack'
  | 'multi_agent_collusion'
  | 'reward_hacking'

export type AttackScenario =
  | 'clean'
  | 'reward_hacking'
  | 'memory_poisoning'
  | 'prompt_drift'
  | 'retrieval_manipulation'
  | 'tool_hijack'
  | 'multi_agent_collusion'
  | 'slow_burn'

export type TelemetryVerdict = 'clean' | 'suspicious' | 'poisoned'

export interface TelemetrySpan {
  span_id: string
  trace_id: string
  parent_span_id: string | null
  event_type: TelemetryEventType
  agent_id: string
  timestamp: string
  duration_ms: number
  risk_score: number
  is_anomalous: boolean
  anomaly_types: AnomalyType[]
  attributes: Record<string, unknown>
}

export interface TelemetryTrace {
  trace_id: string
  spans: TelemetrySpan[]
  total_duration_ms: number
  root_cause_span_id: string | null
  anomaly_summary: Record<string, unknown>
}

export interface TelemetryAnalysisResult {
  total_traces: number
  total_spans: number
  anomalous_traces: number
  anomaly_breakdown: Record<string, number>
  prompt_risk_distribution: {
    mean: number
    std: number
    p95: number
    p99: number
  }
  tool_denial_rate: number
  avg_latency_ms: number
  latency_p99_ms: number
  distribution_shift_score: number
  root_cause_traces: Array<{
    trace_id: string
    root_cause_span_id: string
    anomaly_types: string[]
    risk_score: number
  }>
  risk_score: number
  verdict: TelemetryVerdict
  execution_timeline: Array<{
    timestamp: string
    agent_id: string
    event_type: string
    duration_ms: number
    risk_score: number
    is_anomalous: boolean
    anomaly_types: string[]
  }>
}

export interface SimulationConfig {
  scenario: AttackScenario
  num_traces: number
  num_agents: number
  avg_spans_per_trace: number
  poison_ratio: number
  noise_level: number
  time_window_hours: number
  seed: number | null
}

export interface SimulationResponse {
  simulation_id: string
  scenario: string
  traces_generated: number
  analysis: TelemetryAnalysisResult
  sample_traces: TelemetryTrace[]
  generated_at: string
}

export interface ScenarioInfo {
  name: string
  description: string
  typical_indicators: string[]
}

// ─── API responses ────────────────────────────────────────────────────────────

export interface ApiResponse<T> {
  data: T
  error: null
  timestamp: string
}

export interface ApiError {
  data: null
  error: {
    code: string
    message: string
    details?: Record<string, unknown>
  }
  timestamp: string
}

export type ApiResult<T> = ApiResponse<T> | ApiError

// ─── Self-Evolution Loop (Gap 1) ─────────────────────────────────────────────

export interface EvolutionRound {
  round: number
  timestamp: string
  attackSamples: number
  detectedCount: number
  missedCount: number
  detectionRate: number          // 0–1
  falsePositiveRate: number      // 0–1
  hardeningApplied: string[]     // list of mutations applied
  convergenceDelta: number       // change vs previous round
}

export interface EvolutionSession {
  id: string
  status: 'running' | 'converged' | 'stopped' | 'failed'
  rounds: EvolutionRound[]
  startedAt: string
  finishedAt: string | null
  finalDetectionRate: number
  convergenceThreshold: number   // default 0.01
  maxRounds: number
}

// ─── Live System Integration (Gap 2) ────────────────────────────────────────

export type ConnectorType = 'vector_store' | 'mcp_server' | 'rag_pipeline'

export type ConnectorStatus = 'connected' | 'disconnected' | 'error' | 'scanning'

export interface LiveConnector {
  id: string
  type: ConnectorType
  name: string
  endpoint: string
  status: ConnectorStatus
  lastChecked: string | null
  lastScanResult: {
    riskScore: number
    findings: number
    verdict: VerdictLabel
  } | null
  config: Record<string, unknown>
}

export interface MCPIntrospection {
  serverId: string
  serverName: string
  tools: Array<{
    name: string
    description: string
    schemaHash: string
    paramCount: number
    riskFlags: string[]
  }>
  lastDiff: {
    added: string[]
    removed: string[]
    modified: string[]
    diffAt: string
  } | null
}

// ─── Cross-Engine Attack Correlation (Gap 3) ─────────────────────────────────

export interface CorrelatedEvent {
  id: string
  engine: string                 // which detection engine
  type: ThreatType
  severity: ThreatSeverity
  timestamp: string
  entityId: string               // document/tool/model ID
  riskScore: number
  details: string
}

export interface AttackCluster {
  id: string
  events: CorrelatedEvent[]
  killChainStage: 'reconnaissance' | 'initial_access' | 'persistence' | 'exfiltration' | 'impact'
  confidence: number             // 0–1
  firstSeen: string
  lastSeen: string
  entityIds: string[]            // unique entities involved
  timeWindowMinutes: number
}

export interface CorrelationResult {
  clusters: AttackCluster[]
  totalEvents: number
  correlatedEvents: number
  uncorrelatedEvents: number
  killChainCoverage: Record<string, number>  // stage → event count
  timeline: CorrelatedEvent[]
}

// ─── Automated Remediation (Gap 4) ──────────────────────────────────────────

export type RemediationAction = 'quarantine' | 'block' | 'disable' | 'pause' | 'alert_only'

export type RemediationMode = 'auto' | 'manual' | 'confirm'

export interface RemediationRule {
  id: string
  engine: string
  severity: ThreatSeverity
  action: RemediationAction
  mode: RemediationMode
  enabled: boolean
  createdAt: string
}

export interface RemediationEvent {
  id: string
  ruleId: string
  alertId: string
  action: RemediationAction
  engine: string
  entityId: string
  status: 'pending' | 'executed' | 'rolled_back' | 'failed'
  executedAt: string
  rolledBackAt: string | null
  details: string
}

export interface RemediationConfig {
  rules: RemediationRule[]
  globalMode: RemediationMode
  auditLog: RemediationEvent[]
}

// ─── Cryptographic Proof + Detection Bounds (Gap 5) ──────────────────────────

export interface ScanProof {
  scanId: string
  timestamp: string
  contentHash: string            // SHA-256 of input
  resultHash: string             // SHA-256 of scan result
  previousProofHash: string | null  // chain link
  chainHash: string              // SHA-256(previousProofHash + resultHash)
  engine: string
  verdict: VerdictLabel
}

export interface ProofChain {
  chainId: string
  proofs: ScanProof[]
  isValid: boolean               // full chain verification result
  length: number
  firstProof: string             // timestamp
  lastProof: string
}

export interface DetectionBound {
  technique: string              // attack technique name
  engineDetectionRates: Record<string, number>  // engine → detection rate 0–1
  combinedDetectionRate: number  // fused rate
  falsePositiveRate: number
  sampleSize: number
  lastUpdated: string
}

export interface CoverageMatrix {
  techniques: string[]
  engines: string[]
  matrix: number[][]             // [technique][engine] = detection rate
  overallCoverage: number        // weighted average
  gaps: Array<{ technique: string; bestRate: number }>  // techniques with <0.5 detection
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

export interface JWTPayload {
  sub: string                    // user id
  tenantId: string
  tenantName: string
  role: 'admin' | 'analyst' | 'viewer'
  iat: number
  exp: number
}
