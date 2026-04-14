/**
 * SimulationPanel — client component for configuring and running synthetic
 * telemetry simulations, then displaying multi-chart results.
 *
 * Usage (called by telemetry/page.tsx):
 *   <SimulationPanel scenarios={[{ id: 'clean', name: 'Clean Baseline' }, ...]} />
 */

'use client'

import { useState, useId, useCallback } from 'react'
import {
  BarChart,
  Bar,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  Legend,
} from 'recharts'
import {
  Play,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  ShieldAlert,
  BarChart2,
  Clock,
  FlaskConical,
  RefreshCw,
} from 'lucide-react'
import { runSimulation } from '@/lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ScenarioOption {
  id: string
  name: string
}

interface SimulationConfig {
  scenario: string
  num_traces: number
  num_agents: number
  poison_ratio: number   // 0-100 (percent)
  noise_level: number    // 0-100 (percent)
  time_window_hours: number
  seed: number | ''
}

type AnomalyType =
  | 'reward_hacking'
  | 'memory_poisoning'
  | 'prompt_drift'
  | 'retrieval_manipulation'
  | 'tool_hijack'
  | 'multi_agent_collusion'
  | 'slow_burn'

interface TraceRecord {
  trace_id: string
  agent_id: string
  timestamp: string          // ISO-8601
  risk_score: number         // 0–1
  is_anomalous: boolean
  anomaly_types: AnomalyType[]
  root_cause_span_id: string | null
  duration_ms: number
}

interface AnomalyBreakdownEntry {
  anomaly_type: AnomalyType
  count: number
}

interface SimulationResult {
  total_traces: number
  anomalous_traces: number
  overall_risk_score: number
  verdict: 'clean' | 'suspicious' | 'poisoned'
  anomaly_breakdown: AnomalyBreakdownEntry[]
  traces: TraceRecord[]
  distribution_shift: number | null  // KL divergence vs baseline, null if no baseline
  simulation_duration_ms: number
}

type RunState = 'idle' | 'running' | 'success' | 'error'

// ─── Constants ────────────────────────────────────────────────────────────────

const ANOMALY_TYPE_LABELS: Record<AnomalyType, string> = {
  reward_hacking:          'Reward Hacking',
  memory_poisoning:        'Memory Poisoning',
  prompt_drift:            'Prompt Drift',
  retrieval_manipulation:  'Retrieval Manipulation',
  tool_hijack:             'Tool Hijack',
  multi_agent_collusion:   'Multi-Agent Collusion',
  slow_burn:               'Slow Burn',
}

const ANOMALY_COLORS: Record<AnomalyType, string> = {
  reward_hacking:          '#ef4444',
  memory_poisoning:        '#a855f7',
  prompt_drift:            '#f59e0b',
  retrieval_manipulation:  '#f97316',
  tool_hijack:             '#dc2626',
  multi_agent_collusion:   '#ec4899',
  slow_burn:               '#eab308',
}

const VERDICT_CONFIG = {
  clean:      { label: 'Clean',      badge: 'bg-green-950 border-green-900 text-green-300', dot: 'bg-green-400' },
  suspicious: { label: 'Suspicious', badge: 'bg-amber-950 border-amber-900 text-amber-300', dot: 'bg-amber-400' },
  poisoned:   { label: 'Poisoned',   badge: 'bg-red-950 border-red-900 text-red-300',       dot: 'bg-red-400'   },
} as const

// ─── Mock simulation (fallback when API is unavailable) ───────────────────────

function buildMockResult(config: SimulationConfig): SimulationResult {
  const seed = typeof config.seed === 'number' ? config.seed : Date.now()
  // Deterministic-ish LCG for reproducible mocks when seed is provided
  let rng = seed
  const rand = () => {
    rng = (rng * 1664525 + 1013904223) & 0xffffffff
    return Math.abs(rng) / 0xffffffff
  }

  const poisonFraction = config.poison_ratio / 100
  const noiseFraction  = config.noise_level  / 100
  const anomalousCount = Math.round(config.num_traces * poisonFraction)
  const overallRisk    = parseFloat((poisonFraction * 0.85 + noiseFraction * 0.15 + rand() * 0.05).toFixed(3))

  const now = Date.now()
  const windowMs = config.time_window_hours * 3_600_000

  const agentIds = Array.from({ length: config.num_agents }, (_, i) => `agent-${String(i + 1).padStart(2, '0')}`)

  const scenarioTypes: AnomalyType[] = config.scenario === 'clean' ? [] : [config.scenario as AnomalyType]

  const traces: TraceRecord[] = Array.from({ length: config.num_traces }, (_, i) => {
    const isAnomalous = i < anomalousCount
    const ts = new Date(now - windowMs + (i / config.num_traces) * windowMs).toISOString()
    return {
      trace_id:           `trc-${String(i).padStart(5, '0')}`,
      agent_id:           agentIds[Math.floor(rand() * agentIds.length)],
      timestamp:          ts,
      risk_score:         isAnomalous
                            ? parseFloat((0.55 + rand() * 0.45).toFixed(4))
                            : parseFloat((rand() * 0.3).toFixed(4)),
      is_anomalous:       isAnomalous,
      anomaly_types:      isAnomalous && scenarioTypes.length > 0 ? scenarioTypes : [],
      root_cause_span_id: isAnomalous ? `span-${Math.floor(rand() * 9000 + 1000)}` : null,
      duration_ms:        Math.round(rand() * 4800 + 200),
    }
  })

  const breakdownMap: Partial<Record<AnomalyType, number>> = {}
  for (const t of traces) {
    for (const at of t.anomaly_types) {
      breakdownMap[at] = (breakdownMap[at] ?? 0) + 1
    }
  }
  const anomaly_breakdown: AnomalyBreakdownEntry[] = Object.entries(breakdownMap).map(
    ([anomaly_type, count]) => ({ anomaly_type: anomaly_type as AnomalyType, count: count as number })
  )

  const verdict: SimulationResult['verdict'] =
    overallRisk >= 0.6 ? 'poisoned' : overallRisk >= 0.25 ? 'suspicious' : 'clean'

  return {
    total_traces: config.num_traces,
    anomalous_traces: anomalousCount,
    overall_risk_score: overallRisk,
    verdict,
    anomaly_breakdown,
    traces,
    distribution_shift: poisonFraction > 0.05 ? parseFloat((poisonFraction * 1.4 + rand() * 0.1).toFixed(4)) : null,
    simulation_duration_ms: Math.round(rand() * 600 + 80),
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function KpiCard({
  label,
  value,
  sub,
  accent,
}: {
  label: string
  value: React.ReactNode
  sub?: string
  accent?: 'green' | 'amber' | 'red' | 'blue'
}) {
  const ACCENT = {
    green: 'text-green-400',
    amber: 'text-amber-400',
    red:   'text-red-400',
    blue:  'text-blue-400',
  }
  return (
    <div className="card flex flex-col gap-1">
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{label}</p>
      <p className={['text-2xl font-bold tabular-nums leading-none', accent ? ACCENT[accent] : 'text-slate-100'].join(' ')}>
        {value}
      </p>
      {sub && <p className="text-[11px] text-slate-500">{sub}</p>}
    </div>
  )
}

function VerdictBadge({ verdict }: { verdict: SimulationResult['verdict'] }) {
  const cfg = VERDICT_CONFIG[verdict]
  return (
    <span className={['inline-flex items-center gap-1.5 font-semibold text-sm px-3 py-1.5 rounded-full border', cfg.badge].join(' ')}>
      <span className={['w-2 h-2 rounded-full', cfg.dot].join(' ')} aria-hidden="true" />
      {cfg.label}
    </span>
  )
}

interface SliderFieldProps {
  id: string
  label: string
  min: number
  max: number
  step?: number
  value: number
  onChange: (v: number) => void
  format?: (v: number) => string
  disabled?: boolean
}

function SliderField({
  id,
  label,
  min,
  max,
  step = 1,
  value,
  onChange,
  format,
  disabled,
}: SliderFieldProps) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <label htmlFor={id} className="text-xs font-medium text-slate-400">
          {label}
        </label>
        <span className="text-xs font-semibold text-slate-200 tabular-nums font-mono">
          {format ? format(value) : value}
        </span>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className={[
          'w-full h-1.5 rounded-full appearance-none cursor-pointer',
          'bg-slate-700 accent-blue-500',
          disabled ? 'opacity-40 cursor-not-allowed' : '',
        ].join(' ')}
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={value}
        aria-label={label}
      />
      <div className="flex justify-between text-[9px] text-slate-600 mt-0.5">
        <span>{format ? format(min) : min}</span>
        <span>{format ? format(max) : max}</span>
      </div>
    </div>
  )
}

// ─── Recharts: Anomaly Breakdown ──────────────────────────────────────────────

function AnomalyBreakdownChart({ data }: { data: AnomalyBreakdownEntry[] }) {
  if (data.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-slate-600 gap-2">
        <CheckCircle2 className="w-6 h-6 text-green-500" aria-hidden="true" />
        <p className="text-xs">No anomaly types recorded</p>
      </div>
    )
  }

  const chartData = data.map((d) => ({
    name: ANOMALY_TYPE_LABELS[d.anomaly_type] ?? d.anomaly_type,
    count: d.count,
    color: ANOMALY_COLORS[d.anomaly_type] ?? '#64748b',
    type: d.anomaly_type,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart
        data={chartData}
        layout="vertical"
        margin={{ top: 0, right: 16, left: 0, bottom: 0 }}
        aria-label="Anomaly breakdown by type"
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
        <XAxis
          type="number"
          tick={{ fill: '#64748b', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          allowDecimals={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={160}
          tick={{ fill: '#94a3b8', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
          contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
          labelStyle={{ color: '#94a3b8' }}
          itemStyle={{ color: '#f1f5f9' }}
          formatter={(value: number) => [value, 'Traces']}
        />
        <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={24}>
          {chartData.map((entry) => (
            <Cell key={entry.type} fill={entry.color} fillOpacity={0.85} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// ─── Recharts: Execution Timeline ─────────────────────────────────────────────

function ExecutionTimeline({ traces }: { traces: TraceRecord[] }) {
  // Bucket traces into 40 time buckets for the area chart
  if (traces.length === 0) return null

  const sorted = [...traces].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )
  const tMin = new Date(sorted[0].timestamp).getTime()
  const tMax = new Date(sorted[sorted.length - 1].timestamp).getTime()
  const buckets = 40
  const bucketSize = Math.max((tMax - tMin) / buckets, 1)

  const bucketedData = Array.from({ length: buckets }, (_, i) => {
    const bStart = tMin + i * bucketSize
    const bEnd   = bStart + bucketSize
    const inBucket = sorted.filter((t) => {
      const ts = new Date(t.timestamp).getTime()
      return ts >= bStart && ts < bEnd
    })
    const avgRisk = inBucket.length
      ? inBucket.reduce((s, t) => s + t.risk_score, 0) / inBucket.length
      : 0
    const anomalous = inBucket.filter((t) => t.is_anomalous).length
    return {
      t: new Date(bStart).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }),
      avg_risk: parseFloat(avgRisk.toFixed(4)),
      anomalous_count: anomalous,
      normal_count: inBucket.length - anomalous,
    }
  })

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart
        data={bucketedData}
        margin={{ top: 4, right: 16, left: 0, bottom: 0 }}
        aria-label="Risk score over time"
      >
        <defs>
          <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.35} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.03} />
          </linearGradient>
          <linearGradient id="anomalyGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.45} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.03} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="t"
          tick={{ fill: '#64748b', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fill: '#64748b', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          domain={[0, 1]}
          tickFormatter={(v: number) => v.toFixed(1)}
          width={32}
        />
        <Tooltip
          contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
          labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
          itemStyle={{ color: '#f1f5f9' }}
          formatter={(value: number, name: string) => [
            name === 'avg_risk' ? value.toFixed(4) : value,
            name === 'avg_risk' ? 'Avg Risk Score' : 'Anomalous Traces',
          ]}
        />
        <Legend
          formatter={(value) =>
            value === 'avg_risk' ? 'Avg Risk Score' : 'Anomalous Traces'
          }
          wrapperStyle={{ fontSize: '11px', color: '#94a3b8', paddingTop: '8px' }}
        />
        <Area
          type="monotone"
          dataKey="avg_risk"
          stroke="#3b82f6"
          strokeWidth={1.5}
          fill="url(#riskGradient)"
          dot={false}
        />
        <Area
          type="monotone"
          dataKey="anomalous_count"
          stroke="#ef4444"
          strokeWidth={1.5}
          fill="url(#anomalyGradient)"
          dot={false}
          yAxisId={0}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

// ─── Root Cause Table ─────────────────────────────────────────────────────────

function RootCauseTable({ traces }: { traces: TraceRecord[] }) {
  const flagged = traces
    .filter((t) => t.is_anomalous && t.root_cause_span_id)
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 25)

  if (flagged.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-8 text-slate-600">
        <CheckCircle2 className="w-5 h-5 text-green-500" aria-hidden="true" />
        <p className="text-xs">No flagged traces with root cause spans</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto -mx-5 px-5">
      <table className="data-table" aria-label="Root cause trace analysis">
        <thead>
          <tr>
            <th>Trace ID</th>
            <th>Agent</th>
            <th>Risk Score</th>
            <th>Anomaly Types</th>
            <th>Root Cause Span</th>
            <th>Duration</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {flagged.map((t) => (
            <tr key={t.trace_id}>
              <td>
                <span className="font-mono text-xs text-slate-300">{t.trace_id}</span>
              </td>
              <td>
                <span className="text-xs text-slate-400 bg-slate-700 px-2 py-0.5 rounded font-mono">
                  {t.agent_id}
                </span>
              </td>
              <td>
                <div className="flex items-center gap-2">
                  <div className="w-14 h-1.5 bg-slate-700 rounded-full overflow-hidden flex-shrink-0">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${t.risk_score * 100}%`,
                        background:
                          t.risk_score >= 0.7
                            ? '#ef4444'
                            : t.risk_score >= 0.4
                            ? '#f59e0b'
                            : '#22c55e',
                      }}
                      role="meter"
                      aria-valuenow={t.risk_score * 100}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-label={`Risk score ${(t.risk_score * 100).toFixed(1)}%`}
                    />
                  </div>
                  <span
                    className={[
                      'font-mono text-xs tabular-nums',
                      t.risk_score >= 0.7
                        ? 'text-red-400'
                        : t.risk_score >= 0.4
                        ? 'text-amber-400'
                        : 'text-green-400',
                    ].join(' ')}
                  >
                    {t.risk_score.toFixed(4)}
                  </span>
                </div>
              </td>
              <td>
                <div className="flex flex-wrap gap-1">
                  {t.anomaly_types.length === 0 ? (
                    <span className="text-xs text-slate-600">—</span>
                  ) : (
                    t.anomaly_types.map((at) => (
                      <span
                        key={at}
                        className="text-[10px] px-1.5 py-0.5 rounded"
                        style={{
                          background: `${ANOMALY_COLORS[at] ?? '#64748b'}22`,
                          color: ANOMALY_COLORS[at] ?? '#94a3b8',
                          border: `1px solid ${ANOMALY_COLORS[at] ?? '#64748b'}44`,
                        }}
                      >
                        {ANOMALY_TYPE_LABELS[at] ?? at}
                      </span>
                    ))
                  )}
                </div>
              </td>
              <td>
                <span className="font-mono text-xs text-slate-400">{t.root_cause_span_id}</span>
              </td>
              <td>
                <span className="font-mono text-xs text-slate-500 tabular-nums">{t.duration_ms}ms</span>
              </td>
              <td>
                <time dateTime={t.timestamp} className="text-xs text-slate-500 whitespace-nowrap">
                  {new Date(t.timestamp).toLocaleTimeString('en-US', {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: false,
                  })}
                </time>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {flagged.length === 25 && (
        <p className="text-[10px] text-slate-600 mt-2 text-center">
          Showing top 25 flagged traces by risk score
        </p>
      )}
    </div>
  )
}

// ─── Distribution Shift Gauge ─────────────────────────────────────────────────

function DistributionShiftGauge({ shift }: { shift: number }) {
  // KL divergence — clamp display at 2.0 for the bar
  const normalized = Math.min(shift / 2.0, 1)
  const level = shift >= 1.0 ? 'critical' : shift >= 0.3 ? 'warning' : 'safe'
  const COLOR = { critical: '#ef4444', warning: '#f59e0b', safe: '#22c55e' } as const
  const LABEL = {
    critical: 'Severe distribution shift detected — likely active attack',
    warning:  'Moderate distribution shift — monitor closely',
    safe:     'Distribution within expected baseline bounds',
  } as const

  return (
    <div className="card" role="region" aria-label="Distribution shift gauge">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-200">Distribution Shift</h3>
        <span
          className="text-xs font-semibold font-mono tabular-nums"
          style={{ color: COLOR[level] }}
        >
          KL = {shift.toFixed(4)}
        </span>
      </div>

      <div className="w-full h-2.5 bg-slate-700 rounded-full overflow-hidden mb-2">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${normalized * 100}%`, background: COLOR[level] }}
          role="meter"
          aria-valuenow={shift}
          aria-valuemin={0}
          aria-valuemax={2}
          aria-label="KL divergence from baseline"
        />
      </div>

      <div className="flex justify-between text-[9px] text-slate-600 mb-3">
        <span>0.0 (identical)</span>
        <span>1.0 (diverged)</span>
        <span>2.0+ (extreme)</span>
      </div>

      <p className="text-xs" style={{ color: COLOR[level] }}>
        {LABEL[level]}
      </p>
    </div>
  )
}

// ─── Prompt Risk Distribution (histogram of risk_score values) ────────────────

function PromptRiskDistribution({ traces }: { traces: TraceRecord[] }) {
  const BINS = 20
  const bins = Array.from({ length: BINS }, (_, i) => ({
    rangeStart: i / BINS,
    rangeEnd:   (i + 1) / BINS,
    label:      ((i + 0.5) / BINS).toFixed(2),
    count:      0,
    anomalous:  0,
  }))

  for (const t of traces) {
    const idx = Math.min(Math.floor(t.risk_score * BINS), BINS - 1)
    bins[idx].count += 1
    if (t.is_anomalous) bins[idx].anomalous += 1
  }

  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart
        data={bins}
        margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
        aria-label="Risk score distribution histogram"
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fill: '#64748b', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          interval={4}
        />
        <YAxis
          tick={{ fill: '#64748b', fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          width={28}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
          labelStyle={{ color: '#94a3b8' }}
          itemStyle={{ color: '#f1f5f9' }}
          formatter={(value: number, name: string) => [
            value,
            name === 'count' ? 'Total traces' : 'Anomalous',
          ]}
          labelFormatter={(label: string) => `Risk Score ≈ ${label}`}
        />
        <Bar dataKey="count" fill="#3b82f6" fillOpacity={0.6} radius={[2, 2, 0, 0]} maxBarSize={20} />
        <Bar dataKey="anomalous" fill="#ef4444" fillOpacity={0.8} radius={[2, 2, 0, 0]} maxBarSize={20} />
      </BarChart>
    </ResponsiveContainer>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

interface SimulationPanelProps {
  scenarios: ScenarioOption[]
}

const DEFAULT_CONFIG: SimulationConfig = {
  scenario:           'clean',
  num_traces:         100,
  num_agents:         5,
  poison_ratio:       15,
  noise_level:        10,
  time_window_hours:  24,
  seed:               '',
}

export function SimulationPanel({ scenarios }: SimulationPanelProps) {
  const uid = useId()
  const [config, setConfig] = useState<SimulationConfig>(DEFAULT_CONFIG)
  const [runState, setRunState] = useState<RunState>('idle')
  const [result, setResult] = useState<SimulationResult | null>(null)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const setField = useCallback(
    <K extends keyof SimulationConfig>(key: K, value: SimulationConfig[K]) => {
      setConfig((prev) => ({ ...prev, [key]: value }))
    },
    [],
  )

  const handleRun = useCallback(async () => {
    setRunState('running')
    setErrorMsg(null)

    const payload = {
      scenario: config.scenario,
      num_traces: config.num_traces,
      num_agents: config.num_agents,
      poison_ratio: config.poison_ratio / 100,
      ...(config.seed !== '' ? { seed: Number(config.seed) } : {}),
    }

    try {
      const data: SimulationResult = await runSimulation(payload)
      setResult(data)
      setRunState('success')
    } catch (err) {
      setRunState('error')
      setErrorMsg(err instanceof Error ? err.message : 'An unknown error occurred')
    }
  }, [config])

  const handleReset = useCallback(() => {
    setResult(null)
    setRunState('idle')
    setErrorMsg(null)
  }, [])

  const isRunning = runState === 'running'

  // ── Derived risk score accent ────────────────────────────────────────────────
  const riskAccent =
    result == null           ? undefined
    : result.overall_risk_score >= 0.6 ? 'red'
    : result.overall_risk_score >= 0.25 ? 'amber'
    : 'green'

  return (
    <div className="space-y-6">

      {/* ── Config card ── */}
      <div className="card" aria-label="Simulation configuration">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <FlaskConical className="w-4 h-4 text-blue-400" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-200">Simulation Controls</h2>
          </div>
          {result && (
            <button
              type="button"
              onClick={handleReset}
              className="btn-ghost text-xs"
              aria-label="Reset simulation"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              Reset
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-8 gap-y-5">

          {/* Scenario */}
          <div className="md:col-span-2 xl:col-span-3">
            <label htmlFor={`${uid}-scenario`} className="text-xs font-medium text-slate-400 block mb-1.5">
              Attack Scenario
            </label>
            <select
              id={`${uid}-scenario`}
              value={config.scenario}
              onChange={(e) => setField('scenario', e.target.value)}
              disabled={isRunning}
              className="field"
              aria-label="Select attack scenario"
            >
              {scenarios.map((s) => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </div>

          {/* Sliders */}
          <SliderField
            id={`${uid}-num-traces`}
            label="Number of Traces"
            min={10}
            max={10000}
            step={10}
            value={config.num_traces}
            onChange={(v) => setField('num_traces', v)}
            format={(v) => v.toLocaleString()}
            disabled={isRunning}
          />

          <SliderField
            id={`${uid}-num-agents`}
            label="Number of Agents"
            min={1}
            max={50}
            value={config.num_agents}
            onChange={(v) => setField('num_agents', v)}
            disabled={isRunning}
          />

          <SliderField
            id={`${uid}-poison-ratio`}
            label="Poison Ratio"
            min={0}
            max={100}
            step={1}
            value={config.poison_ratio}
            onChange={(v) => setField('poison_ratio', v)}
            format={(v) => `${v}%`}
            disabled={isRunning}
          />

          <SliderField
            id={`${uid}-noise-level`}
            label="Noise Level"
            min={0}
            max={100}
            step={1}
            value={config.noise_level}
            onChange={(v) => setField('noise_level', v)}
            format={(v) => `${v}%`}
            disabled={isRunning}
          />

          <SliderField
            id={`${uid}-time-window`}
            label="Time Window"
            min={1}
            max={168}
            step={1}
            value={config.time_window_hours}
            onChange={(v) => setField('time_window_hours', v)}
            format={(v) => v >= 24 ? `${(v / 24).toFixed(v % 24 === 0 ? 0 : 1)}d` : `${v}h`}
            disabled={isRunning}
          />

          {/* Seed input */}
          <div>
            <label htmlFor={`${uid}-seed`} className="text-xs font-medium text-slate-400 block mb-1.5">
              Random Seed{' '}
              <span className="text-slate-600 font-normal">(optional — leave blank for random)</span>
            </label>
            <input
              id={`${uid}-seed`}
              type="number"
              min={0}
              placeholder="e.g. 42"
              value={config.seed}
              onChange={(e) => setField('seed', e.target.value === '' ? '' : Number(e.target.value))}
              disabled={isRunning}
              className="field"
              aria-label="Random seed for reproducible simulation"
            />
          </div>
        </div>

        {/* Run button + status */}
        <div className="mt-6 flex items-center gap-4 border-t border-slate-700 pt-5">
          <button
            type="button"
            onClick={handleRun}
            disabled={isRunning}
            className="btn-primary"
            aria-label={isRunning ? 'Simulation running…' : 'Run simulation'}
          >
            {isRunning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                Running…
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" aria-hidden="true" />
                Run Simulation
              </>
            )}
          </button>

          {runState === 'success' && result && (
            <div role="status" className="flex items-center gap-1.5 text-xs text-green-400">
              <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
              Completed in {result.simulation_duration_ms}ms
            </div>
          )}

          {runState === 'error' && errorMsg && (
            <div role="alert" className="flex items-center gap-1.5 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
              {errorMsg}
            </div>
          )}
        </div>
      </div>

      {/* ── Results section ── */}
      {result && (
        <div className="space-y-4 animate-fade-in" aria-label="Simulation results" role="region">

          {/* KPI row */}
          <div>
            <p className="section-heading">Results</p>
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
              <KpiCard
                label="Total Traces"
                value={result.total_traces.toLocaleString()}
                sub={`${config.num_agents} agent${config.num_agents !== 1 ? 's' : ''} · ${config.time_window_hours}h window`}
                accent="blue"
              />
              <KpiCard
                label="Anomalous Traces"
                value={result.anomalous_traces.toLocaleString()}
                sub={`${((result.anomalous_traces / result.total_traces) * 100).toFixed(1)}% of total`}
                accent={result.anomalous_traces === 0 ? 'green' : result.anomalous_traces / result.total_traces >= 0.3 ? 'red' : 'amber'}
              />
              <KpiCard
                label="Overall Risk Score"
                value={result.overall_risk_score.toFixed(4)}
                sub="0 = clean · 1 = fully poisoned"
                accent={riskAccent}
              />
              <div className="card flex flex-col gap-2">
                <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Verdict</p>
                <div className="flex items-center gap-2">
                  {result.verdict === 'poisoned' && (
                    <ShieldAlert className="w-5 h-5 text-red-400 flex-shrink-0" aria-hidden="true" />
                  )}
                  <VerdictBadge verdict={result.verdict} />
                </div>
              </div>
            </div>
          </div>

          {/* Charts row */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

            {/* Anomaly breakdown */}
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <BarChart2 className="w-4 h-4 text-slate-500" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-200">Anomaly Breakdown</h3>
              </div>
              <AnomalyBreakdownChart data={result.anomaly_breakdown} />
            </div>

            {/* Execution timeline */}
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <Clock className="w-4 h-4 text-slate-500" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-200">Execution Timeline</h3>
                <p className="ml-auto text-[10px] text-slate-600">avg risk + anomaly count over time</p>
              </div>
              <ExecutionTimeline traces={result.traces} />
            </div>
          </div>

          {/* Distribution shift gauge (only when applicable) */}
          {result.distribution_shift !== null && (
            <DistributionShiftGauge shift={result.distribution_shift} />
          )}

          {/* Prompt risk distribution */}
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-200 mb-1">Prompt Risk Distribution</h3>
            <p className="text-xs text-slate-500 mb-4">
              Histogram of risk scores across all {result.total_traces.toLocaleString()} traces.{' '}
              <span className="text-blue-400">Blue</span> = all traces · <span className="text-red-400">Red</span> = anomalous
            </p>
            <PromptRiskDistribution traces={result.traces} />
          </div>

          {/* Root cause analysis */}
          <div className="card">
            <h3 className="text-sm font-semibold text-slate-200 mb-1">Root Cause Analysis</h3>
            <p className="text-xs text-slate-500 mb-5">
              Flagged traces with identified root cause spans — sorted by risk score descending
            </p>
            <RootCauseTable traces={result.traces} />
          </div>

        </div>
      )}
    </div>
  )
}
