/**
 * CorrelationPanel — Cross-Engine Attack Correlation client component.
 *
 * Features:
 *   - Config controls: time window slider (5–240 min), min cluster size slider (2–10)
 *   - Stats row: total / correlated / uncorrelated events + cluster count
 *   - Kill Chain Coverage: recharts BarChart per stage
 *   - Attack Clusters: expandable cards with event drill-down
 *   - Unified Timeline: full correlated event table sorted by timestamp
 *
 * Usage (called by correlation/page.tsx):
 *   <CorrelationPanel />
 */

'use client'

import { useState, useEffect, useCallback, useId } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import {
  Network,
  Clock,
  Shield,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  Loader2,
  Target,
  AlertTriangle,
  Eye,
} from 'lucide-react'
import { fetchCorrelationResults } from '@/lib/api'
import type { CorrelationResult, AttackCluster, CorrelatedEvent } from '@/lib/types'

// ─── Kill chain stage metadata ────────────────────────────────────────────────

type KillChainStage = AttackCluster['killChainStage']

const KILL_CHAIN_META: Record<
  KillChainStage,
  { label: string; color: string; barColor: string; badgeBg: string; badgeText: string }
> = {
  reconnaissance: {
    label: 'Reconnaissance',
    color: '#3b82f6',
    barColor: '#3b82f6',
    badgeBg: 'bg-blue-900/40',
    badgeText: 'text-blue-300',
  },
  initial_access: {
    label: 'Initial Access',
    color: '#eab308',
    barColor: '#eab308',
    badgeBg: 'bg-yellow-900/40',
    badgeText: 'text-yellow-300',
  },
  persistence: {
    label: 'Persistence',
    color: '#f97316',
    barColor: '#f97316',
    badgeBg: 'bg-orange-900/40',
    badgeText: 'text-orange-300',
  },
  exfiltration: {
    label: 'Exfiltration',
    color: '#ef4444',
    barColor: '#ef4444',
    badgeBg: 'bg-red-900/40',
    badgeText: 'text-red-300',
  },
  impact: {
    label: 'Impact',
    color: '#a855f7',
    barColor: '#a855f7',
    badgeBg: 'bg-purple-900/40',
    badgeText: 'text-purple-300',
  },
}

// ─── Severity helpers ─────────────────────────────────────────────────────────

function severityPill(severity: CorrelatedEvent['severity']) {
  const map: Record<CorrelatedEvent['severity'], string> = {
    critical: 'bg-red-900/50 text-red-300 border border-red-700/50',
    warning: 'bg-yellow-900/50 text-yellow-300 border border-yellow-700/50',
    info: 'bg-blue-900/50 text-blue-300 border border-blue-700/50',
    safe: 'bg-emerald-900/50 text-emerald-300 border border-emerald-700/50',
  }
  return map[severity] ?? map.info
}

function confidenceColor(score: number): string {
  if (score >= 0.85) return 'text-red-400'
  if (score >= 0.65) return 'text-orange-400'
  return 'text-yellow-400'
}

function engineBadge(engine: string): string {
  const map: Record<string, string> = {
    vector_analyzer: 'bg-violet-900/40 text-violet-300 border-violet-700/40',
    rag_detector: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/40',
    mcp_auditor: 'bg-amber-900/40 text-amber-300 border-amber-700/40',
    provenance_tracker: 'bg-teal-900/40 text-teal-300 border-teal-700/40',
    telemetry: 'bg-indigo-900/40 text-indigo-300 border-indigo-700/40',
  }
  return map[engine] ?? 'bg-slate-800 text-slate-300 border-slate-700/40'
}

function formatTs(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
}

function formatTsShort(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface SliderProps {
  id: string
  label: string
  min: number
  max: number
  step: number
  value: number
  onChange: (v: number) => void
  unit?: string
}

function LabeledSlider({ id, label, min, max, step, value, onChange, unit = '' }: SliderProps) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <label htmlFor={id} className="text-xs font-medium text-slate-400">
          {label}
        </label>
        <span className="text-xs font-mono font-semibold text-slate-200">
          {value}{unit}
        </span>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        className="w-full h-1.5 rounded-full appearance-none cursor-pointer bg-slate-700 accent-orange-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60"
        aria-valuemin={min}
        aria-valuemax={max}
        aria-valuenow={value}
        aria-valuetext={`${value}${unit}`}
      />
      <div className="flex justify-between text-[10px] text-slate-600">
        <span>{min}{unit}</span>
        <span>{max}{unit}</span>
      </div>
    </div>
  )
}

// ─── Kill chain coverage chart ────────────────────────────────────────────────

interface CoverageChartProps {
  coverage: Record<string, number>
}

function KillChainCoverageChart({ coverage }: CoverageChartProps) {
  const STAGES: KillChainStage[] = [
    'reconnaissance',
    'initial_access',
    'persistence',
    'exfiltration',
    'impact',
  ]

  const data = STAGES.map(stage => ({
    stage,
    label: KILL_CHAIN_META[stage].label,
    count: coverage[stage] ?? 0,
    color: KILL_CHAIN_META[stage].barColor,
  }))

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 11, fill: '#94a3b8' }}
          axisLine={false}
          tickLine={false}
        />
        <YAxis
          allowDecimals={false}
          tick={{ fontSize: 11, fill: '#64748b' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: '#0f172a',
            border: '1px solid #1e293b',
            borderRadius: 8,
            fontSize: 12,
            color: '#e2e8f0',
          }}
          cursor={{ fill: 'rgba(255,255,255,0.03)' }}
          formatter={(value: number) => [`${value} events`, 'Count']}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={48}>
          {data.map(entry => (
            <Cell key={entry.stage} fill={entry.color} fillOpacity={0.85} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

// ─── Attack cluster card ──────────────────────────────────────────────────────

interface ClusterCardProps {
  cluster: AttackCluster
  index: number
}

function ClusterCard({ cluster, index }: ClusterCardProps) {
  const [expanded, setExpanded] = useState(false)
  const meta = KILL_CHAIN_META[cluster.killChainStage]
  const headerId = `cluster-header-${cluster.id}`
  const bodyId = `cluster-body-${cluster.id}`

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 overflow-hidden">
      {/* Card header — always visible */}
      <button
        id={headerId}
        aria-expanded={expanded}
        aria-controls={bodyId}
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-start justify-between gap-3 p-4 text-left hover:bg-slate-800/40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60 focus-visible:ring-inset"
      >
        {/* Left: index + stage */}
        <div className="flex items-start gap-3 min-w-0">
          <div className="w-7 h-7 shrink-0 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-mono text-slate-400">
            {index + 1}
          </div>
          <div className="min-w-0 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border ${meta.badgeBg} ${meta.badgeText} border-current/20`}
              >
                <Target className="w-3 h-3" aria-hidden="true" />
                {meta.label}
              </span>
              <span className={`text-sm font-semibold ${confidenceColor(cluster.confidence)}`}>
                {(cluster.confidence * 100).toFixed(0)}% confidence
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" aria-hidden="true" />
                {cluster.timeWindowMinutes}m window
              </span>
              <span className="flex items-center gap-1">
                <Shield className="w-3 h-3" aria-hidden="true" />
                {cluster.events.length} events
              </span>
              <span>
                {formatTsShort(cluster.firstSeen)} → {formatTsShort(cluster.lastSeen)}
              </span>
            </div>
            {/* Entity IDs */}
            <div className="flex flex-wrap gap-1.5">
              {cluster.entityIds.map(eid => (
                <span
                  key={eid}
                  className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-400"
                >
                  {eid}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Right: chevron */}
        <div className="shrink-0 mt-0.5 text-slate-500">
          {expanded
            ? <ChevronUp className="w-4 h-4" aria-hidden="true" />
            : <ChevronDown className="w-4 h-4" aria-hidden="true" />}
        </div>
      </button>

      {/* Expandable event list */}
      {expanded && (
        <div
          id={bodyId}
          role="region"
          aria-labelledby={headerId}
          className="border-t border-slate-800"
        >
          <div className="p-3 space-y-1.5">
            {cluster.events.map(evt => (
              <div
                key={evt.id}
                className="flex flex-wrap items-center gap-2 px-3 py-2 rounded-lg bg-slate-800/50 text-xs"
              >
                <span
                  className={`shrink-0 inline-flex items-center px-2 py-0.5 rounded-full font-medium border text-[10px] ${severityPill(evt.severity)}`}
                >
                  {evt.severity}
                </span>
                <span
                  className={`shrink-0 inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-mono ${engineBadge(evt.engine)}`}
                >
                  {evt.engine}
                </span>
                <span className="text-slate-300 font-medium truncate">{evt.type.replace(/_/g, ' ')}</span>
                <span className="text-slate-500 ml-auto font-mono">{formatTs(evt.timestamp)}</span>
                <span className={`font-semibold ${evt.riskScore >= 0.7 ? 'text-red-400' : evt.riskScore >= 0.4 ? 'text-orange-400' : 'text-slate-400'}`}>
                  {(evt.riskScore * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main panel ───────────────────────────────────────────────────────────────

export function CorrelationPanel() {
  const [timeWindow, setTimeWindow] = useState(60)
  const [minCluster, setMinCluster] = useState(2)
  const [result, setResult] = useState<CorrelationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const timeWindowId = useId()
  const minClusterId = useId()

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await fetchCorrelationResults({
        timeWindowMinutes: timeWindow,
        minClusterSize: minCluster,
      })
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch correlation data')
    } finally {
      setLoading(false)
    }
  }, [timeWindow, minCluster])

  // Initial load
  useEffect(() => {
    load()
  }, [load])

  // ── Derived stats ──────────────────────────────────────────────────────────

  const stats = result
    ? [
        {
          label: 'Total Events',
          value: result.totalEvents,
          icon: Eye,
          color: 'text-slate-300',
          bg: 'bg-slate-800/60',
        },
        {
          label: 'Correlated',
          value: result.correlatedEvents,
          icon: Network,
          color: 'text-orange-400',
          bg: 'bg-orange-900/20',
        },
        {
          label: 'Uncorrelated',
          value: result.uncorrelatedEvents,
          icon: AlertTriangle,
          color: 'text-slate-400',
          bg: 'bg-slate-800/60',
        },
        {
          label: 'Clusters',
          value: result.clusters.length,
          icon: Target,
          color: 'text-amber-400',
          bg: 'bg-amber-900/20',
        },
      ]
    : []

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* Config controls */}
      <section
        aria-label="Correlation configuration"
        className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-5"
      >
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
            <Shield className="w-4 h-4 text-orange-400" aria-hidden="true" />
            Configuration
          </h2>
          <button
            onClick={load}
            disabled={loading}
            aria-label="Refresh correlation results"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-orange-600/20 text-orange-300 border border-orange-600/30 hover:bg-orange-600/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60"
          >
            {loading
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
              : <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />}
            {loading ? 'Correlating…' : 'Refresh'}
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
          <LabeledSlider
            id={timeWindowId}
            label="Time Window"
            min={5}
            max={240}
            step={5}
            value={timeWindow}
            onChange={setTimeWindow}
            unit=" min"
          />
          <LabeledSlider
            id={minClusterId}
            label="Min Cluster Size"
            min={2}
            max={10}
            step={1}
            value={minCluster}
            onChange={setMinCluster}
            unit=" events"
          />
        </div>
      </section>

      {/* Error state */}
      {error && (
        <div
          role="alert"
          className="flex items-start gap-3 p-4 rounded-xl border border-red-800/50 bg-red-900/20 text-sm text-red-300"
        >
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-red-400" aria-hidden="true" />
          <span>{error}</span>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && !result && (
        <div className="space-y-3" aria-busy="true" aria-label="Loading correlation data">
          {[88, 64, 72].map(w => (
            <div
              key={w}
              className="h-12 rounded-xl bg-slate-800/60 animate-pulse"
              style={{ width: `${w}%` }}
            />
          ))}
        </div>
      )}

      {result && (
        <>
          {/* Stats row */}
          <section aria-label="Summary statistics">
            <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {stats.map(({ label, value, icon: Icon, color, bg }) => (
                <div
                  key={label}
                  className={`rounded-xl border border-slate-800 ${bg} p-4 space-y-1`}
                >
                  <dt className="flex items-center gap-1.5 text-xs text-slate-500">
                    <Icon className={`w-3.5 h-3.5 ${color}`} aria-hidden="true" />
                    {label}
                  </dt>
                  <dd className={`text-2xl font-bold font-mono tracking-tight ${color}`}>
                    {value}
                  </dd>
                </div>
              ))}
            </dl>
          </section>

          {/* Kill Chain Coverage */}
          <section
            aria-label="Kill chain coverage"
            className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4"
          >
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Target className="w-4 h-4 text-orange-400" aria-hidden="true" />
              Kill Chain Coverage
            </h2>
            <KillChainCoverageChart coverage={result.killChainCoverage} />

            {/* Stage legend pills */}
            <div className="flex flex-wrap gap-2" aria-label="Kill chain stage legend">
              {(Object.keys(KILL_CHAIN_META) as KillChainStage[]).map(stage => {
                const meta = KILL_CHAIN_META[stage]
                const count = result.killChainCoverage[stage] ?? 0
                return (
                  <div
                    key={stage}
                    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border ${meta.badgeBg} ${meta.badgeText} border-current/20`}
                  >
                    <span
                      className="w-2 h-2 rounded-full inline-block"
                      style={{ backgroundColor: meta.color }}
                      aria-hidden="true"
                    />
                    {meta.label}
                    <span className="font-mono font-semibold ml-0.5">{count}</span>
                  </div>
                )
              })}
            </div>
          </section>

          {/* Attack Clusters */}
          <section aria-label="Attack clusters">
            <div className="space-y-3">
              <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Network className="w-4 h-4 text-orange-400" aria-hidden="true" />
                Attack Clusters
                <span className="ml-auto text-xs font-normal text-slate-500">
                  {result.clusters.length} cluster{result.clusters.length !== 1 ? 's' : ''} detected
                </span>
              </h2>

              {result.clusters.length === 0 ? (
                <div className="flex items-center justify-center gap-2 h-24 rounded-xl border border-slate-800 bg-slate-900/40 text-sm text-slate-500">
                  <Shield className="w-4 h-4" aria-hidden="true" />
                  No clusters detected with current parameters
                </div>
              ) : (
                <div className="space-y-2">
                  {result.clusters.map((cluster, i) => (
                    <ClusterCard key={cluster.id} cluster={cluster} index={i} />
                  ))}
                </div>
              )}
            </div>
          </section>

          {/* Unified Timeline */}
          <section aria-label="Unified correlated event timeline">
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
                <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-orange-400" aria-hidden="true" />
                  Unified Timeline
                  <span className="text-xs font-normal text-slate-500">
                    — {result.timeline.length} correlated events
                  </span>
                </h2>
              </div>

              {result.timeline.length === 0 ? (
                <div className="flex items-center justify-center gap-2 h-20 text-sm text-slate-500">
                  <Eye className="w-4 h-4" aria-hidden="true" />
                  No correlated events in timeline
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs" role="table" aria-label="Correlated events timeline">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500">
                        <th scope="col" className="px-4 py-2.5 text-left font-medium">Timestamp</th>
                        <th scope="col" className="px-4 py-2.5 text-left font-medium">Engine</th>
                        <th scope="col" className="px-4 py-2.5 text-left font-medium">Type</th>
                        <th scope="col" className="px-4 py-2.5 text-left font-medium">Severity</th>
                        <th scope="col" className="px-4 py-2.5 text-left font-medium">Entity</th>
                        <th scope="col" className="px-4 py-2.5 text-right font-medium">Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {result.timeline.map(evt => (
                        <tr
                          key={evt.id}
                          className="hover:bg-slate-800/30 transition-colors"
                        >
                          {/* Timestamp */}
                          <td className="px-4 py-2.5 font-mono text-slate-400 whitespace-nowrap">
                            {formatTsShort(evt.timestamp)}
                          </td>

                          {/* Engine badge */}
                          <td className="px-4 py-2.5">
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-mono whitespace-nowrap ${engineBadge(evt.engine)}`}
                            >
                              {evt.engine}
                            </span>
                          </td>

                          {/* Type */}
                          <td className="px-4 py-2.5 text-slate-300 whitespace-nowrap">
                            {evt.type.replace(/_/g, ' ')}
                          </td>

                          {/* Severity pill */}
                          <td className="px-4 py-2.5">
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded-full font-medium border text-[10px] whitespace-nowrap ${severityPill(evt.severity)}`}
                            >
                              {evt.severity}
                            </span>
                          </td>

                          {/* Entity ID — styled as a link-like element */}
                          <td className="px-4 py-2.5">
                            <span
                              className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600 cursor-default transition-colors"
                              title={`Entity: ${evt.entityId}`}
                              aria-label={`Entity ID: ${evt.entityId}`}
                            >
                              {evt.entityId}
                            </span>
                          </td>

                          {/* Risk score */}
                          <td className="px-4 py-2.5 text-right font-mono font-semibold">
                            <span
                              className={
                                evt.riskScore >= 0.7
                                  ? 'text-red-400'
                                  : evt.riskScore >= 0.4
                                  ? 'text-orange-400'
                                  : 'text-slate-400'
                              }
                            >
                              {(evt.riskScore * 100).toFixed(0)}%
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
