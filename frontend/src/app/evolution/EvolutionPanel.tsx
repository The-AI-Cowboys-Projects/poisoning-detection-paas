/**
 * EvolutionPanel — client component implementing the Self-Evolution Loop.
 *
 * Runs generate→detect→score→harden cycles in real time, showing round-by-round
 * detection rate, false positive rate, and convergence delta charts.
 *
 * Usage (called by evolution/page.tsx):
 *   <EvolutionPanel />
 */

'use client'

import { useState, useCallback, useRef, useId } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'
import {
  Play,
  Square,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Dna,
  ShieldCheck,
  Activity,
  TrendingDown,
  ChevronDown,
  ChevronUp,
  Zap,
  BookOpen,
} from 'lucide-react'
import { startEvolutionSession, runEvolutionRound } from '@/lib/api'
import type { EvolutionRound, EvolutionSession } from '@/lib/types'

// ─── Attack type options ───────────────────────────────────────────────────────

const ATTACK_TYPE_OPTIONS = [
  { id: 'prompt_injection',        label: 'Prompt Injection' },
  { id: 'rag_poisoning',           label: 'RAG Poisoning' },
  { id: 'hidden_instruction',      label: 'Hidden Instruction' },
  { id: 'schema_manipulation',     label: 'Schema Manipulation' },
  { id: 'reward_hacking',          label: 'Reward Hacking' },
  { id: 'memory_poisoning',        label: 'Memory Poisoning' },
  { id: 'retrieval_manipulation',  label: 'Retrieval Manipulation' },
  { id: 'multi_agent_collusion',   label: 'Multi-Agent Collusion' },
] as const

type AttackTypeId = (typeof ATTACK_TYPE_OPTIONS)[number]['id']

// ─── Config types ──────────────────────────────────────────────────────────────

interface EvolutionConfig {
  maxRounds: number
  convergenceThreshold: number
  attackTypes: AttackTypeId[]
  samplesPerRound: number
}

type SessionState = 'idle' | 'running' | 'converged' | 'stopped' | 'error'

// ─── Chart data shape ──────────────────────────────────────────────────────────

interface RoundChartPoint {
  round: number
  detectionRate: number
  falsePositiveRate: number
  convergenceDelta: number
}

// ─── Sub-components ───────────────────────────────────────────────────────────

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
          'bg-slate-700 accent-purple-500',
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

// ─── Status bar ───────────────────────────────────────────────────────────────

interface StatusBarProps {
  state: SessionState
  currentRound: number
  maxRounds: number
  session: EvolutionSession | null
  errorMsg: string | null
}

function StatusBar({ state, currentRound, maxRounds, session, errorMsg }: StatusBarProps) {
  const progress = maxRounds > 0 ? Math.min((currentRound / maxRounds) * 100, 100) : 0

  const STATE_CONFIG = {
    idle: {
      label: 'Idle — configure and start an evolution session',
      dot: 'bg-slate-500',
      bar: 'bg-slate-600',
      text: 'text-slate-400',
    },
    running: {
      label: `Round ${currentRound} / ${maxRounds} — evolving detection…`,
      dot: 'bg-purple-400 animate-pulse',
      bar: 'bg-purple-500',
      text: 'text-purple-300',
    },
    converged: {
      label: `Converged after ${currentRound} round${currentRound !== 1 ? 's' : ''} — detection rate stabilized`,
      dot: 'bg-green-400',
      bar: 'bg-green-500',
      text: 'text-green-300',
    },
    stopped: {
      label: `Stopped at round ${currentRound}`,
      dot: 'bg-amber-400',
      bar: 'bg-amber-500',
      text: 'text-amber-300',
    },
    error: {
      label: errorMsg ?? 'An error occurred',
      dot: 'bg-red-400',
      bar: 'bg-red-500',
      text: 'text-red-300',
    },
  } as const

  const cfg = STATE_CONFIG[state]

  return (
    <div
      className="card"
      role="status"
      aria-live="polite"
      aria-label="Evolution session status"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className={['w-2 h-2 rounded-full flex-shrink-0', cfg.dot].join(' ')} aria-hidden="true" />
          <span className={['text-xs font-medium', cfg.text].join(' ')}>{cfg.label}</span>
        </div>
        {session && state !== 'idle' && (
          <span className="text-[10px] font-mono text-slate-500 tabular-nums">
            {session.id}
          </span>
        )}
      </div>

      <div className="w-full h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div
          className={['h-full rounded-full transition-all duration-500', cfg.bar].join(' ')}
          style={{ width: `${state === 'idle' ? 0 : progress}%` }}
          role="progressbar"
          aria-valuenow={state === 'idle' ? 0 : currentRound}
          aria-valuemin={0}
          aria-valuemax={maxRounds}
          aria-label={`Evolution progress: round ${currentRound} of ${maxRounds}`}
        />
      </div>

      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-slate-600">Round 0</span>
        <span className="text-[9px] text-slate-600">{maxRounds} max</span>
      </div>
    </div>
  )
}

// ─── Round KPI card ───────────────────────────────────────────────────────────

interface RoundCardProps {
  round: EvolutionRound
  isLatest: boolean
}

function RoundCard({ round, isLatest }: RoundCardProps) {
  const [expanded, setExpanded] = useState(false)

  const drPct = (round.detectionRate * 100).toFixed(1)
  const fpPct = (round.falsePositiveRate * 100).toFixed(1)
  const drAccent =
    round.detectionRate >= 0.9 ? 'text-green-400'
    : round.detectionRate >= 0.7 ? 'text-amber-400'
    : 'text-red-400'

  return (
    <div
      className={[
        'card transition-colors',
        isLatest ? 'border-purple-600/40 bg-purple-950/20' : '',
      ].join(' ')}
      aria-label={`Round ${round.round} results`}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-2 flex-shrink-0">
          <div className="w-7 h-7 rounded-lg bg-slate-700 flex items-center justify-center">
            <span className="text-[10px] font-bold text-slate-300 tabular-nums">{round.round}</span>
          </div>
          {isLatest && (
            <span className="text-[10px] font-semibold text-purple-400 bg-purple-900/40 px-1.5 py-0.5 rounded border border-purple-800/50">
              Latest
            </span>
          )}
        </div>

        <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div>
            <p className="text-[10px] text-slate-500 mb-0.5">Detection Rate</p>
            <p className={['text-base font-bold tabular-nums font-mono leading-none', drAccent].join(' ')}>
              {drPct}%
            </p>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 mb-0.5">False Positives</p>
            <p className={[
              'text-base font-bold tabular-nums font-mono leading-none',
              round.falsePositiveRate <= 0.05 ? 'text-green-400' : round.falsePositiveRate <= 0.12 ? 'text-amber-400' : 'text-red-400',
            ].join(' ')}>
              {fpPct}%
            </p>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 mb-0.5">Missed</p>
            <p className={[
              'text-base font-bold tabular-nums font-mono leading-none',
              round.missedCount === 0 ? 'text-green-400' : 'text-red-400',
            ].join(' ')}>
              {round.missedCount}
              <span className="text-xs text-slate-500 font-normal ml-0.5">/ {round.attackSamples}</span>
            </p>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 mb-0.5">Conv. Delta</p>
            <p className={[
              'text-base font-bold tabular-nums font-mono leading-none',
              round.convergenceDelta <= 0.005 ? 'text-green-400' : round.convergenceDelta <= 0.02 ? 'text-amber-400' : 'text-purple-400',
            ].join(' ')}>
              {round.convergenceDelta.toFixed(4)}
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="btn-ghost px-2 py-1 text-xs flex-shrink-0"
          aria-expanded={expanded}
          aria-label={expanded ? 'Collapse mutations' : 'Expand mutations'}
        >
          {expanded
            ? <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
            : <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
          }
        </button>
      </div>

      {expanded && (
        <div className="mt-4 pt-4 border-t border-slate-700">
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-2">
            Hardening Mutations Applied ({round.hardeningApplied.length})
          </p>
          {round.hardeningApplied.length === 0 ? (
            <p className="text-xs text-slate-600 italic">No mutations applied this round — model held stable</p>
          ) : (
            <ul className="space-y-1.5" aria-label="Hardening mutations applied">
              {round.hardeningApplied.map((mutation, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <Zap className="w-3 h-3 text-purple-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
                  <span className="text-xs text-slate-300">{mutation}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="text-[10px] text-slate-600 mt-2 font-mono">
            {new Date(round.timestamp).toLocaleTimeString('en-US', {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
              hour12: false,
            })}
          </p>
        </div>
      )}
    </div>
  )
}

// ─── Recharts: Detection Rate over rounds ─────────────────────────────────────

function DetectionRateChart({ data }: { data: RoundChartPoint[] }) {
  if (data.length < 2) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-slate-600 gap-2">
        <Activity className="w-5 h-5" aria-hidden="true" />
        <p className="text-xs">Waiting for at least 2 rounds…</p>
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart
        data={data}
        margin={{ top: 8, right: 16, left: 0, bottom: 0 }}
        aria-label="Detection rate and false positive rate over evolution rounds"
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="round"
          tick={{ fill: '#64748b', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          label={{ value: 'Round', position: 'insideBottomRight', offset: -8, fontSize: 11, fill: '#64748b' }}
        />
        <YAxis
          tick={{ fill: '#64748b', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          domain={[0, 1]}
          tickFormatter={(v: number) => `${(v * 100).toFixed(0)}%`}
          width={40}
        />
        <Tooltip
          contentStyle={{
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
          itemStyle={{ color: '#f1f5f9' }}
          labelFormatter={(label: number) => `Round ${label}`}
          formatter={(value: number, name: string) => [
            `${(value * 100).toFixed(2)}%`,
            name === 'detectionRate' ? 'Detection Rate' : 'False Positive Rate',
          ]}
        />
        <Legend
          formatter={(value) =>
            value === 'detectionRate' ? 'Detection Rate' : 'False Positive Rate'
          }
          wrapperStyle={{ fontSize: '11px', color: '#94a3b8', paddingTop: '8px' }}
        />
        <Line
          type="monotone"
          dataKey="detectionRate"
          stroke="#a855f7"
          strokeWidth={2}
          dot={{ fill: '#a855f7', r: 3, strokeWidth: 0 }}
          activeDot={{ r: 5, fill: '#a855f7' }}
        />
        <Line
          type="monotone"
          dataKey="falsePositiveRate"
          stroke="#f59e0b"
          strokeWidth={2}
          dot={{ fill: '#f59e0b', r: 3, strokeWidth: 0 }}
          activeDot={{ r: 5, fill: '#f59e0b' }}
          strokeDasharray="4 2"
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

// ─── Recharts: Convergence delta over rounds ──────────────────────────────────

function ConvergenceDeltaChart({
  data,
  threshold,
}: {
  data: RoundChartPoint[]
  threshold: number
}) {
  if (data.length < 2) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-slate-600 gap-2">
        <TrendingDown className="w-5 h-5" aria-hidden="true" />
        <p className="text-xs">Waiting for at least 2 rounds…</p>
      </div>
    )
  }

  // Build reference line data at the convergence threshold
  const thresholdData = data.map((d) => ({ ...d, threshold }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart
        data={thresholdData}
        margin={{ top: 8, right: 16, left: 0, bottom: 0 }}
        aria-label="Convergence delta over evolution rounds"
      >
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          dataKey="round"
          tick={{ fill: '#64748b', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          label={{ value: 'Round', position: 'insideBottomRight', offset: -8, fontSize: 11, fill: '#64748b' }}
        />
        <YAxis
          tick={{ fill: '#64748b', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v: number) => v.toFixed(3)}
          width={46}
        />
        <Tooltip
          contentStyle={{
            background: '#1e293b',
            border: '1px solid #334155',
            borderRadius: '8px',
            fontSize: '12px',
          }}
          labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
          itemStyle={{ color: '#f1f5f9' }}
          labelFormatter={(label: number) => `Round ${label}`}
          formatter={(value: number, name: string) => [
            value.toFixed(4),
            name === 'convergenceDelta' ? 'Conv. Delta' : 'Threshold',
          ]}
        />
        <Legend
          formatter={(value) =>
            value === 'convergenceDelta' ? 'Convergence Delta' : `Threshold (${threshold})`
          }
          wrapperStyle={{ fontSize: '11px', color: '#94a3b8', paddingTop: '8px' }}
        />
        <Line
          type="monotone"
          dataKey="convergenceDelta"
          stroke="#38bdf8"
          strokeWidth={2}
          dot={{ fill: '#38bdf8', r: 3, strokeWidth: 0 }}
          activeDot={{ r: 5, fill: '#38bdf8' }}
        />
        <Line
          type="monotone"
          dataKey="threshold"
          stroke="#ef4444"
          strokeWidth={1.5}
          strokeDasharray="6 3"
          dot={false}
          activeDot={false}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

// ─── Mutations history panel ───────────────────────────────────────────────────

function MutationsHistory({ rounds }: { rounds: EvolutionRound[] }) {
  // Flatten all mutations with their round number, newest first
  const allMutations = [...rounds]
    .reverse()
    .flatMap((r) => r.hardeningApplied.map((m) => ({ round: r.round, mutation: m })))

  if (allMutations.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-slate-600 gap-2">
        <ShieldCheck className="w-5 h-5" aria-hidden="true" />
        <p className="text-xs">No hardening mutations recorded yet</p>
      </div>
    )
  }

  return (
    <div className="space-y-2 max-h-64 overflow-y-auto pr-1" aria-label="Hardening mutation history">
      {allMutations.map(({ round, mutation }, idx) => (
        <div
          key={idx}
          className="flex items-start gap-3 py-2 border-b border-slate-700/50 last:border-0"
        >
          <div className="w-6 h-6 rounded-md bg-purple-900/40 border border-purple-800/40 flex items-center justify-center flex-shrink-0 mt-0.5">
            <span className="text-[9px] font-bold text-purple-400 tabular-nums">{round}</span>
          </div>
          <span className="text-xs text-slate-300 leading-relaxed">{mutation}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Summary KPI row ──────────────────────────────────────────────────────────

interface SummaryKpisProps {
  rounds: EvolutionRound[]
  convergenceThreshold: number
  consecutiveConvergedRounds: number
}

function SummaryKpis({ rounds, convergenceThreshold, consecutiveConvergedRounds }: SummaryKpisProps) {
  const latest = rounds[rounds.length - 1]
  const totalMutations = rounds.reduce((sum, r) => sum + r.hardeningApplied.length, 0)
  const bestDr = rounds.length > 0 ? Math.max(...rounds.map((r) => r.detectionRate)) : 0
  const isConverging = consecutiveConvergedRounds > 0

  return (
    <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
      <div className="card flex flex-col gap-1">
        <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
          Current Detection Rate
        </p>
        <p className={[
          'text-2xl font-bold tabular-nums font-mono leading-none',
          latest
            ? latest.detectionRate >= 0.9 ? 'text-green-400'
              : latest.detectionRate >= 0.7 ? 'text-amber-400'
              : 'text-red-400'
            : 'text-slate-600',
        ].join(' ')}>
          {latest ? `${(latest.detectionRate * 100).toFixed(1)}%` : '—'}
        </p>
        <p className="text-[11px] text-slate-500">
          {latest ? `FP: ${(latest.falsePositiveRate * 100).toFixed(1)}%` : 'No rounds yet'}
        </p>
      </div>

      <div className="card flex flex-col gap-1">
        <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
          Best Detection Rate
        </p>
        <p className={[
          'text-2xl font-bold tabular-nums font-mono leading-none',
          bestDr >= 0.9 ? 'text-green-400' : bestDr >= 0.7 ? 'text-amber-400' : 'text-slate-400',
        ].join(' ')}>
          {rounds.length > 0 ? `${(bestDr * 100).toFixed(1)}%` : '—'}
        </p>
        <p className="text-[11px] text-slate-500">across {rounds.length} round{rounds.length !== 1 ? 's' : ''}</p>
      </div>

      <div className="card flex flex-col gap-1">
        <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
          Mutations Applied
        </p>
        <p className="text-2xl font-bold tabular-nums font-mono leading-none text-purple-400">
          {totalMutations}
        </p>
        <p className="text-[11px] text-slate-500">
          {rounds.length > 0 ? `~${(totalMutations / rounds.length).toFixed(1)} per round` : 'No rounds yet'}
        </p>
      </div>

      <div className="card flex flex-col gap-1">
        <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">
          Convergence
        </p>
        <div className="flex items-center gap-2">
          <div className={[
            'w-2.5 h-2.5 rounded-full flex-shrink-0',
            isConverging ? 'bg-green-400' : 'bg-slate-600',
          ].join(' ')} aria-hidden="true" />
          <p className={[
            'text-2xl font-bold tabular-nums font-mono leading-none',
            isConverging ? 'text-green-400' : 'text-slate-400',
          ].join(' ')}>
            {consecutiveConvergedRounds}/3
          </p>
        </div>
        <p className="text-[11px] text-slate-500">
          δ &lt; {convergenceThreshold} for {consecutiveConvergedRounds} round{consecutiveConvergedRounds !== 1 ? 's' : ''}
        </p>
      </div>
    </div>
  )
}

// ─── HASTE Prior Art Differentiation ─────────────────────────────────────────

const HASTE_ROWS: { dimension: string; haste: string; aispm: string }[] = [
  {
    dimension: 'Attack Surface',
    haste: 'Prompt injection only',
    aispm:
      '8 attack types across 4 surfaces (training, RAG, MCP, inference)',
  },
  {
    dimension: 'Generator',
    haste: 'Static adversarial prompts',
    aispm:
      'Polymorphic payloads — 19 evasion techniques with runtime mutation',
  },
  {
    dimension: 'Scope',
    haste: 'Research prototype',
    aispm: 'PaaS-level API with multi-tenant isolation',
  },
  {
    dimension: 'Detection Targets',
    haste: 'Single classifier hardening',
    aispm:
      '5 detection engines (vector, RAG, MCP, provenance, telemetry)',
  },
  {
    dimension: 'Evolution Mechanism',
    haste: 'Re-inject misclassified prompts into training',
    aispm:
      'Cross-surface hardening: missed samples drive threshold, regex, and heuristic mutations across all engines',
  },
  {
    dimension: 'Convergence',
    haste: 'Not formally defined',
    aispm:
      'δ < threshold for 3 consecutive rounds with cryptographic proof chain',
  },
  {
    dimension: 'Output',
    haste: 'Hardened prompt classifier',
    aispm:
      'Continuously hardened multi-engine detection platform with audit trail',
  },
]

function HASTEDifferentiation() {
  return (
    <div
      className="rounded-xl border border-blue-800/40 bg-blue-950/20 p-5"
      aria-label="Prior art differentiation: HASTE vs AI-SPM Evolution Engine"
    >
      {/* Header */}
      <div className="flex items-center gap-2 mb-4">
        <BookOpen className="w-4 h-4 text-blue-400 flex-shrink-0" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-slate-200">
          Prior Art Differentiation: HASTE (NDSS 2026)
        </h2>
        <span className="ml-auto text-[10px] font-mono text-blue-500 tabular-nums">
          arXiv 2601.19051
        </span>
      </div>

      {/* Comparison table */}
      <div className="overflow-x-auto -mx-1">
        <table className="w-full text-xs border-collapse" aria-label="HASTE vs AI-SPM comparison table">
          <thead>
            <tr>
              <th
                scope="col"
                className="text-left py-2 px-3 text-[10px] font-semibold uppercase tracking-wider text-slate-500 w-[18%]"
              >
                Dimension
              </th>
              <th
                scope="col"
                className="text-left py-2 px-3 text-[10px] font-semibold uppercase tracking-wider text-blue-500/80 w-[36%]"
              >
                HASTE (arXiv 2601.19051)
              </th>
              <th
                scope="col"
                className="text-left py-2 px-3 text-[10px] font-semibold uppercase tracking-wider text-purple-400 w-[46%]"
              >
                AI-SPM Evolution Engine
              </th>
            </tr>
          </thead>
          <tbody>
            {HASTE_ROWS.map((row, idx) => (
              <tr
                key={row.dimension}
                className={idx % 2 === 0 ? 'bg-slate-800/20' : ''}
              >
                <td className="py-2.5 px-3 text-slate-400 font-medium align-top leading-snug">
                  {row.dimension}
                </td>
                <td className="py-2.5 px-3 text-slate-400 align-top leading-snug">
                  {row.haste}
                </td>
                <td className="py-2.5 px-3 align-top leading-snug">
                  <span className="font-semibold text-purple-300">
                    {row.aispm}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Default config ────────────────────────────────────────────────────────────

const DEFAULT_CONFIG: EvolutionConfig = {
  maxRounds: 20,
  convergenceThreshold: 0.01,
  attackTypes: ['prompt_injection', 'rag_poisoning', 'hidden_instruction'],
  samplesPerRound: 50,
}

// ─── Main component ───────────────────────────────────────────────────────────

export function EvolutionPanel() {
  const uid = useId()

  const [config, setConfig] = useState<EvolutionConfig>(DEFAULT_CONFIG)
  const [sessionState, setSessionState] = useState<SessionState>('idle')
  const [session, setSession] = useState<EvolutionSession | null>(null)
  const [rounds, setRounds] = useState<EvolutionRound[]>([])
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [consecutiveConverged, setConsecutiveConverged] = useState(0)

  // Abort flag — set to true by the Stop button; the loop checks it between rounds
  const abortRef = useRef(false)

  const setConfigField = useCallback(
    <K extends keyof EvolutionConfig>(key: K, value: EvolutionConfig[K]) => {
      setConfig((prev) => ({ ...prev, [key]: value }))
    },
    [],
  )

  const toggleAttackType = useCallback((id: AttackTypeId) => {
    setConfig((prev) => {
      const already = prev.attackTypes.includes(id)
      // Always keep at least one attack type selected
      if (already && prev.attackTypes.length === 1) return prev
      return {
        ...prev,
        attackTypes: already
          ? prev.attackTypes.filter((t) => t !== id)
          : [...prev.attackTypes, id],
      }
    })
  }, [])

  const handleStart = useCallback(async () => {
    abortRef.current = false
    setSessionState('running')
    setRounds([])
    setErrorMsg(null)
    setConsecutiveConverged(0)

    let activeSession: EvolutionSession
    try {
      activeSession = await startEvolutionSession({
        maxRounds: config.maxRounds,
        convergenceThreshold: config.convergenceThreshold,
        attackTypes: config.attackTypes,
        samplesPerRound: config.samplesPerRound,
      })
      setSession(activeSession)
    } catch (err) {
      setSessionState('error')
      setErrorMsg(err instanceof Error ? err.message : 'Failed to start evolution session')
      return
    }

    let consecutiveCount = 0
    const collectedRounds: EvolutionRound[] = []

    for (let i = 0; i < config.maxRounds; i++) {
      // Check abort flag before each round
      if (abortRef.current) {
        setSessionState('stopped')
        return
      }

      let round: EvolutionRound
      try {
        round = await runEvolutionRound(activeSession.id)
      } catch (err) {
        setSessionState('error')
        setErrorMsg(err instanceof Error ? err.message : 'Evolution round failed')
        return
      }

      // The mock API returns a random round number — override it to the sequential index
      const normalizedRound: EvolutionRound = { ...round, round: i + 1 }
      collectedRounds.push(normalizedRound)
      setRounds((prev) => [...prev, normalizedRound])

      // Convergence detection: delta < threshold for 3 consecutive rounds
      if (normalizedRound.convergenceDelta < config.convergenceThreshold) {
        consecutiveCount += 1
      } else {
        consecutiveCount = 0
      }
      setConsecutiveConverged(consecutiveCount)

      if (consecutiveCount >= 3) {
        setSessionState('converged')
        return
      }

      // Check abort again after receiving the result
      if (abortRef.current) {
        setSessionState('stopped')
        return
      }
    }

    // Ran all rounds without converging
    setSessionState('stopped')
  }, [config])

  const handleStop = useCallback(() => {
    abortRef.current = true
  }, [])

  const handleReset = useCallback(() => {
    abortRef.current = true
    setSessionState('idle')
    setSession(null)
    setRounds([])
    setErrorMsg(null)
    setConsecutiveConverged(0)
  }, [])

  const isRunning = sessionState === 'running'
  const hasRounds = rounds.length > 0

  const chartData: RoundChartPoint[] = rounds.map((r) => ({
    round: r.round,
    detectionRate: r.detectionRate,
    falsePositiveRate: r.falsePositiveRate,
    convergenceDelta: r.convergenceDelta,
  }))

  return (
    <div className="space-y-6">

      {/* ── Config card ── */}
      <div className="card" aria-label="Evolution configuration">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Dna className="w-4 h-4 text-purple-400" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-200">Evolution Configuration</h2>
          </div>
          {(hasRounds || sessionState !== 'idle') && (
            <button
              type="button"
              onClick={handleReset}
              disabled={isRunning}
              className="btn-ghost text-xs"
              aria-label="Reset evolution session"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              Reset
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-x-8 gap-y-5">

          <SliderField
            id={`${uid}-max-rounds`}
            label="Max Rounds"
            min={5}
            max={50}
            step={1}
            value={config.maxRounds}
            onChange={(v) => setConfigField('maxRounds', v)}
            disabled={isRunning}
          />

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label htmlFor={`${uid}-threshold`} className="text-xs font-medium text-slate-400">
                Convergence Threshold
              </label>
              <span className="text-xs font-semibold text-slate-200 tabular-nums font-mono">
                {config.convergenceThreshold}
              </span>
            </div>
            <input
              id={`${uid}-threshold`}
              type="number"
              min={0.001}
              max={0.1}
              step={0.001}
              value={config.convergenceThreshold}
              onChange={(e) => {
                const v = parseFloat(e.target.value)
                if (!isNaN(v) && v >= 0.001 && v <= 0.1) {
                  setConfigField('convergenceThreshold', v)
                }
              }}
              disabled={isRunning}
              className="field font-mono"
              aria-label="Convergence threshold (0.001–0.1)"
            />
            <p className="text-[10px] text-slate-600 mt-1">
              Auto-stop when δ &lt; threshold for 3 consecutive rounds · range 0.001–0.1
            </p>
          </div>

          <SliderField
            id={`${uid}-samples`}
            label="Samples per Round"
            min={10}
            max={200}
            step={10}
            value={config.samplesPerRound}
            onChange={(v) => setConfigField('samplesPerRound', v)}
            format={(v) => v.toLocaleString()}
            disabled={isRunning}
          />

          {/* Attack type multi-select */}
          <div className="md:col-span-2 xl:col-span-3">
            <p className="text-xs font-medium text-slate-400 mb-2" id={`${uid}-attack-types-label`}>
              Attack Types
              <span className="ml-2 text-slate-600 font-normal">
                ({config.attackTypes.length} selected)
              </span>
            </p>
            <div
              className="flex flex-wrap gap-2"
              role="group"
              aria-labelledby={`${uid}-attack-types-label`}
            >
              {ATTACK_TYPE_OPTIONS.map((opt) => {
                const selected = config.attackTypes.includes(opt.id)
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => toggleAttackType(opt.id)}
                    disabled={isRunning}
                    aria-pressed={selected}
                    className={[
                      'text-xs px-3 py-1.5 rounded-lg border transition-colors',
                      'focus:outline-none focus:ring-2 focus:ring-purple-500/50',
                      'disabled:opacity-40 disabled:cursor-not-allowed',
                      selected
                        ? 'bg-purple-900/40 border-purple-700/60 text-purple-300'
                        : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600 hover:text-slate-300',
                    ].join(' ')}
                  >
                    {opt.label}
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="mt-6 flex items-center gap-3 border-t border-slate-700 pt-5">
          <button
            type="button"
            onClick={handleStart}
            disabled={isRunning || config.attackTypes.length === 0}
            className={[
              'inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-colors',
              'focus:outline-none focus:ring-2 focus:ring-purple-500/50',
              'disabled:opacity-50 disabled:cursor-not-allowed',
              'bg-purple-600 hover:bg-purple-500 text-white',
            ].join(' ')}
            aria-label={isRunning ? 'Evolution running…' : 'Start evolution session'}
          >
            {isRunning ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                Evolving…
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" aria-hidden="true" />
                Start Evolution
              </>
            )}
          </button>

          {isRunning && (
            <button
              type="button"
              onClick={handleStop}
              className={[
                'inline-flex items-center gap-2 text-sm font-medium px-4 py-2 rounded-lg transition-colors',
                'focus:outline-none focus:ring-2 focus:ring-red-500/50',
                'bg-red-900/40 hover:bg-red-900/70 text-red-300 border border-red-800/50',
              ].join(' ')}
              aria-label="Stop evolution early"
            >
              <Square className="w-3.5 h-3.5" aria-hidden="true" />
              Stop
            </button>
          )}

          {sessionState === 'converged' && (
            <div role="status" className="flex items-center gap-1.5 text-xs text-green-400">
              <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
              Converged after {rounds.length} round{rounds.length !== 1 ? 's' : ''}
            </div>
          )}

          {sessionState === 'error' && errorMsg && (
            <div role="alert" className="flex items-center gap-1.5 text-xs text-red-400">
              <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
              {errorMsg}
            </div>
          )}
        </div>
      </div>

      {/* ── Status bar (shown once a session starts) ── */}
      {sessionState !== 'idle' && (
        <StatusBar
          state={sessionState}
          currentRound={rounds.length}
          maxRounds={config.maxRounds}
          session={session}
          errorMsg={errorMsg}
        />
      )}

      {/* ── Prior art differentiation (always visible) ── */}
      <HASTEDifferentiation />

      {/* ── Live results (shown as soon as any round data arrives) ── */}
      {hasRounds && (
        <div className="space-y-4" aria-label="Evolution results" role="region">

          {/* Summary KPIs */}
          <SummaryKpis
            rounds={rounds}
            convergenceThreshold={config.convergenceThreshold}
            consecutiveConvergedRounds={consecutiveConverged}
          />

          {/* Charts row */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

            {/* Detection rate + false positive rate */}
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <Activity className="w-4 h-4 text-purple-400" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-200">Detection & False Positive Rates</h3>
                <span className="ml-auto text-[10px] text-slate-600">per round</span>
              </div>
              <DetectionRateChart data={chartData} />
            </div>

            {/* Convergence delta */}
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <TrendingDown className="w-4 h-4 text-sky-400" aria-hidden="true" />
                <h3 className="text-sm font-semibold text-slate-200">Convergence Delta</h3>
                <span className="ml-auto text-[10px] text-slate-600">
                  threshold: {config.convergenceThreshold}
                </span>
              </div>
              <ConvergenceDeltaChart data={chartData} threshold={config.convergenceThreshold} />
            </div>
          </div>

          {/* Round-by-round cards + mutations history side-by-side on xl */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

            {/* Per-round cards — takes 2/3 of the xl grid */}
            <div className="xl:col-span-2 space-y-3">
              <p className="section-heading">Round History</p>
              <div className="space-y-2">
                {[...rounds].reverse().map((round) => (
                  <RoundCard
                    key={round.round}
                    round={round}
                    isLatest={round.round === rounds[rounds.length - 1].round}
                  />
                ))}
              </div>
            </div>

            {/* Mutations history — takes 1/3 */}
            <div>
              <p className="section-heading">Hardening Mutations</p>
              <div className="card">
                <div className="flex items-center gap-2 mb-4">
                  <ShieldCheck className="w-4 h-4 text-green-400" aria-hidden="true" />
                  <h3 className="text-sm font-semibold text-slate-200">Applied Mutations</h3>
                  <span className="ml-auto text-[10px] text-slate-600">newest first</span>
                </div>
                <MutationsHistory rounds={rounds} />
              </div>
            </div>
          </div>

        </div>
      )}
    </div>
  )
}
