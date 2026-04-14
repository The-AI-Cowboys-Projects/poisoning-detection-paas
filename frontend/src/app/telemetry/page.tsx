/**
 * Telemetry Simulator page — synthetic telemetry generation and behavioral
 * anomaly detection across attack scenarios.
 *
 * Usage:
 *   Navigating to /telemetry renders the scenario selector and delegates
 *   simulation config + results to the client component <SimulationPanel />.
 */

import type { Metadata } from 'next'
import {
  Activity,
  Brain,
  Shield,
  Zap,
  AlertTriangle,
  Network,
  Clock,
  Bug,
  type LucideIcon,
} from 'lucide-react'
import { SimulationPanel } from './SimulationPanel'

export const metadata: Metadata = { title: 'Telemetry Simulator' }

// ─── Scenario definitions ─────────────────────────────────────────────────────

type ScenarioColor =
  | 'green'
  | 'red'
  | 'purple'
  | 'amber'
  | 'orange'
  | 'pink'
  | 'yellow'

interface Scenario {
  id: string
  name: string
  icon: LucideIcon
  description: string
  color: ScenarioColor
  /** Brief note on what signals to expect */
  signals: string
}

const SCENARIOS: Scenario[] = [
  {
    id: 'clean',
    name: 'Clean Baseline',
    icon: Shield,
    description: 'Normal operational telemetry',
    color: 'green',
    signals: 'Low risk scores, no anomalous spans, uniform tool calls',
  },
  {
    id: 'reward_hacking',
    name: 'Reward Hacking',
    icon: Zap,
    description: 'Agent games reward metrics',
    color: 'red',
    signals: 'Inflated reward signals, metric-targeted span clusters',
  },
  {
    id: 'memory_poisoning',
    name: 'Memory Poisoning',
    icon: Brain,
    description: 'Corrupted agent memory',
    color: 'purple',
    signals: 'Unexpected memory reads, embedding drift in retrieval spans',
  },
  {
    id: 'prompt_drift',
    name: 'Prompt Drift',
    icon: Activity,
    description: 'Gradual distribution shift',
    color: 'amber',
    signals: 'Rising KL divergence across prompt windows, slow baseline decay',
  },
  {
    id: 'retrieval_manipulation',
    name: 'Retrieval Manipulation',
    icon: AlertTriangle,
    description: 'RAG pipeline injection',
    color: 'orange',
    signals: 'High cosine deviation on retrieved chunks, injected context spans',
  },
  {
    id: 'tool_hijack',
    name: 'Tool Hijack',
    icon: Bug,
    description: 'MCP tool redirection',
    color: 'red',
    signals: 'Off-schema tool calls, novel tool_name values, privilege escalation',
  },
  {
    id: 'multi_agent_collusion',
    name: 'Multi-Agent Collusion',
    icon: Network,
    description: 'Coordinated agent attack',
    color: 'pink',
    signals: 'Correlated anomaly bursts across agent_ids, shared root cause spans',
  },
  {
    id: 'slow_burn',
    name: 'Slow Burn',
    icon: Clock,
    description: 'Gradual accumulation',
    color: 'yellow',
    signals: 'Sub-threshold individual traces, compound risk growth over time window',
  },
]

// ─── Color maps ───────────────────────────────────────────────────────────────

const ICON_BG: Record<ScenarioColor, string> = {
  green:  'bg-green-900/50 text-green-400',
  red:    'bg-red-900/50 text-red-400',
  purple: 'bg-purple-900/50 text-purple-400',
  amber:  'bg-amber-900/50 text-amber-400',
  orange: 'bg-orange-900/50 text-orange-400',
  pink:   'bg-pink-900/50 text-pink-400',
  yellow: 'bg-yellow-900/40 text-yellow-400',
}

const BORDER_ACCENT: Record<ScenarioColor, string> = {
  green:  'border-green-800/40',
  red:    'border-red-800/40',
  purple: 'border-purple-800/40',
  amber:  'border-amber-800/40',
  orange: 'border-orange-800/40',
  pink:   'border-pink-800/40',
  yellow: 'border-yellow-800/40',
}

const SIGNAL_TEXT: Record<ScenarioColor, string> = {
  green:  'text-green-400',
  red:    'text-red-400',
  purple: 'text-purple-400',
  amber:  'text-amber-400',
  orange: 'text-orange-400',
  pink:   'text-pink-400',
  yellow: 'text-yellow-400',
}

// ─── Scenario card (server-rendered) ─────────────────────────────────────────

function ScenarioCard({ scenario }: { scenario: Scenario }) {
  const Icon = scenario.icon
  return (
    <div
      className={[
        'card border transition-shadow hover:shadow-lg hover:border-opacity-80',
        BORDER_ACCENT[scenario.color],
      ].join(' ')}
      aria-label={`Scenario: ${scenario.name}`}
    >
      <div className="flex items-start gap-3">
        <div
          className={[
            'w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0',
            ICON_BG[scenario.color],
          ].join(' ')}
          aria-hidden="true"
        >
          <Icon className="w-4.5 h-4.5" style={{ width: '18px', height: '18px' }} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-200 leading-snug">
            {scenario.name}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">{scenario.description}</p>
        </div>
      </div>
      <p
        className={[
          'mt-3 text-[10px] leading-relaxed pt-3 border-t border-slate-700',
          SIGNAL_TEXT[scenario.color],
        ].join(' ')}
      >
        <span className="text-slate-600 font-semibold uppercase tracking-wide text-[9px] mr-1">
          Signals:
        </span>
        {scenario.signals}
      </p>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function TelemetryPage() {
  return (
    <div className="space-y-8 animate-fade-in">

      {/* ── Header ── */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Telemetry Simulator</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          Synthetic telemetry generation and behavioral anomaly detection
        </p>
      </div>

      {/* ── Scenario selector ── */}
      <section aria-label="Attack scenario selector">
        <p className="section-heading">Attack Scenarios</p>
        <p className="text-xs text-slate-500 -mt-3 mb-4">
          Select a scenario in the simulation controls below to generate synthetic traces
          with the corresponding poisoning pattern.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {SCENARIOS.map((scenario) => (
            <ScenarioCard key={scenario.id} scenario={scenario} />
          ))}
        </div>
      </section>

      {/* ── Simulation panel (client component — config, run, results) ── */}
      <section aria-label="Simulation configuration and results">
        <SimulationPanel scenarios={SCENARIOS.map((s) => ({ id: s.id, name: s.name }))} />
      </section>

    </div>
  )
}
