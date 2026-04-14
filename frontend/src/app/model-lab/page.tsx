/**
 * Model Lab — Local LLM integration for detection hardening.
 *
 * Connect local models (Ollama, llama.cpp, vLLM, custom endpoints) to:
 *   1. Run LLM-as-a-judge evaluation on generated poison samples
 *   2. Power autonomous detection agents that scan for poisoning
 *   3. Self-improve detection heuristics through iterative testing
 */

import type { Metadata } from 'next'
import {
  FlaskConical,
  Bot,
  ShieldCheck,
  Zap,
  BarChart3,
  RefreshCw,
  type LucideIcon,
} from 'lucide-react'
import { ModelLabPanel } from './ModelLabPanel'

export const metadata: Metadata = { title: 'Model Lab — Local LLM Detection' }

// ─── Capability cards ────────────────────────────────────────────────────────

interface CapabilityInfo {
  name: string
  icon: LucideIcon
  description: string
  color: string
  borderColor: string
}

const CAPABILITIES: CapabilityInfo[] = [
  {
    name: 'LLM-as-a-Judge',
    icon: ShieldCheck,
    description: 'Evaluate generated poison samples against a local model — test whether your samples fool the evaluator',
    color: 'bg-blue-900/50 text-blue-400',
    borderColor: 'border-blue-800/40',
  },
  {
    name: 'Detection Agent',
    icon: Bot,
    description: 'Autonomous agent that scans text, documents, and tool schemas for poisoning indicators using local inference',
    color: 'bg-emerald-900/50 text-emerald-400',
    borderColor: 'border-emerald-800/40',
  },
  {
    name: 'Self-Evolution Loop',
    icon: RefreshCw,
    description: 'Iterative self-improvement: generate attacks → evaluate → harden detection → repeat until convergence',
    color: 'bg-violet-900/50 text-violet-400',
    borderColor: 'border-violet-800/40',
  },
  {
    name: 'Benchmark Suite',
    icon: BarChart3,
    description: 'Run standardized detection benchmarks across models — compare accuracy, false positive rates, and latency',
    color: 'bg-amber-900/50 text-amber-400',
    borderColor: 'border-amber-800/40',
  },
]

function CapabilityCard({ cap }: { cap: CapabilityInfo }) {
  const Icon = cap.icon
  return (
    <div className={`card border transition-shadow hover:shadow-lg hover:border-opacity-80 ${cap.borderColor}`}>
      <div className="flex items-start gap-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${cap.color}`}>
          <Icon className="w-4.5 h-4.5" style={{ width: '18px', height: '18px' }} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-200 leading-snug">{cap.name}</p>
          <p className="text-xs text-slate-500 mt-0.5">{cap.description}</p>
        </div>
      </div>
    </div>
  )
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function ModelLabPage() {
  return (
    <div className="space-y-8 animate-fade-in">

      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-violet-900/40 border border-violet-800/50 flex items-center justify-center">
            <FlaskConical className="w-5 h-5 text-violet-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Model Lab</h1>
            <p className="text-sm text-slate-400 mt-0.5">
              Local LLM integration for detection hardening, evaluation, and self-improvement
            </p>
          </div>
        </div>
        <div className="mt-4 bg-violet-950/30 border border-violet-800/40 rounded-lg px-4 py-3">
          <div className="flex items-start gap-2">
            <Zap className="w-4 h-4 text-violet-300 flex-shrink-0 mt-0.5" aria-hidden="true" />
            <p className="text-xs text-violet-300">
              Connect local models (Ollama, llama.cpp, vLLM, LM Studio, or any OpenAI-compatible endpoint)
              to power detection agents, evaluate poison samples, and iteratively harden your defenses.
              Compatible with MiniMax M2.7, Gemma, Llama, Mistral, Qwen, and any GGUF model.
            </p>
          </div>
        </div>
      </div>

      {/* Capability cards */}
      <section aria-label="Model Lab capabilities">
        <p className="section-heading">Capabilities</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {CAPABILITIES.map(cap => (
            <CapabilityCard key={cap.name} cap={cap} />
          ))}
        </div>
      </section>

      {/* Main panel */}
      <section aria-label="Model Lab controls">
        <ModelLabPanel />
      </section>

    </div>
  )
}
