/**
 * Synthetic Poison Generator — Red Team data generation for testing
 * LLM/SLM resilience against state-of-the-art poisoning attacks.
 *
 * Techniques: AutoBackdoor pipelines, adversarial decoding, DDIPE,
 * Virus Infection Attack simulation, ASCII smuggling, homoglyph injection.
 */

import type { Metadata } from 'next'
import {
  Skull,
  FlaskConical,
  ShieldAlert,
  Bug,
  Eye,
  EyeOff,
  Fingerprint,
  Network,
  FileCode2,
  type LucideIcon,
} from 'lucide-react'
import { PoisonGenerator } from './PoisonGenerator'

export const metadata: Metadata = { title: 'Synthetic Poison Generator' }

// ─── Attack category definitions ────────────────────────────────────────────

type CategoryColor = 'red' | 'orange' | 'purple' | 'amber' | 'pink' | 'yellow' | 'cyan'

interface AttackCategoryInfo {
  id: string
  name: string
  icon: LucideIcon
  description: string
  color: CategoryColor
  techniques: string
}

const CATEGORIES: AttackCategoryInfo[] = [
  {
    id: 'training_poisoning',
    name: 'Training Data Poisoning',
    icon: FlaskConical,
    description: 'Malicious instruction-response pairs for fine-tuning attacks',
    color: 'red',
    techniques: 'AutoBackdoor agent pipelines, gradient-aligned payloads, epoch-targeted drift',
  },
  {
    id: 'prompt_injection',
    name: 'Prompt Injection',
    icon: ShieldAlert,
    description: 'Inputs that override system prompts and hijack model behavior',
    color: 'orange',
    techniques: 'Direct override, context switching, delimiter attacks, encoded payloads',
  },
  {
    id: 'rag_document_poisoning',
    name: 'RAG Document Poisoning',
    icon: FileCode2,
    description: 'Documents with hidden instructions activated during retrieval',
    color: 'purple',
    techniques: 'DDIPE, adversarial decoding optimization, cosine-maximized injections',
  },
  {
    id: 'embedding_manipulation',
    name: 'Embedding Manipulation',
    icon: Network,
    description: 'Vectors crafted to mislead similarity search and retrieval',
    color: 'amber',
    techniques: 'Perturbation attacks, cluster drift, split-view poisoning vectors',
  },
  {
    id: 'backdoor_trigger',
    name: 'Backdoor Triggers',
    icon: Eye,
    description: 'Sleeper agent samples with hidden activation phrases',
    color: 'pink',
    techniques: 'Semantic triggers, token-level backdoors, activation rate tuning',
  },
  {
    id: 'instruction_hijacking',
    name: 'Instruction Hijacking',
    icon: Bug,
    description: 'Fine-tuning data that gradually shifts alignment over epochs',
    color: 'yellow',
    techniques: 'Gradual drift injection, VIA propagation, cumulative subversion',
  },
  {
    id: 'data_exfiltration',
    name: 'Data Exfiltration',
    icon: Fingerprint,
    description: 'Inputs that cause models to leak training data or system prompts',
    color: 'cyan',
    techniques: 'Role-play extraction, encoding tricks, continuation attacks',
  },
  {
    id: 'alignment_subversion',
    name: 'Alignment Subversion',
    icon: EyeOff,
    description: 'Subtle samples that erode safety guardrails over fine-tuning',
    color: 'red',
    techniques: 'ASCII smuggling, Unicode tag injection, safety boundary erosion',
  },
]

// ─── Color maps ─────────────────────────────────────────────────────────────

const ICON_BG: Record<CategoryColor, string> = {
  red:    'bg-red-900/50 text-red-400',
  orange: 'bg-orange-900/50 text-orange-400',
  purple: 'bg-purple-900/50 text-purple-400',
  amber:  'bg-amber-900/50 text-amber-400',
  pink:   'bg-pink-900/50 text-pink-400',
  yellow: 'bg-yellow-900/40 text-yellow-400',
  cyan:   'bg-cyan-900/50 text-cyan-400',
}

const BORDER_ACCENT: Record<CategoryColor, string> = {
  red:    'border-red-800/40',
  orange: 'border-orange-800/40',
  purple: 'border-purple-800/40',
  amber:  'border-amber-800/40',
  pink:   'border-pink-800/40',
  yellow: 'border-yellow-800/40',
  cyan:   'border-cyan-800/40',
}

const TECHNIQUE_TEXT: Record<CategoryColor, string> = {
  red:    'text-red-400',
  orange: 'text-orange-400',
  purple: 'text-purple-400',
  amber:  'text-amber-400',
  pink:   'text-pink-400',
  yellow: 'text-yellow-400',
  cyan:   'text-cyan-400',
}

// ─── Category card ──────────────────────────────────────────────────────────

function CategoryCard({ category }: { category: AttackCategoryInfo }) {
  const Icon = category.icon
  return (
    <div
      className={[
        'card border transition-shadow hover:shadow-lg hover:border-opacity-80',
        BORDER_ACCENT[category.color],
      ].join(' ')}
      aria-label={`Attack category: ${category.name}`}
    >
      <div className="flex items-start gap-3">
        <div
          className={[
            'w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0',
            ICON_BG[category.color],
          ].join(' ')}
          aria-hidden="true"
        >
          <Icon className="w-4.5 h-4.5" style={{ width: '18px', height: '18px' }} />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-200 leading-snug">
            {category.name}
          </p>
          <p className="text-xs text-slate-500 mt-0.5">{category.description}</p>
        </div>
      </div>
      <p
        className={[
          'mt-3 text-[10px] leading-relaxed pt-3 border-t border-slate-700',
          TECHNIQUE_TEXT[category.color],
        ].join(' ')}
      >
        <span className="text-slate-600 font-semibold uppercase tracking-wide text-[9px] mr-1">
          Techniques:
        </span>
        {category.techniques}
      </p>
    </div>
  )
}

// ─── Page ───────────────────────────────────────────────────────────────────

export default function GeneratorPage() {
  return (
    <div className="space-y-8 animate-fade-in">

      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-900/40 border border-red-800/50 flex items-center justify-center">
            <Skull className="w-5 h-5 text-red-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Synthetic Poison Generator</h1>
            <p className="text-sm text-slate-400 mt-0.5">
              Red team data generation for testing LLM/SLM resilience against poisoning attacks
            </p>
          </div>
        </div>
        <div className="mt-4 bg-red-950/30 border border-red-800/40 rounded-lg px-4 py-3">
          <p className="text-xs text-red-300">
            <span className="font-semibold">Research Use Only.</span>{' '}
            This module generates synthetic adversarial data for authorized security testing,
            red team exercises, and detection system validation. Generated samples should only
            be used within sandboxed environments.
          </p>
        </div>
      </div>

      {/* Attack category cards */}
      <section aria-label="Attack category reference">
        <p className="section-heading">Attack Categories</p>
        <p className="text-xs text-slate-500 -mt-3 mb-4">
          Select a category below to generate synthetic poisoning samples using state-of-the-art
          techniques including AutoBackdoor pipelines, adversarial decoding, DDIPE, VIA simulation,
          and ASCII smuggling.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3">
          {CATEGORIES.map(cat => (
            <CategoryCard key={cat.id} category={cat} />
          ))}
        </div>
      </section>

      {/* Generator panel */}
      <section aria-label="Poison data generator controls and output">
        <PoisonGenerator />
      </section>

    </div>
  )
}
