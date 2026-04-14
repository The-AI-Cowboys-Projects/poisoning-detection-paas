/**
 * MetricCard — KPI card with label, large value, trend delta, and icon slot.
 *
 * Usage:
 *   <MetricCard
 *     label="Total Scans"
 *     value="14,832"
 *     delta={12.4}
 *     deltaLabel="vs last 14 days"
 *     icon={<ScanSearch className="w-5 h-5" />}
 *     accentColor="blue"
 *   />
 */

import type { ReactNode } from 'react'
import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

type AccentColor = 'blue' | 'red' | 'amber' | 'green' | 'purple'

interface MetricCardProps {
  label: string
  value: string | number
  /** Percentage change vs reference period. Positive = up, negative = down. */
  delta?: number
  deltaLabel?: string
  icon?: ReactNode
  accentColor?: AccentColor
  /** When true, a higher delta is considered bad (e.g. threats detected). */
  invertDelta?: boolean
  loading?: boolean
}

const ACCENT_CLASSES: Record<AccentColor, { icon: string; border: string }> = {
  blue:   { icon: 'text-blue-400 bg-blue-900/40',   border: 'border-blue-800/50' },
  red:    { icon: 'text-red-400 bg-red-900/40',     border: 'border-red-800/50'  },
  amber:  { icon: 'text-amber-400 bg-amber-900/40', border: 'border-amber-800/50'},
  green:  { icon: 'text-green-400 bg-green-900/40', border: 'border-green-800/50'},
  purple: { icon: 'text-purple-400 bg-purple-900/40', border: 'border-purple-800/50'},
}

function DeltaChip({
  delta,
  invert,
}: {
  delta: number
  invert: boolean
}) {
  const isNeutral = delta === 0
  const isPositive = delta > 0
  // "good" means positive delta on a good metric OR negative delta on an inverted metric
  const isGood = invert ? !isPositive : isPositive

  if (isNeutral) {
    return (
      <span className="delta-neutral inline-flex items-center gap-0.5">
        <Minus className="w-3 h-3" aria-hidden="true" />
        {Math.abs(delta).toFixed(1)}%
      </span>
    )
  }

  return isGood ? (
    <span className="delta-up inline-flex items-center gap-0.5">
      <TrendingUp className="w-3 h-3" aria-hidden="true" />
      {isPositive ? '+' : ''}{delta.toFixed(1)}%
    </span>
  ) : (
    <span className="delta-down inline-flex items-center gap-0.5">
      <TrendingDown className="w-3 h-3" aria-hidden="true" />
      {isPositive ? '+' : ''}{delta.toFixed(1)}%
    </span>
  )
}

export function MetricCard({
  label,
  value,
  delta,
  deltaLabel,
  icon,
  accentColor = 'blue',
  invertDelta = false,
  loading = false,
}: MetricCardProps) {
  const accent = ACCENT_CLASSES[accentColor]

  if (loading) {
    return (
      <div className={`card border ${accent.border} animate-pulse`} aria-busy="true">
        <div className="flex items-start justify-between mb-4">
          <div className="h-4 w-24 bg-slate-700 rounded" />
          <div className="w-10 h-10 bg-slate-700 rounded-lg" />
        </div>
        <div className="h-8 w-32 bg-slate-700 rounded mb-2" />
        <div className="h-3 w-20 bg-slate-700 rounded" />
      </div>
    )
  }

  return (
    <div className={`card border ${accent.border} transition-shadow hover:shadow-lg`}>
      <div className="flex items-start justify-between mb-3">
        <p className="text-sm font-medium text-slate-400 leading-tight">{label}</p>
        {icon && (
          <div
            className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${accent.icon}`}
            aria-hidden="true"
          >
            {icon}
          </div>
        )}
      </div>

      <p className="text-3xl font-bold text-slate-100 tabular-nums tracking-tight">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>

      {delta !== undefined && (
        <div className="mt-2 flex items-center gap-1.5 flex-wrap">
          <DeltaChip delta={delta} invert={invertDelta} />
          {deltaLabel && (
            <span className="text-xs text-slate-500">{deltaLabel}</span>
          )}
        </div>
      )}
    </div>
  )
}
