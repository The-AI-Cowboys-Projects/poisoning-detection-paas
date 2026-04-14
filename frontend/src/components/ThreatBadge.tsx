/**
 * ThreatBadge — severity pill with optional animated pulse dot.
 *
 * Usage:
 *   <ThreatBadge severity="critical" />
 *   <ThreatBadge severity="warning" label="High Risk" pulse />
 */

import type { ThreatSeverity } from '@/lib/types'

interface ThreatBadgeProps {
  severity: ThreatSeverity
  /** Override the display text. Defaults to capitalised severity name. */
  label?: string
  /** Show a pulsing dot for active/live alerts. */
  pulse?: boolean
  size?: 'sm' | 'md'
}

const SEVERITY_STYLES: Record<
  ThreatSeverity,
  { wrapper: string; dot: string; text: string }
> = {
  critical: {
    wrapper: 'bg-red-950 border-red-900 text-red-300',
    dot: 'bg-red-400',
    text: 'Critical',
  },
  warning: {
    wrapper: 'bg-amber-950 border-amber-900 text-amber-300',
    dot: 'bg-amber-400',
    text: 'Warning',
  },
  safe: {
    wrapper: 'bg-green-950 border-green-900 text-green-300',
    dot: 'bg-green-400',
    text: 'Safe',
  },
  info: {
    wrapper: 'bg-blue-950 border-blue-900 text-blue-300',
    dot: 'bg-blue-400',
    text: 'Info',
  },
}

const SIZE_CLASSES: Record<'sm' | 'md', { badge: string; dot: string }> = {
  sm: { badge: 'px-1.5 py-0.5 text-[10px] gap-1', dot: 'w-1.5 h-1.5' },
  md: { badge: 'px-2.5 py-1 text-xs gap-1.5',     dot: 'w-2 h-2' },
}

export function ThreatBadge({
  severity,
  label,
  pulse = false,
  size = 'md',
}: ThreatBadgeProps) {
  const styles = SEVERITY_STYLES[severity]
  const sizes = SIZE_CLASSES[size]

  return (
    <span
      className={[
        'inline-flex items-center font-semibold rounded-full border',
        styles.wrapper,
        sizes.badge,
      ].join(' ')}
      aria-label={`Severity: ${label ?? styles.text}`}
    >
      <span
        className={[
          'rounded-full flex-shrink-0',
          styles.dot,
          sizes.dot,
          pulse ? 'animate-pulse-slow' : '',
        ].join(' ')}
        aria-hidden="true"
      />
      {label ?? styles.text}
    </span>
  )
}
