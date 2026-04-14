/**
 * ChartWrapper — responsive container for Recharts charts with loading skeleton
 * and error boundary fallback.
 *
 * Usage:
 *   <ChartWrapper title="Scan Volume" height={260} loading={isLoading}>
 *     <AreaChart data={data}>...</AreaChart>
 *   </ChartWrapper>
 */

'use client'

import { type ReactNode, Component, type ErrorInfo } from 'react'
import { AlertTriangle } from 'lucide-react'
import { ResponsiveContainer } from 'recharts'

interface ChartWrapperProps {
  title?: string
  subtitle?: string
  height?: number
  loading?: boolean
  error?: string | null
  children: ReactNode
  /** Extra classes for the outer card container. */
  className?: string
  /** Action slot rendered top-right of the card header. */
  action?: ReactNode
}

// ─── Error boundary ───────────────────────────────────────────────────────────

interface ErrorBoundaryState {
  hasError: boolean
  message: string
}

class ChartErrorBoundary extends Component<
  { children: ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: ReactNode }) {
    super(props)
    this.state = { hasError: false, message: '' }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, message: error.message }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('[ChartWrapper] Render error:', error, info)
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-2 text-slate-500">
          <AlertTriangle className="w-6 h-6 text-amber-500" aria-hidden="true" />
          <p className="text-sm">Chart failed to render</p>
          <p className="text-xs text-slate-600 font-mono">{this.state.message}</p>
        </div>
      )
    }
    return this.props.children
  }
}

// ─── Skeleton ─────────────────────────────────────────────────────────────────

function ChartSkeleton({ height }: { height: number }) {
  return (
    <div
      className="animate-pulse rounded-lg bg-slate-700/30 w-full"
      style={{ height }}
      aria-label="Loading chart"
      role="status"
    >
      {/* Simulated chart bars */}
      <div className="flex items-end gap-1 px-6 pt-8 h-full pb-4">
        {Array.from({ length: 20 }, (_, i) => (
          <div
            key={i}
            className="flex-1 bg-slate-700 rounded-t"
            style={{ height: `${20 + Math.sin(i * 0.6) * 30 + 30}%` }}
          />
        ))}
      </div>
    </div>
  )
}

// ─── Main wrapper ─────────────────────────────────────────────────────────────

export function ChartWrapper({
  title,
  subtitle,
  height = 260,
  loading = false,
  error = null,
  children,
  className = '',
  action,
}: ChartWrapperProps) {
  return (
    <div className={`card ${className}`}>
      {(title || action) && (
        <div className="flex items-start justify-between mb-5">
          <div>
            {title && (
              <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
            )}
            {subtitle && (
              <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>
            )}
          </div>
          {action && <div className="flex-shrink-0">{action}</div>}
        </div>
      )}

      {error ? (
        <div
          className="flex flex-col items-center justify-center gap-2 text-slate-500"
          style={{ height }}
          role="alert"
        >
          <AlertTriangle className="w-6 h-6 text-amber-500" aria-hidden="true" />
          <p className="text-sm">{error}</p>
        </div>
      ) : loading ? (
        <ChartSkeleton height={height} />
      ) : (
        <ChartErrorBoundary>
          <ResponsiveContainer width="100%" height={height}>
            {children as React.ReactElement}
          </ResponsiveContainer>
        </ChartErrorBoundary>
      )}
    </div>
  )
}
