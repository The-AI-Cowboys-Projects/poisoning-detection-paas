/**
 * Dashboard home — AI-SPM overview with KPI cards, time-series chart,
 * threat breakdown donut, and recent alerts table.
 *
 * Server component: data fetched at request time.
 * Charts are client components rendered in <ChartWrapper>.
 */

import type { Metadata } from 'next'
import { ScanSearch, ShieldAlert, Radio, Zap } from 'lucide-react'
import { MetricCard } from '@/components/MetricCard'
import { ThreatBadge } from '@/components/ThreatBadge'
import { DashboardCharts } from './DashboardCharts'
import {
  fetchMetrics,
  fetchTimeSeries,
  fetchThreatBreakdown,
  fetchRecentAlerts,
} from '@/lib/api'
import { formatDistanceToNow } from 'date-fns'

export const metadata: Metadata = { title: 'Dashboard' }

// Revalidate every 60 s (ISR)
export const revalidate = 60

// ─── Alert status badge ───────────────────────────────────────────────────────

function StatusPill({ status }: { status: 'open' | 'acknowledged' | 'resolved' }) {
  const styles = {
    open:         'bg-red-900/50 text-red-300 border-red-800',
    acknowledged: 'bg-amber-900/50 text-amber-300 border-amber-800',
    resolved:     'bg-green-900/50 text-green-300 border-green-800',
  }
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${styles[status]}`}>
      {status}
    </span>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default async function DashboardPage() {
  const [metrics, timeSeries, breakdown, alerts] = await Promise.all([
    fetchMetrics(),
    fetchTimeSeries(14),
    fetchThreatBreakdown(),
    fetchRecentAlerts(8),
  ])

  return (
    <div className="space-y-6 animate-fade-in">
      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">AI-SPM Dashboard</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Tenant: <span className="text-slate-300 font-medium">Acme Corp</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-xs text-green-400 bg-green-900/30 border border-green-800/50 px-3 py-1.5 rounded-full">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse-slow" aria-hidden="true" />
            Live monitoring active
          </span>
        </div>
      </div>

      {/* ── KPI cards ── */}
      <section aria-label="Key performance indicators">
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <MetricCard
            label="Total Scans"
            value={metrics.totalScans}
            delta={metrics.totalScansChange}
            deltaLabel="vs last 14 days"
            icon={<ScanSearch className="w-5 h-5" aria-hidden="true" />}
            accentColor="blue"
          />
          <MetricCard
            label="Threats Detected"
            value={metrics.threatsDetected}
            delta={metrics.threatsDetectedChange}
            deltaLabel="vs last 14 days"
            icon={<ShieldAlert className="w-5 h-5" aria-hidden="true" />}
            accentColor="red"
            invertDelta
          />
          <MetricCard
            label="Active Monitors"
            value={metrics.activeMonitors}
            delta={metrics.activeMonitorsChange}
            deltaLabel="vs last 14 days"
            icon={<Radio className="w-5 h-5" aria-hidden="true" />}
            accentColor="green"
          />
          <MetricCard
            label="Threat Velocity"
            value={`${metrics.threatVelocity}/hr`}
            delta={metrics.threatVelocityChange}
            deltaLabel="vs last 14 days"
            icon={<Zap className="w-5 h-5" aria-hidden="true" />}
            accentColor="amber"
            invertDelta
          />
        </div>
      </section>

      {/* ── Charts (client component) ── */}
      <DashboardCharts timeSeries={timeSeries} breakdown={breakdown} />

      {/* ── Recent alerts table ── */}
      <section aria-label="Recent alerts">
        <div className="card">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-sm font-semibold text-slate-200">Recent Alerts</h2>
            <a
              href="/alerts"
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              View all
            </a>
          </div>

          <div className="overflow-x-auto -mx-5 px-5">
            <table className="data-table" aria-label="Recent threat alerts">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Type</th>
                  <th>Message</th>
                  <th>Time</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <ThreatBadge
                        severity={alert.severity}
                        size="sm"
                        pulse={alert.status === 'open' && alert.severity === 'critical'}
                      />
                    </td>
                    <td>
                      <span className="text-slate-300 font-medium text-xs">
                        {alert.typeLabel}
                      </span>
                    </td>
                    <td>
                      <span className="text-slate-400 text-xs truncate block max-w-xs">
                        {alert.message}
                      </span>
                    </td>
                    <td>
                      <time
                        dateTime={alert.timestamp}
                        className="text-slate-500 text-xs whitespace-nowrap"
                      >
                        {formatDistanceToNow(new Date(alert.timestamp), {
                          addSuffix: true,
                        })}
                      </time>
                    </td>
                    <td>
                      <StatusPill status={alert.status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  )
}
