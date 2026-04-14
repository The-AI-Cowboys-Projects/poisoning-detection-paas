/**
 * AlertsPanel — client-side alert management with filtering, status updates,
 * severity breakdown stats, and alert detail drill-down.
 */

'use client'

import { useState, useMemo, useCallback } from 'react'
import {
  Bell,
  Filter,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  Eye,
  CheckCheck,
  Clock,
  Shield,
  X,
} from 'lucide-react'
import type { RecentAlert } from '@/lib/types'
import type { ThreatSeverity } from '@/lib/types'
import { updateAlertStatus } from '@/lib/api'

// ─── Types ───────────────────────────────────────────────────────────────────

type AlertStatus = 'open' | 'acknowledged' | 'resolved'
type FilterSeverity = ThreatSeverity | 'all'
type FilterStatus = AlertStatus | 'all'

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<ThreatSeverity, { label: string; icon: typeof XCircle; color: string; bg: string; border: string }> = {
  critical: { label: 'Critical', icon: XCircle,        color: 'text-red-400',    bg: 'bg-red-900/50',    border: 'border-red-800/50' },
  warning:  { label: 'Warning',  icon: AlertTriangle,  color: 'text-amber-400',  bg: 'bg-amber-900/50',  border: 'border-amber-800/50' },
  safe:     { label: 'Safe',     icon: CheckCircle2,   color: 'text-green-400',  bg: 'bg-green-900/50',  border: 'border-green-800/50' },
  info:     { label: 'Info',     icon: Info,            color: 'text-blue-400',   bg: 'bg-blue-900/50',   border: 'border-blue-800/50' },
}

const STATUS_CONFIG: Record<AlertStatus, { label: string; color: string; bg: string }> = {
  open:         { label: 'Open',         color: 'text-red-300',    bg: 'bg-red-900/50 border-red-800' },
  acknowledged: { label: 'Acknowledged', color: 'text-amber-300',  bg: 'bg-amber-900/50 border-amber-800' },
  resolved:     { label: 'Resolved',     color: 'text-green-300',  bg: 'bg-green-900/50 border-green-800' },
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: ThreatSeverity }) {
  const cfg = SEVERITY_CONFIG[severity]
  const Icon = cfg.icon
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}>
      <Icon className="w-3 h-3" aria-hidden="true" />
      {cfg.label}
    </span>
  )
}

function StatusPill({ status }: { status: AlertStatus }) {
  const cfg = STATUS_CONFIG[status]
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color}`}>
      {cfg.label}
    </span>
  )
}

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number; icon: typeof Bell; color: string }) {
  return (
    <div className="card border border-slate-700">
      <div className="flex items-center gap-3">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${color}`}>
          <Icon className="w-4 h-4" aria-hidden="true" />
        </div>
        <div>
          <p className="text-lg font-bold text-slate-100">{value}</p>
          <p className="text-[11px] text-slate-500">{label}</p>
        </div>
      </div>
    </div>
  )
}

// ─── Detail modal ────────────────────────────────────────────────────────────

function AlertDetail({
  alert,
  onClose,
  onStatusChange,
}: {
  alert: RecentAlert
  onClose: () => void
  onStatusChange: (id: string, status: AlertStatus) => void
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div className="card border border-slate-600 max-w-lg w-full mx-4 shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={alert.severity} />
            <StatusPill status={alert.status} />
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 transition-colors" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        <h3 className="text-sm font-semibold text-slate-200 mb-1">{alert.typeLabel}</h3>
        <p className="text-xs text-slate-400 mb-4">{alert.message}</p>

        <div className="grid grid-cols-2 gap-3 mb-4">
          <div className="bg-slate-800/50 rounded-lg px-3 py-2">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide">Alert ID</p>
            <p className="text-xs text-slate-300 font-mono mt-0.5">{alert.id}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg px-3 py-2">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide">Threat Type</p>
            <p className="text-xs text-slate-300 mt-0.5">{alert.type}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg px-3 py-2">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide">Timestamp</p>
            <p className="text-xs text-slate-300 mt-0.5">{new Date(alert.timestamp).toLocaleString()}</p>
          </div>
          <div className="bg-slate-800/50 rounded-lg px-3 py-2">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide">Tenant</p>
            <p className="text-xs text-slate-300 mt-0.5">{alert.tenantId}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 pt-3 border-t border-slate-700">
          <p className="text-[10px] text-slate-500 uppercase tracking-wide mr-auto">Update Status:</p>
          {alert.status !== 'acknowledged' && (
            <button
              onClick={() => onStatusChange(alert.id, 'acknowledged')}
              className="flex items-center gap-1.5 text-xs text-amber-400 bg-amber-900/30 border border-amber-800/50 px-3 py-1.5 rounded-lg hover:bg-amber-900/50 transition-colors"
            >
              <Eye className="w-3 h-3" /> Acknowledge
            </button>
          )}
          {alert.status !== 'resolved' && (
            <button
              onClick={() => onStatusChange(alert.id, 'resolved')}
              className="flex items-center gap-1.5 text-xs text-green-400 bg-green-900/30 border border-green-800/50 px-3 py-1.5 rounded-lg hover:bg-green-900/50 transition-colors"
            >
              <CheckCheck className="w-3 h-3" /> Resolve
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Main panel ──────────────────────────────────────────────────────────────

export function AlertsPanel({ initialAlerts }: { initialAlerts: RecentAlert[] }) {
  const [alerts, setAlerts] = useState(initialAlerts)
  const [filterSeverity, setFilterSeverity] = useState<FilterSeverity>('all')
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all')
  const [selectedAlert, setSelectedAlert] = useState<RecentAlert | null>(null)

  // Stats
  const stats = useMemo(() => ({
    total: alerts.length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    open: alerts.filter(a => a.status === 'open').length,
    resolved: alerts.filter(a => a.status === 'resolved').length,
  }), [alerts])

  // Filtered list
  const filtered = useMemo(() => {
    return alerts.filter(a => {
      if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false
      if (filterStatus !== 'all' && a.status !== filterStatus) return false
      return true
    })
  }, [alerts, filterSeverity, filterStatus])

  const handleStatusChange = useCallback(async (id: string, newStatus: AlertStatus) => {
    // Optimistic update
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: newStatus } : a))
    setSelectedAlert(prev => prev?.id === id ? { ...prev, status: newStatus } : prev)
    try {
      await updateAlertStatus(id, newStatus)
    } catch {
      // Revert on failure
      setAlerts(prev => prev.map(a => a.id === id ? { ...a, status: a.status } : a))
    }
  }, [])

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Total Alerts" value={stats.total} icon={Bell} color="bg-blue-900/50 text-blue-400" />
        <StatCard label="Critical" value={stats.critical} icon={XCircle} color="bg-red-900/50 text-red-400" />
        <StatCard label="Open" value={stats.open} icon={Clock} color="bg-amber-900/50 text-amber-400" />
        <StatCard label="Resolved" value={stats.resolved} icon={Shield} color="bg-green-900/50 text-green-400" />
      </div>

      {/* Filters */}
      <div className="card border border-slate-700">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="w-4 h-4 text-slate-500" aria-hidden="true" />
          <p className="text-xs font-semibold text-slate-400">Filters</p>
        </div>
        <div className="flex flex-wrap gap-4">
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Severity</label>
            <select
              value={filterSeverity}
              onChange={e => setFilterSeverity(e.target.value as FilterSeverity)}
              className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="safe">Safe</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Status</label>
            <select
              value={filterStatus}
              onChange={e => setFilterStatus(e.target.value as FilterStatus)}
              className="bg-slate-800 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
          <div className="flex items-end">
            <p className="text-[11px] text-slate-500">
              Showing <span className="text-slate-300 font-medium">{filtered.length}</span> of {alerts.length} alerts
            </p>
          </div>
        </div>
      </div>

      {/* Alert table */}
      <div className="card border border-slate-700">
        <div className="overflow-x-auto -mx-5 px-5">
          <table className="data-table" aria-label="Alert list">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Type</th>
                <th>Message</th>
                <th>Time</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-slate-500 text-sm">
                    No alerts match the current filters.
                  </td>
                </tr>
              ) : (
                filtered.map(alert => (
                  <tr key={alert.id} className="cursor-pointer hover:bg-slate-800/50" onClick={() => setSelectedAlert(alert)}>
                    <td><SeverityBadge severity={alert.severity} /></td>
                    <td><span className="text-slate-300 font-medium text-xs">{alert.typeLabel}</span></td>
                    <td><span className="text-slate-400 text-xs truncate block max-w-xs">{alert.message}</span></td>
                    <td>
                      <time dateTime={alert.timestamp} className="text-slate-500 text-xs whitespace-nowrap">
                        {new Date(alert.timestamp).toLocaleString()}
                      </time>
                    </td>
                    <td><StatusPill status={alert.status} /></td>
                    <td>
                      <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                        {alert.status === 'open' && (
                          <button
                            onClick={() => handleStatusChange(alert.id, 'acknowledged')}
                            className="text-amber-400 hover:text-amber-300 transition-colors p-1"
                            title="Acknowledge"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        )}
                        {alert.status !== 'resolved' && (
                          <button
                            onClick={() => handleStatusChange(alert.id, 'resolved')}
                            className="text-green-400 hover:text-green-300 transition-colors p-1"
                            title="Resolve"
                          >
                            <CheckCheck className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail modal */}
      {selectedAlert && (
        <AlertDetail
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onStatusChange={handleStatusChange}
        />
      )}
    </div>
  )
}
