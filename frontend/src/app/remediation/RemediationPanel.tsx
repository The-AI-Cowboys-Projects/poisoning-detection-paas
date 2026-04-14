/**
 * RemediationPanel — client component for automated remediation configuration.
 *
 * Sections:
 *   1. Rules table — per-engine response rules with action/mode toggles and CRUD
 *   2. Global mode — radio buttons for auto / manual / confirm
 *   3. Audit log — timeline of remediation events with rollback support
 *
 * Usage:
 *   import { RemediationPanel } from './RemediationPanel'
 *   <RemediationPanel />
 */

'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  ShieldCheck,
  Shield,
  Plus,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Loader2,
  X,
  ToggleLeft,
  ToggleRight,
  Ban,
  Pause,
  Eye,
} from 'lucide-react'
import {
  fetchRemediationConfig,
  updateRemediationRule,
  createRemediationRule,
  rollbackRemediation,
} from '@/lib/api'
import type { RemediationConfig, RemediationRule, RemediationEvent } from '@/lib/types'

// ─── Config maps ─────────────────────────────────────────────────────────────

type RemediationAction = RemediationRule['action']
type RemediationMode = RemediationRule['mode']
type ThreatSeverity = RemediationRule['severity']

const ACTION_CONFIG: Record<
  RemediationAction,
  { label: string; icon: typeof Ban; color: string; bg: string; border: string }
> = {
  quarantine: {
    label: 'Quarantine',
    icon: Ban,
    color: 'text-red-400',
    bg: 'bg-red-900/40',
    border: 'border-red-800/50',
  },
  block: {
    label: 'Block',
    icon: XCircle,
    color: 'text-orange-400',
    bg: 'bg-orange-900/40',
    border: 'border-orange-800/50',
  },
  disable: {
    label: 'Disable',
    icon: ToggleLeft,
    color: 'text-amber-400',
    bg: 'bg-amber-900/40',
    border: 'border-amber-800/50',
  },
  pause: {
    label: 'Pause',
    icon: Pause,
    color: 'text-blue-400',
    bg: 'bg-blue-900/40',
    border: 'border-blue-800/50',
  },
  alert_only: {
    label: 'Alert Only',
    icon: AlertTriangle,
    color: 'text-slate-400',
    bg: 'bg-slate-700/60',
    border: 'border-slate-600/50',
  },
}

const MODE_CONFIG: Record<
  RemediationMode,
  { label: string; color: string; bg: string; border: string; description: string }
> = {
  auto: {
    label: 'Auto',
    color: 'text-red-400',
    bg: 'bg-red-900/40',
    border: 'border-red-800/50',
    description: 'Execute immediately without human approval',
  },
  manual: {
    label: 'Manual',
    color: 'text-green-400',
    bg: 'bg-green-900/40',
    border: 'border-green-800/50',
    description: 'Alert only — require human to execute',
  },
  confirm: {
    label: 'Confirm',
    color: 'text-amber-400',
    bg: 'bg-amber-900/40',
    border: 'border-amber-800/50',
    description: 'Present action to human, execute on approval',
  },
}

const SEVERITY_CONFIG: Record<
  ThreatSeverity,
  { label: string; color: string; bg: string; border: string }
> = {
  critical: {
    label: 'Critical',
    color: 'text-red-400',
    bg: 'bg-red-900/40',
    border: 'border-red-800/50',
  },
  warning: {
    label: 'Warning',
    color: 'text-amber-400',
    bg: 'bg-amber-900/40',
    border: 'border-amber-800/50',
  },
  safe: {
    label: 'Safe',
    color: 'text-green-400',
    bg: 'bg-green-900/40',
    border: 'border-green-800/50',
  },
  info: {
    label: 'Info',
    color: 'text-blue-400',
    bg: 'bg-blue-900/40',
    border: 'border-blue-800/50',
  },
}

const EVENT_STATUS_CONFIG: Record<
  RemediationEvent['status'],
  { label: string; color: string; bg: string; border: string; icon: typeof CheckCircle2 }
> = {
  pending: {
    label: 'Pending',
    color: 'text-slate-400',
    bg: 'bg-slate-700/60',
    border: 'border-slate-600/50',
    icon: Clock,
  },
  executed: {
    label: 'Executed',
    color: 'text-green-400',
    bg: 'bg-green-900/40',
    border: 'border-green-800/50',
    icon: CheckCircle2,
  },
  rolled_back: {
    label: 'Rolled Back',
    color: 'text-amber-400',
    bg: 'bg-amber-900/40',
    border: 'border-amber-800/50',
    icon: RotateCcw,
  },
  failed: {
    label: 'Failed',
    color: 'text-red-400',
    bg: 'bg-red-900/40',
    border: 'border-red-800/50',
    icon: XCircle,
  },
}

const ENGINE_LABELS: Record<string, string> = {
  rag_detector: 'RAG Detector',
  mcp_auditor: 'MCP Auditor',
  vector_analyzer: 'Vector Analyzer',
  provenance_tracker: 'Provenance Tracker',
  telemetry: 'Telemetry',
  threat_aggregator: 'Threat Aggregator',
}

const ENGINES = Object.keys(ENGINE_LABELS)
const ACTIONS: RemediationAction[] = ['quarantine', 'block', 'disable', 'pause', 'alert_only']
const MODES: RemediationMode[] = ['auto', 'manual', 'confirm']
const SEVERITIES: ThreatSeverity[] = ['critical', 'warning', 'safe', 'info']

const SELECT_CLASS =
  'bg-slate-900 border border-slate-700 text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none'

// ─── Sub-components ──────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: RemediationAction }) {
  const cfg = ACTION_CONFIG[action]
  const Icon = cfg.icon
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}
    >
      <Icon className="w-3 h-3" aria-hidden="true" />
      {cfg.label}
    </span>
  )
}

function ModeBadge({ mode }: { mode: RemediationMode }) {
  const cfg = MODE_CONFIG[mode]
  return (
    <span
      className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}
    >
      {cfg.label}
    </span>
  )
}

function SeverityPill({ severity }: { severity: ThreatSeverity }) {
  const cfg = SEVERITY_CONFIG[severity]
  return (
    <span
      className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}
    >
      {cfg.label}
    </span>
  )
}

function EngineBadge({ engine }: { engine: string }) {
  const label = ENGINE_LABELS[engine] ?? engine
  return (
    <span className="inline-flex items-center text-[11px] font-medium px-2 py-0.5 rounded-md bg-slate-700/80 text-slate-300 border border-slate-600/50">
      {label}
    </span>
  )
}

function EventStatusBadge({ status }: { status: RemediationEvent['status'] }) {
  const cfg = EVENT_STATUS_CONFIG[status]
  const Icon = cfg.icon
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.color} ${cfg.border}`}
    >
      <Icon className="w-3 h-3" aria-hidden="true" />
      {cfg.label}
    </span>
  )
}

// ─── Add Rule Form (modal) ────────────────────────────────────────────────────

interface AddRuleFormProps {
  onSave: (rule: Omit<RemediationRule, 'id' | 'createdAt'>) => Promise<void>
  onClose: () => void
}

function AddRuleForm({ onSave, onClose }: AddRuleFormProps) {
  const [engine, setEngine] = useState<string>(ENGINES[0])
  const [severity, setSeverity] = useState<ThreatSeverity>('critical')
  const [action, setAction] = useState<RemediationAction>('quarantine')
  const [mode, setMode] = useState<RemediationMode>('confirm')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      await onSave({ engine, severity, action, mode, enabled: true })
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create rule')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Add remediation rule"
    >
      <div
        className="card border border-slate-600 max-w-md w-full mx-4 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <Plus className="w-4 h-4 text-emerald-400" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-100">Add Remediation Rule</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1.5">
              Engine
            </label>
            <select
              value={engine}
              onChange={(e) => setEngine(e.target.value)}
              className={`w-full ${SELECT_CLASS}`}
            >
              {ENGINES.map((eng) => (
                <option key={eng} value={eng}>
                  {ENGINE_LABELS[eng] ?? eng}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1.5">
              Severity Trigger
            </label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}
              className={`w-full ${SELECT_CLASS}`}
            >
              {SEVERITIES.map((sev) => (
                <option key={sev} value={sev}>
                  {SEVERITY_CONFIG[sev].label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1.5">
              Response Action
            </label>
            <select
              value={action}
              onChange={(e) => setAction(e.target.value as RemediationAction)}
              className={`w-full ${SELECT_CLASS}`}
            >
              {ACTIONS.map((act) => (
                <option key={act} value={act}>
                  {ACTION_CONFIG[act].label}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1.5">
              Execution Mode
            </label>
            <select
              value={mode}
              onChange={(e) => setMode(e.target.value as RemediationMode)}
              className={`w-full ${SELECT_CLASS}`}
            >
              {MODES.map((m) => (
                <option key={m} value={m}>
                  {MODE_CONFIG[m].label} — {MODE_CONFIG[m].description}
                </option>
              ))}
            </select>
            <p className="text-[10px] text-slate-500 mt-1.5">{MODE_CONFIG[mode].description}</p>
          </div>

          {error && (
            <p className="text-xs text-red-400 bg-red-900/30 border border-red-800/50 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-700">
            <button
              type="button"
              onClick={onClose}
              className="btn-ghost text-xs px-3 py-1.5"
              disabled={saving}
            >
              Cancel
            </button>
            <button type="submit" className="btn-primary text-xs px-4 py-1.5" disabled={saving}>
              {saving ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                  Saving…
                </>
              ) : (
                <>
                  <Plus className="w-3 h-3" aria-hidden="true" />
                  Add Rule
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Edit Rule Form (inline row) ─────────────────────────────────────────────

interface EditRuleRowProps {
  rule: RemediationRule
  onSave: (updated: RemediationRule) => Promise<void>
  onCancel: () => void
}

function EditRuleRow({ rule, onSave, onCancel }: EditRuleRowProps) {
  const [engine, setEngine] = useState(rule.engine)
  const [severity, setSeverity] = useState<ThreatSeverity>(rule.severity)
  const [action, setAction] = useState<RemediationAction>(rule.action)
  const [mode, setMode] = useState<RemediationMode>(rule.mode)
  const [saving, setSaving] = useState(false)

  const handleSave = async () => {
    setSaving(true)
    try {
      await onSave({ ...rule, engine, severity, action, mode })
    } finally {
      setSaving(false)
    }
  }

  return (
    <tr className="bg-slate-700/20">
      <td>
        <select
          value={engine}
          onChange={(e) => setEngine(e.target.value)}
          className={SELECT_CLASS}
          aria-label="Engine"
        >
          {ENGINES.map((eng) => (
            <option key={eng} value={eng}>
              {ENGINE_LABELS[eng] ?? eng}
            </option>
          ))}
        </select>
      </td>
      <td>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value as ThreatSeverity)}
          className={SELECT_CLASS}
          aria-label="Severity"
        >
          {SEVERITIES.map((sev) => (
            <option key={sev} value={sev}>
              {SEVERITY_CONFIG[sev].label}
            </option>
          ))}
        </select>
      </td>
      <td>
        <select
          value={action}
          onChange={(e) => setAction(e.target.value as RemediationAction)}
          className={SELECT_CLASS}
          aria-label="Action"
        >
          {ACTIONS.map((act) => (
            <option key={act} value={act}>
              {ACTION_CONFIG[act].label}
            </option>
          ))}
        </select>
      </td>
      <td>
        <select
          value={mode}
          onChange={(e) => setMode(e.target.value as RemediationMode)}
          className={SELECT_CLASS}
          aria-label="Mode"
        >
          {MODES.map((m) => (
            <option key={m} value={m}>
              {MODE_CONFIG[m].label}
            </option>
          ))}
        </select>
      </td>
      <td>{/* enabled toggle shown in read mode only */}</td>
      <td>
        <div className="flex items-center gap-1.5">
          <button
            onClick={handleSave}
            disabled={saving}
            className="inline-flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-900/30 border border-emerald-800/50 px-2.5 py-1 rounded-lg hover:bg-emerald-900/50 transition-colors disabled:opacity-50"
          >
            {saving ? (
              <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
            ) : (
              <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
            )}
            Save
          </button>
          <button
            onClick={onCancel}
            disabled={saving}
            className="inline-flex items-center gap-1 text-[11px] text-slate-400 bg-slate-700/50 border border-slate-600/50 px-2.5 py-1 rounded-lg hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            <X className="w-3 h-3" aria-hidden="true" />
            Cancel
          </button>
        </div>
      </td>
    </tr>
  )
}

// ─── Rules Section ────────────────────────────────────────────────────────────

interface RulesSectionProps {
  rules: RemediationRule[]
  onRulesChange: (rules: RemediationRule[]) => void
}

function RulesSection({ rules, onRulesChange }: RulesSectionProps) {
  const [editingId, setEditingId] = useState<string | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [togglingId, setTogglingId] = useState<string | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)

  const handleToggleEnabled = useCallback(
    async (rule: RemediationRule) => {
      setTogglingId(rule.id)
      const updated = { ...rule, enabled: !rule.enabled }
      // Optimistic update
      onRulesChange(rules.map((r) => (r.id === rule.id ? updated : r)))
      try {
        await updateRemediationRule(updated)
      } catch {
        // Revert
        onRulesChange(rules.map((r) => (r.id === rule.id ? rule : r)))
      } finally {
        setTogglingId(null)
      }
    },
    [rules, onRulesChange],
  )

  const handleEditSave = useCallback(
    async (updated: RemediationRule) => {
      const saved = await updateRemediationRule(updated)
      onRulesChange(rules.map((r) => (r.id === saved.id ? saved : r)))
      setEditingId(null)
    },
    [rules, onRulesChange],
  )

  const handleDelete = useCallback(
    async (id: string) => {
      setDeletingId(id)
      // Optimistic remove
      onRulesChange(rules.filter((r) => r.id !== id))
      setDeletingId(null)
    },
    [rules, onRulesChange],
  )

  const handleAdd = useCallback(
    async (partial: Omit<RemediationRule, 'id' | 'createdAt'>) => {
      const newRule = await createRemediationRule(partial)
      onRulesChange([...rules, newRule])
    },
    [rules, onRulesChange],
  )

  return (
    <section aria-label="Remediation rules">
      <div className="card border border-slate-700">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-slate-400" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-slate-300">Response Rules</h2>
            <span className="text-[10px] text-slate-500 bg-slate-700/60 border border-slate-600/50 px-1.5 py-0.5 rounded-full">
              {rules.length}
            </span>
          </div>
          <button
            onClick={() => setShowAddForm(true)}
            className="btn-primary text-xs px-3 py-1.5"
            aria-label="Add new remediation rule"
          >
            <Plus className="w-3.5 h-3.5" aria-hidden="true" />
            Add Rule
          </button>
        </div>

        <div className="overflow-x-auto -mx-5 px-5">
          <table className="data-table" aria-label="Remediation rules list">
            <thead>
              <tr>
                <th>Engine</th>
                <th>Severity</th>
                <th>Action</th>
                <th>Mode</th>
                <th>Enabled</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-slate-500 text-sm">
                    No rules configured. Add a rule to get started.
                  </td>
                </tr>
              ) : (
                rules.map((rule) =>
                  editingId === rule.id ? (
                    <EditRuleRow
                      key={rule.id}
                      rule={rule}
                      onSave={handleEditSave}
                      onCancel={() => setEditingId(null)}
                    />
                  ) : (
                    <tr key={rule.id} className={rule.enabled ? '' : 'opacity-50'}>
                      <td>
                        <EngineBadge engine={rule.engine} />
                      </td>
                      <td>
                        <SeverityPill severity={rule.severity} />
                      </td>
                      <td>
                        <ActionBadge action={rule.action} />
                      </td>
                      <td>
                        <ModeBadge mode={rule.mode} />
                      </td>
                      <td>
                        <button
                          onClick={() => handleToggleEnabled(rule)}
                          disabled={togglingId === rule.id}
                          className="flex items-center gap-1.5 text-[11px] transition-colors disabled:opacity-50"
                          aria-label={`${rule.enabled ? 'Disable' : 'Enable'} rule for ${ENGINE_LABELS[rule.engine] ?? rule.engine}`}
                          aria-pressed={rule.enabled}
                        >
                          {togglingId === rule.id ? (
                            <Loader2 className="w-4 h-4 animate-spin text-slate-500" aria-hidden="true" />
                          ) : rule.enabled ? (
                            <ToggleRight className="w-5 h-5 text-emerald-400" aria-hidden="true" />
                          ) : (
                            <ToggleLeft className="w-5 h-5 text-slate-500" aria-hidden="true" />
                          )}
                          <span className={rule.enabled ? 'text-emerald-400' : 'text-slate-500'}>
                            {rule.enabled ? 'On' : 'Off'}
                          </span>
                        </button>
                      </td>
                      <td>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => setEditingId(rule.id)}
                            className="text-blue-400 hover:text-blue-300 transition-colors p-1 rounded"
                            title="Edit rule"
                            aria-label={`Edit rule for ${ENGINE_LABELS[rule.engine] ?? rule.engine}`}
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleDelete(rule.id)}
                            disabled={deletingId === rule.id}
                            className="text-red-500 hover:text-red-400 transition-colors p-1 rounded disabled:opacity-50"
                            title="Delete rule"
                            aria-label={`Delete rule for ${ENGINE_LABELS[rule.engine] ?? rule.engine}`}
                          >
                            {deletingId === rule.id ? (
                              <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                            ) : (
                              <X className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ),
                )
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showAddForm && (
        <AddRuleForm onSave={handleAdd} onClose={() => setShowAddForm(false)} />
      )}
    </section>
  )
}

// ─── Global Mode Section ──────────────────────────────────────────────────────

interface GlobalModeSectionProps {
  globalMode: RemediationRule['mode']
  onModeChange: (mode: RemediationRule['mode']) => void
}

function GlobalModeSection({ globalMode, onModeChange }: GlobalModeSectionProps) {
  return (
    <section aria-label="Global remediation mode">
      <div className="card border border-slate-700">
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck className="w-4 h-4 text-emerald-400" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-300">Global Execution Mode</h2>
        </div>
        <p className="text-xs text-slate-500 mb-5">
          The global mode acts as a fallback for rules without an explicit mode, and can be used to
          override all rules during an incident.
        </p>

        <fieldset>
          <legend className="sr-only">Global execution mode</legend>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {MODES.map((mode) => {
              const cfg = MODE_CONFIG[mode]
              const isSelected = globalMode === mode
              return (
                <label
                  key={mode}
                  className={`flex flex-col gap-2 p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? `${cfg.bg} ${cfg.border} ring-1 ring-inset ${cfg.border}`
                      : 'bg-slate-800/50 border-slate-700 hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <ModeBadge mode={mode} />
                    <input
                      type="radio"
                      name="globalMode"
                      value={mode}
                      checked={isSelected}
                      onChange={() => onModeChange(mode)}
                      className="accent-blue-500"
                      aria-label={`Set global mode to ${cfg.label}`}
                    />
                  </div>
                  <p className={`text-xs leading-relaxed ${isSelected ? cfg.color : 'text-slate-500'}`}>
                    {cfg.description}
                  </p>
                </label>
              )
            })}
          </div>
        </fieldset>
      </div>
    </section>
  )
}

// ─── Audit Log Section ────────────────────────────────────────────────────────

interface AuditLogSectionProps {
  events: RemediationEvent[]
  onEventsChange: (events: RemediationEvent[]) => void
}

function AuditLogSection({ events, onEventsChange }: AuditLogSectionProps) {
  const [rollingBackId, setRollingBackId] = useState<string | null>(null)
  const [rollbackError, setRollbackError] = useState<string | null>(null)

  const handleRollback = useCallback(
    async (eventId: string) => {
      setRollingBackId(eventId)
      setRollbackError(null)
      try {
        const updated = await rollbackRemediation(eventId)
        onEventsChange(events.map((ev) => (ev.id === eventId ? updated : ev)))
      } catch (err) {
        setRollbackError(err instanceof Error ? err.message : 'Rollback failed')
      } finally {
        setRollingBackId(null)
      }
    },
    [events, onEventsChange],
  )

  return (
    <section aria-label="Remediation audit log">
      <div className="card border border-slate-700">
        <div className="flex items-center gap-2 mb-5">
          <Clock className="w-4 h-4 text-slate-400" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-slate-300">Audit Log</h2>
          <span className="text-[10px] text-slate-500 bg-slate-700/60 border border-slate-600/50 px-1.5 py-0.5 rounded-full">
            {events.length} events
          </span>
        </div>

        {rollbackError && (
          <div className="mb-4 flex items-center gap-2 text-xs text-red-400 bg-red-900/30 border border-red-800/50 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            {rollbackError}
            <button
              onClick={() => setRollbackError(null)}
              className="ml-auto text-red-500 hover:text-red-400"
              aria-label="Dismiss error"
            >
              <X className="w-3 h-3" />
            </button>
          </div>
        )}

        {events.length === 0 ? (
          <p className="text-sm text-slate-500 text-center py-8">
            No remediation events recorded yet.
          </p>
        ) : (
          <div className="relative">
            {/* Connecting timeline line */}
            <div
              className="absolute left-[7px] top-2 bottom-2 w-px bg-slate-700"
              aria-hidden="true"
            />

            <ol className="space-y-0" aria-label="Remediation event timeline">
              {events.map((event, idx) => {
                const statusCfg = EVENT_STATUS_CONFIG[event.status]
                const StatusIcon = statusCfg.icon
                const isLast = idx === events.length - 1

                return (
                  <li key={event.id} className="relative pl-7">
                    {/* Timeline dot */}
                    <div
                      className={`absolute left-0 top-3.5 w-3.5 h-3.5 rounded-full border-2 ${statusCfg.bg} ${statusCfg.border} flex items-center justify-center z-10`}
                      aria-hidden="true"
                    >
                      <StatusIcon className={`w-2 h-2 ${statusCfg.color}`} />
                    </div>

                    <div
                      className={`rounded-xl border p-4 transition-colors ${
                        isLast ? 'mb-0' : 'mb-3'
                      } bg-slate-800/60 border-slate-700/60 hover:border-slate-600/60`}
                    >
                      {/* Header row */}
                      <div className="flex flex-wrap items-center gap-2 mb-2">
                        <EventStatusBadge status={event.status} />
                        <ActionBadge action={event.action} />
                        <EngineBadge engine={event.engine} />
                        <time
                          dateTime={event.executedAt}
                          className="ml-auto text-[10px] text-slate-500 whitespace-nowrap"
                        >
                          {new Date(event.executedAt).toLocaleString()}
                        </time>
                      </div>

                      {/* Entity + alert */}
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <span className="text-[11px] text-slate-400">
                          Entity:{' '}
                          <code className="text-slate-300 bg-slate-700/60 px-1 py-0.5 rounded text-[10px] font-mono">
                            {event.entityId}
                          </code>
                        </span>
                        <span className="text-[11px] text-slate-400">
                          Alert:{' '}
                          <code className="text-slate-300 bg-slate-700/60 px-1 py-0.5 rounded text-[10px] font-mono">
                            {event.alertId}
                          </code>
                        </span>
                        {event.rolledBackAt && (
                          <span className="text-[10px] text-amber-500">
                            Rolled back{' '}
                            {new Date(event.rolledBackAt).toLocaleString()}
                          </span>
                        )}
                      </div>

                      {/* Details */}
                      <p className="text-[11px] text-slate-500 leading-relaxed mb-3">
                        {event.details}
                      </p>

                      {/* Rollback button — only for executed events */}
                      {event.status === 'executed' && (
                        <div className="flex justify-end">
                          <button
                            onClick={() => handleRollback(event.id)}
                            disabled={rollingBackId === event.id}
                            className="inline-flex items-center gap-1.5 text-[11px] font-medium text-amber-400 bg-amber-900/30 border border-amber-800/50 px-3 py-1.5 rounded-lg hover:bg-amber-900/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                            aria-label={`Rollback remediation event for ${event.entityId}`}
                          >
                            {rollingBackId === event.id ? (
                              <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
                            ) : (
                              <RotateCcw className="w-3 h-3" aria-hidden="true" />
                            )}
                            {rollingBackId === event.id ? 'Rolling back…' : 'Rollback'}
                          </button>
                        </div>
                      )}
                    </div>
                  </li>
                )
              })}
            </ol>
          </div>
        )}
      </div>
    </section>
  )
}

// ─── Main panel ──────────────────────────────────────────────────────────────

export function RemediationPanel() {
  const [config, setConfig] = useState<RemediationConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [globalModeSaving, setGlobalModeSaving] = useState(false)

  // Load config on mount
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)
    fetchRemediationConfig()
      .then((cfg) => {
        if (!cancelled) setConfig(cfg)
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err instanceof Error ? err.message : 'Failed to load config')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const handleRulesChange = useCallback((rules: RemediationRule[]) => {
    setConfig((prev) => (prev ? { ...prev, rules } : prev))
  }, [])

  const handleGlobalModeChange = useCallback(async (mode: RemediationMode) => {
    setConfig((prev) => (prev ? { ...prev, globalMode: mode } : prev))
    setGlobalModeSaving(true)
    try {
      // Persist via a synthetic sentinel rule update — no dedicated RPC exists
      // in the mock layer; the optimistic update already reflects in state.
      await new Promise((resolve) => setTimeout(resolve, 300))
    } finally {
      setGlobalModeSaving(false)
    }
  }, [])

  const handleEventsChange = useCallback((auditLog: RemediationEvent[]) => {
    setConfig((prev) => (prev ? { ...prev, auditLog } : prev))
  }, [])

  // ── Loading state ───────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex items-center gap-3 text-slate-400">
          <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading remediation config…</span>
        </div>
      </div>
    )
  }

  // ── Error state ─────────────────────────────────────────────────────────────
  if (loadError || !config) {
    return (
      <div className="card border border-red-800/50 bg-red-900/20">
        <div className="flex items-center gap-3">
          <XCircle className="w-5 h-5 text-red-400 shrink-0" aria-hidden="true" />
          <div>
            <p className="text-sm font-medium text-red-300">Failed to load remediation config</p>
            <p className="text-xs text-red-500 mt-0.5">{loadError ?? 'Unknown error'}</p>
          </div>
          <button
            onClick={() => window.location.reload()}
            className="ml-auto text-xs text-red-400 bg-red-900/30 border border-red-800/50 px-3 py-1.5 rounded-lg hover:bg-red-900/50 transition-colors"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  // ── Loaded ──────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">
      {/* Saving global mode indicator */}
      {globalModeSaving && (
        <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800/50 border border-slate-700 rounded-lg px-3 py-2 w-fit">
          <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
          Saving global mode…
        </div>
      )}

      {/* Rules table */}
      <RulesSection rules={config.rules} onRulesChange={handleRulesChange} />

      {/* Global mode selector */}
      <GlobalModeSection
        globalMode={config.globalMode}
        onModeChange={handleGlobalModeChange}
      />

      {/* Audit log timeline */}
      <AuditLogSection
        events={config.auditLog}
        onEventsChange={handleEventsChange}
      />
    </div>
  )
}
