'use client'

/**
 * ConnectorsPanel — Live System Integration client component.
 *
 * Usage:
 *   import { ConnectorsPanel } from './ConnectorsPanel'
 *   <ConnectorsPanel />
 *
 * Renders connectors grouped by type with per-connector scan + MCP introspection.
 */

import { useCallback, useEffect, useId, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  Eye,
  GitFork,
  Loader2,
  Plus,
  Plug,
  RefreshCw,
  Server,
  X,
  XCircle,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import {
  fetchLiveConnectors,
  addLiveConnector,
  scanConnector,
  fetchMCPIntrospection,
} from '@/lib/api'
import type { ConnectorType, LiveConnector, MCPIntrospection, VerdictLabel } from '@/lib/types'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const GROUP_META: Record<
  ConnectorType,
  { label: string; icon: React.ElementType; accent: string; border: string }
> = {
  vector_store: {
    label: 'Vector Stores',
    icon: Database,
    accent: 'text-violet-400',
    border: 'border-violet-800/40',
  },
  mcp_server: {
    label: 'MCP Servers',
    icon: Server,
    accent: 'text-sky-400',
    border: 'border-sky-800/40',
  },
  rag_pipeline: {
    label: 'RAG Pipelines',
    icon: GitFork,
    accent: 'text-emerald-400',
    border: 'border-emerald-800/40',
  },
}

const GROUP_ORDER: ConnectorType[] = ['vector_store', 'mcp_server', 'rag_pipeline']

function statusBadge(status: LiveConnector['status']) {
  switch (status) {
    case 'connected':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-900/50 border border-emerald-800/60 text-emerald-400">
          <CheckCircle2 className="w-2.5 h-2.5" aria-hidden="true" />
          Connected
        </span>
      )
    case 'disconnected':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-400">
          <XCircle className="w-2.5 h-2.5" aria-hidden="true" />
          Disconnected
        </span>
      )
    case 'error':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-red-900/50 border border-red-800/60 text-red-400">
          <AlertTriangle className="w-2.5 h-2.5" aria-hidden="true" />
          Error
        </span>
      )
    case 'scanning':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-900/50 border border-amber-800/60 text-amber-400">
          <Loader2 className="w-2.5 h-2.5 animate-spin" aria-hidden="true" />
          Scanning
        </span>
      )
  }
}

function verdictBadge(verdict: VerdictLabel) {
  switch (verdict) {
    case 'clean':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-900/40 border border-emerald-800/50 text-emerald-400">
          <CheckCircle2 className="w-2.5 h-2.5" aria-hidden="true" />
          Clean
        </span>
      )
    case 'suspicious':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-amber-900/40 border border-amber-800/50 text-amber-400">
          <AlertTriangle className="w-2.5 h-2.5" aria-hidden="true" />
          Suspicious
        </span>
      )
    case 'malicious':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-red-900/40 border border-red-800/50 text-red-400">
          <XCircle className="w-2.5 h-2.5" aria-hidden="true" />
          Malicious
        </span>
      )
    case 'unknown':
      return (
        <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-500">
          Unknown
        </span>
      )
  }
}

function riskBarColor(score: number): string {
  if (score >= 0.6) return 'bg-red-500'
  if (score >= 0.3) return 'bg-amber-500'
  return 'bg-emerald-500'
}

function riskTextColor(score: number): string {
  if (score >= 0.6) return 'text-red-400'
  if (score >= 0.3) return 'text-amber-400'
  return 'text-emerald-400'
}

// ─── MCP Introspection Modal ──────────────────────────────────────────────────

interface MCPModalProps {
  connectorName: string
  data: MCPIntrospection
  onClose: () => void
}

function MCPIntrospectionModal({ connectorName, data, onClose }: MCPModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null)

  // Close on backdrop click
  const handleBackdropClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === backdropRef.current) onClose()
    },
    [onClose],
  )

  // Close on Escape
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const { lastDiff } = data

  return (
    <div
      ref={backdropRef}
      role="dialog"
      aria-modal="true"
      aria-label={`MCP Introspection — ${connectorName}`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={handleBackdropClick}
    >
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-sky-900/40 border border-sky-800/50 flex items-center justify-center">
              <Eye className="w-4 h-4 text-sky-400" aria-hidden="true" />
            </div>
            <div>
              <p className="text-sm font-bold text-slate-100">MCP Introspection</p>
              <p className="text-[10px] text-slate-500">{connectorName}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-slate-500 hover:text-slate-200 hover:bg-slate-700 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {/* Last diff */}
          {lastDiff && (
            <section aria-label="Schema diff since last scan">
              <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
                Last Diff —{' '}
                {formatDistanceToNow(new Date(lastDiff.diffAt), { addSuffix: true })}
              </p>
              <div className="grid grid-cols-3 gap-3">
                <DiffColumn
                  label="Added"
                  items={lastDiff.added}
                  chipClass="bg-emerald-900/40 border-emerald-800/50 text-emerald-300"
                  emptyText="None"
                />
                <DiffColumn
                  label="Removed"
                  items={lastDiff.removed}
                  chipClass="bg-red-900/40 border-red-800/50 text-red-300"
                  emptyText="None"
                />
                <DiffColumn
                  label="Modified"
                  items={lastDiff.modified}
                  chipClass="bg-amber-900/40 border-amber-800/50 text-amber-300"
                  emptyText="None"
                />
              </div>
            </section>
          )}

          {!lastDiff && (
            <div className="rounded-lg border border-slate-700 bg-slate-800/40 px-4 py-3 text-xs text-slate-500">
              No diff data available — this is the first introspection.
            </div>
          )}

          {/* Tool list */}
          <section aria-label="Tool list">
            <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider mb-3">
              {data.tools.length} Tool{data.tools.length !== 1 ? 's' : ''} Registered
            </p>
            <div className="space-y-2">
              {data.tools.map((tool) => (
                <div
                  key={tool.name}
                  className={[
                    'rounded-xl border p-3.5',
                    tool.riskFlags.length > 0
                      ? 'border-amber-800/40 bg-amber-900/10'
                      : 'border-slate-700 bg-slate-800/40',
                  ].join(' ')}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-slate-200 font-mono">{tool.name}</p>
                      <p className="text-xs text-slate-500 mt-0.5 leading-relaxed">
                        {tool.description}
                      </p>
                    </div>
                    <span className="flex-shrink-0 text-[10px] text-slate-500 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded tabular-nums whitespace-nowrap">
                      {tool.paramCount} param{tool.paramCount !== 1 ? 's' : ''}
                    </span>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                    <span className="font-mono text-[10px] text-slate-600 truncate max-w-[180px]">
                      {tool.schemaHash}
                    </span>
                    {tool.riskFlags.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {tool.riskFlags.map((flag) => (
                          <span
                            key={flag}
                            className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-red-900/40 border border-red-800/50 text-red-300"
                          >
                            <AlertTriangle className="w-2.5 h-2.5" aria-hidden="true" />
                            {flag.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    )}
                    {tool.riskFlags.length === 0 && (
                      <span className="inline-flex items-center gap-1 text-[10px] text-emerald-500">
                        <CheckCircle2 className="w-2.5 h-2.5" aria-hidden="true" />
                        No risk flags
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

interface DiffColumnProps {
  label: string
  items: string[]
  chipClass: string
  emptyText: string
}

function DiffColumn({ label, items, chipClass, emptyText }: DiffColumnProps) {
  return (
    <div className="rounded-lg border border-slate-700 bg-slate-800/40 p-3">
      <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wide mb-2">
        {label}
      </p>
      {items.length === 0 ? (
        <p className="text-[10px] text-slate-700 italic">{emptyText}</p>
      ) : (
        <div className="space-y-1">
          {items.map((item) => (
            <span
              key={item}
              className={`block font-mono text-[10px] px-2 py-1 rounded border ${chipClass} truncate`}
            >
              {item}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Add Connector Modal ──────────────────────────────────────────────────────

interface AddConnectorModalProps {
  onClose: () => void
  onAdd: (connector: LiveConnector) => void
}

const CONNECTOR_TYPE_LABELS: Record<ConnectorType, string> = {
  vector_store: 'Vector Store',
  mcp_server: 'MCP Server',
  rag_pipeline: 'RAG Pipeline',
}

function AddConnectorModal({ onClose, onAdd }: AddConnectorModalProps) {
  const formId = useId()
  const backdropRef = useRef<HTMLDivElement>(null)
  const [type, setType] = useState<ConnectorType>('vector_store')
  const [name, setName] = useState('')
  const [endpoint, setEndpoint] = useState('')
  const [configRaw, setConfigRaw] = useState('{}')
  const [configError, setConfigError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === backdropRef.current) onClose()
    },
    [onClose],
  )

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  function validateConfig(raw: string): Record<string, unknown> | null {
    try {
      const parsed = JSON.parse(raw)
      if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
        setConfigError('Config must be a JSON object.')
        return null
      }
      setConfigError(null)
      return parsed
    } catch {
      setConfigError('Invalid JSON.')
      return null
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const config = validateConfig(configRaw)
    if (!config) return
    if (!name.trim() || !endpoint.trim()) return

    setSubmitting(true)
    setError(null)
    try {
      const created = await addLiveConnector({ type, name: name.trim(), endpoint: endpoint.trim(), config })
      onAdd(created)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add connector.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      ref={backdropRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby={`${formId}-title`}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={handleBackdropClick}
    >
      <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-900/40 border border-cyan-800/50 flex items-center justify-center">
              <Plus className="w-4 h-4 text-cyan-400" aria-hidden="true" />
            </div>
            <p id={`${formId}-title`} className="text-sm font-bold text-slate-100">
              Add Connector
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 rounded-lg flex items-center justify-center text-slate-500 hover:text-slate-200 hover:bg-slate-700 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>
        </div>

        {/* Form */}
        <form id={formId} onSubmit={handleSubmit} className="p-5 space-y-4" noValidate>
          {/* Type */}
          <div>
            <label
              htmlFor={`${formId}-type`}
              className="block text-xs font-medium text-slate-400 mb-1.5"
            >
              Connector Type
            </label>
            <select
              id={`${formId}-type`}
              value={type}
              onChange={(e) => setType(e.target.value as ConnectorType)}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-600/60"
            >
              {(Object.keys(CONNECTOR_TYPE_LABELS) as ConnectorType[]).map((t) => (
                <option key={t} value={t}>
                  {CONNECTOR_TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </div>

          {/* Name */}
          <div>
            <label
              htmlFor={`${formId}-name`}
              className="block text-xs font-medium text-slate-400 mb-1.5"
            >
              Name
            </label>
            <input
              id={`${formId}-name`}
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Production Pinecone"
              required
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-600/60"
            />
          </div>

          {/* Endpoint */}
          <div>
            <label
              htmlFor={`${formId}-endpoint`}
              className="block text-xs font-medium text-slate-400 mb-1.5"
            >
              Endpoint URL
            </label>
            <input
              id={`${formId}-endpoint`}
              type="url"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://..."
              required
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-600/60"
            />
          </div>

          {/* Config JSON */}
          <div>
            <label
              htmlFor={`${formId}-config`}
              className="block text-xs font-medium text-slate-400 mb-1.5"
            >
              Config
              <span className="ml-1 text-slate-600 font-normal">(JSON object)</span>
            </label>
            <textarea
              id={`${formId}-config`}
              value={configRaw}
              onChange={(e) => {
                setConfigRaw(e.target.value)
                validateConfig(e.target.value)
              }}
              rows={4}
              spellCheck={false}
              className={[
                'w-full bg-slate-800 border rounded-lg px-3 py-2 text-sm font-mono text-slate-200 placeholder:text-slate-600 resize-y focus:outline-none focus:ring-2 focus:ring-cyan-500/50',
                configError ? 'border-red-700 focus:border-red-600' : 'border-slate-700 focus:border-cyan-600/60',
              ].join(' ')}
            />
            {configError && (
              <p className="text-[10px] text-red-400 mt-1" role="alert">
                {configError}
              </p>
            )}
          </div>

          {/* Submit error */}
          {error && (
            <div
              role="alert"
              className="flex items-center gap-2 text-xs text-red-300 bg-red-950/60 border border-red-900/60 rounded-lg px-3 py-2.5"
            >
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />
              {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !!configError || !name.trim() || !endpoint.trim()}
              className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-white bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60"
            >
              {submitting && <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />}
              {submitting ? 'Adding...' : 'Add Connector'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ─── Connector Card ───────────────────────────────────────────────────────────

interface ConnectorCardProps {
  connector: LiveConnector
  onScanComplete: (updated: LiveConnector) => void
  onIntrospect: (connector: LiveConnector) => void
}

function ConnectorCard({ connector, onScanComplete, onIntrospect }: ConnectorCardProps) {
  const [scanning, setScanning] = useState(connector.status === 'scanning')
  const meta = GROUP_META[connector.type]

  async function handleScan() {
    setScanning(true)
    try {
      const updated = await scanConnector(connector.id)
      onScanComplete(updated)
    } finally {
      setScanning(false)
    }
  }

  const scan = connector.lastScanResult
  const isError = connector.status === 'error'

  return (
    <div
      className={[
        'rounded-xl border bg-slate-800/50 p-4 flex flex-col gap-3 transition-shadow hover:shadow-lg hover:shadow-black/20',
        isError ? 'border-red-800/50' : meta.border,
      ].join(' ')}
    >
      {/* Card header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={`w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center bg-slate-900/60 border border-slate-700`}
            aria-hidden="true"
          >
            <meta.icon className={`w-4 h-4 ${meta.accent}`} />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-200 truncate">{connector.name}</p>
            <p className="text-[10px] text-slate-600 font-mono truncate">{connector.endpoint}</p>
          </div>
        </div>
        {statusBadge(scanning ? 'scanning' : connector.status)}
      </div>

      {/* Last scan result */}
      {scan ? (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500">Risk Score</span>
            <span className={`font-bold tabular-nums ${riskTextColor(scan.riskScore)}`}>
              {(scan.riskScore * 100).toFixed(0)}
              <span className="text-slate-600 font-normal">/100</span>
            </span>
          </div>
          {/* Risk bar */}
          <div
            className="h-1.5 w-full rounded-full bg-slate-700 overflow-hidden"
            role="meter"
            aria-valuenow={Math.round(scan.riskScore * 100)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`Risk score ${Math.round(scan.riskScore * 100)} out of 100`}
          >
            <div
              className={`h-full rounded-full transition-all duration-500 ${riskBarColor(scan.riskScore)}`}
              style={{ width: `${Math.round(scan.riskScore * 100)}%` }}
            />
          </div>
          <div className="flex items-center justify-between">
            {verdictBadge(scan.verdict)}
            <span className="text-[10px] text-slate-600 tabular-nums">
              {scan.findings} finding{scan.findings !== 1 ? 's' : ''}
            </span>
          </div>
        </div>
      ) : (
        <div className="text-[10px] text-slate-700 italic py-1">No scan data yet</div>
      )}

      {/* Last checked */}
      {connector.lastChecked && (
        <p className="text-[10px] text-slate-700">
          Last checked{' '}
          {formatDistanceToNow(new Date(connector.lastChecked), { addSuffix: true })}
        </p>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-0.5 border-t border-slate-700/50">
        <button
          type="button"
          onClick={handleScan}
          disabled={scanning}
          className="flex items-center gap-1.5 text-[11px] font-medium px-3 py-1.5 rounded-lg text-slate-300 bg-slate-700/60 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60"
          aria-label={`Scan ${connector.name}`}
        >
          {scanning ? (
            <Loader2 className="w-3 h-3 animate-spin" aria-hidden="true" />
          ) : (
            <RefreshCw className="w-3 h-3" aria-hidden="true" />
          )}
          {scanning ? 'Scanning...' : 'Scan Now'}
        </button>

        {connector.type === 'mcp_server' && (
          <button
            type="button"
            onClick={() => onIntrospect(connector)}
            className="flex items-center gap-1.5 text-[11px] font-medium px-3 py-1.5 rounded-lg text-sky-300 bg-sky-900/30 hover:bg-sky-900/50 border border-sky-800/40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60"
            aria-label={`Introspect ${connector.name}`}
          >
            <Eye className="w-3 h-3" aria-hidden="true" />
            Introspect
          </button>
        )}
      </div>
    </div>
  )
}

// ─── Stats Row ────────────────────────────────────────────────────────────────

interface StatsRowProps {
  connectors: LiveConnector[]
  lastFetch: Date | null
}

function StatsRow({ connectors, lastFetch }: StatsRowProps) {
  const total = connectors.length
  const connected = connectors.filter((c) => c.status === 'connected' || c.status === 'scanning').length
  const activeThreats = connectors.filter(
    (c) => c.lastScanResult?.verdict === 'malicious' || c.lastScanResult?.verdict === 'suspicious',
  ).length

  const stats = [
    {
      label: 'Total Connectors',
      value: total,
      icon: Plug,
      accent: 'text-cyan-400',
      bg: 'bg-cyan-900/20 border-cyan-800/30',
    },
    {
      label: 'Connected',
      value: connected,
      icon: CheckCircle2,
      accent: 'text-emerald-400',
      bg: 'bg-emerald-900/20 border-emerald-800/30',
    },
    {
      label: 'Active Threats',
      value: activeThreats,
      icon: AlertTriangle,
      accent: activeThreats > 0 ? 'text-red-400' : 'text-slate-500',
      bg: activeThreats > 0 ? 'bg-red-900/20 border-red-800/30' : 'bg-slate-800/40 border-slate-700',
    },
    {
      label: 'Last Refresh',
      value: lastFetch ? formatDistanceToNow(lastFetch, { addSuffix: true }) : '—',
      icon: RefreshCw,
      accent: 'text-slate-400',
      bg: 'bg-slate-800/40 border-slate-700',
      isText: true,
    },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3" role="region" aria-label="Connector statistics">
      {stats.map((stat) => {
        const Icon = stat.icon
        return (
          <div
            key={stat.label}
            className={`flex items-center gap-3 rounded-xl border px-4 py-3 ${stat.bg}`}
          >
            <div
              className={`w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center bg-slate-900/40`}
              aria-hidden="true"
            >
              <Icon className={`w-4 h-4 ${stat.accent}`} />
            </div>
            <div className="min-w-0">
              <p className="text-[10px] text-slate-500 leading-none mb-1">{stat.label}</p>
              <p
                className={`text-sm font-bold leading-none truncate ${stat.isText ? 'text-slate-400 text-[11px]' : stat.accent}`}
              >
                {stat.value}
              </p>
            </div>
          </div>
        )
      })}
    </div>
  )
}

// ─── Main Panel ───────────────────────────────────────────────────────────────

export function ConnectorsPanel() {
  const [connectors, setConnectors] = useState<LiveConnector[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [lastFetch, setLastFetch] = useState<Date | null>(null)
  const [showAddModal, setShowAddModal] = useState(false)
  const [introspectTarget, setIntrospectTarget] = useState<LiveConnector | null>(null)
  const [introspectData, setIntrospectData] = useState<MCPIntrospection | null>(null)
  const [introspectLoading, setIntrospectLoading] = useState(false)
  const [introspectError, setIntrospectError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      const data = await fetchLiveConnectors()
      setConnectors(data)
      setLastFetch(new Date())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load connectors.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function handleScanComplete(updated: LiveConnector) {
    setConnectors((prev) =>
      prev.map((c) =>
        c.id === updated.id
          ? { ...c, ...updated }
          : c,
      ),
    )
    setLastFetch(new Date())
  }

  function handleConnectorAdded(connector: LiveConnector) {
    setConnectors((prev) => [connector, ...prev])
    setLastFetch(new Date())
  }

  async function handleIntrospect(connector: LiveConnector) {
    setIntrospectTarget(connector)
    setIntrospectData(null)
    setIntrospectError(null)
    setIntrospectLoading(true)
    try {
      const data = await fetchMCPIntrospection(connector.id)
      setIntrospectData(data)
    } catch (err) {
      setIntrospectError(err instanceof Error ? err.message : 'Introspection failed.')
    } finally {
      setIntrospectLoading(false)
    }
  }

  function closeIntrospectModal() {
    setIntrospectTarget(null)
    setIntrospectData(null)
    setIntrospectError(null)
    setIntrospectLoading(false)
  }

  // Group connectors by type
  const grouped = GROUP_ORDER.reduce<Record<ConnectorType, LiveConnector[]>>(
    (acc, type) => {
      acc[type] = connectors.filter((c) => c.type === type)
      return acc
    },
    { vector_store: [], mcp_server: [], rag_pipeline: [] },
  )

  return (
    <>
      <div className="space-y-6">
        {/* Stats row */}
        {!loading && !fetchError && (
          <StatsRow connectors={connectors} lastFetch={lastFetch} />
        )}

        {/* Toolbar */}
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-slate-500">
            {loading
              ? 'Loading connectors...'
              : fetchError
              ? 'Could not load connectors.'
              : `${connectors.length} connector${connectors.length !== 1 ? 's' : ''} registered`}
          </p>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={load}
              disabled={loading}
              className="flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded-lg text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60"
              aria-label="Refresh connectors"
            >
              {loading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
              ) : (
                <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              )}
              Refresh
            </button>
            <button
              type="button"
              onClick={() => setShowAddModal(true)}
              className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-lg text-white bg-cyan-600 hover:bg-cyan-500 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60"
              aria-label="Add new connector"
            >
              <Plus className="w-3.5 h-3.5" aria-hidden="true" />
              Add Connector
            </button>
          </div>
        </div>

        {/* Error state */}
        {fetchError && !loading && (
          <div
            role="alert"
            className="flex items-center gap-2.5 text-sm text-red-300 bg-red-950/50 border border-red-900/60 rounded-xl px-4 py-3"
          >
            <AlertTriangle className="w-4 h-4 flex-shrink-0" aria-hidden="true" />
            {fetchError}
          </div>
        )}

        {/* Loading skeleton */}
        {loading && (
          <div className="space-y-6" aria-busy="true" aria-label="Loading connectors">
            {GROUP_ORDER.map((type) => (
              <div key={type}>
                <div className="h-4 w-32 rounded bg-slate-800 mb-4 animate-pulse" />
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {[1, 2].map((i) => (
                    <div
                      key={i}
                      className="h-48 rounded-xl border border-slate-700 bg-slate-800/50 animate-pulse"
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Grouped connector sections */}
        {!loading && !fetchError && (
          <div className="space-y-8">
            {GROUP_ORDER.map((type) => {
              const group = grouped[type]
              const meta = GROUP_META[type]
              const Icon = meta.icon

              return (
                <section key={type} aria-label={meta.label}>
                  <div className="flex items-center gap-2 mb-4">
                    <Icon className={`w-4 h-4 ${meta.accent}`} aria-hidden="true" />
                    <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      {meta.label}
                    </p>
                    <span className="text-[10px] text-slate-600 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded-full tabular-nums">
                      {group.length}
                    </span>
                  </div>

                  {group.length === 0 ? (
                    <div className="rounded-xl border border-slate-700/50 border-dashed bg-slate-800/20 px-5 py-6 text-center">
                      <p className="text-xs text-slate-600">
                        No {meta.label.toLowerCase()} configured.
                      </p>
                      <button
                        type="button"
                        onClick={() => setShowAddModal(true)}
                        className="mt-2 text-xs text-cyan-500 hover:text-cyan-400 underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/60 rounded"
                      >
                        Add one
                      </button>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                      {group.map((connector) => (
                        <ConnectorCard
                          key={connector.id}
                          connector={connector}
                          onScanComplete={handleScanComplete}
                          onIntrospect={handleIntrospect}
                        />
                      ))}
                    </div>
                  )}
                </section>
              )
            })}
          </div>
        )}
      </div>

      {/* Add Connector Modal */}
      {showAddModal && (
        <AddConnectorModal
          onClose={() => setShowAddModal(false)}
          onAdd={handleConnectorAdded}
        />
      )}

      {/* MCP Introspection Modal */}
      {introspectTarget && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label={`MCP Introspection — ${introspectTarget.name}`}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeIntrospectModal()
          }}
        >
          {introspectLoading && (
            <div className="bg-slate-900 border border-slate-700 rounded-2xl px-8 py-10 flex flex-col items-center gap-3 shadow-2xl">
              <Loader2 className="w-7 h-7 text-sky-400 animate-spin" aria-hidden="true" />
              <p className="text-sm text-slate-400">Introspecting {introspectTarget.name}...</p>
            </div>
          )}

          {introspectError && !introspectLoading && (
            <div className="bg-slate-900 border border-red-800/60 rounded-2xl px-8 py-10 flex flex-col items-center gap-3 shadow-2xl max-w-sm">
              <AlertTriangle className="w-7 h-7 text-red-400" aria-hidden="true" />
              <p className="text-sm text-slate-300 text-center">{introspectError}</p>
              <button
                type="button"
                onClick={closeIntrospectModal}
                className="mt-1 text-xs text-slate-400 hover:text-slate-200 underline underline-offset-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60 rounded"
              >
                Close
              </button>
            </div>
          )}

          {introspectData && !introspectLoading && (
            <MCPIntrospectionModal
              connectorName={introspectTarget.name}
              data={introspectData}
              onClose={closeIntrospectModal}
            />
          )}
        </div>
      )}
    </>
  )
}
