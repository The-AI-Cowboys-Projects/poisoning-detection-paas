/**
 * SettingsPanel — client component for tenant configuration, API key management,
 * notification preferences, detection thresholds, and system health status.
 */

'use client'

import { useState, useCallback, useEffect } from 'react'
import {
  Key,
  Bell,
  Shield,
  Sliders,
  Copy,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  Check,
  Server,
  Database,
  Activity,
  Wifi,
  Loader2,
  AlertTriangle,
} from 'lucide-react'
import {
  updateTenantSettings,
  updateNotificationPrefs,
  updateDetectionThresholds,
  createApiKey,
  revokeApiKey,
  fetchSystemHealth,
} from '@/lib/api'

// ─── Types ───────────────────────────────────────────────────────────────────

type SettingsTab = 'general' | 'api-keys' | 'notifications' | 'thresholds' | 'health'

interface ApiKeyEntry {
  id: string
  name: string
  prefix: string
  createdAt: string
  lastUsed: string | null
  isRevoked: boolean
}

// ─── Tab buttons ─────────────────────────────────────────────────────────────

const TABS: { id: SettingsTab; label: string; icon: typeof Key }[] = [
  { id: 'general',       label: 'General',       icon: Shield },
  { id: 'api-keys',      label: 'API Keys',      icon: Key },
  { id: 'notifications', label: 'Notifications',  icon: Bell },
  { id: 'thresholds',    label: 'Thresholds',    icon: Sliders },
  { id: 'health',        label: 'System Health',  icon: Activity },
]

// ─── General settings ────────────────────────────────────────────────────────

function GeneralSettings() {
  const [tenantName, setTenantName] = useState('Acme Corp')
  const [contactEmail, setContactEmail] = useState('analyst@acme.io')
  const [tier, setTier] = useState('enterprise')
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const save = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      await updateTenantSettings({ tenantName, contactEmail, tier })
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-sm font-semibold text-slate-200 mb-4">Tenant Configuration</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Organization Name</label>
            <input
              type="text"
              value={tenantName}
              onChange={e => setTenantName(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Contact Email</label>
            <input
              type="email"
              value={contactEmail}
              onChange={e => setContactEmail(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Subscription Tier</label>
            <select
              value={tier}
              onChange={e => setTier(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
            >
              <option value="free">Free</option>
              <option value="pro">Pro</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </div>
          <div>
            <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Tenant ID</label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
                readOnly
                className="w-full bg-slate-900 border border-slate-700 text-slate-500 text-xs font-mono rounded-lg px-3 py-2"
              />
              <button
                onClick={() => navigator.clipboard?.writeText('a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d')}
                className="text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0"
                title="Copy"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {saveError && (
        <p className="text-xs text-red-400 flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3" /> {saveError}
        </p>
      )}

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <button
          onClick={save}
          disabled={saving}
          className="flex items-center gap-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-2 rounded-lg transition-colors"
        >
          {saving ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
           : saved ? <><Check className="w-3.5 h-3.5" /> Saved</>
           : 'Save Changes'}
        </button>
      </div>
    </div>
  )
}

// ─── API key management ──────────────────────────────────────────────────────

function ApiKeySettings() {
  const [keys, setKeys] = useState<ApiKeyEntry[]>([
    { id: 'key-1', name: 'Production Scanner',  prefix: 'aispm_prod_7x9k', createdAt: '2026-03-15T00:00:00Z', lastUsed: '2026-04-14T09:30:00Z', isRevoked: false },
    { id: 'key-2', name: 'CI/CD Pipeline',      prefix: 'aispm_ci_m2q4',   createdAt: '2026-04-01T00:00:00Z', lastUsed: '2026-04-14T08:15:00Z', isRevoked: false },
    { id: 'key-3', name: 'Dev Environment',      prefix: 'aispm_dev_n8p1',  createdAt: '2026-02-20T00:00:00Z', lastUsed: null,                    isRevoked: true },
  ])
  const [showNew, setShowNew] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [generatedKey, setGeneratedKey] = useState<string | null>(null)
  const [visibleKeys, setVisibleKeys] = useState<Set<string>>(new Set())

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return
    try {
      const result = await createApiKey(newKeyName)
      const newEntry: ApiKeyEntry = {
        id: result.id,
        name: result.name,
        prefix: result.prefix,
        createdAt: new Date().toISOString(),
        lastUsed: null,
        isRevoked: false,
      }
      setKeys(prev => [newEntry, ...prev])
      setGeneratedKey(result.key)
      setNewKeyName('')
    } catch {
      setGeneratedKey(null)
    }
  }

  const handleRevokeKey = async (id: string) => {
    setKeys(prev => prev.map(k => k.id === id ? { ...k, isRevoked: true } : k))
    try {
      await revokeApiKey(id)
    } catch {
      // Revert on failure
      setKeys(prev => prev.map(k => k.id === id ? { ...k, isRevoked: false } : k))
    }
  }

  const toggleVisible = (id: string) => {
    setVisibleKeys(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">API Keys</h3>
        <button
          onClick={() => { setShowNew(!showNew); setGeneratedKey(null) }}
          className="flex items-center gap-1.5 text-xs font-medium text-blue-400 bg-blue-900/30 border border-blue-800/50 px-3 py-1.5 rounded-lg hover:bg-blue-900/50 transition-colors"
        >
          <Plus className="w-3 h-3" /> New Key
        </button>
      </div>

      {showNew && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 space-y-3">
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Key Name</label>
              <input
                type="text"
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                placeholder="e.g., Production Scanner"
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
              />
            </div>
            <button
              onClick={handleCreateKey}
              disabled={!newKeyName.trim()}
              className="text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 px-4 py-2 rounded-lg transition-colors"
            >
              Generate
            </button>
          </div>
          {generatedKey && (
            <div className="bg-green-950/30 border border-green-800/40 rounded-lg px-3 py-2">
              <p className="text-[10px] text-green-400 font-semibold mb-1">Key created — copy it now, it won&apos;t be shown again:</p>
              <div className="flex items-center gap-2">
                <code className="text-xs text-green-300 font-mono flex-1 break-all">{generatedKey}</code>
                <button
                  onClick={() => navigator.clipboard?.writeText(generatedKey)}
                  className="text-green-400 hover:text-green-300 flex-shrink-0"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="data-table" aria-label="API keys">
          <thead>
            <tr>
              <th>Name</th>
              <th>Key Prefix</th>
              <th>Created</th>
              <th>Last Used</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {keys.map(key => (
              <tr key={key.id} className={key.isRevoked ? 'opacity-50' : ''}>
                <td><span className="text-sm text-slate-200 font-medium">{key.name}</span></td>
                <td>
                  <div className="flex items-center gap-1.5">
                    <code className="text-xs text-slate-400 font-mono">
                      {visibleKeys.has(key.id) ? key.prefix : `${key.prefix.slice(0, 10)}${'•'.repeat(8)}`}
                    </code>
                    <button onClick={() => toggleVisible(key.id)} className="text-slate-500 hover:text-slate-300 transition-colors">
                      {visibleKeys.has(key.id) ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    </button>
                  </div>
                </td>
                <td><span className="text-xs text-slate-500">{new Date(key.createdAt).toLocaleDateString()}</span></td>
                <td><span className="text-xs text-slate-500">{key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : 'Never'}</span></td>
                <td>
                  <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${
                    key.isRevoked
                      ? 'bg-red-900/50 text-red-300 border-red-800'
                      : 'bg-green-900/50 text-green-300 border-green-800'
                  }`}>
                    {key.isRevoked ? 'Revoked' : 'Active'}
                  </span>
                </td>
                <td>
                  {!key.isRevoked && (
                    <button
                      onClick={() => handleRevokeKey(key.id)}
                      className="text-red-400 hover:text-red-300 transition-colors p-1"
                      title="Revoke key"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Notification preferences ────────────────────────────────────────────────

function NotificationSettings() {
  const [prefs, setPrefs] = useState({
    emailCritical: true,
    emailWarning: true,
    emailInfo: false,
    slackCritical: true,
    slackWarning: false,
    webhookEnabled: false,
    webhookUrl: '',
    digestFrequency: 'daily',
  })
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const toggle = (key: keyof typeof prefs) => {
    setPrefs(p => ({ ...p, [key]: !p[key] }))
  }

  const save = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      await updateNotificationPrefs(prefs)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-6">
      <h3 className="text-sm font-semibold text-slate-200">Notification Preferences</h3>

      {/* Email notifications */}
      <div>
        <p className="text-xs text-slate-400 font-medium mb-3">Email Alerts</p>
        <div className="space-y-2">
          {([['emailCritical', 'Critical threats'], ['emailWarning', 'Warnings'], ['emailInfo', 'Informational']] as const).map(([key, label]) => (
            <label key={key} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={prefs[key] as boolean}
                onChange={() => toggle(key)}
                className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-blue-500 focus:ring-blue-500/40"
              />
              <span className="text-sm text-slate-300">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Slack */}
      <div>
        <p className="text-xs text-slate-400 font-medium mb-3">Slack Integration</p>
        <div className="space-y-2">
          {([['slackCritical', 'Critical threats'], ['slackWarning', 'Warnings']] as const).map(([key, label]) => (
            <label key={key} className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={prefs[key] as boolean}
                onChange={() => toggle(key)}
                className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-blue-500 focus:ring-blue-500/40"
              />
              <span className="text-sm text-slate-300">{label}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Webhook */}
      <div>
        <p className="text-xs text-slate-400 font-medium mb-3">Webhook</p>
        <label className="flex items-center gap-3 cursor-pointer mb-3">
          <input
            type="checkbox"
            checked={prefs.webhookEnabled}
            onChange={() => toggle('webhookEnabled')}
            className="w-4 h-4 rounded bg-slate-800 border-slate-600 text-blue-500 focus:ring-blue-500/40"
          />
          <span className="text-sm text-slate-300">Enable webhook notifications</span>
        </label>
        {prefs.webhookEnabled && (
          <input
            type="url"
            value={prefs.webhookUrl}
            onChange={e => setPrefs(p => ({ ...p, webhookUrl: e.target.value }))}
            placeholder="https://your-app.com/webhook"
            className="w-full bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
          />
        )}
      </div>

      {/* Digest frequency */}
      <div>
        <label className="text-[10px] text-slate-500 uppercase tracking-wide block mb-1">Digest Frequency</label>
        <select
          value={prefs.digestFrequency}
          onChange={e => setPrefs(p => ({ ...p, digestFrequency: e.target.value }))}
          className="bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/40 outline-none"
        >
          <option value="realtime">Real-time</option>
          <option value="hourly">Hourly</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
        </select>
      </div>

      {saveError && (
        <p className="text-xs text-red-400 flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3" /> {saveError}
        </p>
      )}

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <button onClick={save} disabled={saving} className="flex items-center gap-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-2 rounded-lg transition-colors">
          {saving ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
           : saved ? <><Check className="w-3.5 h-3.5" /> Saved</>
           : 'Save Preferences'}
        </button>
      </div>
    </div>
  )
}

// ─── Detection thresholds ────────────────────────────────────────────────────

function ThresholdSettings() {
  const [thresholds, setThresholds] = useState({
    vectorAnomalyScore: 0.75,
    ragCosineDeviation: 0.65,
    toolRiskScore: 70,
    provenanceContamination: 0.5,
    telemetryRiskScore: 0.8,
    falsePositiveTarget: 0.05,
  })
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  const update = (key: keyof typeof thresholds, value: number) => {
    setThresholds(prev => ({ ...prev, [key]: value }))
  }

  const save = async () => {
    setSaving(true)
    setSaveError(null)
    try {
      await updateDetectionThresholds(thresholds)
      setSaved(true)
      setTimeout(() => setSaved(false), 2000)
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  const sliders: { key: keyof typeof thresholds; label: string; description: string; min: number; max: number; step: number; unit: string }[] = [
    { key: 'vectorAnomalyScore', label: 'Vector Anomaly Threshold', description: 'Minimum anomaly score to flag a vector as suspicious', min: 0, max: 1, step: 0.05, unit: '' },
    { key: 'ragCosineDeviation', label: 'RAG Cosine Deviation', description: 'Cosine deviation threshold for hidden instruction detection', min: 0, max: 1, step: 0.05, unit: '' },
    { key: 'toolRiskScore', label: 'MCP Tool Risk Score', description: 'Minimum risk score (0-100) to flag a tool schema', min: 0, max: 100, step: 5, unit: '' },
    { key: 'provenanceContamination', label: 'Provenance Contamination', description: 'Contamination score threshold for lineage alerts', min: 0, max: 1, step: 0.05, unit: '' },
    { key: 'telemetryRiskScore', label: 'Telemetry Risk Score', description: 'Risk score threshold for trace-level anomaly detection', min: 0, max: 1, step: 0.05, unit: '' },
    { key: 'falsePositiveTarget', label: 'False Positive Target', description: 'Target false positive rate — lower = more alerts but fewer misses', min: 0.01, max: 0.2, step: 0.01, unit: '' },
  ]

  return (
    <div className="space-y-6">
      <h3 className="text-sm font-semibold text-slate-200">Detection Thresholds</h3>
      <p className="text-xs text-slate-500">Adjust sensitivity for each detection engine. Lower thresholds catch more threats but may increase false positives.</p>

      <div className="space-y-5">
        {sliders.map(s => (
          <div key={s.key}>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs text-slate-300 font-medium">{s.label}</label>
              <span className="text-xs text-blue-400 font-mono font-bold">{thresholds[s.key]}{s.unit}</span>
            </div>
            <p className="text-[10px] text-slate-500 mb-2">{s.description}</p>
            <input
              type="range"
              min={s.min}
              max={s.max}
              step={s.step}
              value={thresholds[s.key]}
              onChange={e => update(s.key, Number(e.target.value))}
              className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-blue-500"
            />
          </div>
        ))}
      </div>

      {saveError && (
        <p className="text-xs text-red-400 flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3" /> {saveError}
        </p>
      )}

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <button onClick={save} disabled={saving} className="flex items-center gap-2 text-xs font-medium text-white bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-2 rounded-lg transition-colors">
          {saving ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Saving...</>
           : saved ? <><Check className="w-3.5 h-3.5" /> Saved</>
           : 'Save Thresholds'}
        </button>
      </div>
    </div>
  )
}

// ─── System health ───────────────────────────────────────────────────────────

function SystemHealth() {
  const [loading, setLoading] = useState(true)
  const [services, setServices] = useState<Array<{
    name: string
    icon: typeof Server
    status: 'healthy' | 'degraded' | 'down'
    latency: string
    uptime: string
  }>>([])

  const ICON_MAP: Record<string, typeof Server> = {
    'FastAPI Backend': Server,
    'PostgreSQL': Database,
    'Redis Cache': Activity,
    'Neo4j Graph': Database,
    'Supabase Edge': Wifi,
    'Kafka Streaming': Activity,
  }

  useEffect(() => {
    fetchSystemHealth().then(data => {
      setServices(data.map(s => ({
        name: s.name,
        icon: ICON_MAP[s.name] ?? Server,
        status: s.status,
        latency: s.latency_ms != null ? `${s.latency_ms}ms` : 'N/A',
        uptime: s.uptime_pct != null ? `${s.uptime_pct}%` : 'N/A',
      })))
    }).catch(() => {
      setServices([{ name: 'Health Check', icon: Server, status: 'down', latency: 'N/A', uptime: 'N/A' }])
    }).finally(() => setLoading(false))
  }, [])

  const statusStyles = {
    healthy:  'bg-green-900/50 text-green-300 border-green-800',
    degraded: 'bg-amber-900/50 text-amber-300 border-amber-800',
    down:     'bg-red-900/50 text-red-300 border-red-800',
  }

  return (
    <div className="space-y-6">
      <h3 className="text-sm font-semibold text-slate-200">System Health</h3>

      {loading ? (
        <div className="flex items-center gap-2 text-slate-500 text-sm py-8 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" /> Checking services...
        </div>
      ) : (
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
        {services.map(svc => {
          const Icon = svc.icon
          return (
            <div key={svc.name} className="card border border-slate-700">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                  <Icon className="w-4 h-4 text-slate-400" aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-slate-200">{svc.name}</p>
                </div>
                <span className={`text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${statusStyles[svc.status]}`}>
                  {svc.status}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="bg-slate-800/50 rounded px-2 py-1">
                  <p className="text-[9px] text-slate-500 uppercase">Latency</p>
                  <p className="text-xs text-slate-300 font-mono">{svc.latency}</p>
                </div>
                <div className="bg-slate-800/50 rounded px-2 py-1">
                  <p className="text-[9px] text-slate-500 uppercase">Uptime</p>
                  <p className="text-xs text-slate-300 font-mono">{svc.uptime}</p>
                </div>
              </div>
            </div>
          )
        })}
      </div>
      )}

      <div className="bg-amber-950/30 border border-amber-800/40 rounded-lg px-4 py-3">
        <p className="text-xs text-amber-300">
          <span className="font-semibold">Note:</span> Kafka streaming is configured but not yet wired to the main event loop.
          Event ingestion currently operates synchronously through the REST API and Supabase Edge Functions.
        </p>
      </div>
    </div>
  )
}

// ─── Main panel ──────────────────────────────────────────────────────────────

export function SettingsPanel() {
  const [activeTab, setActiveTab] = useState<SettingsTab>('general')

  const renderContent = useCallback(() => {
    switch (activeTab) {
      case 'general':       return <GeneralSettings />
      case 'api-keys':      return <ApiKeySettings />
      case 'notifications': return <NotificationSettings />
      case 'thresholds':    return <ThresholdSettings />
      case 'health':        return <SystemHealth />
    }
  }, [activeTab])

  return (
    <div className="space-y-6">
      {/* Tabs */}
      <div className="flex gap-1 overflow-x-auto pb-1">
        {TABS.map(tab => {
          const Icon = tab.icon
          const active = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={[
                'flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-all',
                active
                  ? 'bg-blue-600/20 text-blue-300 border border-blue-600/30'
                  : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200 border border-transparent',
              ].join(' ')}
            >
              <Icon className="w-3.5 h-3.5" aria-hidden="true" />
              {tab.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      <div className="card border border-slate-700">
        {renderContent()}
      </div>
    </div>
  )
}
