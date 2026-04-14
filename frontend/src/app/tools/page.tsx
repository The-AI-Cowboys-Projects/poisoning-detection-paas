/**
 * MCP Tool Audit page — risk cards, known threat patterns, schema analysis panels.
 */

import type { Metadata } from 'next'
import { fetchToolAudits, fetchKnownThreatPatterns } from '@/lib/api'
import { ThreatBadge } from '@/components/ThreatBadge'
import { RiskGauge } from './RiskGauge'
import { SchemaPanel } from './SchemaPanel'
import { Shield, ShieldAlert, Clock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export const metadata: Metadata = { title: 'MCP Tool Audit' }
export const revalidate = 60

const CATEGORY_LABELS: Record<string, string> = {
  backdoor: 'Backdoor',
  data_exfil: 'Data Exfil',
  privilege_escalation: 'Priv. Escalation',
  lateral_movement: 'Lateral Movement',
}

const CATEGORY_COLORS: Record<string, string> = {
  backdoor: 'text-red-400 bg-red-900/40 border-red-900',
  data_exfil: 'text-amber-400 bg-amber-900/40 border-amber-900',
  privilege_escalation: 'text-purple-400 bg-purple-900/40 border-purple-900',
  lateral_movement: 'text-orange-400 bg-orange-900/40 border-orange-900',
}

export default async function ToolsPage() {
  const [audits, patterns] = await Promise.all([
    fetchToolAudits(),
    fetchKnownThreatPatterns(),
  ])

  const criticalTools = audits.filter((a) => a.severity === 'critical').length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">MCP Tool Audit</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Schema analysis and risk scoring for Model Context Protocol tools
          </p>
        </div>
        {criticalTools > 0 && (
          <span className="flex items-center gap-1.5 text-xs text-red-300 bg-red-950 border border-red-900 px-3 py-1.5 rounded-full">
            <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
            {criticalTools} critical risk tool{criticalTools !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Tool audit cards */}
      <section aria-label="Tool audit results">
        <p className="section-heading">Audited Tools</p>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {audits.map((audit) => (
            <div
              key={audit.id}
              className={[
                'card border transition-shadow hover:shadow-lg',
                audit.severity === 'critical'
                  ? 'border-red-800/60 glow-critical'
                  : audit.severity === 'warning'
                  ? 'border-amber-800/40'
                  : 'border-slate-700',
              ].join(' ')}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div
                    className={[
                      'w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0',
                      audit.severity === 'critical'
                        ? 'bg-red-900/50 text-red-400'
                        : audit.severity === 'warning'
                        ? 'bg-amber-900/50 text-amber-400'
                        : 'bg-green-900/40 text-green-400',
                    ].join(' ')}
                    aria-hidden="true"
                  >
                    {audit.severity === 'critical' || audit.severity === 'warning' ? (
                      <ShieldAlert className="w-4 h-4" />
                    ) : (
                      <Shield className="w-4 h-4" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-slate-200">{audit.toolName}</p>
                    <p className="text-[10px] text-slate-500">v{audit.toolVersion}</p>
                  </div>
                </div>
                <ThreatBadge severity={audit.severity} size="sm" />
              </div>

              {/* Risk gauge */}
              <div className="mb-3">
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="text-slate-500">Risk Score</span>
                  <span
                    className={[
                      'font-bold tabular-nums',
                      audit.riskScore >= 70
                        ? 'text-red-400'
                        : audit.riskScore >= 40
                        ? 'text-amber-400'
                        : 'text-green-400',
                    ].join(' ')}
                  >
                    {audit.riskScore}/100
                  </span>
                </div>
                <RiskGauge score={audit.riskScore} />
              </div>

              {/* Schema hash */}
              <div className="mb-3">
                <p className="text-[10px] text-slate-600 mb-1">Schema hash</p>
                <p className="font-mono text-[10px] text-slate-500 truncate">{audit.schemaHash}</p>
              </div>

              {/* Audited time */}
              <div className="flex items-center gap-1.5 text-[10px] text-slate-600 mb-3">
                <Clock className="w-3 h-3" aria-hidden="true" />
                Audited {formatDistanceToNow(new Date(audit.auditedAt), { addSuffix: true })}
              </div>

              {/* Findings — expandable schema panels */}
              {audit.findings.length > 0 && (
                <div className="border-t border-slate-700 pt-3">
                  <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-wide mb-2">
                    {audit.findings.length} Finding{audit.findings.length !== 1 ? 's' : ''}
                  </p>
                  {audit.findings.map((f) => (
                    <SchemaPanel key={f.id} finding={f} />
                  ))}
                </div>
              )}

              {audit.findings.length === 0 && (
                <div className="flex items-center gap-1.5 text-xs text-green-400">
                  <Shield className="w-3.5 h-3.5" aria-hidden="true" />
                  No findings — passed all patterns
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Known threat patterns */}
      <section aria-label="Known threat patterns">
        <p className="section-heading">Known Threat Patterns</p>
        <div className="card">
          <div className="space-y-0">
            {patterns.map((pattern, i) => (
              <div
                key={pattern.id}
                className={[
                  'py-4 flex flex-col sm:flex-row sm:items-start gap-3',
                  i < patterns.length - 1 ? 'border-b border-slate-700/50' : '',
                ].join(' ')}
              >
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="font-mono text-[10px] text-slate-600 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded">
                    {pattern.id}
                  </span>
                  <span
                    className={[
                      'text-[10px] font-semibold px-2 py-0.5 rounded-full border',
                      CATEGORY_COLORS[pattern.category] ?? 'text-slate-400 bg-slate-800 border-slate-700',
                    ].join(' ')}
                  >
                    {CATEGORY_LABELS[pattern.category] ?? pattern.category}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-slate-200">{pattern.name}</p>
                  <p className="text-xs text-slate-500 mt-0.5">{pattern.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-[10px] text-slate-600">
                    <span>
                      <span className="text-slate-400 font-semibold">{pattern.matchCount}</span> match{pattern.matchCount !== 1 ? 'es' : ''}
                    </span>
                    <span>
                      First seen:{' '}
                      {formatDistanceToNow(new Date(pattern.firstSeen), { addSuffix: true })}
                    </span>
                    <span>
                      Last:{' '}
                      {formatDistanceToNow(new Date(pattern.lastSeen), { addSuffix: true })}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
