/**
 * RAG Scanning page — document scan results, cosine deviation chart,
 * hidden instruction findings, and batch upload form.
 */

export const dynamic = 'force-dynamic'

import type { Metadata } from 'next'
import { fetchRAGResults, fetchCosineHistogram, fetchHiddenInstructions } from '@/lib/api'
import { ThreatBadge } from '@/components/ThreatBadge'
import { CosineHistogram } from './CosineHistogram'
import { BatchUploadForm } from './BatchUploadForm'
import { AlertTriangle, CheckCircle2, Clock } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import type { VerdictLabel } from '@/lib/types'

export const metadata: Metadata = { title: 'RAG Scanning' }
export const revalidate = 30

// ─── Verdict badge ─────────────────────────────────────────────────────────────

const VERDICT_MAP: Record<VerdictLabel, { severity: 'critical' | 'warning' | 'safe' | 'info'; label: string }> = {
  clean:      { severity: 'safe',     label: 'Clean' },
  suspicious: { severity: 'warning',  label: 'Suspicious' },
  malicious:  { severity: 'critical', label: 'Malicious' },
  unknown:    { severity: 'info',     label: 'Unknown' },
}

// ─── Pattern type label ────────────────────────────────────────────────────────

const PATTERN_LABELS: Record<string, string> = {
  prompt_injection: 'Prompt Injection',
  jailbreak: 'Jailbreak',
  data_exfil: 'Data Exfiltration',
  role_override: 'Role Override',
}

export default async function RAGPage() {
  const [results, histogram, findings] = await Promise.all([
    fetchRAGResults({ limit: 20 }),
    fetchCosineHistogram(),
    fetchHiddenInstructions(),
  ])

  const maliciousCount = results.filter((r) => r.verdict === 'malicious').length
  const suspiciousCount = results.filter((r) => r.verdict === 'suspicious').length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">RAG Scanning</h1>
          <p className="text-sm text-slate-400 mt-0.5">
            Document corpus integrity — cosine deviation and hidden instruction detection
          </p>
        </div>
        <div className="flex gap-2">
          {maliciousCount > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-red-300 bg-red-950 border border-red-900 px-3 py-1.5 rounded-full">
              <AlertTriangle className="w-3 h-3" aria-hidden="true" />
              {maliciousCount} malicious doc{maliciousCount !== 1 ? 's' : ''}
            </span>
          )}
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Cosine deviation histogram */}
        <section aria-label="Cosine deviation distribution" className="xl:col-span-2 card">
          <h2 className="text-sm font-semibold text-slate-200 mb-1">Cosine Deviation Distribution</h2>
          <p className="text-xs text-slate-500 mb-4">
            Higher deviation indicates larger semantic shift from training baseline
          </p>
          <CosineHistogram bins={histogram} />
          <div className="mt-3 flex gap-4 text-xs text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-blue-500 opacity-80" aria-hidden="true" />
              Normal (0–0.3)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-amber-500 opacity-80" aria-hidden="true" />
              Suspicious (0.3–0.6)
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-red-500 opacity-80" aria-hidden="true" />
              Malicious (&gt;0.6)
            </span>
          </div>
        </section>

        {/* Hidden instruction findings */}
        <section aria-label="Hidden instruction findings">
          <div className="card h-full">
            <h2 className="text-sm font-semibold text-slate-200 mb-4">
              Hidden Instruction Findings
              {findings.length > 0 && (
                <span className="ml-2 bg-red-500 text-white text-[10px] font-bold px-1.5 py-0.5 rounded-full">
                  {findings.length}
                </span>
              )}
            </h2>
            {findings.length === 0 ? (
              <div className="flex flex-col items-center gap-2 py-8 text-slate-500">
                <CheckCircle2 className="w-6 h-6 text-green-500" aria-hidden="true" />
                <p className="text-sm">No hidden instructions detected</p>
              </div>
            ) : (
              <div className="space-y-3">
                {findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-3 rounded-lg bg-red-950/40 border border-red-900/60"
                    role="alert"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wide">
                        {PATTERN_LABELS[f.patternType] ?? f.patternType}
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {(f.confidence * 100).toFixed(0)}% conf.
                      </span>
                    </div>
                    <p className="text-xs text-red-300/80 font-mono leading-relaxed truncate-2 break-all">
                      {f.snippet}
                    </p>
                    <div className="flex items-center gap-1 mt-2">
                      <Clock className="w-3 h-3 text-slate-600" aria-hidden="true" />
                      <time dateTime={f.detectedAt} className="text-[10px] text-slate-600">
                        {formatDistanceToNow(new Date(f.detectedAt), { addSuffix: true })}
                      </time>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Scan results table */}
      <section aria-label="Document scan results">
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-200 mb-5">Document Scan Results</h2>
          <div className="overflow-x-auto -mx-5 px-5">
            <table className="data-table" aria-label="Document scan results">
              <thead>
                <tr>
                  <th>Document ID</th>
                  <th>Source</th>
                  <th>Cosine Dev.</th>
                  <th>Verdict</th>
                  <th>Hidden Instructions</th>
                  <th>Duration</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r) => {
                  const verdict = VERDICT_MAP[r.verdict]
                  return (
                    <tr key={r.id}>
                      <td>
                        <span className="font-mono text-xs text-slate-300">{r.documentId}</span>
                      </td>
                      <td>
                        <span
                          className="text-xs text-slate-400 max-w-[200px] block truncate"
                          title={r.source}
                        >
                          {r.source}
                        </span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full"
                              style={{
                                width: `${Math.min(r.cosineDeviation * 100, 100)}%`,
                                background:
                                  r.cosineDeviation > 0.6
                                    ? '#ef4444'
                                    : r.cosineDeviation > 0.3
                                    ? '#f59e0b'
                                    : '#3b82f6',
                              }}
                              aria-label={`Cosine deviation: ${(r.cosineDeviation * 100).toFixed(1)}%`}
                            />
                          </div>
                          <span className="font-mono text-xs text-slate-300 tabular-nums">
                            {r.cosineDeviation.toFixed(4)}
                          </span>
                        </div>
                      </td>
                      <td>
                        <ThreatBadge severity={verdict.severity} label={verdict.label} size="sm" />
                      </td>
                      <td>
                        {r.hasHiddenInstructions ? (
                          <span className="flex items-center gap-1 text-xs text-red-400">
                            <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                            Detected
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-slate-500">
                            <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                            None
                          </span>
                        )}
                      </td>
                      <td>
                        <span className="text-xs text-slate-500 tabular-nums font-mono">
                          {r.scanDurationMs}ms
                        </span>
                      </td>
                      <td>
                        <time dateTime={r.timestamp} className="text-xs text-slate-500 whitespace-nowrap">
                          {formatDistanceToNow(new Date(r.timestamp), { addSuffix: true })}
                        </time>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Batch upload form */}
      <section aria-label="Batch document scan">
        <BatchUploadForm />
      </section>
    </div>
  )
}
