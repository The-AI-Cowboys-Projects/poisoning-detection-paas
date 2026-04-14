/**
 * ProofsPanel — Cryptographic Proof Chain viewer + Detection Coverage Matrix.
 *
 * Tab 1 — Proof Chain:
 *   Loads hash-chained scan proofs, shows chain stats, per-block breakdown
 *   (scanId, timestamp, engine, verdict, content/result/chain hashes),
 *   and a "Verify Chain" action with live feedback.
 *
 * Tab 2 — Coverage Matrix:
 *   Heatmap table (19 techniques × 5 engines), combined row, per-engine bar
 *   chart via recharts, gaps list, and overall coverage prominently shown.
 *
 * Usage:
 *   <ProofsPanel />
 */

'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Fingerprint,
  ShieldCheck,
  Link,
  Copy,
  CheckCircle2,
  XCircle,
  Loader2,
  Grid3x3,
  AlertTriangle,
  Lock,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { fetchProofChain, verifyProofChain, fetchCoverageMatrix } from '@/lib/api'
import type { ProofChain, ScanProof, CoverageMatrix } from '@/lib/types'

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = 'chain' | 'coverage'

type VerifyState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'valid'; message: string }
  | { status: 'invalid'; message: string; invalidAt: number | null }

// ─── Constants ────────────────────────────────────────────────────────────────

const VERDICT_CONFIG = {
  clean:      { label: 'Clean',      bg: 'bg-green-900/50',  text: 'text-green-300',  border: 'border-green-800/50' },
  suspicious: { label: 'Suspicious', bg: 'bg-amber-900/50',  text: 'text-amber-300',  border: 'border-amber-800/50' },
  malicious:  { label: 'Malicious',  bg: 'bg-red-900/50',    text: 'text-red-300',    border: 'border-red-800/50'   },
  unknown:    { label: 'Unknown',    bg: 'bg-slate-700',      text: 'text-slate-400',  border: 'border-slate-600'    },
} as const

const ENGINE_COLORS: Record<string, string> = {
  'RAG Detector':    '#8b5cf6',
  'Vector Analyzer': '#3b82f6',
  'MCP Auditor':     '#06b6d4',
  'Provenance':      '#10b981',
  'Telemetry':       '#f59e0b',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function truncateHash(hash: string, chars = 12): string {
  if (hash.length <= chars * 2 + 3) return hash
  return `${hash.slice(0, chars)}…${hash.slice(-chars)}`
}

function formatTimestamp(iso: string): string {
  try {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(new Date(iso))
  } catch {
    return iso
  }
}

function cellColor(rate: number): string {
  if (rate >= 0.8) return 'bg-green-900/50 text-green-300'
  if (rate >= 0.5) return 'bg-amber-900/50 text-amber-300'
  return 'bg-red-900/50 text-red-300'
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function VerdictBadge({ verdict }: { verdict: ScanProof['verdict'] }) {
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.unknown
  return (
    <span
      className={`inline-flex items-center text-[10px] font-semibold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.text} ${cfg.border}`}
      aria-label={`Verdict: ${cfg.label}`}
    >
      {cfg.label}
    </span>
  )
}

function EngineBadge({ engine }: { engine: string }) {
  return (
    <span className="inline-flex items-center text-[10px] font-medium px-2 py-0.5 rounded bg-slate-700 text-slate-300 border border-slate-600 whitespace-nowrap">
      {engine}
    </span>
  )
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // clipboard unavailable in some environments — silent fail
    }
  }, [value])

  return (
    <button
      onClick={handleCopy}
      className="ml-1.5 text-slate-500 hover:text-slate-300 transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-blue-500 rounded"
      aria-label={copied ? 'Copied!' : `Copy ${label}`}
      title={copied ? 'Copied!' : `Copy ${label}`}
    >
      {copied ? (
        <CheckCircle2 className="w-3 h-3 text-green-400" aria-hidden="true" />
      ) : (
        <Copy className="w-3 h-3" aria-hidden="true" />
      )}
    </button>
  )
}

function HashRow({
  label,
  hash,
  highlight = false,
}: {
  label: string
  hash: string
  highlight?: boolean
}) {
  return (
    <div className="flex items-center gap-1.5 min-w-0">
      <span className="text-[10px] text-slate-500 w-20 flex-shrink-0">{label}</span>
      <span
        className={`font-mono text-[10px] truncate ${
          highlight ? 'text-green-400' : 'text-slate-400'
        }`}
        title={hash}
      >
        {truncateHash(hash)}
      </span>
      <CopyButton value={hash} label={label} />
    </div>
  )
}

// ─── Proof Chain Tab ──────────────────────────────────────────────────────────

function ProofBlock({
  proof,
  index,
  isLast,
  isInvalidAt,
}: {
  proof: ScanProof
  index: number
  isLast: boolean
  isInvalidAt: boolean
}) {
  const isGenesis = proof.previousProofHash === null

  return (
    <div className="relative flex gap-3">
      {/* Vertical connector line */}
      {!isLast && (
        <div
          className="absolute left-[19px] top-[40px] bottom-0 w-px bg-slate-700"
          aria-hidden="true"
        />
      )}

      {/* Block index bubble */}
      <div
        className={`flex-shrink-0 w-10 h-10 rounded-full border-2 flex items-center justify-center text-xs font-bold z-10 ${
          isInvalidAt
            ? 'border-red-500 bg-red-900/40 text-red-300'
            : isGenesis
            ? 'border-violet-500 bg-violet-900/40 text-violet-300'
            : 'border-slate-600 bg-slate-800 text-slate-400'
        }`}
        aria-label={`Block ${index + 1}${isGenesis ? ' (genesis)' : ''}`}
      >
        {isGenesis ? (
          <Lock className="w-4 h-4" aria-hidden="true" />
        ) : (
          <span>{index + 1}</span>
        )}
      </div>

      {/* Block card */}
      <div
        className={`flex-1 mb-3 rounded-xl border p-3 ${
          isInvalidAt
            ? 'bg-red-900/10 border-red-800/50'
            : 'bg-slate-800/80 border-slate-700'
        }`}
        role="listitem"
        aria-label={`Scan proof ${proof.scanId}`}
      >
        {/* Header row */}
        <div className="flex flex-wrap items-center gap-2 mb-2">
          <span className="font-mono text-xs text-slate-300 font-semibold">
            {proof.scanId}
          </span>
          <EngineBadge engine={proof.engine} />
          <VerdictBadge verdict={proof.verdict} />
          <time
            dateTime={proof.timestamp}
            className="text-[10px] text-slate-500 ml-auto whitespace-nowrap"
          >
            {formatTimestamp(proof.timestamp)}
          </time>
        </div>

        {/* Hash rows */}
        <div className="space-y-1">
          <HashRow label="Content" hash={proof.contentHash} />
          <HashRow label="Result" hash={proof.resultHash} />
          <HashRow label="Chain" hash={proof.chainHash} highlight />
          {proof.previousProofHash && (
            <div className="flex items-center gap-1.5 pt-0.5">
              <Link className="w-3 h-3 text-slate-600 flex-shrink-0" aria-hidden="true" />
              <span className="text-[10px] text-slate-600 font-mono truncate" title={proof.previousProofHash}>
                prev: {truncateHash(proof.previousProofHash, 8)}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ProofChainTab({ chain }: { chain: ProofChain }) {
  const [verifyState, setVerifyState] = useState<VerifyState>({ status: 'idle' })

  const handleVerify = useCallback(async () => {
    setVerifyState({ status: 'loading' })
    try {
      const result = await verifyProofChain(chain.chainId)
      if (result.isValid) {
        setVerifyState({ status: 'valid', message: result.message })
      } else {
        setVerifyState({
          status: 'invalid',
          message: result.message,
          invalidAt: result.invalidAt,
        })
      }
    } catch (err) {
      setVerifyState({
        status: 'invalid',
        message: err instanceof Error ? err.message : 'Verification failed',
        invalidAt: null,
      })
    }
  }, [chain.chainId])

  const invalidAtIndex =
    verifyState.status === 'invalid' ? (verifyState.invalidAt ?? null) : null

  return (
    <div className="space-y-4">
      {/* Chain stats bar */}
      <div className="card">
        <div className="flex flex-wrap items-center gap-4">
          {/* Stats */}
          <div className="flex flex-wrap items-center gap-6 flex-1 min-w-0">
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide">Chain ID</p>
              <p className="text-xs font-mono text-slate-300 mt-0.5">{chain.chainId}</p>
            </div>
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide">Length</p>
              <p className="text-sm font-bold text-slate-100 mt-0.5 tabular-nums">
                {chain.length} proofs
              </p>
            </div>
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide">Status</p>
              <div className="flex items-center gap-1.5 mt-0.5">
                {chain.isValid ? (
                  <>
                    <CheckCircle2 className="w-3.5 h-3.5 text-green-400" aria-hidden="true" />
                    <span className="text-xs font-semibold text-green-300">Valid</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-3.5 h-3.5 text-red-400" aria-hidden="true" />
                    <span className="text-xs font-semibold text-red-300">Invalid</span>
                  </>
                )}
              </div>
            </div>
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide">First Proof</p>
              <p className="text-xs text-slate-400 mt-0.5">
                {chain.firstProof ? formatTimestamp(chain.firstProof) : '—'}
              </p>
            </div>
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide">Last Proof</p>
              <p className="text-xs text-slate-400 mt-0.5">
                {chain.lastProof ? formatTimestamp(chain.lastProof) : '—'}
              </p>
            </div>
          </div>

          {/* Verify button */}
          <div className="flex flex-col items-end gap-2 flex-shrink-0">
            <button
              onClick={handleVerify}
              disabled={verifyState.status === 'loading'}
              className="inline-flex items-center gap-2 bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-semibold px-4 py-2 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-violet-500/50"
              aria-label="Verify entire proof chain integrity"
            >
              {verifyState.status === 'loading' ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                  Verifying…
                </>
              ) : (
                <>
                  <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
                  Verify Chain
                </>
              )}
            </button>

            {/* Verify result */}
            {verifyState.status === 'valid' && (
              <p
                className="flex items-center gap-1.5 text-[11px] text-green-300"
                role="status"
                aria-live="polite"
              >
                <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                {verifyState.message}
              </p>
            )}
            {verifyState.status === 'invalid' && (
              <p
                className="flex items-center gap-1.5 text-[11px] text-red-300"
                role="alert"
                aria-live="assertive"
              >
                <XCircle className="w-3.5 h-3.5" aria-hidden="true" />
                {verifyState.message}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Chain visualization */}
      <div className="card">
        <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <Link className="w-4 h-4 text-violet-400" aria-hidden="true" />
          Hash Chain
          <span className="text-xs text-slate-500 font-normal ml-1">
            — each block links to the previous via chain hash
          </span>
        </h2>

        <div
          role="list"
          aria-label="Proof chain blocks"
          className="space-y-0 max-h-[640px] overflow-y-auto pr-1"
        >
          {chain.proofs.map((proof, i) => (
            <ProofBlock
              key={proof.scanId}
              proof={proof}
              index={i}
              isLast={i === chain.proofs.length - 1}
              isInvalidAt={invalidAtIndex !== null && i >= invalidAtIndex}
            />
          ))}
          {chain.proofs.length === 0 && (
            <p className="text-sm text-slate-500 text-center py-8">
              No proofs in chain yet.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Coverage Matrix Tab ──────────────────────────────────────────────────────

interface EngineBarDatum {
  name: string
  rate: number
  fill: string
}

function CoverageMatrixTab({ coverage }: { coverage: CoverageMatrix }) {
  const overallPct = (coverage.overallCoverage * 100).toFixed(1)

  // Combined detection rate per technique: max across all engines for that row
  const combinedRates: number[] = coverage.matrix.map((row) =>
    Math.max(...row)
  )

  // Per-engine overall rates: average of each engine's column
  const engineBarData: EngineBarDatum[] = coverage.engines.map((eng, ei) => {
    const colRates = coverage.matrix.map((row) => row[ei])
    const avg = colRates.reduce((s, v) => s + v, 0) / colRates.length
    return {
      name: eng,
      rate: parseFloat(avg.toFixed(3)),
      fill: ENGINE_COLORS[eng] ?? '#8b5cf6',
    }
  })

  return (
    <div className="space-y-4">
      {/* Overall coverage stat */}
      <div className="card flex flex-wrap items-center gap-6">
        <div>
          <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-1">Overall Coverage</p>
          <p
            className={`text-4xl font-black tabular-nums ${
              coverage.overallCoverage >= 0.8
                ? 'text-green-300'
                : coverage.overallCoverage >= 0.5
                ? 'text-amber-300'
                : 'text-red-300'
            }`}
            aria-label={`Overall detection coverage: ${overallPct} percent`}
          >
            {overallPct}%
          </p>
        </div>
        <div className="flex-1 min-w-[200px]">
          <div className="w-full h-3 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                coverage.overallCoverage >= 0.8
                  ? 'bg-green-500'
                  : coverage.overallCoverage >= 0.5
                  ? 'bg-amber-500'
                  : 'bg-red-500'
              }`}
              style={{ width: `${coverage.overallCoverage * 100}%` }}
              role="meter"
              aria-valuenow={coverage.overallCoverage * 100}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Overall coverage meter"
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-500 mt-1">
            <span>0%</span>
            <span>50%</span>
            <span>100%</span>
          </div>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-green-900/80 border border-green-700" aria-hidden="true" />
            <span className="text-slate-400">≥ 80%</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-900/80 border border-amber-700" aria-hidden="true" />
            <span className="text-slate-400">50–79%</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-red-900/80 border border-red-700" aria-hidden="true" />
            <span className="text-slate-400">&lt; 50%</span>
          </span>
        </div>
      </div>

      {/* Heatmap table */}
      <div className="card overflow-hidden">
        <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <Grid3x3 className="w-4 h-4 text-violet-400" aria-hidden="true" />
          Detection Rate by Technique & Engine
        </h2>
        <div className="overflow-x-auto -mx-5 px-5">
          <table
            className="w-full text-xs border-separate border-spacing-0"
            aria-label="Detection coverage heatmap"
          >
            <thead>
              <tr>
                <th
                  scope="col"
                  className="py-2 pr-4 text-left text-[10px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap sticky left-0 bg-slate-800 z-10"
                >
                  Technique
                </th>
                {coverage.engines.map((eng) => (
                  <th
                    key={eng}
                    scope="col"
                    className="py-2 px-2 text-center text-[10px] font-semibold text-slate-400 uppercase tracking-wider whitespace-nowrap min-w-[90px]"
                  >
                    {eng}
                  </th>
                ))}
                <th
                  scope="col"
                  className="py-2 px-2 text-center text-[10px] font-semibold text-slate-300 uppercase tracking-wider whitespace-nowrap min-w-[80px]"
                >
                  Combined
                </th>
              </tr>
            </thead>
            <tbody>
              {coverage.techniques.map((tech, ti) => (
                <tr key={tech} className="group">
                  <td className="py-1.5 pr-4 text-slate-300 font-medium whitespace-nowrap border-t border-slate-700/40 sticky left-0 bg-slate-800 z-10 group-hover:bg-slate-750">
                    {tech}
                  </td>
                  {coverage.matrix[ti].map((rate, ei) => (
                    <td
                      key={coverage.engines[ei]}
                      className={`py-1.5 px-2 text-center font-mono font-semibold border-t border-slate-700/40 ${cellColor(rate)}`}
                      aria-label={`${tech} — ${coverage.engines[ei]}: ${(rate * 100).toFixed(0)}%`}
                    >
                      <span className={`inline-flex items-center justify-center w-full h-6 rounded text-[11px] ${cellColor(rate)}`}>
                        {(rate * 100).toFixed(0)}%
                      </span>
                    </td>
                  ))}
                  {/* Combined column */}
                  <td
                    className={`py-1.5 px-2 text-center font-mono font-bold border-t border-slate-700/40 ${cellColor(combinedRates[ti])}`}
                    aria-label={`${tech} combined: ${(combinedRates[ti] * 100).toFixed(0)}%`}
                  >
                    <span className={`inline-flex items-center justify-center w-full h-6 rounded text-[11px] ring-1 ring-slate-600 ${cellColor(combinedRates[ti])}`}>
                      {(combinedRates[ti] * 100).toFixed(0)}%
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Per-engine bar chart */}
      <div className="card">
        <h2 className="text-sm font-semibold text-slate-200 mb-4">
          Per-Engine Average Detection Rate
        </h2>
        <div aria-label="Bar chart showing per-engine detection rates" role="img">
          <ResponsiveContainer width="100%" height={180}>
            <BarChart
              data={engineBarData}
              margin={{ top: 4, right: 16, left: -8, bottom: 4 }}
              aria-label="Per-engine detection rate bar chart"
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="name"
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                domain={[0, 1]}
                tickFormatter={(v: number) => `${(v * 100).toFixed(0)}%`}
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                formatter={(value: number) => [`${(value * 100).toFixed(1)}%`, 'Avg Detection Rate']}
                contentStyle={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                  fontSize: '12px',
                }}
                labelStyle={{ color: '#94a3b8', fontSize: '11px', marginBottom: '4px' }}
                cursor={{ fill: 'rgba(148,163,184,0.06)' }}
              />
              <Bar dataKey="rate" radius={[4, 4, 0, 0]} maxBarSize={60}>
                {engineBarData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Coverage gaps */}
      {coverage.gaps.length > 0 && (
        <div className="card border border-red-800/40">
          <h2 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" aria-hidden="true" />
            Coverage Gaps
            <span className="text-xs text-slate-500 font-normal">
              — techniques with best detection rate below 50%
            </span>
          </h2>
          <div
            role="list"
            aria-label="Detection coverage gaps"
            className="space-y-2"
          >
            {coverage.gaps.map((gap) => (
              <div
                key={gap.technique}
                role="listitem"
                className="flex items-center justify-between gap-3 py-2 px-3 rounded-lg bg-red-900/10 border border-red-800/30"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" aria-hidden="true" />
                  <span className="text-xs text-slate-300 truncate">{gap.technique}</span>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <div className="w-24 h-1.5 bg-slate-700 rounded-full overflow-hidden" aria-hidden="true">
                    <div
                      className="h-full bg-red-500 rounded-full"
                      style={{ width: `${gap.bestRate * 100}%` }}
                    />
                  </div>
                  <span
                    className="text-[10px] font-semibold bg-red-900/60 text-red-300 border border-red-800/60 px-2 py-0.5 rounded-full tabular-nums"
                    aria-label={`Best detection rate: ${(gap.bestRate * 100).toFixed(0)} percent`}
                  >
                    {(gap.bestRate * 100).toFixed(0)}% best
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Main Panel ───────────────────────────────────────────────────────────────

export function ProofsPanel() {
  const [activeTab, setActiveTab] = useState<Tab>('chain')

  // Proof chain state
  const [chain, setChain] = useState<ProofChain | null>(null)
  const [chainLoading, setChainLoading] = useState(true)
  const [chainError, setChainError] = useState<string | null>(null)

  // Coverage matrix state
  const [coverage, setCoverage] = useState<CoverageMatrix | null>(null)
  const [coverageLoading, setCoverageLoading] = useState(false)
  const [coverageLoaded, setCoverageLoaded] = useState(false)
  const [coverageError, setCoverageError] = useState<string | null>(null)

  // Load proof chain on mount
  useEffect(() => {
    let cancelled = false
    setChainLoading(true)
    setChainError(null)
    fetchProofChain(50)
      .then((data) => {
        if (!cancelled) {
          setChain(data)
          setChainLoading(false)
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setChainError(err instanceof Error ? err.message : 'Failed to load proof chain')
          setChainLoading(false)
        }
      })
    return () => { cancelled = true }
  }, [])

  // Lazy-load coverage matrix when tab is first activated
  useEffect(() => {
    if (activeTab !== 'coverage' || coverageLoaded) return
    let cancelled = false
    setCoverageLoading(true)
    setCoverageError(null)
    fetchCoverageMatrix()
      .then((data) => {
        if (!cancelled) {
          setCoverage(data)
          setCoverageLoading(false)
          setCoverageLoaded(true)
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setCoverageError(err instanceof Error ? err.message : 'Failed to load coverage matrix')
          setCoverageLoading(false)
        }
      })
    return () => { cancelled = true }
  }, [activeTab, coverageLoaded])

  const tabs: { id: Tab; label: string; icon: typeof Fingerprint }[] = [
    { id: 'chain',    label: 'Proof Chain',      icon: Lock    },
    { id: 'coverage', label: 'Coverage Matrix',  icon: Grid3x3 },
  ]

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div
        className="flex gap-1 p-1 bg-slate-800 border border-slate-700 rounded-xl w-fit"
        role="tablist"
        aria-label="Proofs navigation"
      >
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            role="tab"
            aria-selected={activeTab === id}
            aria-controls={`tabpanel-${id}`}
            id={`tab-${id}`}
            onClick={() => setActiveTab(id)}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-500/50 ${
              activeTab === id
                ? 'bg-violet-600/20 text-violet-300 border border-violet-600/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
            }`}
          >
            <Icon className="w-4 h-4" aria-hidden="true" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab panels */}
      <div
        id="tabpanel-chain"
        role="tabpanel"
        aria-labelledby="tab-chain"
        hidden={activeTab !== 'chain'}
      >
        {chainLoading ? (
          <div className="card flex items-center justify-center gap-3 py-16 text-slate-500">
            <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
            <span className="text-sm">Loading proof chain…</span>
          </div>
        ) : chainError ? (
          <div
            className="card flex items-center gap-3 border border-red-800/50 text-red-300"
            role="alert"
          >
            <XCircle className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold">Failed to load proof chain</p>
              <p className="text-xs text-slate-400 mt-0.5">{chainError}</p>
            </div>
          </div>
        ) : chain ? (
          <ProofChainTab chain={chain} />
        ) : null}
      </div>

      <div
        id="tabpanel-coverage"
        role="tabpanel"
        aria-labelledby="tab-coverage"
        hidden={activeTab !== 'coverage'}
      >
        {coverageLoading ? (
          <div className="card flex items-center justify-center gap-3 py-16 text-slate-500">
            <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
            <span className="text-sm">Loading coverage matrix…</span>
          </div>
        ) : coverageError ? (
          <div
            className="card flex items-center gap-3 border border-red-800/50 text-red-300"
            role="alert"
          >
            <XCircle className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold">Failed to load coverage matrix</p>
              <p className="text-xs text-slate-400 mt-0.5">{coverageError}</p>
            </div>
          </div>
        ) : coverage ? (
          <CoverageMatrixTab coverage={coverage} />
        ) : null}
      </div>
    </div>
  )
}
