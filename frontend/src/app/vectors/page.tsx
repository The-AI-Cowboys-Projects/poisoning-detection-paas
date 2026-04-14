/**
 * Vector Analysis page — scatter plot, results table, baseline status,
 * anomaly score histogram.
 */

import type { Metadata } from 'next'
import {
  fetchVectorPoints,
  fetchVectorResults,
  fetchVectorBaseline,
  fetchAnomalyHistogram,
} from '@/lib/api'
import { ThreatBadge } from '@/components/ThreatBadge'
import { VectorScatterPlot } from './VectorScatterPlot'
import { AnomalyHistogram } from './AnomalyHistogram'
import { CheckCircle2, XCircle, Clock, Database } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export const metadata: Metadata = { title: 'Vector Analysis' }
export const revalidate = 30

function BaselineCard({
  baseline,
}: {
  baseline: Awaited<ReturnType<typeof fetchVectorBaseline>>
}) {
  return (
    <div className="card">
      <h2 className="text-sm font-semibold text-slate-200 mb-4">Baseline Status</h2>
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          {baseline.isEstablished ? (
            <CheckCircle2 className="w-5 h-5 text-green-400 flex-shrink-0" aria-hidden="true" />
          ) : (
            <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" aria-hidden="true" />
          )}
          <div>
            <p className="text-xs font-semibold text-slate-200">
              {baseline.isEstablished ? 'Baseline established' : 'No baseline'}
            </p>
            <p className="text-[10px] text-slate-500">
              {baseline.isEstablished ? 'Normal behavior profile active' : 'Ingest documents to establish baseline'}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-700">
          <div>
            <div className="flex items-center gap-1.5 mb-1">
              <Database className="w-3 h-3 text-slate-500" aria-hidden="true" />
              <span className="text-[10px] text-slate-500 uppercase tracking-wide">Documents</span>
            </div>
            <p className="text-lg font-bold text-slate-100 tabular-nums">
              {baseline.documentCount.toLocaleString()}
            </p>
          </div>
          <div>
            <div className="flex items-center gap-1.5 mb-1">
              <Clock className="w-3 h-3 text-slate-500" aria-hidden="true" />
              <span className="text-[10px] text-slate-500 uppercase tracking-wide">Updated</span>
            </div>
            <p className="text-xs text-slate-300">
              {baseline.lastUpdated
                ? formatDistanceToNow(new Date(baseline.lastUpdated), { addSuffix: true })
                : 'Never'}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-1">Mean Norm</p>
            <p className="text-sm font-semibold text-slate-200 tabular-nums font-mono">
              {baseline.meanNorm.toFixed(4)}
            </p>
          </div>
          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-1">Std Dev</p>
            <p className="text-sm font-semibold text-slate-200 tabular-nums font-mono">
              {baseline.stdNorm.toFixed(4)}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default async function VectorsPage() {
  const [points, results, baseline, histogram] = await Promise.all([
    fetchVectorPoints(),
    fetchVectorResults({ limit: 20 }),
    fetchVectorBaseline(),
    fetchAnomalyHistogram(),
  ])

  const anomalyCount = points.filter((p) => p.isAnomaly).length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Vector Analysis</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          Embedding space monitoring — detecting anomalous vector distributions
        </p>
      </div>

      {/* Top row: scatter + baseline + histogram */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Scatter plot */}
        <section aria-label="Vector space scatter plot" className="xl:col-span-2">
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Embedding Space</h2>
                <p className="text-xs text-slate-500 mt-0.5">UMAP 2D projection — {points.length} vectors</p>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-blue-500" aria-hidden="true" />
                  Normal
                </span>
                <span className="flex items-center gap-1.5 text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-500" aria-hidden="true" />
                  Anomaly ({anomalyCount})
                </span>
              </div>
            </div>
            <VectorScatterPlot points={points} />
          </div>
        </section>

        {/* Right column */}
        <div className="space-y-4">
          <BaselineCard baseline={baseline} />
          <section aria-label="Anomaly score distribution">
            <div className="card">
              <h2 className="text-sm font-semibold text-slate-200 mb-4">
                Anomaly Score Distribution
              </h2>
              <AnomalyHistogram bins={histogram} />
            </div>
          </section>
        </div>
      </div>

      {/* Results table */}
      <section aria-label="Vector analysis results">
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-200 mb-5">
            Recent Analysis Results
          </h2>
          <div className="overflow-x-auto -mx-5 px-5">
            <table className="data-table" aria-label="Vector analysis results">
              <thead>
                <tr>
                  <th>Document ID</th>
                  <th>Vector ID</th>
                  <th>Anomaly Score</th>
                  <th>Baseline Dev.</th>
                  <th>Cluster</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <span className="font-mono text-xs text-slate-300">{r.documentId}</span>
                    </td>
                    <td>
                      <span className="font-mono text-xs text-slate-500">{r.vectorId}</span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all"
                            style={{
                              width: `${r.anomalyScore * 100}%`,
                              background: r.anomalyScore > 0.7
                                ? '#ef4444'
                                : r.anomalyScore > 0.4
                                ? '#f59e0b'
                                : '#22c55e',
                            }}
                            aria-label={`Anomaly score: ${(r.anomalyScore * 100).toFixed(1)}%`}
                          />
                        </div>
                        <span className="font-mono text-xs text-slate-300 tabular-nums">
                          {r.anomalyScore.toFixed(4)}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="font-mono text-xs text-slate-300 tabular-nums">
                        {r.baselineDeviation.toFixed(4)}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
                        C-{r.clusterId}
                      </span>
                    </td>
                    <td>
                      <ThreatBadge
                        severity={r.isAnomaly ? 'critical' : 'safe'}
                        label={r.isAnomaly ? 'Anomaly' : 'Normal'}
                        size="sm"
                      />
                    </td>
                    <td>
                      <time
                        dateTime={r.timestamp}
                        className="text-xs text-slate-500 whitespace-nowrap"
                      >
                        {formatDistanceToNow(new Date(r.timestamp), { addSuffix: true })}
                      </time>
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
