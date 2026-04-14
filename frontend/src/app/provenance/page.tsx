/**
 * Provenance Tracker page — lineage DAG visualization, contamination panel,
 * dataset registration form, generation depth indicator.
 */

export const dynamic = 'force-dynamic'

import type { Metadata } from 'next'
import { fetchProvenance, fetchContaminationStatus } from '@/lib/api'
import { ProvenanceDAG } from './ProvenanceDAG'
import { DatasetRegistrationForm } from './DatasetRegistrationForm'
import { AlertTriangle, CheckCircle2, Activity } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'

export const metadata: Metadata = { title: 'Provenance Tracker' }
export const revalidate = 60

export default async function ProvenancePage() {
  const [graph, contamination] = await Promise.all([
    fetchProvenance(),
    fetchContaminationStatus(),
  ])

  const maxDepth = Math.max(...graph.nodes.map((n) => n.depth))
  const contaminatedCount = graph.nodes.filter((n) => n.contaminated).length

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-slate-100">Provenance Tracker</h1>
        <p className="text-sm text-slate-400 mt-0.5">
          Dataset and model lineage — trace contamination through the training pipeline
        </p>
      </div>

      {/* Top row: graph + contamination panel */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* DAG visualization */}
        <section aria-label="Dataset lineage graph" className="xl:col-span-2">
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-slate-200">Lineage Graph</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  {graph.nodes.length} nodes · {graph.edges.length} edges · depth {maxDepth}
                </p>
              </div>
              <div className="flex items-center gap-3 text-xs">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-2.5 h-2.5 rounded border-2 border-slate-500" aria-hidden="true" />
                  Clean
                </span>
                <span className="flex items-center gap-1.5 text-red-400">
                  <span className="w-2.5 h-2.5 rounded bg-red-900 border-2 border-red-500" aria-hidden="true" />
                  Contaminated
                </span>
              </div>
            </div>
            <ProvenanceDAG graph={graph} />
          </div>
        </section>

        {/* Right column */}
        <div className="space-y-4">
          {/* Contamination status */}
          <section aria-label="Contamination status">
            <div
              className={[
                'card border',
                contamination.isContaminated ? 'border-red-800/60' : 'border-green-800/40',
              ].join(' ')}
              role={contamination.isContaminated ? 'alert' : 'status'}
            >
              <h2 className="text-sm font-semibold text-slate-200 mb-4">Contamination Status</h2>

              <div className="flex items-center gap-3 mb-4">
                {contamination.isContaminated ? (
                  <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" aria-hidden="true" />
                ) : (
                  <CheckCircle2 className="w-6 h-6 text-green-400 flex-shrink-0" aria-hidden="true" />
                )}
                <div>
                  <p className={`text-sm font-semibold ${contamination.isContaminated ? 'text-red-300' : 'text-green-300'}`}>
                    {contamination.isContaminated ? 'Contamination detected' : 'Pipeline clean'}
                  </p>
                  <p className="text-xs text-slate-500">
                    {contamination.affectedNodes.length} affected node{contamination.affectedNodes.length !== 1 ? 's' : ''}
                  </p>
                </div>
              </div>

              {/* Contamination score meter */}
              <div className="mb-4">
                <div className="flex justify-between text-[10px] text-slate-500 mb-1.5">
                  <span>Contamination Score</span>
                  <span className="font-semibold text-slate-300">
                    {(contamination.contaminationScore * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-700 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${contamination.contaminationScore * 100}%`,
                      background: contamination.contaminationScore > 0.5
                        ? '#ef4444'
                        : contamination.contaminationScore > 0.25
                        ? '#f59e0b'
                        : '#22c55e',
                    }}
                    role="meter"
                    aria-valuenow={contamination.contaminationScore * 100}
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-label="Contamination score"
                  />
                </div>
              </div>

              {/* Stats grid */}
              <div className="grid grid-cols-2 gap-3 text-xs border-t border-slate-700 pt-3">
                <div>
                  <p className="text-slate-500 mb-0.5">Traceback Depth</p>
                  <p className="font-bold text-slate-200">{contamination.tracebackDepth} levels</p>
                </div>
                <div>
                  <p className="text-slate-500 mb-0.5">Detected</p>
                  <p className="font-bold text-slate-200">
                    {contamination.detectedAt
                      ? formatDistanceToNow(new Date(contamination.detectedAt), { addSuffix: true })
                      : 'N/A'}
                  </p>
                </div>
              </div>

              {contamination.affectedNodes.length > 0 && (
                <div className="mt-3 border-t border-slate-700 pt-3">
                  <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-2">Affected Nodes</p>
                  <div className="flex flex-wrap gap-1">
                    {contamination.affectedNodes.map((nid) => {
                      const node = graph.nodes.find((n) => n.id === nid)
                      return (
                        <span
                          key={nid}
                          className="text-[10px] bg-red-900/40 text-red-300 border border-red-800/60 px-2 py-0.5 rounded"
                        >
                          {node?.label ?? nid}
                        </span>
                      )
                    })}
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* Generation depth indicator */}
          <section aria-label="Generation depth">
            <div className="card">
              <h2 className="text-sm font-semibold text-slate-200 mb-4">
                <Activity className="w-4 h-4 inline mr-1.5 text-blue-400" aria-hidden="true" />
                Generation Depth
              </h2>
              <div className="space-y-2">
                {Array.from({ length: maxDepth + 1 }, (_, depth) => {
                  const nodesAtDepth = graph.nodes.filter((n) => n.depth === depth)
                  const contamAtDepth = nodesAtDepth.filter((n) => n.contaminated).length
                  return (
                    <div key={depth} className="flex items-center gap-3">
                      <span className="text-xs text-slate-500 w-12 flex-shrink-0">
                        Depth {depth}
                      </span>
                      <div className="flex-1 flex items-center gap-1">
                        {nodesAtDepth.map((node) => (
                          <div
                            key={node.id}
                            title={node.label}
                            className={[
                              'h-5 flex-1 rounded text-[9px] flex items-center justify-center font-medium truncate px-1',
                              node.contaminated
                                ? 'bg-red-900/60 text-red-300 border border-red-800'
                                : 'bg-slate-700 text-slate-400 border border-slate-600',
                            ].join(' ')}
                          >
                            {node.type.slice(0, 3).toUpperCase()}
                          </div>
                        ))}
                      </div>
                      {contamAtDepth > 0 && (
                        <span className="text-[10px] text-red-400 flex-shrink-0">
                          {contamAtDepth} contaminated
                        </span>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </section>
        </div>
      </div>

      {/* Node details */}
      <section aria-label="Node registry">
        <div className="card">
          <h2 className="text-sm font-semibold text-slate-200 mb-5">Registered Nodes</h2>
          <div className="overflow-x-auto -mx-5 px-5">
            <table className="data-table" aria-label="Provenance nodes">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Label</th>
                  <th>Type</th>
                  <th>Depth</th>
                  <th>Status</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                {graph.nodes.map((node) => (
                  <tr key={node.id}>
                    <td>
                      <span className="font-mono text-xs text-slate-400">{node.id}</span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-300 font-medium">{node.label}</span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 bg-slate-700 px-2 py-0.5 rounded capitalize">
                        {node.type}
                      </span>
                    </td>
                    <td>
                      <span className="text-xs text-slate-400 tabular-nums">{node.depth}</span>
                    </td>
                    <td>
                      {node.contaminated ? (
                        <span className="flex items-center gap-1 text-xs text-red-400">
                          <AlertTriangle className="w-3 h-3" aria-hidden="true" />
                          Contaminated
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <CheckCircle2 className="w-3 h-3" aria-hidden="true" />
                          Clean
                        </span>
                      )}
                    </td>
                    <td>
                      <time dateTime={node.registeredAt} className="text-xs text-slate-500 whitespace-nowrap">
                        {formatDistanceToNow(new Date(node.registeredAt), { addSuffix: true })}
                      </time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Registration form */}
      <section aria-label="Register new dataset">
        <DatasetRegistrationForm existingNodes={graph.nodes} />
      </section>
    </div>
  )
}
