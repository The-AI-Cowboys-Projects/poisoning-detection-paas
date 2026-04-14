'use client'

import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import type { VectorPoint } from '@/lib/types'

interface Props {
  points: VectorPoint[]
}

const CLUSTER_COLORS = ['#3b82f6', '#22c55e', '#f59e0b', '#8b5cf6']

function ScatterTooltip({
  active,
  payload,
}: {
  active?: boolean
  payload?: Array<{ payload: VectorPoint }>
}) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="font-semibold text-slate-200 mb-1">{p.label ?? p.id}</p>
      <p className="text-slate-400">
        Anomaly Score:{' '}
        <span className={p.isAnomaly ? 'text-red-400 font-semibold' : 'text-slate-200'}>
          {p.anomalyScore.toFixed(4)}
        </span>
      </p>
      <p className="text-slate-400">
        Cluster: <span className="text-slate-200">C-{p.clusterId}</span>
      </p>
    </div>
  )
}

export function VectorScatterPlot({ points }: Props) {
  const normal = points.filter((p) => !p.isAnomaly)
  const anomalies = points.filter((p) => p.isAnomaly)

  // Split normal points by cluster
  const clusters = [0, 1, 2, 3].map((id) =>
    normal.filter((p) => p.clusterId === id),
  )

  return (
    <ResponsiveContainer width="100%" height={280}>
      <ScatterChart margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
        <XAxis
          type="number"
          dataKey="x"
          name="UMAP-1"
          tick={{ fontSize: 10, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
          domain={['auto', 'auto']}
        />
        <YAxis
          type="number"
          dataKey="y"
          name="UMAP-2"
          tick={{ fontSize: 10, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
          domain={['auto', 'auto']}
        />
        <Tooltip content={<ScatterTooltip />} cursor={{ strokeDasharray: '3 3' }} />

        {clusters.map((clusterPoints, i) => (
          <Scatter
            key={`cluster-${i}`}
            name={`Cluster ${i}`}
            data={clusterPoints}
            fill={CLUSTER_COLORS[i]}
            opacity={0.55}
            r={3}
          />
        ))}

        {/* Anomalies rendered on top with distinct styling */}
        <Scatter
          name="Anomalies"
          data={anomalies}
          fill="#ef4444"
          opacity={0.9}
          r={5}
          shape={(props: { cx?: number; cy?: number }) => {
            const { cx = 0, cy = 0 } = props
            return (
              <g>
                <circle cx={cx} cy={cy} r={6} fill="none" stroke="#ef4444" strokeWidth={1.5} opacity={0.6} />
                <circle cx={cx} cy={cy} r={4} fill="#ef4444" opacity={0.85} />
              </g>
            )
          }}
        />
      </ScatterChart>
    </ResponsiveContainer>
  )
}
