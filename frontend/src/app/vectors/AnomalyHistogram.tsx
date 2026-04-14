'use client'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from 'recharts'
import type { AnomalyScoreHistogramBin } from '@/lib/types'

interface Props {
  bins: AnomalyScoreHistogramBin[]
}

function getBarColor(rangeStart: number): string {
  if (rangeStart >= 0.7) return '#ef4444'
  if (rangeStart >= 0.4) return '#f59e0b'
  return '#3b82f6'
}

function HistogramTooltip({
  active,
  payload,
}: {
  active?: boolean
  payload?: Array<{ payload: AnomalyScoreHistogramBin & { label: string }; value: number }>
}) {
  if (!active || !payload?.length) return null
  const bin = payload[0].payload
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-1">{bin.label}</p>
      <p className="text-slate-100 font-semibold">
        {payload[0].value.toLocaleString()} vectors
      </p>
    </div>
  )
}

export function AnomalyHistogram({ bins }: Props) {
  const data = bins.map((b) => ({
    ...b,
    label: `${b.rangeStart.toFixed(1)} – ${b.rangeEnd.toFixed(1)}`,
  }))

  return (
    <ResponsiveContainer width="100%" height={160}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 9, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fontSize: 9, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<HistogramTooltip />} cursor={{ fill: 'rgba(148,163,184,0.06)' }} />
        <Bar dataKey="count" radius={[3, 3, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={getBarColor(entry.rangeStart)} opacity={0.8} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
