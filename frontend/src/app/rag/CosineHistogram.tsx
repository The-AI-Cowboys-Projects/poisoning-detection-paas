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
import type { CosineDeviationBin } from '@/lib/types'

interface Props {
  bins: CosineDeviationBin[]
}

function getColor(rangeStart: number): string {
  if (rangeStart >= 0.6) return '#ef4444'
  if (rangeStart >= 0.3) return '#f59e0b'
  return '#3b82f6'
}

function CosineTooltip({
  active,
  payload,
}: {
  active?: boolean
  payload?: Array<{ payload: CosineDeviationBin & { label: string }; value: number }>
}) {
  if (!active || !payload?.length) return null
  const bin = payload[0].payload
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-1">Deviation {bin.label}</p>
      <p className="text-slate-100 font-semibold">
        {payload[0].value.toLocaleString()} documents
      </p>
    </div>
  )
}

export function CosineHistogram({ bins }: Props) {
  const data = bins.map((b) => ({
    ...b,
    label: `${b.rangeStart.toFixed(1)}–${b.rangeEnd.toFixed(1)}`,
  }))

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 10, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fontSize: 10, fill: '#64748b' }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip
          content={<CosineTooltip />}
          cursor={{ fill: 'rgba(148,163,184,0.06)' }}
        />
        <Bar dataKey="count" radius={[3, 3, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={getColor(entry.rangeStart)} opacity={0.8} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
