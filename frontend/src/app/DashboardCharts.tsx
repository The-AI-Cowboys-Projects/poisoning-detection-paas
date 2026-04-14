/**
 * DashboardCharts — client component containing the time-series area chart
 * and the threat breakdown donut chart.
 *
 * Separated from page.tsx so the server component can own data fetching while
 * Recharts (which requires browser APIs) runs only on the client.
 */

'use client'

import { useMemo } from 'react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
} from 'recharts'
import { format } from 'date-fns'
import { ChartWrapper } from '@/components/ChartWrapper'
import type { TimeSeriesPoint, ThreatBreakdown } from '@/lib/types'

// ─── Types ────────────────────────────────────────────────────────────────────

interface DashboardChartsProps {
  timeSeries: TimeSeriesPoint[]
  breakdown: ThreatBreakdown[]
}

// ─── Tooltip renderers ────────────────────────────────────────────────────────

function TimeSeriesTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: Array<{ name: string; value: number; color: string }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-400 mb-2">{label}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: entry.color }}
            aria-hidden="true"
          />
          <span className="text-slate-300 capitalize">{entry.name}:</span>
          <span className="text-slate-100 font-semibold tabular-nums">
            {entry.value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  )
}

function DonutTooltip({
  active,
  payload,
}: {
  active?: boolean
  payload?: Array<{ name: string; value: number; payload: ThreatBreakdown }>
}) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-3 text-xs shadow-xl">
      <p className="text-slate-100 font-semibold">{item.name}</p>
      <p className="text-slate-400 mt-1">
        Count:{' '}
        <span className="text-slate-100 font-semibold">{item.value}</span>
      </p>
      <p className="text-slate-400">
        Share:{' '}
        <span className="text-slate-100 font-semibold">
          {item.payload.percentage.toFixed(1)}%
        </span>
      </p>
    </div>
  )
}

// ─── DonutLabel ───────────────────────────────────────────────────────────────

function DonutCenterLabel({ total }: { total: number }) {
  return (
    <>
      <text
        x="50%"
        y="46%"
        textAnchor="middle"
        dominantBaseline="middle"
        className="fill-slate-100"
        style={{ fontSize: '24px', fontWeight: 700 }}
      >
        {total}
      </text>
      <text
        x="50%"
        y="58%"
        textAnchor="middle"
        dominantBaseline="middle"
        className="fill-slate-500"
        style={{ fontSize: '10px' }}
      >
        threats
      </text>
    </>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function DashboardCharts({ timeSeries, breakdown }: DashboardChartsProps) {
  // Downsample to ~one point every 4 hours for readability
  const sampledSeries = useMemo(
    () => timeSeries.filter((_, i) => i % 4 === 0),
    [timeSeries],
  )

  const formattedSeries = useMemo(
    () =>
      sampledSeries.map((p) => ({
        ...p,
        label: format(new Date(p.timestamp), 'MMM d HH:mm'),
      })),
    [sampledSeries],
  )

  const totalThreats = useMemo(
    () => breakdown.reduce((sum, b) => sum + b.count, 0),
    [breakdown],
  )

  return (
    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
      {/* Area chart — 2 columns wide */}
      <section aria-label="Scan volume over time" className="xl:col-span-2">
        <ChartWrapper
          title="Scan Volume & Threats"
          subtitle="Last 14 days, hourly"
          height={280}
        >
          <AreaChart
            data={formattedSeries}
            margin={{ top: 4, right: 16, left: -10, bottom: 0 }}
          >
            <defs>
              <linearGradient id="grad-scans" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="grad-threats" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="label"
              tick={{ fontSize: 10, fill: '#64748b' }}
              tickLine={false}
              axisLine={false}
              interval={Math.floor(formattedSeries.length / 6)}
            />
            <YAxis
              tick={{ fontSize: 10, fill: '#64748b' }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip content={<TimeSeriesTooltip />} />
            <Legend
              wrapperStyle={{ fontSize: '11px', color: '#94a3b8', paddingTop: '8px' }}
            />
            <Area
              type="monotone"
              dataKey="scans"
              name="Scans"
              stroke="#3b82f6"
              strokeWidth={1.5}
              fill="url(#grad-scans)"
              dot={false}
              activeDot={{ r: 4, fill: '#3b82f6' }}
            />
            <Area
              type="monotone"
              dataKey="threats"
              name="Threats"
              stroke="#ef4444"
              strokeWidth={1.5}
              fill="url(#grad-threats)"
              dot={false}
              activeDot={{ r: 4, fill: '#ef4444' }}
            />
          </AreaChart>
        </ChartWrapper>
      </section>

      {/* Donut chart — 1 column */}
      <section aria-label="Threat type breakdown">
        <ChartWrapper title="Threat Types" subtitle="Distribution by category" height={280}>
          <PieChart>
            <Pie
              data={breakdown}
              cx="50%"
              cy="50%"
              innerRadius="55%"
              outerRadius="75%"
              dataKey="count"
              nameKey="label"
              paddingAngle={3}
              strokeWidth={0}
            >
              {breakdown.map((entry) => (
                <Cell key={entry.type} fill={entry.color} opacity={0.9} />
              ))}
            </Pie>
            <Tooltip content={<DonutTooltip />} />
            <DonutCenterLabel total={totalThreats} />
          </PieChart>
        </ChartWrapper>

        {/* Legend */}
        <div className="card mt-3 py-3 space-y-2">
          {breakdown.map((item) => (
            <div key={item.type} className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span
                  className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                  style={{ background: item.color }}
                  aria-hidden="true"
                />
                <span className="text-xs text-slate-400">{item.label}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-slate-200 tabular-nums">
                  {item.count}
                </span>
                <span className="text-[10px] text-slate-600 w-9 text-right">
                  {item.percentage.toFixed(1)}%
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
