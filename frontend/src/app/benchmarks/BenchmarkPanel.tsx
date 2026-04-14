'use client'

/**
 * BenchmarkPanel — Empirical Validation UI
 *
 * Usage:
 *   import { BenchmarkPanel } from '@/app/benchmarks/BenchmarkPanel'
 *   <BenchmarkPanel />
 *
 * Sections:
 *   A. Overall KPI cards (Detection Rate, FPR, F1, AUC)
 *   B. Engine Rankings — horizontal bar chart + ranked table
 *   C. Per-Technique Heatmap — F1 cells per engine×technique with hover tooltip
 *   D. Technique Gaps — techniques where best F1 < 0.85
 *   E. Confusion Matrix Detail — expandable per-engine accordion
 */

import { useEffect, useState, useCallback } from 'react'
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
import {
  FlaskConical,
  Play,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  BarChart2,
  Target,
  Shield,
  ChevronDown,
  ChevronUp,
  Database,
} from 'lucide-react'
import {
  fetchBenchmarkDatasets,
  runBenchmarkSuite,
  type BenchmarkDataset,
  type BenchmarkResult,
  type BenchmarkSuite,
} from '@/lib/api'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pct(n: number) {
  return `${(n * 100).toFixed(1)}%`
}

function f1Color(f1: number): string {
  if (f1 >= 0.8) return 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
  if (f1 >= 0.5) return 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
  return 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
}

function f1Hex(f1: number): string {
  if (f1 >= 0.8) return '#10b981'
  if (f1 >= 0.5) return '#f59e0b'
  return '#f43f5e'
}

// Aggregate results across datasets for the same engine+technique pair
function aggregateResults(results: BenchmarkResult[]): BenchmarkResult[] {
  const map = new Map<string, BenchmarkResult[]>()
  for (const r of results) {
    const key = `${r.engine}__${r.technique}`
    if (!map.has(key)) map.set(key, [])
    map.get(key)!.push(r)
  }
  const out: BenchmarkResult[] = []
  for (const [, rs] of map.entries()) {
    const avg = (fn: (r: BenchmarkResult) => number) =>
      rs.reduce((s, r) => s + fn(r), 0) / rs.length
    out.push({
      ...rs[0],
      truePositives: Math.round(avg(r => r.truePositives)),
      falsePositives: Math.round(avg(r => r.falsePositives)),
      trueNegatives: Math.round(avg(r => r.trueNegatives)),
      falseNegatives: Math.round(avg(r => r.falseNegatives)),
      precision: parseFloat(avg(r => r.precision).toFixed(4)),
      recall: parseFloat(avg(r => r.recall).toFixed(4)),
      f1Score: parseFloat(avg(r => r.f1Score).toFixed(4)),
      accuracy: parseFloat(avg(r => r.accuracy).toFixed(4)),
      detectionRate: parseFloat(avg(r => r.detectionRate).toFixed(4)),
      falsePositiveRate: parseFloat(avg(r => r.falsePositiveRate).toFixed(4)),
      auc: parseFloat(avg(r => r.auc).toFixed(4)),
      avgLatencyMs: Math.round(avg(r => r.avgLatencyMs)),
      p95LatencyMs: Math.round(avg(r => r.p95LatencyMs)),
    })
  }
  return out
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface KpiCardProps {
  label: string
  value: string
  icon: React.ReactNode
  good: boolean
  subtitle?: string
}

function KpiCard({ label, value, icon, good, subtitle }: KpiCardProps) {
  return (
    <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 p-4 flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400 font-medium">{label}</span>
        <span className={`w-7 h-7 rounded-lg flex items-center justify-center ${good ? 'bg-emerald-500/15' : 'bg-rose-500/15'}`}>
          {icon}
        </span>
      </div>
      <span className={`text-2xl font-bold tabular-nums ${good ? 'text-emerald-300' : 'text-rose-300'}`}>
        {value}
      </span>
      {subtitle && <span className="text-[10px] text-slate-500">{subtitle}</span>}
    </div>
  )
}

// ─── Section A: Overall Metrics ───────────────────────────────────────────────

function OverallMetricsSection({ suite }: { suite: BenchmarkSuite }) {
  const m = suite.overallMetrics
  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <Target className="w-4 h-4 text-rose-400" />
        Overall Metrics
      </h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <KpiCard
          label="Mean Detection Rate"
          value={pct(m.meanDetectionRate)}
          icon={<Shield className={`w-4 h-4 ${m.meanDetectionRate > 0.8 ? 'text-emerald-400' : 'text-rose-400'}`} />}
          good={m.meanDetectionRate > 0.8}
          subtitle="Recall / TPR across all engines"
        />
        <KpiCard
          label="Mean False Positive Rate"
          value={pct(m.meanFalsePositiveRate)}
          icon={<AlertTriangle className={`w-4 h-4 ${m.meanFalsePositiveRate < 0.05 ? 'text-emerald-400' : 'text-amber-400'}`} />}
          good={m.meanFalsePositiveRate < 0.05}
          subtitle="FPR — lower is better"
        />
        <KpiCard
          label="Mean F1 Score"
          value={m.meanF1.toFixed(3)}
          icon={<FlaskConical className={`w-4 h-4 ${m.meanF1 > 0.8 ? 'text-emerald-400' : 'text-amber-400'}`} />}
          good={m.meanF1 > 0.8}
          subtitle="Harmonic mean precision/recall"
        />
        <KpiCard
          label="Mean AUC"
          value={m.meanAUC.toFixed(3)}
          icon={<BarChart2 className={`w-4 h-4 ${m.meanAUC > 0.85 ? 'text-emerald-400' : 'text-amber-400'}`} />}
          good={m.meanAUC > 0.85}
          subtitle="Area under ROC curve"
        />
      </div>
    </div>
  )
}

// ─── Section B: Engine Rankings ───────────────────────────────────────────────

const ENGINE_CHART_COLORS = ['#10b981', '#6366f1', '#f59e0b', '#06b6d4', '#f43f5e']

function EngineRankingsSection({ suite }: { suite: BenchmarkSuite }) {
  const rankings = suite.overallMetrics.engineRankings
  const chartData = rankings.map((r, i) => ({
    engine: r.engine.replace(' ', '\n'),
    label: r.engine,
    avgF1: parseFloat((r.avgF1 * 100).toFixed(1)),
    avgAUC: parseFloat((r.avgAUC * 100).toFixed(1)),
    color: ENGINE_CHART_COLORS[i % ENGINE_CHART_COLORS.length],
  }))

  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <BarChart2 className="w-4 h-4 text-indigo-400" />
        Engine Rankings
      </h2>
      <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 p-4">
        <ResponsiveContainer width="100%" height={220}>
          <BarChart
            data={chartData}
            layout="vertical"
            margin={{ top: 4, right: 48, left: 8, bottom: 4 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
            <XAxis
              type="number"
              domain={[0, 100]}
              tickFormatter={(v) => `${v}%`}
              tick={{ fill: '#64748b', fontSize: 11 }}
              axisLine={{ stroke: '#334155' }}
              tickLine={false}
            />
            <YAxis
              type="category"
              dataKey="label"
              width={130}
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip
              cursor={{ fill: 'rgba(99,102,241,0.08)' }}
              contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
              formatter={(value: number, name: string) => [`${value}%`, name === 'avgF1' ? 'Avg F1' : 'Avg AUC']}
              labelStyle={{ color: '#e2e8f0' }}
            />
            <Bar dataKey="avgF1" name="Avg F1" radius={[0, 4, 4, 0]} barSize={18}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>

        <div className="mt-4 border-t border-slate-700/50 pt-4">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 border-b border-slate-700/50">
                <th className="text-left pb-2 font-medium">Rank</th>
                <th className="text-left pb-2 font-medium">Engine</th>
                <th className="text-right pb-2 font-medium">Avg F1</th>
                <th className="text-right pb-2 font-medium">Avg AUC</th>
              </tr>
            </thead>
            <tbody>
              {rankings.map((r, i) => (
                <tr key={r.engine} className="border-b border-slate-700/30 last:border-0">
                  <td className="py-2 pr-3">
                    <span
                      className={`inline-flex w-5 h-5 rounded-full items-center justify-center text-[10px] font-bold ${
                        i === 0
                          ? 'bg-amber-500/20 text-amber-300'
                          : i === 1
                          ? 'bg-slate-500/20 text-slate-300'
                          : i === 2
                          ? 'bg-orange-700/20 text-orange-400'
                          : 'bg-slate-700/30 text-slate-500'
                      }`}
                    >
                      {i + 1}
                    </span>
                  </td>
                  <td className="py-2 text-slate-200 font-medium">{r.engine}</td>
                  <td className="py-2 text-right">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono ${f1Color(r.avgF1)}`}>
                      {r.avgF1.toFixed(3)}
                    </span>
                  </td>
                  <td className="py-2 text-right">
                    <span className="text-slate-300 font-mono">{r.avgAUC.toFixed(3)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── Section C: Per-Technique Heatmap ─────────────────────────────────────────

interface HeatmapTooltipState {
  visible: boolean
  x: number
  y: number
  result: BenchmarkResult | null
}

function TechniqueHeatmapSection({
  results,
  gapTechniques,
}: {
  results: BenchmarkResult[]
  gapTechniques: Set<string>
}) {
  const [tooltip, setTooltip] = useState<HeatmapTooltipState>({
    visible: false,
    x: 0,
    y: 0,
    result: null,
  })

  const engines = Array.from(new Set(results.map(r => r.engine)))
  const techniques = Array.from(new Set(results.map(r => r.technique)))
  const aggregated = aggregateResults(results)

  const getCell = (engine: string, technique: string) =>
    aggregated.find(r => r.engine === engine && r.technique === technique)

  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <FlaskConical className="w-4 h-4 text-violet-400" />
        Per-Technique Heatmap
        <span className="ml-auto text-[10px] text-slate-500 font-normal">F1 score per engine</span>
      </h2>
      <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-slate-700/50">
                <th className="text-left px-3 py-2.5 text-slate-500 font-medium min-w-[160px]">Technique</th>
                {engines.map(e => (
                  <th key={e} className="text-center px-2 py-2.5 text-slate-400 font-medium whitespace-nowrap min-w-[110px]">
                    {e}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {techniques.map(technique => {
                const isGap = gapTechniques.has(technique)
                return (
                  <tr
                    key={technique}
                    className={`border-b border-slate-700/30 last:border-0 ${isGap ? 'bg-amber-500/5' : ''}`}
                  >
                    <td className="px-3 py-2 text-slate-300">
                      <div className="flex items-center gap-1.5">
                        {isGap && <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />}
                        <span className={isGap ? 'text-amber-200' : ''}>{technique}</span>
                      </div>
                    </td>
                    {engines.map(engine => {
                      const cell = getCell(engine, technique)
                      if (!cell) {
                        return (
                          <td key={engine} className="px-2 py-2 text-center">
                            <span className="text-slate-600">—</span>
                          </td>
                        )
                      }
                      return (
                        <td
                          key={engine}
                          className="px-2 py-2 text-center relative"
                          onMouseEnter={(e) => {
                            const rect = e.currentTarget.getBoundingClientRect()
                            setTooltip({
                              visible: true,
                              x: rect.left + rect.width / 2,
                              y: rect.top,
                              result: cell,
                            })
                          }}
                          onMouseLeave={() => setTooltip(t => ({ ...t, visible: false }))}
                        >
                          <span
                            className={`inline-block px-2 py-1 rounded font-mono cursor-default select-none ${f1Color(cell.f1Score)}`}
                          >
                            {cell.f1Score.toFixed(3)}
                          </span>
                        </td>
                      )
                    })}
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 px-3 py-2 border-t border-slate-700/50 bg-slate-900/30">
          <span className="text-[10px] text-slate-500 mr-1">F1 legend:</span>
          {[
            { label: '≥ 0.8 Strong', cls: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' },
            { label: '0.5–0.8 Moderate', cls: 'bg-amber-500/20 text-amber-300 border border-amber-500/30' },
            { label: '< 0.5 Weak', cls: 'bg-rose-500/20 text-rose-300 border border-rose-500/30' },
          ].map(({ label, cls }) => (
            <span key={label} className={`text-[10px] px-2 py-0.5 rounded ${cls}`}>
              {label}
            </span>
          ))}
        </div>
      </div>

      {/* Floating tooltip */}
      {tooltip.visible && tooltip.result && (
        <div
          className="fixed z-50 pointer-events-none bg-slate-900 border border-slate-700 rounded-lg p-3 shadow-xl text-xs w-52"
          style={{ left: tooltip.x - 104, top: tooltip.y - 130 }}
        >
          <p className="font-semibold text-slate-200 mb-1.5">{tooltip.result.engine}</p>
          <p className="text-slate-400 mb-2 text-[10px]">{tooltip.result.technique}</p>
          <div className="grid grid-cols-2 gap-x-3 gap-y-1">
            {[
              { label: 'F1', value: tooltip.result.f1Score.toFixed(3) },
              { label: 'AUC', value: tooltip.result.auc.toFixed(3) },
              { label: 'TPR', value: pct(tooltip.result.detectionRate) },
              { label: 'FPR', value: pct(tooltip.result.falsePositiveRate) },
              { label: 'Precision', value: pct(tooltip.result.precision) },
              { label: 'Recall', value: pct(tooltip.result.recall) },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between">
                <span className="text-slate-500">{label}</span>
                <span className="text-slate-200 font-mono">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Section D: Technique Gaps ────────────────────────────────────────────────

function TechniqueGapsSection({ suite }: { suite: BenchmarkSuite }) {
  const gaps = suite.overallMetrics.techniqueGaps
  if (gaps.length === 0) {
    return (
      <div>
        <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          Technique Gaps
        </h2>
        <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 p-6 text-center">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <p className="text-sm text-emerald-300 font-medium">No critical gaps detected</p>
          <p className="text-xs text-slate-500 mt-1">All techniques achieve F1 ≥ 0.85 across at least one engine</p>
        </div>
      </div>
    )
  }
  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <AlertTriangle className="w-4 h-4 text-amber-400" />
        Technique Gaps
        <span className="ml-1 text-[10px] bg-amber-500/15 text-amber-300 border border-amber-500/30 px-1.5 py-0.5 rounded-full">
          {gaps.length} technique{gaps.length !== 1 ? 's' : ''} below 0.85 F1
        </span>
      </h2>
      <div className="rounded-xl bg-slate-800/60 border border-slate-700/50 divide-y divide-slate-700/40">
        {gaps.map((gap) => {
          const isCritical = gap.bestF1 < 0.5
          return (
            <div key={gap.technique} className="flex items-center gap-4 px-4 py-3">
              <div className="shrink-0">
                <AlertTriangle className={`w-4 h-4 ${isCritical ? 'text-rose-400' : 'text-amber-400'}`} />
              </div>
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-medium ${isCritical ? 'text-rose-200' : 'text-amber-200'}`}>
                  {gap.technique}
                </p>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Worst engine: <span className="text-slate-400">{gap.worstEngine}</span>
                </p>
              </div>
              <div className="shrink-0 text-right">
                <span
                  className={`inline-block px-2.5 py-1 rounded text-xs font-mono font-semibold ${
                    isCritical
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  Best F1: {gap.bestF1.toFixed(3)}
                </span>
                {isCritical && (
                  <p className="text-[10px] text-rose-400 mt-1">Critical gap</p>
                )}
              </div>
              <div className="w-28 shrink-0">
                <div className="w-full bg-slate-700/50 rounded-full h-1.5">
                  <div
                    className={`h-1.5 rounded-full transition-all ${isCritical ? 'bg-rose-500' : 'bg-amber-500'}`}
                    style={{ width: `${Math.min(gap.bestF1 * 100, 100)}%` }}
                  />
                </div>
                <p className="text-[10px] text-slate-500 mt-0.5 text-right">{pct(gap.bestF1)}</p>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Section E: Confusion Matrix Detail ───────────────────────────────────────

function ProgressBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-slate-700/50 rounded-full h-1.5">
        <div
          className="h-1.5 rounded-full transition-all"
          style={{ width: `${Math.min(value * 100, 100)}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-[11px] font-mono text-slate-300 w-12 text-right">{pct(value)}</span>
    </div>
  )
}

function ConfusionMatrixSection({ results }: { results: BenchmarkResult[] }) {
  const [expandedEngine, setExpandedEngine] = useState<string | null>(null)
  const aggregated = aggregateResults(results)
  const engines = Array.from(new Set(aggregated.map(r => r.engine)))

  return (
    <div>
      <h2 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <Shield className="w-4 h-4 text-cyan-400" />
        Confusion Matrix Detail
        <span className="ml-auto text-[10px] text-slate-500 font-normal">Averaged across all techniques and datasets</span>
      </h2>
      <div className="space-y-2">
        {engines.map(engine => {
          const engineResults = aggregated.filter(r => r.engine === engine)
          const avg = (fn: (r: BenchmarkResult) => number) =>
            engineResults.reduce((s, r) => s + fn(r), 0) / engineResults.length
          const tp = Math.round(avg(r => r.truePositives))
          const fp = Math.round(avg(r => r.falsePositives))
          const tn = Math.round(avg(r => r.trueNegatives))
          const fn_ = Math.round(avg(r => r.falseNegatives))
          const precision = avg(r => r.precision)
          const recall = avg(r => r.recall)
          const f1 = avg(r => r.f1Score)
          const accuracy = avg(r => r.accuracy)
          const isExpanded = expandedEngine === engine

          return (
            <div
              key={engine}
              className="rounded-xl bg-slate-800/60 border border-slate-700/50 overflow-hidden"
            >
              <button
                className="w-full flex items-center gap-3 px-4 py-3 hover:bg-slate-700/30 transition-colors text-left"
                onClick={() => setExpandedEngine(isExpanded ? null : engine)}
                aria-expanded={isExpanded}
              >
                <span className={`w-2.5 h-2.5 rounded-full shrink-0`} style={{ backgroundColor: f1Hex(f1) }} />
                <span className="flex-1 text-sm font-medium text-slate-200">{engine}</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded ${f1Color(f1)}`}>
                  F1 {f1.toFixed(3)}
                </span>
                <span className="text-xs text-slate-500 font-mono">{pct(accuracy)} acc</span>
                {isExpanded ? (
                  <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
                )}
              </button>

              {isExpanded && (
                <div className="border-t border-slate-700/50 px-4 pb-4 pt-3 grid grid-cols-1 md:grid-cols-2 gap-5">
                  {/* Confusion Matrix Grid */}
                  <div>
                    <p className="text-[11px] text-slate-500 mb-2 font-medium uppercase tracking-wide">Confusion Matrix (avg)</p>
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: 'True Positives', value: tp, cls: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' },
                        { label: 'False Positives', value: fp, cls: 'bg-amber-500/10 border-amber-500/30 text-amber-300' },
                        { label: 'False Negatives', value: fn_, cls: 'bg-rose-500/10 border-rose-500/30 text-rose-300' },
                        { label: 'True Negatives', value: tn, cls: 'bg-sky-500/10 border-sky-500/30 text-sky-300' },
                      ].map(({ label, value, cls }) => (
                        <div key={label} className={`rounded-lg border p-3 text-center ${cls}`}>
                          <p className="text-xl font-bold tabular-nums">{value}</p>
                          <p className="text-[10px] mt-0.5 opacity-80">{label}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Metrics bars */}
                  <div className="space-y-3">
                    <p className="text-[11px] text-slate-500 mb-2 font-medium uppercase tracking-wide">Derived Metrics</p>
                    {[
                      { label: 'Precision', value: precision, color: '#6366f1' },
                      { label: 'Recall (TPR)', value: recall, color: '#10b981' },
                      { label: 'F1 Score', value: f1, color: f1Hex(f1) },
                      { label: 'Accuracy', value: accuracy, color: '#06b6d4' },
                    ].map(({ label, value, color }) => (
                      <div key={label}>
                        <div className="flex justify-between mb-1">
                          <span className="text-[11px] text-slate-400">{label}</span>
                        </div>
                        <ProgressBar value={value} color={color} />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Dataset Selector ─────────────────────────────────────────────────────────

function DatasetSelector({
  datasets,
  selected,
  onToggle,
  onSelectAll,
}: {
  datasets: BenchmarkDataset[]
  selected: Set<string>
  onToggle: (id: string) => void
  onSelectAll: () => void
}) {
  const allSelected = selected.size === datasets.length

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
          <Database className="w-4 h-4 text-slate-400" />
          Select Datasets
        </h2>
        <button
          onClick={onSelectAll}
          className="text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors"
        >
          {allSelected ? 'Deselect all' : 'Select all'}
        </button>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {datasets.map(ds => {
          const isSelected = selected.has(ds.id)
          return (
            <label
              key={ds.id}
              className={`flex gap-3 p-3 rounded-xl border cursor-pointer transition-all ${
                isSelected
                  ? 'bg-indigo-500/10 border-indigo-500/40'
                  : 'bg-slate-800/50 border-slate-700/40 hover:border-slate-600/60'
              }`}
            >
              <input
                type="checkbox"
                checked={isSelected}
                onChange={() => onToggle(ds.id)}
                className="mt-0.5 shrink-0 w-4 h-4 accent-indigo-500"
                aria-label={`Select ${ds.name}`}
              />
              <div className="min-w-0">
                <p className={`text-sm font-medium truncate ${isSelected ? 'text-indigo-200' : 'text-slate-300'}`}>
                  {ds.name}
                </p>
                <p className="text-[10px] text-slate-500 mt-0.5 truncate">{ds.source}</p>
                <div className="flex items-center gap-2 mt-1.5">
                  <span className="text-[10px] bg-slate-700/60 text-slate-400 px-1.5 py-0.5 rounded">
                    {ds.sampleCount.toLocaleString()} samples
                  </span>
                  <span className="text-[10px] bg-rose-500/10 text-rose-400 border border-rose-500/20 px-1.5 py-0.5 rounded">
                    {ds.poisonedCount} poisoned
                  </span>
                </div>
              </div>
            </label>
          )
        })}
      </div>
    </div>
  )
}

// ─── Run Button ───────────────────────────────────────────────────────────────

function RunButton({
  disabled,
  loading,
  selectedCount,
  onClick,
}: {
  disabled: boolean
  loading: boolean
  selectedCount: number
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
        disabled || loading
          ? 'bg-slate-700/50 text-slate-500 cursor-not-allowed border border-slate-600/30'
          : 'bg-rose-600 hover:bg-rose-500 text-white border border-rose-500/50 shadow-lg shadow-rose-900/30'
      }`}
      aria-label={loading ? 'Running benchmark suite' : 'Run benchmark suite'}
    >
      {loading ? (
        <Loader2 className="w-4 h-4 animate-spin" />
      ) : (
        <Play className="w-4 h-4" />
      )}
      {loading
        ? 'Running suite…'
        : selectedCount === 0
        ? 'Select datasets to run'
        : `Run Suite (${selectedCount} dataset${selectedCount !== 1 ? 's' : ''})`}
    </button>
  )
}

// ─── Main Panel ───────────────────────────────────────────────────────────────

export function BenchmarkPanel() {
  const [datasets, setDatasets] = useState<BenchmarkDataset[]>([])
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [loading, setLoading] = useState(false)
  const [datasetsLoading, setDatasetsLoading] = useState(true)
  const [suite, setSuite] = useState<BenchmarkSuite | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    setDatasetsLoading(true)
    fetchBenchmarkDatasets()
      .then(setDatasets)
      .catch(e => setError(e.message))
      .finally(() => setDatasetsLoading(false))
  }, [])

  const toggleDataset = useCallback((id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const selectAll = useCallback(() => {
    setSelectedIds(prev =>
      prev.size === datasets.length ? new Set() : new Set(datasets.map(d => d.id))
    )
  }, [datasets])

  const handleRun = useCallback(async () => {
    if (selectedIds.size === 0) return
    setLoading(true)
    setError(null)
    setSuite(null)
    try {
      const result = await runBenchmarkSuite(Array.from(selectedIds))
      setSuite(result)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Benchmark failed')
    } finally {
      setLoading(false)
    }
  }, [selectedIds])

  const gapTechniques = suite
    ? new Set(suite.overallMetrics.techniqueGaps.map(g => g.technique))
    : new Set<string>()

  return (
    <div className="space-y-6">
      {/* Dataset selection + run button */}
      <div className="rounded-2xl bg-slate-900/60 border border-slate-700/50 p-5 space-y-4">
        {datasetsLoading ? (
          <div className="flex items-center gap-2 text-slate-400 text-sm py-4">
            <Loader2 className="w-4 h-4 animate-spin" />
            Loading datasets…
          </div>
        ) : (
          <DatasetSelector
            datasets={datasets}
            selected={selectedIds}
            onToggle={toggleDataset}
            onSelectAll={selectAll}
          />
        )}

        <div className="flex items-center gap-4 pt-1">
          <RunButton
            disabled={selectedIds.size === 0 || datasetsLoading}
            loading={loading}
            selectedCount={selectedIds.size}
            onClick={handleRun}
          />
          {suite && suite.status === 'complete' && (
            <span className="flex items-center gap-1.5 text-xs text-emerald-400">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Completed {new Date(suite.completedAt!).toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="rounded-xl bg-rose-500/10 border border-rose-500/30 p-4 flex items-start gap-3">
          <AlertTriangle className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-medium text-rose-300">Benchmark failed</p>
            <p className="text-xs text-rose-400/80 mt-0.5">{error}</p>
          </div>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="rounded-2xl bg-slate-900/60 border border-slate-700/50 p-8 flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 text-rose-400 animate-spin" />
          <p className="text-sm text-slate-300 font-medium">Running benchmark suite…</p>
          <p className="text-xs text-slate-500">
            Evaluating {selectedIds.size} dataset{selectedIds.size !== 1 ? 's' : ''} across all detection engines
          </p>
          <div className="w-48 bg-slate-700/50 rounded-full h-1 mt-2 overflow-hidden">
            <div className="h-1 bg-rose-500 rounded-full animate-pulse w-2/3" />
          </div>
        </div>
      )}

      {/* Results */}
      {suite && !loading && (
        <div className="space-y-6">
          <OverallMetricsSection suite={suite} />
          <EngineRankingsSection suite={suite} />
          <TechniqueHeatmapSection results={suite.results} gapTechniques={gapTechniques} />
          <TechniqueGapsSection suite={suite} />
          <ConfusionMatrixSection results={suite.results} />
        </div>
      )}
    </div>
  )
}
