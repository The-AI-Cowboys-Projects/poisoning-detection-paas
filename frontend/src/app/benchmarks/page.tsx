import { FlaskConical } from 'lucide-react'
import { BenchmarkPanel } from './BenchmarkPanel'

export const metadata = { title: 'Empirical Validation — AI-SPM' }

export default function BenchmarkPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-rose-600/20 border border-rose-600/30 flex items-center justify-center">
          <FlaskConical className="w-5 h-5 text-rose-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Empirical Validation</h1>
          <p className="text-xs text-slate-500">Detection benchmarks against real poisoning datasets — per-engine, per-technique</p>
        </div>
      </div>
      <BenchmarkPanel />
    </div>
  )
}
