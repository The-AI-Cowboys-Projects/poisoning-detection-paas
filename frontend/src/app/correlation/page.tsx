import { Network } from 'lucide-react'
import { CorrelationPanel } from './CorrelationPanel'

export const metadata = { title: 'Attack Correlation — AI-SPM' }

export default function CorrelationPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-orange-600/20 border border-orange-600/30 flex items-center justify-center">
          <Network className="w-5 h-5 text-orange-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Cross-Engine Attack Correlation</h1>
          <p className="text-xs text-slate-500">Temporal + entity correlation with kill chain reconstruction</p>
        </div>
      </div>
      <CorrelationPanel />
    </div>
  )
}
