import { Dna } from 'lucide-react'
import { EvolutionPanel } from './EvolutionPanel'

export const metadata = { title: 'Self-Evolution Loop — AI-SPM' }

export default function EvolutionPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-purple-600/20 border border-purple-600/30 flex items-center justify-center">
          <Dna className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Self-Evolution Loop</h1>
          <p className="text-xs text-slate-500">Generate → Detect → Score → Harden → Repeat</p>
        </div>
      </div>
      <EvolutionPanel />
    </div>
  )
}
