import { Fingerprint } from 'lucide-react'
import { ProofsPanel } from './ProofsPanel'

export const metadata = { title: 'Cryptographic Proofs — AI-SPM' }

export default function ProofsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-violet-600/20 border border-violet-600/30 flex items-center justify-center">
          <Fingerprint className="w-5 h-5 text-violet-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Cryptographic Proofs & Detection Bounds</h1>
          <p className="text-xs text-slate-500">Hash-chained scan results and detection coverage matrix</p>
        </div>
      </div>
      <ProofsPanel />
    </div>
  )
}
