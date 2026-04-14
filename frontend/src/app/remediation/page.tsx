import { ShieldCheck } from 'lucide-react'
import { RemediationPanel } from './RemediationPanel'

export const metadata = { title: 'Automated Remediation — AI-SPM' }

export default function RemediationPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-emerald-600/20 border border-emerald-600/30 flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Automated Remediation</h1>
          <p className="text-xs text-slate-500">Per-engine response actions with auto/manual toggle and audit trail</p>
        </div>
      </div>
      <RemediationPanel />
    </div>
  )
}
