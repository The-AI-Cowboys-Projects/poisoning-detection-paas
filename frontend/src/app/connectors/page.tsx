import { Plug } from 'lucide-react'
import { ConnectorsPanel } from './ConnectorsPanel'

export const metadata = { title: 'Live Connectors — AI-SPM' }

export default function ConnectorsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-cyan-600/20 border border-cyan-600/30 flex items-center justify-center">
          <Plug className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-slate-100">Live Connectors</h1>
          <p className="text-xs text-slate-500">Monitor vector stores, MCP servers, and RAG pipelines in real-time</p>
        </div>
      </div>
      <ConnectorsPanel />
    </div>
  )
}
