'use client'

import { useState } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { ThreatBadge } from '@/components/ThreatBadge'
import type { ToolFinding } from '@/lib/types'

interface Props {
  finding: ToolFinding
}

export function SchemaPanel({ finding }: Props) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="rounded-lg border border-slate-700 overflow-hidden mb-2 last:mb-0">
      <button
        type="button"
        className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-slate-700/40 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500/60"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={`schema-detail-${finding.id}`}
      >
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" aria-hidden="true" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" aria-hidden="true" />
        )}
        <span className="flex-1 text-xs text-slate-300 font-medium truncate">
          {finding.description}
        </span>
        <ThreatBadge severity={finding.severity} size="sm" />
      </button>

      {expanded && (
        <div
          id={`schema-detail-${finding.id}`}
          className="px-3 pb-3 pt-1 border-t border-slate-700 bg-slate-900/60"
        >
          <div className="space-y-2">
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">Pattern ID</p>
              <span className="font-mono text-[10px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                {finding.patternId}
              </span>
            </div>
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">Schema Field</p>
              <span className="font-mono text-xs text-blue-300">{finding.field}</span>
            </div>
            <div>
              <p className="text-[10px] text-slate-600 uppercase tracking-wide mb-1">Evidence</p>
              <pre className="text-[10px] text-slate-400 bg-slate-950 border border-slate-800 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.evidence}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
