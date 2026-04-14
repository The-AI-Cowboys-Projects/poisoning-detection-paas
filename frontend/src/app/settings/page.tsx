/**
 * Settings — Tenant configuration, API keys, notification preferences,
 * detection thresholds, and system health.
 */

import type { Metadata } from 'next'
import { Settings } from 'lucide-react'
import { SettingsPanel } from './SettingsPanel'

export const metadata: Metadata = { title: 'Settings — AI-SPM' }

export default function SettingsPage() {
  return (
    <div className="space-y-8 animate-fade-in">

      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-slate-700/60 border border-slate-600/50 flex items-center justify-center">
            <Settings className="w-5 h-5 text-slate-300" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Settings</h1>
            <p className="text-sm text-slate-400 mt-0.5">
              Tenant configuration, API keys, notification preferences, and detection thresholds
            </p>
          </div>
        </div>
      </div>

      {/* Settings panel */}
      <section aria-label="Platform settings">
        <SettingsPanel />
      </section>

    </div>
  )
}
