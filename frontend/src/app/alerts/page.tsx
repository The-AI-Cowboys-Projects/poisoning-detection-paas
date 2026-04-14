/**
 * Alerts — Full alert management with filtering, status updates, and drill-down.
 *
 * Server component: fetches alert data at request time.
 */

export const dynamic = 'force-dynamic'

import type { Metadata } from 'next'
import { Bell } from 'lucide-react'
import { fetchRecentAlerts } from '@/lib/api'
import { AlertsPanel } from './AlertsPanel'

export const metadata: Metadata = { title: 'Alerts — AI-SPM' }

export default async function AlertsPage() {
  const alerts = await fetchRecentAlerts(50)

  return (
    <div className="space-y-8 animate-fade-in">

      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-red-900/40 border border-red-800/50 flex items-center justify-center">
            <Bell className="w-5 h-5 text-red-400" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-100">Alerts</h1>
            <p className="text-sm text-slate-400 mt-0.5">
              Security alerts, threat notifications, and incident management
            </p>
          </div>
        </div>
      </div>

      {/* Alert management panel */}
      <section aria-label="Alert management">
        <AlertsPanel initialAlerts={alerts} />
      </section>

    </div>
  )
}
