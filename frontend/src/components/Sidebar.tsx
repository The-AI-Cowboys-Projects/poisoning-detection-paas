/**
 * Sidebar — collapsible navigation with active state and keyboard accessibility.
 *
 * Usage (inside layout):
 *   <Sidebar />
 */

'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useState, useCallback } from 'react'
import {
  LayoutDashboard,
  ScatterChart,
  FileSearch,
  Wrench,
  GitBranch,
  Activity,
  Skull,
  Shield,
  ChevronLeft,
  ChevronRight,
  Bell,
  Settings,
  LogOut,
  FlaskConical,
} from 'lucide-react'

// ─── Nav items ────────────────────────────────────────────────────────────────

interface NavItem {
  label: string
  href: string
  icon: React.ElementType
  badge?: number
}

const PRIMARY_NAV: NavItem[] = [
  { label: 'Dashboard',     href: '/',           icon: LayoutDashboard },
  { label: 'Vector Analysis', href: '/vectors',  icon: ScatterChart },
  { label: 'RAG Scanning',  href: '/rag',        icon: FileSearch },
  { label: 'MCP Tools',     href: '/tools',      icon: Wrench },
  { label: 'Provenance',    href: '/provenance', icon: GitBranch },
  { label: 'Telemetry',     href: '/telemetry',  icon: Activity },
  { label: 'Poison Generator', href: '/generator', icon: Skull },
  { label: 'Model Lab', href: '/model-lab', icon: FlaskConical },
]

const SECONDARY_NAV: NavItem[] = [
  { label: 'Alerts',    href: '/alerts',   icon: Bell },
  { label: 'Settings',  href: '/settings', icon: Settings },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

function NavLink({
  item,
  collapsed,
  active,
}: {
  item: NavItem
  collapsed: boolean
  active: boolean
}) {
  const Icon = item.icon

  return (
    <Link
      href={item.href}
      title={collapsed ? item.label : undefined}
      aria-current={active ? 'page' : undefined}
      className={[
        'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60',
        active
          ? 'bg-blue-600/20 text-blue-300 border border-blue-600/30'
          : 'text-slate-400 hover:bg-slate-700/60 hover:text-slate-200 border border-transparent',
        collapsed ? 'justify-center' : '',
      ].join(' ')}
    >
      <Icon
        className={['w-4.5 h-4.5 flex-shrink-0', active ? 'text-blue-400' : ''].join(' ')}
        aria-hidden="true"
        style={{ width: '18px', height: '18px' }}
      />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {!collapsed && item.badge != null && item.badge > 0 && (
        <span className="ml-auto bg-red-500 text-white text-[10px] font-bold w-4.5 h-4.5 rounded-full flex items-center justify-center flex-shrink-0">
          {item.badge > 9 ? '9+' : item.badge}
        </span>
      )}
    </Link>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function Sidebar() {
  const pathname = usePathname()
  const [collapsed, setCollapsed] = useState(false)

  const toggle = useCallback(() => setCollapsed((v) => !v), [])

  const isActive = (href: string) =>
    href === '/' ? pathname === '/' : pathname.startsWith(href)

  return (
    <aside
      className={[
        'relative flex flex-col h-dvh bg-slate-900 border-r border-slate-800',
        'transition-all duration-200 ease-in-out flex-shrink-0',
        collapsed ? 'w-[68px]' : 'w-[240px]',
      ].join(' ')}
      aria-label="Primary navigation"
    >
      {/* ── Logo / brand ── */}
      <div
        className={[
          'flex items-center gap-3 px-4 py-4 border-b border-slate-800',
          collapsed ? 'justify-center' : '',
        ].join(' ')}
      >
        <div
          className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center flex-shrink-0"
          aria-hidden="true"
        >
          <Shield className="w-4 h-4 text-white" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <p className="text-sm font-bold text-slate-100 leading-tight truncate">
              AI-SPM
            </p>
            <p className="text-[10px] text-slate-500 leading-tight">
              Threat Detection
            </p>
          </div>
        )}
      </div>

      {/* ── Collapse toggle ── */}
      <button
        onClick={toggle}
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        className={[
          'absolute top-[52px] -right-3 z-10',
          'w-6 h-6 rounded-full bg-slate-700 border border-slate-600',
          'flex items-center justify-center',
          'hover:bg-slate-600 transition-colors',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60',
        ].join(' ')}
      >
        {collapsed ? (
          <ChevronRight className="w-3 h-3 text-slate-300" aria-hidden="true" />
        ) : (
          <ChevronLeft className="w-3 h-3 text-slate-300" aria-hidden="true" />
        )}
      </button>

      {/* ── Primary nav ── */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden px-3 py-4 space-y-1">
        {!collapsed && (
          <p className="px-3 mb-2 text-[10px] font-semibold text-slate-600 uppercase tracking-widest">
            Detection
          </p>
        )}
        {PRIMARY_NAV.map((item) => (
          <NavLink
            key={item.href}
            item={item}
            collapsed={collapsed}
            active={isActive(item.href)}
          />
        ))}

        <div className="pt-4 mt-4 border-t border-slate-800">
          {!collapsed && (
            <p className="px-3 mb-2 text-[10px] font-semibold text-slate-600 uppercase tracking-widest">
              System
            </p>
          )}
          {SECONDARY_NAV.map((item) => (
            <NavLink
              key={item.href}
              item={item}
              collapsed={collapsed}
              active={isActive(item.href)}
            />
          ))}
        </div>
      </nav>

      {/* ── Tenant info / sign out ── */}
      <div className="border-t border-slate-800 px-3 py-3">
        {!collapsed ? (
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-violet-600 flex-shrink-0" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className="text-xs font-semibold text-slate-200 truncate">Acme Corp</p>
              <p className="text-[10px] text-slate-500 truncate">analyst@acme.io</p>
            </div>
            <button
              aria-label="Sign out"
              className="text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0"
              onClick={async () => {
                try {
                  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
                  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
                  if (supabaseUrl && supabaseKey) {
                    const { createBrowserClient } = await import('@supabase/ssr')
                    const supabase = createBrowserClient(supabaseUrl, supabaseKey)
                    await supabase.auth.signOut()
                  }
                  localStorage.removeItem('ai_spm_jwt')
                } catch { /* ignore */ }
                window.location.href = '/login'
              }}
            >
              <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
            </button>
          </div>
        ) : (
          <div className="flex justify-center">
            <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-violet-600" aria-hidden="true" />
          </div>
        )}
      </div>
    </aside>
  )
}
