'use client'

import { useState } from 'react'
import { Shield } from 'lucide-react'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mode, setMode] = useState<'password' | 'magic'>('password')
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError('')
    setMessage('')

    try {
      const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
      const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

      if (!supabaseUrl || !supabaseKey) {
        // Mock mode — just redirect
        window.location.href = '/'
        return
      }

      const { createBrowserClient } = await import('@supabase/ssr')
      const supabase = createBrowserClient(supabaseUrl, supabaseKey)

      if (mode === 'magic') {
        const { error } = await supabase.auth.signInWithOtp({
          email,
          options: { emailRedirectTo: `${window.location.origin}/auth/callback` },
        })
        if (error) throw error
        setMessage('Check your email for the magic link!')
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password })
        if (error) throw error
        window.location.href = '/'
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-dvh flex items-center justify-center bg-slate-950">
      <div
        className="card w-full max-w-md mx-4 p-8"
        style={{
          backgroundColor: 'var(--card-bg, #0f172a)',
          border: '1px solid var(--card-border, #1e293b)',
          borderRadius: '0.75rem',
        }}
      >
        {/* Branding */}
        <div className="flex flex-col items-center gap-3 mb-8">
          <div
            className="flex items-center justify-center w-14 h-14 rounded-xl"
            style={{ backgroundColor: '#1d4ed8' }}
          >
            <Shield className="w-8 h-8 text-white" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold text-white tracking-tight">AI-SPM</h1>
            <p className="text-sm text-slate-400 mt-0.5">AI Security Posture Management</p>
          </div>
        </div>

        {/* Mode toggle */}
        <div
          className="flex rounded-lg p-1 mb-6"
          style={{ backgroundColor: '#1e293b' }}
        >
          <button
            type="button"
            onClick={() => { setMode('password'); setError(''); setMessage('') }}
            className="flex-1 py-1.5 text-sm font-medium rounded-md transition-colors"
            style={{
              backgroundColor: mode === 'password' ? '#2563eb' : 'transparent',
              color: mode === 'password' ? '#ffffff' : '#94a3b8',
            }}
          >
            Password
          </button>
          <button
            type="button"
            onClick={() => { setMode('magic'); setError(''); setMessage('') }}
            className="flex-1 py-1.5 text-sm font-medium rounded-md transition-colors"
            style={{
              backgroundColor: mode === 'magic' ? '#2563eb' : 'transparent',
              color: mode === 'magic' ? '#ffffff' : '#94a3b8',
            }}
          >
            Magic Link
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="email"
              className="text-sm font-medium"
              style={{ color: '#cbd5e1' }}
            >
              Email address
            </label>
            <input
              id="email"
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full px-3 py-2 text-sm rounded-lg outline-none transition-colors"
              style={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                color: '#f1f5f9',
              }}
              onFocus={(e) => (e.currentTarget.style.borderColor = '#3b82f6')}
              onBlur={(e) => (e.currentTarget.style.borderColor = '#334155')}
            />
          </div>

          {mode === 'password' && (
            <div className="flex flex-col gap-1.5">
              <label
                htmlFor="password"
                className="text-sm font-medium"
                style={{ color: '#cbd5e1' }}
              >
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full px-3 py-2 text-sm rounded-lg outline-none transition-colors"
                style={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  color: '#f1f5f9',
                }}
                onFocus={(e) => (e.currentTarget.style.borderColor = '#3b82f6')}
                onBlur={(e) => (e.currentTarget.style.borderColor = '#334155')}
              />
            </div>
          )}

          {/* Error message */}
          {error && (
            <div
              className="px-3 py-2 text-sm rounded-lg"
              style={{ backgroundColor: '#450a0a', border: '1px solid #7f1d1d', color: '#fca5a5' }}
            >
              {error}
            </div>
          )}

          {/* Success message */}
          {message && (
            <div
              className="px-3 py-2 text-sm rounded-lg"
              style={{ backgroundColor: '#052e16', border: '1px solid #14532d', color: '#86efac' }}
            >
              {message}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 text-sm font-semibold text-white rounded-lg transition-opacity"
            style={{
              backgroundColor: '#2563eb',
              opacity: loading ? 0.6 : 1,
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            {loading
              ? 'Please wait...'
              : mode === 'magic'
              ? 'Send magic link'
              : 'Sign in'}
          </button>
        </form>

        <p className="text-center text-xs mt-6" style={{ color: '#475569' }}>
          Secured by Supabase Auth
        </p>
      </div>
    </div>
  )
}
