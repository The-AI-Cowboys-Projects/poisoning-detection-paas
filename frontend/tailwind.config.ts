import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Threat severity palette
        threat: {
          critical: {
            DEFAULT: '#ef4444',   // red-500
            bg: '#450a0a',        // red-950
            border: '#7f1d1d',    // red-900
            text: '#fca5a5',      // red-300
          },
          warning: {
            DEFAULT: '#f59e0b',   // amber-500
            bg: '#451a03',        // amber-950
            border: '#78350f',    // amber-900
            text: '#fcd34d',      // amber-300
          },
          safe: {
            DEFAULT: '#22c55e',   // green-500
            bg: '#052e16',        // green-950
            border: '#14532d',    // green-900
            text: '#86efac',      // green-300
          },
          info: {
            DEFAULT: '#3b82f6',   // blue-500
            bg: '#172554',        // blue-950
            border: '#1e3a8a',    // blue-900
            text: '#93c5fd',      // blue-300
          },
        },
        // Dashboard surface palette
        surface: {
          bg: '#0f172a',          // slate-900
          card: '#1e293b',        // slate-800
          border: '#334155',      // slate-700
          muted: '#475569',       // slate-600
          subtle: '#64748b',      // slate-500
        },
      },
      fontFamily: {
        sans: ['var(--font-inter)', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-in': 'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-8px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'grid-pattern': 'linear-gradient(rgba(148,163,184,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.05) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '32px 32px',
      },
    },
  },
  plugins: [],
}

export default config
