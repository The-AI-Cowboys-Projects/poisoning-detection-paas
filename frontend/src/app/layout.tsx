import type { Metadata, Viewport } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Sidebar } from '@/components/Sidebar'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

export const metadata: Metadata = {
  title: {
    default: 'AI-SPM Dashboard',
    template: '%s | AI-SPM',
  },
  description:
    'AI Security Posture Management — real-time LLM data poisoning detection and threat monitoring.',
  robots: { index: false, follow: false },
  icons: {
    icon: [{ url: '/favicon.ico' }],
  },
}

export const viewport: Viewport = {
  themeColor: '#0f172a',
  colorScheme: 'dark',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`dark ${inter.variable}`} suppressHydrationWarning>
      <body className="bg-slate-900 text-slate-100 antialiased">
        <div className="flex h-dvh overflow-hidden">
          {/* Sidebar is a client component (uses usePathname) */}
          <Sidebar />

          {/* Main content area */}
          <main
            id="main-content"
            className="flex-1 flex flex-col overflow-y-auto bg-slate-900 bg-grid"
            tabIndex={-1}
          >
            {/* Skip-to-content link for keyboard users */}
            <a
              href="#main-content"
              className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50
                         bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium"
            >
              Skip to main content
            </a>

            <div className="flex-1 px-6 py-6 max-w-[1440px] w-full mx-auto">
              {children}
            </div>
          </main>
        </div>
      </body>
    </html>
  )
}
