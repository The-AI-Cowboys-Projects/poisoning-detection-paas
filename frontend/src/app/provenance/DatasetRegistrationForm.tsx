'use client'

import { useState, type FormEvent } from 'react'
import { Plus, Loader2, CheckCircle2, X } from 'lucide-react'
import { registerDataset } from '@/lib/api'
import type { ProvenanceNode } from '@/lib/types'

interface Props {
  existingNodes: ProvenanceNode[]
}

type FormState = 'idle' | 'submitting' | 'success' | 'error'

export function DatasetRegistrationForm({ existingNodes }: Props) {
  const [formState, setFormState] = useState<FormState>('idle')
  const [error, setError] = useState<string | null>(null)
  const [selectedParents, setSelectedParents] = useState<string[]>([])

  const toggleParent = (id: string) => {
    setSelectedParents((prev) =>
      prev.includes(id) ? prev.filter((p) => p !== id) : [...prev, id],
    )
  }

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setFormState('submitting')
    setError(null)

    const fd = new FormData(e.currentTarget)
    const name = fd.get('name') as string
    const source = fd.get('source') as string
    const version = fd.get('version') as string
    const hash = fd.get('hash') as string

    try {
      await registerDataset({
        name,
        source,
        version,
        hash,
        parentIds: selectedParents,
        metadata: {},
      })
      setFormState('success')
      setTimeout(() => setFormState('idle'), 3000)
    } catch (err) {
      setFormState('error')
      setError(err instanceof Error ? err.message : 'Registration failed.')
    }
  }

  return (
    <div className="card">
      <h2 className="text-sm font-semibold text-slate-200 mb-1">Register Dataset</h2>
      <p className="text-xs text-slate-500 mb-5">
        Add a new dataset or model artifact to the provenance graph.
      </p>

      <form onSubmit={handleSubmit} aria-label="Dataset registration" className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label htmlFor="ds-name" className="block text-xs font-medium text-slate-400 mb-1.5">
              Dataset Name <span className="text-red-400" aria-hidden="true">*</span>
            </label>
            <input
              id="ds-name"
              name="name"
              type="text"
              required
              placeholder="e.g. Fine-tune Corpus v3"
              className="field"
              disabled={formState === 'submitting'}
              aria-required="true"
            />
          </div>

          <div>
            <label htmlFor="ds-source" className="block text-xs font-medium text-slate-400 mb-1.5">
              Source URI <span className="text-red-400" aria-hidden="true">*</span>
            </label>
            <input
              id="ds-source"
              name="source"
              type="text"
              required
              placeholder="e.g. s3://bucket/path or https://..."
              className="field"
              disabled={formState === 'submitting'}
              aria-required="true"
            />
          </div>

          <div>
            <label htmlFor="ds-version" className="block text-xs font-medium text-slate-400 mb-1.5">
              Version
            </label>
            <input
              id="ds-version"
              name="version"
              type="text"
              placeholder="e.g. 1.0.0"
              className="field"
              disabled={formState === 'submitting'}
            />
          </div>

          <div>
            <label htmlFor="ds-hash" className="block text-xs font-medium text-slate-400 mb-1.5">
              Content Hash (SHA-256)
            </label>
            <input
              id="ds-hash"
              name="hash"
              type="text"
              placeholder="sha256:..."
              className="field font-mono"
              disabled={formState === 'submitting'}
            />
          </div>
        </div>

        {/* Parent node selection */}
        <div>
          <p className="text-xs font-medium text-slate-400 mb-2">
            Parent Nodes
            <span className="text-slate-600 font-normal ml-1">(optional — select all that apply)</span>
          </p>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Parent node selection">
            {existingNodes.map((node) => {
              const selected = selectedParents.includes(node.id)
              return (
                <button
                  key={node.id}
                  type="button"
                  onClick={() => toggleParent(node.id)}
                  aria-pressed={selected}
                  disabled={formState === 'submitting'}
                  className={[
                    'flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors',
                    'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/60',
                    selected
                      ? 'bg-blue-900/40 text-blue-300 border-blue-700'
                      : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-slate-500 hover:text-slate-300',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                  ].join(' ')}
                >
                  {selected && <X className="w-3 h-3" aria-hidden="true" />}
                  <span className="truncate max-w-[120px]">{node.label}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Status messages */}
        {formState === 'success' && (
          <div
            role="status"
            className="flex items-center gap-2 text-sm text-green-400 bg-green-900/30 border border-green-800/50 px-4 py-3 rounded-lg"
          >
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" aria-hidden="true" />
            Dataset registered and added to the provenance graph.
          </div>
        )}

        {formState === 'error' && error && (
          <p role="alert" className="text-sm text-red-400">
            {error}
          </p>
        )}

        <div className="flex justify-end">
          <button
            type="submit"
            className="btn-primary"
            disabled={formState === 'submitting' || formState === 'success'}
          >
            {formState === 'submitting' ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                Registering...
              </>
            ) : (
              <>
                <Plus className="w-3.5 h-3.5" aria-hidden="true" />
                Register Dataset
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}
