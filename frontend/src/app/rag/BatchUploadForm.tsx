'use client'

import { useState, useCallback, useRef } from 'react'
import { Upload, X, FileText, Loader2, CheckCircle2, AlertTriangle } from 'lucide-react'
import { scanRAGDocument } from '@/lib/api'

type UploadState = 'idle' | 'uploading' | 'success' | 'error'

interface QueuedFile {
  id: string
  file: File
  progress: number
}

export function BatchUploadForm() {
  const [files, setFiles] = useState<QueuedFile[]>([])
  const [state, setState] = useState<UploadState>('idle')
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleFiles = useCallback((incoming: FileList | null) => {
    if (!incoming) return
    const allowed = Array.from(incoming).filter((f) =>
      ['application/pdf', 'text/plain', 'application/json', 'text/markdown'].includes(f.type)
    )
    setFiles((prev) => [
      ...prev,
      ...allowed.map((f) => ({
        id: `${f.name}-${Date.now()}`,
        file: f,
        progress: 0,
      })),
    ])
  }, [])

  const removeFile = useCallback((id: string) => {
    setFiles((prev) => prev.filter((f) => f.id !== id))
  }, [])

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault()
      handleFiles(e.dataTransfer.files)
    },
    [handleFiles],
  )

  const handleSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault()
      if (!files.length) return
      setState('uploading')
      setError(null)

      try {
        for (let i = 0; i < files.length; i++) {
          // Show 50% progress while scanning
          setFiles((prev) =>
            prev.map((f, j) => ({
              ...f,
              progress: j < i ? 100 : j === i ? 50 : 0,
            })),
          )

          // Read file content and call scanRAGDocument
          const content = await files[i].file.text()
          const docId = `upload-${files[i].file.name}-${Date.now()}`
          await scanRAGDocument(content, docId, files[i].file.name)

          // Mark complete
          setFiles((prev) =>
            prev.map((f, j) => ({ ...f, progress: j <= i ? 100 : 0 })),
          )
        }
        setState('success')
        setTimeout(() => {
          setFiles([])
          setState('idle')
        }, 2500)
      } catch (err) {
        setState('error')
        setError(err instanceof Error ? err.message : 'Upload failed. Please try again.')
      }
    },
    [files],
  )

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className="card">
      <h2 className="text-sm font-semibold text-slate-200 mb-1">Batch Scan Upload</h2>
      <p className="text-xs text-slate-500 mb-5">
        Upload documents for RAG poisoning analysis. Supports PDF, TXT, JSON, and Markdown.
      </p>

      <form onSubmit={handleSubmit} aria-label="Batch document upload">
        {/* Drop zone */}
        <div
          role="button"
          tabIndex={0}
          aria-label="Drop files here or click to select"
          onDrop={handleDrop}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => inputRef.current?.click()}
          onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
          className={[
            'border-2 border-dashed rounded-xl px-6 py-10 text-center cursor-pointer',
            'transition-colors',
            state === 'uploading'
              ? 'border-blue-700 bg-blue-900/10 cursor-not-allowed'
              : 'border-slate-700 hover:border-slate-500 hover:bg-slate-800/60',
          ].join(' ')}
        >
          <Upload className="w-8 h-8 text-slate-600 mx-auto mb-3" aria-hidden="true" />
          <p className="text-sm text-slate-400">
            Drag and drop files, or{' '}
            <span className="text-blue-400 underline">browse</span>
          </p>
          <p className="text-xs text-slate-600 mt-1">PDF, TXT, JSON, MD — max 50 MB each</p>
        </div>

        <input
          ref={inputRef}
          type="file"
          multiple
          accept=".pdf,.txt,.json,.md,application/pdf,text/plain,application/json,text/markdown"
          className="sr-only"
          aria-hidden="true"
          onChange={(e) => handleFiles(e.target.files)}
          tabIndex={-1}
          disabled={state === 'uploading'}
        />

        {/* File list */}
        {files.length > 0 && (
          <ul className="mt-4 space-y-2" aria-label="Queued files">
            {files.map((qf) => (
              <li
                key={qf.id}
                className="flex items-center gap-3 bg-slate-900 rounded-lg px-3 py-2.5"
              >
                <FileText className="w-4 h-4 text-slate-500 flex-shrink-0" aria-hidden="true" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-slate-300 truncate font-medium">{qf.file.name}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] text-slate-500">{formatBytes(qf.file.size)}</span>
                    {state === 'uploading' && (
                      <div className="flex-1 h-1 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all duration-300"
                          style={{ width: `${qf.progress}%` }}
                          role="progressbar"
                          aria-valuenow={qf.progress}
                          aria-valuemin={0}
                          aria-valuemax={100}
                          aria-label={`Uploading ${qf.file.name}`}
                        />
                      </div>
                    )}
                  </div>
                </div>
                {state !== 'uploading' && (
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); removeFile(qf.id) }}
                    aria-label={`Remove ${qf.file.name}`}
                    className="text-slate-600 hover:text-slate-300 transition-colors flex-shrink-0"
                  >
                    <X className="w-3.5 h-3.5" aria-hidden="true" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}

        {/* Status messages */}
        {state === 'success' && (
          <div
            role="status"
            className="mt-4 flex items-center gap-2 text-sm text-green-400 bg-green-900/30 border border-green-800/50 px-4 py-3 rounded-lg"
          >
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" aria-hidden="true" />
            Upload complete — scan initiated in the background
          </div>
        )}

        {state === 'error' && error && (
          <p role="alert" className="mt-4 text-sm text-red-400">
            {error}
          </p>
        )}

        {/* Submit */}
        <div className="mt-4 flex items-center justify-between">
          <p className="text-xs text-slate-500">
            {files.length > 0 ? `${files.length} file${files.length !== 1 ? 's' : ''} queued` : 'No files selected'}
          </p>
          <button
            type="submit"
            className="btn-primary"
            disabled={files.length === 0 || state === 'uploading' || state === 'success'}
            aria-disabled={files.length === 0 || state === 'uploading'}
          >
            {state === 'uploading' ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" aria-hidden="true" />
                Uploading...
              </>
            ) : (
              <>
                <Upload className="w-3.5 h-3.5" aria-hidden="true" />
                Start Scan
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}
