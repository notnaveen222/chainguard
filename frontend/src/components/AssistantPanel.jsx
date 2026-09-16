import { useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  ArrowUp,
  Check,
  FileText,
  History,
  Loader2,
  RotateCcw,
  ScrollText,
  Sparkles,
  Square,
  Wrench,
  X,
} from 'lucide-react'

import { streamAssistant } from '@/api'
import { cn } from '@/lib/utils'

const TOOL_LABELS = {
  list_scans: 'Listing scans',
  get_scan_summary: 'Reading scan summary',
  get_package_details: 'Inspecting package',
  list_vulnerabilities: 'Checking vulnerabilities',
  get_model_card: 'Reading model metrics',
  read_logs: 'Reading server logs',
  get_scan_status: 'Checking scan progress',
  package_history: 'Searching scan history',
  check_package: 'Analysing package live',
}

const SUGGESTIONS = [
  { icon: FileText, text: 'Summarise my latest scan. What actually needs my attention?' },
  { icon: Sparkles, text: 'Can I safely use axios@0.21.1?' },
  { icon: History, text: 'What happened to fsevents in my scans?' },
  { icon: Wrench, text: 'What should I upgrade or remove first?' },
  { icon: ScrollText, text: 'Were there any errors or failed downloads in the logs?' },
]

function toolDetail(name, input) {
  if (!input || typeof input !== 'object') return ''
  if (input.package) return input.package
  if (name === 'read_logs') return [input.min_level, input.contains].filter(Boolean).join(' · ')
  if (name === 'list_vulnerabilities' && input.reachable !== undefined) return input.reachable ? 'reachable' : 'not reachable'
  return ''
}

export default function AssistantPanel({ open, onClose, scanId, available }) {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const abortRef = useRef(null)
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 150)
  }, [open])

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages])

  function patchLast(fn) {
    setMessages((current) => {
      const next = [...current]
      next[next.length - 1] = fn({ ...next[next.length - 1] })
      return next
    })
  }

  async function send(text) {
    const content = (text ?? input).trim()
    if (!content || busy) return
    setInput('')

    const history = [
      ...messages.filter((m) => m.content).map(({ role, content }) => ({ role, content })),
      { role: 'user', content },
    ]
    setMessages((current) => [
      ...current,
      { role: 'user', content },
      { role: 'assistant', content: '', tools: [], pending: true },
    ])
    setBusy(true)

    const controller = new AbortController()
    abortRef.current = controller
    try {
      await streamAssistant(
        history,
        scanId,
        (event) => {
          if (event.type === 'text') {
            patchLast((m) => ({ ...m, content: m.content + event.delta }))
          } else if (event.type === 'tool') {
            patchLast((m) => ({
              ...m,
              tools: [...m.tools, { id: event.id, name: event.name, detail: toolDetail(event.name, event.input), done: false }],
            }))
          } else if (event.type === 'tool_result') {
            patchLast((m) => ({
              ...m,
              tools: m.tools.map((t) => (t.id === event.id ? { ...t, done: true, error: event.is_error } : t)),
            }))
          } else if (event.type === 'error') {
            patchLast((m) => ({ ...m, error: event.message }))
          }
        },
        controller.signal,
      )
    } catch (err) {
      if (err.name !== 'AbortError') patchLast((m) => ({ ...m, error: err.message }))
    } finally {
      patchLast((m) => ({ ...m, pending: false }))
      setBusy(false)
      abortRef.current = null
    }
  }

  function stop() {
    abortRef.current?.abort()
  }

  function reset() {
    stop()
    setMessages([])
  }

  return (
    <>
      <div
        className={cn(
          'fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px] transition-opacity lg:hidden',
          open ? 'opacity-100' : 'pointer-events-none opacity-0',
        )}
        onClick={onClose}
      />
      <aside
        className={cn(
          'fixed right-0 top-0 z-50 h-full w-full sm:w-[440px] flex flex-col bg-card border-l border-border shadow-2xl shadow-black/50',
          'transition-transform duration-300 ease-out',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
        aria-hidden={!open}
      >
        <header className="h-14 shrink-0 flex items-center gap-3 px-4 border-b border-border">
          <div className="grid h-7 w-7 place-items-center rounded-lg bg-gradient-to-b from-violet-400/20 to-cyan-400/10 ring-1 ring-inset ring-violet-300/25">
            <Sparkles size={14} className="text-violet-200" />
          </div>
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground leading-none">Security consultant</div>
            <div className="text-[11px] text-muted-foreground mt-1 leading-none truncate">
              {scanId ? <>Looking at scan <span className="font-mono">{scanId}</span></> : 'Ask about any package, scan or log'}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-1">
            {messages.length > 0 && (
              <button onClick={reset} className="btn-ghost h-8 w-8 px-0" title="New conversation">
                <RotateCcw size={15} />
              </button>
            )}
            <button onClick={onClose} className="btn-ghost h-8 w-8 px-0" title="Close">
              <X size={16} />
            </button>
          </div>
        </header>

        <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-5 space-y-5">
          {!available && (
            <div className="rounded-xl border border-amber-500/25 bg-amber-500/[0.06] p-4 text-sm text-amber-100/90 leading-relaxed">
              The consultant needs an OpenAI API key. Add <code className="font-mono text-amber-200">OPENAI_API_KEY=…</code> to the
              <code className="font-mono text-amber-200"> .env</code> file in the repository root, then restart the API.
            </div>
          )}

          {messages.length === 0 && available && (
            <div className="pt-6">
              <p className="text-lg font-semibold tracking-tight text-foreground">Your security consultant</p>
              <p className="text-sm text-muted-foreground mt-1">
                Ask anything about your dependencies. It checks real scan results, package history, live package analysis and server logs before answering.
              </p>
              <div className="mt-5 space-y-2">
                {SUGGESTIONS.map(({ icon: Icon, text }) => (
                  <button
                    key={text}
                    onClick={() => send(text)}
                    className="w-full flex items-center gap-3 text-left rounded-lg border border-border bg-white/[0.015] hover:bg-white/[0.04] px-3 py-2.5 text-[13px] text-foreground/85 transition-colors"
                  >
                    <Icon size={15} className="text-muted-foreground shrink-0" />
                    {text}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((message, index) =>
            message.role === 'user' ? (
              <div key={index} className="flex justify-end">
                <div className="max-w-[85%] rounded-2xl rounded-br-md bg-white/[0.07] px-3.5 py-2 text-sm text-foreground whitespace-pre-wrap">
                  {message.content}
                </div>
              </div>
            ) : (
              <div key={index} className="space-y-2.5">
                {message.tools?.length > 0 && (
                  <div className="space-y-1">
                    {message.tools.map((tool) => (
                      <div key={tool.id} className="flex items-center gap-2 text-xs text-muted-foreground">
                        {tool.done ? (
                          <Check size={12} className={tool.error ? 'text-amber-400' : 'text-emerald-400'} />
                        ) : (
                          <Loader2 size={12} className="animate-spin text-cyan-400" />
                        )}
                        <span>{TOOL_LABELS[tool.name] || tool.name}</span>
                        {tool.detail && <span className="font-mono text-foreground/60 truncate">{tool.detail}</span>}
                      </div>
                    ))}
                  </div>
                )}

                {message.content && (
                  <div className="assistant-md text-sm text-foreground/90 leading-relaxed">
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
                  </div>
                )}

                {message.pending && !message.content && (!message.tools?.length || message.tools.every((t) => t.done)) && (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="flex gap-1">
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/60 animate-pulse" />
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/60 animate-pulse [animation-delay:150ms]" />
                      <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/60 animate-pulse [animation-delay:300ms]" />
                    </span>
                    Thinking
                  </div>
                )}

                {message.error && (
                  <div className="rounded-lg border border-red-500/25 bg-red-500/[0.06] px-3 py-2 text-xs text-red-200">
                    {message.error}
                  </div>
                )}
              </div>
            ),
          )}
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault()
            send()
          }}
          className="shrink-0 p-3 border-t border-border"
        >
          <div className="relative rounded-xl border border-input bg-background focus-within:border-ring focus-within:ring-2 focus-within:ring-ring/30 transition">
            <textarea
              ref={inputRef}
              rows={2}
              value={input}
              disabled={!available}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  send()
                }
              }}
              placeholder={available ? 'e.g. Can I use lodash 4.17.20? What happened to fsevents?' : 'API key required'}
              className="block w-full resize-none bg-transparent px-3.5 pt-3 pb-11 text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none disabled:opacity-50"
            />
            <div className="absolute bottom-2 right-2 flex items-center gap-2">
              {busy ? (
                <button type="button" onClick={stop} className="grid h-8 w-8 place-items-center rounded-lg bg-white/10 text-foreground hover:bg-white/15" title="Stop">
                  <Square size={12} fill="currentColor" />
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!input.trim() || !available}
                  className="grid h-8 w-8 place-items-center rounded-lg bg-primary text-primary-foreground disabled:opacity-30 transition-opacity"
                  title="Send"
                >
                  <ArrowUp size={15} strokeWidth={2.25} />
                </button>
              )}
            </div>
          </div>
          <p className="mt-2 px-1 text-[11px] text-muted-foreground/70">
            Uses OpenAI via your API key · reads scans, history and logs · verify important conclusions
          </p>
        </form>
      </aside>
    </>
  )
}
