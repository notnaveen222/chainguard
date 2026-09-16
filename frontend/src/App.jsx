import { useEffect, useState } from 'react'
import { Brain, Clock, ScanLine, ShieldCheck, Sparkles } from 'lucide-react'

import { api } from './api'
import AssistantPanel from '@/components/AssistantPanel'
import { SidebarNav } from '@/components/ui/sidebar-nav'
import { cn } from '@/lib/utils'
import HistoryPage from './pages/History'
import ModelPage from './pages/Model'
import ScanPage from './pages/Scan'

const PAGES = {
  scan: {
    title: 'Scan',
    icon: ScanLine,
    description: 'Detect malicious packages and find which known vulnerabilities your code can actually reach.',
  },
  model: {
    title: 'Model & evaluation',
    icon: Brain,
    description: 'Out-of-fold metrics, baseline comparison, feature importance and ablation.',
  },
  history: {
    title: 'History',
    icon: Clock,
    description: 'Completed scans, stored locally.',
  },
}

const NAV_GROUPS = [
  { heading: 'Analyse', items: [{ id: 'scan', title: 'Scan', icon: ScanLine }] },
  {
    heading: 'Insights',
    items: [
      { id: 'model', title: 'Model & evaluation', icon: Brain },
      { id: 'history', title: 'History', icon: Clock },
    ],
  },
]

export default function App() {
  const [tab, setTab] = useState('scan')
  const [health, setHealth] = useState(null)
  const [historyToken, setHistoryToken] = useState(0)
  const [assistantOpen, setAssistantOpen] = useState(false)
  const [assistantScanId, setAssistantScanId] = useState(null)

  function openAssistant(scanId) {
    if (scanId) setAssistantScanId(scanId)
    setAssistantOpen(true)
  }

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: 'unreachable' }))
  }, [])

  const page = PAGES[tab]

  return (
    <div className="h-screen flex overflow-hidden bg-background">
      <SidebarNav
        className="hidden md:flex shrink-0"
        groups={NAV_GROUPS}
        activeId={tab}
        onSelect={setTab}
        header={<Brand />}
        footer={<HealthPanel health={health} />}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 shrink-0 border-b border-border flex items-center gap-3 px-4 md:px-8 bg-background/80 backdrop-blur">
          <div className="md:hidden flex items-center gap-2 mr-2">
            <ShieldCheck className="text-cyan-400" size={18} />
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground min-w-0">
            <span className="hidden sm:inline">ChainGuard</span>
            <span className="hidden sm:inline text-muted-foreground/40">/</span>
            <span className="font-medium text-foreground truncate">{page.title}</span>
          </div>

          {/* Compact nav for narrow screens, where the sidebar is hidden. */}
          <nav className="md:hidden ml-auto flex gap-1">
            {Object.entries(PAGES).map(([id, { icon: Icon, title }]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                aria-label={title}
                className={cn(
                  'p-2 rounded-md',
                  tab === id ? 'bg-white/[0.08] text-foreground' : 'text-muted-foreground',
                )}
              >
                <Icon size={16} />
              </button>
            ))}
          </nav>

          <span className="hidden xl:inline ml-auto text-xs text-muted-foreground">
            Static analysis only — scanned packages are never executed
          </span>

          <button
            onClick={() => openAssistant()}
            className={cn(
              'group relative inline-flex items-center gap-2 h-8 px-3 rounded-lg text-[13px] font-medium ring-1 ring-inset transition-colors',
              'ring-violet-300/25 bg-gradient-to-b from-violet-400/15 to-cyan-400/5 text-violet-100 hover:from-violet-400/25',
              'ml-2 md:ml-auto xl:ml-4',
            )}
          >
            <Sparkles size={14} className="text-violet-200" />
            <span className="hidden sm:inline">Ask AI</span>
          </button>
        </header>

        <main className="flex-1 overflow-y-auto">
          <div className="max-w-6xl mx-auto px-4 md:px-8 py-8">
            <div className="mb-7">
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">{page.title}</h1>
              <p className="text-sm text-muted-foreground mt-1">{page.description}</p>
            </div>

            <div key={tab} className="animate-fade-in">
              {tab === 'scan' && (
                <ScanPage
                  onScanComplete={() => setHistoryToken((t) => t + 1)}
                  onAskAI={openAssistant}
                />
              )}
              {tab === 'model' && <ModelPage />}
              {tab === 'history' && <HistoryPage refreshToken={historyToken} />}
            </div>
          </div>
        </main>
      </div>

      <AssistantPanel
        open={assistantOpen}
        onClose={() => setAssistantOpen(false)}
        scanId={assistantScanId}
        available={health?.assistant_available !== false}
      />
    </div>
  )
}

function Brand() {
  return (
    <div className="flex items-center gap-3 px-2 py-2 mb-3">
      <div className="relative grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-b from-cyan-400/20 to-cyan-400/5 ring-1 ring-inset ring-cyan-400/25">
        <ShieldCheck className="text-cyan-300" size={17} strokeWidth={2} />
      </div>
      <div className="min-w-0">
        <div className="text-[14px] font-semibold leading-none text-foreground">ChainGuard</div>
        <div className="text-[11px] text-muted-foreground leading-none mt-1.5">Supply chain security</div>
      </div>
    </div>
  )
}

function HealthPanel({ health }) {
  if (!health) {
    return <div className="px-2.5 py-2 text-xs text-muted-foreground">Connecting…</div>
  }

  if (health.status === 'unreachable') {
    return (
      <div className="px-2.5 py-2 flex items-center gap-2 text-xs">
        <span className="h-2 w-2 rounded-full bg-red-500" />
        <span className="text-red-300">Backend unreachable</span>
      </div>
    )
  }

  const trained = health.model_trained
  return (
    <div className="px-2.5 py-2 space-y-2 text-xs">
      <div className="flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
        </span>
        <span className="text-foreground/80">API connected</span>
        <span className="ml-auto text-muted-foreground font-mono">v{health.version}</span>
      </div>
      <div
        className="flex items-center justify-between text-muted-foreground"
        title={trained ? 'Scoring with the trained classifier' : 'No model trained yet — scoring with the rules baseline'}
      >
        <span>Detector</span>
        <span className={trained ? 'text-cyan-300' : 'text-amber-300'}>
          {trained ? 'ML classifier' : 'Rules baseline'}
        </span>
      </div>
      <div className="flex items-center justify-between text-muted-foreground">
        <span>LLM explanations</span>
        <span>{health.llm_enabled ? 'on' : 'off'}</span>
      </div>
    </div>
  )
}
