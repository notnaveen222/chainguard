import { useEffect, useState } from 'react'
import { Brain, Clock, ScanLine, ShieldCheck } from 'lucide-react'

import { api } from './api'
import HistoryPage from './pages/History'
import ModelPage from './pages/Model'
import ScanPage from './pages/Scan'

const TABS = [
  { id: 'scan', label: 'Scan', icon: ScanLine, component: ScanPage },
  { id: 'model', label: 'Model & evaluation', icon: Brain, component: ModelPage },
  { id: 'history', label: 'History', icon: Clock, component: HistoryPage },
]

export default function App() {
  const [tab, setTab] = useState('scan')
  const [health, setHealth] = useState(null)
  const [historyToken, setHistoryToken] = useState(0)

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: 'unreachable' }))
  }, [])

  const Active = TABS.find((t) => t.id === tab).component

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-ink-800 bg-ink-900/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="text-cyan-400" size={24} />
            <div>
              <h1 className="font-bold text-ink-50 leading-tight">ChainGuard</h1>
              <p className="text-[11px] text-ink-500 leading-tight">
                Malicious package detection &amp; vulnerability reachability analysis
              </p>
            </div>
          </div>

          <nav className="flex gap-1 ml-4">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm transition-colors ${
                  tab === id
                    ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-800'
                    : 'text-ink-400 hover:text-ink-200 border border-transparent'
                }`}
              >
                <Icon size={15} />
                {label}
              </button>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-3 text-xs">
            {health && <HealthPill health={health} />}
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6">
        {tab === 'scan' && (
          <ScanPage onScanComplete={() => setHistoryToken((t) => t + 1)} />
        )}
        {tab === 'model' && <ModelPage />}
        {tab === 'history' && <HistoryPage refreshToken={historyToken} />}
      </main>

      <footer className="border-t border-ink-800 py-4">
        <div className="max-w-7xl mx-auto px-6 text-xs text-ink-600 flex flex-wrap gap-x-6 gap-y-1">
          <span>Analysis is entirely static — no scanned package is ever executed.</span>
          <span className="ml-auto">ChainGuard {health?.version || ''}</span>
        </div>
      </footer>
    </div>
  )
}

function HealthPill({ health }) {
  if (health.status === 'unreachable') {
    return (
      <span className="badge border border-red-800 bg-red-950 text-red-300">
        backend unreachable
      </span>
    )
  }

  const trained = health.model_trained
  return (
    <div className="flex items-center gap-2">
      <span
        className={`badge border ${
          trained
            ? 'border-emerald-800 bg-emerald-950 text-emerald-300'
            : 'border-amber-800 bg-amber-950 text-amber-300'
        }`}
        title={
          trained
            ? 'Scoring with the trained classifier'
            : 'No model trained yet — scoring with the rules baseline'
        }
      >
        {trained ? 'model' : 'rules baseline'}
      </span>
      {health.llm_enabled && (
        <span className="badge border border-cyan-800 bg-cyan-950 text-cyan-300">llm on</span>
      )}
    </div>
  )
}
