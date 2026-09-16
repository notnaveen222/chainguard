import { Fragment, useEffect, useState } from 'react'
import {
  ArrowRight,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  FileCode2,
  FolderSearch,
  KeyRound,
  Loader2,
  Bug,
  Package,
  Play,
  Search,
  ShieldAlert,
  Sparkles,
  Wrench,
} from 'lucide-react'

import { api, pollScan } from '../api'
import { StatStrip } from '@/components/ui/stat-strip'
import { cn } from '@/lib/utils'
import {
  Badge,
  Card,
  ConfidencePill,
  EmptyState,
  ErrorBanner,
  ReachabilityHeadline,
} from '../ui'

const MODES = [
  { id: 'project', label: 'Project directory', icon: FolderSearch,
    hint: 'Dependencies + source code for reachability' },
  { id: 'manifest', label: 'Paste a manifest', icon: FileCode2,
    hint: 'package.json or requirements.txt' },
  { id: 'package', label: 'Single package', icon: Package,
    hint: 'Analyse one package in isolation' },
  { id: 'sample', label: 'Known malware', icon: Bug,
    hint: 'Real malicious package from the research vault' },
]

export default function ScanPage({ onScanComplete, onAskAI }) {
  const [mode, setMode] = useState('project')
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState(null)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const [projectPath, setProjectPath] = useState('')
  const [manifestText, setManifestText] = useState('')
  const [manifestName, setManifestName] = useState('requirements.txt')
  const [sourcePath, setSourcePath] = useState('')
  const [pkgName, setPkgName] = useState('')
  const [pkgVersion, setPkgVersion] = useState('latest')
  const [ecosystem, setEcosystem] = useState('PyPI')
  const [includeDev, setIncludeDev] = useState(false)
  const [sample, setSample] = useState(null)

  async function submit(event) {
    event?.preventDefault()
    setError(null)
    setResult(null)
    setBusy(true)
    setProgress({ stage: 'queued', progress: 0, message: 'Submitting scan…' })

    try {
      let submission
      if (mode === 'project') {
        if (!projectPath.trim()) throw new Error('Enter the path to a project directory')
        submission = await api.scanProject(projectPath.trim(), includeDev)
      } else if (mode === 'manifest') {
        if (!manifestText.trim()) throw new Error('Paste a manifest first')
        submission = await api.scanManifest(
          manifestText, manifestName, sourcePath.trim() || null, includeDev,
        )
      } else if (mode === 'sample') {
        if (!sample) throw new Error('Pick a malware sample first')
        setProgress({ stage: 'detect', progress: 0.5, message: `Decrypting ${sample.name} in memory and analysing…` })
        setResult(await api.scanSample(sample.name, sample.ecosystem))
        onScanComplete?.()
        return
      } else {
        if (!pkgName.trim()) throw new Error('Enter a package name')
        submission = await api.scanPackage(pkgName.trim(), pkgVersion.trim() || 'latest', ecosystem)
      }

      const finished = await pollScan(submission.scan_id, setProgress)
      setResult(finished)
      onScanComplete?.()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
      setProgress(null)
    }
  }

  return (
    <div className="space-y-6">
      <ScanForm
        {...{
          mode, setMode, busy, submit,
          projectPath, setProjectPath,
          manifestText, setManifestText, manifestName, setManifestName,
          sourcePath, setSourcePath,
          pkgName, setPkgName, pkgVersion, setPkgVersion,
          ecosystem, setEcosystem, includeDev, setIncludeDev,
          sample, setSample,
        }}
      />

      <ErrorBanner message={error} onDismiss={() => setError(null)} />
      {busy && <ProgressPanel progress={progress} />}
      {result && <ScanResult result={result} onAskAI={onAskAI} />}
      {!busy && !result && !error && (
        <Card>
          <EmptyState icon={ShieldAlert} title="No scan yet">
            Point ChainGuard at a project directory to get both halves of the analysis:
            malicious-package detection across the dependency tree, and reachability
            analysis showing which known vulnerabilities your code can actually reach.
          </EmptyState>
        </Card>
      )}
    </div>
  )
}

function ScanForm(props) {
  const { mode, setMode, busy, submit } = props

  return (
    <section className="card overflow-hidden">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-px bg-border border-b border-border">
        {MODES.map(({ id, label, icon: Icon, hint }) => {
          const active = mode === id
          return (
            <button
              key={id}
              type="button"
              onClick={() => setMode(id)}
              className={cn(
                'relative text-left px-5 py-4 transition-colors bg-card',
                active
                  ? 'shadow-[inset_0_0_0_999px_rgba(34,211,238,0.035)]'
                  : 'hover:shadow-[inset_0_0_0_999px_rgba(255,255,255,0.02)]',
              )}
            >
              <div className="flex items-center gap-2.5">
                <span
                  className={cn(
                    'grid h-7 w-7 place-items-center rounded-md ring-1 ring-inset transition-colors',
                    active ? 'bg-cyan-400/10 ring-cyan-400/30 text-cyan-300' : 'bg-white/[0.03] ring-white/10 text-muted-foreground',
                  )}
                >
                  <Icon size={15} strokeWidth={1.75} />
                </span>
                <span className={cn('text-sm font-medium', active ? 'text-foreground' : 'text-foreground/70')}>
                  {label}
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-2 leading-snug">{hint}</p>
              {active && <span className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-cyan-400 to-transparent" />}
            </button>
          )
        })}
      </div>

      <form onSubmit={submit} className="p-5 space-y-4">
        {mode === 'project' && (
          <Field
            label="Project directory"
            hint="Absolute path. Its manifest is discovered automatically and its source is used for reachability analysis."
          >
            <div className="relative">
              <FolderSearch size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground/60" />
              <input
                className="input font-mono pl-9"
                placeholder="D:\projects\my-app"
                value={props.projectPath}
                onChange={(e) => props.setProjectPath(e.target.value)}
              />
            </div>
          </Field>
        )}

        {mode === 'manifest' && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Field label="Manifest type">
                <select
                  className="input"
                  value={props.manifestName}
                  onChange={(e) => props.setManifestName(e.target.value)}
                >
                  <option value="requirements.txt">requirements.txt (PyPI)</option>
                  <option value="package.json">package.json (npm)</option>
                  <option value="package-lock.json">package-lock.json (npm)</option>
                  <option value="pyproject.toml">pyproject.toml (PyPI)</option>
                </select>
              </Field>
              <Field
                label="Source directory (optional)"
                hint="Without it, every advisory is reported as reachable."
              >
                <input
                  className="input font-mono"
                  placeholder="D:\projects\my-app\src"
                  value={props.sourcePath}
                  onChange={(e) => props.setSourcePath(e.target.value)}
                />
              </Field>
            </div>
            <Field label="Manifest contents">
              <textarea
                className="input font-mono h-40 resize-y"
                placeholder={'requests==2.19.0\npyyaml==5.1\nflask>=2.0'}
                value={props.manifestText}
                onChange={(e) => props.setManifestText(e.target.value)}
              />
            </Field>
          </>
        )}

        {mode === 'sample' && <SamplePicker selected={props.sample} onSelect={props.setSample} />}

        {mode === 'package' && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Field label="Package name">
              <input
                className="input font-mono"
                placeholder="requests"
                value={props.pkgName}
                onChange={(e) => props.setPkgName(e.target.value)}
              />
            </Field>
            <Field label="Version">
              <input
                className="input font-mono"
                placeholder="latest"
                value={props.pkgVersion}
                onChange={(e) => props.setPkgVersion(e.target.value)}
              />
            </Field>
            <Field label="Ecosystem">
              <select
                className="input"
                value={props.ecosystem}
                onChange={(e) => props.setEcosystem(e.target.value)}
              >
                <option value="PyPI">PyPI</option>
                <option value="npm">npm</option>
              </select>
            </Field>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          {mode === 'project' || mode === 'manifest' ? (
            <label className="flex items-center gap-2.5 text-sm text-muted-foreground cursor-pointer select-none">
              <input
                type="checkbox"
                checked={props.includeDev}
                onChange={(e) => props.setIncludeDev(e.target.checked)}
                className="h-4 w-4 rounded border-input bg-background accent-cyan-400"
              />
              Include dev dependencies
            </label>
          ) : (
            <span />
          )}

          <button type="submit" className="btn-primary min-w-[120px]" disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={14} fill="currentColor" />}
            {busy ? 'Scanning…' : 'Run scan'}
          </button>
        </div>
      </form>
    </section>
  )
}

function SamplePicker({ selected, onSelect }) {
  const [query, setQuery] = useState('')
  const [data, setData] = useState(null)

  useEffect(() => {
    const timer = setTimeout(() => {
      api.samples(query, 30).then(setData).catch(() => setData({ total: 0, samples: [] }))
    }, 200)
    return () => clearTimeout(timer)
  }, [query])

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[13px] font-medium text-foreground/80">Malware sample</span>
        <span className="text-xs text-muted-foreground">
          {data ? `${data.total} real samples · DataDog malicious-software-packages-dataset` : 'Loading…'}
        </span>
      </div>
      <div className="relative">
        <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground/60" />
        <input
          className="input pl-9 font-mono"
          placeholder="Search by name, e.g. captcha"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </div>
      <div className="max-h-56 overflow-y-auto rounded-lg border border-border divide-y divide-border">
        {(data?.samples || []).map((s) => {
          const active = selected?.name === s.name && selected?.ecosystem === s.ecosystem
          return (
            <button
              type="button"
              key={`${s.ecosystem}:${s.name}@${s.version}`}
              onClick={() => onSelect(s)}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-2 text-left transition-colors',
                active ? 'bg-red-500/[0.08]' : 'hover:bg-white/[0.03]',
              )}
            >
              <Bug size={14} className={active ? 'text-red-400' : 'text-muted-foreground/60'} />
              <span className="font-mono text-sm text-foreground/90">{s.name}</span>
              <span className="font-mono text-xs text-muted-foreground">{s.version}</span>
              <span className="ml-auto text-[11px] text-muted-foreground">{s.ecosystem}</span>
            </button>
          )
        })}
        {data && !data.samples.length && <p className="px-3 py-4 text-sm text-muted-foreground">No samples match.</p>}
      </div>
      <p className="text-xs text-muted-foreground">
        Decrypted into memory and parsed only — never executed. These samples are part of the training
        corpus, so this demonstrates the evidence pipeline on real malware rather than measuring accuracy.
      </p>
    </div>
  )
}

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="block text-[13px] font-medium text-foreground/80 mb-1.5">{label}</span>
      {children}
      {hint && <span className="block text-xs text-muted-foreground mt-1.5">{hint}</span>}
    </label>
  )
}

const STAGES = [
  { id: 'resolve', label: 'Resolve', hint: 'dependency tree' },
  { id: 'detect', label: 'Detect', hint: 'malicious code' },
  { id: 'advise', label: 'Advise', hint: 'known CVEs' },
  { id: 'reach', label: 'Reach', hint: 'call graph' },
]

function ProgressPanel({ progress }) {
  const pct = Math.round((progress?.progress || 0) * 100)
  const currentIndex = STAGES.findIndex((s) => s.id === progress?.stage)

  return (
    <section className="card p-5 animate-fade-in">
      <div className="flex items-center gap-3">
        <Loader2 size={16} className="animate-spin text-cyan-400" />
        <span className="text-sm text-foreground">{progress?.message || 'Working…'}</span>
        <span className="ml-auto text-sm text-muted-foreground tabular-nums font-mono">{pct}%</span>
      </div>

      <div className="mt-4 h-1 w-full rounded-full bg-white/[0.05] overflow-hidden">
        <div
          className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-cyan-300 transition-all duration-700 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>

      <ol className="mt-5 grid grid-cols-2 sm:grid-cols-4 gap-3">
        {STAGES.map((stage, index) => {
          const done = index < currentIndex
          const active = index === currentIndex
          return (
            <li key={stage.id} className="flex items-center gap-3">
              <span
                className={cn(
                  'grid h-7 w-7 shrink-0 place-items-center rounded-full text-xs font-medium ring-1 ring-inset transition-colors',
                  done && 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/30',
                  active && 'bg-cyan-400/10 text-cyan-300 ring-cyan-400/40',
                  !done && !active && 'bg-white/[0.02] text-muted-foreground/60 ring-white/10',
                )}
              >
                {done ? <Check size={13} strokeWidth={2.5} /> : active ? <Loader2 size={13} className="animate-spin" /> : index + 1}
              </span>
              <span className="min-w-0">
                <span className={cn('block text-[13px] font-medium', done || active ? 'text-foreground' : 'text-muted-foreground/70')}>
                  {stage.label}
                </span>
                <span className="block text-[11px] text-muted-foreground">{stage.hint}</span>
              </span>
            </li>
          )
        })}
      </ol>
    </section>
  )
}

function ScanResult({ result, onAskAI }) {
  const summary = result.summary || {}
  const flagged = (result.packages || []).filter(
    (p) => p.verdict === 'malicious' || p.verdict === 'suspicious',
  )

  return (
    <div className="space-y-6 animate-fade-in">
      {onAskAI && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-violet-300/15 bg-gradient-to-r from-violet-400/[0.07] via-transparent to-transparent px-4 py-3">
          <Sparkles size={16} className="text-violet-200 shrink-0" />
          <p className="text-sm text-foreground/85">
            Scan <span className="font-mono text-foreground">{result.scan_id}</span> complete.
            <span className="text-muted-foreground"> Ask the assistant to explain the findings or check for false positives.</span>
          </p>
          <button
            onClick={() => onAskAI(result.scan_id)}
            className="ml-auto btn h-8 px-3 text-[13px] ring-1 ring-inset ring-violet-300/25 bg-violet-400/10 text-violet-100 hover:bg-violet-400/20"
          >
            Analyse with AI
          </button>
        </div>
      )}

      <StatStrip
        items={[
          {
            title: 'Packages scanned',
            subtitle: 'Full dependency tree',
            value: summary.total_packages ?? 0,
            icon: Package,
            pill: `${summary.direct_packages ?? 0} direct`,
            hint: `max depth ${summary.max_depth ?? 0}`,
          },
          {
            title: 'Malicious',
            subtitle: 'ML classifier verdict',
            value: summary.malicious_packages ?? 0,
            tone: summary.malicious_packages ? 'danger' : 'good',
            icon: ShieldAlert,
            pill: `${summary.suspicious_packages ?? 0} suspicious`,
            hint: summary.malicious_packages ? 'review the evidence below' : 'no malicious packages found',
          },
          {
            title: 'Reachable CVEs',
            subtitle: 'Called from your code',
            value: summary.reachable_vulnerabilities ?? 0,
            tone: summary.reachable_vulnerabilities ? 'warn' : 'good',
            pill: `of ${summary.total_vulnerabilities ?? 0}`,
            hint: 'the ones that need fixing first',
          },
          {
            title: 'Scan time',
            subtitle: `Detector: ${result.model_source}`,
            value: Number((result.duration_seconds || 0).toFixed(1)),
            decimals: 1,
            suffix: 's',
            tone: 'accent',
            icon: Clock,
            hint: 'static analysis — nothing executed',
          },
        ]}
      />

      <ReachabilityHeadline summary={summary} />

      {flagged.length > 0 && <FlaggedPackages packages={flagged} />}
      <UnanalysedPackages packages={result.packages || []} />
      <VulnerabilityTable vulnerabilities={result.packages?.flatMap((p) => p.vulnerabilities || []) || []} />
      {result.remediation?.length > 0 && <RemediationPlan actions={result.remediation} />}

      {(result.warnings?.length > 0 || result.errors?.length > 0) && (
        <Card title="Scan notes" subtitle="Coverage gaps are reported, not hidden">
          <ul className="space-y-1.5 text-sm">
            {result.errors?.map((e, i) => (
              <li key={`e${i}`} className="flex gap-2 text-red-300"><span className="text-red-500">•</span>{e}</li>
            ))}
            {result.warnings?.map((w, i) => (
              <li key={`w${i}`} className="flex gap-2 text-amber-200/80"><span className="text-amber-500">•</span>{w}</li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

function ScoreMeter({ score }) {
  const value = score ?? 0
  const colour = value >= 0.6 ? 'bg-red-500' : value >= 0.3 ? 'bg-amber-500' : 'bg-emerald-500'
  return (
    <span className="flex items-center gap-2.5">
      <span className="hidden sm:block h-1.5 w-20 rounded-full bg-white/[0.06] overflow-hidden">
        <span className={cn('block h-full rounded-full', colour)} style={{ width: `${value * 100}%` }} />
      </span>
      <span className="font-mono text-sm text-foreground/90 tabular-nums">{value.toFixed(3)}</span>
    </span>
  )
}

function FlaggedPackages({ packages }) {
  const [expanded, setExpanded] = useState(packages.length === 1 ? `${packages[0].name}@${packages[0].version}` : null)

  return (
    <Card
      title="Flagged packages"
      subtitle="Scored by the classifier, with the evidence that produced the verdict"
      right={<Badge tone="CRITICAL" dot>{packages.length} flagged</Badge>}
      bodyClassName="p-0"
    >
      <div className="divide-y divide-border">
        {packages.map((pkg) => {
          const key = `${pkg.name}@${pkg.version}`
          const open = expanded === key
          return (
            <div key={key}>
              <button
                onClick={() => setExpanded(open ? null : key)}
                className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-white/[0.02] text-left transition-colors"
              >
                <ChevronRight size={15} className={cn('text-muted-foreground transition-transform', open && 'rotate-90')} />
                <span className="font-mono text-sm text-foreground">{key}</span>
                <Badge tone={pkg.verdict} dot>{pkg.verdict}</Badge>
                {pkg.typosquat_target && (
                  <span className="text-xs text-amber-400">resembles “{pkg.typosquat_target}”</span>
                )}
                <span className="ml-auto"><ScoreMeter score={pkg.malice_score} /></span>
              </button>

              {open && (
                <div className="px-5 pb-5 pt-1 space-y-5 animate-fade-in">
                  {pkg.explanation && (
                    <div className="rounded-lg border border-border bg-white/[0.02] p-4">
                      <p className="eyebrow mb-2">
                        Assessment
                        <span className="ml-2 normal-case tracking-normal text-muted-foreground/60">
                          ({pkg.explanation_source === 'llm' ? 'written by Claude' : 'generated locally'})
                        </span>
                      </p>
                      <p className="text-sm text-foreground/80 leading-relaxed">{pkg.explanation}</p>
                    </div>
                  )}

                  {pkg.exfiltration?.length > 0 && <ExfiltrationExposure flows={pkg.exfiltration} />}

                  {pkg.top_contributors?.length > 0 && (
                    <div>
                      <p className="eyebrow mb-2">Features driving this score</p>
                      <div className="flex flex-wrap gap-1.5">
                        {pkg.top_contributors.map(([name, value]) => (
                          <span
                            key={name}
                            className="inline-flex items-center gap-1.5 rounded-md bg-white/[0.04] ring-1 ring-inset ring-white/10 px-2 py-1 font-mono text-[11px] text-foreground/80"
                          >
                            {name}
                            <span className="text-cyan-300/80">{value}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div>
                    <p className="eyebrow mb-2">Evidence · {(pkg.signals || []).length} signals</p>
                    <div className="rounded-lg border border-border divide-y divide-border overflow-hidden">
                      {(pkg.signals || []).map((signal, index) => (
                        <div key={index} className="px-4 py-3 text-sm bg-white/[0.01]">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge tone={signal.severity}>{signal.severity}</Badge>
                            <span className="font-mono text-foreground/90 text-xs">{signal.code}</span>
                            {signal.occurrences > 1 && (
                              <span className="text-xs text-muted-foreground">×{signal.occurrences}</span>
                            )}
                            {signal.file && (
                              <span className="ml-auto text-xs text-muted-foreground font-mono">
                                {signal.file}{signal.line ? `:${signal.line}` : ''}
                                {signal.occurrences > 1 && ' +more'}
                              </span>
                            )}
                          </div>
                          {signal.detail && (
                            <p className="text-muted-foreground text-xs mt-1.5">{signal.detail}</p>
                          )}
                          {signal.evidence && (
                            <pre className="mt-2 text-xs bg-background border border-border rounded-md px-3 py-2 overflow-x-auto text-amber-200/80 font-mono">
                              {signal.evidence}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </Card>
  )
}

const EXPOSURE_LABELS = {
  install_time: { label: 'Runs on install', tone: 'CRITICAL' },
  import_time: { label: 'Runs on import', tone: 'HIGH' },
  call_reachable: { label: 'Reachable from your code', tone: 'HIGH' },
  call_not_reachable: { label: 'Not called by your code', tone: 'LOW' },
  unknown: { label: 'Exposure unknown', tone: 'UNKNOWN' },
}

/**
 * Confirmed credential-exfiltration data flows (analysis/dataflow.py), each with
 * its exposure verdict for this project (analysis/exposure.py).
 */
function ExfiltrationExposure({ flows }) {
  return (
    <div>
      <p className="eyebrow mb-2 flex items-center gap-1.5">
        <KeyRound size={12} /> Confirmed credential exfiltration · traced data flow
      </p>
      <div className="space-y-3">
        {flows.map((flow, i) => {
          const verdict = EXPOSURE_LABELS[flow.verdict] || EXPOSURE_LABELS.unknown
          return (
            <div key={i} className="rounded-lg border border-red-500/20 bg-red-500/[0.03] p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={verdict.tone} dot>{verdict.label}</Badge>
                <span className="font-mono text-xs text-muted-foreground">
                  {flow.file} · {flow.function_scope}
                </span>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-2 font-mono text-xs">
                <span className="rounded-md bg-white/[0.04] ring-1 ring-inset ring-white/10 px-2 py-1 text-amber-200/90">
                  L{flow.source_line} · {flow.source_evidence}
                </span>
                <ArrowRight size={14} className="text-red-400" />
                <span className="rounded-md bg-white/[0.04] ring-1 ring-inset ring-white/10 px-2 py-1 text-red-300">
                  L{flow.sink_line} · {flow.sink_target}
                </span>
              </div>
              {flow.reason && <p className="mt-3 text-xs text-muted-foreground leading-relaxed">{flow.reason}</p>}
              {flow.call_path?.length > 0 && (
                <div className="mt-3"><CallPath steps={flow.call_path} /></div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

/** A call path rendered as a vertical trace: entry point at the top, vulnerable call at the bottom. */
function CallPath({ steps }) {
  return (
    <ol className="relative rounded-lg border border-border bg-background/60 p-4">
      {steps.map((step, i) => {
        const last = i === steps.length - 1
        return (
          <li key={i} className="relative flex gap-3 pb-3 last:pb-0">
            {!last && <span className="absolute left-[9px] top-5 bottom-0 w-px bg-gradient-to-b from-white/15 to-white/5" />}
            <span
              className={cn(
                'relative z-10 mt-0.5 grid h-[19px] w-[19px] shrink-0 place-items-center rounded-full text-[10px] font-mono ring-1 ring-inset',
                last ? 'bg-red-500/15 text-red-300 ring-red-500/40' : 'bg-card text-muted-foreground ring-white/15',
              )}
            >
              {i + 1}
            </span>
            <div className="min-w-0 font-mono text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-foreground/80">{step.caller}</span>
                <ArrowRight size={12} className="text-muted-foreground/60" />
                <span className={last ? 'text-red-300 font-medium' : 'text-cyan-200/90'}>{step.callee}</span>
              </div>
              <div className="text-muted-foreground/60 mt-0.5">
                {step.file}{step.line ? `:${step.line}` : ''}
              </div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

/**
 * Packages that could not be inspected.
 *
 * These score 0.0 and would otherwise sit silently among the clean results,
 * which is the one place a false all-clear really matters: a typosquat that has
 * since been taken down from the registry lands here.
 */
function UnanalysedPackages({ packages }) {
  const unanalysed = packages.filter((p) => p.analysis_error || !p.files_analysed)
  if (!unanalysed.length) return null

  return (
    <Card
      title="Not inspected"
      subtitle="These packages could not be downloaded or contained no analysable files — they are not confirmed clean"
      right={<Badge tone="MODERATE">{unanalysed.length}</Badge>}
      bodyClassName="p-0"
    >
      <div className="divide-y divide-border">
        {unanalysed.slice(0, 15).map((pkg) => (
          <div key={`${pkg.name}@${pkg.version}`} className="flex flex-wrap items-center gap-3 px-5 py-2.5">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            <span className="font-mono text-sm text-foreground/90">{pkg.name}@{pkg.version}</span>
            <span className="text-xs text-amber-200/70">
              {pkg.analysis_error || 'No analysable files in the distribution'}
            </span>
          </div>
        ))}
      </div>
    </Card>
  )
}

function VulnerabilityTable({ vulnerabilities }) {
  const [filter, setFilter] = useState('reachable')
  const [expanded, setExpanded] = useState(null)

  const reachable = vulnerabilities.filter((v) => v.reachable)
  const unreachable = vulnerabilities.filter((v) => !v.reachable)
  const shown =
    filter === 'reachable' ? reachable : filter === 'unreachable' ? unreachable : vulnerabilities

  const sorted = [...shown].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))

  if (!vulnerabilities.length) return null

  return (
    <Card
      title="Vulnerabilities"
      subtitle="Reachable findings first — these are the ones that actually need attention"
      bodyClassName="p-0"
      right={
        <div className="inline-flex rounded-lg bg-white/[0.03] p-0.5 ring-1 ring-inset ring-white/10 text-xs">
          {[
            ['reachable', 'Reachable', reachable.length],
            ['unreachable', 'Not reachable', unreachable.length],
            ['all', 'All', vulnerabilities.length],
          ].map(([id, label, count]) => (
            <button
              key={id}
              onClick={() => setFilter(id)}
              className={cn(
                'px-2.5 py-1 rounded-md transition-colors flex items-center gap-1.5',
                filter === id ? 'bg-white/[0.08] text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
              )}
            >
              {label}
              <span className={cn('tabular-nums', filter === id ? 'text-cyan-300' : 'text-muted-foreground/60')}>{count}</span>
            </button>
          ))}
        </div>
      }
    >
      {!sorted.length ? (
        <EmptyState title={`No ${filter} vulnerabilities`} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px]">
            <thead className="border-b border-border bg-white/[0.015]">
              <tr>
                <th className="table-header w-8" />
                <th className="table-header">Advisory</th>
                <th className="table-header">Package</th>
                <th className="table-header">Severity</th>
                <th className="table-header">Reachability</th>
                <th className="table-header">Fixed in</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sorted.map((vuln, index) => {
                const key = `${vuln.id}-${vuln.package}-${index}`
                const open = expanded === key
                return (
                  <Fragment key={key}>
                    <tr
                      onClick={() => setExpanded(open ? null : key)}
                      className={cn('cursor-pointer transition-colors', open ? 'bg-white/[0.025]' : 'hover:bg-white/[0.02]')}
                    >
                      <td className="table-cell text-muted-foreground">
                        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="table-cell font-mono text-xs text-foreground">
                        {vuln.cve_id || vuln.id}
                      </td>
                      <td className="table-cell font-mono text-xs text-foreground/70">
                        {vuln.package}@{vuln.version}
                      </td>
                      <td className="table-cell">
                        <Badge tone={vuln.severity} dot>
                          {vuln.severity}{vuln.cvss_score ? ` ${vuln.cvss_score}` : ''}
                        </Badge>
                      </td>
                      <td className="table-cell">
                        {vuln.reachable ? (
                          <span className="inline-flex items-center gap-1.5 text-red-400 text-xs font-medium">
                            <span className="h-1.5 w-1.5 rounded-full bg-red-400 shadow-[0_0_8px_rgba(248,113,113,0.8)]" />
                            Reachable
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-emerald-400/90 text-xs font-medium">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/70" />
                            Not reachable
                          </span>
                        )}
                        <div className="text-[11px] text-muted-foreground mt-0.5">
                          {vuln.reachability_verdict?.replace(/_/g, ' ')}
                        </div>
                      </td>
                      <td className="table-cell font-mono text-xs text-emerald-300/80">
                        {vuln.fixed_version || <span className="text-muted-foreground">—</span>}
                      </td>
                    </tr>

                    {open && (
                      <tr className="bg-white/[0.015]">
                        <td />
                        <td colSpan={5} className="px-4 pb-5 pt-1">
                          <p className="text-sm text-foreground/80 leading-relaxed">{vuln.summary}</p>

                          <div className="mt-3 flex flex-wrap items-center gap-2">
                            <ConfidencePill level={vuln.reachability_confidence} />
                            <span className="badge ring-1 ring-inset ring-white/10 bg-white/[0.04] text-muted-foreground normal-case">
                              symbols: {vuln.symbol_confidence}
                            </span>
                          </div>

                          <p className="mt-3 text-sm text-muted-foreground">{vuln.reachability_reason}</p>

                          {vuln.call_path?.length > 0 && (
                            <div className="mt-4">
                              <p className="eyebrow mb-2">Proof — call path from an entry point</p>
                              <CallPath steps={vuln.call_path} />
                            </div>
                          )}

                          {vuln.imported_by?.length > 0 && (
                            <p className="mt-3 text-xs text-muted-foreground font-mono">
                              imported by: {vuln.imported_by.join(', ')}
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}

function RemediationPlan({ actions }) {
  return (
    <Card
      title="Remediation plan"
      subtitle="Ordered by reachable vulnerabilities fixed, not raw count"
      right={<Wrench size={15} className="text-muted-foreground" />}
      bodyClassName="p-0"
    >
      <ol className="divide-y divide-border">
        {actions.slice(0, 12).map((action, i) => (
          <li
            key={`${action.ecosystem}-${action.package}`}
            className="flex flex-wrap items-center gap-3 px-5 py-3 hover:bg-white/[0.02] transition-colors"
          >
            <span className="w-5 text-xs text-muted-foreground/60 font-mono tabular-nums">{i + 1}</span>
            <span className="font-mono text-sm text-foreground">{action.package}</span>
            <span className="font-mono text-xs text-muted-foreground flex items-center gap-1.5">
              {action.current_version}
              <ArrowRight size={12} />
              <span className="text-emerald-400">{action.target_version}</span>
            </span>
            {action.is_direct && (
              <span className="badge ring-1 ring-inset bg-cyan-400/10 text-cyan-300 ring-cyan-400/25">direct</span>
            )}
            <Badge tone={action.highest_severity}>{action.highest_severity}</Badge>
            <span className="ml-auto text-sm text-muted-foreground">
              fixes <strong className="text-foreground font-medium">{action.fixes_total}</strong>
              {action.fixes_reachable > 0 && (
                <span className="text-red-400"> · {action.fixes_reachable} reachable</span>
              )}
            </span>
          </li>
        ))}
      </ol>
    </Card>
  )
}
