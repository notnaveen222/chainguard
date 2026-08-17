import { useState } from 'react'
import {
  ChevronDown,
  ChevronRight,
  FileCode2,
  FolderSearch,
  Loader2,
  Package,
  PlayCircle,
  ShieldAlert,
  Wrench,
} from 'lucide-react'

import { api, pollScan } from '../api'
import {
  Badge,
  Card,
  ConfidencePill,
  EmptyState,
  ErrorBanner,
  ReachabilityHeadline,
  Stat,
} from '../ui'

const MODES = [
  { id: 'project', label: 'Project directory', icon: FolderSearch,
    hint: 'Scans dependencies AND analyses your source for reachability' },
  { id: 'manifest', label: 'Paste a manifest', icon: FileCode2,
    hint: 'package.json or requirements.txt' },
  { id: 'package', label: 'Single package', icon: Package,
    hint: 'Analyse one package in isolation' },
]

export default function ScanPage({ onScanComplete }) {
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
        }}
      />

      <ErrorBanner message={error} onDismiss={() => setError(null)} />
      {busy && <ProgressPanel progress={progress} />}
      {result && <ScanResult result={result} />}
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
    <Card title="New scan" subtitle="Analyse a dependency tree for malicious packages and reachable vulnerabilities">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
        {MODES.map(({ id, label, icon: Icon, hint }) => (
          <button
            key={id}
            type="button"
            onClick={() => setMode(id)}
            className={`text-left p-3 rounded-lg border transition-colors ${
              mode === id
                ? 'border-cyan-600 bg-cyan-950/40'
                : 'border-ink-800 bg-ink-950 hover:border-ink-700'
            }`}
          >
            <div className="flex items-center gap-2 font-medium text-ink-100 text-sm">
              <Icon size={16} className={mode === id ? 'text-cyan-400' : 'text-ink-400'} />
              {label}
            </div>
            <p className="text-xs text-ink-500 mt-1 leading-snug">{hint}</p>
          </button>
        ))}
      </div>

      <form onSubmit={submit} className="space-y-4">
        {mode === 'project' && (
          <Field
            label="Project directory"
            hint="Absolute path. Its manifest is discovered automatically and its source is used for reachability analysis."
          >
            <input
              className="input font-mono"
              placeholder="D:\projects\my-app"
              value={props.projectPath}
              onChange={(e) => props.setProjectPath(e.target.value)}
            />
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

        <div className="flex items-center justify-between pt-1">
          {mode !== 'package' ? (
            <label className="flex items-center gap-2 text-sm text-ink-400 cursor-pointer">
              <input
                type="checkbox"
                checked={props.includeDev}
                onChange={(e) => props.setIncludeDev(e.target.checked)}
                className="rounded border-ink-700 bg-ink-950 text-cyan-600 focus:ring-cyan-600"
              />
              Include dev dependencies
            </label>
          ) : (
            <span />
          )}

          <button type="submit" className="btn-primary" disabled={busy}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <PlayCircle size={16} />}
            {busy ? 'Scanning…' : 'Run scan'}
          </button>
        </div>
      </form>
    </Card>
  )
}

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="block text-sm font-medium text-ink-300 mb-1.5">{label}</span>
      {children}
      {hint && <span className="block text-xs text-ink-500 mt-1.5">{hint}</span>}
    </label>
  )
}

function ProgressPanel({ progress }) {
  const pct = Math.round((progress?.progress || 0) * 100)
  const stages = ['resolve', 'detect', 'advise', 'reach']
  const currentIndex = stages.indexOf(progress?.stage)

  return (
    <Card>
      <div className="flex items-center gap-3 mb-4">
        <Loader2 size={18} className="animate-spin text-cyan-400" />
        <span className="text-ink-200">{progress?.message || 'Working…'}</span>
        <span className="ml-auto text-sm text-ink-400 tabular-nums">{pct}%</span>
      </div>

      <div className="h-2 w-full rounded-full bg-ink-800 overflow-hidden">
        <div
          className="h-full bg-cyan-500 transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-4 grid grid-cols-4 gap-2 text-xs">
        {stages.map((stage, index) => (
          <div
            key={stage}
            className={`rounded px-2 py-1.5 text-center capitalize border ${
              index < currentIndex
                ? 'border-emerald-800 bg-emerald-950/50 text-emerald-300'
                : index === currentIndex
                  ? 'border-cyan-700 bg-cyan-950/50 text-cyan-300'
                  : 'border-ink-800 bg-ink-950 text-ink-600'
            }`}
          >
            {stage}
          </div>
        ))}
      </div>
    </Card>
  )
}

function ScanResult({ result }) {
  const summary = result.summary || {}
  const flagged = (result.packages || []).filter(
    (p) => p.verdict === 'malicious' || p.verdict === 'suspicious',
  )

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat
          label="Packages scanned"
          value={summary.total_packages ?? 0}
          hint={`${summary.direct_packages ?? 0} direct · depth ${summary.max_depth ?? 0}`}
          icon={Package}
        />
        <Stat
          label="Malicious"
          value={summary.malicious_packages ?? 0}
          tone={summary.malicious_packages ? 'danger' : 'good'}
          hint={`${summary.suspicious_packages ?? 0} suspicious`}
          icon={ShieldAlert}
        />
        <Stat
          label="Reachable CVEs"
          value={summary.reachable_vulnerabilities ?? 0}
          tone={summary.reachable_vulnerabilities ? 'warn' : 'good'}
          hint={`of ${summary.total_vulnerabilities ?? 0} reported`}
        />
        <Stat
          label="Scan time"
          value={`${(result.duration_seconds || 0).toFixed(1)}s`}
          tone="accent"
          hint={`detector: ${result.model_source}`}
        />
      </div>

      <ReachabilityHeadline summary={summary} />

      {flagged.length > 0 && <FlaggedPackages packages={flagged} />}
      <VulnerabilityTable vulnerabilities={result.packages?.flatMap((p) => p.vulnerabilities || []) || []} />
      {result.remediation?.length > 0 && <RemediationPlan actions={result.remediation} />}

      {(result.warnings?.length > 0 || result.errors?.length > 0) && (
        <Card title="Scan notes" subtitle="Coverage gaps are reported, not hidden">
          <ul className="space-y-1.5 text-sm">
            {result.errors?.map((e, i) => (
              <li key={`e${i}`} className="text-red-300">• {e}</li>
            ))}
            {result.warnings?.map((w, i) => (
              <li key={`w${i}`} className="text-amber-300/90">• {w}</li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  )
}

function FlaggedPackages({ packages }) {
  const [expanded, setExpanded] = useState(null)

  return (
    <Card
      title="Flagged packages"
      subtitle="Scored by the classifier, with the evidence that produced the verdict"
      right={<Badge tone="CRITICAL">{packages.length} flagged</Badge>}
    >
      <div className="space-y-3">
        {packages.map((pkg) => {
          const key = `${pkg.name}@${pkg.version}`
          const open = expanded === key
          return (
            <div key={key} className="border border-ink-800 rounded-lg overflow-hidden">
              <button
                onClick={() => setExpanded(open ? null : key)}
                className="w-full flex items-center gap-3 px-4 py-3 hover:bg-ink-800/40 text-left"
              >
                {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                <span className="font-mono text-sm text-ink-100">{key}</span>
                <Badge tone={pkg.verdict}>{pkg.verdict}</Badge>
                {pkg.typosquat_target && (
                  <span className="text-xs text-amber-400">
                    resembles “{pkg.typosquat_target}”
                  </span>
                )}
                <span className="ml-auto font-mono text-sm text-ink-300 tabular-nums">
                  {(pkg.malice_score ?? 0).toFixed(3)}
                </span>
              </button>

              {open && (
                <div className="px-4 pb-4 pt-1 border-t border-ink-800 bg-ink-950/60">
                  {pkg.top_contributors?.length > 0 && (
                    <div className="mb-3">
                      <p className="text-xs uppercase tracking-wide text-ink-500 mb-1.5">
                        Features driving this score
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {pkg.top_contributors.map(([name, value]) => (
                          <span key={name} className="badge bg-ink-800 text-ink-300 border border-ink-700 font-mono normal-case">
                            {name} · {value}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <p className="text-xs uppercase tracking-wide text-ink-500 mb-2">Evidence</p>
                  <div className="space-y-2">
                    {(pkg.signals || []).map((signal, index) => (
                      <div key={index} className="text-sm">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge tone={signal.severity}>{signal.severity}</Badge>
                          <span className="font-mono text-ink-200 text-xs">{signal.code}</span>
                          {signal.file && (
                            <span className="text-xs text-ink-500 font-mono">
                              {signal.file}{signal.line ? `:${signal.line}` : ''}
                            </span>
                          )}
                        </div>
                        {signal.detail && (
                          <p className="text-ink-400 text-xs mt-1 ml-1">{signal.detail}</p>
                        )}
                        {signal.evidence && (
                          <pre className="mt-1 ml-1 text-xs bg-ink-950 border border-ink-800 rounded px-2 py-1 overflow-x-auto text-amber-200/80">
                            {signal.evidence}
                          </pre>
                        )}
                      </div>
                    ))}
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
      right={
        <div className="flex gap-1 text-xs">
          {[
            ['reachable', `Reachable (${reachable.length})`],
            ['unreachable', `Not reachable (${unreachable.length})`],
            ['all', `All (${vulnerabilities.length})`],
          ].map(([id, label]) => (
            <button
              key={id}
              onClick={() => setFilter(id)}
              className={`px-2.5 py-1 rounded border transition-colors ${
                filter === id
                  ? 'border-cyan-700 bg-cyan-950/60 text-cyan-300'
                  : 'border-ink-800 text-ink-400 hover:border-ink-700'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      }
    >
      {!sorted.length ? (
        <EmptyState title={`No ${filter} vulnerabilities`} />
      ) : (
        <div className="overflow-x-auto -mx-5">
          <table className="w-full min-w-[720px]">
            <thead className="border-b border-ink-800">
              <tr>
                <th className="table-header w-8" />
                <th className="table-header">Advisory</th>
                <th className="table-header">Package</th>
                <th className="table-header">Severity</th>
                <th className="table-header">Reachability</th>
                <th className="table-header">Fixed in</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-800/70">
              {sorted.map((vuln, index) => {
                const key = `${vuln.id}-${vuln.package}-${index}`
                const open = expanded === key
                return (
                  <>
                    <tr
                      key={key}
                      onClick={() => setExpanded(open ? null : key)}
                      className="hover:bg-ink-800/30 cursor-pointer"
                    >
                      <td className="table-cell text-ink-500">
                        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                      </td>
                      <td className="table-cell font-mono text-xs text-ink-200">
                        {vuln.cve_id || vuln.id}
                      </td>
                      <td className="table-cell font-mono text-xs text-ink-300">
                        {vuln.package}@{vuln.version}
                      </td>
                      <td className="table-cell">
                        <Badge tone={vuln.severity}>
                          {vuln.severity}{vuln.cvss_score ? ` ${vuln.cvss_score}` : ''}
                        </Badge>
                      </td>
                      <td className="table-cell">
                        {vuln.reachable ? (
                          <span className="text-red-400 text-xs font-semibold">REACHABLE</span>
                        ) : (
                          <span className="text-emerald-400 text-xs font-semibold">not reachable</span>
                        )}
                        <div className="text-[11px] text-ink-500 mt-0.5">
                          {vuln.reachability_verdict?.replace(/_/g, ' ')}
                        </div>
                      </td>
                      <td className="table-cell font-mono text-xs text-ink-300">
                        {vuln.fixed_version || '—'}
                      </td>
                    </tr>

                    {open && (
                      <tr key={`${key}-detail`} className="bg-ink-950/70">
                        <td />
                        <td colSpan={5} className="px-4 pb-4 pt-1">
                          <p className="text-sm text-ink-300">{vuln.summary}</p>

                          <div className="mt-3 flex flex-wrap items-center gap-2">
                            <ConfidencePill level={vuln.reachability_confidence} />
                            <span className="badge bg-ink-800 text-ink-400 border border-ink-700 normal-case">
                              symbols: {vuln.symbol_confidence}
                            </span>
                          </div>

                          <p className="mt-2 text-sm text-ink-400">{vuln.reachability_reason}</p>

                          {vuln.call_path?.length > 0 && (
                            <div className="mt-3">
                              <p className="text-xs uppercase tracking-wide text-ink-500 mb-1.5">
                                Proof — call path from an entry point
                              </p>
                              <div className="rounded-lg border border-red-900/60 bg-red-950/20 p-3 space-y-1">
                                {vuln.call_path.map((step, i) => (
                                  <div key={i} className="font-mono text-xs flex flex-wrap items-center gap-2">
                                    <span className="text-ink-500 w-4">{i + 1}.</span>
                                    <span className="text-ink-200">{step.caller}</span>
                                    <span className="text-red-400">→</span>
                                    <span className="text-amber-300">{step.callee}</span>
                                    <span className="text-ink-600">
                                      {step.file}{step.line ? `:${step.line}` : ''}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {vuln.imported_by?.length > 0 && (
                            <p className="mt-3 text-xs text-ink-500 font-mono">
                              imported by: {vuln.imported_by.join(', ')}
                            </p>
                          )}
                        </td>
                      </tr>
                    )}
                  </>
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
      right={<Wrench size={16} className="text-ink-400" />}
    >
      <div className="space-y-2">
        {actions.slice(0, 12).map((action) => (
          <div
            key={`${action.ecosystem}-${action.package}`}
            className="flex flex-wrap items-center gap-3 px-4 py-3 rounded-lg border border-ink-800 bg-ink-950/50"
          >
            <span className="font-mono text-sm text-ink-100">{action.package}</span>
            <span className="font-mono text-xs text-ink-500">
              {action.current_version} → <span className="text-emerald-400">{action.target_version}</span>
            </span>
            {action.is_direct && (
              <span className="badge bg-cyan-950 text-cyan-300 border border-cyan-800">direct</span>
            )}
            <Badge tone={action.highest_severity}>{action.highest_severity}</Badge>
            <span className="ml-auto text-sm text-ink-300">
              fixes <strong className="text-ink-100">{action.fixes_total}</strong>
              {action.fixes_reachable > 0 && (
                <span className="text-red-400"> ({action.fixes_reachable} reachable)</span>
              )}
            </span>
          </div>
        ))}
      </div>
    </Card>
  )
}
