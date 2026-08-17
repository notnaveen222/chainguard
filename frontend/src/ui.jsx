/**
 * Shared presentation primitives.
 *
 * Severity and verdict styling lives here rather than being repeated per table,
 * so a "critical" finding looks identical everywhere it appears. Getting that
 * inconsistent across views is how a dashboard stops being readable at a glance.
 */

import { AlertTriangle, CheckCircle2, Info, ShieldAlert, ShieldCheck } from 'lucide-react'

export const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-950 text-red-300 border-red-800',
  HIGH: 'bg-orange-950 text-orange-300 border-orange-800',
  MODERATE: 'bg-amber-950 text-amber-300 border-amber-800',
  MEDIUM: 'bg-amber-950 text-amber-300 border-amber-800',
  LOW: 'bg-cyan-950 text-cyan-300 border-cyan-800',
  INFO: 'bg-ink-800 text-ink-400 border-ink-700',
  UNKNOWN: 'bg-ink-800 text-ink-400 border-ink-700',
}

export const VERDICT_STYLES = {
  malicious: 'bg-red-950 text-red-300 border-red-800',
  suspicious: 'bg-amber-950 text-amber-300 border-amber-800',
  benign: 'bg-emerald-950 text-emerald-300 border-emerald-800',
}

export function Badge({ children, tone = 'UNKNOWN', className = '' }) {
  const style = SEVERITY_STYLES[tone?.toUpperCase?.()] || VERDICT_STYLES[tone] || SEVERITY_STYLES.UNKNOWN
  return <span className={`badge border ${style} ${className}`}>{children}</span>
}

export function Card({ title, subtitle, right, children, className = '' }) {
  return (
    <section className={`card ${className}`}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-4 px-5 py-4 border-b border-ink-800">
          <div>
            {title && <h2 className="font-semibold text-ink-100">{title}</h2>}
            {subtitle && <p className="text-sm text-ink-400 mt-0.5">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint, tone = 'default', icon: Icon }) {
  const tones = {
    default: 'text-ink-100',
    danger: 'text-red-400',
    warn: 'text-amber-400',
    good: 'text-emerald-400',
    accent: 'text-cyan-400',
  }
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 text-ink-400 text-sm">
        {Icon && <Icon size={15} />}
        <span>{label}</span>
      </div>
      <div className={`mt-2 text-3xl font-bold tabular-nums ${tones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-xs text-ink-500">{hint}</div>}
    </div>
  )
}

export function EmptyState({ icon: Icon = Info, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 text-center">
      <Icon size={34} className="text-ink-600 mb-3" />
      <p className="text-ink-300 font-medium">{title}</p>
      {children && <p className="text-sm text-ink-500 mt-1 max-w-md">{children}</p>}
    </div>
  )
}

export function ErrorBanner({ message, onDismiss }) {
  if (!message) return null
  return (
    <div className="flex items-start gap-3 rounded-lg border border-red-800 bg-red-950/60 px-4 py-3">
      <AlertTriangle size={18} className="text-red-400 shrink-0 mt-0.5" />
      <p className="text-sm text-red-200 flex-1">{message}</p>
      {onDismiss && (
        <button onClick={onDismiss} className="text-red-400 hover:text-red-200 text-sm">
          dismiss
        </button>
      )}
    </div>
  )
}

/**
 * The project's headline metric, given deliberate visual weight: how many
 * reported advisories reachability analysis ruled out.
 */
export function ReachabilityHeadline({ summary }) {
  const total = summary?.total_vulnerabilities || 0
  const reachable = summary?.reachable_vulnerabilities || 0
  const unreachable = summary?.unreachable_vulnerabilities || 0
  const pct = total ? Math.round((unreachable / total) * 100) : 0

  if (!total) {
    return (
      <div className="card p-6 flex items-center gap-3">
        <ShieldCheck className="text-emerald-400" size={22} />
        <p className="text-ink-200">No known vulnerabilities were found in this dependency tree.</p>
      </div>
    )
  }

  return (
    <div className="card p-6 bg-gradient-to-br from-ink-900 to-ink-950 border-cyan-900/60">
      <div className="flex items-center gap-2 text-cyan-400 text-sm font-medium">
        <ShieldAlert size={16} />
        Vulnerability reachability
      </div>

      <div className="mt-4 flex flex-wrap items-end gap-x-8 gap-y-4">
        <div>
          <div className="text-4xl font-bold text-ink-100 tabular-nums">{total}</div>
          <div className="text-sm text-ink-400 mt-1">advisories reported</div>
        </div>
        <div className="text-3xl text-ink-600 pb-2">&rarr;</div>
        <div>
          <div className="text-4xl font-bold text-red-400 tabular-nums">{reachable}</div>
          <div className="text-sm text-ink-400 mt-1">actually reachable</div>
        </div>
        <div className="ml-auto text-right">
          <div className="text-4xl font-bold text-emerald-400 tabular-nums">{pct}%</div>
          <div className="text-sm text-ink-400 mt-1">ruled out as unreachable</div>
        </div>
      </div>

      <div className="mt-5 h-2.5 w-full rounded-full bg-ink-800 overflow-hidden flex">
        <div
          className="bg-red-600 h-full transition-all"
          style={{ width: `${total ? (reachable / total) * 100 : 0}%` }}
        />
        <div
          className="bg-emerald-700 h-full transition-all"
          style={{ width: `${total ? (unreachable / total) * 100 : 0}%` }}
        />
      </div>
      <p className="mt-3 text-xs text-ink-500">
        Unreachable findings are not dismissed — they are de-prioritised, and the reason is
        recorded for each one.
      </p>
    </div>
  )
}

export function ConfidencePill({ level }) {
  const styles = {
    high: 'bg-emerald-950 text-emerald-300 border-emerald-800',
    medium: 'bg-amber-950 text-amber-300 border-amber-800',
    low: 'bg-orange-950 text-orange-300 border-orange-800',
    none: 'bg-ink-800 text-ink-400 border-ink-700',
  }
  return (
    <span className={`badge border ${styles[level] || styles.none}`} title="Confidence in this verdict">
      {level || 'none'} confidence
    </span>
  )
}

export function CheckIcon() {
  return <CheckCircle2 size={15} className="text-emerald-400" />
}
