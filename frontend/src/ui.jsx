/**
 * Shared presentation primitives.
 *
 * Severity and verdict styling lives here rather than being repeated per table,
 * so a "critical" finding looks identical everywhere it appears. Getting that
 * inconsistent across views is how a dashboard stops being readable at a glance.
 */

import { AlertTriangle, CheckCircle2, Info, ShieldCheck, X } from 'lucide-react'

import { BorderBeam } from '@/components/ui/border-beam'
import { NumberTicker } from '@/components/ui/number-ticker'
import { cn } from '@/lib/utils'

export const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-500/10 text-red-400 ring-red-500/25',
  HIGH: 'bg-orange-500/10 text-orange-400 ring-orange-500/25',
  MODERATE: 'bg-amber-500/10 text-amber-400 ring-amber-500/25',
  MEDIUM: 'bg-amber-500/10 text-amber-400 ring-amber-500/25',
  LOW: 'bg-sky-500/10 text-sky-400 ring-sky-500/25',
  INFO: 'bg-white/[0.05] text-muted-foreground ring-white/10',
  UNKNOWN: 'bg-white/[0.05] text-muted-foreground ring-white/10',
}

export const VERDICT_STYLES = {
  malicious: 'bg-red-500/10 text-red-400 ring-red-500/25',
  suspicious: 'bg-amber-500/10 text-amber-400 ring-amber-500/25',
  benign: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/25',
}

const DOT_STYLES = {
  CRITICAL: 'bg-red-400', HIGH: 'bg-orange-400', MODERATE: 'bg-amber-400', MEDIUM: 'bg-amber-400',
  LOW: 'bg-sky-400', malicious: 'bg-red-400', suspicious: 'bg-amber-400', benign: 'bg-emerald-400',
}

export function Badge({ children, tone = 'UNKNOWN', className = '', dot = false }) {
  const key = tone?.toUpperCase?.()
  const style = SEVERITY_STYLES[key] || VERDICT_STYLES[tone] || SEVERITY_STYLES.UNKNOWN
  const dotStyle = DOT_STYLES[key] || DOT_STYLES[tone]
  return (
    <span className={cn('badge ring-1 ring-inset', style, className)}>
      {dot && dotStyle && <span className={cn('h-1.5 w-1.5 rounded-full', dotStyle)} />}
      {children}
    </span>
  )
}

export function Card({ title, subtitle, right, children, className = '', bodyClassName = '' }) {
  return (
    <section className={cn('card', className)}>
      {(title || right) && (
        <header className="flex items-start justify-between gap-4 px-5 pt-4 pb-3.5 border-b border-border">
          <div className="min-w-0">
            {title && <h2 className="text-[15px] font-semibold tracking-tight text-foreground">{title}</h2>}
            {subtitle && <p className="text-[13px] text-muted-foreground mt-0.5">{subtitle}</p>}
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </header>
      )}
      <div className={cn('p-5', bodyClassName)}>{children}</div>
    </section>
  )
}

export function Stat({ label, value, hint, tone = 'default', icon: Icon }) {
  const tones = {
    default: 'text-foreground',
    danger: 'text-red-400',
    warn: 'text-amber-400',
    good: 'text-emerald-400',
    accent: 'text-cyan-300',
  }
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between text-muted-foreground text-[13px]">
        <span>{label}</span>
        {Icon && <Icon size={15} strokeWidth={1.75} className="opacity-60" />}
      </div>
      <div className={cn('mt-3 text-3xl font-semibold tracking-tight tabular-nums', tones[tone])}>{value}</div>
      {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}

export function EmptyState({ icon: Icon = Info, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center">
      <div className="mb-4 grid h-11 w-11 place-items-center rounded-xl border border-border bg-white/[0.03]">
        <Icon size={20} strokeWidth={1.75} className="text-muted-foreground" />
      </div>
      <p className="text-foreground font-medium">{title}</p>
      {children && <p className="text-sm text-muted-foreground mt-1.5 max-w-md leading-relaxed">{children}</p>}
    </div>
  )
}

export function ErrorBanner({ message, onDismiss }) {
  if (!message) return null
  return (
    <div className="flex items-start gap-3 rounded-xl border border-red-500/25 bg-red-500/[0.06] px-4 py-3 animate-fade-in">
      <AlertTriangle size={17} className="text-red-400 shrink-0 mt-0.5" />
      <p className="text-sm text-red-200 flex-1">{message}</p>
      {onDismiss && (
        <button onClick={onDismiss} className="text-red-400/70 hover:text-red-300" aria-label="Dismiss">
          <X size={16} />
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
      <div className="card p-5 flex items-center gap-3">
        <ShieldCheck className="text-emerald-400" size={20} />
        <p className="text-foreground/90 text-sm">No known vulnerabilities were found in this dependency tree.</p>
      </div>
    )
  }

  return (
    <div className="relative overflow-hidden rounded-xl border border-border bg-card">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_120%_at_0%_0%,rgba(34,211,238,0.08),transparent_60%)]" />
      <BorderBeam size={120} duration={10} />

      <div className="relative p-6">
        <div className="flex items-center justify-between gap-4">
          <div className="eyebrow text-cyan-300/80">Vulnerability reachability</div>
          <span className="text-xs text-muted-foreground">call-graph verified</span>
        </div>

        <div className="mt-5 grid grid-cols-1 sm:grid-cols-[auto_auto_auto_1fr] items-end gap-x-8 gap-y-4">
          <div>
            <div className="text-5xl font-semibold tracking-tight text-foreground">
              <NumberTicker value={total} />
            </div>
            <div className="text-[13px] text-muted-foreground mt-1.5">advisories reported</div>
          </div>
          <svg className="hidden sm:block mb-7 text-muted-foreground/40" width="40" height="12" viewBox="0 0 40 12" fill="none">
            <path d="M0 6h37m0 0-5-5m5 5-5 5" stroke="currentColor" strokeWidth="1.5" />
          </svg>
          <div>
            <div className="text-5xl font-semibold tracking-tight text-red-400">
              <NumberTicker value={reachable} />
            </div>
            <div className="text-[13px] text-muted-foreground mt-1.5">actually reachable</div>
          </div>
          <div className="sm:text-right">
            <div className="text-5xl font-semibold tracking-tight text-emerald-400">
              <NumberTicker value={pct} suffix="%" />
            </div>
            <div className="text-[13px] text-muted-foreground mt-1.5">noise ruled out</div>
          </div>
        </div>

        <div className="mt-6 h-2 w-full rounded-full bg-white/[0.05] overflow-hidden flex gap-0.5">
          <div
            className="bg-red-500 h-full rounded-full transition-all duration-1000"
            style={{ width: `${(reachable / total) * 100}%`, minWidth: reachable ? 6 : 0 }}
          />
          <div
            className="bg-emerald-500/60 h-full rounded-full transition-all duration-1000"
            style={{ width: `${(unreachable / total) * 100}%` }}
          />
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-red-500" />reachable from your code</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-emerald-500/60" />present but never called</span>
          <span className="sm:ml-auto">Unreachable findings are de-prioritised, not dismissed — each keeps its reason.</span>
        </div>
      </div>
    </div>
  )
}

export function ConfidencePill({ level }) {
  const styles = {
    high: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/25',
    medium: 'bg-amber-500/10 text-amber-400 ring-amber-500/25',
    low: 'bg-orange-500/10 text-orange-400 ring-orange-500/25',
    none: 'bg-white/[0.05] text-muted-foreground ring-white/10',
  }
  return (
    <span className={cn('badge ring-1 ring-inset', styles[level] || styles.none)} title="Confidence in this verdict">
      {level || 'none'} confidence
    </span>
  )
}

export function CheckIcon() {
  return <CheckCircle2 size={15} className="text-emerald-400" />
}
