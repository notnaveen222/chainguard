/**
 * Joined statistics strip — adapted from "Statistics Card 7" by sean0205 on
 * 21st.dev (https://21st.dev/@sean0205/components/statistics-card-7).
 *
 * Changes from the original: TSX to JSX, data passed as props, @container
 * queries replaced by plain responsive breakpoints (Tailwind v3), and numeric
 * values animated with NumberTicker.
 */
import { cn } from '@/lib/utils'
import { NumberTicker } from './number-ticker'

const TONES = {
  default: { value: 'text-foreground', pill: 'bg-white/[0.06] text-muted-foreground ring-white/10' },
  danger: { value: 'text-red-400', pill: 'bg-red-500/10 text-red-400 ring-red-500/20' },
  warn: { value: 'text-amber-400', pill: 'bg-amber-500/10 text-amber-400 ring-amber-500/20' },
  good: { value: 'text-emerald-400', pill: 'bg-emerald-500/10 text-emerald-400 ring-emerald-500/20' },
  accent: { value: 'text-cyan-300', pill: 'bg-cyan-500/10 text-cyan-300 ring-cyan-500/20' },
}

export function StatStrip({ items, className }) {
  return (
    <div
      className={cn(
        'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-px bg-border overflow-hidden rounded-xl border border-border',
        className,
      )}
    >
      {items.map((item, i) => {
        const tone = TONES[item.tone] || TONES.default
        const Icon = item.icon
        return (
          <div key={i} className="flex flex-col justify-between gap-5 p-5 bg-card">
            <div className="flex items-start justify-between gap-2">
              <div>
                <div className="text-sm font-medium text-foreground/90">{item.title}</div>
                {item.subtitle && <div className="text-xs text-muted-foreground mt-0.5">{item.subtitle}</div>}
              </div>
              {Icon && <Icon className="w-4 h-4 text-muted-foreground/60" strokeWidth={1.75} />}
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={cn('text-3xl font-semibold tracking-tight tabular-nums', tone.value)}>
                  {typeof item.value === 'number' ? (
                    <NumberTicker value={item.value} decimalPlaces={item.decimals || 0} suffix={item.suffix || ''} />
                  ) : (
                    item.value
                  )}
                </span>
                {item.pill && (
                  <span
                    className={cn(
                      'inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ring-1 ring-inset',
                      tone.pill,
                    )}
                  >
                    {item.pill}
                  </span>
                )}
              </div>
              {item.hint && <div className="text-xs text-muted-foreground">{item.hint}</div>}
            </div>
          </div>
        )
      })}
    </div>
  )
}
