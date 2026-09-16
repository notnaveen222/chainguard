/**
 * Border Beam — Magic UI (magicui.design, MIT), converted from TSX to JSX and
 * from Tailwind v4 syntax to v3 (inline styles for the mask and gradient).
 * A light that travels around the border of its (relative, rounded) parent.
 */
import { motion } from 'motion/react'

import { cn } from '@/lib/utils'

export function BorderBeam({
  className,
  size = 80,
  delay = 0,
  duration = 8,
  colorFrom = '#22d3ee',
  colorTo = '#a78bfa',
  borderWidth = 1,
  reverse = false,
  initialOffset = 0,
}) {
  const mask = 'linear-gradient(transparent, transparent), linear-gradient(#000, #000)'
  return (
    <div
      className="pointer-events-none absolute inset-0 rounded-[inherit] border-transparent"
      style={{
        borderWidth,
        borderStyle: 'solid',
        WebkitMask: mask,
        mask,
        WebkitMaskClip: 'padding-box, border-box',
        maskClip: 'padding-box, border-box',
        WebkitMaskComposite: 'source-in, xor',
        maskComposite: 'intersect',
      }}
    >
      <motion.div
        className={cn('absolute aspect-square', className)}
        style={{
          width: size,
          offsetPath: `rect(0 auto auto 0 round ${size}px)`,
          background: `linear-gradient(to left, ${colorFrom}, ${colorTo}, transparent)`,
        }}
        initial={{ offsetDistance: `${initialOffset}%` }}
        animate={{
          offsetDistance: reverse
            ? [`${100 - initialOffset}%`, `${-initialOffset}%`]
            : [`${initialOffset}%`, `${100 + initialOffset}%`],
        }}
        transition={{ repeat: Infinity, ease: 'linear', duration, delay: -delay }}
      />
    </div>
  )
}
