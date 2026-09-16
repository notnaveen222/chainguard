/**
 * Sidebar navigation — adapted from "Dashboard Sidebar" by arunjdass on 21st.dev
 * (https://21st.dev/@arunjdass/components/dashboard-sidebar).
 *
 * Changes from the original: TSX to JSX, mock data replaced by props, the
 * workspace switcher replaced by a header slot (brand), and the bottom
 * "settings / log out" items replaced by a footer slot (backend health).
 */
import { useState } from 'react'
import { ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'

function NavItem({ item, activeId, onSelect, level = 0 }) {
  const isActive = activeId === item.id
  const hasChildren = !!item.children
  const [isOpen, setIsOpen] = useState(false)
  const Icon = item.icon

  return (
    <div className="flex flex-col w-full">
      <button
        type="button"
        className={cn(
          'group flex w-full items-center justify-between px-2.5 py-[7px] rounded-md transition-all duration-200 select-none text-left',
          isActive
            ? 'bg-white/[0.07] text-foreground font-medium shadow-[inset_0_0_0_1px_rgba(255,255,255,0.05)]'
            : 'text-muted-foreground hover:bg-white/[0.04] hover:text-foreground/90',
        )}
        style={{ paddingLeft: `${level * 12 + 10}px` }}
        onClick={() => (hasChildren ? setIsOpen(!isOpen) : onSelect(item.id))}
      >
        <span className="flex items-center gap-2.5 min-w-0">
          <Icon
            className={cn(
              'w-4 h-4 shrink-0 transition-colors',
              isActive ? 'text-cyan-400' : 'text-muted-foreground/70 group-hover:text-foreground/70',
            )}
            strokeWidth={1.75}
          />
          <span className="text-[13px] truncate">{item.title}</span>
        </span>

        <span className="flex items-center gap-2">
          {item.shortcut && (
            <kbd className="hidden group-hover:inline-flex items-center justify-center h-5 px-1.5 text-[10px] font-medium font-mono text-muted-foreground/60 bg-background/50 border border-border rounded">
              {item.shortcut}
            </kbd>
          )}
          {item.badge != null && (
            <span className="flex items-center justify-center min-w-[20px] h-5 px-1.5 text-[10px] font-medium rounded-full bg-white/[0.06] text-muted-foreground">
              {item.badge}
            </span>
          )}
          {hasChildren && (
            <ChevronRight
              className={cn(
                'w-3.5 h-3.5 text-muted-foreground/50 transition-transform duration-200',
                isOpen && 'rotate-90',
              )}
              strokeWidth={2}
            />
          )}
        </span>
      </button>

      {hasChildren && (
        <div
          className={cn(
            'grid transition-[grid-template-rows,opacity] duration-300 ease-in-out',
            isOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0',
          )}
        >
          <div className="overflow-hidden min-h-0 relative flex flex-col gap-0.5 mt-0.5">
            {item.children.map((child) => (
              <NavItem key={child.id} item={child} activeId={activeId} onSelect={onSelect} level={level + 1} />
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export function SidebarNav({ groups, activeId, onSelect, header, footer, className }) {
  return (
    <aside className={cn('flex flex-col w-[248px] h-full bg-card/40 border-r border-border p-3', className)}>
      {header}

      <nav className="flex-1 overflow-y-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden flex flex-col gap-5 mt-2">
        {groups.map((group, idx) => (
          <div key={idx} className="flex flex-col gap-0.5">
            {group.heading && (
              <span className="px-2.5 mb-1 text-[11px] font-medium tracking-wider text-muted-foreground/50 uppercase">
                {group.heading}
              </span>
            )}
            {group.items.map((item) => (
              <NavItem key={item.id} item={item} activeId={activeId} onSelect={onSelect} />
            ))}
          </div>
        ))}
      </nav>

      {footer && <div className="mt-auto pt-3 border-t border-border">{footer}</div>}
    </aside>
  )
}
