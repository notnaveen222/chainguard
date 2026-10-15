import { useState } from 'react'
import { ArrowRight, Fingerprint, Loader2, Play, ShieldAlert, ShieldCheck } from 'lucide-react'

import { api } from '../api'
import { cn } from '@/lib/utils'
import { Badge, Card, EmptyState, ErrorBanner } from '../ui'

const STATUS_STYLES = {
  added: 'text-emerald-300 bg-emerald-400/10',
  removed: 'text-red-300 bg-red-400/10',
  modified: 'text-amber-300 bg-amber-400/10',
}

const short = (hash) => (hash ? `${hash.slice(0, 12)}…${hash.slice(-6)}` : '—')
const kb = (bytes) => `${(bytes / 1024).toFixed(1)} KB`

/**
 * Did an upgrade actually change anything? Compares two versions of a package by
 * SHA-256: the whole archive first, then each file inside it.
 */
export default function DiffPage() {
  const [ecosystem, setEcosystem] = useState('PyPI')
  const [name, setName] = useState('requests')
  const [oldVersion, setOldVersion] = useState('2.31.0')
  const [newVersion, setNewVersion] = useState('2.32.0')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [diff, setDiff] = useState(null)

  const run = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setDiff(null)
    try {
      setDiff(await api.diffVersions(name.trim(), oldVersion.trim(), newVersion.trim(), ecosystem))
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const input = 'h-9 rounded-md border border-border bg-white/[0.02] px-3 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-cyan-300/40'

  return (
    <div className="space-y-6">
      <Card
        title="Compare two versions by SHA-256"
        subtitle="Hash the whole archive first; if it differs, hash every file inside to see what changed"
      >
        <form onSubmit={run} className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-muted-foreground">
            Ecosystem
            <select value={ecosystem} onChange={(e) => setEcosystem(e.target.value)} className={cn(input, 'mt-1 block')}>
              <option value="PyPI">PyPI</option>
              <option value="npm">npm</option>
            </select>
          </label>
          <label className="text-xs text-muted-foreground">
            Package
            <input value={name} onChange={(e) => setName(e.target.value)} className={cn(input, 'mt-1 block w-48')} required />
          </label>
          <label className="text-xs text-muted-foreground">
            Current version
            <input value={oldVersion} onChange={(e) => setOldVersion(e.target.value)} className={cn(input, 'mt-1 block w-32')} required />
          </label>
          <ArrowRight size={16} className="mb-2.5 text-muted-foreground" />
          <label className="text-xs text-muted-foreground">
            Upgrade to
            <input value={newVersion} onChange={(e) => setNewVersion(e.target.value)} className={cn(input, 'mt-1 block w-32')} required />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="ml-auto inline-flex h-9 items-center gap-2 rounded-lg bg-foreground px-4 text-sm font-medium text-background disabled:opacity-50"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            Compare
          </button>
        </form>
        <p className="mt-3 text-xs text-muted-foreground">
          Exact versions only. Packages are downloaded into memory, hashed and compared; nothing is executed or written to disk.
        </p>
      </Card>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {!diff && !busy && !error && (
        <EmptyState icon={Fingerprint} title="No comparison yet">
          Enter a package and two versions to see whether the upgrade really changed anything.
        </EmptyState>
      )}

      {diff && <DiffResult diff={diff} />}
    </div>
  )
}

function DiffResult({ diff }) {
  const verdict = diff.identical
    ? { tone: 'benign', text: 'Identical: the two archives have the same SHA-256, so the upgrade changed nothing.' }
    : diff.archive_only_change
      ? { tone: 'suspicious', text: 'Archives differ, but no analysed file changed.' }
      : { tone: 'suspicious', text: `${diff.changes.length} file${diff.changes.length === 1 ? '' : 's'} changed between versions.` }

  return (
    <div className="space-y-6 animate-fade-in">
      <Card
        title={`${diff.name}: ${diff.old.version} → ${diff.new.version}`}
        subtitle={verdict.text}
        right={<Badge tone={verdict.tone} dot>{diff.identical ? 'identical' : 'different'}</Badge>}
      >
        <div className="grid gap-3 md:grid-cols-2">
          {[['Current', diff.old], ['Upgrade', diff.new]].map(([label, side]) => (
            <div key={label} className="rounded-lg border border-border bg-white/[0.02] p-4">
              <p className="eyebrow mb-2">{label} · {side.version}</p>
              <p className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-muted-foreground">
                <Fingerprint size={12} /> SHA-256
              </p>
              <p className="mt-1 break-all font-mono text-xs text-foreground">{side.sha256}</p>
              <p className="mt-2 text-xs text-muted-foreground">
                {side.filename} · {kb(side.size_bytes)}
              </p>
              <p className={cn('mt-2 flex items-center gap-1.5 text-xs',
                side.registry_verified === false ? 'text-red-300' : 'text-muted-foreground')}>
                {side.registry_verified === false ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
                {side.registry_verified === true && `Matches the ${side.registry_algorithm} digest the registry published`}
                {side.registry_verified === false && `Does NOT match the registry's ${side.registry_algorithm} digest`}
                {side.registry_verified == null && 'Registry published no digest to check against'}
              </p>
            </div>
          ))}
        </div>

        {!diff.identical && (
          <dl className="mt-4 grid grid-cols-4 gap-2 text-center text-xs">
            {[['Added', diff.added, 'text-emerald-300'], ['Removed', diff.removed, 'text-red-300'],
              ['Modified', diff.modified, 'text-amber-300'], ['Unchanged', diff.unchanged, 'text-foreground']].map(
              ([label, value, color]) => (
                <div key={label} className="rounded-md bg-white/[0.03] px-2 py-2">
                  <dd className={cn('text-lg font-semibold', color)}>{value}</dd>
                  <dt className="text-muted-foreground">{label}</dt>
                </div>
              ),
            )}
          </dl>
        )}

        {diff.notes.map((note) => (
          <p key={note} className="mt-3 text-xs text-amber-300/90">{note}</p>
        ))}
      </Card>

      {diff.changes.length > 0 && (
        <Card
          title="Changed files"
          subtitle="Install-time files (package.json, setup.py, …) are listed first. Each file is compared by SHA-256."
          bodyClassName="p-0"
        >
          <div className="divide-y divide-border">
            {diff.changes.map((change) => (
              <div key={change.path} className="flex flex-wrap items-center gap-3 px-5 py-2.5">
                <span className={cn('w-20 rounded px-2 py-0.5 text-center text-[11px] font-medium', STATUS_STYLES[change.status])}>
                  {change.status}
                </span>
                <span className="font-mono text-sm text-foreground">{change.path}</span>
                {change.sensitive && <Badge tone="HIGH">install-time file</Badge>}
                <span className="ml-auto font-mono text-[11px] text-muted-foreground">
                  {short(change.old_sha256)} → {short(change.new_sha256)}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
