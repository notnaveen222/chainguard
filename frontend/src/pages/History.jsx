import { useEffect, useState } from 'react'
import { Clock, Trash2 } from 'lucide-react'

import { api } from '../api'
import { Badge, Card, EmptyState, ErrorBanner } from '../ui'

export default function HistoryPage({ refreshToken }) {
  const [scans, setScans] = useState(null)
  const [error, setError] = useState(null)

  async function load() {
    try {
      const data = await api.history(50)
      setScans(data.scans || [])
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => { load() }, [refreshToken])

  async function remove(scanId) {
    try {
      await api.remove(scanId)
      setScans((current) => current.filter((s) => s.scan_id !== scanId))
    } catch (err) {
      setError(err.message)
    }
  }

  if (error) return <ErrorBanner message={error} onDismiss={() => setError(null)} />
  if (!scans) return <Card><EmptyState title="Loading history…" /></Card>

  if (!scans.length) {
    return (
      <Card title="Scan history">
        <EmptyState icon={Clock} title="No scans yet">
          Completed scans are stored locally in SQLite and appear here.
        </EmptyState>
      </Card>
    )
  }

  return (
    <Card title="Scan history" subtitle={`${scans.length} stored scans`}>
      <div className="overflow-x-auto -mx-5">
        <table className="w-full min-w-[760px]">
          <thead className="border-b border-ink-800">
            <tr>
              <th className="table-header">Target</th>
              <th className="table-header">When</th>
              <th className="table-header">Packages</th>
              <th className="table-header">Flagged</th>
              <th className="table-header">Vulnerabilities</th>
              <th className="table-header">Detector</th>
              <th className="table-header" />
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-800/70">
            {scans.map((scan) => (
              <tr key={scan.scan_id} className="hover:bg-ink-800/30">
                <td className="table-cell">
                  <div className="font-mono text-xs text-ink-100">{scan.target}</div>
                  <div className="text-[11px] text-ink-500">{scan.ecosystem}</div>
                </td>
                <td className="table-cell text-xs text-ink-400">
                  {scan.created_at ? new Date(scan.created_at).toLocaleString() : '—'}
                  <div className="text-[11px] text-ink-600">
                    {scan.duration_seconds?.toFixed(1)}s
                  </div>
                </td>
                <td className="table-cell text-sm tabular-nums text-ink-200">
                  {scan.total_packages}
                </td>
                <td className="table-cell">
                  {scan.malicious_packages > 0 ? (
                    <Badge tone="CRITICAL">{scan.malicious_packages} malicious</Badge>
                  ) : scan.suspicious_packages > 0 ? (
                    <Badge tone="MODERATE">{scan.suspicious_packages} suspicious</Badge>
                  ) : (
                    <span className="text-emerald-400 text-xs">clean</span>
                  )}
                </td>
                <td className="table-cell text-sm">
                  <span className="text-red-400 font-semibold tabular-nums">
                    {scan.reachable_vulnerabilities}
                  </span>
                  <span className="text-ink-500"> reachable of </span>
                  <span className="text-ink-300 tabular-nums">{scan.total_vulnerabilities}</span>
                </td>
                <td className="table-cell text-xs text-ink-400">{scan.model_source}</td>
                <td className="table-cell">
                  <button
                    onClick={() => remove(scan.scan_id)}
                    className="text-ink-500 hover:text-red-400 transition-colors"
                    title="Delete this scan"
                  >
                    <Trash2 size={15} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
