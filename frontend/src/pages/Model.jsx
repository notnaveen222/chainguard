import { useEffect, useState } from 'react'
import { Brain, FlaskConical, Info, TrendingUp } from 'lucide-react'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { api } from '../api'
import { Card, EmptyState, ErrorBanner, Stat } from '../ui'

const GROUP_COLOURS = {
  install_execution: '#dc2626',
  exfiltration: '#9333ea',
  dynamic_execution: '#ea580c',
  credentials: '#db2777',
  network: '#2563eb',
  obfuscation: '#d97706',
  process: '#ef4444',
  typosquat: '#0d9488',
  metadata: '#64748b',
  structure: '#94a3b8',
  aggregate: '#334155',
}

/**
 * Model evaluation view.
 *
 * This page exists because "how do you know it works?" is the first question a
 * reviewer asks. It shows out-of-fold metrics, the comparison against the rules
 * baseline, what the model learned from, and what breaks when each signal family
 * is removed.
 */
export default function ModelPage() {
  const [card, setCard] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.modelCard().then(setCard).catch((e) => setError(e.message))
  }, [])

  if (error) return <ErrorBanner message={error} />
  if (!card) return <Card><EmptyState title="Loading model card…" /></Card>

  if (!card.trained) {
    return (
      <Card title="No trained model">
        <EmptyState icon={Brain} title="The classifier has not been trained yet">
          {card.message} Scans still work — they fall back to the rules baseline, and every
          result says which detector produced its score.
        </EmptyState>
      </Card>
    )
  }

  const cv = card.cv_metrics || {}
  const baseline = card.baseline_metrics || {}
  const matrix = cv.confusion_matrix || {}

  const importances = (card.feature_importances || [])
    .filter(([, v]) => v > 0)
    .slice(0, 18)
    .map(([name, value]) => ({ name, value: Number(value.toFixed(5)) }))

  const ablation = Object.entries(card.ablation || {})
    .map(([group, metrics]) => ({
      group,
      drop: Number(((cv.f1 || 0) - (metrics.f1 || 0)).toFixed(4)),
    }))
    .sort((a, b) => b.drop - a.drop)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat label="Precision" value={fmt(cv.precision)} tone="accent"
              hint={`± ${fmt(cv.fold_std?.precision)} across folds`} />
        <Stat label="Recall" value={fmt(cv.recall)} tone="accent"
              hint={`± ${fmt(cv.fold_std?.recall)} across folds`} />
        <Stat label="F1" value={fmt(cv.f1)} tone="good"
              hint={`${cv.n_splits || 0}-fold grouped CV`} />
        <Stat label="PR-AUC" value={fmt(cv.pr_auc)} tone="good"
              hint="headline metric under class imbalance" icon={TrendingUp} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Confusion matrix" subtitle="Out-of-fold predictions across all samples">
          <div className="grid grid-cols-2 gap-3">
            <MatrixCell label="True negative" value={matrix.true_negative} tone="good"
                        hint="benign, correctly cleared" />
            <MatrixCell label="False positive" value={matrix.false_positive} tone="warn"
                        hint="benign, wrongly flagged" />
            <MatrixCell label="False negative" value={matrix.false_negative} tone="danger"
                        hint="malware that got through" />
            <MatrixCell label="True positive" value={matrix.true_positive} tone="good"
                        hint="malware caught" />
          </div>
          <p className="mt-4 text-xs text-ink-500 leading-relaxed">
            False negatives matter more than false positives here: a wrongly flagged package
            costs a developer a few minutes, while a missed one ships malware into production.
          </p>
        </Card>

        <Card title="Model vs. rules baseline"
              subtitle="Does the machine learning layer actually earn its place?">
          <div className="space-y-3">
            {['precision', 'recall', 'f1', 'pr_auc'].map((metric) => (
              <ComparisonBar
                key={metric}
                label={metric.replace('_', '-').toUpperCase()}
                model={cv[metric]}
                baseline={baseline[metric]}
              />
            ))}
          </div>
          <p className="mt-4 text-xs text-ink-500 leading-relaxed">
            The baseline is a weighted-sum rules engine over the same signals, scored on the
            same data. Reporting a classifier without this comparison would be an assertion
            rather than a result.
          </p>
        </Card>
      </div>

      <Card title="Feature importance"
            subtitle="What the model learned to rely on, coloured by signal family">
        <ResponsiveContainer width="100%" height={Math.max(340, importances.length * 26)}>
          <BarChart data={importances} layout="vertical"
                    margin={{ left: 150, right: 24, top: 8, bottom: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
            <XAxis type="number" stroke="#64748b" fontSize={11} />
            <YAxis type="category" dataKey="name" stroke="#94a3b8" fontSize={11} width={145} />
            <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#1e293b55' }} />
            <Bar dataKey="value" radius={[0, 3, 3, 0]}>
              {importances.map((entry) => (
                <Cell key={entry.name} fill={colourFor(entry.name)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Card>

      {ablation.length > 0 && (
        <Card title="Ablation study"
              subtitle="F1 lost when each signal family is removed and the model retrained"
              right={<FlaskConical size={16} className="text-ink-400" />}>
          <ResponsiveContainer width="100%" height={Math.max(300, ablation.length * 34)}>
            <BarChart data={ablation} layout="vertical"
                      margin={{ left: 130, right: 24, top: 8, bottom: 8 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" stroke="#64748b" fontSize={11} />
              <YAxis type="category" dataKey="group" stroke="#94a3b8" fontSize={11} width={125} />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: '#1e293b55' }} />
              <Bar dataKey="drop" radius={[0, 3, 3, 0]}>
                {ablation.map((entry) => (
                  <Cell key={entry.group} fill={GROUP_COLOURS[entry.group] || '#475569'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <p className="mt-2 text-xs text-ink-500">
            A larger bar means the family carries more of the model. A negative bar means
            removing it slightly helped — that family was adding noise.
          </p>
        </Card>
      )}

      <Card title="Training methodology" right={<Info size={16} className="text-ink-400" />}>
        <dl className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
          <Meta label="Algorithm" value={card.algorithm} />
          <Meta label="Samples" value={card.n_samples} />
          <Meta label="Malicious" value={card.n_malicious} />
          <Meta label="Benign" value={card.n_benign} />
        </dl>
        <ul className="space-y-2">
          {(card.notes || []).map((note, index) => (
            <li key={index} className="text-sm text-ink-400 flex gap-2 leading-relaxed">
              <span className="text-cyan-500 shrink-0">▸</span>
              <span>{note}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  )
}

const TOOLTIP_STYLE = {
  background: '#0f172a',
  border: '1px solid #334155',
  borderRadius: 8,
  fontSize: 12,
  color: '#e2e8f0',
}

function colourFor(featureName) {
  const groups = {
    install_hook: 'install_execution', setup_py: 'install_execution',
    dynamic_eval: 'dynamic_execution', decode_then_exec: 'dynamic_execution',
    dynamic_import: 'dynamic_execution',
    process_spawn: 'process', shell_execution: 'process', reverse_shell: 'process',
    network_access: 'network', hardcoded_ip: 'network', suspicious_endpoint: 'network',
    dns_exfil: 'network',
    sensitive_path: 'credentials', crypto_wallet: 'credentials', env_: 'credentials',
    file_write: 'credentials', host_recon: 'credentials',
    exfil_: 'exfiltration',
    typosquat: 'typosquat',
  }
  for (const [prefix, group] of Object.entries(groups)) {
    if (featureName.startsWith(prefix)) return GROUP_COLOURS[group]
  }
  if (/entropy|base64|charcode|hex_escape|string_array|minified|max_line|parse_failure/.test(featureName))
    return GROUP_COLOURS.obfuscation
  if (/signals|rules_baseline/.test(featureName)) return GROUP_COLOURS.aggregate
  if (/repository|age_days|version_count|maintainer|description|dependency/.test(featureName))
    return GROUP_COLOURS.metadata
  return GROUP_COLOURS.structure
}

function fmt(value) {
  return value === null || value === undefined ? '—' : Number(value).toFixed(3)
}

function MatrixCell({ label, value, tone, hint }) {
  const tones = {
    good: 'border-emerald-900 bg-emerald-950/40 text-emerald-300',
    warn: 'border-amber-900 bg-amber-950/40 text-amber-300',
    danger: 'border-red-900 bg-red-950/40 text-red-300',
  }
  return (
    <div className={`rounded-lg border p-4 ${tones[tone]}`}>
      <div className="text-3xl font-bold tabular-nums">{value ?? 0}</div>
      <div className="text-sm mt-1 font-medium">{label}</div>
      <div className="text-xs opacity-70 mt-0.5">{hint}</div>
    </div>
  )
}

function ComparisonBar({ label, model, baseline }) {
  const modelValue = model || 0
  const baselineValue = baseline || 0
  const delta = modelValue - baselineValue

  return (
    <div>
      <div className="flex items-baseline justify-between text-sm mb-1">
        <span className="text-ink-300 font-medium">{label}</span>
        <span className="tabular-nums text-ink-400">
          <span className="text-cyan-400 font-semibold">{fmt(model)}</span>
          {' vs '}
          <span className="text-ink-500">{fmt(baseline)}</span>
          <span className={delta >= 0 ? 'text-emerald-400 ml-2' : 'text-red-400 ml-2'}>
            {delta >= 0 ? '+' : ''}{delta.toFixed(3)}
          </span>
        </span>
      </div>
      <div className="relative h-5 rounded bg-ink-800 overflow-hidden">
        <div className="absolute inset-y-0 left-0 bg-ink-600"
             style={{ width: `${baselineValue * 100}%` }} />
        <div className="absolute inset-y-0 left-0 bg-cyan-600/80"
             style={{ width: `${modelValue * 100}%` }} />
      </div>
    </div>
  )
}

function Meta({ label, value }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-ink-500">{label}</dt>
      <dd className="text-lg font-semibold text-ink-100 mt-0.5">{value ?? '—'}</dd>
    </div>
  )
}
