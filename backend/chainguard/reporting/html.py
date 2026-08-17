"""Self-contained HTML scan report.

Renders a scan result as a single file with no external assets — no CDN scripts,
no web fonts, no linked stylesheet. That matters for the actual use case: the
report gets attached to an email, committed to a repository, or opened from a USB
stick on a machine with no network. A report that renders as unstyled text
because a CDN was unreachable is not a report.

It is also the print path. Browsers print HTML well, and a print stylesheet is
far less machinery than a PDF toolchain that would need its own binary
dependency.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.scanner import ScanResult, build_remediation_plan

logger = get_logger(__name__)

_STYLES = """
:root {
  --bg: #ffffff; --fg: #1e293b; --muted: #64748b; --line: #e2e8f0;
  --panel: #f8fafc; --critical: #b91c1c; --high: #c2410c;
  --moderate: #b45309; --low: #0e7490; --safe: #047857; --accent: #0e7490;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.5rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2.5rem 0 .75rem; padding-bottom: .4rem;
     border-bottom: 2px solid var(--line); }
h3 { font-size: .95rem; margin: 1.25rem 0 .4rem; }
.sub { color: var(--muted); margin: 0 0 1.5rem; font-size: .9rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
        gap: .75rem; margin: 1.25rem 0; }
.stat { border: 1px solid var(--line); border-radius: .5rem; padding: .85rem 1rem;
        background: var(--panel); }
.stat .n { font-size: 1.7rem; font-weight: 700; line-height: 1.1; }
.stat .l { color: var(--muted); font-size: .78rem; text-transform: uppercase;
           letter-spacing: .04em; margin-top: .2rem; }
.headline { border: 2px solid var(--accent); border-radius: .6rem; padding: 1.25rem;
            margin: 1.5rem 0; background: #ecfeff; }
.headline .row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 1.5rem; }
.headline .big { font-size: 2rem; font-weight: 700; }
table { width: 100%; border-collapse: collapse; margin: .75rem 0; font-size: .87rem; }
th { text-align: left; padding: .5rem .6rem; border-bottom: 2px solid var(--line);
     font-size: .72rem; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
td { padding: .5rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
code, .mono { font-family: ui-monospace, Consolas, monospace; font-size: .85em; }
.tag { display: inline-block; padding: .1rem .45rem; border-radius: .25rem;
       font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }
.critical { background: #fee2e2; color: var(--critical); }
.high { background: #ffedd5; color: var(--high); }
.moderate, .medium { background: #fef3c7; color: var(--moderate); }
.low { background: #cffafe; color: var(--low); }
.unknown { background: #f1f5f9; color: var(--muted); }
.malicious { background: #fee2e2; color: var(--critical); }
.suspicious { background: #fef3c7; color: var(--moderate); }
.yes { color: var(--critical); font-weight: 700; }
.no { color: var(--safe); font-weight: 600; }
.path { background: #fef2f2; border: 1px solid #fecaca; border-radius: .4rem;
        padding: .6rem .75rem; margin: .4rem 0; font-family: ui-monospace, monospace;
        font-size: .78rem; }
.path div { padding: .1rem 0; }
.note { color: var(--muted); font-size: .85rem; }
.warn { background: #fffbeb; border-left: 3px solid #f59e0b; padding: .5rem .75rem;
        margin: .3rem 0; font-size: .85rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
         color: var(--muted); font-size: .8rem; }
@media print {
  body { padding: 0; font-size: 11pt; }
  h2 { page-break-after: avoid; }
  table, .path, .headline { page-break-inside: avoid; }
}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _tag(text: str) -> str:
    return f'<span class="tag {_esc(str(text).lower())}">{_esc(text)}</span>'


def render_report(result: ScanResult, generated_at: Optional[datetime] = None) -> str:
    """Render a scan result as a standalone HTML document."""
    summary = result.summary
    stamp = (generated_at or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC")
    reduction = summary.noise_reduction

    parts: list[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>ChainGuard report — {_esc(result.target)}</title>",
        f"<style>{_STYLES}</style></head><body><div class='wrap'>",
        f"<h1>ChainGuard scan report</h1>",
        f"<p class='sub'><strong>{_esc(result.target)}</strong> · "
        f"{_esc(result.ecosystem)} · generated {stamp} · "
        f"scan took {result.duration_seconds:.1f}s · "
        f"detector: {_esc(result.model_source)}</p>",
    ]

    # --- headline stats ---------------------------------------------------- #
    parts.append("<div class='grid'>")
    for label, value in (
        ("Packages", summary.total_packages),
        ("Direct", summary.direct_packages),
        ("Malicious", summary.malicious_packages),
        ("Suspicious", summary.suspicious_packages),
        ("Advisories", summary.total_vulnerabilities),
        ("Reachable", summary.reachable_vulnerabilities),
    ):
        parts.append(f"<div class='stat'><div class='n'>{value}</div><div class='l'>{label}</div></div>")
    parts.append("</div>")

    # --- reachability headline ---------------------------------------------- #
    if summary.total_vulnerabilities:
        parts.append(
            "<div class='headline'><div class='row'>"
            f"<div><div class='big'>{summary.total_vulnerabilities}</div>"
            "<div class='note'>advisories reported</div></div>"
            f"<div><div class='big'>{summary.reachable_vulnerabilities}</div>"
            "<div class='note'>actually reachable</div></div>"
            f"<div><div class='big'>{reduction:.0%}</div>"
            "<div class='note'>ruled out as unreachable</div></div>"
            "</div><p class='note' style='margin:.75rem 0 0'>Unreachable findings are "
            "de-prioritised, not dismissed — a reason is recorded for each.</p></div>"
        )

    if not result.reachability_available:
        parts.append(
            "<div class='warn'>No application source was analysed, so every advisory "
            "is reported as reachable. Scan a project directory to enable reachability "
            "analysis.</div>"
        )

    # --- flagged packages ----------------------------------------------------- #
    flagged = result.flagged_packages()
    parts.append("<h2>Malicious package detection</h2>")
    if not flagged:
        parts.append("<p class='note'>No packages were flagged.</p>")
    else:
        for package in flagged[:25]:
            parts.append(
                f"<h3><span class='mono'>{_esc(package.name)}@{_esc(package.version)}</span> "
                f"{_tag(package.verdict)} <span class='note'>score "
                f"{package.malice_score:.3f}</span></h3>"
            )
            if package.explanation:
                parts.append(f"<p>{_esc(package.explanation)}</p>")
            if package.typosquat_target:
                parts.append(
                    f"<p class='note'>Name resembles the popular package "
                    f"<code>{_esc(package.typosquat_target)}</code>.</p>"
                )
            if package.signals:
                parts.append("<table><thead><tr><th>Severity</th><th>Signal</th>"
                             "<th>Location</th><th>Detail</th></tr></thead><tbody>")
                for signal in package.signals[:10]:
                    count = (
                        f" <span class='note'>&times;{signal.occurrences}</span>"
                        if signal.occurrences > 1 else ""
                    )
                    location = _esc(signal.location)
                    if signal.occurrences > 1:
                        location += " <span class='note'>and elsewhere</span>"
                    parts.append(
                        f"<tr><td>{_tag(signal.severity.value)}</td>"
                        f"<td class='mono'>{_esc(signal.code)}{count}</td>"
                        f"<td class='mono note'>{location}</td>"
                        f"<td>{_esc(signal.detail or '')}</td></tr>"
                    )
                parts.append("</tbody></table>")

    # --- vulnerabilities ------------------------------------------------------ #
    parts.append("<h2>Reachable vulnerabilities</h2>")
    reachable = [v for v in result.prioritised_vulnerabilities() if v.reachable]
    if not reachable:
        parts.append("<p class='note'>No reachable vulnerabilities were found.</p>")
    else:
        parts.append("<table><thead><tr><th>Advisory</th><th>Package</th><th>Severity</th>"
                     "<th>Fixed in</th><th>Why it is reachable</th></tr></thead><tbody>")
        for vuln in reachable[:60]:
            reason = _esc(vuln.reachability_reason)
            parts.append(
                f"<tr><td class='mono'>{_esc(vuln.cve_id or vuln.id)}</td>"
                f"<td class='mono'>{_esc(vuln.package)}@{_esc(vuln.version)}</td>"
                f"<td>{_tag(vuln.severity)}"
                + (f" {vuln.cvss_score}" if vuln.cvss_score else "")
                + f"</td><td class='mono'>{_esc(vuln.fixed_version or '—')}</td>"
                f"<td>{reason}</td></tr>"
            )
        parts.append("</tbody></table>")

        proofs = [v for v in reachable if v.call_path][:10]
        if proofs:
            parts.append("<h3>Call paths</h3><p class='note'>Each path traces from an "
                         "application entry point to the vulnerable function.</p>")
            for vuln in proofs:
                parts.append(f"<p class='mono'><strong>{_esc(vuln.cve_id or vuln.id)}</strong> "
                             f"— {_esc(vuln.package)}</p><div class='path'>")
                for index, step in enumerate(vuln.call_path, start=1):
                    parts.append(
                        f"<div>{index}. {_esc(step.get('caller'))} &rarr; "
                        f"<strong>{_esc(step.get('callee'))}</strong> "
                        f"<span class='note'>{_esc(step.get('file'))}:"
                        f"{_esc(step.get('line'))}</span></div>"
                    )
                parts.append("</div>")

    # --- unreachable ---------------------------------------------------------- #
    unreachable = [v for v in result.all_vulnerabilities() if not v.reachable]
    if unreachable:
        parts.append(f"<h2>Not reachable ({len(unreachable)})</h2>")
        parts.append("<p class='note'>Present in the dependency tree, but the vulnerable "
                     "code cannot be reached from this application. De-prioritised, not "
                     "dismissed.</p>")
        parts.append("<table><thead><tr><th>Advisory</th><th>Package</th><th>Severity</th>"
                     "<th>Reason</th></tr></thead><tbody>")
        for vuln in sorted(unreachable, key=lambda v: -(v.cvss_score or 0))[:40]:
            parts.append(
                f"<tr><td class='mono'>{_esc(vuln.cve_id or vuln.id)}</td>"
                f"<td class='mono'>{_esc(vuln.package)}</td>"
                f"<td>{_tag(vuln.severity)}</td>"
                f"<td class='note'>{_esc(vuln.reachability_reason)}</td></tr>"
            )
        parts.append("</tbody></table>")

    # --- remediation ------------------------------------------------------------ #
    plan = build_remediation_plan(result)
    if plan:
        parts.append("<h2>Remediation plan</h2>")
        parts.append("<p class='note'>Ordered by reachable vulnerabilities fixed, not raw "
                     "count — an upgrade clearing one reachable flaw matters more than one "
                     "clearing fifty unreachable ones.</p>")
        parts.append("<table><thead><tr><th>Package</th><th>Upgrade</th><th>Fixes</th>"
                     "<th>Reachable</th><th>Highest</th></tr></thead><tbody>")
        for action in plan[:20]:
            parts.append(
                f"<tr><td class='mono'>{_esc(action.package)}</td>"
                f"<td class='mono'>{_esc(action.current_version)} &rarr; "
                f"{_esc(action.target_version)}</td>"
                f"<td>{action.fixes_total}</td>"
                f"<td class={'yes' if action.fixes_reachable else 'no'}>"
                f"{action.fixes_reachable}</td>"
                f"<td>{_tag(action.highest_severity)}</td></tr>"
            )
        parts.append("</tbody></table>")

    # --- notes -------------------------------------------------------------------- #
    if result.warnings or result.errors:
        parts.append("<h2>Scan notes</h2>")
        for error in result.errors[:10]:
            parts.append(f"<div class='warn'><strong>Error:</strong> {_esc(error)}</div>")
        for warning in result.warnings[:15]:
            parts.append(f"<div class='warn'>{_esc(warning)}</div>")

    parts.append(
        "<footer>Generated by ChainGuard — malicious package detection and vulnerability "
        "reachability analysis. All analysis is static; no scanned package was executed. "
        "&ldquo;Not statically reachable&rdquo; is a weaker claim than &ldquo;not "
        "exploitable&rdquo;.</footer></div></body></html>"
    )

    return "".join(parts)


def write_report(result: ScanResult, path: Optional[Path] = None) -> Path:
    """Render and write a report, returning the path written."""
    target = path or (get_settings().reports_dir / f"scan-{result.scan_id}.html")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_report(result), encoding="utf-8")
    logger.info("Report written to %s", target)
    return target
