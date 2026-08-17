"""Command-line interface.

Exists for two reasons beyond convenience: it is the demo path that works when
nothing else is running (no server, no browser), and it is the fastest way to
reproduce a finding while developing.

    python -m chainguard scan-project D:\\some\\project
    python -m chainguard scan-package requests 2.19.0 --ecosystem PyPI
    python -m chainguard scan-manifest requirements.txt --source ./src
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from chainguard import __version__
from chainguard.logging_setup import setup_logging
from chainguard.models.package import Ecosystem
from chainguard.scanner import Scanner, ScanResult, build_remediation_plan

app = typer.Typer(
    add_completion=False,
    help="ChainGuard — malicious package detection and vulnerability reachability analysis",
)
console = Console()

_SEVERITY_COLOURS = {
    "CRITICAL": "bold red", "HIGH": "red", "MODERATE": "yellow",
    "MEDIUM": "yellow", "LOW": "cyan", "UNKNOWN": "dim",
}
_VERDICT_COLOURS = {"malicious": "bold red", "suspicious": "yellow", "benign": "green"}


def _run(coro):
    return asyncio.run(coro)


def _scanner_with_progress(progress: Progress, task_id) -> Scanner:
    def _report(stage: str, pct: float, message: str) -> None:
        progress.update(task_id, completed=pct * 100, description=f"[cyan]{message}")

    return Scanner(progress=_report)


def _render(result: ScanResult, *, show_all: bool = False) -> None:
    """Print a scan result."""
    summary = result.summary

    console.print()
    console.print(
        Panel(
            f"[bold]{result.target}[/bold]  ({result.ecosystem})\n"
            f"{summary.total_packages} packages "
            f"({summary.direct_packages} direct, max depth {summary.max_depth})  ·  "
            f"{result.duration_seconds:.1f}s  ·  detector: {result.model_source}",
            title="ChainGuard scan",
            border_style="cyan",
        )
    )

    # --- malicious packages ------------------------------------------------ #
    flagged = result.flagged_packages()
    if flagged:
        table = Table(title="Flagged packages", title_style="bold red", header_style="bold")
        table.add_column("Package")
        table.add_column("Score", justify="right")
        table.add_column("Verdict")
        table.add_column("Top evidence")
        for package in flagged[:15]:
            evidence = "; ".join(
                s.code for s in sorted(package.signals, key=lambda s: -s.severity.rank)[:2]
            )
            table.add_row(
                f"{package.name}@{package.version}",
                f"{package.malice_score:.3f}",
                f"[{_VERDICT_COLOURS.get(package.verdict, '')}]{package.verdict}[/]",
                evidence or "-",
            )
        console.print(table)
    else:
        console.print("[green]No packages were flagged as malicious or suspicious.[/green]")

    # --- vulnerabilities ---------------------------------------------------- #
    if summary.total_vulnerabilities:
        console.print()
        reduction = summary.noise_reduction
        console.print(
            Panel(
                f"[bold]{summary.total_vulnerabilities}[/bold] advisories found  →  "
                f"[bold red]{summary.reachable_vulnerabilities}[/bold red] reachable, "
                f"[dim]{summary.unreachable_vulnerabilities} not reachable[/dim]\n"
                f"Reachability analysis ruled out [bold green]{reduction:.0%}[/bold green] "
                f"of reported vulnerabilities.",
                title="Vulnerability reachability",
                border_style="magenta",
            )
        )

        table = Table(title="Prioritised vulnerabilities", header_style="bold")
        table.add_column("ID")
        table.add_column("Package")
        table.add_column("Severity")
        table.add_column("Reachable")
        table.add_column("Why")

        entries = result.prioritised_vulnerabilities()
        shown = entries if show_all else [v for v in entries if v.reachable][:20]
        if not shown:
            shown = entries[:10]

        for vulnerability in shown[:30]:
            colour = _SEVERITY_COLOURS.get(vulnerability.severity.upper(), "")
            mark = "[red]YES[/red]" if vulnerability.reachable else "[green]no[/green]"
            reason = vulnerability.reachability_reason or "-"
            if vulnerability.call_path:
                path = " → ".join(
                    [vulnerability.call_path[0]["caller"]]
                    + [s["callee"] for s in vulnerability.call_path]
                )
                reason = f"{path}"
            table.add_row(
                vulnerability.cve_id or vulnerability.id,
                f"{vulnerability.package}@{vulnerability.version}",
                f"[{colour}]{vulnerability.severity}[/]",
                mark,
                reason[:74],
            )
        console.print(table)

        # --- remediation ---------------------------------------------------- #
        plan = build_remediation_plan(result)
        actionable = [a for a in plan if a.fixes_reachable > 0] or plan[:5]
        if actionable:
            table = Table(title="Remediation plan", title_style="bold green", header_style="bold")
            table.add_column("Upgrade")
            table.add_column("Fixes", justify="right")
            table.add_column("Reachable", justify="right")
            table.add_column("Highest")
            for action in actionable[:12]:
                table.add_row(
                    f"{action.package}  {action.current_version} → {action.target_version}",
                    str(action.fixes_total),
                    str(action.fixes_reachable),
                    f"[{_SEVERITY_COLOURS.get(action.highest_severity, '')}]"
                    f"{action.highest_severity}[/]",
                )
            console.print(table)
    else:
        console.print("[green]No known vulnerabilities found.[/green]")

    if result.reachability_available:
        console.print(f"[dim]Call graph: {result.reachability_stats}[/dim]")

    for warning in result.warnings[:6]:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    for error in result.errors[:6]:
        console.print(f"[red]error:[/red] {error}")


@app.command("scan-project")
def scan_project(
    path: Path = typer.Argument(..., help="Project directory to scan"),
    include_dev: bool = typer.Option(False, "--dev", help="Include dev dependencies"),
    max_packages: Optional[int] = typer.Option(None, "--limit", help="Cap packages scanned"),
    show_all: bool = typer.Option(False, "--all", help="Show unreachable vulnerabilities too"),
) -> None:
    """Scan a project directory, including reachability analysis of its source."""
    setup_logging("WARNING")
    if not path.is_dir():
        console.print(f"[red]Not a directory:[/red] {path}")
        raise typer.Exit(1)

    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Starting...", total=100)
        scanner = _scanner_with_progress(progress, task_id)
        result = _run(
            scanner.scan_project(path, include_dev=include_dev, max_packages=max_packages)
        )

    _render(result, show_all=show_all)


@app.command("scan-manifest")
def scan_manifest(
    manifest: Path = typer.Argument(..., help="package.json or requirements.txt"),
    source: Optional[Path] = typer.Option(
        None, "--source", help="Project source directory, for reachability analysis"
    ),
    include_dev: bool = typer.Option(False, "--dev"),
    show_all: bool = typer.Option(False, "--all"),
) -> None:
    """Scan a manifest file."""
    setup_logging("WARNING")
    if not manifest.is_file():
        console.print(f"[red]No such file:[/red] {manifest}")
        raise typer.Exit(1)

    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), console=console
    ) as progress:
        task_id = progress.add_task("[cyan]Starting...", total=100)
        scanner = _scanner_with_progress(progress, task_id)
        result = _run(
            scanner.scan_manifest(
                manifest.read_text(encoding="utf-8", errors="replace"),
                manifest.name,
                project_root=source,
                include_dev=include_dev,
            )
        )

    _render(result, show_all=show_all)


@app.command("scan-package")
def scan_package(
    name: str = typer.Argument(..., help="Package name"),
    version: str = typer.Argument("latest", help="Version"),
    ecosystem: str = typer.Option("PyPI", "--ecosystem", "-e", help="npm or PyPI"),
) -> None:
    """Analyse a single package."""
    setup_logging("WARNING")
    try:
        eco = Ecosystem(ecosystem)
    except ValueError:
        console.print("[red]ecosystem must be 'npm' or 'PyPI'[/red]")
        raise typer.Exit(1) from None

    with console.status(f"[cyan]Analysing {name}@{version}..."):
        result = _run(Scanner().scan_package(name, version, eco))

    _render(result, show_all=True)

    for package in result.packages:
        if not package.signals:
            continue
        console.print(f"\n[bold]Evidence for {package.name}@{package.version}[/bold]")
        for signal in package.signals:
            colour = _SEVERITY_COLOURS.get(signal.severity.value.upper(), "")
            console.print(f"  [{colour}]{signal.severity.value:9}[/] {signal.code}")
            console.print(f"            {signal.location}")
            if signal.detail:
                console.print(f"            [dim]{signal.detail}[/dim]")


@app.command("version")
def version() -> None:
    """Print the version."""
    console.print(f"ChainGuard {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
