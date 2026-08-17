"""Background scan jobs.

A scan of a real project takes tens of seconds to a few minutes — far too long
for a synchronous HTTP request. Submitting a scan therefore returns a job id
immediately, and the client polls for progress.

Job state lives in memory; completed results are persisted to SQLite. That split
is deliberate: progress is ephemeral and worthless after a restart, whereas
results are the thing worth keeping. A restart mid-scan loses the job, which is
the correct behaviour for a single-node tool — resuming a half-finished scan
would be more machinery than the problem warrants.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from chainguard.logging_setup import get_logger
from chainguard.ml.model import MalwareClassifier
from chainguard.models.db import save_scan
from chainguard.models.package import Ecosystem
from chainguard.scanner import ScanResult, Scanner, build_remediation_plan

logger = get_logger(__name__)

#: Scans older than this are dropped from the in-memory registry. Results are
#: already in SQLite by then, so nothing is lost.
_JOB_TTL_SECONDS = 3600
_MAX_TRACKED_JOBS = 200


@dataclass
class JobState:
    """Live state of one running or finished scan."""

    scan_id: str
    target: str
    status: str = "queued"  # queued | running | completed | failed
    stage: str = "queued"
    progress: float = 0.0
    message: str = "Waiting to start"
    created_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    error: Optional[str] = None
    result: Optional[ScanResult] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "stage": self.stage,
            "progress": round(self.progress, 3),
            "message": self.message,
            "created_at": self.created_at,
            "elapsed_seconds": round((self.finished_at or time.time()) - self.created_at, 2),
            "error": self.error,
        }


class JobRegistry:
    """Tracks running scans and their progress."""

    def __init__(self) -> None:
        self._jobs: dict[str, JobState] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._classifier: Optional[MalwareClassifier] = None

    @property
    def classifier(self) -> MalwareClassifier:
        """Load the model once and share it across scans."""
        if self._classifier is None:
            self._classifier = MalwareClassifier.load()
        return self._classifier

    def reload_classifier(self) -> None:
        self._classifier = MalwareClassifier.load()

    # ------------------------------------------------------------------ #

    def get(self, scan_id: str) -> Optional[JobState]:
        return self._jobs.get(scan_id)

    def all(self) -> list[JobState]:
        return sorted(self._jobs.values(), key=lambda j: -j.created_at)

    def _prune(self) -> None:
        """Drop finished jobs that are old, and cap total tracked jobs."""
        now = time.time()
        stale = [
            scan_id
            for scan_id, job in self._jobs.items()
            if job.status in ("completed", "failed")
            and now - (job.finished_at or job.created_at) > _JOB_TTL_SECONDS
        ]
        for scan_id in stale:
            self._jobs.pop(scan_id, None)
            self._tasks.pop(scan_id, None)

        if len(self._jobs) > _MAX_TRACKED_JOBS:
            for job in sorted(self._jobs.values(), key=lambda j: j.created_at)[
                : len(self._jobs) - _MAX_TRACKED_JOBS
            ]:
                if job.status in ("completed", "failed"):
                    self._jobs.pop(job.scan_id, None)
                    self._tasks.pop(job.scan_id, None)

    # ------------------------------------------------------------------ #

    def submit_manifest(
        self,
        scan_id: str,
        manifest_text: str,
        filename: str,
        *,
        project_root: Optional[Path] = None,
        include_dev: bool = False,
        max_packages: Optional[int] = None,
    ) -> JobState:
        """Start a manifest scan in the background."""
        self._prune()
        job = JobState(scan_id=scan_id, target=filename)
        self._jobs[scan_id] = job

        async def _run() -> None:
            await self._execute(
                job,
                lambda scanner: scanner.scan_manifest(
                    manifest_text,
                    filename,
                    project_root=project_root,
                    include_dev=include_dev,
                    max_packages=max_packages,
                ),
            )

        self._tasks[scan_id] = asyncio.create_task(_run())
        return job

    def submit_package(
        self, scan_id: str, name: str, version: str, ecosystem: Ecosystem
    ) -> JobState:
        """Start a single-package scan in the background."""
        self._prune()
        job = JobState(scan_id=scan_id, target=f"{name}@{version}")
        self._jobs[scan_id] = job

        async def _run() -> None:
            await self._execute(
                job, lambda scanner: scanner.scan_package(name, version, ecosystem)
            )

        self._tasks[scan_id] = asyncio.create_task(_run())
        return job

    async def _execute(self, job: JobState, run: Any) -> None:
        """Run a scan, recording progress and persisting the result."""
        job.status = "running"
        job.stage = "starting"
        job.message = "Starting scan"

        def _progress(stage: str, pct: float, message: str) -> None:
            job.stage = stage
            job.progress = pct
            job.message = message

        scanner = Scanner(classifier=self.classifier, progress=_progress)

        try:
            result: ScanResult = await run(scanner)
            job.result = result
            job.status = "completed" if result.status != "failed" else "failed"
            job.progress = 1.0
            job.message = (
                f"{result.summary.total_packages} packages, "
                f"{result.summary.reachable_vulnerabilities} reachable vulnerabilities"
            )
            if result.errors:
                job.error = "; ".join(result.errors[:3])

            try:
                save_scan(result)
            except Exception as exc:  # noqa: BLE001 — a storage failure must not lose the result
                logger.error("Could not persist scan %s: %s", job.scan_id, exc)
                job.error = (job.error or "") + f" (result not persisted: {exc})"

        except asyncio.CancelledError:
            job.status = "failed"
            job.error = "Scan was cancelled"
            raise
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scan %s failed", job.scan_id)
            job.status = "failed"
            job.error = str(exc)
            job.message = "Scan failed"
        finally:
            job.finished_at = time.time()

    def cancel(self, scan_id: str) -> bool:
        task = self._tasks.get(scan_id)
        if task is None or task.done():
            return False
        task.cancel()
        return True


registry = JobRegistry()


def result_payload(result: ScanResult) -> dict[str, Any]:
    """Serialise a scan result for the API, adding the remediation plan.

    The plan is derived rather than stored: it is a pure function of the
    findings, so computing it here keeps one source of truth.
    """
    payload = result.model_dump(mode="json")
    payload["remediation"] = [a.model_dump(mode="json") for a in build_remediation_plan(result)]
    payload["noise_reduction"] = round(result.summary.noise_reduction, 4)
    return payload
