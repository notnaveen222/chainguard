"""FastAPI application.

Exposes scan submission, progress polling, results, history, and the model card.
OpenAPI documentation is generated automatically at ``/docs``.

CORS is open to the Vite dev server origins only. It is not open to ``*``: this
service reads local files and triggers outbound network requests, so any page in
any tab being able to drive it would be a genuine problem rather than a
theoretical one.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from chainguard import __version__
from chainguard.analysis.signals import CATALOGUE
from chainguard.api.jobs import registry, result_payload
from chainguard.config import get_settings
from chainguard.llm.assistant import assistant_available, install_log_buffer, run_chat
from chainguard.logging_setup import get_logger, setup_logging
from chainguard.models.db import delete_scan, init_db, list_scans, load_scan
from chainguard.models.package import Ecosystem

logger = get_logger(__name__)

MAX_MANIFEST_BYTES = 2 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    install_log_buffer()
    settings = get_settings()
    settings.ensure_directories()
    init_db()

    classifier = registry.classifier
    logger.info(
        "ChainGuard %s ready — detector: %s",
        __version__,
        "trained model" if classifier.is_trained else "rules baseline (no model trained yet)",
    )
    if settings.llm_available:
        logger.info("LLM explanation layer: enabled")
    yield


app = FastAPI(
    title="ChainGuard API",
    version=__version__,
    description=(
        "AI-powered software supply chain security: malicious package detection "
        "and vulnerability reachability analysis."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:4173", "http://127.0.0.1:4173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #


class ManifestScanRequest(BaseModel):
    """Scan a manifest supplied as text."""

    manifest: str = Field(description="Contents of package.json / requirements.txt")
    filename: str = Field(default="requirements.txt", description="Used to select the parser")
    project_root: Optional[str] = Field(
        default=None,
        description=(
            "Absolute path to the project's source. Required for reachability "
            "analysis; without it every advisory is reported as reachable."
        ),
    )
    include_dev: bool = False
    max_packages: Optional[int] = Field(default=None, ge=1, le=2000)


class ProjectScanRequest(BaseModel):
    """Scan a project directory on the local filesystem."""

    path: str = Field(description="Absolute path to the project directory")
    include_dev: bool = False
    max_packages: Optional[int] = Field(default=None, ge=1, le=2000)


class PackageScanRequest(BaseModel):
    """Scan one package without resolving a dependency tree."""

    name: str
    version: str = "latest"
    ecosystem: str = Field(default="PyPI", description="'npm' or 'PyPI'")


# --------------------------------------------------------------------------- #
# Meta
# --------------------------------------------------------------------------- #


@app.get("/api/health", tags=["meta"])
async def health() -> dict[str, Any]:
    """Liveness and capability report."""
    settings = get_settings()
    classifier = registry.classifier
    return {
        "status": "ok",
        "version": __version__,
        "detector": "model" if classifier.is_trained else "rules-baseline",
        "model_trained": classifier.is_trained,
        "llm_enabled": settings.llm_available,
        "assistant_available": assistant_available(),
        "thresholds": {
            "malicious": settings.malicious_threshold,
            "suspicious": settings.suspicious_threshold,
        },
    }


@app.get("/api/model", tags=["meta"])
async def model_card() -> dict[str, Any]:
    """The trained model's card: metrics, ablation, feature importances."""
    classifier = registry.classifier
    if not classifier.is_trained or classifier.metadata is None:
        return {
            "trained": False,
            "detector": "rules-baseline",
            "message": (
                "No model has been trained yet. Run scripts/build_dataset.py then "
                "scripts/train_model.py. Scans still work using the rules baseline."
            ),
        }
    return {"trained": True, **classifier.metadata.to_dict()}


@app.get("/api/signals", tags=["meta"])
async def signal_catalogue() -> dict[str, Any]:
    """The detection signal catalogue, for the dashboard's reference view."""
    return {
        "count": len(CATALOGUE),
        "signals": [
            {
                "code": s.code,
                "title": s.title,
                "description": s.description,
                "category": s.category.value,
                "severity": s.severity.value,
            }
            for s in sorted(CATALOGUE.values(), key=lambda s: (s.category.value, -s.severity.rank))
        ],
    }


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #


def _resolve_project_root(path: Optional[str]) -> Optional[Path]:
    if not path:
        return None
    root = Path(path).expanduser()
    if not root.is_dir():
        raise HTTPException(400, f"Project path is not a directory: {path}")
    return root


@app.post("/api/scans/manifest", tags=["scans"], status_code=202)
async def scan_manifest(request: ManifestScanRequest) -> dict[str, Any]:
    """Submit a manifest for scanning. Returns immediately with a job id."""
    if not request.manifest.strip():
        raise HTTPException(400, "Manifest is empty")
    if len(request.manifest.encode()) > MAX_MANIFEST_BYTES:
        raise HTTPException(413, "Manifest is too large")

    scan_id = uuid.uuid4().hex[:12]
    job = registry.submit_manifest(
        scan_id,
        request.manifest,
        request.filename,
        project_root=_resolve_project_root(request.project_root),
        include_dev=request.include_dev,
        max_packages=request.max_packages,
    )
    return {"scan_id": scan_id, "status": job.status, "poll": f"/api/scans/{scan_id}/status"}


@app.post("/api/scans/upload", tags=["scans"], status_code=202)
async def scan_upload(
    file: UploadFile, project_root: Optional[str] = None, include_dev: bool = False
) -> dict[str, Any]:
    """Submit an uploaded manifest file."""
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "Uploaded file is empty")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise HTTPException(413, "Uploaded file is too large")

    scan_id = uuid.uuid4().hex[:12]
    job = registry.submit_manifest(
        scan_id,
        raw.decode("utf-8", errors="replace"),
        file.filename or "requirements.txt",
        project_root=_resolve_project_root(project_root),
        include_dev=include_dev,
    )
    return {"scan_id": scan_id, "status": job.status, "poll": f"/api/scans/{scan_id}/status"}


@app.post("/api/scans/project", tags=["scans"], status_code=202)
async def scan_project(request: ProjectScanRequest) -> dict[str, Any]:
    """Scan a project directory, discovering its manifest and using its source.

    This is the endpoint that produces reachability results, since it has both
    the dependency list and the application code.
    """
    root = _resolve_project_root(request.path)
    if root is None:
        # `path` is required on this model, so this is unreachable — but an
        # assert would be stripped under `python -O`, turning a clear 400 into
        # an AttributeError further down.
        raise HTTPException(400, "A project path is required")

    from chainguard.registry.manifest import detect_project_manifests

    manifests = detect_project_manifests(root)
    if not manifests:
        raise HTTPException(
            400,
            f"No package.json, requirements.txt or pyproject.toml found in {request.path}",
        )

    manifest_path = manifests[0]
    scan_id = uuid.uuid4().hex[:12]
    job = registry.submit_manifest(
        scan_id,
        manifest_path.read_text(encoding="utf-8", errors="replace"),
        manifest_path.name,
        project_root=root,
        include_dev=request.include_dev,
        max_packages=request.max_packages,
    )
    return {
        "scan_id": scan_id,
        "status": job.status,
        "manifest": manifest_path.name,
        "poll": f"/api/scans/{scan_id}/status",
    }


@app.post("/api/scans/package", tags=["scans"], status_code=202)
async def scan_package(request: PackageScanRequest) -> dict[str, Any]:
    """Analyse a single package."""
    try:
        ecosystem = Ecosystem(request.ecosystem)
    except ValueError:
        raise HTTPException(400, "ecosystem must be 'npm' or 'PyPI'") from None

    scan_id = uuid.uuid4().hex[:12]
    job = registry.submit_package(scan_id, request.name, request.version, ecosystem)
    return {"scan_id": scan_id, "status": job.status, "poll": f"/api/scans/{scan_id}/status"}


@app.get("/api/scans/{scan_id}/status", tags=["scans"])
async def scan_status(scan_id: str) -> dict[str, Any]:
    """Poll a running scan's progress."""
    job = registry.get(scan_id)
    if job is None:
        # Not in memory — it may have completed earlier and been persisted.
        if load_scan(scan_id) is not None:
            return {"scan_id": scan_id, "status": "completed", "progress": 1.0,
                    "message": "Loaded from history"}
        raise HTTPException(404, f"No scan with id {scan_id}")
    return job.to_dict()


@app.get("/api/scans/{scan_id}", tags=["scans"])
async def scan_result(scan_id: str) -> dict[str, Any]:
    """Fetch a completed scan result."""
    job = registry.get(scan_id)
    if job is not None and job.result is not None:
        return result_payload(job.result)

    stored = load_scan(scan_id)
    if stored is not None:
        return stored

    if job is not None:
        return JSONResponse(
            status_code=202,
            content={"scan_id": scan_id, "status": job.status, "message": job.message},
        )
    raise HTTPException(404, f"No scan with id {scan_id}")


@app.get("/api/scans/{scan_id}/report", tags=["scans"], response_class=HTMLResponse)
async def scan_report(scan_id: str) -> HTMLResponse:
    """Render a completed scan as a self-contained HTML report.

    Served inline rather than as a download so it can be viewed in a tab and
    printed to PDF from the browser.
    """
    from chainguard.reporting.html import render_report
    from chainguard.scanner import ScanResult

    job = registry.get(scan_id)
    result = job.result if job is not None else None

    if result is None:
        stored = load_scan(scan_id)
        if stored is None:
            raise HTTPException(404, f"No completed scan with id {scan_id}")
        try:
            result = ScanResult.model_validate(stored)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(500, f"Stored scan could not be rendered: {exc}") from exc

    return HTMLResponse(content=render_report(result))


@app.get("/api/scans", tags=["scans"])
async def scan_history(limit: int = 50) -> dict[str, Any]:
    """List previous scans, most recent first."""
    return {"scans": list_scans(min(max(limit, 1), 200))}


@app.delete("/api/scans/{scan_id}", tags=["scans"])
async def remove_scan(scan_id: str) -> dict[str, Any]:
    """Delete a stored scan."""
    registry.cancel(scan_id)
    if not delete_scan(scan_id):
        raise HTTPException(404, f"No scan with id {scan_id}")
    return {"deleted": scan_id}


# --------------------------------------------------------------------------- #
# AI assistant
# --------------------------------------------------------------------------- #


class ChatTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatTurn] = Field(min_length=1, max_length=60)
    scan_id: Optional[str] = None


@app.post("/api/assistant/chat", tags=["assistant"])
def assistant_chat(request: ChatRequest) -> StreamingResponse:
    """Chat with the analysis assistant. Streams newline-delimited JSON events."""
    if not assistant_available():
        raise HTTPException(
            503,
            "The AI consultant needs an OpenAI API key. Add OPENAI_API_KEY to the .env "
            "file in the repository root and restart the API.",
        )
    history = [turn.model_dump() for turn in request.messages]
    return StreamingResponse(
        run_chat(history, scan_id=request.scan_id),
        media_type="application/x-ndjson",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# --------------------------------------------------------------------------- #
# Known malware samples (quarantine vault)
# --------------------------------------------------------------------------- #


@app.get("/api/samples", tags=["samples"])
def list_samples(query: str = "", limit: int = 40) -> dict[str, Any]:
    """Real malicious packages stored (encrypted) in the local quarantine vault."""
    from chainguard.dataset.vault import SampleVault

    needle = query.strip().lower()
    records = [r for r in SampleVault().records() if r.label == "malicious"]
    matches = [r for r in records if not needle or needle in r.name.lower()]
    return {
        "total": len(records),
        "samples": [
            {"name": r.name, "version": r.version, "ecosystem": r.ecosystem, "source": r.source}
            for r in matches[: min(max(limit, 1), 200)]
        ],
    }


class SampleScanRequest(BaseModel):
    name: str
    ecosystem: Optional[str] = None


@app.post("/api/samples/scan", tags=["samples"])
def scan_sample(request: SampleScanRequest) -> dict[str, Any]:
    """Statically analyse one vault sample and return it as a one-package scan.

    The sample is decrypted into memory and parsed only — never executed. Vault
    samples are part of the training corpus, so this demonstrates the evidence
    and explanation pipeline on genuine malware; it is not a held-out accuracy
    measurement (the model card reports those).
    """
    import time as _time

    from chainguard.dataset.corpus import analyse_sample
    from chainguard.dataset.vault import SampleVault
    from chainguard.analysis.exposure import classify_exposure
    from chainguard.scanner import PackageFinding, ScanResult, _explain_flagged, _summarise, _to_exfiltration
    from chainguard.models.db import save_scan

    started = _time.time()
    vault = SampleVault()
    record = next(
        (
            r for r in vault.records()
            if r.label == "malicious" and r.name.lower() == request.name.strip().lower()
            and (not request.ecosystem or r.ecosystem.lower() == request.ecosystem.lower())
        ),
        None,
    )
    if record is None:
        raise HTTPException(404, f"No malicious sample named '{request.name}' in the vault")
    payload = vault.get(record.sample_id)
    analysis = analyse_sample(record, payload) if payload is not None else None
    if analysis is None:
        raise HTTPException(422, f"Sample '{request.name}' could not be decoded or has no analysable files")

    prediction = registry.classifier.predict(analysis.features, analysis.rules_score)
    finding = PackageFinding(
        name=record.name, version=record.version or "0.0.0", ecosystem=record.ecosystem,
        is_direct=True, required_by=["sample"],
        malice_score=round(prediction.probability, 4), verdict=prediction.verdict,
        score_source=prediction.source, top_contributors=prediction.top_contributors,
        typosquat_target=analysis.typosquat_target, files_analysed=analysis.files_analysed,
        signals=analysis.top_signals(12),
        exfiltration=[_to_exfiltration(classify_exposure(f, record.name, analyser=None))
                      for f in analysis.confirmed_flows],
    )
    _explain_flagged([finding])  # same hybrid review + explanation path as a real scan

    result = ScanResult(
        scan_id=uuid.uuid4().hex[:12], target=f"sample:{record.name}", ecosystem=record.ecosystem,
        started_at=started, packages=[finding],
        model_source="model" if registry.classifier.is_trained else "rules-baseline",
        warnings=[f"Known malware sample from {record.source}. It is part of the training corpus: "
                  "this shows the evidence pipeline on real malware, not a held-out accuracy result."],
    )
    _summarise(result)
    result.duration_seconds = round(_time.time() - started, 3)
    save_scan(result)
    return result_payload(result)
