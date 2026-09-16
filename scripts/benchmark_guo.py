"""Evaluate ChainGuard on the Guo et al. npm benchmark (ASE 2026).

Benchmark: "How Effective Are NPM Malicious Package Detectors? A Large-Scale
Empirical Study", replication package DOI 10.6084/m9.figshare.31869370
(CC BY 4.0): ~6,500 malicious and ~7,000 benign npm package versions, with the
per-package verdicts of 11 other tools.

Safety: the archive contains real malware. Packages are read from the zip into
memory and parsed statically; nothing is extracted to disk or executed.

Step 1 (featurize, slow, parallel) writes one feature vector per package to
benchmark_features.csv, resumable. Step 2 (score) applies any trained model to
those vectors and prints precision / recall / F1 next to the published tools.

Run:
  python scripts/benchmark_guo.py download-benign --labels C:/Benchmarks/labels.json
  python scripts/benchmark_guo.py featurize --zip C:/Benchmarks/NPMStudy_full.zip --labels C:/Benchmarks/labels.json
  python scripts/benchmark_guo.py score
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

REPO = Path(__file__).resolve().parents[1]
#: Working directory for the downloaded archive. Deliberately outside the repo:
#: it contains live malware and must never be committed (see docs/BENCHMARK.md).
OUT_DIR = Path(os.environ.get("CHAINGUARD_BENCHMARK_DIR", "C:/Benchmarks"))
FEATURES_CSV = OUT_DIR / "benchmark_features.csv"
#: Committed, malware-free copy: one 58-number feature row per package.
REPO_FEATURES_CSV = REPO / "data" / "benchmarks" / "guo2026_npm_features.csv"


BENIGN_DIR = OUT_DIR / "benign_tgz"


def _is_malicious(tags: list[str]) -> bool:
    return bool(set(tags) & {"malware", "malicious"})


def _npm_name(key: str) -> tuple[str, str]:
    """'@scope##name/1.0.0' -> ('@scope/name', '1.0.0')."""
    name, version = key.rsplit("/", 1)
    return name.replace("##", "/"), version


def malware_members(zip_path: str, labels: dict[str, list[str]]) -> dict[str, str]:
    """Label key -> zip member of the malware tarball."""
    z = zipfile.ZipFile(zip_path)
    out = {}
    for info in z.infolist():
        n = info.filename
        if not (n.startswith("NPMStudy/Dataset/zip_malware/") and n.endswith(".tgz")):
            continue
        key = "/".join(n.split("/")[3:5])
        if key in labels:
            out[key] = n
    return out


def benign_path(key: str) -> Path:
    return BENIGN_DIR / (re.sub(r"[^A-Za-z0-9._-]", "_", key) + ".tgz")


def download_benign(labels_path: str, concurrency: int = 16) -> int:
    """Fetch the benchmark's benign packages from the public npm registry."""
    import asyncio

    import httpx

    labels = json.loads(Path(labels_path).read_text())
    keys = [k for k, v in labels.items() if not _is_malicious(v) and not benign_path(k).exists()]
    BENIGN_DIR.mkdir(parents=True, exist_ok=True)
    print(f"{len(keys)} benign packages to download")
    failed: list[str] = []

    async def run() -> None:
        sem = asyncio.Semaphore(concurrency)
        async with httpx.AsyncClient(timeout=60, follow_redirects=True) as client:
            async def one(key: str) -> None:
                name, version = _npm_name(key)
                short = name.split("/")[-1]
                url = f"https://registry.npmjs.org/{name}/-/{short}-{version}.tgz"
                async with sem:
                    for attempt in range(3):
                        try:
                            r = await client.get(url)
                            if r.status_code == 200:
                                benign_path(key).write_bytes(r.content)
                                return
                            if r.status_code == 404:
                                break
                        except httpx.HTTPError:
                            await asyncio.sleep(1 + attempt)
                failed.append(key)

            for i in range(0, len(keys), 500):
                await asyncio.gather(*(one(k) for k in keys[i:i + 500]))
                print(f"  {min(i + 500, len(keys))}/{len(keys)} (unavailable {len(failed)})", flush=True)

    asyncio.run(run())
    (OUT_DIR / "benign_unavailable.txt").write_text("\n".join(failed))
    print(f"done; unavailable on npm: {len(failed)}")
    return 0


def _analyse(job: tuple[str, str, str | None]) -> tuple[str, list[float] | None, str]:
    zip_path, key, member = job
    try:
        import io
        import tarfile

        from chainguard.analysis.engine import analyse_package
        from chainguard.dataset.corpus import metadata_from_archive
        from chainguard.logging_setup import setup_logging
        from chainguard.models.package import Ecosystem, PackageContents, PackageFile, PackageRef

        setup_logging("ERROR")
        if member:  # malware: read the tarball from the benchmark zip, in memory
            if getattr(_analyse, "path", None) != zip_path:
                _analyse.zip, _analyse.path = zipfile.ZipFile(zip_path), zip_path
            payload = _analyse.zip.read(member)
        else:
            payload = benign_path(key).read_bytes()

        files: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
            for m in tar:
                if m.isfile() and m.size <= 2 * 1024 * 1024:
                    data = tar.extractfile(m)
                    path = m.name.replace("\\", "/")
                    files[path.split("/", 1)[1] if "/" in path else path] = data.read() if data else b""
        name, version = _npm_name(key)
        contents = PackageContents(
            ref=PackageRef(name=name, version=version, ecosystem=Ecosystem.NPM),
            metadata=metadata_from_archive(files, name, version, Ecosystem.NPM),
            files=[PackageFile(path=p, content=d) for p, d in files.items()],
        )
        return key, analyse_package(contents).features.to_vector(), ""
    except Exception as exc:  # noqa: BLE001
        return key, None, f"{type(exc).__name__}: {exc}"


def featurize(zip_path: str, labels_path: str, workers: int) -> int:
    from chainguard.analysis.features import FEATURE_NAMES

    labels = json.loads(Path(labels_path).read_text())
    mal = malware_members(zip_path, labels)
    jobs = [(zip_path, k, m) for k, m in mal.items()]
    jobs += [(zip_path, k, None) for k, v in labels.items() if not _is_malicious(v) and benign_path(k).exists()]
    print(f"{len(labels)} labelled; available: {len(mal)} malicious, {len(jobs) - len(mal)} benign")

    done: set[str] = set()
    if FEATURES_CSV.exists():
        with FEATURES_CSV.open(encoding="utf-8") as fh:
            done = {row["key"] for row in csv.DictReader(fh)}
    todo = [j for j in jobs if j[1] not in done]
    print(f"{len(done)} already featurized, {len(todo)} to go, {workers} workers")

    new_file = not FEATURES_CSV.exists()
    failures = 0
    with FEATURES_CSV.open("a", encoding="utf-8", newline="") as fh, ProcessPoolExecutor(workers) as pool:
        writer = csv.writer(fh)
        if new_file:
            writer.writerow(["key", "label", *FEATURE_NAMES])
        futures = [pool.submit(_analyse, job) for job in todo]
        for i, fut in enumerate(as_completed(futures), 1):
            key, vector, error = fut.result()
            if vector is None:
                failures += 1
            else:
                writer.writerow([key, 1 if _is_malicious(labels[key]) else 0, *vector])
            if i % 250 == 0:
                fh.flush()
                print(f"  {i}/{len(todo)} (failures {failures})", flush=True)
    print(f"done; failures {failures}")
    return 0


def published_results(small_zip: Path) -> dict[str, dict]:
    z = zipfile.ZipFile(small_zip)
    names = set(z.namelist())
    out: dict[str, dict] = {}
    for tool in ("guarddog", "sap_XGB", "sap_RF", "socketai", "ossgadget", "packj_static", "genie"):
        preds = {}
        for fname in ("malicious_reports", "false_negatives", "benign_reports", "false_positives"):
            path = f"NPMStudy/ToolDetection/DetectionResults/{tool}/{fname}.json"
            if path in names:
                for key, rec in json.loads(z.read(path)).items():
                    preds[key] = 1 if rec.get("prediction") in ("malware", "malicious") else 0
        out[tool] = preds
    return out


def metrics(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = len(y_true) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def score(model_path: str | None, threshold: float) -> int:
    import joblib
    import numpy as np

    from chainguard.config import get_settings

    source = FEATURES_CSV if FEATURES_CSV.exists() else REPO_FEATURES_CSV
    rows = list(csv.DictReader(source.open(encoding="utf-8")))
    keys = [r["key"] for r in rows]
    y = [int(r["label"]) for r in rows]
    from chainguard.analysis.features import FEATURE_NAMES

    X = np.asarray([[float(r[f]) for f in FEATURE_NAMES] for r in rows], dtype=float)
    model = joblib.load(model_path or get_settings().models_dir / "classifier.joblib")
    probs = model.predict_proba(X)[:, 1]
    ours = [int(p >= threshold) for p in probs]

    print(f"\nBenchmark packages featurized: {len(keys)} ({sum(y)} malicious, {len(y) - sum(y)} benign)")
    print(f"{'detector':<22} {'precision':>9} {'recall':>7} {'F1':>7}   TP / FP / FN / TN   (same {len(keys)} packages)")
    m = metrics(y, ours)
    print(f"{'ChainGuard (ours)':<22} {m['precision']:>9.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}   {m['tp']} / {m['fp']} / {m['fn']} / {m['tn']}")

    small = OUT_DIR / "NPMStudy_small.zip"
    committed = REPO / "data" / "benchmarks" / "guo2026_published_verdicts.json"
    published = published_results(small) if small.exists() else (
        json.loads(committed.read_text()) if committed.exists() else {})
    if published:
        for tool, preds in published.items():
            common = [i for i, k in enumerate(keys) if k in preds]
            m = metrics([y[i] for i in common], [preds[keys[i]] for i in common])
            print(f"{tool:<22} {m['precision']:>9.4f} {m['recall']:>7.4f} {m['f1']:>7.4f}   "
                  f"{m['tp']} / {m['fp']} / {m['fn']} / {m['tn']}   (n={len(common)})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("download-benign")
    d.add_argument("--labels", required=True)
    f = sub.add_parser("featurize")
    f.add_argument("--zip", required=True)
    f.add_argument("--labels", required=True)
    f.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    s = sub.add_parser("score")
    s.add_argument("--model", default=None)
    s.add_argument("--threshold", type=float, default=0.60)
    args = parser.parse_args()
    if args.cmd == "download-benign":
        return download_benign(args.labels)
    if args.cmd == "featurize":
        return featurize(args.zip, args.labels, args.workers)
    return score(args.model, args.threshold)


if __name__ == "__main__":
    raise SystemExit(main())
