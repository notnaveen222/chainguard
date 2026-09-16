"""Real-world false-positive check for classifier variants.

Cross-validation only measures the model against its own training corpora. This
script measures what users actually see: it takes the packages from real,
completed scans of legitimate projects (stored in the scan history), re-analyses
each one from the registry cache, and counts how many every model variant would
flag. Every package in these projects is a normal published dependency, so each
flag is treated as a false positive (and listed, so that can be checked).

Run:  python scripts/evaluate_realworld.py [scan_id ...]
      (defaults to every completed scan in history, de-duplicated by package)
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import numpy as np  # noqa: E402

from chainguard.analysis.engine import analyse_package  # noqa: E402
from chainguard.config import get_settings  # noqa: E402
from chainguard.ml.train import load_dataset, train_final  # noqa: E402
from chainguard.models.db import list_scans, load_scan  # noqa: E402
from chainguard.registry.http import CachedHTTPClient  # noqa: E402
from chainguard.registry.npm import NpmClient  # noqa: E402
from chainguard.registry.pypi import PyPIClient  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from experiment_features import VARIANTS, zeroed  # noqa: E402

MALICIOUS, SUSPICIOUS = 0.60, 0.30
CACHE = get_settings().corpus_dir / "realworld_features.json"


async def featurize(packages: list[tuple[str, str, str]]) -> dict[str, list[float]]:
    cached: dict[str, list[float]] = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    todo = [p for p in packages if "|".join(p) not in cached]
    semaphore = asyncio.Semaphore(8)

    async with CachedHTTPClient() as http:
        npm, pypi = NpmClient(http), PyPIClient(http)

        async def one(eco: str, name: str, version: str) -> None:
            try:
                async with semaphore:
                    if eco == "npm":
                        meta = await npm.fetch_metadata(name, version)
                        contents = await npm.fetch_contents(meta)
                    else:
                        meta = await pypi.fetch_metadata(name, f"=={version}")
                        contents = await pypi.fetch_contents(meta)
                if not contents.files:
                    return
                analysis = await asyncio.to_thread(analyse_package, contents)
                cached["|".join((eco, name, version))] = analysis.features.to_vector()
            except Exception as exc:  # noqa: BLE001 — unavailable packages are skipped, as in a scan
                print(f"  skip {name}@{version}: {type(exc).__name__}")

        await asyncio.gather(*(one(*p) for p in todo))

    CACHE.write_text(json.dumps(cached))
    return {"|".join(p): cached["|".join(p)] for p in packages if "|".join(p) in cached}


def main() -> int:
    scan_ids = sys.argv[1:] or [s["scan_id"] for s in list_scans(200) if s.get("status") == "completed"]
    packages: set[tuple[str, str, str]] = set()
    for scan_id in scan_ids:
        data = load_scan(scan_id)
        for p in (data or {}).get("packages") or []:
            if p.get("files_analysed"):
                packages.add((p["ecosystem"], p["name"], p["version"]))
    packages_list = sorted(packages)
    print(f"{len(packages_list)} distinct analysable packages from {len(scan_ids)} scans; featurizing...")

    vectors = asyncio.run(featurize(packages_list))
    keys = list(vectors)
    X = np.asarray([vectors[k] for k in keys], dtype=float)
    print(f"{len(keys)} packages featurized\n")

    dataset = load_dataset(get_settings().corpus_dir / "features.csv")
    print(f"{'variant':<26} {'malicious (>=0.60)':>18} {'suspicious (0.30-0.60)':>23}")
    report = {}
    for label, names in VARIANTS.items():
        model, _ = train_final(zeroed(dataset, names))
        Xv = X.copy()
        for name in names:
            Xv[:, dataset.feature_names.index(name)] = 0.0
        scores = model.predict_proba(Xv)[:, 1]
        mal = [(keys[i], round(float(s), 3)) for i, s in enumerate(scores) if s >= MALICIOUS]
        sus = [(keys[i], round(float(s), 3)) for i, s in enumerate(scores) if SUSPICIOUS <= s < MALICIOUS]
        report[label] = {"malicious": sorted(mal, key=lambda x: -x[1]), "suspicious": sorted(sus, key=lambda x: -x[1])}
        print(f"{label:<26} {len(mal):>18} {len(sus):>23}")

    out = get_settings().corpus_dir / "realworld_report.json"
    out.write_text(json.dumps({"packages": len(keys), "variants": report}, indent=2))
    print(f"\nFlag lists written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
