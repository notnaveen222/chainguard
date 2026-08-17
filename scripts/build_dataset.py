"""Build the labelled training dataset.

Downloads malicious samples from the DataDog research dataset and benign samples
from the live npm/PyPI registries, stores both encoded in the quarantine vault,
then analyses everything into a feature matrix written to ``data/corpus/``.

Safe to re-run: samples already in the vault are skipped, so an interrupted build
resumes rather than restarting.

Nothing downloaded here is ever executed. Malicious archives stay encrypted on
disk and are decrypted in memory only.

Run:  python scripts/build_dataset.py [--malicious N] [--benign N]
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
from pathlib import Path

#: Fixed so that a rebuild selects the same benign packages and the dataset is
#: reproducible.
BENIGN_SEED = 20260817

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from chainguard.analysis.features import FEATURE_NAMES  # noqa: E402
from chainguard.config import get_settings  # noqa: E402
from chainguard.dataset.corpus import build_matrix, matrix_summary  # noqa: E402
from chainguard.dataset.sources import (  # noqa: E402
    DATASET_LICENCE,
    DATASET_REPO,
    collect_benign,
    collect_malicious,
    load_popular_names,
)
from chainguard.dataset.vault import SampleVault  # noqa: E402
from chainguard.logging_setup import get_logger  # noqa: E402
from chainguard.models.package import Ecosystem  # noqa: E402
from chainguard.registry.http import CachedHTTPClient  # noqa: E402

logger = get_logger("build_dataset")


async def acquire(vault: SampleVault, malicious_per_eco: int, benign_per_eco: int) -> None:
    """Download samples into the vault."""
    async with CachedHTTPClient() as http:
        for ecosystem in (Ecosystem.PYPI, Ecosystem.NPM):
            logger.info("--- %s ---", ecosystem.display_name)

            stored = await collect_malicious(
                vault, http, ecosystem, limit=malicious_per_eco
            )
            logger.info("  malicious stored: %d", stored)

            # Sample across the whole popular list rather than taking a prefix.
            # The list is sorted alphabetically, so a prefix would return only
            # packages starting with "a" — a benign corpus biased by name rather
            # than representative of real library code.
            all_names = load_popular_names(ecosystem)
            # Deterministic sampling, not a security primitive — a fixed seed is
            # the point, so the dataset is reproducible.
            random.Random(BENIGN_SEED).shuffle(all_names)  # noqa: S311
            names = all_names[:benign_per_eco]
            stored = await collect_benign(vault, http, ecosystem, names)
            logger.info("  benign stored   : %d", stored)


def write_matrix(samples: list, output_dir: Path) -> tuple[Path, Path]:
    """Write the feature matrix and its metadata sidecar."""
    output_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = output_dir / "features.csv"
    meta_path = output_dir / "samples.jsonl"

    with matrix_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["sample_id", "label", "group", *FEATURE_NAMES])
        for sample in samples:
            writer.writerow([sample.sample_id, sample.label, sample.group, *sample.features])

    with meta_path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(
                json.dumps(
                    {
                        "sample_id": sample.sample_id,
                        "name": sample.name,
                        "version": sample.version,
                        "ecosystem": sample.ecosystem,
                        "label": sample.label,
                        "group": sample.group,
                        "signal_codes": sample.signal_codes,
                        "file_count": sample.file_count,
                        "source": sample.source,
                    }
                )
                + "\n"
            )

    return matrix_path, meta_path


async def main() -> int:
    parser = argparse.ArgumentParser(description="Build the ChainGuard training dataset")
    parser.add_argument("--malicious", type=int, default=450,
                        help="malicious samples per ecosystem (default: 450)")
    parser.add_argument("--benign", type=int, default=450,
                        help="benign samples per ecosystem (default: 450)")
    parser.add_argument("--skip-download", action="store_true",
                        help="analyse what is already in the vault, download nothing")
    args = parser.parse_args()

    settings = get_settings()
    vault = SampleVault()

    if not args.skip_download:
        logger.info("Acquiring samples (malicious source: %s, %s)", DATASET_REPO, DATASET_LICENCE)
        await acquire(vault, args.malicious, args.benign)

    logger.info("Vault contents: %s", vault.stats())

    logger.info("Verifying vault integrity...")
    ok, problems = vault.verify()
    logger.info("  %d samples verified", ok)
    if problems:
        # Reported rather than ignored: silently training on a shrunken dataset
        # is the exact failure this pipeline is designed to prevent.
        logger.warning("  %d samples are unreadable or corrupt:", len(problems))
        for problem in problems[:10]:
            logger.warning("    %s", problem)

    logger.info("Analysing samples into a feature matrix...")
    samples = build_matrix(vault)
    if not samples:
        logger.error("No samples could be analysed — nothing to write.")
        return 1

    summary = matrix_summary(samples)
    matrix_path, meta_path = write_matrix(samples, settings.corpus_dir)

    summary_path = settings.corpus_dir / "dataset_summary.json"
    summary["source_malicious"] = f"{DATASET_REPO} ({DATASET_LICENCE})"
    summary["source_benign"] = "live npm and PyPI registries"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    logger.info("--- dataset built ---")
    logger.info("  total     : %d samples (%d malicious, %d benign)",
                summary["total"], summary["malicious"], summary["benign"])
    logger.info("  balance   : %.1f%% malicious", summary["class_balance"] * 100)
    logger.info("  groups    : %d distinct package families", summary["distinct_groups"])
    logger.info("  by eco    : %s", summary["by_ecosystem"])
    logger.info("  features  : %d (%d zeroed to prevent leakage)",
                summary["feature_count"], len(summary["zeroed_features"]))
    logger.info("  matrix    : %s", matrix_path)
    logger.info("  metadata  : %s", meta_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
