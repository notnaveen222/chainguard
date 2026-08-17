# Dataset

How ChainGuard's training data is assembled, where it comes from, and what its
limitations are.

Rebuild with:

```bash
python scripts/build_dataset.py --malicious 450 --benign 450
```

Re-analyse an existing vault without re-downloading:

```bash
python scripts/build_dataset.py --skip-download
```

---

## 1. Sources

| Class | Source | Licence | Count |
|---|---|---|---|
| Malicious | [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | Apache-2.0 | 448 PyPI + 450 npm |
| Benign | Live npm and PyPI registries | various (upstream) | 450 PyPI + 449 npm |

**Total: 1,797 samples**, approximately balanced across both class and ecosystem.

### Why this malicious source

It is real, published, curated, permissively licensed, and covers both target
ecosystems. Every sample is a package that was actually caught attacking users.
The alternative considered, `lxyeternal/pypi_malregistry`, is PyPI-only,
unlicensed, and stores samples as plain tarballs.

Critically, DataDog ships its samples as **password-encrypted ZIP archives**
(password `infected`) — the dataset's own convention for keeping malware inert on
disk. ChainGuard preserves that property end to end: the archive is decrypted in
memory only, and the vault re-encodes it before anything is written.

### Why the benign corpus is real packages

Negative examples are genuine popular packages downloaded from the live
registries, sampled across the whole popular-package list with a fixed seed.

This matters more than it might appear. The classifier's job is to separate
malware from **real library code** — which is full of network calls, subprocess
invocation, dynamic imports, minified bundles and `eval`. A benign corpus of
hand-written "clean" examples would produce a model that scores beautifully in
evaluation and collapses on the first real scan.

An early version took a prefix of the alphabetically-sorted list, which returned
only packages beginning with "a". Now shuffled with a fixed seed so the sample is
representative and the build stays reproducible.

---

## 2. Storage: the quarantine vault

All samples live in `data/quarantine/`, **encoded at rest**. See
`backend/chainguard/dataset/vault.py` and `data/quarantine/README.md`.

Two reasons, and the second is the one that actually drove the design:

1. No antivirus exclusion is required. Because plaintext malicious source is
   never written to disk, Windows Defender never flags it, so no security setting
   on the machine had to be weakened.
2. More importantly, Defender would otherwise have quarantined samples **silently
   and mid-build**. An unattended overnight dataset build would have lost samples
   partway through and trained on a truncated corpus with nothing obviously
   failing.

**This is obfuscation, not cryptography.** The key is a constant in the source
file. The threat model is an antivirus scanner or a careless double-click, not an
attacker with disk access — who can also read the key.

The security property that actually matters does not depend on the encoding:
**no code path in this project executes a sample.** Analysis is static parsing of
source text. There is no `pip install`, no `npm install`, no `setup.py`
invocation, and no `eval` of package content anywhere in the codebase.

The build verifies every stored sample by hash before analysis. Training on a
silently shrinking dataset is the exact failure this design exists to prevent, so
a corrupt blob is reported loudly rather than skipped.

---

## 3. Preventing label leakage

**This is the most important methodological decision in the project.**

Malicious samples come from an archive. Those packages were removed from npm and
PyPI years ago, so no live registry metadata exists for them: no publication
date, no version count, no maintainer list. Benign samples are fetched live and
have all of it.

Feeding registry metadata to the classifier would let `version_count > 0`
separate the two classes perfectly — not because it detects malware, but because
it detects **which corpus a sample came from**. The model would report
near-perfect metrics and be worthless on real input. Worse, the failure would be
invisible: the numbers would simply look excellent.

Two countermeasures, both enforced in code rather than by convention:

1. **Metadata is reconstructed only from inside the archive** — from the
   `package.json` or `PKG-INFO` the package itself ships. Both classes are
   treated identically, and the available fields are exactly the fields an
   attacker also controls.
2. **Registry-only features are zeroed for every training sample**, inside
   `corpus.build_matrix`, so no caller can bypass it:

   `age_days`, `version_count`, `maintainer_count`, `is_single_version`,
   `is_very_new`

   They remain in the schema and are still populated at **scan** time, where the
   information is real and symmetric across all packages.

The cost is that the model cannot learn "this package was published yesterday" as
evidence. That is the correct trade: a feature available for only one class in
training is not a feature, it is the label.

A related fix: `SINGLE_VERSION` was firing on 100% of **both** classes, because
archive-derived metadata always reports a version count of 0. The signal now
distinguishes 0 ("unknown") from 1 ("genuinely a single version").

---

## 4. Grouped splitting

Splits are grouped by package name using `StratifiedGroupKFold`. Different
versions of one package, and repeat uploads from a single attack campaign, never
appear on both sides of a split.

Without grouping, a near-duplicate of a test sample sits in the training set and
every reported score is inflated. This one choice is the difference between an
honest number and a flattering one. Only one archive per package is downloaded in
the first place, for the same reason.

---

## 5. Known limitations

Stated plainly, because a dataset's limitations bound every claim made from it.

- **Temporal skew.** Malicious samples are historical (mostly 2022–2024);
  benign samples are current. Some separability may come from era-specific coding
  style rather than intent. Mitigated by excluding registry metadata, but not
  eliminated.
- **Survivorship in the malicious set.** These are packages that were *caught*.
  Malware sophisticated enough to evade detection is, by construction, absent —
  so real-world recall is likely lower than reported recall.
- **Benign corpus is popular packages.** Widely-used libraries are better
  maintained and better structured than the long tail of the registry. The false
  positive rate on obscure but legitimate packages will be higher than measured.
- **Class balance is artificial.** The corpus is roughly 50/50; a real registry
  is closer to 1-in-10,000 malicious. This is why PR-AUC leads over accuracy, and
  why precision at deployment scale would be lower than measured here.
- **Analysis timeouts.** A small number of very large packages (`litellm`,
  `notebook`) exceed the 60-second per-package analysis ceiling and are recorded
  as truncated. Their feature vectors are partial.
- **npm sample tree is truncated by GitHub.** The dataset holds 47,406 npm
  packages; the GitHub trees API returns roughly 61,670 entries before
  truncating, so selection samples from that prefix rather than the full set.
  This is logged at build time rather than passed off as a complete listing.

---

## 6. Outputs

| File | Contents |
|---|---|
| `data/corpus/features.csv` | The feature matrix: `sample_id`, `label`, `group`, then one column per feature |
| `data/corpus/samples.jsonl` | Per-sample metadata: name, version, ecosystem, signal codes, provenance |
| `data/corpus/dataset_summary.json` | Counts, class balance, group count, zeroed features |
| `data/quarantine/index.jsonl` | Vault index — one record per stored sample |

None of these are committed; `data/` is gitignored. Rebuild them with the
commands at the top of this document.
