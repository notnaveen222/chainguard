# ⚠️ QUARANTINE DIRECTORY — READ BEFORE TOUCHING ANYTHING HERE

This directory holds **malicious package samples** used as labelled training data
for the ChainGuard classifier. They come from published academic malware
registries and are real, previously in-the-wild attacks.

## How they are stored

Samples are **encoded at rest**. Nothing in this directory is a runnable source
file. Each sample is stored as an opaque encoded blob plus a metadata record, and
is decoded **into memory only**, at feature-extraction time, then discarded.

Two reasons for this, both deliberate (see `BUILD_LOG.md`, decision D-005):

1. **No antivirus exclusion is required.** Because plaintext malicious source is
   never written to disk, Windows Defender never flags it, so no security setting
   on the machine had to be weakened.
2. **Nothing here can be executed by accident.** The files are not valid
   JavaScript or Python as stored.

## Rules

- **Never** run `pip install`, `npm install`, or any other install command in or
  against this directory.
- **Never** decode a sample to disk. The decode path in
  `chainguard/dataset/vault.py` returns bytes in memory and has no
  write-to-disk mode, by design.
- **Never** commit this directory. It is gitignored (only this README is tracked).
- ChainGuard itself never executes these samples under any code path. All
  analysis is static — parsing source text into an AST and counting patterns.

## If your antivirus flags something anyway

It should not, because of the encoding. If it does, let it quarantine the file
and re-run `scripts/build_dataset.py`, which will skip anything unreadable and
log the gap rather than training on a silently truncated dataset.

## Provenance

Sample sources, licences, and counts are recorded in `docs/DATASET.md` and in the
dataset manifest written alongside the samples.
