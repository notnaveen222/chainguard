"""Typosquat detection.

A typosquat is a package deliberately named to be installed by mistake —
``reqeusts`` for ``requests``, ``crossenv`` for ``cross-env``, ``python-dateutil``
re-published as ``python-dateutils``. The attack costs nothing and works because
a single mistyped character in a manifest is invisible in review.

Detection is edit distance against a list of popular packages, with three
refinements that matter in practice:

1. **Keyboard adjacency weighting.** ``reqeusts`` (adjacent-key transposition) is
   a far more plausible typo than ``reqzests``. Substitutions between keys that
   sit next to each other cost less than distant ones.
2. **Homoglyph awareness.** ``1odash`` vs ``lodash`` is one substitution by edit
   distance but visually near-identical, so it is scored as a distinct and more
   severe category.
3. **Structural variants.** Separator swaps (``-``/``_``/``.``), added or removed
   suffixes (``-js``, ``.js``, ``2``), and scope manipulation are enumerated
   directly rather than left to edit distance, because they are exact-match
   tricks rather than typos.

The popular-package list is the ground truth, and a package *on* that list is
never flagged — ``lodash`` is not a typosquat of itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from chainguard.models.package import Ecosystem

_DATA_FILE = Path(__file__).resolve().parent / "data" / "popular_packages.json"

# Keys physically adjacent on a QWERTY keyboard. Used to weight substitutions:
# a typo is usually a neighbouring key, not a random one.
_ADJACENCY: dict[str, str] = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
    "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
    "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
    "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
    "z": "asx", "-": "_", "_": "-", ".": "-",
}

# Characters that render similarly to one another.
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "l": "1", "o": "0", "5": "s", "s": "5",
    "2": "z", "z": "2", "8": "b", "b": "8", "rn": "m", "vv": "w",
}

# Suffixes and prefixes attackers append to an otherwise-correct name.
_AFFIXES = (
    "js", "-js", ".js", "node", "-node", "py", "-py", "python", "-python",
    "2", "3", "-cli", "cli", "-core", "core", "lib", "-lib", "new", "-new",
    "official", "-official", "dev", "-dev", "es", "-es",
)


@dataclass
class TyposquatMatch:
    """A resemblance between a package name and a popular package."""

    candidate: str
    target: str
    distance: float
    kind: str  # "near_miss" | "homoglyph" | "separator" | "affix" | "scope"
    explanation: str


def _normalise(name: str) -> str:
    return name.strip().lower()


def _strip_scope(name: str) -> str:
    """``@scope/pkg`` → ``pkg``."""
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def _substitution_cost(a: str, b: str) -> float:
    """Cost of substituting ``a`` for ``b``, lowered for adjacent keys."""
    if a == b:
        return 0.0
    if b in _ADJACENCY.get(a, ""):
        return 0.6
    return 1.0


def weighted_damerau_levenshtein(source: str, target: str, ceiling: float = 3.0) -> float:
    """Damerau-Levenshtein distance with keyboard-aware substitution costs.

    Transpositions cost 0.6 rather than 1.0: swapping two adjacent characters
    (``reqeusts``) is the most common typing error there is, so it should rank as
    a closer match than an arbitrary insertion.

    ``ceiling`` allows early exit — callers only care about small distances, and
    abandoning a comparison once the best possible score exceeds the ceiling
    avoids the full matrix for obviously unrelated names.
    """
    if source == target:
        return 0.0
    len_source, len_target = len(source), len(target)
    if abs(len_source - len_target) > ceiling:
        return ceiling + 1.0
    if not source:
        return float(len_target)
    if not target:
        return float(len_source)

    previous_previous: list[float] = []
    previous = [float(i) for i in range(len_target + 1)]

    for i in range(1, len_source + 1):
        current = [float(i)] + [0.0] * len_target
        row_best = current[0]
        for j in range(1, len_target + 1):
            deletion = previous[j] + 1.0
            insertion = current[j - 1] + 1.0
            substitution = previous[j - 1] + _substitution_cost(source[i - 1], target[j - 1])
            best = min(deletion, insertion, substitution)

            if (
                i > 1
                and j > 1
                and source[i - 1] == target[j - 2]
                and source[i - 2] == target[j - 1]
            ):
                best = min(best, previous_previous[j - 2] + 0.6)

            current[j] = best
            row_best = min(row_best, best)

        if row_best > ceiling:
            return ceiling + 1.0

        previous_previous = previous
        previous = current

    return previous[len_target]


def _homoglyph_variants(name: str) -> set[str]:
    """Names reachable from ``name`` by one visually-confusable substitution."""
    variants: set[str] = set()
    for index, char in enumerate(name):
        replacement = _HOMOGLYPHS.get(char)
        if replacement:
            variants.add(name[:index] + replacement + name[index + 1:])
    for pair, single in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        if pair in name:
            variants.add(name.replace(pair, single, 1))
        if single in name:
            variants.add(name.replace(single, pair, 1))
    return variants


def _separator_variants(name: str) -> set[str]:
    """Names differing only in separator characters."""
    stripped = name.replace("-", "").replace("_", "").replace(".", "")
    return {stripped, name.replace("-", "_"), name.replace("_", "-"), name.replace(".", "-")}


def _affix_variants(name: str) -> set[str]:
    """Names produced by adding or removing a common affix."""
    variants: set[str] = set()
    for affix in _AFFIXES:
        if name.endswith(affix) and len(name) > len(affix) + 2:
            variants.add(name[: -len(affix)].rstrip("-._"))
        variants.add(f"{name}{affix}")
        variants.add(f"{name}-{affix}")
    return {v for v in variants if v}


@lru_cache(maxsize=2)
def _popular_index(ecosystem: Ecosystem) -> tuple[frozenset[str], dict[int, tuple[str, ...]]]:
    """Load popular names, plus a length-bucketed index for fast prefiltering.

    Comparing every scanned package against every popular name is O(n·m) string
    comparisons. Bucketing by length lets the search skip names that cannot be
    within the distance ceiling, which is most of them.
    """
    try:
        document = json.loads(_DATA_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return frozenset(), {}

    names = [_normalise(n) for n in document.get(ecosystem.value, []) if n]
    buckets: dict[int, list[str]] = {}
    for name in names:
        buckets.setdefault(len(_strip_scope(name)), []).append(name)

    return frozenset(names), {k: tuple(v) for k, v in buckets.items()}


def popular_names(ecosystem: Ecosystem) -> frozenset[str]:
    """The set of known-popular package names for an ecosystem."""
    return _popular_index(ecosystem)[0]


def find_typosquat(
    name: str, ecosystem: Ecosystem, *, max_distance: float = 2.0
) -> Optional[TyposquatMatch]:
    """Return the closest popular-package resemblance, or ``None``.

    Returns ``None`` immediately for a package that *is* on the popular list —
    ``lodash`` is not a typosquat of ``lodash``.
    """
    known, buckets = _popular_index(ecosystem)
    if not known:
        return None

    normalised = _normalise(name)
    if normalised in known:
        return None

    bare = _strip_scope(normalised)
    if not bare or len(bare) < 3:
        return None

    # --- exact-match tricks, checked before edit distance ------------------- #

    # Scope confusion: "@scope/pkg" published as "scope-pkg", or an unscoped
    # popular name re-published under a scope.
    if normalised.startswith("@"):
        if bare in known or any(k.endswith(f"/{bare}") for k in known):
            return TyposquatMatch(
                candidate=name, target=bare, distance=0.0, kind="scope",
                explanation=f"Scoped package reproduces the popular name '{bare}'",
            )
    else:
        scoped = [k for k in known if k.startswith("@") and _strip_scope(k) == bare]
        if scoped:
            return TyposquatMatch(
                candidate=name, target=scoped[0], distance=0.0, kind="scope",
                explanation=f"Reproduces scoped package '{scoped[0]}' without its scope",
            )

    for variant in _homoglyph_variants(bare):
        if variant in known or f"@{variant}" in known:
            return TyposquatMatch(
                candidate=name, target=variant, distance=0.5, kind="homoglyph",
                explanation=(
                    f"Visually confusable with '{variant}' — differs only by "
                    "characters that render alike"
                ),
            )

    for variant in _separator_variants(bare):
        if variant != bare and variant in known:
            return TyposquatMatch(
                candidate=name, target=variant, distance=0.5, kind="separator",
                explanation=f"Differs from '{variant}' only in separator characters",
            )

    for variant in _affix_variants(bare):
        if variant in known:
            return TyposquatMatch(
                candidate=name, target=variant, distance=1.0, kind="affix",
                explanation=f"'{variant}' with an added or removed suffix",
            )

    # --- weighted edit distance over length-plausible candidates ------------ #
    best: Optional[TyposquatMatch] = None
    span = int(max_distance) + 1
    for length in range(len(bare) - span, len(bare) + span + 1):
        for candidate in buckets.get(length, ()):
            candidate_bare = _strip_scope(candidate)
            distance = weighted_damerau_levenshtein(bare, candidate_bare, ceiling=max_distance)
            if distance > max_distance or distance == 0.0:
                continue
            # Short names are excluded: at four characters, almost everything is
            # within distance 2 of something popular, and the result is noise.
            if len(candidate_bare) < 5:
                continue
            if best is None or distance < best.distance:
                best = TyposquatMatch(
                    candidate=name,
                    target=candidate,
                    distance=distance,
                    kind="near_miss",
                    explanation=(
                        f"Within edit distance {distance:.1f} of the popular package "
                        f"'{candidate}'"
                    ),
                )
    return best


def is_popular(name: str, ecosystem: Ecosystem) -> bool:
    """True if ``name`` is itself a well-known package."""
    return _normalise(name) in popular_names(ecosystem)
