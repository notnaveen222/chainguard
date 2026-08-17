"""A focused semantic-version implementation for resolving npm version ranges.

Why hand-rolled: the published Python semver packages either do not implement
npm's range grammar (``^``, ``~``, ``x`` wildcards, hyphen ranges, ``||`` unions)
or pull in heavy dependencies. ChainGuard needs exactly one operation — given a
range and a registry's list of published versions, pick the version npm would
install — so a compact implementation covering npm's actual grammar is both
smaller and easier to test than adapting a general-purpose library.

Deliberately not supported: build metadata ordering (npm ignores it too) and
``file:`` / ``git:`` / ``npm:`` protocol specifiers, which are resolved by
falling back to the registry's ``latest`` tag.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Optional

_VERSION_RE = re.compile(
    r"^\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?\s*$"
)


@total_ordering
@dataclass(frozen=True)
class Version:
    """A parsed semantic version."""

    major: int
    minor: int
    patch: int
    prerelease: tuple[str | int, ...] = ()
    raw: str = ""

    @classmethod
    def parse(cls, text: str) -> Optional[Version]:
        match = _VERSION_RE.match(text or "")
        if not match:
            return None
        major, minor, patch, pre, _build = match.groups()
        identifiers: tuple[str | int, ...] = ()
        if pre:
            identifiers = tuple(
                int(part) if part.isdigit() else part for part in pre.split(".")
            )
        return cls(
            major=int(major),
            minor=int(minor or 0),
            patch=int(patch or 0),
            prerelease=identifiers,
            raw=text.strip(),
        )

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def __str__(self) -> str:
        return self.raw or f"{self.major}.{self.minor}.{self.patch}"

    def _core(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._core() == other._core() and self.prerelease == other.prerelease

    def __lt__(self, other: Version) -> bool:
        if self._core() != other._core():
            return self._core() < other._core()
        # SemVer §11: a version with a prerelease sorts *before* its release.
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and other.prerelease:
            return False
        # Shortest-wins is deliberate: SemVer §11 compares identifiers pairwise
        # over the common prefix, then breaks ties on length. `strict=` would be
        # wrong here.
        for mine, theirs in zip(self.prerelease, other.prerelease):
            if mine == theirs:
                continue
            # Numeric identifiers always sort below alphanumeric ones.
            if isinstance(mine, int) and isinstance(theirs, int):
                return mine < theirs
            if isinstance(mine, int):
                return True
            if isinstance(theirs, int):
                return False
            return str(mine) < str(theirs)
        return len(self.prerelease) < len(other.prerelease)


@dataclass(frozen=True)
class Comparator:
    """A single ``<operator><version>`` constraint."""

    operator: str
    version: Version

    def matches(self, candidate: Version) -> bool:
        if self.operator == "=":
            return candidate == self.version
        if self.operator == ">":
            return candidate > self.version
        if self.operator == ">=":
            return candidate >= self.version
        if self.operator == "<":
            return candidate < self.version
        if self.operator == "<=":
            return candidate <= self.version
        return False


def _bump_major(v: Version) -> Version:
    return Version(v.major + 1, 0, 0)


def _bump_minor(v: Version) -> Version:
    return Version(v.major, v.minor + 1, 0)


def _expand_caret(text: str) -> list[Comparator]:
    """``^1.2.3`` → ``>=1.2.3 <2.0.0``; ``^0.2.3`` → ``>=0.2.3 <0.3.0``.

    The 0.x special case matters: npm treats pre-1.0 minor bumps as potentially
    breaking, so ``^0.2.3`` must not float to 0.3.0.
    """
    base = Version.parse(text)
    if base is None:
        return []
    if base.major > 0:
        upper = _bump_major(base)
    elif base.minor > 0:
        upper = _bump_minor(base)
    else:
        upper = Version(0, 0, base.patch + 1)
    return [Comparator(">=", base), Comparator("<", upper)]


def _expand_tilde(text: str) -> list[Comparator]:
    """``~1.2.3`` → ``>=1.2.3 <1.3.0`` (patch-level float)."""
    base = Version.parse(text)
    if base is None:
        return []
    return [Comparator(">=", base), Comparator("<", _bump_minor(base))]


def _expand_wildcard(text: str) -> list[Comparator]:
    """``1.2.x`` → ``>=1.2.0 <1.3.0``; ``1.x`` → ``>=1.0.0 <2.0.0``."""
    cleaned = text.strip().rstrip(".")
    parts = cleaned.split(".")
    numeric: list[int] = []
    for part in parts:
        if part in {"x", "X", "*", ""}:
            break
        if not part.isdigit():
            return []
        numeric.append(int(part))

    if not numeric:
        return [Comparator(">=", Version(0, 0, 0))]
    if len(numeric) == 1:
        lower = Version(numeric[0], 0, 0)
        return [Comparator(">=", lower), Comparator("<", _bump_major(lower))]
    lower = Version(numeric[0], numeric[1], 0)
    return [Comparator(">=", lower), Comparator("<", _bump_minor(lower))]


_OPERATOR_RE = re.compile(r"^(>=|<=|>|<|=)\s*(.+)$")


def _parse_comparator_set(text: str) -> list[Comparator]:
    """Parse a space-separated conjunction of constraints (an AND group)."""
    text = text.strip()
    if not text or text in {"*", "x", "X", "latest", ""}:
        return [Comparator(">=", Version(0, 0, 0))]

    # Hyphen range: "1.2.3 - 2.3.4" (inclusive on both ends).
    if " - " in text:
        low_text, _, high_text = text.partition(" - ")
        low, high = Version.parse(low_text), Version.parse(high_text)
        if low and high:
            return [Comparator(">=", low), Comparator("<=", high)]
        return []

    comparators: list[Comparator] = []
    for token in text.split():
        token = token.strip()
        if not token:
            continue
        if token.startswith("^"):
            comparators.extend(_expand_caret(token[1:]))
        elif token.startswith("~"):
            comparators.extend(_expand_tilde(token[1:].lstrip(">")))
        elif "x" in token.lower() or token.endswith("*"):
            comparators.extend(_expand_wildcard(token))
        else:
            match = _OPERATOR_RE.match(token)
            if match:
                operator, version_text = match.groups()
                parsed = Version.parse(version_text)
                if parsed:
                    comparators.append(Comparator(operator, parsed))
            else:
                parsed = Version.parse(token)
                if parsed:
                    comparators.append(Comparator("=", parsed))
    return comparators


class Range:
    """An npm version range: a union (``||``) of conjunctive comparator sets."""

    def __init__(self, spec: str) -> None:
        self.spec = (spec or "*").strip()
        self._groups = [
            group for group in (_parse_comparator_set(part) for part in self.spec.split("||"))
        ]
        # A spec we could not parse at all matches nothing, so callers fall back
        # to the registry's `latest` tag rather than silently picking a version.
        self.parseable = any(self._groups)

    def matches(self, candidate: Version) -> bool:
        for group in self._groups:
            if group and all(comparator.matches(candidate) for comparator in group):
                return True
        return False

    def __repr__(self) -> str:
        return f"Range({self.spec!r})"


def max_satisfying(versions: list[str], spec: str, *, allow_prerelease: bool = False) -> Optional[str]:
    """Return the highest published version satisfying ``spec``.

    Prereleases are excluded unless explicitly requested or unless the range
    pins one exactly — matching npm's behaviour, where ``^1.0.0`` will not
    install ``2.0.0-beta.1``.
    """
    version_range = Range(spec)
    if not version_range.parseable:
        return None

    best: Optional[Version] = None
    for text in versions:
        parsed = Version.parse(text)
        if parsed is None:
            continue
        if parsed.is_prerelease and not allow_prerelease and spec.strip() != text.strip():
            continue
        if not version_range.matches(parsed):
            continue
        if best is None or parsed > best:
            best = parsed

    return best.raw if best else None


def sort_versions(versions: list[str]) -> list[str]:
    """Sort version strings in ascending semantic order, dropping unparseable ones."""
    parsed = [v for v in (Version.parse(text) for text in versions) if v is not None]
    return [v.raw for v in sorted(parsed)]
