"""Manifest and lockfile parsing.

Turns the file a developer actually has — ``package.json``, ``requirements.txt``,
``package-lock.json``, ``pyproject.toml`` — into a normalised set of
requirements the resolver can walk.

Lockfiles are preferred whenever one is present. A lockfile records the exact
versions that are actually installed, whereas a manifest records ranges that
must be re-resolved and may not match what the developer is running. For a
security scan that distinction matters: reporting on a version the user does not
have is a false result in both directions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from packaging.utils import canonicalize_name

from chainguard.logging_setup import get_logger
from chainguard.models.package import Ecosystem

logger = get_logger(__name__)


class ManifestError(ValueError):
    """The manifest could not be parsed."""


@dataclass
class ParsedManifest:
    """Normalised requirements extracted from a project manifest."""

    ecosystem: Ecosystem
    project_name: str = "project"
    source_file: str = ""

    #: Declared requirements: name → version range/specifier.
    requirements: dict[str, str] = field(default_factory=dict)

    #: Exact versions from a lockfile, when one was supplied: name → version.
    #: These take precedence over ``requirements`` during resolution.
    locked: dict[str, str] = field(default_factory=dict)

    #: Development-only requirements, tracked separately so they can be scanned
    #: on request but excluded from production risk scoring by default.
    dev_requirements: dict[str, str] = field(default_factory=dict)

    warnings: list[str] = field(default_factory=list)

    @property
    def has_lockfile(self) -> bool:
        return bool(self.locked)

    @property
    def total_declared(self) -> int:
        return len(self.requirements)


# --------------------------------------------------------------------------- #
# npm
# --------------------------------------------------------------------------- #


def parse_package_json(text: str, source_file: str = "package.json") -> ParsedManifest:
    """Parse an npm ``package.json``."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"Invalid JSON in {source_file}: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError(f"{source_file} is not a JSON object")

    manifest = ParsedManifest(
        ecosystem=Ecosystem.NPM,
        project_name=str(document.get("name") or "project"),
        source_file=source_file,
    )

    for key, target in (
        ("dependencies", manifest.requirements),
        ("optionalDependencies", manifest.requirements),
        ("devDependencies", manifest.dev_requirements),
    ):
        section = document.get(key)
        if isinstance(section, dict):
            for name, spec in section.items():
                target[str(name)] = str(spec)

    # peerDependencies are the consumer's responsibility to install, not this
    # project's, so they are recorded as a warning rather than resolved.
    peers = document.get("peerDependencies")
    if isinstance(peers, dict) and peers:
        manifest.warnings.append(
            f"{len(peers)} peerDependencies declared and not scanned "
            "(installed by the consuming project, not this one)"
        )

    return manifest


def parse_package_lock(text: str, source_file: str = "package-lock.json") -> ParsedManifest:
    """Parse an npm ``package-lock.json`` (lockfile v1, v2 or v3)."""
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"Invalid JSON in {source_file}: {exc}") from exc
    if not isinstance(document, dict):
        raise ManifestError(f"{source_file} is not a JSON object")

    manifest = ParsedManifest(
        ecosystem=Ecosystem.NPM,
        project_name=str(document.get("name") or "project"),
        source_file=source_file,
    )

    # Lockfile v2/v3: a flat "packages" map keyed by install path.
    packages = document.get("packages")
    if isinstance(packages, dict):
        for install_path, entry in packages.items():
            if not isinstance(entry, dict) or not install_path:
                continue  # "" is the root project itself
            name = entry.get("name") or _name_from_lock_path(install_path)
            version = entry.get("version")
            if not name or not version:
                continue
            if entry.get("dev") or entry.get("devOptional"):
                manifest.dev_requirements[str(name)] = str(version)
            else:
                manifest.locked[str(name)] = str(version)

    # Lockfile v1: a nested "dependencies" tree.
    if not manifest.locked:
        _walk_lock_v1(document.get("dependencies"), manifest)

    if manifest.locked:
        manifest.requirements = dict(manifest.locked)
    return manifest


def _name_from_lock_path(install_path: str) -> str:
    """Derive a package name from a lockfile install path.

    ``node_modules/@scope/pkg/node_modules/dep`` → ``dep``: the segment after the
    final ``node_modules`` is the package, and a leading ``@scope`` rejoins it.
    """
    parts = install_path.split("node_modules/")
    tail = parts[-1].strip("/")
    if not tail:
        return ""
    segments = tail.split("/")
    if segments[0].startswith("@") and len(segments) >= 2:
        return f"{segments[0]}/{segments[1]}"
    return segments[0]


def _walk_lock_v1(node: Any, manifest: ParsedManifest, depth: int = 0) -> None:
    if not isinstance(node, dict) or depth > 20:
        return
    for name, entry in node.items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        if version:
            if entry.get("dev"):
                manifest.dev_requirements[str(name)] = str(version)
            else:
                manifest.locked[str(name)] = str(version)
        _walk_lock_v1(entry.get("dependencies"), manifest, depth + 1)


# --------------------------------------------------------------------------- #
# PyPI
# --------------------------------------------------------------------------- #

# Lines that configure pip rather than declare a requirement.
_PIP_OPTION_PREFIXES = (
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-i", "--index-url", "--extra-index-url", "--find-links", "-f",
    "--no-index", "--pre", "--trusted-host", "--hash", "--only-binary",
    "--no-binary", "--prefer-binary", "--use-feature", "--no-deps",
)

_REQUIREMENT_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)"          # distribution name
    r"(?:\[(?P<extras>[^\]]*)\])?"            # optional extras
    r"\s*(?P<spec>(?:[<>=!~^]=?[^;#,\s]*)(?:\s*,\s*[<>=!~^]=?[^;#,\s]*)*)?"
    r"\s*(?:;(?P<marker>[^#]*))?"
)


def parse_requirements_txt(text: str, source_file: str = "requirements.txt") -> ParsedManifest:
    """Parse a pip ``requirements.txt``.

    Handles pinned versions, ranges, extras, environment markers, comments, line
    continuations, and pip option lines. URL and VCS requirements are recorded as
    warnings rather than silently dropped — an unscanned dependency the user
    believes was scanned is worse than a visible gap.
    """
    manifest = ParsedManifest(ecosystem=Ecosystem.PYPI, source_file=source_file)

    # Join backslash continuations before parsing.
    joined = re.sub(r"\\\s*\n", " ", text)

    for raw_line in joined.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith(_PIP_OPTION_PREFIXES) or line.startswith("-"):
            if line.startswith(("-r", "--requirement")):
                manifest.warnings.append(f"Nested requirements file not followed: {line}")
            continue

        if re.match(r"^[a-zA-Z]+\+?[a-zA-Z]*://", line) or line.startswith("git+"):
            manifest.warnings.append(f"URL/VCS requirement not resolvable from PyPI: {line}")
            continue

        match = _REQUIREMENT_RE.match(line)
        if not match or not match.group("name"):
            manifest.warnings.append(f"Unparseable requirement line: {line}")
            continue

        name = canonicalize_name(match.group("name"))
        spec = (match.group("spec") or "").strip()
        marker = (match.group("marker") or "").strip()

        # Requirements gated on an extra are conditional; keep them out of the
        # main set for the same reason the PyPI client does.
        if marker and "extra" in marker:
            manifest.dev_requirements[name] = spec
            continue

        manifest.requirements[name] = spec
        if re.fullmatch(r"==\s*[^,\s]+", spec or ""):
            manifest.locked[name] = spec.lstrip("= ").strip()

    return manifest


def parse_pyproject(text: str, source_file: str = "pyproject.toml") -> ParsedManifest:
    """Parse a PEP 621 ``pyproject.toml`` (with Poetry fallback)."""
    try:
        document = tomllib.loads(text)
    except Exception as exc:  # tomllib raises TOMLDecodeError
        raise ManifestError(f"Invalid TOML in {source_file}: {exc}") from exc

    manifest = ParsedManifest(ecosystem=Ecosystem.PYPI, source_file=source_file)

    project = document.get("project")
    if isinstance(project, dict):
        manifest.project_name = str(project.get("name") or "project")
        for raw in project.get("dependencies") or []:
            if not isinstance(raw, str):
                continue
            match = _REQUIREMENT_RE.match(raw)
            if match and match.group("name"):
                manifest.requirements[canonicalize_name(match.group("name"))] = (
                    match.group("spec") or ""
                ).strip()

        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                for raw in group or []:
                    if not isinstance(raw, str):
                        continue
                    match = _REQUIREMENT_RE.match(raw)
                    if match and match.group("name"):
                        manifest.dev_requirements[canonicalize_name(match.group("name"))] = (
                            match.group("spec") or ""
                        ).strip()

    # Poetry keeps dependencies elsewhere and uses its own caret syntax.
    poetry = ((document.get("tool") or {}).get("poetry")) or {}
    if isinstance(poetry, dict) and poetry.get("dependencies"):
        manifest.project_name = str(poetry.get("name") or manifest.project_name)
        for name, spec in (poetry.get("dependencies") or {}).items():
            if str(name).lower() == "python":
                continue
            manifest.requirements[canonicalize_name(str(name))] = (
                str(spec) if isinstance(spec, str) else ""
            )

    return manifest


# --------------------------------------------------------------------------- #
# Dispatch
# --------------------------------------------------------------------------- #

_PARSERS = {
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject,
}


def parse_manifest(text: str, filename: str) -> ParsedManifest:
    """Parse manifest ``text`` according to its filename."""
    basename = Path(filename).name
    parser = _PARSERS.get(basename)

    if parser is None:
        # Requirements files are often named e.g. `requirements-dev.txt`.
        if basename.endswith(".txt") and "require" in basename.lower():
            parser = parse_requirements_txt
        elif basename.endswith(".json"):
            parser = parse_package_lock if "lock" in basename else parse_package_json
        elif basename.endswith(".toml"):
            parser = parse_pyproject
        else:
            raise ManifestError(f"Unrecognised manifest type: {basename}")

    return parser(text, basename)


def detect_project_manifests(project_dir: Path) -> list[Path]:
    """Find manifest files in a project directory, preferring lockfiles.

    Returns at most one manifest per ecosystem: whichever gives the most precise
    picture of what is actually installed.
    """
    found: list[Path] = []

    # npm: lockfile wins over package.json.
    for candidate in ("package-lock.json", "package.json"):
        path = project_dir / candidate
        if path.is_file():
            found.append(path)
            break

    # PyPI: an all-pinned requirements.txt is effectively a lockfile.
    for candidate in ("requirements.txt", "pyproject.toml"):
        path = project_dir / candidate
        if path.is_file():
            found.append(path)
            break

    return found


def load_manifest(path: Path) -> ParsedManifest:
    """Read and parse a manifest file from disk."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ManifestError(f"Could not read {path}: {exc}") from exc
    return parse_manifest(text, path.name)


def merge_manifests(manifests: list[ParsedManifest]) -> Optional[ParsedManifest]:
    """Merge manifests of the same ecosystem (e.g. package.json + its lockfile)."""
    if not manifests:
        return None
    if len(manifests) == 1:
        return manifests[0]

    base = manifests[0]
    for other in manifests[1:]:
        if other.ecosystem != base.ecosystem:
            continue
        base.requirements.update(other.requirements)
        base.locked.update(other.locked)
        base.dev_requirements.update(other.dev_requirements)
        base.warnings.extend(other.warnings)
    return base
