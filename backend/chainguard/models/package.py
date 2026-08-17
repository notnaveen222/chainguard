"""Core domain types shared across every layer of ChainGuard.

These are deliberately plain data carriers. Behaviour lives in the layers that
consume them (``registry``, ``analysis``, ``vulns``); keeping the types inert
means the analysis engine, the API and the training pipeline can all agree on
one vocabulary without depending on each other.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


class Ecosystem(str, Enum):
    """A package registry ecosystem.

    Values match the identifiers OSV.dev uses, so they can be passed straight
    through to advisory queries without translation.
    """

    NPM = "npm"
    PYPI = "PyPI"

    @property
    def display_name(self) -> str:
        return {Ecosystem.NPM: "npm", Ecosystem.PYPI: "PyPI"}[self]

    @property
    def manifest_files(self) -> tuple[str, ...]:
        """Manifest filenames that indicate a project of this ecosystem."""
        return {
            Ecosystem.NPM: ("package.json", "package-lock.json"),
            Ecosystem.PYPI: ("requirements.txt", "pyproject.toml", "setup.py"),
        }[self]

    @property
    def source_extensions(self) -> tuple[str, ...]:
        """File extensions whose contents this ecosystem's analyser understands."""
        return {
            Ecosystem.NPM: (".js", ".mjs", ".cjs", ".ts", ".json"),
            Ecosystem.PYPI: (".py", ".pyi", ".cfg", ".toml"),
        }[self]


class PackageRef(BaseModel):
    """A specific package at a specific version."""

    name: str
    version: str
    ecosystem: Ecosystem

    def __hash__(self) -> int:
        return hash((self.ecosystem, self.name.lower(), self.version))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PackageRef):
            return NotImplemented
        return (
            self.ecosystem == other.ecosystem
            and self.name.lower() == other.name.lower()
            and self.version == other.version
        )

    def __str__(self) -> str:
        return f"{self.name}@{self.version} ({self.ecosystem.display_name})"

    @property
    def key(self) -> str:
        """Stable identifier usable as a dict key or cache filename component."""
        return f"{self.ecosystem.value}:{self.name.lower()}:{self.version}"


class PackageFile(BaseModel):
    """One file extracted from a package distribution.

    ``content`` is held in memory. Package archives are never expanded to disk —
    see ARCHITECTURE.md §5.
    """

    path: str = Field(description="Path relative to the package root, POSIX separators.")
    content: bytes = Field(repr=False)

    model_config = {"arbitrary_types_allowed": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def size(self) -> int:
        return len(self.content)

    @property
    def suffix(self) -> str:
        _, _, ext = self.path.rpartition(".")
        return f".{ext.lower()}" if ext and ext != self.path else ""

    @property
    def basename(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    def text(self, errors: str = "replace") -> str:
        """Decode the file as UTF-8 text.

        Errors are replaced rather than raised: malicious packages frequently
        contain deliberately malformed bytes, and a decode failure must degrade
        to partial analysis rather than aborting the scan.
        """
        return self.content.decode("utf-8", errors=errors)


class PackageMetadata(BaseModel):
    """Registry-published metadata about a package version.

    Every field is optional because registry records are inconsistent in practice
    — and *absence* is itself a useful signal. A package with no repository, no
    description and one maintainer looks materially different from an established
    one, which is exactly what the metadata analyser measures.
    """

    name: str
    version: str
    ecosystem: Ecosystem

    description: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    published_at: Optional[datetime] = None

    maintainer_count: int = 0
    version_count: int = 0
    dependency_names: list[str] = Field(default_factory=list)

    # npm lifecycle hooks — `postinstall` and friends are the single most common
    # execution vector for malicious npm packages, so they are captured verbatim.
    install_scripts: dict[str, str] = Field(default_factory=dict)

    # Distribution download location, resolved at metadata-fetch time.
    dist_url: Optional[str] = None
    dist_size: Optional[int] = None

    raw: dict[str, Any] = Field(default_factory=dict, repr=False)

    @property
    def ref(self) -> PackageRef:
        return PackageRef(name=self.name, version=self.version, ecosystem=self.ecosystem)

    @property
    def age_days(self) -> Optional[float]:
        """Days since publication, or ``None`` if the registry gave no date."""
        if self.published_at is None:
            return None
        published = self.published_at
        if published.tzinfo is None:
            published = published.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - published).total_seconds() / 86400.0

    @property
    def has_repository(self) -> bool:
        return bool(self.repository_url)


class PackageContents(BaseModel):
    """A downloaded, in-memory package distribution ready for static analysis."""

    ref: PackageRef
    metadata: Optional[PackageMetadata] = None
    files: list[PackageFile] = Field(default_factory=list, repr=False)

    # Set when ingestion hit a configured ceiling, so downstream consumers know
    # the analysis was partial rather than clean.
    truncated: bool = False
    truncation_reason: Optional[str] = None

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def file_count(self) -> int:
        return len(self.files)

    def by_extension(self, *extensions: str) -> list[PackageFile]:
        wanted = {e.lower() for e in extensions}
        return [f for f in self.files if f.suffix in wanted]

    def find(self, basename: str) -> Optional[PackageFile]:
        """Return the shallowest file with the given basename, if present.

        Shallowest wins because package archives commonly nest their real root
        one level down (``package/`` for npm, ``name-version/`` for sdists), and
        vendored copies of the same filename sit deeper.
        """
        matches = [f for f in self.files if f.basename == basename]
        if not matches:
            return None
        return min(matches, key=lambda f: f.path.count("/"))


class DependencyNode(BaseModel):
    """One node in a resolved dependency tree."""

    ref: PackageRef
    depth: int = Field(description="0 for a direct dependency of the scanned project.")
    is_direct: bool = False
    required_by: list[str] = Field(
        default_factory=list,
        description="Names of packages that depend on this one.",
    )
    requested_range: Optional[str] = Field(
        default=None, description="The version specifier that led here, e.g. '^4.17.0'."
    )

    @property
    def is_transitive(self) -> bool:
        return not self.is_direct


class DependencyGraph(BaseModel):
    """The resolved dependency set for a scanned project."""

    ecosystem: Ecosystem
    root_name: str = "project"
    nodes: dict[str, DependencyNode] = Field(default_factory=dict)

    # Populated when resolution stopped early against a configured ceiling.
    truncated: bool = False
    truncation_reason: Optional[str] = None
    unresolved: list[str] = Field(
        default_factory=list,
        description="Requirements that could not be resolved, with the reason.",
    )

    def add(self, node: DependencyNode) -> None:
        """Insert a node, keeping the shallowest occurrence of a package.

        A package can be reached by many paths at different depths. Depth feeds
        risk weighting (a direct dependency is more your problem than one buried
        five levels down), so the shallowest reach is the correct one to keep.
        """
        existing = self.nodes.get(node.ref.key)
        if existing is None:
            self.nodes[node.ref.key] = node
            return
        if node.depth < existing.depth:
            node.required_by = sorted(set(existing.required_by) | set(node.required_by))
            node.is_direct = existing.is_direct or node.is_direct
            self.nodes[node.ref.key] = node
        else:
            existing.required_by = sorted(set(existing.required_by) | set(node.required_by))
            existing.is_direct = existing.is_direct or node.is_direct

    @property
    def all_refs(self) -> list[PackageRef]:
        return [n.ref for n in self.nodes.values()]

    @property
    def direct(self) -> list[DependencyNode]:
        return [n for n in self.nodes.values() if n.is_direct]

    @property
    def transitive(self) -> list[DependencyNode]:
        return [n for n in self.nodes.values() if not n.is_direct]

    @property
    def max_depth(self) -> int:
        return max((n.depth for n in self.nodes.values()), default=0)

    def __len__(self) -> int:
        return len(self.nodes)
