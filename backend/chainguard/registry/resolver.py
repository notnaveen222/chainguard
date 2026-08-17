"""Transitive dependency resolution.

Walks a parsed manifest breadth-first against the live registries to produce the
full set of packages a project actually pulls in.

Breadth-first rather than depth-first is deliberate: it reaches every package by
its *shallowest* path first, and depth feeds risk weighting — a direct dependency
is more the developer's problem than one buried five levels down. BFS also makes
the ceilings meaningful, since truncating a BFS drops the deepest and least
relevant packages rather than an arbitrary subtree.
"""

from __future__ import annotations

from typing import Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import (
    DependencyGraph,
    DependencyNode,
    Ecosystem,
    PackageRef,
)
from chainguard.registry.http import CachedHTTPClient, NotFoundError, RegistryError
from chainguard.registry.manifest import ParsedManifest
from chainguard.registry.npm import NpmClient
from chainguard.registry.pypi import PyPIClient

logger = get_logger(__name__)


class DependencyResolver:
    """Resolves a manifest into a full transitive dependency graph."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http
        self.npm = NpmClient(http)
        self.pypi = PyPIClient(http)
        self.limits = get_settings().limits

    async def resolve(
        self,
        manifest: ParsedManifest,
        *,
        include_dev: bool = False,
        max_depth: Optional[int] = None,
        progress: Optional[callable] = None,
    ) -> DependencyGraph:
        """Resolve ``manifest`` into a :class:`DependencyGraph`."""
        max_depth = max_depth if max_depth is not None else self.limits.max_dependency_depth
        graph = DependencyGraph(
            ecosystem=manifest.ecosystem, root_name=manifest.project_name
        )

        requirements = dict(manifest.requirements)
        if include_dev:
            requirements.update(manifest.dev_requirements)
        if not requirements:
            graph.unresolved.append("Manifest declares no dependencies")
            return graph

        # A lockfile means versions are already decided; resolving ranges again
        # could pick something the developer does not actually have installed.
        if manifest.has_lockfile:
            logger.info(
                "Lockfile present — using %d pinned versions", len(manifest.locked)
            )
            return await self._resolve_from_lockfile(manifest, graph, include_dev)

        # Level 0: the project's direct dependencies.
        frontier = await self._resolve_level(
            manifest.ecosystem,
            [(name, spec) for name, spec in requirements.items()],
            depth=0,
            required_by=manifest.project_name,
            graph=graph,
            is_direct=True,
        )
        if progress:
            progress(len(graph), max_depth)

        # Levels 1..max_depth: transitive closure.
        depth = 1
        while frontier and depth <= max_depth:
            if len(graph) >= self.limits.max_packages_per_scan:
                graph.truncated = True
                graph.truncation_reason = (
                    f"reached the {self.limits.max_packages_per_scan}-package ceiling "
                    f"at depth {depth}"
                )
                logger.warning("Resolution truncated: %s", graph.truncation_reason)
                break

            next_frontier: list[PackageRef] = []
            dependency_sets = await self.http.gather(
                [self._dependencies_of(ref) for ref in frontier],
                concurrency=8,
            )

            for ref, dependencies in zip(frontier, dependency_sets):
                if isinstance(dependencies, Exception):
                    graph.unresolved.append(f"{ref.name}: {dependencies}")
                    continue
                resolved = await self._resolve_level(
                    manifest.ecosystem,
                    list(dependencies.items()),
                    depth=depth,
                    required_by=ref.name,
                    graph=graph,
                    is_direct=False,
                )
                next_frontier.extend(resolved)

            frontier = next_frontier
            if progress:
                progress(len(graph), max_depth)
            depth += 1

        if depth > max_depth and frontier:
            graph.truncated = True
            graph.truncation_reason = f"stopped at the configured depth limit of {max_depth}"

        logger.info(
            "Resolved %d packages (%d direct, max depth %d)",
            len(graph),
            len(graph.direct),
            graph.max_depth,
        )
        return graph

    # ------------------------------------------------------------------ #

    async def _resolve_from_lockfile(
        self, manifest: ParsedManifest, graph: DependencyGraph, include_dev: bool
    ) -> DependencyGraph:
        """Build a graph directly from pinned lockfile versions.

        Depth information is not recoverable from a flat lockfile, so every
        package is recorded at depth 0. Packages that also appear in the
        manifest's own dependency list are marked direct; the rest are
        transitive but of unknown depth.
        """
        pinned = dict(manifest.locked)
        if include_dev:
            pinned.update(manifest.dev_requirements)

        direct_names = {n.lower() for n in manifest.requirements}
        for name, version in pinned.items():
            if len(graph) >= self.limits.max_packages_per_scan:
                graph.truncated = True
                graph.truncation_reason = (
                    f"lockfile exceeds the {self.limits.max_packages_per_scan}-package ceiling"
                )
                break
            graph.add(
                DependencyNode(
                    ref=PackageRef(name=name, version=version, ecosystem=manifest.ecosystem),
                    depth=0,
                    is_direct=name.lower() in direct_names,
                    required_by=[manifest.project_name],
                    requested_range=manifest.requirements.get(name),
                )
            )
        return graph

    async def _resolve_level(
        self,
        ecosystem: Ecosystem,
        requirements: list[tuple[str, str]],
        *,
        depth: int,
        required_by: str,
        graph: DependencyGraph,
        is_direct: bool,
    ) -> list[PackageRef]:
        """Resolve one level of requirements to concrete versions."""
        if not requirements:
            return []

        # Skip anything already in the graph — BFS guarantees the existing entry
        # was reached at an equal or shallower depth.
        pending = [
            (name, spec)
            for name, spec in requirements
            if not self._already_present(graph, ecosystem, name)
        ]
        for name, _ in requirements:
            existing = self._find_node(graph, ecosystem, name)
            if existing and required_by not in existing.required_by:
                existing.required_by.append(required_by)

        if not pending:
            return []

        results = await self.http.gather(
            [self._resolve_one(ecosystem, name, spec) for name, spec in pending],
            concurrency=8,
        )

        newly_added: list[PackageRef] = []
        for (name, spec), result in zip(pending, results):
            if isinstance(result, Exception):
                reason = "not found" if isinstance(result, NotFoundError) else str(result)
                graph.unresolved.append(f"{name}{spec or ''}: {reason}")
                logger.debug("Could not resolve %s%s: %s", name, spec, reason)
                continue
            graph.add(
                DependencyNode(
                    ref=result,
                    depth=depth,
                    is_direct=is_direct,
                    required_by=[required_by],
                    requested_range=spec or None,
                )
            )
            newly_added.append(result)

        return newly_added

    async def _resolve_one(self, ecosystem: Ecosystem, name: str, spec: str) -> PackageRef:
        """Resolve a single ``name``/``spec`` pair to a concrete version."""
        if ecosystem is Ecosystem.NPM:
            version = await self.npm.resolve_version(name, spec or "latest")
        else:
            version = await self.pypi.resolve_version(name, spec or "")
        return PackageRef(name=name, version=version, ecosystem=ecosystem)

    async def _dependencies_of(self, ref: PackageRef) -> dict[str, str]:
        """Fetch the runtime dependencies of a resolved package."""
        try:
            if ref.ecosystem is Ecosystem.NPM:
                return await self.npm.fetch_dependencies(ref)
            return await self.pypi.fetch_dependencies(ref)
        except (RegistryError, NotFoundError) as exc:
            logger.debug("Could not fetch dependencies of %s: %s", ref, exc)
            return {}

    @staticmethod
    def _find_node(
        graph: DependencyGraph, ecosystem: Ecosystem, name: str
    ) -> Optional[DependencyNode]:
        lowered = name.lower()
        for node in graph.nodes.values():
            if node.ref.ecosystem is ecosystem and node.ref.name.lower() == lowered:
                return node
        return None

    @classmethod
    def _already_present(
        cls, graph: DependencyGraph, ecosystem: Ecosystem, name: str
    ) -> bool:
        return cls._find_node(graph, ecosystem, name) is not None


async def resolve_manifest(
    manifest: ParsedManifest,
    *,
    include_dev: bool = False,
    http: Optional[CachedHTTPClient] = None,
) -> DependencyGraph:
    """Convenience wrapper that manages the HTTP client lifecycle."""
    if http is not None:
        return await DependencyResolver(http).resolve(manifest, include_dev=include_dev)
    async with CachedHTTPClient() as client:
        return await DependencyResolver(client).resolve(manifest, include_dev=include_dev)


__all__ = ["DependencyResolver", "resolve_manifest"]
