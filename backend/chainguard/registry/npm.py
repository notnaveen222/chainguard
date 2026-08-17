"""npm registry client.

Fetches package metadata ("packuments") and tarballs from registry.npmjs.org,
and resolves semver ranges against the published version list.

The full packument is requested rather than the abbreviated
(``application/vnd.npm.install-v1+json``) form. The abbreviated document only
reports *whether* a package has install scripts, as a boolean; ChainGuard needs
the script bodies themselves, because ``postinstall`` command text is one of the
strongest malicious-package signals available. Responses are cached, so the
extra payload costs one download per package rather than one per scan.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from urllib.parse import quote

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import (
    Ecosystem,
    PackageContents,
    PackageMetadata,
    PackageRef,
)
from chainguard.registry import semver
from chainguard.registry.archive import ArchiveError, extract
from chainguard.registry.http import CachedHTTPClient, NotFoundError, RegistryError

logger = get_logger(__name__)

# npm lifecycle hooks that execute automatically on `npm install`. These are the
# hooks a malicious package abuses; `test`/`build` and friends require an
# explicit invocation and so carry far less weight.
AUTO_RUN_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


def _quote_name(name: str) -> str:
    """URL-encode a package name, preserving the ``@scope/name`` separator."""
    return quote(name, safe="@/") if name.startswith("@") else quote(name, safe="")


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _repository_url(entry: dict[str, Any]) -> Optional[str]:
    repo = entry.get("repository")
    if isinstance(repo, str):
        return repo or None
    if isinstance(repo, dict):
        url = repo.get("url")
        return url if isinstance(url, str) and url else None
    return None


def _author_name(entry: dict[str, Any]) -> Optional[str]:
    author = entry.get("author")
    if isinstance(author, str):
        return author or None
    if isinstance(author, dict):
        name = author.get("name")
        return name if isinstance(name, str) else None
    return None


class NpmClient:
    """Read-only client for the npm registry."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http
        self.base_url = get_settings().npm_registry_url.rstrip("/")

    async def fetch_packument(self, name: str) -> dict[str, Any]:
        """Fetch the full registry document for a package."""
        url = f"{self.base_url}/{_quote_name(name)}"
        document = await self.http.get_json(url)
        if not isinstance(document, dict):
            raise RegistryError(f"Unexpected packument shape for {name}")
        return document

    async def resolve_version(self, name: str, spec: str = "latest") -> str:
        """Resolve a version range to a concrete published version.

        Falls back to the ``latest`` dist-tag when the specifier is a dist-tag,
        an unsupported protocol (``git:``, ``file:``, ``npm:``), or simply
        unparseable — which is the same thing npm effectively does for a user.
        """
        packument = await self.fetch_packument(name)
        dist_tags = packument.get("dist-tags") or {}
        versions = list((packument.get("versions") or {}).keys())

        if not versions:
            raise NotFoundError(f"npm package {name} has no published versions")

        spec = (spec or "latest").strip()

        if spec in dist_tags:
            return str(dist_tags[spec])
        if spec in versions:
            return spec

        if any(spec.startswith(p) for p in ("git", "file:", "npm:", "link:", "workspace:")):
            logger.debug("Unsupported specifier %r for %s; using latest", spec, name)
            return str(dist_tags.get("latest") or semver.sort_versions(versions)[-1])

        resolved = semver.max_satisfying(versions, spec)
        if resolved:
            return resolved

        fallback = dist_tags.get("latest")
        if fallback:
            logger.debug("Range %r unsatisfiable for %s; using latest %s", spec, name, fallback)
            return str(fallback)
        return semver.sort_versions(versions)[-1]

    async def fetch_metadata(self, name: str, spec: str = "latest") -> PackageMetadata:
        """Fetch metadata for the version of ``name`` satisfying ``spec``."""
        packument = await self.fetch_packument(name)
        versions = packument.get("versions") or {}
        dist_tags = packument.get("dist-tags") or {}

        version = await self._resolve_from_packument(packument, name, spec)
        entry = versions.get(version)
        if not isinstance(entry, dict):
            raise NotFoundError(f"npm package {name}@{version} not found")

        times = packument.get("time") or {}
        maintainers = packument.get("maintainers") or []
        dist = entry.get("dist") or {}
        scripts = entry.get("scripts") or {}

        install_scripts = {
            hook: str(body)
            for hook, body in scripts.items()
            if hook in AUTO_RUN_SCRIPTS and body
        }

        dependencies = entry.get("dependencies") or {}

        return PackageMetadata(
            name=name,
            version=version,
            ecosystem=Ecosystem.NPM,
            description=entry.get("description"),
            author=_author_name(entry),
            license=entry.get("license") if isinstance(entry.get("license"), str) else None,
            homepage=entry.get("homepage") if isinstance(entry.get("homepage"), str) else None,
            repository_url=_repository_url(entry),
            published_at=_parse_time(times.get(version)),
            maintainer_count=len(maintainers) if isinstance(maintainers, list) else 0,
            version_count=len(versions),
            dependency_names=sorted(dependencies.keys()) if isinstance(dependencies, dict) else [],
            install_scripts=install_scripts,
            dist_url=dist.get("tarball"),
            dist_size=dist.get("unpackedSize"),
            raw={
                "dist_tags": dist_tags,
                "dependencies": dependencies,
                "scripts": scripts,
                "deprecated": entry.get("deprecated"),
            },
        )

    async def _resolve_from_packument(
        self, packument: dict[str, Any], name: str, spec: str
    ) -> str:
        """Version resolution against an already-fetched packument."""
        dist_tags = packument.get("dist-tags") or {}
        versions = list((packument.get("versions") or {}).keys())
        if not versions:
            raise NotFoundError(f"npm package {name} has no published versions")

        spec = (spec or "latest").strip()
        if spec in dist_tags:
            return str(dist_tags[spec])
        if spec in versions:
            return spec
        resolved = semver.max_satisfying(versions, spec)
        if resolved:
            return resolved
        return str(dist_tags.get("latest") or semver.sort_versions(versions)[-1])

    async def fetch_contents(self, metadata: PackageMetadata) -> PackageContents:
        """Download and extract a package tarball into memory."""
        ref = metadata.ref
        if not metadata.dist_url:
            raise RegistryError(f"No tarball URL published for {ref}")

        try:
            payload = await self.http.get_bytes(metadata.dist_url)
        except NotFoundError:
            raise NotFoundError(f"Tarball missing for {ref}") from None

        try:
            result = extract(payload, filename=metadata.dist_url)
        except ArchiveError as exc:
            logger.warning("Could not extract %s: %s", ref, exc)
            return PackageContents(
                ref=ref, metadata=metadata, files=[], truncated=True, truncation_reason=str(exc)
            )

        return PackageContents(
            ref=ref,
            metadata=metadata,
            files=result.files,
            truncated=result.truncated,
            truncation_reason=result.reason,
        )

    async def fetch_package(self, name: str, spec: str = "latest") -> PackageContents:
        """Convenience: resolve, fetch metadata, and download contents in one call."""
        metadata = await self.fetch_metadata(name, spec)
        return await self.fetch_contents(metadata)

    async def fetch_dependencies(self, ref: PackageRef) -> dict[str, str]:
        """Return the runtime dependencies (name → range) of a specific version.

        Only runtime dependencies are walked. ``devDependencies`` are not
        installed by consumers of a package, so including them would inflate the
        graph with packages that never reach a production environment.
        """
        packument = await self.fetch_packument(ref.name)
        entry = (packument.get("versions") or {}).get(ref.version)
        if not isinstance(entry, dict):
            return {}
        dependencies = entry.get("dependencies")
        if not isinstance(dependencies, dict):
            return {}
        return {str(k): str(v) for k, v in dependencies.items()}
