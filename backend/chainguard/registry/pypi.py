"""PyPI registry client.

Fetches package metadata from the PyPI JSON API and downloads distributions.

**Source distributions are preferred over wheels.** A wheel is a built artifact
and has already discarded ``setup.py`` — which is precisely the file a malicious
PyPI package uses to execute code at install time. Analysing only wheels would
blind the detector to the most common Python supply-chain attack vector, so the
client falls back to a wheel only when no sdist was published.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion
from packaging.version import Version as PypiVersion

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import (
    Ecosystem,
    PackageContents,
    PackageMetadata,
    PackageRef,
)
from chainguard.registry.archive import ArchiveError, extract
from chainguard.registry.http import CachedHTTPClient, NotFoundError, RegistryError

logger = get_logger(__name__)


def _parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _repository_url(info: dict[str, Any]) -> Optional[str]:
    """Find a source-repository URL among PyPI's several possible locations."""
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for label, url in project_urls.items():
            if not isinstance(url, str):
                continue
            if any(k in label.lower() for k in ("source", "repository", "code", "github")):
                return url
    home_page = info.get("home_page")
    if isinstance(home_page, str) and re.search(r"github\.com|gitlab\.com|bitbucket\.org", home_page):
        return home_page
    return None


def _select_distribution(urls: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    """Choose which uploaded file to download and analyse.

    Preference order is sdist first (retains ``setup.py``), then a pure-Python
    wheel, then any wheel. See the module docstring for why this ordering is a
    detection requirement rather than a preference.
    """
    sdists = [u for u in urls if u.get("packagetype") == "sdist"]
    if sdists:
        return sdists[0]

    wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
    if not wheels:
        return urls[0] if urls else None

    for wheel in wheels:
        filename = str(wheel.get("filename", ""))
        if "py3-none-any" in filename or "py2.py3-none-any" in filename:
            return wheel
    return wheels[0]


class PyPIClient:
    """Read-only client for the PyPI JSON API."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http
        self.base_url = get_settings().pypi_url.rstrip("/")

    async def fetch_project(self, name: str) -> dict[str, Any]:
        """Fetch the top-level project document (all releases)."""
        url = f"{self.base_url}/pypi/{canonicalize_name(name)}/json"
        document = await self.http.get_json(url)
        if not isinstance(document, dict):
            raise RegistryError(f"Unexpected PyPI document shape for {name}")
        return document

    async def resolve_version(self, name: str, spec: str = "") -> str:
        """Resolve a PEP 440 specifier to a concrete published version."""
        project = await self.fetch_project(name)
        releases = project.get("releases") or {}

        # A release with no uploaded files cannot be analysed, so it is not a
        # valid resolution target even though PyPI still lists it.
        candidates: list[PypiVersion] = []
        for text, files in releases.items():
            if not files:
                continue
            try:
                candidates.append(PypiVersion(text))
            except InvalidVersion:
                continue

        if not candidates:
            latest = (project.get("info") or {}).get("version")
            if latest:
                return str(latest)
            raise NotFoundError(f"PyPI project {name} has no downloadable releases")

        spec = (spec or "").strip()
        if not spec:
            stable = [v for v in candidates if not v.is_prerelease]
            return str(max(stable or candidates))

        try:
            specifier = SpecifierSet(spec)
        except InvalidSpecifier:
            logger.debug("Unparseable specifier %r for %s; using latest", spec, name)
            stable = [v for v in candidates if not v.is_prerelease]
            return str(max(stable or candidates))

        matching = list(specifier.filter(candidates))
        if not matching:
            # Retry allowing prereleases before giving up — some projects only
            # ever publish prereleases.
            matching = list(specifier.filter(candidates, prereleases=True))
        if matching:
            return str(max(matching))

        stable = [v for v in candidates if not v.is_prerelease]
        return str(max(stable or candidates))

    async def fetch_metadata(self, name: str, spec: str = "") -> PackageMetadata:
        """Fetch metadata for the version of ``name`` satisfying ``spec``."""
        project = await self.fetch_project(name)
        version = await self._resolve_from_project(project, name, spec)

        info = project.get("info") or {}
        releases = project.get("releases") or {}
        urls = releases.get(version) or []
        if not isinstance(urls, list):
            urls = []

        # The top-level `info` block describes the *latest* release. When a
        # different version was resolved, re-fetch that version specifically so
        # metadata and contents actually correspond.
        if version != info.get("version"):
            try:
                versioned = await self.http.get_json(
                    f"{self.base_url}/pypi/{canonicalize_name(name)}/{version}/json"
                )
                if isinstance(versioned, dict):
                    info = versioned.get("info") or info
                    urls = versioned.get("urls") or urls
            except (RegistryError, NotFoundError):
                logger.debug("No per-version document for %s %s; using project info", name, version)

        distribution = _select_distribution(urls) or {}

        requires = info.get("requires_dist") or []
        dependency_names = self._runtime_dependency_names(requires)

        return PackageMetadata(
            name=name,
            version=version,
            ecosystem=Ecosystem.PYPI,
            description=info.get("summary"),
            author=info.get("author") or info.get("maintainer"),
            license=info.get("license") if isinstance(info.get("license"), str) else None,
            homepage=info.get("home_page") or info.get("package_url"),
            repository_url=_repository_url(info),
            published_at=_parse_time(distribution.get("upload_time_iso_8601")),
            # PyPI does not expose a maintainer list on the JSON API; treat a
            # named author/maintainer as one known maintainer.
            maintainer_count=1 if (info.get("author") or info.get("maintainer")) else 0,
            version_count=len(releases),
            dependency_names=dependency_names,
            install_scripts={},  # Python install-time execution lives in setup.py, not metadata
            dist_url=distribution.get("url"),
            dist_size=distribution.get("size"),
            raw={
                "requires_dist": requires,
                "packagetype": distribution.get("packagetype"),
                "filename": distribution.get("filename"),
                "yanked": distribution.get("yanked", False),
                "requires_python": info.get("requires_python"),
            },
        )

    async def _resolve_from_project(
        self, project: dict[str, Any], name: str, spec: str
    ) -> str:
        releases = project.get("releases") or {}
        candidates: list[PypiVersion] = []
        for text, files in releases.items():
            if not files:
                continue
            try:
                candidates.append(PypiVersion(text))
            except InvalidVersion:
                continue
        if not candidates:
            latest = (project.get("info") or {}).get("version")
            if latest:
                return str(latest)
            raise NotFoundError(f"PyPI project {name} has no downloadable releases")

        spec = (spec or "").strip()
        if spec:
            try:
                matching = list(SpecifierSet(spec).filter(candidates))
                if matching:
                    return str(max(matching))
            except InvalidSpecifier:
                pass
        stable = [v for v in candidates if not v.is_prerelease]
        return str(max(stable or candidates))

    @staticmethod
    def _runtime_dependency_names(requires_dist: list[Any]) -> list[str]:
        """Extract runtime dependency names from PEP 508 requirement strings.

        Requirements gated behind an ``extra`` marker are excluded: they are only
        installed when a consumer opts into that extra, so treating them as
        always-present would inflate the dependency graph with packages the
        project does not actually pull in.
        """
        names: set[str] = set()
        for raw in requires_dist:
            if not isinstance(raw, str):
                continue
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                continue
            if requirement.marker and "extra" in str(requirement.marker):
                continue
            names.add(canonicalize_name(requirement.name))
        return sorted(names)

    async def fetch_contents(self, metadata: PackageMetadata) -> PackageContents:
        """Download and extract a distribution into memory."""
        ref = metadata.ref
        if not metadata.dist_url:
            raise RegistryError(f"No distribution file published for {ref}")

        payload = await self.http.get_bytes(metadata.dist_url)
        filename = str(metadata.raw.get("filename") or metadata.dist_url)

        try:
            result = extract(payload, filename=filename)
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

    async def fetch_package(self, name: str, spec: str = "") -> PackageContents:
        """Convenience: resolve, fetch metadata, and download contents in one call."""
        metadata = await self.fetch_metadata(name, spec)
        return await self.fetch_contents(metadata)

    async def fetch_dependencies(self, ref: PackageRef) -> dict[str, str]:
        """Return runtime dependencies (name → specifier) for a specific version."""
        try:
            document = await self.http.get_json(
                f"{self.base_url}/pypi/{canonicalize_name(ref.name)}/{ref.version}/json"
            )
        except (RegistryError, NotFoundError):
            return {}
        if not isinstance(document, dict):
            return {}

        requires = (document.get("info") or {}).get("requires_dist") or []
        dependencies: dict[str, str] = {}
        for raw in requires:
            if not isinstance(raw, str):
                continue
            try:
                requirement = Requirement(raw)
            except InvalidRequirement:
                continue
            if requirement.marker and "extra" in str(requirement.marker):
                continue
            dependencies[canonicalize_name(requirement.name)] = str(requirement.specifier)
        return dependencies
