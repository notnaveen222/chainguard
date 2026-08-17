"""Shared HTTP client with on-disk response caching and retry.

Caching here is a correctness requirement rather than an optimisation. A scan of
a real project issues several hundred registry and advisory requests; without a
cache, a live demo would be slow and would risk rate limiting on a college
network. The cache is content-addressed and safe to delete at any time.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Optional

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)


class RegistryError(RuntimeError):
    """A registry request failed in a way the caller should handle."""


class NotFoundError(RegistryError):
    """The requested package or version does not exist upstream."""


# Retrying a 404 is pointless and slows every scan that contains one deleted
# package, so only genuinely transient failures are retried.
_TRANSIENT = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)


class CachedHTTPClient:
    """Async HTTP client with a content-addressed disk cache.

    Intended to be used as an async context manager, and shared for the lifetime
    of a scan so that connection pooling actually applies.
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        *,
        enabled: Optional[bool] = None,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        settings = get_settings()
        self.cache_dir = cache_dir or settings.cache_dir
        self.cache_enabled = settings.cache_enabled if enabled is None else enabled
        self.ttl_seconds = ttl_seconds if ttl_seconds is not None else settings.cache_ttl_seconds
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.http_timeout_seconds),
            limits=httpx.Limits(
                max_connections=settings.http_max_connections,
                max_keepalive_connections=settings.http_max_connections,
            ),
            headers={"User-Agent": settings.http_user_agent},
            follow_redirects=True,
        )
        self._settings = settings
        self._stats = {"hits": 0, "misses": 0, "errors": 0}

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def __aenter__(self) -> CachedHTTPClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------ #
    # Cache plumbing
    # ------------------------------------------------------------------ #

    def _cache_path(self, method: str, url: str, body: Optional[bytes]) -> Path:
        digest = hashlib.sha256(
            b"|".join([method.encode(), url.encode(), body or b""])
        ).hexdigest()
        # Two-level fan-out: a flat directory with tens of thousands of entries
        # is slow to enumerate on Windows.
        return self.cache_dir / digest[:2] / f"{digest}.cache"

    def _read_cache(self, path: Path) -> Optional[bytes]:
        if not self.cache_enabled or not path.exists():
            return None
        try:
            age = time.time() - path.stat().st_mtime
            if age > self.ttl_seconds:
                return None
            return path.read_bytes()
        except OSError:
            # A corrupt or locked cache entry must never fail a scan.
            return None

    def _write_cache(self, path: Path, payload: bytes) -> None:
        if not self.cache_enabled:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write-then-rename so a crash mid-write cannot leave a truncated
            # entry that later reads as valid.
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(payload)
            tmp.replace(path)
        except OSError as exc:
            logger.debug("Cache write failed for %s: %s", path.name, exc)

    # ------------------------------------------------------------------ #
    # Requests
    # ------------------------------------------------------------------ #

    @retry(
        retry=retry_if_exception_type(_TRANSIENT),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=8),
        reraise=True,
    )
    async def _request(
        self, method: str, url: str, *, content: Optional[bytes] = None, **kwargs: Any
    ) -> httpx.Response:
        return await self._client.request(method, url, content=content, **kwargs)

    async def get_bytes(self, url: str, *, use_cache: bool = True) -> bytes:
        """GET a URL, returning raw bytes. Raises :class:`NotFoundError` on 404."""
        path = self._cache_path("GET", url, None)
        if use_cache:
            cached = self._read_cache(path)
            if cached is not None:
                self._stats["hits"] += 1
                return cached

        self._stats["misses"] += 1
        try:
            response = await self._request("GET", url)
        except _TRANSIENT as exc:
            self._stats["errors"] += 1
            raise RegistryError(f"Network failure fetching {url}: {exc}") from exc

        if response.status_code == 404:
            raise NotFoundError(f"Not found: {url}")
        if response.status_code >= 400:
            self._stats["errors"] += 1
            raise RegistryError(f"HTTP {response.status_code} fetching {url}")

        payload = response.content
        if use_cache:
            self._write_cache(path, payload)
        return payload

    async def get_json(self, url: str, *, use_cache: bool = True) -> Any:
        """GET a URL and parse the response as JSON."""
        payload = await self.get_bytes(url, use_cache=use_cache)
        try:
            return json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"Malformed JSON from {url}: {exc}") from exc

    async def post_json(
        self, url: str, payload: dict[str, Any], *, use_cache: bool = True
    ) -> Any:
        """POST a JSON body and parse the JSON response.

        Used by the OSV advisory API, whose queries are POSTs. The cache key
        includes the request body, so different queries to the same endpoint do
        not collide.
        """
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        path = self._cache_path("POST", url, body)
        if use_cache:
            cached = self._read_cache(path)
            if cached is not None:
                self._stats["hits"] += 1
                try:
                    return json.loads(cached)
                except json.JSONDecodeError:
                    pass  # fall through and re-fetch

        self._stats["misses"] += 1
        try:
            response = await self._request(
                "POST",
                url,
                content=body,
                headers={"Content-Type": "application/json"},
            )
        except _TRANSIENT as exc:
            self._stats["errors"] += 1
            raise RegistryError(f"Network failure posting to {url}: {exc}") from exc

        if response.status_code >= 400:
            self._stats["errors"] += 1
            raise RegistryError(f"HTTP {response.status_code} posting to {url}")

        raw = response.content
        if use_cache:
            self._write_cache(path, raw)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"Malformed JSON from {url}: {exc}") from exc

    async def gather(self, coros: list[Any], *, concurrency: int = 8) -> list[Any]:
        """Run awaitables with bounded concurrency, returning results in order.

        Exceptions are returned in place rather than raised, so that one bad
        package cannot abort a scan of several hundred. Callers are responsible
        for checking whether an entry is an ``Exception``.
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def _guarded(coro: Any) -> Any:
            async with semaphore:
                try:
                    return await coro
                except Exception as exc:  # noqa: BLE001 - deliberate isolation boundary
                    return exc

        return await asyncio.gather(*(_guarded(c) for c in coros))
