"""OSV.dev advisory client.

OSV is the open vulnerability database Google maintains; it aggregates GitHub
Security Advisories, PyPA, npm and others behind one schema covering both
ecosystems this project supports, with no API key required.

Extracting vulnerable *symbols* is the part that matters for reachability, and it
is genuinely hard: unlike Go advisories, npm and PyPI records almost never carry
structured symbol data. What they do carry is prose describing the vulnerable
function, usually with the identifier in a code span. Symbols are therefore
recovered from three places in descending order of reliability:

1. structured ``ecosystem_specific.imports`` / ``affected_functions`` when present;
2. a small curated table for advisories that matter most in demonstrations;
3. code spans and call-shaped tokens parsed out of the advisory text.

Tier 3 is a heuristic and is labelled as such on the result, because a
reachability verdict is only as trustworthy as the symbol list it was computed
against — and claiming otherwise would be the most misleading thing this system
could do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from chainguard.config import get_settings
from chainguard.logging_setup import get_logger
from chainguard.models.package import Ecosystem, PackageRef
from chainguard.registry.http import CachedHTTPClient, RegistryError

logger = get_logger(__name__)


class SymbolConfidence(str):
    """How the vulnerable symbols for an advisory were obtained."""

    STRUCTURED = "structured"
    CURATED = "curated"
    PARSED = "parsed"
    NONE = "none"


@dataclass
class Vulnerability:
    """One advisory affecting one package version."""

    id: str
    package: str
    ecosystem: str
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: str = "UNKNOWN"  # CRITICAL | HIGH | MODERATE | LOW | UNKNOWN
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    fixed_version: Optional[str] = None
    introduced_version: Optional[str] = None
    published: Optional[str] = None
    references: list[str] = field(default_factory=list)

    #: Symbols whose use makes this advisory relevant, and how they were found.
    vulnerable_symbols: list[str] = field(default_factory=list)
    symbol_confidence: str = SymbolConfidence.NONE

    @property
    def cve_id(self) -> Optional[str]:
        """The CVE identifier, if this advisory has one."""
        if self.id.startswith("CVE-"):
            return self.id
        return next((a for a in self.aliases if a.startswith("CVE-")), None)

    @property
    def display_id(self) -> str:
        return self.cve_id or self.id

    @property
    def severity_rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}.get(
            self.severity.upper(), 0
        )


# --------------------------------------------------------------------------- #
# Curated symbol table
# --------------------------------------------------------------------------- #

# Advisories where the vulnerable entry point is well known and stable. This is a
# seed set, not a complete database — commercial reachability tools maintain
# thousands of these, and the gap is documented rather than papered over.
CURATED_SYMBOLS: dict[str, list[str]] = {
    # PyPI
    "pyyaml": ["yaml.load", "yaml.unsafe_load", "yaml.full_load", "load"],
    "jinja2": ["jinja2.Environment", "Environment", "from_string"],
    "flask": ["flask.Flask.send_file", "send_file", "send_from_directory"],
    "requests": ["requests.Session", "Session", "requests.get", "requests.post"],
    "urllib3": ["urllib3.PoolManager", "PoolManager", "urlopen", "request"],
    "cryptography": ["Cipher", "decrypt", "encrypt"],
    "pillow": ["Image.open", "open", "ImageFont.truetype"],
    "numpy": ["numpy.load", "load"],
    "lxml": ["etree.fromstring", "fromstring", "etree.parse"],
    "django": ["QuerySet.filter", "filter", "mark_safe"],
    "aiohttp": ["ClientSession", "web.static", "aiohttp.ClientSession"],
    "werkzeug": ["send_file", "safe_join", "werkzeug.utils.safe_join"],
    "setuptools": ["easy_install", "package_index"],
    "tornado": ["StaticFileHandler", "RequestHandler"],
    "paramiko": ["Transport", "SSHClient", "paramiko.SSHClient"],
    # npm
    "lodash": ["template", "merge", "mergeWith", "set", "setWith", "zipObjectDeep"],
    "minimist": ["minimist", "parse"],
    "axios": ["axios", "axios.get", "axios.post", "request"],
    "express": ["express", "res.redirect", "query"],
    "moment": ["moment", "parse", "moment.duration"],
    "handlebars": ["compile", "precompile", "Handlebars.compile"],
    "ejs": ["render", "renderFile", "compile"],
    "node-fetch": ["fetch", "nodeFetch"],
    "ws": ["WebSocket", "Server"],
    "tar": ["extract", "x", "tar.extract"],
    "semver": ["satisfies", "validRange", "coerce"],
    "json5": ["parse", "JSON5.parse"],
    "qs": ["parse", "qs.parse"],
    "braces": ["braces", "expand"],
    "micromatch": ["micromatch", "isMatch"],
    "y18n": ["__", "setLocale"],
    "shell-quote": ["parse", "quote"],
    "decode-uri-component": ["decodeUriComponent"],
}

# Identifiers inside code spans, e.g. `yaml.load()` or `Handlebars.compile`.
_CODE_SPAN_RE = re.compile(r"`([A-Za-z_$][\w$.]{2,60})(?:\(\))?`")
# Call-shaped tokens in plain prose, e.g. "the load() function".
_CALL_SHAPE_RE = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(\s*\)")

# Words that look like identifiers but are prose or metadata, not symbols.
_SYMBOL_STOPWORDS = frozenset(
    {
        "the", "this", "that", "and", "for", "with", "from", "when", "which", "user",
        "users", "attacker", "version", "versions", "package", "packages", "library",
        "function", "functions", "method", "methods", "module", "modules", "code",
        "input", "output", "value", "values", "string", "strings", "object", "array",
        "true", "false", "null", "none", "undefined", "npm", "pypi", "github", "http",
        "https", "cve", "ghsa", "note", "warning", "example", "usage", "fix", "fixed",
        "patch", "patched", "affected", "vulnerable", "vulnerability", "severity",
        "impact", "workaround", "workarounds", "credit", "credits", "references",
        "javascript", "typescript", "python", "nodejs", "node", "install", "update",
    }
)


def _severity_from_database_specific(vuln: dict[str, Any]) -> Optional[str]:
    specific = vuln.get("database_specific")
    if isinstance(specific, dict):
        value = specific.get("severity")
        if isinstance(value, str) and value:
            return value.upper()
    return None


def _parse_cvss(vuln: dict[str, Any]) -> tuple[Optional[float], Optional[str]]:
    """Extract a CVSS base score and vector from an advisory."""
    entries = vuln.get("severity")
    if not isinstance(entries, list):
        return None, None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        vector = entry.get("score")
        if not isinstance(vector, str):
            continue
        if vector.startswith("CVSS:"):
            score = _score_from_vector(vector)
            return score, vector
        try:
            return float(vector), None
        except ValueError:
            continue
    return None, None


# Base-score weights for CVSS v3. A full implementation of the specification is
# unnecessary here — the score is used for ordering findings, and an approximation
# accurate to a severity band is sufficient for that. Where the advisory also
# states a severity label, that label wins.
_CVSS_METRIC_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _score_from_vector(vector: str) -> Optional[float]:
    """Approximate a CVSS v3 base score from its vector string."""
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        if key and value:
            metrics[key] = value

    try:
        impact_base = 1 - (
            (1 - _CVSS_METRIC_WEIGHTS["C"][metrics["C"]])
            * (1 - _CVSS_METRIC_WEIGHTS["I"][metrics["I"]])
            * (1 - _CVSS_METRIC_WEIGHTS["A"][metrics["A"]])
        )
        scope_changed = metrics.get("S") == "C"
        if scope_changed:
            impact = 7.52 * (impact_base - 0.029) - 3.25 * pow(impact_base - 0.02, 15)
        else:
            impact = 6.42 * impact_base

        exploitability = (
            8.22
            * _CVSS_METRIC_WEIGHTS["AV"][metrics["AV"]]
            * _CVSS_METRIC_WEIGHTS["AC"][metrics["AC"]]
            * _CVSS_METRIC_WEIGHTS["PR"][metrics["PR"]]
            * _CVSS_METRIC_WEIGHTS["UI"][metrics["UI"]]
        )
    except KeyError:
        return None

    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    # CVSS rounds up to one decimal place.
    return float(int(raw * 10 + 0.99999) / 10)


def _severity_label(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MODERATE"
    return "LOW"


def _version_bounds(vuln: dict[str, Any], package: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(introduced, fixed)`` versions for the affected package."""
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package") or {}
        if str(pkg.get("name", "")).lower() != package.lower():
            continue
        for entry in affected.get("ranges") or []:
            if not isinstance(entry, dict):
                continue
            introduced = fixed = None
            for event in entry.get("events") or []:
                if not isinstance(event, dict):
                    continue
                if "introduced" in event:
                    introduced = str(event["introduced"])
                if "fixed" in event:
                    fixed = str(event["fixed"])
            if fixed or introduced:
                return introduced, fixed
    return None, None


def extract_symbols(vuln: dict[str, Any], package: str) -> tuple[list[str], str]:
    """Determine which symbols make an advisory relevant.

    Returns ``(symbols, confidence)``. Confidence is what callers must surface:
    a reachability verdict computed from parsed prose is a weaker claim than one
    computed from structured advisory data.
    """
    # --- Tier 1: structured data -------------------------------------------- #
    structured: list[str] = []
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        specific = affected.get("ecosystem_specific")
        if isinstance(specific, dict):
            for key in ("imports", "affected_functions", "functions", "symbols"):
                value = specific.get(key)
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            structured.append(item)
                        elif isinstance(item, dict):
                            structured.extend(
                                s for s in item.get("symbols", []) if isinstance(s, str)
                            )
    if structured:
        return sorted(set(structured)), SymbolConfidence.STRUCTURED

    # --- Tier 2: curated table ---------------------------------------------- #
    curated = CURATED_SYMBOLS.get(package.lower())
    if curated:
        return list(curated), SymbolConfidence.CURATED

    # --- Tier 3: parsed from advisory prose --------------------------------- #
    text = f"{vuln.get('summary', '')}\n{vuln.get('details', '')}"
    candidates: set[str] = set()

    for match in _CODE_SPAN_RE.finditer(text):
        candidates.add(match.group(1))
    for match in _CALL_SHAPE_RE.finditer(text):
        candidates.add(match.group(1))

    symbols = [
        candidate
        for candidate in candidates
        if candidate.split(".")[-1].lower() not in _SYMBOL_STOPWORDS
        and not candidate.lower().startswith(("cve-", "ghsa-", "http"))
        and len(candidate) >= 3
    ]
    if symbols:
        return sorted(symbols)[:12], SymbolConfidence.PARSED

    return [], SymbolConfidence.NONE


def parse_vulnerability(vuln: dict[str, Any], ref: PackageRef) -> Vulnerability:
    """Convert an OSV record into a :class:`Vulnerability`."""
    score, vector = _parse_cvss(vuln)
    label = _severity_from_database_specific(vuln) or _severity_label(score)
    introduced, fixed = _version_bounds(vuln, ref.name)
    symbols, confidence = extract_symbols(vuln, ref.name)

    references = [
        str(r.get("url"))
        for r in (vuln.get("references") or [])
        if isinstance(r, dict) and r.get("url")
    ]

    return Vulnerability(
        id=str(vuln.get("id", "UNKNOWN")),
        package=ref.name,
        ecosystem=ref.ecosystem.value,
        summary=str(vuln.get("summary") or "")[:500],
        details=str(vuln.get("details") or "")[:4000],
        aliases=[str(a) for a in (vuln.get("aliases") or [])],
        severity=label,
        cvss_score=score,
        cvss_vector=vector,
        fixed_version=fixed,
        introduced_version=introduced,
        published=str(vuln.get("published") or "") or None,
        references=references[:8],
        vulnerable_symbols=symbols,
        symbol_confidence=confidence,
    )


class OSVClient:
    """Queries OSV.dev for advisories affecting resolved packages."""

    def __init__(self, http: CachedHTTPClient) -> None:
        self.http = http
        self.base_url = get_settings().osv_api_url.rstrip("/")

    async def query(self, ref: PackageRef) -> list[Vulnerability]:
        """Advisories affecting one specific package version."""
        payload = {
            "package": {"name": ref.name, "ecosystem": _osv_ecosystem(ref.ecosystem)},
            "version": ref.version,
        }
        try:
            document = await self.http.post_json(f"{self.base_url}/v1/query", payload)
        except RegistryError as exc:
            logger.debug("OSV query failed for %s: %s", ref, exc)
            return []

        vulns = (document or {}).get("vulns") or []
        return [parse_vulnerability(v, ref) for v in vulns if isinstance(v, dict)]

    async def query_batch(
        self, refs: list[PackageRef], *, chunk_size: int = 100
    ) -> dict[str, list[Vulnerability]]:
        """Advisories for many packages at once, keyed by ``PackageRef.key``.

        OSV's batch endpoint returns only advisory *ids*, not full records, so
        each distinct id is then fetched once and shared across every package it
        affects. For a real dependency tree this is far fewer requests than
        querying each package individually.
        """
        results: dict[str, list[Vulnerability]] = {ref.key: [] for ref in refs}
        id_to_refs: dict[str, list[PackageRef]] = {}

        for start in range(0, len(refs), chunk_size):
            chunk = refs[start:start + chunk_size]
            payload = {
                "queries": [
                    {
                        "package": {
                            "name": ref.name,
                            "ecosystem": _osv_ecosystem(ref.ecosystem),
                        },
                        "version": ref.version,
                    }
                    for ref in chunk
                ]
            }
            try:
                document = await self.http.post_json(
                    f"{self.base_url}/v1/querybatch", payload
                )
            except RegistryError as exc:
                logger.warning("OSV batch query failed: %s", exc)
                continue

            for ref, result in zip(chunk, (document or {}).get("results") or []):
                for entry in (result or {}).get("vulns") or []:
                    vuln_id = str(entry.get("id", ""))
                    if vuln_id:
                        id_to_refs.setdefault(vuln_id, []).append(ref)

        if not id_to_refs:
            return results

        logger.info(
            "OSV: %d distinct advisories across %d packages", len(id_to_refs), len(refs)
        )

        documents = await self.http.gather(
            [self._fetch_vuln(vuln_id) for vuln_id in id_to_refs], concurrency=10
        )

        for vuln_id, document in zip(id_to_refs, documents):
            if isinstance(document, Exception) or not isinstance(document, dict):
                continue
            for ref in id_to_refs[vuln_id]:
                results[ref.key].append(parse_vulnerability(document, ref))

        return results

    async def _fetch_vuln(self, vuln_id: str) -> Any:
        return await self.http.get_json(f"{self.base_url}/v1/vulns/{vuln_id}")


def _osv_ecosystem(ecosystem: Ecosystem) -> str:
    """OSV's ecosystem identifier for one of ours."""
    return {Ecosystem.NPM: "npm", Ecosystem.PYPI: "PyPI"}[ecosystem]
