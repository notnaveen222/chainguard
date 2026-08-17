"""The signal catalogue: what the static analysers look for, and what it means.

A *signal* is one piece of observable evidence found in a package — "this file
reads ``~/.ssh/id_rsa``", "this ``postinstall`` hook pipes curl into bash". The
classifier consumes signals as numeric features; a human reads the same signals
as the justification for a verdict.

That dual role is the point. A malice score with no evidence behind it is
unauditable, and an examiner asking "why did it flag this?" deserves an answer
better than "the model said so". Every signal therefore carries the file and line
it was found at, plus the source snippet that triggered it.

Severity vs. weight
-------------------
``severity`` is for humans, and orders the evidence list in the report.

``weight`` is a prior used **only** by the rules-only baseline detector, which
exists to demonstrate that the ML layer earns its place (see ARCHITECTURE.md §8).
The trained classifier ignores weights entirely and learns its own from data, so
a mis-set weight here cannot bias the real detector.

Several weights carry a note recording that they were lowered after measurement
against real packages. Those notes are deliberate: the original values were set
by intuition and were wrong, and the corrected value is only defensible with the
evidence attached.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """How alarming a signal is on its own."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class SignalCategory(str, Enum):
    """Families of behaviour. Also the granularity used for ablation studies."""

    INSTALL_HOOK = "install_hook"
    DYNAMIC_EXEC = "dynamic_exec"
    PROCESS_SPAWN = "process_spawn"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    CREDENTIAL_ACCESS = "credential_access"
    OBFUSCATION = "obfuscation"
    EXFILTRATION = "exfiltration"
    METADATA = "metadata"
    TYPOSQUAT = "typosquat"


class SignalType(BaseModel):
    """A definition in the catalogue (not an occurrence)."""

    code: str
    title: str
    description: str
    category: SignalCategory
    severity: Severity
    weight: float = Field(
        default=1.0, description="Prior used by the rules-only baseline detector only."
    )


class Signal(BaseModel):
    """One occurrence of a signal type inside a specific package."""

    code: str
    title: str
    category: SignalCategory
    severity: Severity

    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = Field(
        default=None, description="Source snippet that triggered the signal, truncated."
    )
    detail: Optional[str] = Field(
        default=None, description="Human-readable explanation of this occurrence."
    )
    occurrences: int = Field(
        default=1,
        description=(
            "How many times this signal code fired, set when signals are collapsed "
            "for display. Always 1 on the raw signals used for feature extraction."
        ),
    )

    @property
    def location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "(package metadata)"


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #

CATALOGUE: dict[str, SignalType] = {}


def _register(
    code: str,
    title: str,
    description: str,
    category: SignalCategory,
    severity: Severity,
    weight: float = 1.0,
) -> SignalType:
    signal_type = SignalType(
        code=code,
        title=title,
        description=description,
        category=category,
        severity=severity,
        weight=weight,
    )
    CATALOGUE[code] = signal_type
    return signal_type


# --- Install-time execution ------------------------------------------------- #
# The single most important category. Code here runs automatically on
# `npm install` / `pip install`, before the developer has run anything.

_register(
    "INSTALL_HOOK_PRESENT",
    "Package runs code at install time",
    "Declares an npm lifecycle hook (preinstall/install/postinstall) that executes "
    "automatically when the package is installed.",
    SignalCategory.INSTALL_HOOK,
    Severity.MEDIUM,
    weight=1.5,
)
_register(
    "INSTALL_HOOK_NETWORK",
    "Install hook contacts the network",
    "An install-time hook downloads from a remote host. This is the classic "
    "delivery mechanism for a second-stage payload.",
    SignalCategory.INSTALL_HOOK,
    Severity.CRITICAL,
    weight=4.0,
)
_register(
    "INSTALL_HOOK_SHELL_PIPE",
    "Install hook pipes remote content into a shell",
    "An install hook fetches a remote resource and pipes it directly to a shell "
    "interpreter (curl | bash and variants). Near-conclusive of malicious intent.",
    SignalCategory.INSTALL_HOOK,
    Severity.CRITICAL,
    weight=5.0,
)
_register(
    "INSTALL_HOOK_OBFUSCATED",
    "Install hook is obfuscated",
    "An install hook contains encoded or heavily obfuscated content rather than a "
    "readable build command.",
    SignalCategory.INSTALL_HOOK,
    Severity.CRITICAL,
    weight=4.0,
)
_register(
    "SETUP_PY_SIDE_EFFECTS",
    "setup.py executes logic at install time",
    "The Python packaging script calls into a process, network or execution sink "
    "at module level. setup.py runs during installation from an sdist, so this is "
    "the Python equivalent of a postinstall hook.",
    SignalCategory.INSTALL_HOOK,
    Severity.HIGH,
    weight=3.0,
)

# --- Dynamic execution ------------------------------------------------------ #

_register(
    "DYNAMIC_EVAL",
    "Evaluates code at runtime",
    "Uses eval / exec / new Function / compile. Legitimate in a minority of "
    "libraries, but the standard way to hide a payload from static review.",
    SignalCategory.DYNAMIC_EXEC,
    Severity.HIGH,
    # Lowered from 2.5 after measurement: eval/exec/compile appears in `requests`,
    # `flask`, `urllib3` and `rich` for compatibility shims and dynamic class
    # creation. Genuinely informative, but far too common in benign Python to
    # carry a heavy prior alone.
    weight=1.5,
)
_register(
    "DECODE_THEN_EXEC",
    "Decodes data and immediately executes it",
    "A decoding call (base64/hex/fromCharCode) feeds directly into an execution "
    "sink. This composition has almost no legitimate use and is the signature of "
    "a packed payload.",
    SignalCategory.DYNAMIC_EXEC,
    Severity.CRITICAL,
    weight=5.0,
)
_register(
    "DYNAMIC_IMPORT",
    "Resolves imports from runtime-computed names",
    "Uses __import__/importlib/require with a computed argument, hiding which "
    "module is actually loaded.",
    SignalCategory.DYNAMIC_EXEC,
    Severity.MEDIUM,
    # Lowered from 1.5: plugin systems and optional-dependency shims use this
    # routinely (observed in `requests`, `flask`, `pyyaml`, `express`).
    weight=1.0,
)

# --- Process execution ------------------------------------------------------ #

_register(
    "PROCESS_SPAWN",
    "Spawns an operating-system process",
    "Uses child_process / subprocess / os.system to run external commands.",
    SignalCategory.PROCESS_SPAWN,
    Severity.MEDIUM,
    weight=1.5,
)
_register(
    "SHELL_TRUE",
    "Spawns a process through a shell",
    "Executes a command with shell interpretation enabled, allowing chaining and "
    "injection.",
    SignalCategory.PROCESS_SPAWN,
    Severity.HIGH,
    weight=2.0,
)
_register(
    "REVERSE_SHELL_PATTERN",
    "Contains a reverse-shell pattern",
    "Combines socket creation with process spawning and dynamic execution — the "
    "canonical reverse shell.",
    SignalCategory.PROCESS_SPAWN,
    Severity.CRITICAL,
    weight=5.0,
)

# --- Network ---------------------------------------------------------------- #

_register(
    "NETWORK_ACCESS",
    "Performs network I/O",
    "Opens sockets or issues HTTP requests. Common and often benign; meaningful "
    "mainly in combination with credential access.",
    SignalCategory.NETWORK,
    Severity.LOW,
    weight=0.5,
)
_register(
    "HARDCODED_IP_ENDPOINT",
    "Sends data to a hardcoded IP address",
    "Contacts a raw IP literal rather than a domain. Legitimate packages use "
    "hostnames; hardcoded IPs are typical of attacker infrastructure.",
    SignalCategory.NETWORK,
    Severity.HIGH,
    # Lowered from 3.0: documentation examples and default-route constants in
    # networking libraries (observed in `urllib3`) match this.
    weight=2.5,
)
_register(
    "SUSPICIOUS_ENDPOINT",
    "Contacts a service associated with exfiltration",
    "Sends data to a paste site, webhook relay, request-capture service or "
    "dynamic-DNS host commonly used to collect stolen data.",
    SignalCategory.NETWORK,
    Severity.CRITICAL,
    weight=4.5,
)
_register(
    "DNS_EXFIL_PATTERN",
    "Encodes data into DNS lookups",
    "Performs DNS resolution against dynamically constructed names — a covert "
    "channel that bypasses HTTP egress filtering.",
    SignalCategory.NETWORK,
    Severity.HIGH,
    weight=3.5,
)

# --- Filesystem and credentials --------------------------------------------- #

_register(
    "SENSITIVE_PATH_ACCESS",
    "Reads a sensitive filesystem location",
    "Accesses SSH keys, cloud credentials, shell history, keychains or browser "
    "profile data.",
    SignalCategory.CREDENTIAL_ACCESS,
    Severity.CRITICAL,
    # Lowered from 4.5 after measurement: a single path match fires on `requests`
    # (.netrc authentication support), `flask` and `axios`. The precise signal is
    # the EXFIL_* composite, which additionally requires network egress in the
    # same file and fired on none of those packages.
    weight=3.0,
)
_register(
    "CRYPTO_WALLET_ACCESS",
    "Targets cryptocurrency wallet data",
    "References wallet files, recovery phrases or wallet browser extensions.",
    SignalCategory.CREDENTIAL_ACCESS,
    Severity.CRITICAL,
    weight=5.0,
)
_register(
    "ENV_ACCESS",
    "Reads environment variables",
    "Reads process environment. Ubiquitous and usually benign on its own.",
    SignalCategory.CREDENTIAL_ACCESS,
    Severity.INFO,
    weight=0.2,
)
_register(
    "ENV_BULK_HARVEST",
    "Serialises the entire environment",
    "Captures the whole environment block at once rather than reading specific "
    "variables — the shape of credential theft, not configuration.",
    SignalCategory.CREDENTIAL_ACCESS,
    Severity.HIGH,
    # Lowered from 3.5: logging and debug libraries legitimately snapshot the
    # environment (observed in `debug`).
    weight=2.5,
)
_register(
    "FILE_WRITE_SENSITIVE",
    "Writes to a startup or configuration location",
    "Writes into shell profiles, cron, autostart or system directories — a "
    "persistence mechanism.",
    SignalCategory.FILESYSTEM,
    Severity.HIGH,
    # Lowered from 3.0: build tools reference these paths for legitimate reasons
    # (observed in `webpack`).
    weight=2.0,
)
_register(
    "HOST_RECON",
    "Collects host identity information",
    "Gathers hostname, username, network interfaces or working directory — the "
    "reconnaissance beacon a dropper sends home.",
    SignalCategory.FILESYSTEM,
    Severity.MEDIUM,
    # Lowered from 1.8: build and logging tooling reads hostname and platform
    # routinely (observed seven times in `webpack`).
    weight=1.0,
)

# --- Obfuscation ------------------------------------------------------------ #

_register(
    "HIGH_ENTROPY_STRING",
    "Contains an opaque high-entropy literal",
    "A long literal with no whitespace and a near-uniform encoded alphabet — "
    "encoded or encrypted data rather than text.",
    SignalCategory.OBFUSCATION,
    Severity.MEDIUM,
    weight=1.5,
)
_register(
    "BASE64_BLOB",
    "Embeds a large base64 blob",
    "Contains a substantial base64-encoded literal, a common payload carrier.",
    SignalCategory.OBFUSCATION,
    Severity.MEDIUM,
    # Lowered from 1.8: inline assets, source maps and test vectors match
    # (observed in `axios` and `webpack`).
    weight=1.2,
)
_register(
    "CHARCODE_OBFUSCATION",
    "Builds strings from character codes",
    "Assembles strings via fromCharCode/chr() sequences to evade text search.",
    SignalCategory.OBFUSCATION,
    Severity.HIGH,
    weight=2.5,
)
_register(
    "HEX_ESCAPE_HEAVY",
    "Heavy use of hex or unicode escapes",
    "Source is written predominantly with escape sequences instead of readable "
    "literals.",
    SignalCategory.OBFUSCATION,
    Severity.MEDIUM,
    weight=2.0,
)
_register(
    "STRING_ARRAY_DECODER",
    "Uses a string-array decoder",
    "Exhibits the string-array-plus-index-decoder structure emitted by "
    "JavaScript obfuscators such as obfuscator.io.",
    SignalCategory.OBFUSCATION,
    Severity.HIGH,
    weight=3.0,
)
_register(
    "MINIFIED_SOURCE",
    "Source appears minified",
    "Very long lines and short identifiers. Normal in build output, notable when "
    "it is the package's only source.",
    SignalCategory.OBFUSCATION,
    Severity.LOW,
    weight=0.4,
)

# --- Composite exfiltration ------------------------------------------------- #
# The highest-value signals. Individually common behaviours become conclusive
# when they co-occur in a single file — and measured against real packages, none
# of these fired on any of express, chalk, debug, requests, click, urllib3,
# flask, pyyaml, rich, axios, webpack or commander.

_register(
    "EXFIL_ENV_TO_NETWORK",
    "Sends environment data to the network",
    "Reads environment variables, collects host information, and transmits over "
    "the network from one file. Composition is what makes this conclusive — each "
    "part alone is unremarkable.",
    SignalCategory.EXFILTRATION,
    Severity.CRITICAL,
    weight=5.0,
)
_register(
    "EXFIL_CREDENTIALS_TO_NETWORK",
    "Sends credential files to the network",
    "Reads a sensitive credential path and transmits data in the same file.",
    SignalCategory.EXFILTRATION,
    Severity.CRITICAL,
    weight=6.0,
)
_register(
    "EXFIL_ON_INSTALL",
    "Exfiltration reachable from an install hook",
    "Data collection or remote access occurs in a file executed at install time.",
    SignalCategory.EXFILTRATION,
    Severity.CRITICAL,
    weight=6.0,
)

# --- Metadata --------------------------------------------------------------- #

_register(
    "NO_REPOSITORY",
    "No source repository declared",
    "Publishes no repository URL, so the shipped code cannot be compared against "
    "public source.",
    SignalCategory.METADATA,
    Severity.LOW,
    weight=0.6,
)
_register(
    "VERY_NEW_PACKAGE",
    "Published very recently",
    "Uploaded within the last few days. Most malicious packages are removed within "
    "days of publication, so live malware is nearly always new.",
    SignalCategory.METADATA,
    Severity.MEDIUM,
    weight=1.2,
)
_register(
    "SINGLE_VERSION",
    "Only one version ever published",
    "No release history. Real libraries iterate; single-version packages are "
    "typical of throwaway malicious uploads.",
    SignalCategory.METADATA,
    Severity.LOW,
    weight=0.8,
)
_register(
    "EMPTY_DESCRIPTION",
    "No description provided",
    "Publishes no summary of what the package does.",
    SignalCategory.METADATA,
    Severity.LOW,
    weight=0.5,
)
_register(
    "TINY_PACKAGE_WITH_HOOK",
    "Almost no code, but runs on install",
    "Ships very little source yet executes at install time — the shape of a pure "
    "dropper rather than a library.",
    SignalCategory.METADATA,
    Severity.HIGH,
    weight=3.0,
)

# --- Typosquatting ---------------------------------------------------------- #

_register(
    "TYPOSQUAT_NEAR_MISS",
    "Name closely resembles a popular package",
    "Within a small edit distance of a widely used package name — the mechanism "
    "behind install-time typo attacks.",
    SignalCategory.TYPOSQUAT,
    Severity.HIGH,
    weight=3.5,
)
_register(
    "TYPOSQUAT_HOMOGLYPH",
    "Name uses visually confusable characters",
    "Contains characters that render similarly to another package's name "
    "(digit/letter or cross-script substitution).",
    SignalCategory.TYPOSQUAT,
    Severity.HIGH,
    weight=3.5,
)
_register(
    "TYPOSQUAT_SCOPE_CONFUSION",
    "Mimics a scoped package name",
    "Reproduces a scoped package's name without the scope, or adds a scope to an "
    "unscoped popular name.",
    SignalCategory.TYPOSQUAT,
    Severity.HIGH,
    weight=3.0,
)


def get_signal_type(code: str) -> Optional[SignalType]:
    return CATALOGUE.get(code)


def make_signal(
    code: str,
    *,
    file: Optional[str] = None,
    line: Optional[int] = None,
    evidence: Optional[str] = None,
    detail: Optional[str] = None,
) -> Signal:
    """Instantiate a catalogue signal at a concrete location.

    Evidence is truncated and newline-collapsed: obfuscated source routinely
    contains single lines of hundreds of kilobytes, and an unbounded snippet
    would make reports unreadable and bloat stored scan results.
    """
    signal_type = CATALOGUE.get(code)
    if signal_type is None:
        raise KeyError(f"Unknown signal code: {code}")

    if evidence:
        evidence = " ".join(evidence.split())
        if len(evidence) > 220:
            evidence = evidence[:217] + "..."

    return Signal(
        code=signal_type.code,
        title=signal_type.title,
        category=signal_type.category,
        severity=signal_type.severity,
        file=file,
        line=line,
        evidence=evidence,
        detail=detail,
    )


#: Logistic parameters for the baseline score. The midpoint is the weighted total
#: at which the baseline becomes undecided (0.5). It was raised from 6.0 to 9.0
#: after measuring real packages: at 6.0, ordinary libraries such as `flask` and
#: `urllib3` scored above 0.9 purely by being large, which made the baseline
#: useless as a comparison point rather than merely worse than the model.
_BASELINE_MIDPOINT = 9.0
_BASELINE_SCALE = 2.5


def rules_score(signals: list[Signal]) -> float:
    """Baseline detector: a weighted sum of signals, squashed to 0–1.

    This exists purely as the comparison baseline for the evaluation section.
    Showing that the trained classifier beats a sensible rules engine is what
    justifies the ML component; without the comparison, "we used machine
    learning" is an assertion rather than a result.

    Repeat occurrences of one signal code have diminishing returns — twenty
    ``NETWORK_ACCESS`` hits in a large library must not outweigh a single
    ``EXFIL_CREDENTIALS_TO_NETWORK``.
    """
    if not signals:
        return 0.0

    counts: dict[str, int] = {}
    total = 0.0
    for signal in signals:
        signal_type = CATALOGUE.get(signal.code)
        if signal_type is None:
            continue
        seen = counts.get(signal.code, 0)
        counts[signal.code] = seen + 1
        total += signal_type.weight / (1.0 + seen)

    return 1.0 / (1.0 + math.exp(-(total - _BASELINE_MIDPOINT) / _BASELINE_SCALE))


ALL_CATEGORIES: tuple[SignalCategory, ...] = tuple(SignalCategory)
