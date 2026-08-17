"""Analysis of npm lifecycle-hook command strings.

An npm ``postinstall`` value is a shell command, not JavaScript, so it needs its
own analysis. It is also the highest-value place to look: the command runs
automatically on ``npm install``, before the developer has executed a single line
of their own code.

Distinguishing a legitimate hook from a malicious one is mostly about what the
command *reaches for*. ``node scripts/build.js`` and ``node-gyp rebuild`` are
ordinary. Fetching a remote URL and piping it into a shell is not.
"""

from __future__ import annotations

import re

from chainguard.analysis.indicators import (
    SUSPICIOUS_DOMAIN_MATCHERS,
    find_base64_blobs,
    find_public_ip_literals,
    match_all,
    shannon_entropy,
)
from chainguard.analysis.signals import Signal, make_signal

# Commands that fetch remote content.
_FETCH_RE = re.compile(
    r"\b(curl|wget|fetch|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|nc|ncat)\b",
    re.IGNORECASE,
)

# Interpreters that will execute whatever they are handed.
_INTERPRETER_RE = re.compile(
    r"\b(sh|bash|zsh|dash|ksh|cmd|powershell|pwsh|python\d?|perl|ruby|node)\b",
    re.IGNORECASE,
)

# Fetch piped straight into an interpreter — "curl … | bash" and variants.
_PIPE_TO_SHELL_RE = re.compile(
    r"(curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)[^|;&]*[|]\s*"
    r"(sudo\s+)?(sh|bash|zsh|dash|python\d?|perl|node|pwsh|powershell)\b",
    re.IGNORECASE,
)

# Inline code execution: `node -e "..."`, `python -c "..."`.
_INLINE_EXEC_RE = re.compile(
    r"\b(node|python\d?|perl|ruby)\s+-(e|c)\b", re.IGNORECASE
)

# An http(s) URL anywhere in the command.
_URL_RE = re.compile(r"https?://[^\s'\"|;&)>]+", re.IGNORECASE)

# Base64 decoding inside a shell command.
_B64_DECODE_RE = re.compile(
    r"(base64\s+(-d|--decode|-D)|FromBase64String|atob\s*\(|b64decode)", re.IGNORECASE
)

# Output redirected to /dev/null or suppressed — hiding what the hook did.
_SILENCING_RE = re.compile(r"(>\s*/dev/null\s*2>&1|2>\s*/dev/null|-s\s+-S|--silent)", re.IGNORECASE)

# Hooks that are almost always what they look like. Matching one of these does
# not clear a package — the other checks still run — but it avoids flagging every
# native module in the ecosystem as suspicious for having a build step.
_BENIGN_HOOKS = re.compile(
    r"^\s*(node-gyp\s+(rebuild|configure|build)"
    r"|prebuild-install(\s|$)"
    r"|(npm|yarn|pnpm)\s+run\s+[\w:-]+"
    r"|tsc(\s|$)|husky(\s+install)?|patch-package"
    r"|opencollective|funding|echo\s+"
    r"|node\s+(\./)?(scripts?|bin|install|postinstall)[\w/.-]*\.(js|cjs|mjs)"
    r")",
    re.IGNORECASE,
)


def analyse_install_command(hook: str, command: str) -> list[Signal]:
    """Analyse one lifecycle hook, returning the signals it raises.

    ``hook`` is the lifecycle name (``postinstall``), ``command`` its value.
    """
    signals: list[Signal] = []
    if not command or not command.strip():
        return signals

    location = f"package.json ({hook})"
    stripped = command.strip()

    signals.append(
        make_signal(
            "INSTALL_HOOK_PRESENT",
            file=location,
            evidence=stripped,
            detail=f"'{hook}' runs automatically during npm install",
        )
    )

    # --- fetch piped into an interpreter: the strongest single indicator --- #
    if _PIPE_TO_SHELL_RE.search(stripped):
        signals.append(
            make_signal(
                "INSTALL_HOOK_SHELL_PIPE",
                file=location,
                evidence=stripped,
                detail="Downloads a remote resource and executes it directly in a shell",
            )
        )

    # --- network access from an install hook -------------------------------- #
    urls = _URL_RE.findall(stripped)
    fetches = _FETCH_RE.search(stripped)
    if urls or fetches:
        # A registry or documentation URL in an echo is not an egress event.
        benign_url_only = bool(urls) and not fetches and stripped.lower().startswith("echo")
        if not benign_url_only:
            detail = f"Contacts {urls[0]}" if urls else "Uses a network fetch utility"
            signals.append(
                make_signal(
                    "INSTALL_HOOK_NETWORK",
                    file=location,
                    evidence=stripped,
                    detail=detail,
                )
            )

    for address in find_public_ip_literals(stripped):
        signals.append(
            make_signal(
                "HARDCODED_IP_ENDPOINT",
                file=location,
                evidence=address,
                detail="Install hook contacts a raw IP address",
            )
        )
        break

    for matched, label in match_all(stripped, SUSPICIOUS_DOMAIN_MATCHERS):
        signals.append(
            make_signal(
                "SUSPICIOUS_ENDPOINT",
                file=location,
                evidence=matched,
                detail=f"Install hook contacts a {label.lower()}",
            )
        )
        break

    # --- obfuscated hook contents ------------------------------------------- #
    obfuscation_reason = None
    if _B64_DECODE_RE.search(stripped):
        obfuscation_reason = "decodes base64 content before executing it"
    elif find_base64_blobs(stripped, min_length=40):
        obfuscation_reason = "embeds a base64 blob"
    elif len(stripped) > 160 and shannon_entropy(stripped) > 4.8:
        obfuscation_reason = "is long and high-entropy rather than a readable command"
    elif stripped.count("\\x") > 8 or stripped.count("\\u") > 8:
        obfuscation_reason = "is written with escape sequences"

    if obfuscation_reason:
        signals.append(
            make_signal(
                "INSTALL_HOOK_OBFUSCATED",
                file=location,
                evidence=stripped,
                detail=f"Hook {obfuscation_reason}",
            )
        )

    # --- inline code execution ---------------------------------------------- #
    if _INLINE_EXEC_RE.search(stripped) and not _BENIGN_HOOKS.match(stripped):
        signals.append(
            make_signal(
                "DYNAMIC_EVAL",
                file=location,
                evidence=stripped,
                detail="Install hook executes inline code passed on the command line",
            )
        )

    # --- process spawning ---------------------------------------------------- #
    if _INTERPRETER_RE.search(stripped) and not _BENIGN_HOOKS.match(stripped):
        signals.append(
            make_signal(
                "PROCESS_SPAWN",
                file=location,
                evidence=stripped,
                detail="Install hook invokes an interpreter or shell",
            )
        )

    # --- output suppression --------------------------------------------------- #
    if _SILENCING_RE.search(stripped) and (urls or fetches):
        signals.append(
            make_signal(
                "INSTALL_HOOK_OBFUSCATED",
                file=location,
                evidence=stripped,
                detail="Suppresses its own output while contacting the network",
            )
        )

    return signals


def looks_like_build_step(command: str) -> bool:
    """True if a hook matches a well-known build or tooling command.

    Used to damp the metadata heuristics, not to clear a package: a malicious
    hook can begin with a plausible prefix, so every other check still runs.
    """
    return bool(_BENIGN_HOOKS.match(command.strip()))
