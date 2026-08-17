"""Language-independent indicators of interest inside source text.

These are string- and pattern-level facts that mean the same thing whether they
appear in Python or JavaScript: a path to an SSH key is a path to an SSH key.
Keeping them here stops the two analysers from drifting apart, and means adding
a new indicator improves detection in both ecosystems at once.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# --------------------------------------------------------------------------- #
# Sensitive filesystem locations
# --------------------------------------------------------------------------- #

# Paths whose only realistic reason for appearing in a third-party library is
# credential harvesting. Matched case-insensitively against string literals.
SENSITIVE_PATHS: tuple[tuple[str, str], ...] = (
    (r"\.ssh[/\\]", "SSH key directory"),
    (r"id_rsa|id_ed25519|id_ecdsa|id_dsa", "SSH private key"),
    (r"\.aws[/\\]credentials|\.aws[/\\]config", "AWS credentials"),
    (r"\.config[/\\]gcloud", "Google Cloud credentials"),
    (r"\.azure[/\\]", "Azure credentials"),
    (r"\.kube[/\\]config", "Kubernetes cluster credentials"),
    (r"\.docker[/\\]config\.json", "Docker registry credentials"),
    (r"\.npmrc|\.pypirc|\.gem[/\\]credentials", "Package registry auth tokens"),
    (r"\.netrc|_netrc", "Network credentials file"),
    (r"\.git-credentials", "Git credentials"),
    (r"\.bash_history|\.zsh_history", "Shell history"),
    (r"/etc/passwd|/etc/shadow", "System account database"),
    (r"[/\\]Login Data\b|[/\\]Web Data\b|[/\\]Cookies\b", "Browser credential store"),
    (r"[/\\]Local State\b", "Browser encryption key store"),
    (r"Keychains[/\\]|login\.keychain", "macOS keychain"),
    (r"AppData[/\\]Roaming[/\\]Mozilla", "Firefox profile data"),
    (r"Discord[/\\]Local Storage|discord.*leveldb", "Discord token store"),
    # Anchored to a path separator or line start: a bare ".env" appears in
    # documentation, dotenv tooling and config examples far too often to be
    # informative on its own.
    (r"(?:^|[/\\~])\.env(?:\.[a-z]+)?\b", "Environment file"),
    (r"/etc/shadow\b", "Password hashes"),
)

# Cryptocurrency wallet artefacts — a distinct category because they are
# unambiguous: no legitimate utility library reads a seed phrase.
#: Every pattern here must be wallet-*specific*. Generic cryptography terms are
#: deliberately excluded: `private_key`, `mnemonic` and `seed` appear constantly
#: in legitimate TLS, SSH and crypto libraries, and including them made this
#: signal fire on `urllib3` and `rich`. A signal that fires on ordinary crypto
#: code carries no information — the point is wallet theft, not cryptography.
CRYPTO_WALLET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"wallet\.dat", "Bitcoin wallet file"),
    (r"Exodus[/\\]exodus\.wallet", "Exodus wallet"),
    (r"Electrum[/\\]wallets", "Electrum wallet"),
    (r"Ethereum[/\\]keystore", "Ethereum keystore"),
    (r"nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask extension ID"),
    (r"\bmetamask\b", "MetaMask reference"),
    (r"seed[_ ]?phrase|mnemonic[_ ]?phrase", "Wallet recovery phrase"),
    (r"\b(trustwallet|coinbase[_ ]?wallet|phantom[_ ]?wallet)\b", "Wallet application"),
    (r"[/\\]Local Extension Settings[/\\]", "Browser wallet extension storage"),
)

# Locations that grant persistence across reboots or shell sessions.
PERSISTENCE_PATHS: tuple[tuple[str, str], ...] = (
    (r"\.bashrc|\.bash_profile|\.zshrc|\.profile", "Shell startup file"),
    (r"/etc/cron|crontab", "Scheduled task"),
    (r"Start ?Menu[/\\]Programs[/\\]Startup", "Windows startup folder"),
    (r"CurrentVersion[/\\]?Run", "Windows Run registry key"),
    (r"LaunchAgents|LaunchDaemons", "macOS launch agent"),
    (r"/etc/systemd/system|\.service\b", "systemd unit"),
    (r"/etc/rc\.local", "System init script"),
)

# --------------------------------------------------------------------------- #
# Network endpoints
# --------------------------------------------------------------------------- #

# Services routinely used to collect stolen data: paste sites, webhook relays,
# request-capture endpoints, tunnels and dynamic DNS. Their presence in a
# library's source is very difficult to explain benignly.
SUSPICIOUS_DOMAINS: tuple[tuple[str, str], ...] = (
    (r"pastebin\.com|paste\.ee|hastebin|ghostbin|controlc\.com", "Paste site"),
    (r"discord(?:app)?\.com/api/webhooks", "Discord webhook (data collection)"),
    (r"hooks\.slack\.com", "Slack webhook"),
    (r"api\.telegram\.org", "Telegram bot API (common exfil channel)"),
    (r"requestbin|pipedream\.net|webhook\.site|beeceptor", "Request-capture service"),
    (r"burpcollaborator|oastify\.com|interact\.sh|oast\.(?:pro|live|fun)", "OOB interaction server"),
    (r"ngrok\.io|ngrok-free\.app|trycloudflare\.com|localtunnel", "Tunnel to a private host"),
    (r"\.duckdns\.org|no-ip\.(?:org|com)|ddns\.net|hopto\.org", "Dynamic DNS host"),
    (r"transfer\.sh|file\.io|anonfiles|gofile\.io", "Anonymous file drop"),
    (r"\.onion\b", "Tor hidden service"),
    (r"bashupload\.com|0x0\.st|termbin\.com", "Anonymous upload endpoint"),
)

# An IPv4 literal used as a network destination. Private, loopback and
# documentation ranges are excluded — those appear constantly in tests and
# defaults, and flagging them would drown the signal in noise.
_IPV4_RE = re.compile(
    r"\b(?:https?://)?((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b"
)
_NON_ROUTABLE_PREFIXES = (
    "0.", "10.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
    "192.0.2.", "198.51.100.", "203.0.113.", "255.", "224.", "239.",
)


def find_public_ip_literals(text: str) -> list[str]:
    """Return routable IPv4 literals appearing in ``text``."""
    found: list[str] = []
    for match in _IPV4_RE.finditer(text):
        address = match.group(1)
        octets = address.split(".")
        if len(octets) != 4:
            continue
        try:
            if any(not (0 <= int(o) <= 255) for o in octets):
                continue
        except ValueError:
            continue
        # A version-like string ("1.2.3.4" in a changelog) is indistinguishable
        # from an address without context; requiring a plausible first octet and
        # excluding private space removes most of that noise.
        if address.startswith(_NON_ROUTABLE_PREFIXES):
            continue
        if int(octets[0]) == 0 or int(octets[0]) > 223:
            continue
        found.append(address)
    return found


# --------------------------------------------------------------------------- #
# Reconnaissance
# --------------------------------------------------------------------------- #

HOST_RECON_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bos\.hostname\b|\bgethostname\b|\bplatform\.node\b", "Hostname"),
    (r"\bos\.userInfo\b|\bgetpass\.getuser\b|\bos\.getlogin\b", "Username"),
    (r"\bos\.networkInterfaces\b|\bnetifaces\b|\bifconfig\b|\bipconfig\b", "Network interfaces"),
    (r"\bplatform\.uname\b|\bos\.release\b|\bsysteminfo\b", "OS fingerprint"),
    (r"\bwhoami\b", "Current user"),
    (r"\buuid\.getnode\b|\bgetmac\b", "MAC address"),
)


# --------------------------------------------------------------------------- #
# Encoding / obfuscation measurement
# --------------------------------------------------------------------------- #

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}")


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character.

    English prose sits around 4.0–4.5; base64 and encrypted blobs approach the
    theoretical maximum for their alphabet. The threshold used by callers (4.5)
    is deliberately above normal text so that ordinary long strings — URLs,
    licence text, minified but readable code — do not trip it.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def looks_like_encoded_payload(text: str, *, min_length: int = 180) -> bool:
    """True if a string literal looks like encoded data rather than content.

    Entropy alone is a poor test and produced most of this project's early false
    positives: real packages are full of long, high-entropy literals that are
    perfectly ordinary — URLs, licence text, unicode tables, test vectors,
    minified CSS. Measured on real packages, entropy > 4.5 fired 19 times in
    ``urllib3`` and 40 times in ``webpack``.

    Three conditions are required together, because encoded payloads differ from
    ordinary long strings in structure, not just in entropy:

    * substantial length — short blobs cannot hold a payload;
    * essentially no whitespace — prose, code and markup all contain spaces;
    * a near-uniform alphabet of base64/hex characters.
    """
    if len(text) < min_length:
        return False

    whitespace = sum(1 for c in text if c.isspace())
    if whitespace / len(text) > 0.02:
        return False

    encoded_alphabet = sum(1 for c in text if c.isalnum() or c in "+/=_-")
    if encoded_alphabet / len(text) < 0.92:
        return False

    # A URL or path is dense and unspaced but is not a payload.
    if "://" in text or text.count("/") > len(text) / 12:
        return False

    return shannon_entropy(text) > 4.8


def find_base64_blobs(text: str, min_length: int = 120) -> list[str]:
    """Return long base64-looking literals.

    Length-filtered because short base64 is everywhere: hashes, UUIDs, integrity
    digests, inline icons and source-map fragments. The threshold was raised from
    60 to 120 after it matched five times in ``axios`` and nine times in
    ``webpack``; a blob long enough to carry a payload is the interesting case.
    """
    blobs = []
    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        if len(candidate) < min_length:
            continue
        # Real base64 payloads have mixed case and digits; a long run of one
        # character class is more likely a hash or an identifier.
        has_lower = any(c.islower() for c in candidate)
        has_upper = any(c.isupper() for c in candidate)
        if has_lower and has_upper:
            blobs.append(candidate)
    return blobs


def count_escape_sequences(text: str) -> tuple[int, int]:
    """Return ``(hex_escapes, unicode_escapes)`` counts."""
    return (
        len(_HEX_ESCAPE_RE.findall(text)),
        len(_UNICODE_ESCAPE_RE.findall(text)),
    )


def looks_minified(text: str) -> tuple[bool, int]:
    """Heuristic minification check, returning ``(is_minified, max_line_length)``.

    Minification is not itself suspicious — it is the normal output of a build
    step. It matters because it *suppresses* other detectors (identifiers become
    meaningless, structure is flattened), so the feature is recorded to let the
    model account for reduced visibility rather than to accuse the package.
    """
    lines = text.splitlines() or [""]
    max_length = max((len(line) for line in lines), default=0)
    if len(lines) <= 2 and len(text) > 2000:
        return True, max_length
    long_lines = sum(1 for line in lines if len(line) > 500)
    if long_lines >= 3 or (max_length > 1000 and len(lines) < 50):
        return True, max_length
    return False, max_length


# --------------------------------------------------------------------------- #
# Compiled matchers
# --------------------------------------------------------------------------- #


def _compile(patterns: tuple[tuple[str, str], ...]) -> tuple[tuple[re.Pattern[str], str], ...]:
    return tuple((re.compile(pattern, re.IGNORECASE), label) for pattern, label in patterns)


SENSITIVE_PATH_MATCHERS = _compile(SENSITIVE_PATHS)
CRYPTO_WALLET_MATCHERS = _compile(CRYPTO_WALLET_PATTERNS)
PERSISTENCE_MATCHERS = _compile(PERSISTENCE_PATHS)
SUSPICIOUS_DOMAIN_MATCHERS = _compile(SUSPICIOUS_DOMAINS)
HOST_RECON_MATCHERS = _compile(HOST_RECON_PATTERNS)


def match_first(
    text: str, matchers: tuple[tuple[re.Pattern[str], str], ...]
) -> tuple[str, str] | None:
    """Return ``(matched_text, label)`` for the first matcher that hits."""
    for pattern, label in matchers:
        match = pattern.search(text)
        if match:
            return match.group(0), label
    return None


def match_all(
    text: str, matchers: tuple[tuple[re.Pattern[str], str], ...]
) -> list[tuple[str, str]]:
    """Return every ``(matched_text, label)`` pair found in ``text``."""
    results: list[tuple[str, str]] = []
    for pattern, label in matchers:
        match = pattern.search(text)
        if match:
            results.append((match.group(0), label))
    return results
