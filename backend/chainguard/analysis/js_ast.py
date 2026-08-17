"""Static analysis of JavaScript source using ``esprima``.

``esprima`` is a pure-Python parser, so the backend needs no Node runtime and no
native build step (see BUILD_LOG D-010). Its limitation is syntax coverage: it
handles ES5/ES6 well but rejects newer syntax and TypeScript. That is handled by
degrading rather than failing — when the parse fails, the analyser falls back to
text-level scanning, which still catches sensitive paths, suspicious endpoints,
obfuscation and encoded blobs. A partial result is recorded as ``parse_failed``
so the feature vector can reflect reduced visibility instead of pretending the
file was clean.
"""

from __future__ import annotations

from typing import Any, Iterator, Optional

import esprima

from chainguard.analysis.base import FileAnalysis
from chainguard.analysis.indicators import (
    CRYPTO_WALLET_MATCHERS,
    HOST_RECON_MATCHERS,
    PERSISTENCE_MATCHERS,
    REVERSE_SHELL_MATCHERS,
    SENSITIVE_PATH_MATCHERS,
    SUSPICIOUS_DOMAIN_MATCHERS,
    count_escape_sequences,
    find_base64_blobs,
    find_public_ip_literals,
    looks_like_encoded_payload,
    looks_minified,
    match_all,
    match_first,
    shannon_entropy,
)
from chainguard.analysis.signals import make_signal
from chainguard.logging_setup import get_logger

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Sink definitions
# --------------------------------------------------------------------------- #

#: Node core modules whose import is itself informative.
NETWORK_MODULES = frozenset({"http", "https", "net", "dgram", "dns", "tls", "http2"})
PROCESS_MODULES = frozenset({"child_process", "worker_threads", "vm"})
FS_MODULES = frozenset({"fs", "fs/promises"})
RECON_MODULES = frozenset({"os", "systeminformation", "node-machine-id"})

#: Third-party HTTP clients.
HTTP_LIBRARIES = frozenset({"axios", "node-fetch", "got", "request", "superagent", "undici"})

PROCESS_CALLS = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
NETWORK_CALLS = frozenset({"request", "get", "post", "put", "patch", "createConnection", "connect"})
DECODE_HINTS = frozenset({"atob", "unescape", "decodeURIComponent"})


def _walk(node: Any, depth: int = 0) -> Iterator[Any]:
    """Yield every AST node beneath ``node``.

    ``esprima`` nodes expose their fields through ``vars()``, so a generic walk
    needs no per-node-type knowledge. Depth is capped because deeply nested
    expressions are a known parser-denial-of-service technique.
    """
    if depth > 300 or node is None:
        return
    if isinstance(node, list):
        for item in node:
            yield from _walk(item, depth + 1)
        return
    if not hasattr(node, "__dict__"):
        return

    yield node
    for value in vars(node).values():
        if isinstance(value, (list, object)) and not isinstance(value, (str, int, float, bool)):
            yield from _walk(value, depth + 1)


def _member_name(node: Any) -> Optional[str]:
    """Reconstruct a dotted name from a MemberExpression / Identifier chain."""
    node_type = getattr(node, "type", None)
    if node_type == "Identifier":
        return getattr(node, "name", None)
    if node_type == "MemberExpression":
        obj = _member_name(getattr(node, "object", None))
        prop = getattr(node, "property", None)
        if getattr(node, "computed", False):
            # obj[expr] — the property name is not statically known.
            return f"{obj}.<computed>" if obj else None
        prop_name = getattr(prop, "name", None) or getattr(prop, "value", None)
        if obj and prop_name:
            return f"{obj}.{prop_name}"
        return obj
    if node_type == "ThisExpression":
        return "this"
    return None


def _literal_value(node: Any) -> Optional[str]:
    if getattr(node, "type", None) == "Literal":
        value = getattr(node, "value", None)
        return value if isinstance(value, str) else None
    return None


class _JsAnalyser:
    """Collects findings from a parsed JavaScript module."""

    def __init__(self, analysis: FileAnalysis) -> None:
        self.analysis = analysis
        #: local identifier -> required module ("cp" -> "child_process")
        self.required: dict[str, str] = {}
        #: destructured binding -> "module.export" ("exec" -> "child_process.exec")
        self.destructured: dict[str, str] = {}
        self.reported: set[str] = set()
        self.string_literals: list[tuple[str, int]] = []
        self.string_array_sizes: list[int] = []
        #: ids of nodes that appear as the ``object`` of a MemberExpression.
        #: Needed to tell ``process.env`` used whole from ``process.env.FOO``,
        #: whose inner ``process.env`` sub-expression is also visited by the walk.
        self.consumed_objects: set[int] = set()
        self.charcode_hits: int = 0

    # -- emission --------------------------------------------------------- #

    def emit(self, code: str, key: str, **kwargs: Any) -> None:
        dedupe = f"{code}:{key}"
        if dedupe in self.reported:
            return
        self.reported.add(dedupe)
        self.analysis.add(make_signal(code, file=self.analysis.path, **kwargs))

    @staticmethod
    def _line(node: Any) -> Optional[int]:
        loc = getattr(node, "loc", None)
        start = getattr(loc, "start", None) if loc else None
        return getattr(start, "line", None) if start else None

    # -- passes ------------------------------------------------------------ #

    def collect_requires(self, tree: Any) -> None:
        """Record ``require()`` bindings and ES module imports."""
        for node in _walk(tree):
            node_type = getattr(node, "type", None)

            if node_type == "VariableDeclarator":
                init = getattr(node, "init", None)
                module = self._required_module(init)
                if not module:
                    continue
                target = getattr(node, "id", None)
                target_type = getattr(target, "type", None)
                if target_type == "Identifier":
                    self.required[getattr(target, "name", "")] = module
                elif target_type == "ObjectPattern":
                    for prop in getattr(target, "properties", []) or []:
                        key = getattr(prop, "key", None)
                        value = getattr(prop, "value", None)
                        local = getattr(value, "name", None) or getattr(key, "name", None)
                        exported = getattr(key, "name", None)
                        if local and exported:
                            self.destructured[local] = f"{module}.{exported}"

            elif node_type == "ImportDeclaration":
                source = _literal_value(getattr(node, "source", None))
                if not source:
                    continue
                for specifier in getattr(node, "specifiers", []) or []:
                    local = getattr(getattr(specifier, "local", None), "name", None)
                    if not local:
                        continue
                    if getattr(specifier, "type", None) == "ImportSpecifier":
                        imported = getattr(getattr(specifier, "imported", None), "name", local)
                        self.destructured[local] = f"{source}.{imported}"
                    else:
                        self.required[local] = source

    @staticmethod
    def _required_module(node: Any) -> Optional[str]:
        """If ``node`` is ``require('x')``, return ``'x'``."""
        if getattr(node, "type", None) != "CallExpression":
            return None
        callee = getattr(node, "callee", None)
        if getattr(callee, "name", None) != "require":
            return None
        args = getattr(node, "arguments", []) or []
        return _literal_value(args[0]) if args else None

    def resolve(self, name: Optional[str]) -> Optional[str]:
        """Map a dotted expression through require/import bindings."""
        if not name:
            return None
        head, _, tail = name.partition(".")
        if head in self.required:
            module = self.required[head]
            return f"{module}.{tail}" if tail else module
        if head in self.destructured and not tail:
            return self.destructured[head]
        return name

    def analyse_nodes(self, tree: Any) -> None:
        # First pass: record which nodes are merely the base of a longer member
        # chain, so `process.env.HOME` is not mistaken for a whole-environment read.
        for node in _walk(tree):
            if getattr(node, "type", None) == "MemberExpression":
                obj = getattr(node, "object", None)
                if obj is not None:
                    self.consumed_objects.add(id(obj))

        for node in _walk(tree):
            node_type = getattr(node, "type", None)

            if node_type == "CallExpression":
                self._check_call(node)
            elif node_type == "NewExpression":
                self._check_new(node)
            elif node_type == "MemberExpression":
                self._check_member(node)
            elif node_type == "Literal":
                value = getattr(node, "value", None)
                if isinstance(value, str) and value:
                    self.string_literals.append((value, self._line(node) or 0))
            elif node_type == "TemplateElement":
                cooked = getattr(getattr(node, "value", None), "cooked", None)
                if isinstance(cooked, str) and cooked:
                    self.string_literals.append((cooked, self._line(node) or 0))
            elif node_type == "ArrayExpression":
                elements = getattr(node, "elements", []) or []
                strings = [e for e in elements if _literal_value(e) is not None]
                if len(strings) >= 25 and len(strings) == len(elements):
                    self.string_array_sizes.append(len(strings))

    def _check_call(self, node: Any) -> None:
        callee = getattr(node, "callee", None)
        name = self.resolve(_member_name(callee))
        line = self._line(node)
        if not name:
            return

        base = name.rsplit(".", 1)[-1]
        root = name.split(".", 1)[0]
        args = getattr(node, "arguments", []) or []

        # --- dynamic execution ------------------------------------------- #
        if name == "eval" or base == "eval":
            self.analysis.has_dynamic_exec = True
            if self._contains_decode(node):
                self.emit(
                    "DECODE_THEN_EXEC", str(line), line=line,
                    detail="Decoded data is passed straight to eval()",
                )
            else:
                self.emit("DYNAMIC_EVAL", "eval", line=line, evidence="eval(...)")

        if name in {"Function", "vm.runInThisContext", "vm.runInNewContext", "vm.compileFunction"}:
            self.analysis.has_dynamic_exec = True
            self.emit("DYNAMIC_EVAL", name, line=line, evidence=f"{name}(...)")

        # setTimeout/setInterval with a string body is eval by another name.
        if base in {"setTimeout", "setInterval"} and args and _literal_value(args[0]):
            self.analysis.has_dynamic_exec = True
            self.emit(
                "DYNAMIC_EVAL", base, line=line,
                detail=f"{base}() called with a string body, which is evaluated as code",
            )

        # --- process spawning --------------------------------------------- #
        if root in PROCESS_MODULES and base in PROCESS_CALLS:
            self.analysis.has_process_spawn = True
            self.emit("PROCESS_SPAWN", name, line=line, evidence=f"{name}(...)")
            if base in {"exec", "execSync"}:
                self.emit(
                    "SHELL_TRUE", name, line=line,
                    detail=f"{base}() runs its argument through a shell",
                )

        # --- network ------------------------------------------------------- #
        if (root in NETWORK_MODULES and base in NETWORK_CALLS) or root in HTTP_LIBRARIES:
            self.analysis.has_network = True
            self.emit("NETWORK_ACCESS", name, line=line, evidence=f"{name}(...)")
        if name in {"fetch", "XMLHttpRequest"} or base == "fetch":
            self.analysis.has_network = True
            self.emit("NETWORK_ACCESS", "fetch", line=line, evidence="fetch(...)")
        if root == "dns" or name.startswith("dns."):
            self.analysis.has_network = True
            if args and getattr(args[0], "type", None) != "Literal":
                self.emit(
                    "DNS_EXFIL_PATTERN", name, line=line,
                    detail="DNS lookup on a dynamically constructed name",
                )

        # --- decoding ------------------------------------------------------ #
        if base in DECODE_HINTS:
            self.analysis.has_decoding = True
        if name in {"Buffer.from", "Buffer.alloc"} and len(args) > 1:
            encoding = _literal_value(args[1])
            if encoding in {"base64", "hex"}:
                self.analysis.has_decoding = True
        # String.fromCharCode is legitimate in parsers, encoders and text
        # utilities, so a single use means nothing. Only sustained use — the
        # pattern of a payload assembled character by character — is recorded,
        # and the emission happens after the whole file has been walked.
        if name == "String.fromCharCode":
            self.charcode_hits += 1

        # --- dynamic require ----------------------------------------------- #
        if getattr(callee, "name", None) == "require" and args:
            if getattr(args[0], "type", None) != "Literal":
                self.emit(
                    "DYNAMIC_IMPORT", "require", line=line,
                    detail="require() called with a computed module name",
                )

        # --- filesystem ----------------------------------------------------- #
        if root in FS_MODULES:
            if base.startswith(("write", "append", "mkdir", "copy", "rename", "chmod")):
                self.analysis.has_filesystem_write = True

        # --- recon ---------------------------------------------------------- #
        if root in RECON_MODULES and base in {
            "hostname", "userInfo", "networkInterfaces", "platform", "release", "arch", "homedir"
        }:
            self.analysis.has_host_recon = True
            self.emit("HOST_RECON", name, line=line, evidence=f"{name}()")

    def _check_new(self, node: Any) -> None:
        callee = getattr(node, "callee", None)
        name = self.resolve(_member_name(callee))
        line = self._line(node)
        if name == "Function":
            self.analysis.has_dynamic_exec = True
            self.emit(
                "DYNAMIC_EVAL", "new Function", line=line,
                evidence="new Function(...)",
                detail="Constructs a function from a string at runtime",
            )
        elif name in {"WebSocket", "net.Socket"}:
            self.analysis.has_network = True
            self.emit("NETWORK_ACCESS", name, line=line, evidence=f"new {name}()")

    def _check_member(self, node: Any) -> None:
        name = self.resolve(_member_name(node))
        if not name:
            return
        line = self._line(node)

        if name.startswith("process.env"):
            self.analysis.has_env_access = True
            self.emit("ENV_ACCESS", "env", line=line, evidence="process.env")

            # `process.env` read as a whole object — passed to a function,
            # spread, or serialised — captures every secret at once. Reading
            # `process.env.HOME` does not, and is what almost all real code does.
            # The distinction is whether this node is itself the base of a longer
            # member chain.
            if name == "process.env" and id(node) not in self.consumed_objects:
                self.emit(
                    "ENV_BULK_HARVEST", "bulk", line=line,
                    detail="Reads the entire environment block rather than named variables",
                )

    def _contains_decode(self, node: Any) -> bool:
        for child in _walk(node):
            if getattr(child, "type", None) != "CallExpression":
                continue
            name = self.resolve(_member_name(getattr(child, "callee", None))) or ""
            base = name.rsplit(".", 1)[-1]
            if base in DECODE_HINTS or name in {"Buffer.from", "String.fromCharCode"}:
                return True
        return False


def _analyse_text_level(analysis: FileAnalysis, source: str) -> None:
    """Text-level checks, applied whether or not parsing succeeded."""
    minified, max_line = looks_minified(source)
    analysis.is_minified = minified
    analysis.max_line_length = max_line
    if minified:
        analysis.add(
            make_signal(
                "MINIFIED_SOURCE", file=analysis.path,
                detail=f"Longest line is {max_line} characters",
            )
        )

    for blob in find_base64_blobs(source)[:1]:
        analysis.has_decoding = True
        analysis.add(
            make_signal(
                "BASE64_BLOB", file=analysis.path, evidence=blob[:80],
                detail=f"{len(blob)}-character base64 literal",
            )
        )

    # Density rather than raw count — see the equivalent note in python_ast.py.
    hex_escapes, unicode_escapes = count_escape_sequences(source)
    escape_chars = (hex_escapes * 4) + (unicode_escapes * 6)
    if hex_escapes + unicode_escapes > 60 and escape_chars / max(len(source), 1) > 0.15:
        analysis.add(
            make_signal(
                "HEX_ESCAPE_HEAVY", file=analysis.path,
                detail=(
                    f"{hex_escapes} hex and {unicode_escapes} unicode escapes make up "
                    f"{escape_chars / max(len(source), 1):.0%} of the file"
                ),
            )
        )

    for matched, label in match_all(source, HOST_RECON_MATCHERS):
        analysis.has_host_recon = True
        analysis.add(
            make_signal("HOST_RECON", file=analysis.path, evidence=matched, detail=f"Collects {label}")
        )
        break

    reverse_shell = match_first(source, REVERSE_SHELL_MATCHERS)
    if reverse_shell:
        matched, label = reverse_shell
        analysis.add(
            make_signal(
                "REVERSE_SHELL_PATTERN", file=analysis.path, evidence=matched,
                detail=f"{label} — the wiring of a reverse shell",
            )
        )


def _analyse_literals(analysis: FileAnalysis, literals: list[tuple[str, int]]) -> None:
    """Inspect string literals for sensitive paths, endpoints and entropy."""
    seen: set[str] = set()

    for text, line in literals:
        if len(text) > 4000:
            text = text[:4000]

        for matched, label in match_all(text, SENSITIVE_PATH_MATCHERS):
            if f"path:{label}" in seen:
                continue
            seen.add(f"path:{label}")
            analysis.has_sensitive_path = True
            analysis.add(
                make_signal(
                    "SENSITIVE_PATH_ACCESS", file=analysis.path, line=line,
                    evidence=matched, detail=f"References {label}",
                )
            )

        for matched, label in match_all(text, CRYPTO_WALLET_MATCHERS):
            if f"wallet:{label}" in seen:
                continue
            seen.add(f"wallet:{label}")
            analysis.has_sensitive_path = True
            analysis.add(
                make_signal(
                    "CRYPTO_WALLET_ACCESS", file=analysis.path, line=line,
                    evidence=matched, detail=f"References {label}",
                )
            )

        for matched, label in match_all(text, SUSPICIOUS_DOMAIN_MATCHERS):
            if f"domain:{label}" in seen:
                continue
            seen.add(f"domain:{label}")
            analysis.has_network = True
            analysis.add(
                make_signal(
                    "SUSPICIOUS_ENDPOINT", file=analysis.path, line=line,
                    evidence=matched, detail=f"{label} — commonly used to collect exfiltrated data",
                )
            )

        for matched, label in match_all(text, PERSISTENCE_MATCHERS):
            if f"persist:{label}" in seen:
                continue
            seen.add(f"persist:{label}")
            analysis.add(
                make_signal(
                    "FILE_WRITE_SENSITIVE", file=analysis.path, line=line,
                    evidence=matched, detail=f"References {label}",
                )
            )

        if "ip" not in seen and ("://" in text or text.count(".") == 3):
            for address in find_public_ip_literals(text):
                seen.add("ip")
                analysis.has_network = True
                analysis.add(
                    make_signal(
                        "HARDCODED_IP_ENDPOINT", file=analysis.path, line=line,
                        evidence=address,
                        detail="Network destination is a raw IP address rather than a hostname",
                    )
                )
                break

        if "entropy" not in seen and looks_like_encoded_payload(text):
            seen.add("entropy")
            analysis.add(
                make_signal(
                    "HIGH_ENTROPY_STRING", file=analysis.path, line=line, evidence=text[:60],
                    detail=(
                        f"{len(text)}-character opaque literal, entropy "
                        f"{shannon_entropy(text):.2f} bits/char"
                    ),
                )
            )


def analyse_javascript_file(path: str, source: str) -> FileAnalysis:
    """Analyse one JavaScript source file. Never raises."""
    analysis = FileAnalysis(path=path, language="javascript")
    analysis.byte_count = len(source)
    analysis.line_count = source.count("\n") + 1

    _analyse_text_level(analysis, source)

    tree = None
    for parser in (esprima.parseModule, esprima.parseScript):
        try:
            tree = parser(source, {"loc": True, "tolerant": True})
            break
        except Exception:  # noqa: BLE001 — esprima raises bare Error subclasses
            continue

    if tree is None:
        # Newer syntax, TypeScript, or deliberately malformed source. Text-level
        # findings still apply; the flag lets the model account for the gap.
        analysis.parse_failed = True
        logger.debug("Could not parse %s as JavaScript", path)
        _analyse_literals(analysis, [(source[:20000], 0)])
        return analysis

    analyser = _JsAnalyser(analysis)
    try:
        analyser.collect_requires(tree)
        analyser.analyse_nodes(tree)
    except (RecursionError, AttributeError, TypeError) as exc:
        analysis.parse_failed = True
        logger.debug("Error walking %s: %s", path, exc)

    _analyse_literals(analysis, analyser.string_literals)

    if analyser.charcode_hits >= 5:
        analysis.add(
            make_signal(
                "CHARCODE_OBFUSCATION", file=path,
                detail=f"{analyser.charcode_hits} String.fromCharCode calls building strings",
            )
        )

    # A large array of string literals combined with obfuscation markers is the
    # structure emitted by obfuscator.io: the real strings live in the array and
    # a decoder function indexes into it, so nothing readable remains in source.
    if analyser.string_array_sizes:
        largest = max(analyser.string_array_sizes)
        if largest >= 40 and (analysis.is_minified or analysis.has_dynamic_exec):
            analysis.add(
                make_signal(
                    "STRING_ARRAY_DECODER", file=path,
                    detail=f"Array of {largest} string literals indexed by a decoder function",
                )
            )

    return analysis
