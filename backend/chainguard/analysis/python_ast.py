"""Static analysis of Python source using the standard-library ``ast`` module.

Parsing rather than pattern-matching matters here. A regex for ``eval(`` matches
the word inside a comment, a docstring, or a variable named ``evaluate``; an AST
sees a genuine :class:`ast.Call` to the ``eval`` builtin and nothing else. It
also resolves aliases — ``import subprocess as sp`` followed by ``sp.run(...)``
is invisible to text search but obvious in the tree.

The parser is never handed anything it might execute: :func:`ast.parse` builds a
tree without evaluating the source, which is what makes static analysis of
hostile code safe in the first place.
"""

from __future__ import annotations

import ast
from typing import Optional

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

#: Builtins that turn data into executing code.
EXEC_BUILTINS = frozenset({"eval", "exec", "compile"})

#: Dotted call targets that spawn an OS process.
PROCESS_SINKS = frozenset(
    {
        "os.system", "os.popen", "os.execv", "os.execve", "os.execvp", "os.spawnl",
        "os.spawnv", "os.forkpty", "pty.spawn",
        "subprocess.run", "subprocess.call", "subprocess.check_call",
        "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "commands.getoutput", "popen2.popen2",
    }
)

#: Dotted call targets that perform network I/O.
NETWORK_SINKS = frozenset(
    {
        "socket.socket", "socket.create_connection", "socket.gethostbyname",
        "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.urlopen",
        "request.urlopen", "urlopen", "urlretrieve",
        "requests.get", "requests.post", "requests.put", "requests.patch",
        "requests.delete", "requests.head", "requests.request", "requests.Session",
        "httpx.get", "httpx.post", "httpx.Client", "httpx.AsyncClient",
        "http.client.HTTPConnection", "http.client.HTTPSConnection",
        "httplib.HTTPConnection", "aiohttp.ClientSession",
        "ftplib.FTP", "smtplib.SMTP", "telnetlib.Telnet", "paramiko.SSHClient",
        "urllib3.PoolManager",
    }
)

#: Calls that decode data into bytes/text — the first half of a packed payload.
DECODE_SINKS = frozenset(
    {
        "base64.b64decode", "base64.b64encode", "base64.b32decode",
        "base64.b16decode", "base64.a85decode", "base64.urlsafe_b64decode",
        "base64.decodebytes", "base64.decodestring",
        "binascii.unhexlify", "binascii.a2b_base64", "binascii.a2b_hex",
        "codecs.decode", "bytes.fromhex", "zlib.decompress", "gzip.decompress",
        "bz2.decompress", "lzma.decompress", "marshal.loads", "pickle.loads",
    }
)

#: Reads of the process environment.
ENV_SINKS = frozenset({"os.environ", "os.getenv", "os.environ.get", "environ.get"})

#: Dynamic module loading with a computed name.
DYNAMIC_IMPORT_SINKS = frozenset(
    {"__import__", "importlib.import_module", "importlib.__import__", "imp.load_source"}
)

#: Filesystem writes.
WRITE_SINKS = frozenset({"open", "io.open", "os.makedirs", "shutil.copy", "shutil.copyfile"})


def _dotted_name(node: ast.AST) -> Optional[str]:
    """Reconstruct a dotted name from a Name/Attribute chain.

    ``os.path.join`` → ``"os.path.join"``. Returns ``None`` for anything
    computed (``obj[key].method``), which is itself a signal of indirection.
    """
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


class _PythonVisitor(ast.NodeVisitor):
    """Walks a module, recording sinks, literals and structure."""

    def __init__(self, analysis: FileAnalysis, is_setup_py: bool) -> None:
        self.analysis = analysis
        self.is_setup_py = is_setup_py

        # alias -> real module, so `import subprocess as sp` resolves `sp.run`.
        self.aliases: dict[str, str] = {}
        #: Names imported directly (``from os import system`` → ``system``).
        self.direct_imports: dict[str, str] = {}

        self.string_literals: list[tuple[str, int]] = []
        self.reported: set[str] = set()

        #: Line numbers where a decode call occurred, used to detect a decode
        #: result flowing into an execution sink.
        self.decode_lines: set[int] = set()
        self.setup_kwargs: dict[str, ast.AST] = {}

    # -- helpers --------------------------------------------------------- #

    def _resolve(self, name: Optional[str]) -> Optional[str]:
        """Map a dotted call target through import aliases to its real name."""
        if not name:
            return None
        head, _, tail = name.partition(".")
        if head in self.aliases:
            real = self.aliases[head]
            return f"{real}.{tail}" if tail else real
        if head in self.direct_imports and not tail:
            return self.direct_imports[head]
        return name

    def _emit_once(self, code: str, key: str, **kwargs: object) -> None:
        """Emit a signal at most once per distinct key, to avoid flooding.

        A file that makes 200 HTTP calls should produce one NETWORK_ACCESS
        signal, not 200 — the report has to stay readable, and the feature
        extractor counts occurrences separately.
        """
        dedupe_key = f"{code}:{key}"
        if dedupe_key in self.reported:
            return
        self.reported.add(dedupe_key)
        self.analysis.add(make_signal(code, file=self.analysis.path, **kwargs))  # type: ignore[arg-type]

    # -- imports --------------------------------------------------------- #

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.asname:
                # `import urllib.request as ur` binds `ur` to the full path.
                self.aliases[alias.asname] = alias.name
            else:
                # `import urllib.request` binds only the ROOT name `urllib`;
                # `request` is then reached by attribute access. Mapping the root
                # to the full dotted path instead would make `urllib.request.
                # urlopen` resolve to `urllib.request.request.urlopen` and match
                # no sink at all — which silently disabled network detection for
                # every dotted import.
                root = alias.name.split(".")[0]
                self.aliases[root] = root
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.direct_imports[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    # -- literals -------------------------------------------------------- #

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value:
            self.string_literals.append((node.value, node.lineno))
        self.generic_visit(node)

    # -- attribute access (os.environ has no Call node) ------------------ #

    def visit_Attribute(self, node: ast.Attribute) -> None:
        resolved = self._resolve(_dotted_name(node))
        if resolved in ENV_SINKS or resolved == "os.environ":
            self.analysis.has_env_access = True
            self._emit_once("ENV_ACCESS", "env", line=node.lineno, evidence=resolved)
        self.generic_visit(node)

    # -- calls ----------------------------------------------------------- #

    def visit_Call(self, node: ast.Call) -> None:
        raw = _dotted_name(node.func)
        resolved = self._resolve(raw)
        line = node.lineno

        if resolved:
            self._check_exec(node, resolved, line)
            self._check_process(node, resolved, line)
            self._check_network(resolved, line)
            self._check_decode(resolved, line)
            self._check_env(node, resolved, line)
            self._check_dynamic_import(node, resolved, line)
            self._check_write(node, resolved, line)

            if self.is_setup_py and resolved.endswith("setup"):
                for keyword in node.keywords:
                    if keyword.arg:
                        self.setup_kwargs[keyword.arg] = keyword.value

        self.generic_visit(node)

    # -- individual checks ------------------------------------------------ #

    def _check_exec(self, node: ast.Call, resolved: str, line: int) -> None:
        base = resolved.rsplit(".", 1)[-1]
        if base not in EXEC_BUILTINS and resolved not in EXEC_BUILTINS:
            return
        self.analysis.has_dynamic_exec = True

        # A decode call nested inside the exec argument is the packed-payload
        # pattern: the executed code never appears in the source as text.
        if self._contains_decode(node):
            self._emit_once(
                "DECODE_THEN_EXEC",
                f"{line}",
                line=line,
                evidence=ast.unparse(node)[:200] if hasattr(ast, "unparse") else base,
                detail=f"Decoded data is passed straight to {base}()",
            )
        else:
            self._emit_once("DYNAMIC_EVAL", base, line=line, evidence=f"{base}(...)")

    def _contains_decode(self, node: ast.AST) -> bool:
        """True if a decoding call appears anywhere inside this expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                target = self._resolve(_dotted_name(child.func))
                if target and (target in DECODE_SINKS or target.rsplit(".", 1)[-1] == "decode"):
                    return True
                # chr()/ord() arithmetic chains are the manual variant.
                if target in {"chr", "bytes", "bytearray"} and isinstance(
                    getattr(child, "args", [None])[0] if child.args else None,
                    (ast.BinOp, ast.ListComp, ast.GeneratorExp),
                ):
                    return True
        return False

    def _check_process(self, node: ast.Call, resolved: str, line: int) -> None:
        if resolved not in PROCESS_SINKS:
            return
        self.analysis.has_process_spawn = True
        self._emit_once("PROCESS_SPAWN", resolved, line=line, evidence=f"{resolved}(...)")

        for keyword in node.keywords:
            if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                if keyword.value.value is True:
                    self._emit_once(
                        "SHELL_TRUE",
                        resolved,
                        line=line,
                        evidence=f"{resolved}(..., shell=True)",
                        detail="Command is interpreted by a shell, allowing chaining",
                    )

    def _check_network(self, resolved: str, line: int) -> None:
        if resolved in NETWORK_SINKS or resolved.split(".")[0] in {"requests", "httpx"}:
            self.analysis.has_network = True
            self._emit_once("NETWORK_ACCESS", resolved, line=line, evidence=f"{resolved}(...)")

    def _check_decode(self, resolved: str, line: int) -> None:
        if resolved in DECODE_SINKS:
            self.analysis.has_decoding = True
            self.decode_lines.add(line)

    def _check_env(self, node: ast.Call, resolved: str, line: int) -> None:
        if resolved not in ENV_SINKS and not resolved.endswith("getenv"):
            return
        self.analysis.has_env_access = True
        self._emit_once("ENV_ACCESS", "env", line=line, evidence=f"{resolved}(...)")

    def _check_dynamic_import(self, node: ast.Call, resolved: str, line: int) -> None:
        if resolved not in DYNAMIC_IMPORT_SINKS:
            return
        # A literal argument is an ordinary import written awkwardly; a computed
        # one hides which module is loaded, which is the part worth flagging.
        first = node.args[0] if node.args else None
        if first is not None and not isinstance(first, ast.Constant):
            self._emit_once(
                "DYNAMIC_IMPORT",
                resolved,
                line=line,
                evidence=f"{resolved}(<computed>)",
                detail="Module name is computed at runtime",
            )

    def _check_write(self, node: ast.Call, resolved: str, line: int) -> None:
        if resolved not in WRITE_SINKS:
            return
        mode = ""
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
            mode = str(node.args[1].value)
        for keyword in node.keywords:
            if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                mode = str(keyword.value.value)
        if any(flag in mode for flag in ("w", "a", "x", "+")):
            self.analysis.has_filesystem_write = True


def _analyse_string_literals(analysis: FileAnalysis, literals: list[tuple[str, int]]) -> None:
    """Inspect collected string literals for sensitive paths and endpoints."""
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
                    "SENSITIVE_PATH_ACCESS",
                    file=analysis.path,
                    line=line,
                    evidence=matched,
                    detail=f"References {label}",
                )
            )

        for matched, label in match_all(text, CRYPTO_WALLET_MATCHERS):
            if f"wallet:{label}" in seen:
                continue
            seen.add(f"wallet:{label}")
            analysis.has_sensitive_path = True
            analysis.add(
                make_signal(
                    "CRYPTO_WALLET_ACCESS",
                    file=analysis.path,
                    line=line,
                    evidence=matched,
                    detail=f"References {label}",
                )
            )

        for matched, label in match_all(text, SUSPICIOUS_DOMAIN_MATCHERS):
            if f"domain:{label}" in seen:
                continue
            seen.add(f"domain:{label}")
            analysis.has_network = True
            analysis.add(
                make_signal(
                    "SUSPICIOUS_ENDPOINT",
                    file=analysis.path,
                    line=line,
                    evidence=matched,
                    detail=f"{label} — commonly used to collect exfiltrated data",
                )
            )

        for matched, label in match_all(text, PERSISTENCE_MATCHERS):
            if f"persist:{label}" in seen:
                continue
            seen.add(f"persist:{label}")
            analysis.add(
                make_signal(
                    "FILE_WRITE_SENSITIVE",
                    file=analysis.path,
                    line=line,
                    evidence=matched,
                    detail=f"References {label}",
                )
            )

        if "ip" not in seen and (text.startswith("http") or "://" in text or text.count(".") == 3):
            for address in find_public_ip_literals(text):
                seen.add("ip")
                analysis.has_network = True
                analysis.add(
                    make_signal(
                        "HARDCODED_IP_ENDPOINT",
                        file=analysis.path,
                        line=line,
                        evidence=address,
                        detail="Network destination is a raw IP address rather than a hostname",
                    )
                )
                break


def _analyse_text_level(analysis: FileAnalysis, source: str) -> None:
    """Checks that operate on raw text rather than the parse tree."""
    minified, max_line = looks_minified(source)
    analysis.is_minified = minified
    analysis.max_line_length = max_line
    if minified:
        analysis.add(
            make_signal(
                "MINIFIED_SOURCE",
                file=analysis.path,
                detail=f"Longest line is {max_line} characters",
            )
        )

    for blob in find_base64_blobs(source)[:1]:
        analysis.has_decoding = True
        analysis.add(
            make_signal(
                "BASE64_BLOB",
                file=analysis.path,
                evidence=blob[:80],
                detail=f"{len(blob)}-character base64 literal",
            )
        )

    # Density, not raw count: unicode tables and encoding maps in legitimate
    # libraries contain hundreds of escapes across thousands of lines. What marks
    # obfuscation is source that is *mostly* escapes.
    hex_escapes, unicode_escapes = count_escape_sequences(source)
    escape_chars = (hex_escapes * 4) + (unicode_escapes * 6)
    if hex_escapes + unicode_escapes > 60 and escape_chars / max(len(source), 1) > 0.15:
        analysis.add(
            make_signal(
                "HEX_ESCAPE_HEAVY",
                file=analysis.path,
                detail=(
                    f"{hex_escapes} hex and {unicode_escapes} unicode escapes make up "
                    f"{escape_chars / max(len(source), 1):.0%} of the file"
                ),
            )
        )

    if source.count("chr(") >= 10:
        analysis.add(
            make_signal(
                "CHARCODE_OBFUSCATION",
                file=analysis.path,
                detail=f"{source.count('chr(')} chr() calls building strings",
            )
        )

    for matched, label in match_all(source, HOST_RECON_MATCHERS):
        analysis.has_host_recon = True
        analysis.add(
            make_signal(
                "HOST_RECON", file=analysis.path, evidence=matched, detail=f"Collects {label}"
            )
        )
        break

    # Detected by its actual wiring rather than by co-occurring flags — see the
    # note above REVERSE_SHELL_PATTERNS in indicators.py.
    reverse_shell = match_first(source, REVERSE_SHELL_MATCHERS)
    if reverse_shell:
        matched, label = reverse_shell
        analysis.add(
            make_signal(
                "REVERSE_SHELL_PATTERN", file=analysis.path, evidence=matched,
                detail=f"{label} — the wiring of a reverse shell",
            )
        )


def _analyse_setup_py(analysis: FileAnalysis, tree: ast.Module, visitor: _PythonVisitor) -> None:
    """Detect install-time execution in a ``setup.py``.

    ``setup.py`` runs as a script during ``pip install`` from an sdist, so any
    logic beyond declaring metadata executes on the installing machine. Two
    variants are flagged: work at module level, and a ``cmdclass`` override that
    replaces the install command with a custom class.
    """
    analysis.runs_at_install = True

    # Type-based detection ("any module-level statement that is not an import")
    # was tried first and was unusable: real setup.py files legitimately contain
    # try/except import guards, version parsing, long_description reads and
    # platform branches. Measured on PyPI, it fired four times on `pyyaml` alone.
    #
    # What actually matters is not *that* module-level code runs, but *what* it
    # does. Each top-level statement is therefore searched for calls into a
    # dangerous sink, and only those are reported.
    risky_sinks = PROCESS_SINKS | NETWORK_SINKS | DECODE_SINKS | EXEC_BUILTINS
    reported_lines: set[int] = set()

    for statement in tree.body:
        # Function and class bodies do not execute merely by being defined.
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue

        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            target = visitor._resolve(_dotted_name(node.func)) or ""
            base = target.rsplit(".", 1)[-1]
            if target.endswith("setup"):
                continue
            if target in risky_sinks or base in EXEC_BUILTINS:
                line = getattr(node, "lineno", 0)
                if line in reported_lines:
                    continue
                reported_lines.add(line)
                analysis.add(
                    make_signal(
                        "SETUP_PY_SIDE_EFFECTS",
                        file=analysis.path,
                        line=line,
                        evidence=f"{target}(...)",
                        detail=(
                            f"Calls {target} at module level of setup.py, so it runs "
                            "during installation"
                        ),
                    )
                )

    if "cmdclass" in visitor.setup_kwargs:
        analysis.add(
            make_signal(
                "SETUP_PY_SIDE_EFFECTS",
                file=analysis.path,
                detail=(
                    "Overrides cmdclass — replaces pip's install command with custom "
                    "code that runs during installation"
                ),
            )
        )


def analyse_python_file(path: str, source: str) -> FileAnalysis:
    """Analyse one Python source file. Never raises."""
    analysis = FileAnalysis(path=path, language="python")
    analysis.byte_count = len(source)
    analysis.line_count = source.count("\n") + 1

    basename = path.rsplit("/", 1)[-1]
    is_setup_py = basename == "setup.py"

    _analyse_text_level(analysis, source)

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        # Python 2 source, deliberately malformed input, or a file that is not
        # really Python. Text-level findings above still stand.
        analysis.parse_failed = True
        logger.debug("Could not parse %s: %s", path, exc)
        return analysis

    visitor = _PythonVisitor(analysis, is_setup_py)
    try:
        visitor.visit(tree)
    except RecursionError:
        # Deeply nested expressions are a known parser-DoS technique.
        analysis.parse_failed = True
        logger.debug("Recursion limit hit walking %s", path)

    _analyse_string_literals(analysis, visitor.string_literals)

    # Entropy is measured per string literal, not over the whole file: prose,
    # licence headers and normal code dilute file-level entropy enough to hide a
    # single packed blob. Only the first hit is reported — one opaque literal is
    # the finding, and a package with forty of them is a data table, not malware.
    for text, line in visitor.string_literals:
        if looks_like_encoded_payload(text):
            analysis.add(
                make_signal(
                    "HIGH_ENTROPY_STRING",
                    file=path,
                    line=line,
                    evidence=text[:60],
                    detail=(
                        f"{len(text)}-character opaque literal, entropy "
                        f"{shannon_entropy(text):.2f} bits/char"
                    ),
                )
            )
            break

    if is_setup_py:
        _analyse_setup_py(analysis, tree, visitor)

    return analysis
