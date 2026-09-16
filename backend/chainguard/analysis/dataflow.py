"""Intra-procedural taint tracing: does a credential-shaped value really reach a
network call, or do the two behaviours merely happen to share a file?

Why this exists
----------------
``engine.py``'s composite signals (``EXFIL_CREDENTIALS_TO_NETWORK`` and friends)
fire on co-occurrence: "this file reads something that looks like a credential
*and*, somewhere, makes a network call." That is real evidence — reading a
credential and reaching the network are each individually rare — but it cannot
distinguish a package that steals a key from a package that happens to read a
config file *and*, in an unrelated function, fetches an update manifest.

This module answers the sharper question: does the *value itself* travel from
the suspicious read to the suspicious send? ``secret = open(path).read();
requests.post(url, data=secret)`` is a confirmed flow. ``open(path); ...;
requests.get(other_url)`` is not — nothing about the network call depends on
what was read.

Scope, deliberately
--------------------
* **Python only.** JavaScript composite signals are untouched by this module.
* **One behaviour family.** Credential-shaped reads (sensitive file paths,
  secret-looking environment variables) flowing into a network call. The other
  composite signals (``EXFIL_ON_INSTALL``, the reverse-shell pattern) are not
  covered — this is one instantiation of a general technique, not three.
* **Intra-procedural.** Taint is tracked within one function scope (or module
  scope) at a time. A secret returned from one function and used in another is
  not traced — that needs interprocedural data-flow analysis, a materially
  larger problem than what a single evening can responsibly claim to solve.
* **Flow-insensitive, deliberately over-approximating.** Once a name is
  observed to be tainted anywhere in its scope, it is treated as tainted for the
  rest of that scope, regardless of intervening reassignment. That can produce
  a false "confirmed" in an unusual case (``s = secret(); s = "safe"; send(s)``)
  but never a false negative in the far more common case (a straight-line read
  and send). Given the choice, this project consistently resolves uncertainty
  toward the more alarming reading (see ``vulns/reachability.py``); this module
  follows the same convention.

This is *additive* evidence. It does not change ``EXFIL_CREDENTIALS_TO_NETWORK``
or its feature-vector mapping, so the already-trained classifier is untouched.
It emits a new, separate signal (``CONFIRMED_CREDENTIAL_EXFILTRATION``) that is
deliberately not wired into the feature vector — see the note in ``signals.py``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable, Optional

from chainguard.analysis.indicators import SENSITIVE_PATH_MATCHERS, match_first

#: Reads a previously-opened file. Chained onto a source call (``open(x).read()``)
#: it is still the same underlying source, not a second one.
_READ_METHODS = frozenset({"read", "readline", "readlines"})

#: Environment-variable names that look like secrets rather than ordinary config
#: (``PATH``, ``LANG``, ``NODE_ENV``). Matched against the key argument, not the
#: value — the value is never visible statically.
_SECRET_ENV_RE = re.compile(
    r"(SECRET|SESSION[_-]?TOKEN|PASSWORD|PRIVATE[_-]?KEY|API[_-]?KEY|"
    r"ACCESS[_-]?KEY|CREDENTIAL|AUTH[_-]?TOKEN)",
    re.IGNORECASE,
)

#: Statement types that open a new taint scope. A nested function's own reads
#: and sends are analysed as their own scope, not folded into the enclosing one
#: — see the module docstring on intra-procedural scope.
_SCOPE_BOUNDARY = (ast.FunctionDef, ast.AsyncFunctionDef)

Resolver = Callable[[Optional[str]], Optional[str]]


@dataclass(frozen=True)
class ConfirmedFlow:
    """One traced path from a credential-shaped read to a network send."""

    file: str
    function_scope: str  # "<module>" or the plain function/method name
    source_line: int
    source_kind: str  # "credential_file" | "credential_env"
    source_evidence: str
    sink_line: int
    sink_target: str
    sink_evidence: str
    runs_at_install: bool = False


@dataclass(frozen=True)
class _SourceInfo:
    line: int
    kind: str
    evidence: str
    label: str


# --------------------------------------------------------------------------- #
# AST plumbing shared with python_ast.py, duplicated deliberately — see the
# equivalent small duplication between python_ast.py and vulns/reachability.py.
# A shared helper here would couple two independently-testable modules for the
# sake of ~10 lines.
# --------------------------------------------------------------------------- #


def _dotted(node: ast.AST) -> Optional[str]:
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _string_hint(node: ast.AST) -> str:
    """Best-effort text for pattern matching — not real evaluation.

    Joins every string constant found anywhere in the subtree, in source order.
    Catches ``os.path.expanduser("~/.ssh/id_rsa")``, f-strings, and
    ``home + "/.aws/credentials"``. A path built with no literal fragment at all
    (fully computed) is invisible to this, the same fail-open trade-off
    ``_dotted_name`` already makes for computed call targets.
    """
    parts = [
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    ]
    return "/".join(parts)


# --------------------------------------------------------------------------- #
# Source detection
# --------------------------------------------------------------------------- #


def _match_open_source(call: ast.Call, resolve: Resolver) -> Optional[tuple[str, str]]:
    """``open(<sensitive path>)`` → ``(matched text, label)``."""
    target = resolve(_dotted(call.func))
    if target not in ("open", "io.open"):
        return None
    if not call.args:
        return None
    hint = _string_hint(call.args[0])
    if not hint:
        return None
    return match_first(hint, SENSITIVE_PATH_MATCHERS)


def _match_env_source(node: ast.AST, resolve: Resolver) -> Optional[tuple[str, str]]:
    """``os.environ["X"]`` / ``os.environ.get("X")`` / ``os.getenv("X")`` for
    secret-looking ``X`` → ``(key text, "environment variable")``."""
    key_node: Optional[ast.AST] = None

    if isinstance(node, ast.Subscript):
        if resolve(_dotted(node.value)) == "os.environ":
            key_node = node.slice
    elif isinstance(node, ast.Call):
        target = resolve(_dotted(node.func))
        if target in ("os.environ.get", "os.getenv") and node.args:
            key_node = node.args[0]

    if key_node is None:
        return None
    hint = _string_hint(key_node)
    if hint and _SECRET_ENV_RE.search(hint):
        return hint, "environment variable"
    return None


def _source_at(node: ast.AST, resolve: Resolver) -> Optional[tuple[str, str, str]]:
    """If ``node`` is itself a source expression, return ``(kind, evidence, label)``."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _READ_METHODS:
            # `open(path).read()` / `f.read()` where `f` was itself a source —
            # the read is transparent; the source is whatever it wraps.
            inner = _source_at(func.value, resolve)
            if inner:
                return inner
        matched = _match_open_source(node, resolve)
        if matched:
            evidence, label = matched
            return "credential_file", evidence, label
        matched = _match_env_source(node, resolve)
        if matched:
            evidence, label = matched
            return "credential_env", evidence, label
    elif isinstance(node, ast.Subscript):
        matched = _match_env_source(node, resolve)
        if matched:
            evidence, label = matched
            return "credential_env", evidence, label
    return None


def _expr_taint_origin(
    node: ast.AST, resolve: Resolver, tainted: dict[str, _SourceInfo]
) -> Optional[_SourceInfo]:
    """Does this expression's subtree contain a source, or reference a tainted name?

    Walking the whole subtree (rather than only the top node) is what catches
    ``requests.post(url, data={"k": secret})`` and ``f"leak:{secret}"`` — the
    tainted value does not have to be the direct argument, only reachable from it.
    """
    for child in ast.walk(node):
        found = _source_at(child, resolve)
        if found:
            kind, evidence, label = found
            return _SourceInfo(
                line=getattr(child, "lineno", getattr(node, "lineno", 0)),
                kind=kind, evidence=evidence, label=label,
            )
        if isinstance(child, ast.Name) and child.id in tainted:
            return tainted[child.id]
    return None


# --------------------------------------------------------------------------- #
# Scope flattening: every statement belonging to one function (or the module),
# without descending into a nested function's own body — that nested function
# is analysed as its own, separate scope by the caller.
# --------------------------------------------------------------------------- #


def _flatten_scope(body: list[ast.stmt]) -> list[ast.stmt]:
    out: list[ast.stmt] = []
    for stmt in body:
        out.append(stmt)
        if isinstance(stmt, _SCOPE_BOUNDARY):
            continue
        for field_name in ("body", "orelse", "finalbody"):
            child = getattr(stmt, field_name, None)
            if isinstance(child, list):
                out.extend(_flatten_scope(child))
        if isinstance(stmt, ast.Try):
            for handler in stmt.handlers:
                out.extend(_flatten_scope(handler.body))
    return out


def _iter_scopes(tree: ast.Module) -> list[tuple[str, list[ast.stmt]]]:
    scopes = [("<module>", _flatten_scope(tree.body))]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scopes.append((node.name, _flatten_scope(node.body)))
    return scopes


def _assignment_pairs(stmt: ast.stmt) -> list[tuple[ast.expr, str]]:
    """``(value expression, assigned name)`` pairs a statement produces.

    Covers plain assignment, annotated assignment, augmented assignment, and
    ``with <source> as name:`` — the last one matters most: it is the idiomatic
    way to read a file in Python, and is exactly the shape of the credential-
    theft example this whole feature is built around.
    """
    pairs: list[tuple[ast.expr, str]] = []
    if isinstance(stmt, ast.Assign):
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                pairs.append((stmt.value, target.id))
    elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        if isinstance(stmt.target, ast.Name):
            pairs.append((stmt.value, stmt.target.id))
    elif isinstance(stmt, ast.AugAssign):
        if isinstance(stmt.target, ast.Name):
            pairs.append((stmt.value, stmt.target.id))
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            if isinstance(item.optional_vars, ast.Name):
                pairs.append((item.context_expr, item.optional_vars.id))
    return pairs


def _propagate_taint(statements: list[ast.stmt], resolve: Resolver) -> dict[str, _SourceInfo]:
    """Fixed-point taint propagation over one scope's statements.

    A single forward pass already resolves the common case, since Python source
    order matches execution order for straight-line code. The repeat passes
    exist for the less common case — taint arriving from a name assigned later
    in the same scope inside a branch the linear pass already walked past
    (e.g. inside a ``try`` block visited before an ``except`` that reassigns).
    Six passes is comfortably more than any real chain length seen in practice;
    the loop exits as soon as nothing new is found.
    """
    tainted: dict[str, _SourceInfo] = {}
    for _ in range(6):
        changed = False
        for stmt in statements:
            for value_expr, name in _assignment_pairs(stmt):
                if name in tainted:
                    continue
                info = _expr_taint_origin(value_expr, resolve, tainted)
                if info is not None:
                    tainted[name] = info
                    changed = True
        if not changed:
            break
    return tainted


def _is_network_sink(target: Optional[str], network_sinks: frozenset[str]) -> bool:
    if target is None:
        return False
    if target in network_sinks:
        return True
    # Mirrors the fallback in python_ast.py's _check_network: `requests.Session()
    # .get(...)` and similar chains are not literally in the sink table but start
    # with a client library's root name.
    return target.split(".")[0] in {"requests", "httpx"}


def _find_sink_calls(
    statements: list[ast.stmt],
    tainted: dict[str, _SourceInfo],
    resolve: Resolver,
    network_sinks: frozenset[str],
    scope_name: str,
    runs_at_install: bool,
    file: str,
) -> list[ConfirmedFlow]:
    flows: list[ConfirmedFlow] = []
    seen: set[tuple[int, int]] = set()

    for stmt in statements:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            target = resolve(_dotted(node.func))
            if not _is_network_sink(target, network_sinks):
                continue

            for arg in (*node.args, *(kw.value for kw in node.keywords)):
                info = _expr_taint_origin(arg, resolve, tainted)
                if info is None:
                    continue
                sink_line = getattr(node, "lineno", 0)
                key = (info.line, sink_line)
                if key in seen:
                    break
                seen.add(key)
                flows.append(
                    ConfirmedFlow(
                        file=file,
                        function_scope=scope_name,
                        source_line=info.line,
                        source_kind=info.kind,
                        source_evidence=f"{info.evidence} ({info.label})",
                        sink_line=sink_line,
                        sink_target=target or "?",
                        sink_evidence=f"{target}(...)",
                        runs_at_install=runs_at_install,
                    )
                )
                break  # one confirmed flow per sink call is enough evidence

    return flows


def find_confirmed_flows(
    tree: ast.Module,
    resolve: Resolver,
    network_sinks: frozenset[str],
    *,
    file: str = "",
    runs_at_install: bool = False,
) -> list[ConfirmedFlow]:
    """Find every traced path from a credential-shaped read to a network send."""
    flows: list[ConfirmedFlow] = []
    for scope_name, statements in _iter_scopes(tree):
        tainted = _propagate_taint(statements, resolve)
        if not tainted:
            continue
        flows.extend(
            _find_sink_calls(
                statements, tainted, resolve, network_sinks, scope_name, runs_at_install, file
            )
        )
    return flows
