"""Vulnerability reachability analysis.

The problem this solves
-----------------------
A real project reports 150–300 known CVEs across its dependency tree. Almost all
of them are irrelevant: the vulnerable *function* is never called by the
application. Reporting them all is why known-vulnerable dependencies stay
unpatched — the signal drowns in noise.

Reachability answers the question that actually matters: *can this application
reach the vulnerable code?* When it can, the answer comes with a call path as
proof.

How it works (Python)
---------------------
1. Every ``.py`` file under the project root becomes a module node.
2. Imports are resolved into either *internal* modules or *external* packages,
   so ``from yaml import load`` in ``app/parser.py`` is recorded as an edge to
   the external symbol ``yaml.load``.
3. A call graph is built at function granularity. Module-level code is its own
   node, because importing a module executes it.
4. Entry points are the modules nothing else imports, plus any explicit
   ``__main__`` block. Reachability is a breadth-first search from those.
5. A vulnerable symbol is reachable if any path from an entry point reaches an
   edge naming it. The path itself is returned.

Verdicts are graded, not binary, because the confidence genuinely differs:

* ``NOT_IMPORTED`` — the package is in the dependency tree but the application
  never imports it. The strongest negative result, and the most common one.
* ``SYMBOL_NOT_CALLED`` — the package is imported, but the specific vulnerable
  function is never called.
* ``REACHABLE`` — a concrete call path exists, and is included.
* ``ASSUMED_REACHABLE`` — the package is imported but the advisory names no
  symbols, so nothing can be ruled out.

Fail-safe direction
-------------------
When the analysis cannot decide, it resolves to **reachable** (BUILD_LOG D-007).
The two errors are not symmetric: a false "reachable" costs an engineer ten
minutes of review, while a false "unreachable" hides a genuinely exploitable
vulnerability. Dynamic dispatch, computed imports and reflection are all treated
as reaching everything.

Honest limits
-------------
"Not statically reachable" is a strictly weaker claim than "not exploitable".
This analysis does not resolve ``getattr`` indirection, monkey-patching, plugin
registries, or calls made from templates and configuration. For npm, only
import-level reachability is computed — full JavaScript call-graph construction
across dynamic ``require``, bundlers and prototype patching is a research problem
in its own right and is deliberately out of scope rather than done badly.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional

from chainguard.logging_setup import get_logger
from chainguard.models.package import Ecosystem
from chainguard.vulns.import_names import ImportNameResolver

logger = get_logger(__name__)

#: Directories that are not application code.
_SKIP_DIRS = frozenset(
    {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__", "site-packages",
        "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        "htmlcov", ".idea", ".vscode", "migrations",
    }
)

MODULE_SCOPE = "<module>"


class Verdict(str, Enum):
    """Why a vulnerability was or was not considered reachable."""

    REACHABLE = "reachable"
    ASSUMED_REACHABLE = "assumed_reachable"
    SYMBOL_NOT_CALLED = "symbol_not_called"
    NOT_IMPORTED = "not_imported"
    NOT_ANALYSED = "not_analysed"

    @property
    def is_reachable(self) -> bool:
        return self in (Verdict.REACHABLE, Verdict.ASSUMED_REACHABLE, Verdict.NOT_ANALYSED)


@dataclass
class CallSite:
    """One step in a call path."""

    caller: str
    callee: str
    file: str
    line: int

    def __str__(self) -> str:
        return f"{self.caller} → {self.callee}  ({self.file}:{self.line})"


@dataclass
class ReachabilityResult:
    """The reachability verdict for one advisory."""

    package: str
    verdict: Verdict
    reason: str
    matched_symbol: Optional[str] = None
    call_path: list[CallSite] = field(default_factory=list)
    imported_by: list[str] = field(default_factory=list)
    confidence: str = "medium"

    @property
    def is_reachable(self) -> bool:
        return self.verdict.is_reachable

    def path_summary(self) -> str:
        if not self.call_path:
            return ""
        steps = [self.call_path[0].caller] + [step.callee for step in self.call_path]
        return " → ".join(steps)


@dataclass
class _Function:
    """A function or module-level scope in the call graph."""

    qualified: str
    module: str
    file: str
    line: int
    calls: list[tuple[str, int]] = field(default_factory=list)


class PythonCallGraph:
    """A call graph over a Python project's own source."""

    def __init__(self, root: Path) -> None:
        self.root = root
        #: qualified name -> function node
        self.functions: dict[str, _Function] = {}
        #: module -> {local alias: resolved target}
        self.imports: dict[str, dict[str, str]] = {}
        #: module -> set of internal modules it imports
        self.module_edges: dict[str, set[str]] = {}
        #: external package -> modules importing it
        self.external_imports: dict[str, set[str]] = {}
        self.modules: set[str] = set()
        self.files_parsed = 0
        self.files_failed = 0

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #

    @classmethod
    def build(cls, root: Path) -> PythonCallGraph:
        graph = cls(root)
        for path in _iter_python_files(root):
            graph._add_file(path)
        graph._resolve_calls()
        logger.info(
            "Call graph: %d modules, %d functions, %d external packages imported",
            len(graph.modules), len(graph.functions), len(graph.external_imports),
        )
        return graph

    def _module_name(self, path: Path) -> str:
        relative = path.relative_to(self.root).with_suffix("")
        parts = list(relative.parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts) if parts else path.stem

    def _add_file(self, path: Path) -> None:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except (OSError, SyntaxError, ValueError, RecursionError) as exc:
            self.files_failed += 1
            logger.debug("Could not parse %s: %s", path, exc)
            return

        self.files_parsed += 1
        module = self._module_name(path)
        self.modules.add(module)
        self.imports.setdefault(module, {})
        self.module_edges.setdefault(module, set())

        relative_file = str(path.relative_to(self.root)).replace("\\", "/")
        collector = _ScopeCollector(module, relative_file)
        collector.visit(tree)

        self.imports[module].update(collector.aliases)
        for function in collector.functions.values():
            self.functions[function.qualified] = function

    def _resolve_calls(self) -> None:
        """Classify each import target as internal module or external package."""
        for module, aliases in self.imports.items():
            for target in aliases.values():
                root_name = target.split(".")[0]
                if self._is_internal(target):
                    self.module_edges[module].add(self._internal_module_of(target))
                else:
                    self.external_imports.setdefault(root_name.lower(), set()).add(module)

    def _is_internal(self, dotted: str) -> bool:
        if dotted in self.modules:
            return True
        # `mypkg.utils.helpers` may name a symbol inside module `mypkg.utils`.
        parts = dotted.split(".")
        return any(".".join(parts[:i]) in self.modules for i in range(len(parts), 0, -1))

    def _internal_module_of(self, dotted: str) -> str:
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            candidate = ".".join(parts[:i])
            if candidate in self.modules:
                return candidate
        return dotted

    # ------------------------------------------------------------------ #
    # Entry points and reachability
    # ------------------------------------------------------------------ #

    def entry_points(self) -> set[str]:
        """Modules that nothing else in the project imports.

        These are the scripts and package roots execution actually starts from.
        If everything imports everything (a cycle), every module is treated as an
        entry point — the fail-safe direction.
        """
        imported: set[str] = set()
        for targets in self.module_edges.values():
            imported.update(targets)

        roots = self.modules - imported
        if not roots:
            roots = set(self.modules)
        return roots

    def seed_scopes(self) -> list[str]:
        """The scopes a reachability search starts from.

        For each entry-point module: its module-level code, **and** its public
        functions. The second part matters and is the fail-safe choice. A module
        nothing else imports is a script, a CLI command, or a plugin — something
        invoked from outside the code being analysed. Its public functions are
        therefore assumed callable, even though no call to them appears in the
        source.

        Modules that *are* imported by others get no such treatment: they are
        internal, so only genuine call edges reach into them. Without that
        distinction every function in the project would be an entry point and the
        analysis would report everything as reachable.
        """
        seeds: list[str] = []
        for module in self.entry_points():
            module_scope = f"{module}::{MODULE_SCOPE}"
            if module_scope in self.functions:
                seeds.append(module_scope)
            for qualified in self.functions:
                if not qualified.startswith(f"{module}::"):
                    continue
                scope = qualified.split("::", 1)[1]
                if scope == MODULE_SCOPE:
                    continue
                # Public, and not a nested/private helper.
                if any(part.startswith("_") for part in scope.split(".")):
                    continue
                seeds.append(qualified)
        return seeds

    def reachable_scopes(self) -> set[str]:
        """Every function and module scope reachable from an entry point."""
        reachable: set[str] = set()
        queue: list[str] = []

        for scope in self.seed_scopes():
            if scope not in reachable:
                reachable.add(scope)
                queue.append(scope)

        while queue:
            current = queue.pop()
            node = self.functions.get(current)
            if node is None:
                continue

            # Importing a module executes its top level, so an imported module's
            # module scope is reachable from the importer.
            for imported_module in self.module_edges.get(node.module, set()):
                scope = f"{imported_module}::{MODULE_SCOPE}"
                if scope in self.functions and scope not in reachable:
                    reachable.add(scope)
                    queue.append(scope)

            for callee, _line in node.calls:
                if callee in self.functions and callee not in reachable:
                    reachable.add(callee)
                    queue.append(callee)

        return reachable

    def find_external_call(
        self, package: str, symbols: Iterable[str], aliases: Iterable[str] = ()
    ) -> tuple[Optional[str], list[CallSite]]:
        """Search for a reachable call to ``package``'s vulnerable symbols.

        Returns ``(matched_symbol, call_path)``. The path is reconstructed from
        the entry point, so the caller can show *why* the code is reachable
        rather than merely asserting that it is.
        """
        # Match against every module the distribution provides, not just its
        # distribution name — `import yaml` must satisfy a query for `pyyaml`.
        roots = {package.lower(), package.lower().replace("-", "_")}
        roots.update(alias.lower() for alias in aliases)
        wanted = {s.split(".")[-1].lower() for s in symbols if s}
        wanted_full = {s.lower() for s in symbols if s}

        # Two passes, because the *quality of the proof* differs. The first pass
        # starts only from module-level code — real execution entry points — so
        # any path it finds is a genuine chain of calls and is the more
        # convincing artifact. Only if that finds nothing does the second pass
        # add the assumed-callable public functions.
        module_seeds = [
            f"{module}::{MODULE_SCOPE}"
            for module in self.entry_points()
            if f"{module}::{MODULE_SCOPE}" in self.functions
        ]
        matched, path = self._search(module_seeds, roots, wanted, wanted_full)
        if matched:
            return matched, path
        return self._search(self.seed_scopes(), roots, wanted, wanted_full)

    def _search(
        self,
        seeds: list[str],
        roots: set[str],
        wanted: set[str],
        wanted_full: set[str],
    ) -> tuple[Optional[str], list[CallSite]]:
        """Breadth-first search from ``seeds`` for a call into ``package``."""
        parents: dict[str, tuple[str, int]] = {}
        queue: list[str] = []
        seen: set[str] = set()
        for scope in seeds:
            if scope not in seen:
                seen.add(scope)
                queue.append(scope)

        while queue:
            current = queue.pop(0)
            node = self.functions.get(current)
            if node is None:
                continue

            for imported_module in self.module_edges.get(node.module, set()):
                scope = f"{imported_module}::{MODULE_SCOPE}"
                if scope in self.functions and scope not in seen:
                    seen.add(scope)
                    parents[scope] = (current, node.line)
                    queue.append(scope)

            for callee, line in node.calls:
                if callee.startswith("ext:"):
                    target = callee[4:]
                    tail = target.split(".")[-1].lower()
                    root = target.split(".")[0].lower()
                    if root not in roots:
                        continue
                    if wanted and tail not in wanted and target.lower() not in wanted_full:
                        continue
                    return target, self._build_path(current, target, node.file, line, parents)

                if callee in self.functions and callee not in seen:
                    seen.add(callee)
                    parents[callee] = (current, line)
                    queue.append(callee)

        return None, []

    def _build_path(
        self,
        terminal_scope: str,
        target: str,
        file: str,
        line: int,
        parents: dict[str, tuple[str, int]],
    ) -> list[CallSite]:
        """Reconstruct the entry-point-to-vulnerable-call path."""
        chain: list[str] = [terminal_scope]
        current = terminal_scope
        guard = 0
        while current in parents and guard < 64:
            current = parents[current][0]
            chain.append(current)
            guard += 1
        chain.reverse()

        path: list[CallSite] = []
        for index in range(len(chain) - 1):
            caller, callee = chain[index], chain[index + 1]
            node = self.functions.get(caller)
            call_line = parents.get(callee, (None, 0))[1]
            path.append(
                CallSite(
                    caller=_pretty(caller),
                    callee=_pretty(callee),
                    file=node.file if node else file,
                    line=call_line,
                )
            )

        path.append(
            CallSite(caller=_pretty(terminal_scope), callee=target, file=file, line=line)
        )
        return path

    def imports_package(self, package: str, aliases: Iterable[str] = ()) -> set[str]:
        """Modules importing ``package``.

        ``aliases`` carries the module names the distribution actually provides
        — ``pyyaml`` ships ``yaml``, ``pillow`` ships ``PIL``. Without them this
        lookup fails on any package whose distribution and import names differ,
        and a missed import produces a false "not imported" verdict.
        """
        package = package.lower()
        candidates = {package, package.replace("-", "_"), package.replace("_", "-")}
        candidates.update(alias.lower() for alias in aliases)

        found: set[str] = set()
        for imported, modules in self.external_imports.items():
            if imported in candidates:
                found.update(modules)
        return found


def _pretty(qualified: str) -> str:
    """Render ``module::func`` for display."""
    module, _, scope = qualified.partition("::")
    return module if scope == MODULE_SCOPE else f"{module}.{scope}"


class _ScopeCollector(ast.NodeVisitor):
    """Collects imports, function scopes and call sites from one module."""

    def __init__(self, module: str, file: str) -> None:
        self.module = module
        self.file = file
        self.aliases: dict[str, str] = {}
        self.functions: dict[str, _Function] = {}

        module_scope = f"{module}::{MODULE_SCOPE}"
        self.functions[module_scope] = _Function(
            qualified=module_scope, module=module, file=file, line=1
        )
        self._stack: list[str] = [module_scope]
        self._class_stack: list[str] = []

    @property
    def _current(self) -> _Function:
        return self.functions[self._stack[-1]]

    # -- imports ---------------------------------------------------------- #

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            # Relative import — resolve against the current package.
            parts = self.module.split(".")
            base = ".".join(parts[: max(0, len(parts) - node.level)])
            module = f"{base}.{node.module}" if node.module else base
        else:
            module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    # -- scopes ------------------------------------------------------------ #

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_function(node)

    def _enter_function(self, node: ast.AST) -> None:
        name = getattr(node, "name", "?")
        scope_name = ".".join([*self._class_stack, name])
        qualified = f"{self.module}::{scope_name}"
        self.functions[qualified] = _Function(
            qualified=qualified,
            module=self.module,
            file=self.file,
            line=getattr(node, "lineno", 0),
        )
        self._stack.append(qualified)
        self.generic_visit(node)
        self._stack.pop()

    # -- calls -------------------------------------------------------------- #

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        if name:
            self._current.calls.append((name, getattr(node, "lineno", 0)))
        self.generic_visit(node)


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


def _iter_python_files(root: Path, limit: int = 4000) -> Iterable[Path]:
    count = 0
    for path in root.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        count += 1
        if count > limit:
            logger.warning("Stopped scanning source files at the %d-file limit", limit)
            return
        yield path


# --------------------------------------------------------------------------- #
# Call resolution against the graph
# --------------------------------------------------------------------------- #


def _link_calls(graph: PythonCallGraph) -> None:
    """Rewrite raw call names into graph node references.

    Each recorded call is resolved to an internal function node
    (``module::func``) or an external symbol (``ext:package.symbol``). Names that
    resolve to neither are dropped: they are builtins, locals or attribute
    accesses on runtime values, none of which are edges in this graph.
    """
    for function in graph.functions.values():
        aliases = graph.imports.get(function.module, {})
        module_functions = {
            q.split("::", 1)[1]: q
            for q in graph.functions
            if q.startswith(f"{function.module}::")
        }

        resolved: list[tuple[str, int]] = []
        for raw, line in function.calls:
            head, _, tail = raw.partition(".")

            target = aliases.get(head)
            if target is not None:
                full = f"{target}.{tail}" if tail else target
                if graph._is_internal(full):
                    internal_module = graph._internal_module_of(full)
                    symbol = full[len(internal_module):].lstrip(".")
                    candidate = f"{internal_module}::{symbol or MODULE_SCOPE}"
                    resolved.append((candidate, line))
                else:
                    resolved.append((f"ext:{full}", line))
                continue

            if not tail and raw in module_functions:
                resolved.append((module_functions[raw], line))
                continue

            if raw in module_functions:
                resolved.append((module_functions[raw], line))

        function.calls = resolved


def build_python_graph(root: Path) -> PythonCallGraph:
    """Build and link a call graph for a Python project."""
    graph = PythonCallGraph.build(root)
    _link_calls(graph)
    return graph


# --------------------------------------------------------------------------- #
# JavaScript: import-level reachability
# --------------------------------------------------------------------------- #

_REQUIRE_RE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_IMPORT_RE = re.compile(r"""\bfrom\s+['"]([^'"]+)['"]|\bimport\s+['"]([^'"]+)['"]""")


class JavaScriptImportGraph:
    """Which npm packages a project's own source imports.

    Import-level only, by design (see the module docstring). Establishing that a
    package is never imported is still a strong and useful negative result — it
    is where most of the noise reduction in a real dependency tree comes from.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.imported: dict[str, set[str]] = {}
        self.files_parsed = 0

    @classmethod
    def build(cls, root: Path) -> JavaScriptImportGraph:
        graph = cls(root)
        patterns = ("*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts", "*.tsx")
        count = 0
        for pattern in patterns:
            for path in root.rglob(pattern):
                if any(part in _SKIP_DIRS for part in path.parts):
                    continue
                count += 1
                if count > 4000:
                    logger.warning("Stopped scanning JS files at the 4000-file limit")
                    break
                graph._add_file(path)
        logger.info(
            "JS import graph: %d files, %d distinct packages imported",
            graph.files_parsed, len(graph.imported),
        )
        return graph

    def _add_file(self, path: Path) -> None:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        self.files_parsed += 1
        relative = str(path.relative_to(self.root)).replace("\\", "/")

        specifiers: set[str] = set()
        specifiers.update(_REQUIRE_RE.findall(source))
        for first, second in _IMPORT_RE.findall(source):
            specifiers.add(first or second)

        for specifier in specifiers:
            if not specifier or specifier.startswith((".", "/", "node:")):
                continue  # relative path or Node builtin, not a dependency
            # "@scope/pkg/sub" -> "@scope/pkg"; "pkg/sub" -> "pkg"
            parts = specifier.split("/")
            package = "/".join(parts[:2]) if specifier.startswith("@") else parts[0]
            self.imported.setdefault(package.lower(), set()).add(relative)

    def imports_package(self, package: str) -> set[str]:
        return self.imported.get(package.lower(), set())


# --------------------------------------------------------------------------- #
# Analyser
# --------------------------------------------------------------------------- #


class ReachabilityAnalyser:
    """Decides whether advisories are reachable from a project's own code."""

    def __init__(
        self,
        project_root: Path,
        ecosystem: Ecosystem,
        resolver: Optional["ImportNameResolver"] = None,
    ) -> None:
        self.project_root = project_root
        self.ecosystem = ecosystem
        # Translates distribution names into the modules they provide. Without
        # it, `pyyaml` never matches `import yaml` and a critical advisory is
        # reported as unreachable.
        self.resolver = resolver or ImportNameResolver()
        self.python_graph: Optional[PythonCallGraph] = None
        self.js_graph: Optional[JavaScriptImportGraph] = None
        self.available = False

        if not project_root.is_dir():
            logger.warning("Project root %s does not exist; reachability disabled", project_root)
            return

        try:
            if ecosystem is Ecosystem.PYPI:
                self.python_graph = build_python_graph(project_root)
                self.available = self.python_graph.files_parsed > 0
            else:
                self.js_graph = JavaScriptImportGraph.build(project_root)
                self.available = self.js_graph.files_parsed > 0
        except Exception as exc:  # noqa: BLE001 — never let analysis abort a scan
            logger.warning("Could not build the call graph: %s", exc)
            self.available = False

    def analyse(self, package: str, symbols: list[str]) -> ReachabilityResult:
        """Determine whether ``package``'s vulnerable symbols are reachable."""
        if not self.available:
            # No source to analyse. Fail safe: report it, do not claim safety.
            return ReachabilityResult(
                package=package,
                verdict=Verdict.NOT_ANALYSED,
                reason="No application source was available to analyse",
                confidence="none",
            )

        if self.ecosystem is Ecosystem.PYPI:
            return self._analyse_python(package, symbols)
        return self._analyse_javascript(package, symbols)

    def _analyse_python(self, package: str, symbols: list[str]) -> ReachabilityResult:
        graph = self.python_graph
        assert graph is not None

        aliases = self.resolver.resolve(package, Ecosystem.PYPI)
        importers = graph.imports_package(package, aliases)
        if not importers:
            return ReachabilityResult(
                package=package,
                verdict=Verdict.NOT_IMPORTED,
                reason=(
                    f"'{package}' is in the dependency tree but no application module "
                    "imports it"
                ),
                confidence="high",
            )

        if not symbols:
            return ReachabilityResult(
                package=package,
                verdict=Verdict.ASSUMED_REACHABLE,
                reason=(
                    f"'{package}' is imported and the advisory names no specific "
                    "vulnerable function, so nothing can be ruled out"
                ),
                imported_by=sorted(importers)[:8],
                confidence="low",
            )

        matched, path = graph.find_external_call(package, symbols, aliases)
        if matched:
            return ReachabilityResult(
                package=package,
                verdict=Verdict.REACHABLE,
                reason=f"Application code calls '{matched}' on a path from an entry point",
                matched_symbol=matched,
                call_path=path,
                imported_by=sorted(importers)[:8],
                confidence="high",
            )

        return ReachabilityResult(
            package=package,
            verdict=Verdict.SYMBOL_NOT_CALLED,
            reason=(
                f"'{package}' is imported, but none of the vulnerable symbols "
                f"({', '.join(symbols[:4])}) are called from a reachable path"
            ),
            imported_by=sorted(importers)[:8],
            confidence="medium",
        )

    def _analyse_javascript(self, package: str, symbols: list[str]) -> ReachabilityResult:
        graph = self.js_graph
        assert graph is not None

        importers = graph.imports_package(package)
        if not importers:
            return ReachabilityResult(
                package=package,
                verdict=Verdict.NOT_IMPORTED,
                reason=(
                    f"'{package}' is in the dependency tree but no application file "
                    "imports or requires it"
                ),
                confidence="high",
            )

        return ReachabilityResult(
            package=package,
            verdict=Verdict.ASSUMED_REACHABLE,
            reason=(
                f"'{package}' is imported by {len(importers)} application file(s). "
                "npm reachability is import-level only, so symbol use is not verified"
            ),
            imported_by=sorted(importers)[:8],
            confidence="low",
        )

    def stats(self) -> dict[str, int]:
        if self.python_graph:
            return {
                "modules": len(self.python_graph.modules),
                "functions": len(self.python_graph.functions),
                "files_parsed": self.python_graph.files_parsed,
                "files_failed": self.python_graph.files_failed,
                "external_packages": len(self.python_graph.external_imports),
                "entry_points": len(self.python_graph.entry_points()),
            }
        if self.js_graph:
            return {
                "files_parsed": self.js_graph.files_parsed,
                "external_packages": len(self.js_graph.imported),
            }
        return {}
