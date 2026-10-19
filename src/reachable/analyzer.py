"""Conservative, import-free Python reachability analysis.

Only :mod:`ast` is used to inspect the target project. Target modules are
never imported, compiled, or executed; unresolved behavior is surfaced as
``UNKNOWN`` rather than guessed.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .advisories import normalize_osv_cache, normalize_osv_record, resolve_symbols
from .models import (
    Advisory,
    AnalysisResult,
    Confidence,
    Evidence,
    Finding,
    ReasonCode,
    Status,
    SymbolSource,
)

_SKIP_DIRS = {".git", ".venv", "venv", "env", "__pycache__", "node_modules", ".tox"}
_DYNAMIC_NAMES = {"eval", "exec", "getattr", "__import__", "compile"}


@dataclass
class _Definition:
    qualified: str
    path: str
    line: int
    node: ast.AST
    decorators: list[str] = field(default_factory=list)
    class_name: str | None = None


@dataclass
class _Call:
    origin: str
    target: str | None
    path: str
    line: int


@dataclass
class _Module:
    path: str
    name: str
    tree: ast.Module
    aliases: dict[str, str] = field(default_factory=dict)
    imported_packages: dict[str, Evidence] = field(default_factory=dict)
    definitions: dict[str, _Definition] = field(default_factory=dict)
    calls: list[_Call] = field(default_factory=list)
    dynamic: list[Evidence] = field(default_factory=list)


def _relative_module(current: str, level: int, module: str | None) -> str:
    parts = current.split(".")
    base = parts[:-1]
    if level > len(base) + 1:
        return module or ""
    prefix = base[: len(base) - level + 1] if level else base
    return ".".join(part for part in (*prefix, *(module or "").split(".")) if part)


def _package_key(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _attribute_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_text(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _decorator_text(node: ast.AST) -> str:
    return _attribute_text(node) or ""


def _is_route(definition: _Definition) -> bool:
    return any(
        text.rsplit(".", 1)[-1].lower() in {"route", "get", "post", "put", "patch", "delete", "api_route"}
        for text in definition.decorators
    )


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


class _CallVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module: _Module,
        origin: str,
        body: Iterable[ast.stmt],
        current_class: str | None = None,
        initial_instances: Mapping[str, str] | None = None,
    ):
        self.module = module
        self.origin = origin
        self.current_class = current_class
        self.instance_types: dict[str, str] = dict(initial_instances or {})
        self._visit_body(body)

    def _visit_body(self, body: Iterable[ast.stmt]) -> None:
        for statement in body:
            self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Nested functions need their own scope and are collected separately.
        return

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.instance_types:
                return self.instance_types[node.id]
            if node.id == "self" and self.current_class:
                return self.current_class
            return self.module.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def _assignment_type(self, value: ast.AST) -> str | None:
        if not isinstance(value, ast.Call):
            return None
        return self._resolve(value.func)

    def _remember_assignment(self, target: ast.AST, value: ast.AST) -> None:
        target_type = self._assignment_type(value)
        if target_type is None:
            return
        if isinstance(target, ast.Name):
            self.instance_types[target.id] = target_type
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                if isinstance(item, ast.Name):
                    self.instance_types[item.id] = target_type

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._remember_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._remember_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        target = self._resolve(node.func)
        path = self.module.path
        line = getattr(node, "lineno", 1)
        if self._is_dynamic(node):
            name = _attribute_text(node.func) or "dynamic call"
            self.module.dynamic.append(Evidence(path, line, name, "dynamic", "static resolution is incomplete"))
        self.module.calls.append(_Call(self.origin, target, path, line))
        self.generic_visit(node)

    def _is_dynamic(self, node: ast.Call) -> bool:
        name = _attribute_text(node.func) or ""
        final = name.rsplit(".", 1)[-1]
        if final in _DYNAMIC_NAMES:
            return True
        return name in {
            "importlib.import_module",
            "pickle.loads",
            "pickle.load",
            "marshal.loads",
            "marshal.load",
        }


def _module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) or path.stem


def _collect_definitions(module: _Module, node: ast.AST, prefix: str | None = None, class_name: str | None = None) -> None:
    body = getattr(node, "body", [])
    for item in body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified = f"{prefix or module.name}.{item.name}"
            definition = _Definition(
                qualified,
                module.path,
                item.lineno,
                item,
                [_decorator_text(dec) for dec in item.decorator_list],
                class_name,
            )
            module.definitions[qualified] = definition
            _collect_definitions(module, item, qualified, class_name)
        elif isinstance(item, ast.ClassDef):
            qualified = f"{prefix or module.name}.{item.name}"
            module.definitions[qualified] = _Definition(qualified, module.path, item.lineno, item, [], qualified)
            _collect_definitions(module, item, qualified, qualified)


def _collect_imports(module: _Module, root: Path) -> None:
    class ImportVisitor(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                target = alias.name if alias.asname else alias.name.split(".")[0]
                module.aliases[local] = target
                package = _package_key(alias.name.split(".")[0])
                module.imported_packages.setdefault(package, Evidence(module.path, node.lineno, target, "import"))

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            base = _relative_module(module.name, node.level, node.module) if node.level else (node.module or "")
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                target = ".".join(part for part in (base, alias.name) if part)
                module.aliases[local] = target
                package = _package_key(target.split(".")[0])
                if package and package != _package_key(module.name.split(".")[0]):
                    module.imported_packages.setdefault(package, Evidence(module.path, node.lineno, target, "import"))

    ImportVisitor().visit(module.tree)


def _collect_calls(module: _Module) -> None:
    # Module-level statements are entry-point code. Definitions are visited in
    # their own scopes so an unused function cannot become reachable by itself.
    module_body: list[ast.stmt] = []
    for statement in module.tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        module_body.append(statement)
    module_visitor = _CallVisitor(module, module.name, module_body)
    for definition in module.definitions.values():
        if not isinstance(definition.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        _CallVisitor(
            module,
            definition.qualified,
            definition.node.body,
            definition.class_name,
            module_visitor.instance_types,
        )


def _parse_project(root: Path, include_tests: bool) -> tuple[list[_Module], list[Evidence]]:
    modules: list[_Module] = []
    parse_errors: list[Evidence] = []
    root = root.resolve()
    for path in sorted(root.rglob("*.py")):
        # Do not follow source symlinks: a project must not make the scanner
        # read files outside the requested analysis root.
        if path.is_symlink():
            continue
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(root)
        except (OSError, ValueError):
            continue
        relative_parts = resolved_path.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in relative_parts):
            continue
        if not include_tests and ("tests" in relative_parts or resolved_path.name.startswith("test_")):
            continue
        relative = resolved_path.relative_to(root).as_posix()
        try:
            tree = ast.parse(resolved_path.read_text(encoding="utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError) as error:
            line = getattr(error, "lineno", 1) or 1
            detail = str(error).splitlines()[0] if str(error) else "unable to parse source"
            parse_errors.append(Evidence(relative, line, kind="parse_error", detail=detail))
            continue
        module = _Module(relative, _module_name(root, path), tree)
        _collect_definitions(module, tree)
        _collect_imports(module, root)
        # Local definitions override an imported name when resolving calls.
        for qualified in module.definitions:
            if qualified.startswith(module.name + "."):
                module.aliases.setdefault(qualified.rsplit(".", 1)[-1], qualified)
        _collect_calls(module)
        modules.append(module)
    return modules, parse_errors


def _symbol_matches(target: str | None, vulnerable: str) -> bool:
    if not target:
        return False
    return target == vulnerable or target.startswith(vulnerable + ".")


def _entry_definitions(modules: list[_Module]) -> dict[str, Evidence]:
    roots: dict[str, Evidence] = {}
    for module in modules:
        for definition in module.definitions.values():
            if _is_route(definition):
                roots[definition.qualified] = Evidence(
                    definition.path, definition.line, definition.qualified, "entry", "route decorator"
                )
        for statement in module.tree.body:
            if isinstance(statement, ast.If) and _is_main_guard(statement):
                roots[module.name] = Evidence(module.path, statement.lineno, module.name, "entry", "__main__ guard")
    # Source-only fixture projects and small scripts often expose a function
    # without a framework decorator or a __main__ block. Treating top-level
    # functions as fallback entries is conservative for this v1 graph: it can
    # prove a direct call inside the function, but never invents a caller hop.
    if not roots:
        for module in modules:
            for definition in module.definitions.values():
                if isinstance(definition.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    roots.setdefault(definition.qualified, Evidence(
                        definition.path, definition.line, definition.qualified, "entry", "top-level function fallback"
                    ))
    return roots


def _find_chain(modules: list[_Module], vulnerable: list[str]) -> tuple[list[Evidence], Evidence | None]:
    roots = _entry_definitions(modules)
    calls_by_origin: dict[str, list[_Call]] = {}
    for module in modules:
        for call in module.calls:
            calls_by_origin.setdefault(call.origin, []).append(call)
            # Module-level code is always an entry point, including imports
            # followed by a call; this is why it is represented separately.
            if call.origin == module.name:
                roots.setdefault(module.name, Evidence(call.path, call.line, module.name, "entry", "module-level code"))

    def walk(origin: str, chain: list[Evidence], seen: set[str]) -> tuple[list[Evidence], Evidence] | None:
        if origin in seen:
            return None
        seen = seen | {origin}
        for call in calls_by_origin.get(origin, []):
            if call.target is None:
                continue
            edge = Evidence(call.path, call.line, call.target, "call")
            next_chain = chain + [edge]
            if any(_symbol_matches(call.target, symbol) for symbol in vulnerable):
                return next_chain, edge
            if call.target in calls_by_origin:
                found = walk(call.target, next_chain, seen)
                if found:
                    return found
        return None

    for root, evidence in roots.items():
        found = walk(root, [evidence], set())
        if found:
            return found
    return [], None


def _coerce_advisories(advisories: Any) -> list[Advisory]:
    if isinstance(advisories, Advisory):
        return [advisories]
    if isinstance(advisories, Mapping):
        if "vulnerabilities" in advisories or "results" in advisories:
            return normalize_osv_cache(advisories)
        return [normalize_osv_record(advisories)]
    return [item if isinstance(item, Advisory) else normalize_osv_record(item) for item in advisories]


def _dependency_is_transitive(dependencies: Mapping[str, Any] | None, package: str) -> bool:
    if not dependencies:
        return False
    dependency_key = _package_key(package)
    dependency_name = next((name for name in dependencies if _package_key(str(name)) == dependency_key), None)
    if dependency_name is None:
        return False
    value = dependencies[dependency_name]
    if isinstance(value, Mapping):
        return value.get("direct") is False or value.get("transitive") is True
    return value is False or value == "transitive"


def analyze_project(
    project_root: str | os.PathLike[str],
    advisories: Any,
    *,
    symbol_map: Mapping[str, Any] | None = None,
    symbol_map_path: str | os.PathLike[str] | None = None,
    dependencies: Mapping[str, Any] | None = None,
    include_tests: bool = False,
) -> AnalysisResult:
    """Analyze Python source against normalized or raw offline OSV records."""

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError(f"project root is not a directory: {project_root}")
    modules, parse_errors = _parse_project(root, include_tests)
    dynamic = [evidence for module in modules for evidence in module.dynamic]
    imported: dict[str, Evidence] = {}
    for module in modules:
        for package, evidence in module.imported_packages.items():
            imported.setdefault(package, evidence)
    findings: list[Finding] = []
    for advisory in _coerce_advisories(advisories):
        symbols = resolve_symbols(advisory, symbol_map, symbol_map_path=symbol_map_path)
        source = symbols[0].source if symbols else SymbolSource.NONE
        confidence = symbols[0].confidence if symbols else Confidence.LOW
        symbol_names = [symbol.name for symbol in symbols]
        common = dict(
            advisory_id=advisory.id,
            package=advisory.package,
            symbol_source=source,
            symbol=symbol_names[0] if symbol_names else None,
            summary=advisory.summary,
        )
        if not symbols:
            findings.append(Finding(
                status=Status.UNKNOWN,
                reason=ReasonCode.NO_SYMBOL_IN_ADVISORY,
                confidence=Confidence.LOW,
                message="The advisory does not identify a callable or module to trace.",
                evidence=[],
                call_chain=[],
                **common,
            ))
            continue
        if _dependency_is_transitive(dependencies, advisory.package):
            evidence = imported.get(advisory.package)
            findings.append(Finding(
                status=Status.UNKNOWN,
                reason=ReasonCode.TRANSITIVE_DEPENDENCY,
                confidence=Confidence.LOW,
                message="Transitive dependencies are not traced in v1.",
                evidence=[evidence] if evidence else [],
                call_chain=[],
                **common,
            ))
            continue
        chain, vulnerable_edge = _find_chain(modules, symbol_names)
        if chain:
            findings.append(Finding(
                status=Status.REACHABLE,
                reason=ReasonCode.CALL_CHAIN_FOUND,
                confidence=confidence,
                message="A static call chain reaches the vulnerable symbol.",
                evidence=chain,
                call_chain=chain,
                **common,
            ))
            continue
        if parse_errors:
            findings.append(Finding(
                status=Status.UNKNOWN,
                reason=ReasonCode.PARSE_ERROR,
                confidence=Confidence.LOW,
                message="At least one Python file could not be parsed, so reachability is incomplete.",
                evidence=parse_errors,
                call_chain=[],
                **common,
            ))
            continue
        if dynamic and _package_key(advisory.package) in imported:
            findings.append(Finding(
                status=Status.UNKNOWN,
                reason=ReasonCode.DYNAMIC_CODE_BLOCKS_ANALYSIS,
                confidence=Confidence.LOW,
                message="Dynamic dispatch prevents a conservative conclusion for this alert.",
                evidence=dynamic,
                call_chain=[],
                **common,
            ))
            continue
        package_key = _package_key(advisory.package)
        if package_key not in imported:
            findings.append(Finding(
                status=Status.NOT_PROVEN_REACHABLE,
                reason=ReasonCode.PACKAGE_NOT_IMPORTED,
                confidence=Confidence.HIGH,
                message="The vulnerable package is not imported by scanned Python files.",
                evidence=[],
                call_chain=[],
                **common,
            ))
        else:
            evidence = imported[package_key]
            findings.append(Finding(
                status=Status.NOT_PROVEN_REACHABLE,
                reason=ReasonCode.SYMBOL_NOT_CALLED,
                confidence=Confidence.HIGH,
                message="The package is imported, but no call to the vulnerable symbol was found.",
                evidence=[evidence],
                call_chain=[],
                **common,
            ))
    return AnalysisResult(root.as_posix(), findings, parse_errors, dynamic)


# Names that are convenient for a later FastAPI/CLI layer.
scan_project = analyze_project
analyze = analyze_project


scan = analyze_project
