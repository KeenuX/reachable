"""Conservative, import-free Python reachability analysis.

Python source is inspected with :mod:`ast` and declarative metadata is read
with standard-library parsers. Target modules are never imported, compiled,
or executed; unresolved behavior is surfaced as ``UNKNOWN`` rather than
guessed.
"""

from __future__ import annotations

import ast
import configparser
import os
import re
import tomllib
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
_REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*")
_EXACT_VERSION = re.compile(r"(?:^|,)\s*={2,3}\s*([^\s,;]+)")


def _canonical_requirement_name(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(".", "_")


def _safe_file(path: Path, root: Path) -> Path | None:
    """Resolve a metadata file only when it remains inside ``root``."""

    if path.is_symlink() or not path.is_file():
        return None
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return resolved


def _load_pyproject(root: Path) -> dict[str, Any]:
    path = _safe_file(root / "pyproject.toml", root)
    if path is None:
        return {}
    try:
        with path.open("rb") as handle:
            payload = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        # Metadata is optional input. A malformed or unsupported file must not
        # cause target code to be imported or executed as a recovery strategy.
        return {}
    return payload if isinstance(payload, dict) else {}


def _dependency_value(
    dependencies: dict[str, dict[str, Any]],
    raw_name: str,
    *,
    specifier: str = "",
    source: str,
    direct: bool = True,
    optional: bool = False,
) -> None:
    name = raw_name.strip()
    if not name or _canonical_requirement_name(name) in {"python", "python_version"}:
        return
    existing = dependencies.setdefault(
        name,
        {
            "name": name,
            "direct": direct,
            "declared": True,
            "optional": optional,
            "specifier": "",
            "installed_version": None,
            "sources": [],
        },
    )
    existing["direct"] = bool(existing.get("direct", direct) and direct)
    existing["optional"] = bool(existing.get("optional", False) or optional)
    if source not in existing["sources"]:
        existing["sources"].append(source)
    specifier = str(specifier or "").strip()
    if specifier and not existing.get("specifier"):
        existing["specifier"] = specifier
    if existing.get("installed_version") is None:
        match = _EXACT_VERSION.search(specifier)
        if match:
            existing["installed_version"] = match.group(1)


def _requirement_parts(raw: Any) -> tuple[str, str] | None:
    if not isinstance(raw, str):
        return None
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    if " #" in line:
        line = line.split(" #", 1)[0].rstrip()
    if line.startswith("-e "):
        line = line[3:].strip()
    egg_match = re.search(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9_.-]*)", line)
    if egg_match and (line.startswith(("git+", "hg+", "svn+", "bzr+", "http://", "https://"))):
        return egg_match.group(1), ""
    if line.startswith(("-", "--")):
        return None
    match = _REQUIREMENT_NAME.match(line)
    if not match:
        return None
    name = match.group(0)
    return name, line[match.end():].strip()


def _requirement_lines(text: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if current:
            current += " " + line
        else:
            current = line
        if current.endswith("\\"):
            current = current[:-1].rstrip()
            continue
        lines.append(current)
        current = ""
    if current:
        lines.append(current)
    return lines


def _read_requirements_file(
    path: Path,
    root: Path,
    dependencies: dict[str, dict[str, Any]],
    seen: set[Path],
    *,
    scan_subfolders: bool = True,
) -> None:
    resolved = _safe_file(path, root)
    if resolved is None or resolved in seen:
        return
    if not scan_subfolders and len(resolved.relative_to(root).parts) > 1:
        return
    seen.add(resolved)
    try:
        text = resolved.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for line in _requirement_lines(text):
        include_match = re.match(r"^(?:-r|--requirement)\s+(.+)$", line)
        constraint_match = re.match(r"^(?:-c|--constraint)\s+(.+)$", line)
        if include_match or constraint_match:
            included = include_match or constraint_match
            include_path = (resolved.parent / included.group(1).strip()).resolve()
            _read_requirements_file(
                include_path,
                root,
                dependencies,
                seen,
                scan_subfolders=scan_subfolders,
            )
            continue
        parts = _requirement_parts(line)
        if parts:
            name, specifier = parts
            _dependency_value(dependencies, name, specifier=specifier, source=resolved.name)


def _literal_assignment_values(tree: ast.AST) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [target for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target]
        else:
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError, SyntaxError):
            continue
        for target in targets:
            values[target.id] = value
    return values


def _setup_py_dependencies(root: Path, dependencies: dict[str, dict[str, Any]]) -> None:
    path = _safe_file(root / "setup.py", root)
    if path is None:
        return
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    except (OSError, SyntaxError, UnicodeDecodeError):
        return
    values = _literal_assignment_values(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, (ast.Name, ast.Attribute)):
            continue
        function_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        if function_name != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg not in {"install_requires", "extras_require"}:
                continue
            value: Any
            try:
                value = ast.literal_eval(keyword.value)
            except (ValueError, TypeError, SyntaxError):
                value = values.get(keyword.value.id) if isinstance(keyword.value, ast.Name) else None
            if keyword.arg == "install_requires":
                entries = value if isinstance(value, (list, tuple, set)) else []
                for entry in entries:
                    parts = _requirement_parts(entry)
                    if parts:
                        _dependency_value(dependencies, parts[0], specifier=parts[1], source="setup.py")
            elif isinstance(value, Mapping):
                for entries in value.values():
                    if isinstance(entries, str):
                        entries = [entries]
                    if not isinstance(entries, (list, tuple, set)):
                        continue
                    for entry in entries:
                        parts = _requirement_parts(entry)
                        if parts:
                            _dependency_value(dependencies, parts[0], specifier=parts[1], source="setup.py", optional=True)


def discover_dependencies(
    project_root: str | os.PathLike[str],
    *,
    scan_subfolders: bool = True,
) -> dict[str, dict[str, Any]]:
    """Read dependency declarations without importing or executing a project.

    The returned values retain the source and exact pinned version when the
    declaration provides one. Unsupported dynamic metadata is ignored rather
    than evaluated.
    """

    root = Path(project_root).resolve()
    if not root.is_dir():
        return {}
    dependencies: dict[str, dict[str, Any]] = {}
    pyproject = _load_pyproject(root)
    project = pyproject.get("project")
    if isinstance(project, Mapping):
        for entry in project.get("dependencies", []) or []:
            parts = _requirement_parts(entry)
            if parts:
                _dependency_value(dependencies, parts[0], specifier=parts[1], source="pyproject.toml")
        optional = project.get("optional-dependencies")
        if isinstance(optional, Mapping):
            for entries in optional.values():
                if isinstance(entries, str):
                    entries = [entries]
                if not isinstance(entries, (list, tuple)):
                    continue
                for entry in entries:
                    parts = _requirement_parts(entry)
                    if parts:
                        _dependency_value(
                            dependencies,
                            parts[0],
                            specifier=parts[1],
                            source="pyproject.toml",
                            optional=True,
                        )

    # Poetry and PDM tables are declarative TOML and can be read safely too.
    tool = pyproject.get("tool")
    if isinstance(tool, Mapping):
        poetry = tool.get("poetry")
        poetry_dependencies: list[Mapping[str, Any]] = []
        if isinstance(poetry, Mapping):
            if isinstance(poetry.get("dependencies"), Mapping):
                poetry_dependencies.append(poetry["dependencies"])
            groups = poetry.get("group")
            if isinstance(groups, Mapping):
                for group in groups.values():
                    if isinstance(group, Mapping) and isinstance(group.get("dependencies"), Mapping):
                        poetry_dependencies.append(group["dependencies"])
        for table in poetry_dependencies:
            for name, value in table.items():
                if _canonical_requirement_name(str(name)) == "python":
                    continue
                if isinstance(value, str):
                    specifier = value
                elif isinstance(value, Mapping):
                    specifier = str(value.get("version") or "")
                else:
                    specifier = ""
                _dependency_value(dependencies, str(name), specifier=specifier, source="pyproject.toml")
        pdm = tool.get("pdm")
        if isinstance(pdm, Mapping):
            table = pdm.get("dependencies")
            if isinstance(table, Mapping):
                for name, value in table.items():
                    specifier = str(value) if isinstance(value, str) else ""
                    _dependency_value(dependencies, str(name), specifier=specifier, source="pyproject.toml")
            dev_tables = pdm.get("dev-dependencies")
            if isinstance(dev_tables, Mapping):
                for entries in dev_tables.values():
                    if isinstance(entries, str):
                        entries = [entries]
                    if not isinstance(entries, (list, tuple)):
                        continue
                    for entry in entries:
                        parts = _requirement_parts(entry)
                        if parts:
                            _dependency_value(
                                dependencies,
                                parts[0],
                                specifier=parts[1],
                                source="pyproject.toml",
                                optional=True,
                            )

    requirement_paths = root.rglob("requirements*.txt") if scan_subfolders else root.glob("requirements*.txt")
    for path in sorted(requirement_paths):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        _read_requirements_file(path, root, dependencies, set(), scan_subfolders=scan_subfolders)

    setup_cfg = _safe_file(root / "setup.cfg", root)
    if setup_cfg is not None:
        parser = configparser.RawConfigParser()
        try:
            parser.read_string(setup_cfg.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, configparser.Error):
            parser = configparser.RawConfigParser()
        if parser.has_option("options", "install_requires"):
            for entry in _requirement_lines(parser.get("options", "install_requires")):
                parts = _requirement_parts(entry)
                if parts:
                    _dependency_value(dependencies, parts[0], specifier=parts[1], source="setup.cfg")
        if parser.has_section("options.extras_require"):
            for _, raw_entries in parser.items("options.extras_require"):
                for entry in _requirement_lines(raw_entries):
                    parts = _requirement_parts(entry)
                    if parts:
                        _dependency_value(
                            dependencies,
                            parts[0],
                            specifier=parts[1],
                            source="setup.cfg",
                            optional=True,
                        )

    _setup_py_dependencies(root, dependencies)
    return dependencies


def discover_console_scripts(project_root: str | os.PathLike[str]) -> dict[str, str]:
    """Discover declarative console scripts from ``pyproject.toml``."""

    pyproject = _load_pyproject(Path(project_root).resolve())
    scripts: dict[str, str] = {}
    project = pyproject.get("project")
    if isinstance(project, Mapping):
        values = project.get("scripts")
        if isinstance(values, Mapping):
            scripts.update({str(name): str(target) for name, target in values.items() if isinstance(target, str)})
        entry_points = project.get("entry-points")
        if isinstance(entry_points, Mapping):
            console = entry_points.get("console_scripts")
            if isinstance(console, Mapping):
                scripts.update({str(name): str(target) for name, target in console.items() if isinstance(target, str)})
    tool = pyproject.get("tool")
    if isinstance(tool, Mapping):
        poetry = tool.get("poetry")
        poetry_scripts = poetry.get("scripts") if isinstance(poetry, Mapping) else None
        if isinstance(poetry_scripts, Mapping):
            for name, target in poetry_scripts.items():
                if isinstance(target, str):
                    scripts.setdefault(str(name), target)
                elif isinstance(target, Mapping) and isinstance(target.get("call"), str):
                    scripts.setdefault(str(name), str(target["call"]))
    return scripts


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
    return value.strip().lower().replace("-", "_").replace(".", "_")


def _attribute_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _attribute_text(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _decorator_text(node: ast.AST) -> str:
    # Route decorators commonly arrive as a Call node, for example
    # ``@app.get(\"/reports\")``. Resolve the callable part without
    # evaluating decorator arguments.
    if isinstance(node, ast.Call):
        node = node.func
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
    if parts and parts[0] == "src" and (root / "src").is_dir():
        parts = parts[1:]
    if parts and parts[-1] == "__init__":
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


def _parse_project(
    root: Path,
    include_tests: bool,
    *,
    scan_subfolders: bool = True,
) -> tuple[list[_Module], list[Evidence]]:
    modules: list[_Module] = []
    parse_errors: list[Evidence] = []
    root = root.resolve()
    python_paths = root.rglob("*.py") if scan_subfolders else root.glob("*.py")
    for path in sorted(python_paths):
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
        if resolved_path.name == "setup.py":
            # Packaging metadata is parsed separately as literals; it is not
            # an application entry point or a runtime module.
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


def build_analysis_dependencies(
    project_root: str | os.PathLike[str],
    *,
    include_tests: bool = False,
    scan_subfolders: bool = True,
) -> dict[str, dict[str, Any]]:
    """Combine declared dependencies with imports without executing code.

    Declared packages remain direct. Imports missing from a declared inventory
    are represented as transitive when declarations exist; source-only projects
    keep them as unknown-directness so a local advisory can still be analyzed.
    """
    root = Path(project_root).resolve()
    dependencies = discover_dependencies(root, scan_subfolders=scan_subfolders)
    imported = discover_imported_packages(
        root,
        include_tests=include_tests,
        scan_subfolders=scan_subfolders,
    )
    has_declarations = bool(dependencies)
    for package in imported:
        if any(_package_key(str(name)) == package for name in dependencies):
            continue
        dependencies[package] = {
            "name": package,
            "direct": False if has_declarations else None,
            "declared": False,
            "imported": True,
            "installed_version": None,
            "specifier": "",
            "sources": ["source-import"],
        }
    return dependencies


def discover_imported_packages(
    project_root: str | os.PathLike[str],
    *,
    include_tests: bool = False,
    scan_subfolders: bool = True,
) -> set[str]:
    """Return normalized top-level imports found by the AST scanner."""

    root = Path(project_root).resolve()
    if not root.is_dir():
        return set()
    modules, _ = _parse_project(root, include_tests, scan_subfolders=scan_subfolders)
    return {
        package
        for module in modules
        for package in module.imported_packages
        if package
    }


def _symbol_matches(target: str | None, vulnerable: str) -> bool:
    if not target:
        return False
    return target == vulnerable or target.startswith(vulnerable + ".")


def _entry_definitions(
    modules: list[_Module],
    console_scripts: Mapping[str, str] | None = None,
) -> dict[str, Evidence]:
    roots: dict[str, Evidence] = {}
    definitions = {
        definition.qualified: definition
        for module in modules
        for definition in module.definitions.values()
    }
    for module in modules:
        for definition in module.definitions.values():
            if _is_route(definition):
                roots[definition.qualified] = Evidence(
                    definition.path, definition.line, definition.qualified, "entry", "route decorator"
                )
        for statement in module.tree.body:
            if isinstance(statement, ast.If) and _is_main_guard(statement):
                roots[module.name] = Evidence(module.path, statement.lineno, module.name, "entry", "__main__ guard")
    for script_name, raw_target in (console_scripts or {}).items():
        target = str(raw_target).strip()
        if ":" not in target:
            continue
        module_name, function_name = target.split(":", 1)
        function_name = function_name.split("[", 1)[0].strip().removesuffix("()")
        qualified = ".".join(part for part in (module_name.strip(), function_name) if part)
        definition = definitions.get(qualified)
        if definition is None:
            continue
        roots.setdefault(
            qualified,
            Evidence(
                definition.path,
                definition.line,
                qualified,
                "entry",
                f"console script: {script_name}",
            ),
        )
    return roots


def _find_chain(
    modules: list[_Module],
    vulnerable: list[str],
    console_scripts: Mapping[str, str] | None = None,
) -> tuple[list[Evidence], Evidence | None]:
    roots = _entry_definitions(modules, console_scripts)
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
    if advisories is None:
        return []
    if isinstance(advisories, Advisory):
        return [advisories]
    if isinstance(advisories, Mapping):
        if "records" in advisories or "vulnerabilities" in advisories or "results" in advisories:
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


def _installed_version(dependencies: Mapping[str, Any] | None, package: str) -> str | None:
    if not dependencies:
        return None
    wanted = _package_key(package)
    for name, value in dependencies.items():
        if _package_key(str(name)) != wanted:
            continue
        if isinstance(value, str):
            return value
        if isinstance(value, Mapping):
            version = value.get("installed_version") or value.get("version")
            return str(version) if version is not None else None
    return None


def analyze_project(
    project_root: str | os.PathLike[str],
    advisories: Any,
    *,
    symbol_map: Mapping[str, Any] | None = None,
    symbol_map_path: str | os.PathLike[str] | None = None,
    dependencies: Mapping[str, Any] | None = None,
    include_tests: bool = False,
    scan_subfolders: bool = True,
    console_scripts: Mapping[str, str] | None = None,
) -> AnalysisResult:
    """Analyze Python source against normalized or raw offline OSV records."""

    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError(f"project root is not a directory: {project_root}")
    modules, parse_errors = _parse_project(root, include_tests, scan_subfolders=scan_subfolders)
    if dependencies is None:
        dependencies = build_analysis_dependencies(
            root,
            include_tests=include_tests,
            scan_subfolders=scan_subfolders,
        )
    if console_scripts is None:
        console_scripts = discover_console_scripts(root)
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
            advisory_text=advisory.details or advisory.summary,
            installed_version=(
                _installed_version(dependencies, advisory.package)
                or (str(advisory.raw.get("version")) if advisory.raw.get("version") else None)
            ),
            severity=advisory.severity,
            fixed_version=advisory.fixed_version,
            references=list(advisory.references),
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
            evidence = imported.get(_package_key(advisory.package))
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
        chain, vulnerable_edge = _find_chain(modules, symbol_names, console_scripts)
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
