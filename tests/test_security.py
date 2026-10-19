from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def _implementation_files():
    if not SRC.is_dir():
        pytest.skip("src/ is not present; implementation security checks activate with the backend")
    files = sorted(SRC.rglob("*.py"))
    if not files:
        pytest.skip("no Python implementation files are present yet")
    return files


def test_subprocess_calls_never_enable_shell_execution():
    violations = []
    for path in _implementation_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"run", "Popen", "call", "check_call", "check_output"}:
                continue
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    violations.append(f"{path}:{node.lineno}")
    assert not violations, "shell=True is forbidden: " + ", ".join(violations)


def test_server_source_does_not_default_to_all_interfaces():
    violations = []
    for path in _implementation_files():
        text = path.read_text(encoding="utf-8")
        if "0.0.0.0" in text:
            violations.append(str(path))
    assert not violations, "loopback-only server must not contain a 0.0.0.0 bind: " + ", ".join(violations)
