"""Small environment configuration helpers with safe local defaults."""
from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_dotenv(path: str | Path | None = None) -> None:
    """Load simple KEY=VALUE settings without overriding the process environment."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    env_path = Path(path) if path else Path.cwd() / ".env"
    if not env_path.is_file():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key.isidentifier():
            os.environ.setdefault(key, value)


def setting(name: str, default: str | None = None) -> str | None:
    load_dotenv()
    value = os.environ.get(name)
    return value if value else default
