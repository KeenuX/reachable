"""Offline OSV loading, normalization, and layered symbol resolution."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import Advisory, Confidence, ResolvedSymbol, SymbolSource


_SYMBOL_KEYS = {
    "callable",
    "callables",
    "affected_function",
    "affected_functions",
    "function",
    "functions",
    "import_path",
    "import_paths",
    "module",
    "modules",
    "symbol",
    "symbols",
    "vulnerable_function",
    "vulnerable_functions",
}
_IDENTIFIER = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)(?:\(\))?")


def _as_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple, set)):
        return " ".join(_as_text(item) for item in value)
    return ""


def _clean_symbol(value: Any, package: str) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().strip("` ").removesuffix("()")
    value = value.replace("::", ".")
    if not value or any(char in value for char in " /\\"):
        return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", value):
        return None
    if "." not in value and package:
        value = f"{package}.{value}"
    return value


def _dedupe(values: Iterable[str], package: str) -> list[str]:
    result: list[str] = []
    for value in values:
        symbol = _clean_symbol(value, package)
        if symbol and symbol not in result:
            result.append(symbol)
    return result


def _structured_symbols(value: Any, package: str, key: str = "") -> list[str]:
    """Extract only explicitly symbol-shaped OSV extension fields."""

    found: list[str] = []
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            lowered = str(child_key).lower().replace("-", "_")
            if lowered in _SYMBOL_KEYS:
                if isinstance(child, str):
                    found.append(child)
                elif isinstance(child, (list, tuple, set)):
                    found.extend(item for item in child if isinstance(item, str))
                elif isinstance(child, Mapping):
                    found.extend(str(item) for item in child.values() if isinstance(item, str))
            elif isinstance(child, (Mapping, list, tuple)):
                found.extend(_structured_symbols(child, package, lowered))
    elif isinstance(value, (list, tuple)):
        for child in value:
            found.extend(_structured_symbols(child, package, key))
    return _dedupe(found, package)


def _package_data(record: Mapping[str, Any]) -> tuple[str, str]:
    affected = record.get("affected") or []
    if isinstance(affected, list):
        for item in affected:
            if not isinstance(item, Mapping):
                continue
            package = item.get("package")
            if isinstance(package, Mapping) and package.get("name"):
                return str(package["name"]), str(package.get("ecosystem", "PyPI"))
    package = record.get("package")
    if isinstance(package, Mapping):
        return str(package.get("name", "")), str(package.get("ecosystem", "PyPI"))
    return str(package or record.get("project") or record.get("name", "")), str(record.get("ecosystem", "PyPI"))


def _first_text(value: Any) -> str | None:
    """Return a useful scalar from OSV's several extension shapes."""

    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, Mapping):
        for key in ("label", "severity", "score", "value"):
            found = _first_text(value.get(key))
            if found:
                return found
    if isinstance(value, (list, tuple)):
        for item in value:
            found = _first_text(item)
            if found:
                return found
    return None


def _record_severity(record: Mapping[str, Any]) -> str | None:
    """Extract a displayable severity without interpreting CVSS scores."""

    candidates: list[Any] = [record.get("severity")]
    database_specific = record.get("database_specific")
    if isinstance(database_specific, Mapping):
        candidates.extend((database_specific.get("severity"), database_specific.get("severity_label")))
    for affected in record.get("affected") or []:
        if not isinstance(affected, Mapping):
            continue
        for section_name in ("database_specific", "ecosystem_specific"):
            section = affected.get(section_name)
            if isinstance(section, Mapping):
                candidates.extend((section.get("severity"), section.get("severity_label")))
    found = next((found for candidate in candidates if (found := _first_text(candidate))), None)
    if not found:
        return None
    normalized = found.strip().lower()
    aliases = {"moderate": "medium", "informational": "low"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in {"critical", "high", "medium", "low", "unknown"} else "unknown"


def _record_fixed_version(record: Mapping[str, Any]) -> str | None:
    """Return the first explicit fixed version in an OSV range."""

    candidates: list[Any] = [record.get("fixed_version"), record.get("fixed"), record.get("fix_versions")]
    database_specific = record.get("database_specific")
    if isinstance(database_specific, Mapping):
        candidates.extend((database_specific.get("fixed_version"), database_specific.get("fixed")))
    for affected in record.get("affected") or []:
        if not isinstance(affected, Mapping):
            continue
        for section_name in ("database_specific", "ecosystem_specific"):
            section = affected.get(section_name)
            if isinstance(section, Mapping):
                candidates.extend((section.get("fixed_version"), section.get("fixed")))
        ranges = affected.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, Mapping):
                continue
            events = version_range.get("events") or []
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, Mapping):
                    candidates.append(event.get("fixed"))
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        if isinstance(candidate, (list, tuple)):
            for nested in candidate:
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
    return None


def normalize_osv_record(record: Mapping[str, Any]) -> Advisory:
    """Normalize one OSV vulnerability while retaining its original shape.

    OSV itself does not mandate vulnerable Python callables.  Extensions such
    as ``database_specific.affected_functions`` are therefore considered
    structured only when their field names explicitly describe symbols.
    """

    if not isinstance(record, Mapping):
        raise TypeError("an OSV record must be a mapping")
    package, ecosystem = _package_data(record)
    database_specific = record.get("database_specific")
    if not isinstance(database_specific, dict):
        database_specific = {}
    structured = _structured_symbols(record, package)
    aliases_value = record.get("aliases", [])
    if isinstance(aliases_value, str):
        aliases_value = [aliases_value]
    if not isinstance(aliases_value, (list, tuple, set)):
        aliases_value = []
    aliases = [str(item) for item in aliases_value if isinstance(item, str)]
    references = []
    for item in record.get("references", []) or []:
        if isinstance(item, Mapping) and isinstance(item.get("url"), str):
            references.append(str(item["url"]))
        elif isinstance(item, str):
            references.append(item)
    for item in record.get("urls", []) or []:
        if isinstance(item, str) and item not in references:
            references.append(item)
    affected_value = record.get("affected") or []
    affected = affected_value if isinstance(affected_value, list) else []
    return Advisory(
        id=str(record.get("id") or (aliases[0] if aliases else "unknown")),
        package=package,
        ecosystem=ecosystem,
        aliases=aliases,
        summary=str(record.get("summary") or record.get("description") or ""),
        details=str(record.get("details") or record.get("description") or ""),
        references=references,
        severity=_record_severity(record),
        fixed_version=_record_fixed_version(record),
        affected=affected,
        structured_symbols=structured,
        database_specific=database_specific,
        raw=dict(record),
    )


def normalize_osv_cache(payload: Any) -> list[Advisory]:
    """Normalize an OSV response, cache export, or list of records."""

    if isinstance(payload, Mapping):
        records = payload.get("records")
        if records is None:
            records = payload.get("vulnerabilities")
        if records is None:
            records = payload.get("results")
        if records is None and "id" in payload:
            records = [payload]
    else:
        records = payload
    if not isinstance(records, list):
        raise ValueError("OSV cache must contain a records list")
    return [normalize_osv_record(record) for record in records if isinstance(record, Mapping)]


def load_osv_cache(path: str | Path) -> list[Advisory]:
    """Read a local OSV JSON file; this function never performs network I/O."""

    with Path(path).open(encoding="utf-8") as handle:
        return normalize_osv_cache(json.load(handle))


def _curated_entries(curated_map: Mapping[str, Any], package: str) -> tuple[list[str], str | None]:
    normalized = package.strip().lower().replace("-", "_").replace(".", "_")
    value = curated_map.get(package)
    if value is None:
        value = next((candidate for key, candidate in curated_map.items()
                      if str(key).strip().lower().replace("-", "_").replace(".", "_") == normalized), {})
    if isinstance(value, list):
        return [str(item) for item in value], None
    if not isinstance(value, Mapping):
        return [], None
    symbols = value.get("symbols") or value.get("functions") or value.get("callables") or []
    if isinstance(symbols, str):
        symbols = [symbols]
    url = value.get("source_url") or value.get("url")
    return [str(item) for item in symbols if isinstance(item, str)], str(url) if url else None


def load_symbol_map(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, Mapping):
        raise ValueError("symbol map must be a JSON object")
    return dict(payload)


def _inferred_symbols(advisory: Advisory) -> list[str]:
    candidates = _IDENTIFIER.findall(advisory.text)
    package = advisory.package.lower().replace("-", "_")
    # Advisory prose may name a module from a vendored or differently
    # normalized distribution package. Preserve the identifier and label it
    # inferred rather than discarding useful evidence.
    return _dedupe(candidates, advisory.package)


def resolve_symbols(
    advisory: Advisory | Mapping[str, Any],
    curated_map: Mapping[str, Any] | None = None,
    *,
    symbol_map_path: str | Path | None = None,
) -> list[ResolvedSymbol]:
    """Resolve symbols in priority order: OSV, curated map, then advisory text."""

    if not isinstance(advisory, Advisory):
        advisory = normalize_osv_record(advisory)
    if symbol_map_path is not None:
        curated_map = load_symbol_map(symbol_map_path)
    curated_map = curated_map or {}
    if advisory.structured_symbols:
        return [
            ResolvedSymbol(advisory.package, symbol, SymbolSource.OSV_STRUCTURED, Confidence.HIGH, advisory.id)
            for symbol in advisory.structured_symbols
        ]
    symbols, url = _curated_entries(curated_map, advisory.package)
    symbols = _dedupe(symbols, advisory.package)
    if symbols:
        return [
            ResolvedSymbol(advisory.package, symbol, SymbolSource.CURATED_MAP, Confidence.HIGH, advisory.id, url)
            for symbol in symbols
        ]
    inferred = _inferred_symbols(advisory)
    return [
        ResolvedSymbol(advisory.package, symbol, SymbolSource.INFERRED_FROM_TEXT, Confidence.MEDIUM, advisory.id)
        for symbol in inferred
    ]


# Friendly aliases for the later API layer.
normalize_record = normalize_osv_record
resolve_advisory_symbols = resolve_symbols


# Explicit names used by integrations that prefer verb-oriented APIs.
load_osv_records = load_osv_cache
normalize_advisory = normalize_osv_record
resolve_vulnerable_symbols = resolve_symbols
