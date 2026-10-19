"""Small, serialisable contracts shared by the offline analyzer.

The models deliberately contain no framework types. They are useful to a CLI,
tests, or a later HTTP layer and keep static analysis independent from display.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping


class _StringEnum(str, Enum):
    def __str__(self) -> str:
        return self.value


class Status(_StringEnum):
    REACHABLE = "REACHABLE"
    NOT_PROVEN_REACHABLE = "NOT_PROVEN_REACHABLE"
    UNKNOWN = "UNKNOWN"


class ReasonCode(_StringEnum):
    CALL_CHAIN_FOUND = "CALL_CHAIN_FOUND"
    PACKAGE_NOT_IMPORTED = "PACKAGE_NOT_IMPORTED"
    SYMBOL_NOT_CALLED = "SYMBOL_NOT_CALLED"
    NO_SYMBOL_IN_ADVISORY = "NO_SYMBOL_IN_ADVISORY"
    DYNAMIC_CODE_BLOCKS_ANALYSIS = "DYNAMIC_CODE_BLOCKS_ANALYSIS"
    TRANSITIVE_DEPENDENCY = "TRANSITIVE_DEPENDENCY"
    PARSE_ERROR = "PARSE_ERROR"


class Confidence(_StringEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SymbolSource(_StringEnum):
    OSV_STRUCTURED = "osv_structured"
    CURATED_MAP = "curated_map"
    INFERRED_FROM_TEXT = "inferred_from_text"
    NONE = "none"


@dataclass(frozen=True)
class Evidence:
    """One source location supporting a finding or uncertainty."""

    file: str
    line: int
    symbol: str | None = None
    kind: str = "source"
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ResolvedSymbol:
    """A vulnerable callable/module name and where that name came from."""

    package: str
    name: str
    source: SymbolSource
    confidence: Confidence
    advisory_id: str | None = None
    source_url: str | None = None

    @property
    def symbol(self) -> str:
        return self.name

    @property
    def symbol_source(self) -> SymbolSource:
        return self.source

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["source"] = self.source.value
        result["confidence"] = self.confidence.value
        return result


@dataclass
class Advisory:
    """Normalized subset of an OSV vulnerability record used by v1."""

    id: str
    package: str
    ecosystem: str = "PyPI"
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    references: list[str] = field(default_factory=list)
    affected: list[dict[str, Any]] = field(default_factory=list)
    structured_symbols: list[str] = field(default_factory=list)
    database_specific: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def text(self) -> str:
        return "\n".join(part for part in (self.summary, self.details) if part)

    @property
    def vulnerable_symbols(self) -> list[str]:
        return self.structured_symbols

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "package": self.package,
            "ecosystem": self.ecosystem,
            "aliases": list(self.aliases),
            "summary": self.summary,
            "details": self.details,
            "references": list(self.references),
            "affected": self.affected,
            "structured_symbols": list(self.structured_symbols),
            "database_specific": self.database_specific,
        }


@dataclass
class Finding:
    """Classification for one advisory in one scanned project."""

    advisory_id: str
    package: str
    status: Status
    reason: ReasonCode
    confidence: Confidence
    symbol_source: SymbolSource
    symbol: str | None = None
    summary: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    call_chain: list[Evidence] = field(default_factory=list)
    message: str = ""

    @property
    def reason_code(self) -> ReasonCode:
        return self.reason

    @property
    def why(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("status", "reason", "confidence", "symbol_source"):
            result[key] = getattr(self, key).value
        result["reason_code"] = result["reason"]
        result["why"] = result["message"]
        result["evidence"] = [item.to_dict() for item in self.evidence]
        result["call_chain"] = [item.to_dict() for item in self.call_chain]
        return result


@dataclass
class AnalysisResult:
    """Stable aggregate returned by :func:`reachable.analyzer.analyze_project`."""

    project_root: str
    findings: list[Finding] = field(default_factory=list)
    parse_errors: list[Evidence] = field(default_factory=list)
    dynamic_evidence: list[Evidence] = field(default_factory=list)

    @property
    def alerts(self) -> list[Finding]:
        return self.findings

    @property
    def results(self) -> list[Finding]:
        return self.findings

    @property
    def summary(self) -> dict[str, int]:
        counts = {"total": len(self.findings), "reachable": 0, "not_proven_reachable": 0, "unknown": 0}
        for finding in self.findings:
            if finding.status is Status.REACHABLE:
                counts["reachable"] += 1
            elif finding.status is Status.NOT_PROVEN_REACHABLE:
                counts["not_proven_reachable"] += 1
            else:
                counts["unknown"] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        findings = [finding.to_dict() for finding in self.findings]
        return {
            "project_root": self.project_root,
            "findings": findings,
            "alerts": findings,
            "summary": self.summary,
            "parse_errors": [item.to_dict() for item in self.parse_errors],
            "dynamic_evidence": [item.to_dict() for item in self.dynamic_evidence],
        }


def enum_value(value: Any) -> str:
    """Return an enum's wire value while accepting plain strings."""

    return value.value if isinstance(value, Enum) else str(value)


def as_mapping(value: Any) -> Mapping[str, Any]:
    """Accept either an Advisory or a JSON-shaped advisory."""

    if isinstance(value, Advisory):
        return value.to_dict()
    if isinstance(value, Mapping):
        return value
    raise TypeError(f"expected Advisory or mapping, got {type(value).__name__}")


# Compatibility names for callers that describe the result as a classification.
Classification = Status
Reason = ReasonCode

Alert = Finding
