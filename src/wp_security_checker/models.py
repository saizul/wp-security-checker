"""Data models shared by checks, reports and the CLI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from . import __version__


class Severity(str, Enum):
    """Severity levels, from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank, higher is more serious."""
        return _RANKS[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity name."""
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            names = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from exc


_RANKS = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


@dataclass
class Finding:
    """The outcome of one check item.

    ``key`` uniquely identifies the item inside a scan (for example
    ``sensitive-files:.env``) and is what baseline comparison uses.
    """

    check_id: str
    key: str
    title: str
    severity: Severity
    passed: bool
    detail: str = ""
    recommendation: str = ""

    @classmethod
    def ok(cls, check_id: str, title: str, detail: str = "", key: str = "") -> Finding:
        """Build a passing finding."""
        return cls(check_id, key or check_id, title, Severity.INFO, True, detail)

    @classmethod
    def issue(
        cls,
        check_id: str,
        title: str,
        severity: Severity,
        detail: str = "",
        recommendation: str = "",
        key: str = "",
    ) -> Finding:
        """Build a failing finding."""
        return cls(check_id, key or check_id, title, severity, False, detail, recommendation)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain JSON-compatible data."""
        return {
            "check_id": self.check_id,
            "key": self.key,
            "title": self.title,
            "severity": self.severity.value,
            "passed": self.passed,
            "detail": self.detail,
            "recommendation": self.recommendation,
        }


@dataclass
class ScanResult:
    """All findings produced by one scan."""

    target: str
    scanned_at: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def failed(self) -> List[Finding]:
        """Findings that represent a problem."""
        return [f for f in self.findings if not f.passed]

    @property
    def passed(self) -> List[Finding]:
        """Findings that are fine."""
        return [f for f in self.findings if f.passed]

    def counts(self) -> Dict[str, int]:
        """Number of failing findings per severity (all levels present)."""
        counts = {s.value: 0 for s in Severity}
        for finding in self.failed:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain JSON-compatible data."""
        return {
            "tool": "wp-security-checker",
            "version": __version__,
            "target": self.target,
            "scanned_at": self.scanned_at,
            "summary": {
                "failed": len(self.failed),
                "passed": len(self.passed),
                "by_severity": self.counts(),
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }
