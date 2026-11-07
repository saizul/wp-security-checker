"""Compare a scan with a previous JSON run."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .models import Finding, ScanResult


class BaselineError(ValueError):
    """Raised when a baseline file is unusable."""


@dataclass
class BaselineDiff:
    """Differences between a previous run and the current one."""

    new: List[Finding] = field(default_factory=list)
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "new": [f.to_dict() for f in self.new],
            "resolved": list(self.resolved),
            "unchanged": [f.to_dict() for f in self.unchanged],
        }


def load_baseline(path: str) -> Dict[str, Any]:
    """Read and validate a previous ``--json`` result."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise BaselineError(f"baseline {path} is not valid JSON") from exc
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list) or not all(
        isinstance(f, dict) and "key" in f and "passed" in f for f in findings
    ):
        raise BaselineError(f"baseline {path} does not look like wp-security-checker output")
    return data


def diff_against(previous: Dict[str, Any], current: ScanResult) -> BaselineDiff:
    """Classify failing findings as new, unchanged or resolved."""
    before = {f["key"]: f for f in previous["findings"] if not f["passed"]}
    now = {f.key: f for f in current.failed}
    diff = BaselineDiff()
    for key, finding in now.items():
        (diff.unchanged if key in before else diff.new).append(finding)
    diff.resolved = [f for key, f in before.items() if key not in now]
    return diff
