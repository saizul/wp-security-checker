"""SARIF 2.1.0 output, so results can be uploaded to GitHub code scanning."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from . import __version__
from .baseline import BaselineDiff
from .models import Finding, ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/saizul/wp-security-checker"

#: SARIF ``level`` per severity.
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
#: GitHub ranks alerts by the numeric ``security-severity`` rule property (CVSS-like, 0-10).
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rules(findings: List[Finding]) -> List[Dict[str, Any]]:
    """One rule per check id; its severity is the worst one seen for that check."""
    worst: Dict[str, Finding] = {}
    for finding in findings:
        current = worst.get(finding.check_id)
        if current is None or finding.severity.rank > current.severity.rank:
            worst[finding.check_id] = finding
    rules = []
    for check_id, finding in sorted(worst.items()):
        rule: Dict[str, Any] = {
            "id": check_id,
            "name": check_id,
            "shortDescription": {"text": finding.title},
            "defaultConfiguration": {"level": _LEVELS[finding.severity]},
            "properties": {
                "tags": ["security", "wordpress"],
                "security-severity": _SECURITY_SEVERITY[finding.severity],
            },
        }
        if finding.recommendation:
            rule["help"] = {"text": finding.recommendation}
        rules.append(rule)
    return rules


def _result(
    finding: Finding, rule_index: Dict[str, int], target: str, location: str, state: Optional[str]
) -> Dict[str, Any]:
    text = finding.title
    if finding.detail:
        text += f": {finding.detail}"
    if finding.recommendation:
        text += f" Recommendation: {finding.recommendation}"
    result: Dict[str, Any] = {
        "ruleId": finding.check_id,
        "ruleIndex": rule_index[finding.check_id],
        "level": _LEVELS[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": location}},
                "logicalLocations": [{"name": target, "kind": "resource"}],
            }
        ],
        # Stable across runs, so GitHub tracks the same alert instead of opening duplicates.
        "partialFingerprints": {"findingKey/v1": f"{target}|{finding.key}"},
        "properties": {
            "severity": finding.severity.value,
            "key": finding.key,
            "security-severity": _SECURITY_SEVERITY[finding.severity],
            "target": target,
        },
    }
    if state:
        result["baselineState"] = state
    return result


def to_sarif(
    result: ScanResult, diff: Optional[BaselineDiff] = None, location: str = "README.md"
) -> Dict[str, Any]:
    """Convert failing findings to a SARIF log (a plain dict).

    Passing findings are not reported. A scan has no source file, so each result points at
    ``location``, a path that exists in the repository that uploads the report.
    """
    failed = result.failed
    rules = _rules(failed)
    rule_index = {r["id"]: i for i, r in enumerate(rules)}
    new_keys = {f.key for f in diff.new} if diff is not None else set()
    results = [
        _result(
            f,
            rule_index,
            result.target,
            location,
            None if diff is None else ("new" if f.key in new_keys else "unchanged"),
        )
        for f in sorted(failed, key=lambda f: (-f.severity.rank, f.key))
    ]
    invocation: Dict[str, Any] = {
        "executionSuccessful": not result.errors,
        "endTimeUtc": result.scanned_at,
    }
    if result.errors:
        invocation["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": message}} for message in result.errors
        ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "wp-security-checker",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [invocation],
                "results": results,
            }
        ],
    }


def to_sarif_json(
    result: ScanResult, diff: Optional[BaselineDiff] = None, location: str = "README.md"
) -> str:
    """Render :func:`to_sarif` as indented JSON."""
    return json.dumps(to_sarif(result, diff, location), indent=2)
