"""Exposure family: leftover or sensitive files."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, NamedTuple

from ..context import ScanContext
from ..http import HttpClient
from ..models import Finding, Severity
from ..registry import register


def _is_html(head: bytes, ctype: str) -> bool:
    start = head.lstrip()[:15].lower()
    return "html" in ctype.lower() or start.startswith((b"<!doctype html", b"<html"))


def _looks_like_env(head: bytes) -> bool:
    return re.search(rb"^[A-Za-z_][A-Za-z0-9_]*\s*=", head, re.M) is not None


def _looks_like_config(head: bytes) -> bool:
    return b"DB_NAME" in head or b"<?php" in head


def _non_empty(head: bytes) -> bool:
    return len(head.strip()) > 0


class Target(NamedTuple):
    """A file to probe."""

    path: str
    label: str
    severity: Severity
    validator: Callable[[bytes], bool]


TARGETS = [
    Target("wp-content/debug.log", "debug log", Severity.HIGH, _non_empty),
    Target(".env", "environment file", Severity.CRITICAL, _looks_like_env),
    Target("wp-config.php.bak", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.php~", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.php.old", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.php.save", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.php.orig", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.php.txt", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.bak", "wp-config backup", Severity.CRITICAL, _looks_like_config),
    Target("wp-config.txt", "wp-config backup", Severity.CRITICAL, _looks_like_config),
]


@register("sensitive-files", "exposure", "Exposed debug.log, .env and wp-config backups")
def check_sensitive_files(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Request well-known paths and inspect only the first bytes.

    File contents are never stored or printed; the first few hundred bytes are
    only used to rule out soft-404 HTML pages.
    """
    targets = list(TARGETS)
    for extra in options.get("extra_paths") or []:
        targets.append(Target(str(extra), "extra file", Severity.HIGH, _non_empty))
    findings: List[Finding] = []
    for target in targets:
        resp = ctx.client.request(ctx.url(target.path), stream=True)
        if resp is None:
            continue
        status = resp.status_code
        ctype = resp.headers.get("Content-Type", "")
        head = HttpClient.read_head(resp, 512)
        if status == 200 and not _is_html(head, ctype) and target.validator(head):
            findings.append(
                Finding.issue(
                    "sensitive-files",
                    f"Exposed {target.label}: /{target.path}",
                    target.severity,
                    f"HTTP 200 and the content type looks like data, not a web page "
                    f"({ctype or 'unknown'}).",
                    "Delete the file or block access to it, and rotate any credentials in it.",
                    key=f"sensitive-files:{target.path}",
                )
            )
    return findings or [Finding.ok("sensitive-files", "No sensitive files exposed")]
