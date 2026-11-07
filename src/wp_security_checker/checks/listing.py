"""Exposure family: directory listing."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

_INDEX = re.compile(r"<title>\s*Index of|<h1>\s*Index of", re.I)


@register("directory-listing", "exposure", "Directory listing enabled (uploads and more)")
def check_directory_listing(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Look for auto-generated 'Index of' pages."""
    paths = options.get("paths") or ["wp-content/uploads/"]
    findings: List[Finding] = []
    for path in paths:
        resp = ctx.client.request(ctx.url(path))
        if resp is not None and resp.status_code == 200 and _INDEX.search(resp.text[:4000]):
            findings.append(
                Finding.issue(
                    "directory-listing",
                    f"Directory listing enabled at /{path.lstrip('/')}",
                    Severity.HIGH,
                    "The server returns an 'Index of' page.",
                    "Disable autoindex (Options -Indexes in Apache, autoindex off in nginx).",
                    key=f"directory-listing:{path}",
                )
            )
    return findings or [Finding.ok("directory-listing", "No directory listing found")]
