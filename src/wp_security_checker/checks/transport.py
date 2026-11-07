"""Transport family: HTTP to HTTPS redirect."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register


@register("https-redirect", "transport", "Plain HTTP redirects to HTTPS")
def check_https_redirect(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Request the http:// URL without following redirects."""
    resp = ctx.client.request(ctx.http_url())
    if resp is None:
        return [Finding.ok("https-redirect", "Plain HTTP not reachable", "No answer on port 80.")]
    location = resp.headers.get("Location", "")
    if 300 <= resp.status_code < 400 and location.lower().startswith("https://"):
        return [Finding.ok("https-redirect", "HTTP redirects to HTTPS", f"HTTP {resp.status_code}")]
    if resp.status_code == 200 or 300 <= resp.status_code < 400:
        return [
            Finding.issue(
                "https-redirect",
                "HTTP does not redirect to HTTPS",
                Severity.MEDIUM,
                f"http:// answered HTTP {resp.status_code}"
                + (f" with Location {location}" if location else "")
                + ".",
                "Add a permanent (301) redirect from http:// to https://.",
            )
        ]
    return [Finding.ok("https-redirect", "HTTP is not served", f"HTTP {resp.status_code}")]
