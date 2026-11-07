"""Surface family: default login URL."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register


@register("login-url", "surface", "Default wp-login.php reachable")
def check_login_url(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Only a GET is made; the login form is never submitted."""
    path = options.get("path", "wp-login.php")
    resp = ctx.client.request(ctx.url(path))
    if (
        resp is not None
        and resp.status_code == 200
        and ("user_login" in resp.text or 'name="log"' in resp.text)
    ):
        return [
            Finding.issue(
                "login-url",
                "Default login URL is reachable",
                Severity.LOW,
                f"/{path} serves the login form.",
                "Consider rate limiting, 2FA and optionally moving or restricting the login page.",
            )
        ]
    return [Finding.ok("login-url", "Default login URL not exposed")]
