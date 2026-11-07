"""Hardening family: HTTP security headers."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

DEFAULT_HSTS_MIN_AGE = 15552000  # 180 days

HEADERS: List[Tuple[str, Severity, str]] = [
    ("Strict-Transport-Security", Severity.MEDIUM, "Send HSTS, e.g. max-age=31536000."),
    ("Content-Security-Policy", Severity.LOW, "Define a Content-Security-Policy."),
    ("X-Frame-Options", Severity.LOW, "Send X-Frame-Options: SAMEORIGIN."),
    ("X-Content-Type-Options", Severity.LOW, "Send X-Content-Type-Options: nosniff."),
    ("Referrer-Policy", Severity.LOW, "Send Referrer-Policy: strict-origin-when-cross-origin."),
    ("Permissions-Policy", Severity.LOW, "Send a Permissions-Policy limiting browser features."),
]


@register("security-headers", "hardening", "Missing or weak HTTP security headers")
def check_security_headers(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Evaluate headers on the home page response."""
    home = ctx.home
    if home is None:
        return []
    required = options.get("required")
    wanted = {str(h).lower() for h in required} if required else None
    min_age = int(options.get("hsts_min_age", DEFAULT_HSTS_MIN_AGE))
    csp = home.headers.get("Content-Security-Policy", "")
    findings: List[Finding] = []
    for name, severity, advice in HEADERS:
        if wanted is not None and name.lower() not in wanted:
            continue
        key = f"security-headers:{name}"
        value = home.headers.get(name)
        title = f"{name} header"
        if name == "X-Frame-Options" and not value and "frame-ancestors" in csp.lower():
            findings.append(
                Finding.ok("security-headers", title, "Covered by CSP frame-ancestors.", key)
            )
            continue
        if not value:
            findings.append(
                Finding.issue("security-headers", f"{title} missing", severity, "", advice, key)
            )
            continue
        if name == "Strict-Transport-Security":
            if not home.url.startswith("https://"):
                findings.append(
                    Finding.issue(
                        "security-headers",
                        f"{title} sent over HTTP",
                        severity,
                        "HSTS is ignored on plain HTTP.",
                        "Serve the site over HTTPS.",
                        key,
                    )
                )
                continue
            match = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
            age = int(match.group(1)) if match else 0
            if age < min_age:
                findings.append(
                    Finding.issue(
                        "security-headers",
                        f"{title} max-age too short",
                        Severity.LOW,
                        f"max-age={age}, recommended at least {min_age}.",
                        advice,
                        key,
                    )
                )
                continue
        findings.append(Finding.ok("security-headers", title, value[:80], key))
    return findings
