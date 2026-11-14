"""Hardening family: Secure, HttpOnly and SameSite flags on cookies.

Only the ``Set-Cookie`` headers of plain GET responses are inspected. Cookie
values are never stored, compared or printed: a finding names the cookie and
the missing attribute, nothing else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

import requests

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

DEFAULT_PATHS = ["", "wp-login.php"]

# Cookies that carry a login or shopping session. A missing flag on one of
# these matters more than on a preference or analytics cookie.
SESSION_PATTERNS = [
    r"^wordpress_logged_in_",
    r"^wordpress_sec_",
    r"^wordpress_[0-9a-f]{32}$",
    r"^wp_woocommerce_session_",
    r"^PHPSESSID$",
    r"^woocommerce_cart_hash$",
    r"^woocommerce_items_in_cart$",
]


@dataclass
class Cookie:
    """Attributes of one ``Set-Cookie`` header (the value is discarded)."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    paths: List[str] = field(default_factory=list)


def set_cookie_headers(response: requests.Response) -> List[str]:
    """Every ``Set-Cookie`` header of a response, one string per header."""
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    for getter in ("getlist", "get_all"):
        func = getattr(raw_headers, getter, None)
        if callable(func):
            try:
                values = func("Set-Cookie")
            except TypeError:  # pragma: no cover - unusual header containers
                continue
            if values:
                return [str(v) for v in values]
    merged = response.headers.get("Set-Cookie", "")
    if not merged:
        return []
    # requests joins repeated headers with ", "; split only where a new
    # "name=" starts so commas inside Expires dates survive.
    return [part.strip() for part in re.split(r",\s*(?=[^;,=\s]+=)", merged) if part.strip()]


def parse_set_cookie(header: str) -> Optional[Cookie]:
    """Parse the attributes of one ``Set-Cookie`` header; None if it has no name."""
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    cookie = Cookie(name)
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite":
            cookie.same_site = value.strip().capitalize() or None
    return cookie


def _compile(patterns: Sequence[str]) -> List[re.Pattern]:
    return [re.compile(p, re.I) for p in patterns]


def _collect(ctx: ScanContext, paths: Sequence[str]) -> Dict[str, Cookie]:
    cookies: Dict[str, Cookie] = {}
    for path in paths:
        resp = ctx.home if path in ("", "/") else ctx.client.request(ctx.url(path))
        if resp is None:
            continue
        label = "/" + str(path).lstrip("/")
        for header in set_cookie_headers(resp):
            cookie = parse_set_cookie(header)
            if cookie is None:
                continue
            seen = cookies.get(cookie.name)
            if seen is None:
                cookie.paths.append(label)
                cookies[cookie.name] = cookie
            else:
                # Report the weakest variant seen for the same cookie name.
                seen.secure = seen.secure and cookie.secure
                seen.http_only = seen.http_only and cookie.http_only
                if cookie.same_site is None or seen.same_site is None:
                    seen.same_site = None
                if label not in seen.paths:
                    seen.paths.append(label)
    return cookies


@register("cookie-flags", "hardening", "Cookies missing Secure, HttpOnly or SameSite")
def check_cookie_flags(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Inspect cookies set by the home page and the login page."""
    paths = options.get("paths", DEFAULT_PATHS)
    report_all = bool(options.get("report_all", False))
    ignore = {str(n).lower() for n in options.get("ignore", [])}
    session_res = _compile(SESSION_PATTERNS + list(options.get("session_patterns", [])))
    https = ctx.base_url.startswith("https://")

    cookies = _collect(ctx, paths)
    findings: List[Finding] = []
    checked = 0
    for name, cookie in cookies.items():
        if name.lower() in ignore:
            continue
        checked += 1
        session = any(rx.search(name) for rx in session_res)
        kind = "session cookie" if session else "cookie"
        where = ", ".join(cookie.paths)
        base = f"cookie-flags:{name}"

        if https and not cookie.secure:
            findings.append(
                Finding.issue(
                    "cookie-flags",
                    f"Secure flag missing: {name}",
                    Severity.MEDIUM if session else Severity.LOW,
                    f"The {kind} set by {where} can be sent over plain HTTP.",
                    "Add the Secure attribute (for WordPress: force HTTPS in "
                    "siteurl/home and FORCE_SSL_ADMIN).",
                    f"{base}:secure",
                )
            )
        if not cookie.http_only and (session or report_all):
            findings.append(
                Finding.issue(
                    "cookie-flags",
                    f"HttpOnly flag missing: {name}",
                    Severity.MEDIUM if session else Severity.LOW,
                    f"The {kind} set by {where} is readable from JavaScript.",
                    "Add the HttpOnly attribute so scripts cannot read the cookie.",
                    f"{base}:httponly",
                )
            )
        if cookie.same_site == "None" and not cookie.secure:
            findings.append(
                Finding.issue(
                    "cookie-flags",
                    f"SameSite=None without Secure: {name}",
                    Severity.LOW,
                    f"Browsers reject the {kind} set by {where}.",
                    "Send SameSite=None only together with Secure, or use SameSite=Lax.",
                    f"{base}:samesite",
                )
            )
        elif cookie.same_site is None and (session or report_all):
            findings.append(
                Finding.issue(
                    "cookie-flags",
                    f"SameSite attribute missing: {name}",
                    Severity.LOW,
                    f"The {kind} set by {where} relies on the browser default.",
                    "Send SameSite=Lax (or Strict) explicitly.",
                    f"{base}:samesite",
                )
            )

    if not findings:
        detail = (
            f"{checked} cookie(s) checked." if checked else "No cookies set on the scanned pages."
        )
        findings.append(Finding.ok("cookie-flags", "Cookie flags look fine", detail))
    return findings
