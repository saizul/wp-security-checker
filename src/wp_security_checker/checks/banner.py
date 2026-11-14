"""Disclosure family: software versions in server response headers."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register
from ..utils import parse_version, version_lt

DEFAULT_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Runtime-Version",
]

# PHP branches still receiving security fixes as of late 2026.
DEFAULT_MIN_PHP = "8.2"

# "Apache/2.4.58", "PHP/8.1.2", "nginx/1.25.3"; a bare "nginx" has no version.
_PRODUCT_RE = re.compile(r"([A-Za-z][\w.+-]*)/(\d+(?:\.\d+)*)")
_PHP_RE = re.compile(r"\bPHP/(\d+(?:\.\d+)*)", re.I)


def disclosed_products(value: str) -> List[Tuple[str, str]]:
    """``(product, version)`` pairs found in a header value."""
    return [(m.group(1), m.group(2)) for m in _PRODUCT_RE.finditer(value or "")]


def php_version(headers: Dict[str, str]) -> Optional[str]:
    """The PHP version announced by any of the given header values."""
    for value in headers.values():
        match = _PHP_RE.search(value or "")
        if match:
            return match.group(1)
    return None


@register("server-banner", "disclosure", "Software versions in Server / X-Powered-By headers")
def check_server_banner(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Read the home page headers; no extra requests are made."""
    home = ctx.home
    if home is None:
        return []
    names = options.get("headers", DEFAULT_HEADERS)
    min_php = str(options.get("min_php", DEFAULT_MIN_PHP))
    min_php_tuple = parse_version(min_php)

    present: Dict[str, str] = {}
    for name in names:
        value = home.headers.get(str(name))
        if value:
            present[str(name)] = value

    findings: List[Finding] = []
    for name, value in present.items():
        products = disclosed_products(value)
        if not products:
            continue
        shown = ", ".join(f"{p}/{v}" for p, v in products)
        findings.append(
            Finding.issue(
                "server-banner",
                f"Software version disclosed in {name} header",
                Severity.LOW,
                f"{name}: {shown}.",
                "Hide version details (Apache: ServerTokens Prod; nginx: server_tokens off; "
                "PHP: expose_php = Off).",
                f"server-banner:{name}",
            )
        )

    php = php_version(present)
    php_tuple = parse_version(php) if php else None
    if php_tuple and min_php_tuple and version_lt(php_tuple, min_php_tuple):
        findings.append(
            Finding.issue(
                "server-banner",
                f"Unsupported PHP version: {php}",
                Severity.MEDIUM,
                f"The site announces PHP {php}; branches below {min_php} no longer "
                "receive security fixes.",
                "Upgrade PHP to a supported branch and turn off expose_php.",
                "server-banner:php-eol",
            )
        )

    if not findings:
        detail = (
            "Headers present without versions: " + ", ".join(present)
            if present
            else "No banner headers sent."
        )
        findings.append(Finding.ok("server-banner", "No software versions in headers", detail))
    return findings
