"""Hardening family: outdated jQuery."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register
from ..utils import parse_version, version_lt

_NAMED = re.compile(r"jquery[-.](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I)
_PLAIN = re.compile(r"^jquery(?:\.min)?\.js$", re.I)


def _detect(src: str) -> Optional[str]:
    parsed = urlparse(src)
    named = _NAMED.search(parsed.path)
    if named:
        return named.group(1)
    if _PLAIN.match(parsed.path.rsplit("/", 1)[-1]):
        vers = parse_qs(parsed.query).get("ver", [])
        if vers and parse_version(vers[0]):
            return vers[0]
    return None


@register("jquery", "hardening", "Outdated jQuery included on the home page")
def check_jquery(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Compare script versions found in the HTML with ``min_version``."""
    soup = ctx.soup
    minimum = parse_version(str(options.get("min_version", "3.5.0"))) or (3, 5, 0)
    found: List[str] = []
    if soup is not None:
        for tag in soup.find_all("script", src=True):
            version = _detect(str(tag["src"]))
            if version:
                found.append(version)
    old = sorted({v for v in found if version_lt(parse_version(v) or (0,), minimum)})
    if old:
        wanted = ".".join(str(p) for p in minimum)
        return [
            Finding.issue(
                "jquery",
                "Outdated jQuery detected",
                Severity.MEDIUM,
                f"Found jQuery {', '.join(old)} (minimum recommended {wanted}).",
                "Update WordPress, themes and plugins so a current jQuery is loaded.",
            )
        ]
    detail = (
        f"Found jQuery {', '.join(sorted(set(found)))}." if found else "No versioned jQuery found."
    )
    return [Finding.ok("jquery", "No outdated jQuery detected", detail)]
