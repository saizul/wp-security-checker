"""Disclosure family: WordPress version exposure."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

_VER = re.compile(r"^\d+\.\d+(?:\.\d+)?$")
_GENERATOR = re.compile(r"wordpress\s*(\d+(?:\.\d+)+)?", re.I)
_README = re.compile(r"Version\s+(\d+(?:\.\d+)+)")


@register("wp-version", "disclosure", "WordPress version exposed (meta, readme.html, ?ver=)")
def check_wp_version(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Look for the WordPress version in public, unauthenticated places."""
    exposures: List[str] = []
    versions: List[str] = []
    soup = ctx.soup
    if soup is not None:
        for meta in soup.find_all("meta"):
            content = str(meta.get("content", ""))
            if str(meta.get("name", "")).lower() == "generator" and content.lower().startswith(
                "wordpress"
            ):
                exposures.append("generator meta tag")
                match = _GENERATOR.match(content)
                if match and match.group(1):
                    versions.append(match.group(1))
                break
        counts: Counter = Counter()
        for tag in soup.find_all(["script", "link"]):
            ref = str(tag.get("src") or tag.get("href") or "")
            if ("/wp-includes/" in ref or "/wp-admin/" in ref) and "/jquery/" not in ref:
                for ver in parse_qs(urlparse(ref).query).get("ver", []):
                    if _VER.match(ver):
                        counts[ver] += 1
        if counts:
            ver = counts.most_common(1)[0][0]
            exposures.append(f"?ver={ver} on core assets")
            versions.append(ver)
    if options.get("check_readme", True):
        resp = ctx.client.request(ctx.url("readme.html"))
        if resp is not None and resp.status_code == 200:
            body = resp.content[:20000].decode("utf-8", "replace")
            if "wordpress" in body.lower():
                exposures.append("readme.html reachable")
                match = _README.search(body)
                if match:
                    versions.append(match.group(1))
    if not exposures:
        return [Finding.ok("wp-version", "WordPress version not exposed")]
    detail = "Exposed via: " + ", ".join(exposures)
    if versions:
        detail += f". Version appears to be {versions[0]}."
    return [
        Finding.issue(
            "wp-version",
            "WordPress version exposed",
            Severity.LOW,
            detail,
            "Remove the generator tag, delete readme.html and strip ?ver= query "
            "strings from assets; keep WordPress updated.",
        )
    ]
