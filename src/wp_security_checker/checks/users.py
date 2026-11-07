"""User enumeration family: REST API and author archives."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

_AUTHOR = re.compile(r"/author/([^/?#]+)")


@register("rest-users", "users", "REST API lists users (/wp-json/wp/v2/users)")
def check_rest_users(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Check whether the users endpoint answers publicly."""
    for path in ("wp-json/wp/v2/users", "?rest_route=/wp/v2/users"):
        resp = ctx.client.request(ctx.url(path))
        if resp is None or resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if isinstance(data, list) and data and all(isinstance(u, dict) for u in data):
            slugs = [str(u["slug"]) for u in data if "slug" in u][:3]
            sample = f" (e.g. {', '.join(slugs)})" if slugs else ""
            return [
                Finding.issue(
                    "rest-users",
                    "REST API exposes user accounts",
                    Severity.MEDIUM,
                    f"{len(data)} user(s) listed publicly{sample}.",
                    "Restrict /wp/v2/users to authenticated requests.",
                )
            ]
    return [Finding.ok("rest-users", "REST API does not list users")]


@register("author-enum", "users", "Author archive enumeration (?author=N)")
def check_author_enum(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Check whether ?author=N redirects to /author/<login>/."""
    ids = options.get("ids", [1])
    for author_id in ids:
        resp = ctx.client.request(ctx.url(f"?author={author_id}"))
        if resp is None or not 300 <= resp.status_code < 400:
            continue
        match = _AUTHOR.search(resp.headers.get("Location", ""))
        if match:
            return [
                Finding.issue(
                    "author-enum",
                    "Author archives reveal usernames",
                    Severity.LOW,
                    f"/?author={author_id} redirects to /author/{match.group(1)}/.",
                    "Redirect or block ?author= queries and disable author archives if unused.",
                )
            ]
    return [Finding.ok("author-enum", "Author enumeration not possible via ?author=")]
