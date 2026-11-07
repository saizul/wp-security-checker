"""Attack-surface family: xmlrpc.php."""

from __future__ import annotations

from typing import Any, Dict, List

from ..context import ScanContext
from ..models import Finding, Severity
from ..registry import register

_PHRASE = "xml-rpc server accepts post requests only"


@register("xmlrpc", "surface", "xmlrpc.php reachable")
def check_xmlrpc(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """A plain GET to xmlrpc.php; no XML-RPC calls are made."""
    resp = ctx.client.request(ctx.url("xmlrpc.php"))
    if resp is not None and (resp.status_code == 405 or _PHRASE in resp.text.lower()):
        return [
            Finding.issue(
                "xmlrpc",
                "xmlrpc.php is reachable",
                Severity.MEDIUM,
                f"GET /xmlrpc.php answered HTTP {resp.status_code}.",
                "Block xmlrpc.php at the web server or with a plugin unless you need it.",
            )
        ]
    return [Finding.ok("xmlrpc", "xmlrpc.php not reachable")]
