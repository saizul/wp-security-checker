"""Console, JSON and HTML renderers."""

from __future__ import annotations

import json
from html import escape
from typing import List, Optional

from rich.console import Console
from rich.table import Table

from .baseline import BaselineDiff
from .models import Finding, ScanResult, Severity

_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_HTML_COLORS = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#0369a1",
    "info": "#6b7280",
}


def sorted_findings(result: ScanResult) -> List[Finding]:
    """Failures first (most serious first), then passes."""
    failed = sorted(result.failed, key=lambda f: -f.severity.rank)
    return failed + result.passed


def to_json(result: ScanResult, diff: Optional[BaselineDiff] = None) -> str:
    """Render the result (and optional baseline diff) as JSON."""
    data = result.to_dict()
    if diff is not None:
        data["baseline"] = diff.to_dict()
    return json.dumps(data, indent=2)


def render_table(result: ScanResult, console: Console, diff: Optional[BaselineDiff] = None) -> None:
    """Print a rich table, a severity summary and optional baseline summary."""
    table = Table(title=f"WordPress security check: {result.target}", show_lines=False)
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("Details", overflow="fold")
    new_keys = {f.key for f in diff.new} if diff else set()
    for f in sorted_findings(result):
        if f.passed:
            status, sev, style = "[green]PASS[/green]", "-", "dim"
        else:
            status = "[red]FAIL[/red]"
            sev = f.severity.value.upper()
            style = _COLORS[f.severity]
        text = f.detail
        if not f.passed and f.recommendation:
            text = f"{text} Fix: {f.recommendation}".strip()
        title = f.title + (" [NEW]" if f.key in new_keys else "")
        table.add_row(status, f"[{style}]{sev}[/{style}]", title, text)
    console.print(table)
    counts = result.counts()
    parts = [
        f"{counts[s.value]} {s.value}" for s in Severity if s is not Severity.INFO or counts["info"]
    ]
    console.print(
        f"Failed: {len(result.failed)} ({', '.join(parts)}) | Passed: {len(result.passed)}"
    )
    if diff is not None:
        console.print(
            f"Baseline: {len(diff.new)} new, {len(diff.resolved)} resolved, "
            f"{len(diff.unchanged)} unchanged"
        )
    for err in result.errors:
        console.print(f"[dim]note: {escape(err)}[/dim]")


def to_html(result: ScanResult, diff: Optional[BaselineDiff] = None) -> str:
    """Render a self-contained HTML report."""
    counts = result.counts()
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {_HTML_COLORS[s.value]}">'
        f"<b>{counts[s.value]}</b><span>{s.value}</span></div>"
        for s in Severity
    )
    rows = []
    for f in sorted_findings(result):
        badge = (
            '<span class="pill ok">PASS</span>'
            if f.passed
            else f'<span class="pill" style="background:{_HTML_COLORS[f.severity.value]}">'
            f"{escape(f.severity.value.upper())}</span>"
        )
        fix = (
            f"<br><small>Fix: {escape(f.recommendation)}</small>"
            if f.recommendation and not f.passed
            else ""
        )
        rows.append(
            f"<tr><td>{badge}</td><td>{escape(f.title)}</td><td>{escape(f.detail)}{fix}</td></tr>"
        )
    base = ""
    if diff is not None:

        def items(values: List[str]) -> str:
            return "".join(f"<li>{escape(v)}</li>" for v in values) or "<li>none</li>"

        base = (
            "<h2>Baseline comparison</h2>"
            f"<h3>New ({len(diff.new)})</h3><ul>{items([f.title for f in diff.new])}</ul>"
            f"<h3>Resolved ({len(diff.resolved)})</h3><ul>{items([f['title'] for f in diff.resolved])}</ul>"
            f"<h3>Unchanged ({len(diff.unchanged)})</h3><ul>{items([f.title for f in diff.unchanged])}</ul>"
        )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>WordPress security report</title><style>"
        "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:960px;color:#111}"
        ".cards{display:flex;gap:12px;margin:1rem 0}"
        ".card{flex:1;padding:12px;background:#f4f4f5;border-radius:6px;text-align:center}"
        ".card b{display:block;font-size:1.8rem}"
        "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}"
        ".pill{color:#fff;padding:2px 8px;border-radius:10px;font-size:.75rem}.ok{background:#15803d}"
        "</style></head><body>"
        f"<h1>WordPress security report</h1><p>Target: {escape(result.target)}<br>"
        f"Scanned: {escape(result.scanned_at)}</p>"
        f"<div class='cards'>{cards}</div>"
        f"<table><tr><th>Status</th><th>Check</th><th>Details</th></tr>{''.join(rows)}</table>"
        f"{base}<p><small>Passive checks only. Scan only sites you own or have permission to test.</small></p>"
        "</body></html>"
    )
