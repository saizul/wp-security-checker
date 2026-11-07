"""Command line interface."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from rich.console import Console

from . import __version__
from .baseline import BaselineError, diff_against, load_baseline
from .config import ConfigError, load_config
from .models import Severity
from .registry import load_builtin_checks, load_plugins
from .report import render_table, to_html, to_json
from .sarif import to_sarif_json
from .scanner import ScanError, build_client, run_scan

NOTICE = (
    "Only scan sites you own or have explicit permission to test. "
    "This tool performs passive checks only."
)


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    p = argparse.ArgumentParser(
        prog="wp-security-check",
        description="Passive security checks for a WordPress site you own.",
        epilog=NOTICE,
    )
    p.add_argument("url", nargs="?", help="site URL, e.g. https://example.com")
    p.add_argument("--config", help="YAML config file")
    p.add_argument("--json", action="store_true", help="print JSON instead of a table")
    p.add_argument("--html", metavar="PATH", help="also write an HTML report")
    p.add_argument(
        "--sarif", metavar="PATH", help="also write a SARIF 2.1.0 report (GitHub code scanning)"
    )
    p.add_argument(
        "--sarif-location",
        metavar="FILE",
        default="README.md",
        help="repository file that SARIF results point at (default README.md)",
    )
    p.add_argument("--baseline", metavar="PATH", help="previous --json output to diff against")
    p.add_argument("--only", help="comma-separated check ids to run")
    p.add_argument("--skip", help="comma-separated check ids to skip")
    p.add_argument("--list-checks", action="store_true", help="list available checks and exit")
    p.add_argument("--delay", type=float, help="seconds between requests")
    p.add_argument("--timeout", type=float, help="request timeout in seconds")
    p.add_argument("--retries", type=int, help="retries on timeouts/429/5xx")
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="exit 1 if a finding at or above this severity exists "
        "(with --baseline, only new findings count)",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _split(value: Optional[str]) -> Optional[List[str]]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def main(argv: Optional[List[str]] = None) -> int:
    """Entry point. Returns 0 (ok), 1 (findings at/above --fail-on) or 2 (error)."""
    args = build_parser().parse_args(argv)
    registry = load_builtin_checks()
    load_plugins(registry)
    if args.list_checks:
        for check in registry.all():
            print(f"{check.id:18} {check.family:12} {check.description}")
        return 0
    if not args.url:
        print("error: a URL is required", file=sys.stderr)
        return 2
    err = Console(stderr=True)
    try:
        config = load_config(args.config)
        for name in ("delay", "timeout", "retries"):
            value = getattr(args, name)
            if value is not None:
                setattr(config.http, name, value)
        previous = load_baseline(args.baseline) if args.baseline else None
        err.print(f"[dim]{NOTICE}[/dim]")
        result = run_scan(
            args.url,
            config=config,
            client=build_client(config),
            registry=registry,
            only=_split(args.only),
            skip=_split(args.skip),
        )
    except (ConfigError, BaselineError, ValueError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    diff = diff_against(previous, result) if previous else None
    if args.html:
        try:
            with open(args.html, "w", encoding="utf-8") as handle:
                handle.write(to_html(result, diff))
        except OSError as exc:
            print(f"error: cannot write {args.html}: {exc.strerror}", file=sys.stderr)
            return 2
    if args.sarif:
        try:
            with open(args.sarif, "w", encoding="utf-8") as handle:
                handle.write(to_sarif_json(result, diff, args.sarif_location))
        except OSError as exc:
            print(f"error: cannot write {args.sarif}: {exc.strerror}", file=sys.stderr)
            return 2
    if args.json:
        print(to_json(result, diff))
    else:
        render_table(result, Console(width=160), diff)
    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        pool = diff.new if diff is not None else result.failed
        if any(f.severity.rank >= threshold for f in pool):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
