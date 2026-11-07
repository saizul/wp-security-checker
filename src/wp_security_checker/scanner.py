"""Run the registered checks against a target."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from .config import Config, ConfigError
from .context import ScanContext
from .http import HttpClient
from .models import Finding, ScanResult, Severity
from .registry import CheckRegistry, load_builtin_checks


class ScanError(RuntimeError):
    """Raised when the target cannot be scanned at all."""


def normalize_url(raw: str) -> str:
    """Add a scheme if missing and validate the URL."""
    value = raw.strip()
    if not value:
        raise ValueError("URL is empty")
    if "://" not in value:
        value = "https://" + value
    parts = urlparse(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"not a valid http(s) URL: {raw}")
    return value if value.endswith("/") else value + "/"


def build_client(config: Config) -> HttpClient:
    """Create an HTTP client from configuration."""
    h = config.http
    return HttpClient(
        user_agent=h.user_agent,
        timeout=h.timeout,
        delay=h.delay,
        retries=h.retries,
        backoff=h.backoff,
    )


def select_checks(
    registry: CheckRegistry,
    config: Config,
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
) -> List[str]:
    """Resolve which check ids will run."""
    only_set = set(only or [])
    skip_set = set(skip or [])
    for name in only_set | skip_set:
        if name not in registry:
            raise ConfigError(f"unknown check id: {name}")
    config.validate_against(registry.ids())
    return [
        c.id
        for c in registry.all()
        if config.enabled(c.id) and (not only_set or c.id in only_set) and c.id not in skip_set
    ]


def run_scan(
    target: str,
    config: Optional[Config] = None,
    client: Optional[HttpClient] = None,
    registry: Optional[CheckRegistry] = None,
    only: Optional[Iterable[str]] = None,
    skip: Optional[Iterable[str]] = None,
) -> ScanResult:
    """Run all selected checks and collect findings.

    A check that raises is reported in ``ScanResult.errors`` and does not stop
    the scan. Raises :class:`ScanError` if the home page cannot be fetched.
    """
    config = config or Config()
    registry = registry if registry is not None else load_builtin_checks()
    base = normalize_url(target)
    selected = select_checks(registry, config, only, skip)
    client = client or build_client(config)
    ctx = ScanContext(base, client)
    if ctx.home is None:
        reason = client.errors[-1] if client.errors else "no response"
        raise ScanError(f"could not reach {base} ({reason})")
    result = ScanResult(base, datetime.now(timezone.utc).isoformat(timespec="seconds"))
    for check_id in selected:
        check = registry.get(check_id)
        options = config.options(check_id)
        try:
            findings = check.func(ctx, options)
        except Exception as exc:
            result.errors.append(f"{check_id}: {exc.__class__.__name__}: {exc}")
            continue
        override = options.get("severity")
        if override:
            try:
                level = Severity.parse(override)
            except ValueError as exc:
                raise ConfigError(f"checks.{check_id}.severity: {exc}") from exc
            for finding in findings:
                if not finding.passed:
                    finding.severity = level
        result.findings.extend(findings)
    result.errors.extend(client.errors)
    return result


__all__ = ["ScanError", "normalize_url", "build_client", "select_checks", "run_scan", "Finding"]
