"""YAML configuration: enable or disable checks, tune thresholds and HTTP settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml

from .http import DEFAULT_USER_AGENT


class ConfigError(ValueError):
    """Raised for invalid configuration."""


@dataclass
class HttpSettings:
    """HTTP behaviour settings."""

    user_agent: str = DEFAULT_USER_AGENT
    timeout: float = 10.0
    delay: float = 0.5
    retries: int = 2
    backoff: float = 0.5


@dataclass
class Config:
    """Parsed configuration."""

    http: HttpSettings = field(default_factory=HttpSettings)
    checks: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def enabled(self, check_id: str) -> bool:
        """Whether a check is enabled (default: yes)."""
        return bool(self.checks.get(check_id, {}).get("enabled", True))

    def options(self, check_id: str) -> Dict[str, Any]:
        """Options for a check (including ``enabled``/``severity`` keys)."""
        return dict(self.checks.get(check_id, {}))

    def validate_against(self, known_ids: Iterable[str]) -> None:
        """Raise ConfigError if the config names a check that does not exist."""
        known = set(known_ids)
        unknown = sorted(set(self.checks) - known)
        if unknown:
            raise ConfigError(
                f"unknown check id(s) in config: {', '.join(unknown)} "
                f"(known: {', '.join(sorted(known))})"
            )


_HTTP_RULES = {
    "user_agent": str,
    "timeout": (int, float),
    "delay": (int, float),
    "retries": int,
    "backoff": (int, float),
}


def parse_config(data: Optional[Dict[str, Any]]) -> Config:
    """Build a :class:`Config` from already-loaded YAML data."""
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError("config root must be a mapping")
    extra = set(data) - {"http", "checks"}
    if extra:
        raise ConfigError(f"unknown top-level key(s): {', '.join(sorted(extra))}")

    http = HttpSettings()
    raw_http = data.get("http", {})
    if raw_http is None:
        raw_http = {}
    if not isinstance(raw_http, dict):
        raise ConfigError("'http' must be a mapping")
    for key, value in raw_http.items():
        if key not in _HTTP_RULES:
            raise ConfigError(f"unknown http setting: {key}")
        expected = _HTTP_RULES[key]
        if isinstance(value, bool) or not isinstance(value, expected):
            raise ConfigError(f"http.{key} has the wrong type")
        if key != "user_agent" and value < 0:
            raise ConfigError(f"http.{key} must not be negative")
        setattr(http, key, value)
    if http.timeout <= 0:
        raise ConfigError("http.timeout must be greater than zero")

    checks: Dict[str, Dict[str, Any]] = {}
    raw_checks = data.get("checks", {})
    if raw_checks is None:
        raw_checks = {}
    if not isinstance(raw_checks, dict):
        raise ConfigError("'checks' must be a mapping")
    for check_id, value in raw_checks.items():
        if isinstance(value, bool):
            checks[str(check_id)] = {"enabled": value}
        elif value is None:
            checks[str(check_id)] = {}
        elif isinstance(value, dict):
            options = dict(value)
            if "enabled" in options and not isinstance(options["enabled"], bool):
                raise ConfigError(f"checks.{check_id}.enabled must be true or false")
            checks[str(check_id)] = options
        else:
            raise ConfigError(f"checks.{check_id} must be a mapping or a boolean")
    return Config(http=http, checks=checks)


def load_config(path: Optional[str]) -> Config:
    """Load configuration from a YAML file (None gives defaults)."""
    if path is None:
        return Config()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    return parse_config(data)
