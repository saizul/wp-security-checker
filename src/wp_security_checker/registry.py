"""Plugin-style registry of checks."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .context import ScanContext
from .models import Finding

CheckFunc = Callable[[ScanContext, Dict[str, Any]], List[Finding]]
ENTRY_POINT_GROUP = "wp_security_checker.checks"


@dataclass(frozen=True)
class Check:
    """A registered check."""

    id: str
    family: str
    description: str
    func: CheckFunc


class CheckRegistry:
    """Ordered collection of :class:`Check` objects."""

    def __init__(self) -> None:
        self._checks: Dict[str, Check] = {}

    def add(self, check: Check) -> Check:
        """Register a check; duplicate ids are rejected."""
        if check.id in self._checks:
            raise ValueError(f"duplicate check id: {check.id}")
        self._checks[check.id] = check
        return check

    def get(self, check_id: str) -> Check:
        """Look up a check by id."""
        return self._checks[check_id]

    def __contains__(self, check_id: object) -> bool:
        return check_id in self._checks

    def __len__(self) -> int:
        return len(self._checks)

    def all(self) -> List[Check]:
        """All checks in registration order."""
        return list(self._checks.values())

    def ids(self) -> List[str]:
        """All check ids in registration order."""
        return list(self._checks)

    def families(self) -> List[str]:
        """Sorted unique family names."""
        return sorted({c.family for c in self._checks.values()})


default_registry = CheckRegistry()


def register(
    check_id: str,
    family: str,
    description: str,
    registry: Optional[CheckRegistry] = None,
) -> Callable[[CheckFunc], CheckFunc]:
    """Decorator that registers a check function."""

    def decorator(func: CheckFunc) -> CheckFunc:
        (default_registry if registry is None else registry).add(
            Check(check_id, family, description, func)
        )
        return func

    return decorator


def load_builtin_checks() -> CheckRegistry:
    """Import the built-in check modules (idempotent) and return the registry."""
    from . import checks  # noqa: F401

    return default_registry


def load_plugins(registry: Optional[CheckRegistry] = None) -> List[str]:
    """Load third-party checks from the ``wp_security_checker.checks`` entry points.

    Each entry point may be a module (imported for its ``@register`` side
    effects) or a callable that receives the registry. Returns loaded names.
    """
    from importlib import metadata

    target = default_registry if registry is None else registry
    eps = metadata.entry_points()
    if hasattr(eps, "select"):
        selected = list(eps.select(group=ENTRY_POINT_GROUP))
    else:  # Python 3.9
        selected = list(eps.get(ENTRY_POINT_GROUP, []))
    loaded: List[str] = []
    for ep in selected:
        try:
            obj = ep.load()
            if callable(obj):
                obj(target)
            loaded.append(ep.name)
        except Exception as exc:  # a broken plugin must not break the scanner
            print(f"warning: could not load check plugin {ep.name}: {exc}", file=sys.stderr)
    return loaded
