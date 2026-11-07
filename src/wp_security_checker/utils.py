"""Small helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

_VERSION_RE = re.compile(r"\d+(?:\.\d+)*")


def parse_version(value: str) -> Optional[Tuple[int, ...]]:
    """Return the leading dotted version in ``value`` as a tuple, or None."""
    match = _VERSION_RE.search(value or "")
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def version_lt(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    """Compare two version tuples, padding the shorter one with zeros."""
    size = max(len(a), len(b))
    pad_a = a + (0,) * (size - len(a))
    pad_b = b + (0,) * (size - len(b))
    return pad_a < pad_b
