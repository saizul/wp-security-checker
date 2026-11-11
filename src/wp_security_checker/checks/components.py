"""Disclosure family: plugins and themes referenced by the home page.

The inventory is built from the asset URLs already present in the home page
HTML, so nothing is guessed or brute forced. The only extra requests are one
``readme.txt`` per detected plugin (capped by ``max_probes``).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlparse

from ..context import ScanContext
from ..http import HttpClient
from ..models import Finding, Severity
from ..registry import register
from ..utils import parse_version, version_lt

CHECK_ID = "plugin-versions"
DEFAULT_MAX_PROBES = 10
_README_BYTES = 4096

_COMPONENT = re.compile(r"/wp-content/(plugins|themes)/([A-Za-z0-9][A-Za-z0-9._-]*)/")
_VER = re.compile(r"^\d+(?:\.\d+)+$")
_STABLE_TAG = re.compile(r"^[ \t]*Stable tag:[ \t]*v?(\d+(?:\.\d+)*)[ \t]*\r?$", re.I | re.M)
_README_TITLE = re.compile(r"^\s*===.+===\s*$", re.M)
_URL_ATTRS = ("src", "href", "data-src")


@dataclass
class Component:
    """A plugin or theme referenced by the home page."""

    kind: str  # "plugin" or "theme"
    slug: str
    asset_versions: Counter = field(default_factory=Counter)
    readme_version: Optional[str] = None
    readme_exposed: bool = False

    @property
    def name(self) -> str:
        """Identifier used in keys and config, e.g. ``plugin/contact-form-7``."""
        return f"{self.kind}/{self.slug}"

    @property
    def asset_version(self) -> Optional[str]:
        """The most common ``?ver=`` value on this component's assets."""
        if not self.asset_versions:
            return None
        return sorted(self.asset_versions.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]

    @property
    def version(self) -> Optional[str]:
        """Best known version: readme.txt first, then the asset query string."""
        return self.readme_version or self.asset_version

    def label(self) -> str:
        """Human readable ``slug version`` text."""
        return f"{self.slug} {self.version}" if self.version else self.slug


def _references(soup: Any) -> Iterable[str]:
    for tag in soup.find_all(["script", "link", "img", "source", "iframe"]):
        for attr in _URL_ATTRS:
            value = tag.get(attr)
            if value:
                yield str(value)


def detect_components(soup: Any) -> List[Component]:
    """Collect plugins and themes from asset URLs in the parsed home page."""
    found: Dict[str, Component] = {}
    if soup is None:
        return []
    for ref in _references(soup):
        parsed = urlparse(ref)
        match = _COMPONENT.search(parsed.path)
        if not match:
            continue
        kind = "plugin" if match.group(1) == "plugins" else "theme"
        slug = match.group(2).lower()
        component = found.setdefault(f"{kind}/{slug}", Component(kind, slug))
        for ver in parse_qs(parsed.query).get("ver", []):
            if _VER.match(ver):
                component.asset_versions[ver] += 1
    return sorted(found.values(), key=lambda c: (c.kind, c.slug))


def parse_readme(head: bytes, ctype: str = "") -> Optional[str]:
    """Return the ``Stable tag`` of a WordPress readme, "" if it has none.

    ``None`` means the bytes do not look like a plugin readme at all (for
    example an HTML soft-404 page).
    """
    start = head.lstrip()[:15].lower()
    if "html" in ctype.lower() or start.startswith((b"<!doctype html", b"<html")):
        return None
    text = head.decode("utf-8", "replace")
    tag = _STABLE_TAG.search(text)
    if tag:
        return tag.group(1)
    if _README_TITLE.search(text) or re.search(r"^[ \t]*Stable tag:", text, re.I | re.M):
        return ""  # a readme, but "Stable tag: trunk" or no tag
    return None


def _normalise_names(values: Any) -> Dict[str, str]:
    """Map ``slug`` and ``kind/slug`` spellings to the given value (lower-cased keys)."""
    if isinstance(values, dict):
        return {str(k).strip().lower(): str(v) for k, v in values.items()}
    return {str(v).strip().lower(): "" for v in values or []}


def _lookup(table: Dict[str, str], component: Component) -> Optional[str]:
    if component.name in table:
        return table[component.name]
    return table.get(component.slug)


def _max_probes(options: Dict[str, Any]) -> int:
    raw = options.get("max_probes", DEFAULT_MAX_PROBES)
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ValueError("max_probes must be a non-negative integer")
    return raw


@register(
    CHECK_ID,
    "disclosure",
    "Plugins and themes on the home page, readable readme.txt, outdated versions",
)
def check_plugin_versions(ctx: ScanContext, options: Dict[str, Any]) -> List[Finding]:
    """Inventory plugins/themes and flag version disclosure and old versions.

    Options: ``probe_readme`` (default true), ``max_probes`` (default 10),
    ``ignore`` (list of slugs) and ``min_versions`` (mapping of slug to the
    lowest acceptable version).
    """
    limit = _max_probes(options)
    ignored = _normalise_names(options.get("ignore"))
    minimums = _normalise_names(options.get("min_versions") or {})
    components = [c for c in detect_components(ctx.soup) if _lookup(ignored, c) is None]
    plugins = [c for c in components if c.kind == "plugin"]
    themes = [c for c in components if c.kind == "theme"]

    skipped = 0
    if options.get("probe_readme", True):
        for index, plugin in enumerate(plugins):
            if index >= limit:
                skipped = len(plugins) - limit
                break
            resp = ctx.client.request(
                ctx.url(f"wp-content/plugins/{plugin.slug}/readme.txt"), stream=True
            )
            if resp is None:
                continue
            ctype = resp.headers.get("Content-Type", "")
            head = HttpClient.read_head(resp, _README_BYTES)
            if resp.status_code != 200:
                continue
            version = parse_readme(head, ctype)
            if version is not None:
                plugin.readme_exposed = True
                plugin.readme_version = version or None

    findings: List[Finding] = []
    for component in components:
        wanted = _lookup(minimums, component)
        current = parse_version(component.version or "")
        minimum = parse_version(wanted or "")
        if wanted and minimum is None:
            raise ValueError(f"min_versions.{component.slug}: not a version: {wanted!r}")
        if minimum and current and version_lt(current, minimum):
            findings.append(
                Finding.issue(
                    CHECK_ID,
                    f"Outdated {component.kind}: {component.slug} {component.version}",
                    Severity.MEDIUM,
                    f"Detected version {component.version}, minimum configured is {wanted}.",
                    f"Update the {component.kind} to {wanted} or newer.",
                    key=f"{CHECK_ID}:outdated:{component.name}",
                )
            )
    for plugin in plugins:
        if not plugin.readme_exposed:
            continue
        detail = f"/wp-content/plugins/{plugin.slug}/readme.txt is publicly readable"
        if plugin.readme_version:
            detail += f" and names version {plugin.readme_version}"
        findings.append(
            Finding.issue(
                CHECK_ID,
                f"Plugin version exposed: {plugin.slug}",
                Severity.LOW,
                detail + ".",
                "Block direct access to plugin readme.txt files and keep the plugin updated.",
                key=f"{CHECK_ID}:readme:{plugin.slug}",
            )
        )

    if not components:
        summary = Finding.ok(CHECK_ID, "No plugins or themes referenced on the home page")
    else:
        parts = []
        if plugins:
            parts.append("Plugins: " + ", ".join(c.label() for c in plugins) + ".")
        if themes:
            parts.append("Themes: " + ", ".join(c.label() for c in themes) + ".")
        if skipped:
            parts.append(f"{skipped} plugin readme probe(s) skipped (max_probes={limit}).")
        summary = Finding.ok(
            CHECK_ID,
            f"Detected {len(plugins)} plugin(s) and {len(themes)} theme(s)",
            " ".join(parts),
            key=f"{CHECK_ID}:inventory",
        )
    return findings + [summary]
