import pytest
import responses
from bs4 import BeautifulSoup
from conftest import BASE, html

from wp_security_checker.checks.components import (
    check_plugin_versions,
    detect_components,
    parse_readme,
)
from wp_security_checker.config import Config
from wp_security_checker.models import Severity
from wp_security_checker.scanner import run_scan

PAGE = """<html><head>
<link rel="stylesheet" href="https://example.com/wp-content/themes/astra/style.css?ver=4.6.3">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8.1">
<script src="https://example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.1"></script>
<script src="https://cdn.example.net/wp-content/plugins/WooCommerce/assets/js/a.min.js?ver=8.2.0"></script>
<script src="/wp-content/plugins/woocommerce/assets/js/b.min.js?ver=8.2.0"></script>
<script src="/wp-content/plugins/woocommerce/assets/js/c.min.js?ver=1.0"></script>
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>
</head><body><img data-src="/wp-content/plugins/lazy-thing/img/x.png" src="/a.png"></body></html>"""

README = """=== Contact Form 7 ===
Contributors: someone
Requires at least: 6.2
Stable tag: 5.8.1
License: GPLv2 or later

Just another contact form plugin.
"""


def readme_url(slug):
    return f"{BASE}wp-content/plugins/{slug}/readme.txt"


def by_key(findings):
    return {f.key: f for f in findings}


def test_detect_components_groups_and_versions():
    found = detect_components(BeautifulSoup(PAGE, "html.parser"))
    assert [c.name for c in found] == [
        "plugin/contact-form-7",
        "plugin/lazy-thing",
        "plugin/woocommerce",
        "theme/astra",
    ]
    versions = {c.slug: c.asset_version for c in found}
    assert versions == {
        "contact-form-7": "5.8.1",
        "lazy-thing": None,
        "woocommerce": "8.2.0",
        "astra": "4.6.3",
    }


def test_detect_components_handles_missing_soup_and_non_numeric_ver():
    assert detect_components(None) == []
    soup = BeautifulSoup('<script src="/wp-content/plugins/x/a.js?ver=abc123"></script>', "html.parser")
    (only,) = detect_components(soup)
    assert only.slug == "x" and only.version is None and only.label() == "x"


def test_parse_readme_variants():
    assert parse_readme(README.encode()) == "5.8.1"
    assert parse_readme(b"=== Thing ===\r\nStable tag: v2.0\r\n") == "2.0"
    assert parse_readme(b"=== Thing ===\nStable tag: trunk\n") == ""
    assert parse_readme(b"=== Thing ===\nNo tag here\n") == ""
    assert parse_readme(b"just some text") is None
    assert parse_readme(b"") is None
    assert parse_readme(b"<!DOCTYPE html><html>Stable tag: 1.0</html>") is None
    assert parse_readme(b"=== Thing ===\nStable tag: 1.0\n", "text/html; charset=utf-8") is None


def test_no_components(mock, ctx):
    html(mock)
    (f,) = check_plugin_versions(ctx, {})
    assert f.passed and f.key == "plugin-versions"
    assert "No plugins or themes" in f.title


def test_inventory_without_exposed_readme(mock, ctx):
    html(mock, PAGE)
    mock.add(responses.GET, readme_url("contact-form-7"), status=403)
    mock.add(responses.GET, readme_url("lazy-thing"), status=404)
    mock.add(
        responses.GET,
        readme_url("woocommerce"),
        body="<html><body>Not found</body></html>",
        content_type="text/html",
    )
    (f,) = check_plugin_versions(ctx, {})
    assert f.passed and f.key == "plugin-versions:inventory"
    assert f.title == "Detected 3 plugin(s) and 1 theme(s)"
    assert "contact-form-7 5.8.1" in f.detail and "woocommerce 8.2.0" in f.detail
    assert "lazy-thing," in f.detail and "Themes: astra 4.6.3." in f.detail


def test_exposed_readme_reported_per_plugin(mock, ctx):
    html(mock, PAGE)
    mock.add(responses.GET, readme_url("contact-form-7"), body=README, content_type="text/plain")
    mock.add(
        responses.GET,
        readme_url("lazy-thing"),
        body="=== Lazy Thing ===\nStable tag: trunk\n",
        content_type="text/plain",
    )
    findings = by_key(check_plugin_versions(ctx, {}))
    cf7 = findings["plugin-versions:readme:contact-form-7"]
    assert not cf7.passed and cf7.severity is Severity.LOW
    assert "names version 5.8.1" in cf7.detail and "readme.txt" in cf7.recommendation
    lazy = findings["plugin-versions:readme:lazy-thing"]
    assert not lazy.passed and "names version" not in lazy.detail
    assert "plugin-versions:readme:woocommerce" not in findings
    assert findings["plugin-versions:inventory"].passed
    # the readme body is never copied into a finding
    assert all("Contributors" not in f.detail for f in findings.values())


def test_readme_version_wins_over_asset_version(mock, ctx):
    html(mock, '<script src="/wp-content/plugins/demo/a.js?ver=1.0"></script>')
    mock.add(
        responses.GET, readme_url("demo"), body="=== Demo ===\nStable tag: 2.3.4\n", content_type="text/plain"
    )
    findings = by_key(check_plugin_versions(ctx, {}))
    assert "demo 2.3.4" in findings["plugin-versions:inventory"].detail


def test_probe_readme_disabled_makes_no_requests(mock, ctx):
    html(mock, PAGE)
    (f,) = check_plugin_versions(ctx, {"probe_readme": False})
    assert f.passed
    assert [c.request.url for c in mock.calls] == [BASE]


def test_max_probes_caps_requests(mock, ctx):
    html(mock, PAGE)
    mock.add(responses.GET, readme_url("contact-form-7"), body=README, content_type="text/plain")
    findings = by_key(check_plugin_versions(ctx, {"max_probes": 1}))
    requested = [c.request.url for c in mock.calls]
    assert requested == [BASE, readme_url("contact-form-7")]
    assert "2 plugin readme probe(s) skipped (max_probes=1)" in findings[
        "plugin-versions:inventory"
    ].detail


def test_max_probes_zero_and_invalid(mock, ctx):
    html(mock, PAGE)
    (f,) = check_plugin_versions(ctx, {"max_probes": 0})
    assert "3 plugin readme probe(s) skipped" in f.detail
    for bad in (-1, "5", True, 1.5):
        with pytest.raises(ValueError, match="max_probes"):
            check_plugin_versions(ctx, {"max_probes": bad})


def test_ignore_by_slug_and_qualified_name(mock, ctx):
    html(mock, PAGE)
    options = {"ignore": ["WooCommerce", "theme/astra", "plugin/lazy-thing"], "probe_readme": False}
    (f,) = check_plugin_versions(ctx, options)
    assert f.title == "Detected 1 plugin(s) and 0 theme(s)"
    assert "woocommerce" not in f.detail and "astra" not in f.detail


def test_min_versions_flags_outdated_plugin_and_theme(mock, ctx):
    html(mock, PAGE)
    options = {
        "probe_readme": False,
        "min_versions": {"woocommerce": "8.5", "theme/astra": "4.6.3", "contact-form-7": "5.8"},
    }
    findings = by_key(check_plugin_versions(ctx, options))
    woo = findings["plugin-versions:outdated:plugin/woocommerce"]
    assert not woo.passed and woo.severity is Severity.MEDIUM
    assert "8.2.0" in woo.title and "minimum configured is 8.5" in woo.detail
    assert "plugin-versions:outdated:theme/astra" not in findings
    assert "plugin-versions:outdated:plugin/contact-form-7" not in findings


def test_min_versions_uses_readme_version_and_skips_unknown(mock, ctx):
    html(mock, PAGE)
    mock.add(
        responses.GET,
        readme_url("lazy-thing"),
        body="=== Lazy ===\nStable tag: 0.9\n",
        content_type="text/plain",
    )
    options = {"min_versions": {"lazy-thing": "1.0", "not-installed": "2.0"}}
    findings = by_key(check_plugin_versions(ctx, options))
    assert not findings["plugin-versions:outdated:plugin/lazy-thing"].passed
    assert not findings["plugin-versions:readme:lazy-thing"].passed


def test_min_versions_without_detected_version_is_not_flagged(mock, ctx):
    html(mock, PAGE)
    options = {"probe_readme": False, "min_versions": {"lazy-thing": "1.0"}}
    (f,) = check_plugin_versions(ctx, options)
    assert f.passed


def test_min_versions_rejects_non_version(mock, ctx):
    html(mock, PAGE)
    with pytest.raises(ValueError, match="min_versions.woocommerce"):
        check_plugin_versions(ctx, {"probe_readme": False, "min_versions": {"woocommerce": "latest"}})


def test_network_failure_is_tolerated(mock, ctx):
    html(mock, PAGE)  # readme URLs are not mocked, so the client returns None
    (f,) = check_plugin_versions(ctx, {})
    assert f.passed and f.key == "plugin-versions:inventory"


def test_run_scan_applies_config_and_severity_override(mock, client):
    html(mock, PAGE)
    mock.add(responses.GET, readme_url("contact-form-7"), body=README, content_type="text/plain")
    config = Config(
        checks={"plugin-versions": {"severity": "high", "min_versions": {"woocommerce": "9.0"}}}
    )
    result = run_scan(BASE, config=config, client=client, only=["plugin-versions"])
    failed = {f.key: f.severity for f in result.failed}
    assert failed == {
        "plugin-versions:outdated:plugin/woocommerce": Severity.HIGH,
        "plugin-versions:readme:contact-form-7": Severity.HIGH,
    }
    assert [f.key for f in result.passed] == ["plugin-versions:inventory"]


def test_run_scan_reports_bad_option_as_error(mock, client):
    html(mock, PAGE)
    config = Config(checks={"plugin-versions": {"max_probes": "many"}})
    result = run_scan(BASE, config=config, client=client, only=["plugin-versions"])
    assert not result.findings
    assert any("plugin-versions" in e and "max_probes" in e for e in result.errors)
