import json

import pytest
from conftest import html

from wp_security_checker.baseline import BaselineError, diff_against, load_baseline
from wp_security_checker.config import Config, ConfigError, parse_config
from wp_security_checker.models import Finding, ScanResult, Severity
from wp_security_checker.registry import Check, CheckRegistry
from wp_security_checker.report import render_table, sorted_findings, to_html, to_json
from wp_security_checker.scanner import ScanError, normalize_url, run_scan, select_checks


def make_result(*findings):
    return ScanResult("https://example.com/", "2026-01-01T00:00:00+00:00", list(findings))


def bad(key, sev=Severity.MEDIUM):
    return Finding.issue(key.split(":")[0], f"Title {key}", sev, "d", "r", key=key)


def good(key):
    return Finding.ok(key.split(":")[0], f"Title {key}", key=key)


# --- scanner ---------------------------------------------------------------


def test_normalize_url():
    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("http://example.com/blog") == "http://example.com/blog/"


@pytest.mark.parametrize("raw", ["", "ftp://x.com", "https://"])
def test_normalize_url_invalid(raw):
    with pytest.raises(ValueError):
        normalize_url(raw)


def test_run_scan_unreachable(mock, client):
    with pytest.raises(ScanError):
        run_scan("https://example.com", client=client)


def test_run_scan_selection_and_isolation(mock, client):
    html(mock)
    reg = CheckRegistry()
    reg.add(Check("a", "f", "", lambda c, o: [Finding.ok("a", "A")]))
    reg.add(Check("boom", "f", "", lambda c, o: 1 / 0))
    reg.add(Check("c", "f", "", lambda c, o: [Finding.issue("c", "C", Severity.LOW)]))
    res = run_scan("https://example.com", client=client, registry=reg)
    assert [f.check_id for f in res.findings] == ["a", "c"]
    assert any("boom" in e for e in res.errors)


def test_run_scan_disabled_via_config(mock, client):
    html(mock)
    reg = CheckRegistry()
    reg.add(Check("a", "f", "", lambda c, o: [Finding.ok("a", "A")]))
    reg.add(Check("b", "f", "", lambda c, o: [Finding.ok("b", "B")]))
    res = run_scan(
        "https://example.com",
        config=parse_config({"checks": {"a": False}}),
        client=client,
        registry=reg,
    )
    assert [f.check_id for f in res.findings] == ["b"]


def test_severity_override_from_config(mock, client):
    html(mock)
    reg = CheckRegistry()
    reg.add(Check("a", "f", "", lambda c, o: [Finding.issue("a", "A", Severity.LOW)]))
    cfg = parse_config({"checks": {"a": {"severity": "critical"}}})
    res = run_scan("https://example.com", config=cfg, client=client, registry=reg)
    assert res.findings[0].severity is Severity.CRITICAL


def test_bad_severity_override(mock, client):
    html(mock)
    reg = CheckRegistry()
    reg.add(Check("a", "f", "", lambda c, o: [Finding.issue("a", "A", Severity.LOW)]))
    with pytest.raises(ConfigError):
        run_scan(
            "https://example.com",
            config=parse_config({"checks": {"a": {"severity": "huge"}}}),
            client=client,
            registry=reg,
        )


def test_only_and_skip_validation():
    reg = CheckRegistry()
    reg.add(Check("a", "f", "", lambda c, o: []))
    reg.add(Check("b", "f", "", lambda c, o: []))
    assert select_checks(reg, Config(), only=["a"]) == ["a"]
    assert select_checks(reg, Config(), skip=["a"]) == ["b"]
    with pytest.raises(ConfigError):
        select_checks(reg, Config(), only=["zzz"])
    with pytest.raises(ConfigError):
        select_checks(reg, parse_config({"checks": {"typo": {}}}))


# --- models ----------------------------------------------------------------


def test_severity_ranking_and_parse():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank > Severity.INFO.rank
    assert Severity.parse(" HIGH ") is Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("nope")


def test_result_counts_and_dict():
    res = make_result(bad("a", Severity.HIGH), bad("b", Severity.LOW), good("c"))
    d = res.to_dict()
    assert d["summary"]["failed"] == 2 and d["summary"]["passed"] == 1
    assert d["summary"]["by_severity"]["high"] == 1
    assert d["findings"][0]["severity"] == "high"


# --- baseline --------------------------------------------------------------


def previous(*findings):
    return make_result(*findings).to_dict()


def test_diff_new_resolved_unchanged():
    prev = previous(bad("a"), bad("b"), good("c"))
    cur = make_result(bad("b"), bad("c"), good("a"))
    diff = diff_against(prev, cur)
    assert [f.key for f in diff.new] == ["c"]
    assert [f["key"] for f in diff.resolved] == ["a"]
    assert [f.key for f in diff.unchanged] == ["b"]


def test_diff_identical_runs():
    res = make_result(bad("a"))
    diff = diff_against(res.to_dict(), res)
    assert not diff.new and not diff.resolved and len(diff.unchanged) == 1


def test_diff_to_dict_roundtrip():
    diff = diff_against(previous(), make_result(bad("a")))
    assert diff.to_dict()["new"][0]["key"] == "a"


def test_load_baseline_ok(tmp_path):
    p = tmp_path / "b.json"
    p.write_text(to_json(make_result(bad("a"))))
    assert load_baseline(str(p))["findings"][0]["key"] == "a"


@pytest.mark.parametrize("content", ["not json", "[]", '{"findings": [1]}', '{"findings": "x"}'])
def test_load_baseline_invalid(tmp_path, content):
    p = tmp_path / "b.json"
    p.write_text(content)
    with pytest.raises(BaselineError):
        load_baseline(str(p))


def test_load_baseline_missing(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(str(tmp_path / "none.json"))


# --- reports ---------------------------------------------------------------


def test_json_report_valid():
    data = json.loads(to_json(make_result(bad("a"), good("b"))))
    assert data["target"] == "https://example.com/" and len(data["findings"]) == 2
    assert "baseline" not in data


def test_json_report_with_baseline():
    res = make_result(bad("a"))
    data = json.loads(to_json(res, diff_against(previous(), res)))
    assert data["baseline"]["new"][0]["key"] == "a"


def test_sorted_findings_failures_first_by_severity():
    res = make_result(good("p"), bad("m", Severity.MEDIUM), bad("h", Severity.HIGH))
    assert [f.key for f in sorted_findings(res)] == ["h", "m", "p"]


def test_html_report_contents_and_escaping():
    res = make_result(
        Finding.issue("x", "<script>alert(1)</script>", Severity.HIGH, "a & b"), good("p")
    )
    page = to_html(res)
    assert "<script>alert" not in page and "&lt;script&gt;" in page and "a &amp; b" in page
    assert page.startswith("<!doctype html>") and "permission" in page
    assert "high" in page and "PASS" in page


def test_html_report_baseline_section():
    res = make_result(bad("a"))
    page = to_html(res, diff_against(previous(bad("z")), res))
    assert "Baseline comparison" in page and "New (1)" in page and "Resolved (1)" in page


def test_render_table_text():
    from io import StringIO

    from rich.console import Console

    buf = StringIO()
    res = make_result(bad("a", Severity.HIGH), good("b"))
    res.errors.append("oops")
    render_table(res, Console(file=buf, width=200), diff_against(previous(), res))
    out = buf.getvalue()
    assert (
        "FAIL" in out and "PASS" in out and "[NEW]" in out and "Baseline:" in out and "oops" in out
    )
