import json

from test_cli import FAST, site
from test_scanner_baseline_report import bad, good, make_result

from wp_security_checker.baseline import diff_against
from wp_security_checker.cli import main
from wp_security_checker.models import Severity
from wp_security_checker.sarif import SARIF_VERSION, to_sarif, to_sarif_json


def validate_structure(log):
    """Check the parts of the SARIF 2.1.0 schema that GitHub code scanning relies on."""
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    assert isinstance(log["runs"], list) and len(log["runs"]) == 1
    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] and driver["version"]
    rule_ids = [r["id"] for r in driver["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note", "none"}
        assert 0 <= float(rule["properties"]["security-severity"]) <= 10
    for res in run["results"]:
        assert res["level"] in {"error", "warning", "note", "none"}
        assert res["message"]["text"]
        assert driver["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert loc and not loc.startswith("/")
        assert res["partialFingerprints"]["findingKey/v1"]
    return run


def test_only_failed_findings_become_results():
    result = make_result(
        bad("xmlrpc", Severity.HIGH),
        good("jquery"),
        bad("sensitive-files:.env", Severity.CRITICAL),
        bad("sensitive-files:backup.zip", Severity.MEDIUM),
    )
    run = validate_structure(to_sarif(result))
    assert [r["properties"]["key"] for r in run["results"]] == [
        "sensitive-files:.env",
        "xmlrpc",
        "sensitive-files:backup.zip",
    ]
    assert [r["level"] for r in run["results"]] == ["error", "error", "warning"]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"xmlrpc", "sensitive-files"}
    # the rule takes the worst severity among its findings
    assert rules["sensitive-files"]["properties"]["security-severity"] == "9.5"


def test_clean_scan_has_no_results():
    run = validate_structure(to_sarif(make_result(good("a"), good("b"))))
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []


def test_message_contains_detail_and_recommendation():
    run = to_sarif(make_result(bad("xmlrpc")))["runs"][0]
    text = run["results"][0]["message"]["text"]
    assert "Title xmlrpc" in text and "d" in text and "Recommendation: r" in text


def test_custom_location_and_target_in_fingerprint():
    log = to_sarif(make_result(bad("xmlrpc")), location="docs/security.md")
    res = log["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "docs/security.md"
    assert res["partialFingerprints"]["findingKey/v1"] == "https://example.com/|xmlrpc"


def test_baseline_state_with_diff():
    previous = {"findings": [{"key": "xmlrpc", "passed": False}, {"key": "gone", "passed": False}]}
    current = make_result(bad("xmlrpc"), bad("jquery"))
    states = {
        r["properties"]["key"]: r["baselineState"]
        for r in to_sarif(current, diff_against(previous, current))["runs"][0]["results"]
    }
    assert states == {"xmlrpc": "unchanged", "jquery": "new"}
    assert "baselineState" not in to_sarif(current)["runs"][0]["results"][0]


def test_scan_errors_are_reported_as_notifications():
    result = make_result(bad("xmlrpc"))
    result.errors.append("check 'boom' crashed")
    inv = to_sarif(result)["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is False
    assert inv["toolExecutionNotifications"][0]["message"]["text"] == "check 'boom' crashed"
    assert to_sarif(make_result())["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_to_sarif_json_roundtrips():
    log = json.loads(to_sarif_json(make_result(bad("xmlrpc"))))
    validate_structure(log)


def test_cli_writes_sarif_file(mock, tmp_path):
    site(mock)
    out = tmp_path / "out.sarif"
    assert main(["example.com", "--only", "xmlrpc", "--sarif", str(out), *FAST]) == 0
    run = validate_structure(json.loads(out.read_text()))
    assert any(r["ruleId"] == "xmlrpc" for r in run["results"])


def test_cli_sarif_location_option(mock, tmp_path):
    site(mock)
    out = tmp_path / "out.sarif"
    args = [
        "example.com",
        "--only",
        "xmlrpc",
        "--sarif",
        str(out),
        "--sarif-location",
        "SECURITY.md",
    ]
    assert main([*args, *FAST]) == 0
    uri = json.loads(out.read_text())["runs"][0]["results"][0]["locations"][0]
    assert uri["physicalLocation"]["artifactLocation"]["uri"] == "SECURITY.md"


def test_cli_sarif_unwritable(mock, tmp_path, capsys):
    site(mock)
    bad_path = tmp_path / "no" / "out.sarif"
    assert main(["example.com", "--only", "xmlrpc", "--sarif", str(bad_path), *FAST]) == 2
    assert "cannot write" in capsys.readouterr().err
