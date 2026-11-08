import json

import responses
from conftest import BASE, html

from wp_security_checker.cli import main

FAST = ["--delay", "0", "--retries", "0"]


def site(mock):
    html(mock, '<meta name="generator" content="WordPress 6.4.2">')
    mock.add(
        responses.GET,
        BASE + "xmlrpc.php",
        status=405,
        body="XML-RPC server accepts POST requests only.",
    )


def test_list_checks(capsys):
    assert main(["--list-checks"]) == 0
    assert "xmlrpc" in capsys.readouterr().out


def test_requires_url(capsys):
    assert main([]) == 2


def test_json_output(mock, capsys):
    site(mock)
    assert main(["example.com", "--json", "--only", "xmlrpc,wp-version", *FAST]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {f["check_id"] for f in data["findings"]} == {"xmlrpc", "wp-version"}
    assert data["summary"]["failed"] == 2


def test_table_output(mock, capsys):
    site(mock)
    assert main(["https://example.com", "--only", "xmlrpc", *FAST]) == 0
    assert "xmlrpc.php is reachable" in capsys.readouterr().out


def test_fail_on(mock, capsys):
    site(mock)
    assert main(["example.com", "--only", "xmlrpc", "--fail-on", "medium", "--json", *FAST]) == 1
    assert main(["example.com", "--only", "xmlrpc", "--fail-on", "high", "--json", *FAST]) == 0


def test_html_output(mock, tmp_path):
    site(mock)
    out = tmp_path / "r.html"
    assert main(["example.com", "--only", "xmlrpc", "--html", str(out), *FAST]) == 0
    assert "xmlrpc.php is reachable" in out.read_text()


def test_html_unwritable(mock, tmp_path, capsys):
    site(mock)
    assert (
        main(["example.com", "--only", "xmlrpc", "--html", str(tmp_path / "no" / "r.html"), *FAST])
        == 2
    )


def test_baseline_flow(mock, tmp_path, capsys):
    site(mock)
    base = tmp_path / "b.json"
    main(["example.com", "--only", "xmlrpc", "--json", *FAST])
    base.write_text(capsys.readouterr().out)
    # same site: nothing new, so --fail-on does not trigger
    assert (
        main(
            [
                "example.com",
                "--only",
                "xmlrpc",
                "--json",
                "--baseline",
                str(base),
                "--fail-on",
                "low",
                *FAST,
            ]
        )
        == 0
    )
    data = json.loads(capsys.readouterr().out)
    assert data["baseline"]["unchanged"] and not data["baseline"]["new"]


def test_baseline_detects_new(mock, tmp_path, capsys):
    site(mock)
    base = tmp_path / "b.json"
    main(["example.com", "--only", "xmlrpc", "--json", *FAST])
    base.write_text(capsys.readouterr().out)
    code = main(
        [
            "example.com",
            "--only",
            "xmlrpc,wp-version",
            "--json",
            "--baseline",
            str(base),
            "--fail-on",
            "low",
            *FAST,
        ]
    )
    assert code == 1


def test_bad_baseline_file(tmp_path, capsys):
    p = tmp_path / "b.json"
    p.write_text("nope")
    assert main(["example.com", "--baseline", str(p)]) == 2
    assert "baseline" in capsys.readouterr().err


def test_config_file_disables_check(mock, tmp_path, capsys):
    site(mock)
    cfg = tmp_path / "c.yml"
    cfg.write_text("checks:\n  xmlrpc: false\n")
    main(["example.com", "--json", "--only", "xmlrpc,wp-version", "--config", str(cfg), *FAST])
    ids = {f["check_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert ids == {"wp-version"}


def test_bad_config_exit_code(tmp_path, capsys):
    cfg = tmp_path / "c.yml"
    cfg.write_text("bogus: 1\n")
    assert main(["example.com", "--config", str(cfg)]) == 2


def test_unknown_check_exit_code(mock, capsys):
    site(mock)
    assert main(["example.com", "--only", "nope", *FAST]) == 2


def test_unreachable_target(mock, capsys):
    assert main(["example.com", *FAST]) == 2
    assert "could not reach" in capsys.readouterr().err


def test_full_scan_clean_site(mock, capsys):
    html(
        mock,
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        },
    )
    assert main(["example.com", "--json", *FAST]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["failed"] == 0


def test_cli_overrides_are_validated(capsys):
    for flags, message in [
        (["--timeout", "0"], "http.timeout must be greater than zero"),
        (["--timeout", "-5"], "http.timeout must be greater than zero"),
        (["--delay", "-1"], "http.delay must not be negative"),
        (["--retries", "-1"], "http.retries must not be negative"),
    ]:
        assert main([BASE, *flags]) == 2
        assert message in capsys.readouterr().err
