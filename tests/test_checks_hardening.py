import responses
from conftest import BASE, html

from wp_security_checker.checks.headers import check_security_headers
from wp_security_checker.checks.jquery import check_jquery
from wp_security_checker.checks.login import check_login_url
from wp_security_checker.checks.transport import check_https_redirect
from wp_security_checker.models import Severity
from wp_security_checker.utils import parse_version, version_lt

ALL = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}


def by_key(findings):
    return {f.key.split(":", 1)[1]: f for f in findings}


def test_all_headers_present(mock, ctx):
    html(mock, headers=ALL)
    assert all(f.passed for f in check_security_headers(ctx, {}))


def test_all_headers_missing(mock, ctx):
    html(mock)
    findings = check_security_headers(ctx, {})
    assert len(findings) == 6 and not any(f.passed for f in findings)
    assert by_key(findings)["Strict-Transport-Security"].severity is Severity.MEDIUM


def test_xfo_satisfied_by_csp_frame_ancestors(mock, ctx):
    html(mock, headers={"Content-Security-Policy": "frame-ancestors 'self'"})
    assert by_key(check_security_headers(ctx, {}))["X-Frame-Options"].passed


def test_hsts_short_max_age(mock, ctx):
    html(mock, headers={"Strict-Transport-Security": "max-age=300"})
    f = by_key(check_security_headers(ctx, {}))["Strict-Transport-Security"]
    assert not f.passed and "300" in f.detail


def test_hsts_threshold_configurable(mock, ctx):
    html(mock, headers={"Strict-Transport-Security": "max-age=300"})
    f = by_key(check_security_headers(ctx, {"hsts_min_age": 100}))["Strict-Transport-Security"]
    assert f.passed


def test_required_subset(mock, ctx):
    html(mock)
    findings = check_security_headers(ctx, {"required": ["x-content-type-options"]})
    assert [f.key for f in findings] == ["security-headers:X-Content-Type-Options"]


def test_https_redirect_ok(mock, ctx):
    mock.add(
        responses.GET,
        "http://example.com/",
        status=301,
        headers={"Location": "https://example.com/"},
    )
    assert check_https_redirect(ctx, {})[0].passed


def test_https_redirect_missing(mock, ctx):
    mock.add(responses.GET, "http://example.com/", status=200, body="hi")
    (f,) = check_https_redirect(ctx, {})
    assert not f.passed and f.severity is Severity.MEDIUM


def test_https_redirect_to_http_is_bad(mock, ctx):
    mock.add(
        responses.GET,
        "http://example.com/",
        status=302,
        headers={"Location": "http://example.com/home"},
    )
    assert not check_https_redirect(ctx, {})[0].passed


def test_http_port_closed(mock, ctx):
    assert check_https_redirect(ctx, {})[0].passed


def test_login_reachable(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "wp-login.php",
        body='<input id="user_login">',
        content_type="text/html",
    )
    (f,) = check_login_url(ctx, {})
    assert not f.passed and f.severity is Severity.LOW


def test_login_redirected_or_404(mock, ctx):
    mock.add(responses.GET, BASE + "wp-login.php", status=404)
    assert check_login_url(ctx, {})[0].passed


def test_login_custom_path(mock, ctx):
    mock.add(responses.GET, BASE + "my-login", body='<input name="log">')
    assert not check_login_url(ctx, {"path": "my-login"})[0].passed


def test_jquery_outdated_from_filename(mock, ctx):
    html(mock, '<script src="/js/jquery-1.12.4.min.js"></script>')
    (f,) = check_jquery(ctx, {})
    assert not f.passed and "1.12.4" in f.detail


def test_jquery_core_ver_param(mock, ctx):
    html(mock, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"></script>')
    assert not check_jquery(ctx, {})[0].passed


def test_jquery_current_ok(mock, ctx):
    html(mock, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>')
    assert check_jquery(ctx, {})[0].passed


def test_jquery_migrate_not_confused(mock, ctx):
    html(mock, '<script src="/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.4.1"></script>')
    assert check_jquery(ctx, {})[0].passed


def test_jquery_threshold_option(mock, ctx):
    html(mock, '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.6.0"></script>')
    assert not check_jquery(ctx, {"min_version": "3.7.0"})[0].passed


def test_parse_version_helpers():
    assert parse_version("v3.5.1-beta") == (3, 5, 1)
    assert parse_version("abc") is None
    assert version_lt((3, 5), (3, 5, 1)) and not version_lt((3, 5, 0), (3, 5))
