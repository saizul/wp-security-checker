import requests
import responses
from conftest import BASE

from wp_security_checker.checks.banner import (
    check_server_banner,
    disclosed_products,
    php_version,
)
from wp_security_checker.checks.cookies import (
    check_cookie_flags,
    parse_set_cookie,
    set_cookie_headers,
)
from wp_security_checker.context import ScanContext
from wp_security_checker.models import Severity
from wp_security_checker.registry import load_builtin_checks

LOGIN = BASE + "wp-login.php"
SESSION = "wordpress_logged_in_0123456789abcdef0123456789abcdef"


def page(mock, url=BASE, cookies=(), headers=()):
    hdrs = [("Content-Type", "text/html")] + [("Set-Cookie", c) for c in cookies] + list(headers)
    mock.add(responses.GET, url, body="<html></html>", headers=hdrs)


def keys(findings):
    return {f.key for f in findings if not f.passed}


# --- parsing -----------------------------------------------------------------


def test_parse_set_cookie_attributes():
    c = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=lax")
    assert (c.name, c.secure, c.http_only, c.same_site) == ("sid", True, True, "Lax")


def test_parse_set_cookie_rejects_nameless():
    assert parse_set_cookie("no-equals-sign") is None
    assert parse_set_cookie("=value; Secure") is None


def test_set_cookie_headers_fallback_split_keeps_expires():
    class Fake:
        raw = None
        headers = {
            "Set-Cookie": "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly, b=2; Secure"
        }

    assert set_cookie_headers(Fake()) == [
        "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly",
        "b=2; Secure",
    ]


def test_set_cookie_headers_reads_every_header(mock, ctx):
    page(mock, cookies=["a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "b=2"])
    assert [h.split("=")[0] for h in set_cookie_headers(ctx.home)] == ["a", "b"]


# --- cookie-flags --------------------------------------------------------------


def test_no_cookies_passes(mock, ctx):
    page(mock)
    page(mock, url=LOGIN)
    (f,) = check_cookie_flags(ctx, {})
    assert f.passed and "No cookies" in f.detail


def test_well_flagged_session_cookie_passes(mock, ctx):
    page(mock)
    page(mock, url=LOGIN, cookies=[f"{SESSION}=x; Secure; HttpOnly; SameSite=Lax"])
    (f,) = check_cookie_flags(ctx, {})
    assert f.passed and "1 cookie" in f.detail


def test_weak_session_cookie_reports_each_flag(mock, ctx):
    page(mock, cookies=["PHPSESSID=secretvalue; Path=/"])
    page(mock, url=LOGIN)
    findings = check_cookie_flags(ctx, {})
    assert keys(findings) == {
        "cookie-flags:PHPSESSID:secure",
        "cookie-flags:PHPSESSID:httponly",
        "cookie-flags:PHPSESSID:samesite",
    }
    by_key = {f.key: f for f in findings}
    assert by_key["cookie-flags:PHPSESSID:secure"].severity is Severity.MEDIUM
    assert by_key["cookie-flags:PHPSESSID:samesite"].severity is Severity.LOW
    # the cookie value must never leak into a report
    assert all("secretvalue" not in f.detail + f.title for f in findings)


def test_plain_cookie_only_secure_by_default(mock, ctx):
    page(mock, cookies=["pref=dark"])
    page(mock, url=LOGIN)
    findings = check_cookie_flags(ctx, {})
    assert keys(findings) == {"cookie-flags:pref:secure"}
    assert findings[0].severity is Severity.LOW


def test_report_all_includes_plain_cookies(mock, ctx):
    page(mock, cookies=["pref=dark"])
    page(mock, url=LOGIN)
    assert keys(check_cookie_flags(ctx, {"report_all": True})) == {
        "cookie-flags:pref:secure",
        "cookie-flags:pref:httponly",
        "cookie-flags:pref:samesite",
    }


def test_samesite_none_without_secure(mock, ctx):
    page(mock, cookies=["track=1; SameSite=None"])
    page(mock, url=LOGIN)
    findings = {f.key: f for f in check_cookie_flags(ctx, {})}
    assert "SameSite=None" in findings["cookie-flags:track:samesite"].title


def test_secure_not_required_on_plain_http(mock, client):
    ctx = ScanContext("http://example.com/", client)
    page(mock, url="http://example.com/", cookies=["pref=dark"])
    page(mock, url="http://example.com/wp-login.php")
    assert check_cookie_flags(ctx, {})[0].passed


def test_ignore_and_custom_session_patterns(mock, ctx):
    page(mock, cookies=["pref=dark", "shop_sess=1; Secure"])
    page(mock, url=LOGIN)
    findings = check_cookie_flags(ctx, {"ignore": ["PREF"], "session_patterns": ["^shop_sess$"]})
    assert keys(findings) == {"cookie-flags:shop_sess:httponly", "cookie-flags:shop_sess:samesite"}


def test_weakest_variant_wins_across_pages(mock, ctx):
    page(mock, cookies=[f"{SESSION}=x; Secure; HttpOnly; SameSite=Lax"])
    page(mock, url=LOGIN, cookies=[f"{SESSION}=x; HttpOnly; SameSite=Lax"])
    findings = check_cookie_flags(ctx, {})
    (f,) = [f for f in findings if not f.passed]
    assert f.key == f"cookie-flags:{SESSION}:secure"
    assert "/, /wp-login.php" in f.detail


def test_custom_paths(mock, ctx):
    page(mock, url=BASE + "my-account/", cookies=["wp_woocommerce_session_abc=1"])
    findings = check_cookie_flags(ctx, {"paths": ["my-account/"]})
    assert "cookie-flags:wp_woocommerce_session_abc:secure" in keys(findings)


# --- server-banner -------------------------------------------------------------


def test_disclosed_products():
    assert disclosed_products("Apache/2.4.58 (Ubuntu) OpenSSL/3.0.2") == [
        ("Apache", "2.4.58"),
        ("OpenSSL", "3.0.2"),
    ]
    assert disclosed_products("nginx") == []
    assert php_version({"X-Powered-By": "PHP/8.1.27"}) == "8.1.27"


def test_banner_clean(mock, ctx):
    page(mock, headers=[("Server", "nginx")])
    (f,) = check_server_banner(ctx, {})
    assert f.passed and "Server" in f.detail


def test_banner_no_headers(mock, ctx):
    page(mock)
    (f,) = check_server_banner(ctx, {})
    assert f.passed and "No banner" in f.detail


def test_banner_versions_and_eol_php(mock, ctx):
    page(mock, headers=[("Server", "Apache/2.4.41"), ("X-Powered-By", "PHP/7.4.33")])
    findings = {f.key: f for f in check_server_banner(ctx, {})}
    assert set(findings) == {
        "server-banner:Server",
        "server-banner:X-Powered-By",
        "server-banner:php-eol",
    }
    assert findings["server-banner:php-eol"].severity is Severity.MEDIUM
    assert "Apache/2.4.41" in findings["server-banner:Server"].detail


def test_banner_supported_php_not_eol(mock, ctx):
    page(mock, headers=[("X-Powered-By", "PHP/8.3.10")])
    assert set(f.key for f in check_server_banner(ctx, {})) == {"server-banner:X-Powered-By"}


def test_banner_min_php_configurable(mock, ctx):
    page(mock, headers=[("X-Powered-By", "PHP/8.3.10")])
    keys_ = {f.key for f in check_server_banner(ctx, {"min_php": "8.4"})}
    assert "server-banner:php-eol" in keys_


def test_banner_custom_header_list(mock, ctx):
    page(mock, headers=[("Server", "Apache/2.4.41"), ("X-Litespeed-Cache", "hit")])
    (f,) = check_server_banner(ctx, {"headers": ["X-Powered-By"]})
    assert f.passed


def test_banner_home_unreachable(ctx, mock):
    mock.add(responses.GET, BASE, body=requests.exceptions.ConnectionError("down"))
    assert check_server_banner(ctx, {}) == []


def test_new_checks_registered():
    reg = load_builtin_checks()
    assert {"cookie-flags", "server-banner"} <= set(reg.ids())
    assert reg.get("cookie-flags").family == "hardening"
    assert reg.get("server-banner").family == "disclosure"
