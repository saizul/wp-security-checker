import responses
from conftest import BASE, html

from wp_security_checker.checks.version import check_wp_version
from wp_security_checker.checks.xmlrpc import check_xmlrpc
from wp_security_checker.models import Severity

PAGE = (
    '<html><head><meta name="generator" content="WordPress 6.4.2">'
    '<script src="https://example.com/wp-includes/js/wp-embed.min.js?ver=6.4.2"></script>'
    '<link rel="stylesheet" href="/wp-includes/css/dist/block-library/style.min.css?ver=6.4.2">'
    "</head></html>"
)


def test_version_exposed_via_all_sources(mock, ctx):
    html(mock, PAGE)
    mock.add(
        responses.GET, BASE + "readme.html", body="<h1>WordPress</h1> Version 6.4.2", status=200
    )
    (f,) = check_wp_version(ctx, {})
    assert not f.passed and f.severity is Severity.LOW
    assert (
        "generator meta tag" in f.detail and "readme.html" in f.detail and "?ver=6.4.2" in f.detail
    )
    assert "6.4.2" in f.detail


def test_version_only_generator(mock, ctx):
    html(mock, '<meta name="generator" content="WordPress 5.9">')
    (f,) = check_wp_version(ctx, {})
    assert not f.passed and "5.9" in f.detail


def test_version_only_readme(mock, ctx):
    html(mock)
    mock.add(responses.GET, BASE + "readme.html", body="WordPress Version 6.1", status=200)
    (f,) = check_wp_version(ctx, {})
    assert not f.passed and "readme.html" in f.detail


def test_version_readme_disabled_by_option(mock, ctx):
    html(mock)
    mock.add(responses.GET, BASE + "readme.html", body="WordPress Version 6.1", status=200)
    (f,) = check_wp_version(ctx, {"check_readme": False})
    assert f.passed


def test_version_clean_site(mock, ctx):
    html(mock)
    mock.add(responses.GET, BASE + "readme.html", status=404)
    (f,) = check_wp_version(ctx, {})
    assert f.passed


def test_version_non_core_ver_ignored(mock, ctx):
    html(mock, '<script src="/wp-content/plugins/x/a.js?ver=1.2.3"></script>')
    (f,) = check_wp_version(ctx, {"check_readme": False})
    assert f.passed


def test_xmlrpc_reachable_405(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "xmlrpc.php",
        status=405,
        body="XML-RPC server accepts POST requests only.",
    )
    (f,) = check_xmlrpc(ctx, {})
    assert not f.passed and f.severity is Severity.MEDIUM


def test_xmlrpc_200_with_phrase(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "xmlrpc.php",
        status=200,
        body="XML-RPC server accepts POST requests only.",
    )
    assert not check_xmlrpc(ctx, {})[0].passed


def test_xmlrpc_blocked(mock, ctx):
    mock.add(responses.GET, BASE + "xmlrpc.php", status=403)
    assert check_xmlrpc(ctx, {})[0].passed


def test_xmlrpc_unreachable(mock, ctx):
    assert check_xmlrpc(ctx, {})[0].passed
