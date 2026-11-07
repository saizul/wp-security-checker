import responses
from conftest import BASE

from wp_security_checker.checks.listing import check_directory_listing
from wp_security_checker.checks.sensitive import check_sensitive_files
from wp_security_checker.checks.users import check_author_enum, check_rest_users
from wp_security_checker.models import Severity


def test_rest_users_listed(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "wp-json/wp/v2/users",
        json=[{"id": 1, "slug": "admin"}, {"id": 2, "slug": "ed"}],
    )
    (f,) = check_rest_users(ctx, {})
    assert not f.passed and "2 user" in f.detail and "admin" in f.detail


def test_rest_users_forbidden(mock, ctx):
    mock.add(
        responses.GET, BASE + "wp-json/wp/v2/users", status=401, json={"code": "rest_cannot_view"}
    )
    assert check_rest_users(ctx, {})[0].passed


def test_rest_users_fallback_route(mock, ctx):
    mock.add(responses.GET, BASE + "wp-json/wp/v2/users", status=404)
    mock.add(responses.GET, BASE + "?rest_route=/wp/v2/users", json=[{"slug": "bob"}])
    assert not check_rest_users(ctx, {})[0].passed


def test_rest_users_empty_list_ok(mock, ctx):
    mock.add(responses.GET, BASE + "wp-json/wp/v2/users", json=[])
    assert check_rest_users(ctx, {})[0].passed


def test_rest_users_non_json(mock, ctx):
    mock.add(responses.GET, BASE + "wp-json/wp/v2/users", body="<html>", status=200)
    assert check_rest_users(ctx, {})[0].passed


def test_author_redirect(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "?author=1",
        status=301,
        headers={"Location": "https://example.com/author/admin/"},
    )
    (f,) = check_author_enum(ctx, {})
    assert not f.passed and "admin" in f.detail and f.severity is Severity.LOW


def test_author_no_redirect(mock, ctx):
    mock.add(responses.GET, BASE + "?author=1", status=200, body="home")
    assert check_author_enum(ctx, {})[0].passed


def test_author_custom_ids(mock, ctx):
    mock.add(responses.GET, BASE + "?author=1", status=404)
    mock.add(responses.GET, BASE + "?author=2", status=302, headers={"Location": "/author/jo/"})
    assert not check_author_enum(ctx, {"ids": [1, 2]})[0].passed


def test_directory_listing_found(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "wp-content/uploads/",
        body="<html><head><title>Index of /wp-content/uploads</title>",
        content_type="text/html",
    )
    (f,) = check_directory_listing(ctx, {})
    assert not f.passed and f.severity is Severity.HIGH


def test_directory_listing_forbidden(mock, ctx):
    mock.add(responses.GET, BASE + "wp-content/uploads/", status=403)
    assert check_directory_listing(ctx, {})[0].passed


def test_directory_listing_extra_paths(mock, ctx):
    mock.add(responses.GET, BASE + "wp-content/uploads/", status=403)
    mock.add(responses.GET, BASE + "wp-content/plugins/", body="<h1>Index of /plugins</h1>")
    findings = check_directory_listing(
        ctx, {"paths": ["wp-content/uploads/", "wp-content/plugins/"]}
    )
    assert len(findings) == 1 and findings[0].key.endswith("plugins/")


def test_sensitive_env_exposed_without_leaking_content(mock, ctx):
    mock.add(
        responses.GET, BASE + ".env", body="DB_PASSWORD=SECRETVALUE\n", content_type="text/plain"
    )
    findings = check_sensitive_files(ctx, {})
    assert len(findings) == 1 and findings[0].severity is Severity.CRITICAL
    blob = repr([f.to_dict() for f in findings])
    assert "SECRETVALUE" not in blob


def test_sensitive_wp_config_backup(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "wp-config.php.bak",
        body="<?php define('DB_NAME', 'x');",
        content_type="text/plain",
    )
    (f,) = check_sensitive_files(ctx, {})
    assert f.key == "sensitive-files:wp-config.php.bak" and f.severity is Severity.CRITICAL


def test_sensitive_debug_log(mock, ctx):
    mock.add(
        responses.GET,
        BASE + "wp-content/debug.log",
        body="[01-Jan-2026] PHP Notice",
        content_type="text/plain",
    )
    (f,) = check_sensitive_files(ctx, {})
    assert f.severity is Severity.HIGH


def test_sensitive_soft_404_html_ignored(mock, ctx):
    mock.add(
        responses.GET,
        BASE + ".env",
        body="<!DOCTYPE html><html>Not found</html>",
        content_type="text/html",
    )
    assert check_sensitive_files(ctx, {})[0].passed


def test_sensitive_404s_pass(mock, ctx):
    mock.add(responses.GET, BASE + ".env", status=404)
    assert check_sensitive_files(ctx, {})[0].passed


def test_sensitive_extra_paths(mock, ctx):
    mock.add(
        responses.GET, BASE + "backup.zip", body=b"PK\x03\x04data", content_type="application/zip"
    )
    (f,) = check_sensitive_files(ctx, {"extra_paths": ["backup.zip"]})
    assert f.key == "sensitive-files:backup.zip"
