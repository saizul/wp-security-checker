from pathlib import Path

import pytest

from wp_security_checker.config import Config, ConfigError, load_config, parse_config

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "wp-security-checker.yml"


def test_defaults():
    cfg = parse_config(None)
    assert cfg.http.delay == 0.5 and cfg.http.retries == 2
    assert cfg.enabled("xmlrpc")


def test_disable_with_mapping_and_shorthand():
    cfg = parse_config({"checks": {"xmlrpc": {"enabled": False}, "jquery": False}})
    assert not cfg.enabled("xmlrpc") and not cfg.enabled("jquery")
    assert cfg.enabled("login-url")


def test_options_returned():
    cfg = parse_config({"checks": {"jquery": {"min_version": "3.6.0"}}})
    assert cfg.options("jquery")["min_version"] == "3.6.0"
    assert cfg.options("missing") == {}


def test_http_overrides():
    cfg = parse_config({"http": {"timeout": 3, "retries": 5, "user_agent": "x"}})
    assert (cfg.http.timeout, cfg.http.retries, cfg.http.user_agent) == (3, 5, "x")


@pytest.mark.parametrize(
    "data",
    [
        {"bogus": 1},
        {"http": {"nope": 1}},
        {"http": {"timeout": "fast"}},
        {"http": {"delay": -1}},
        {"http": {"timeout": 0}},
        {"http": {"retries": True}},
        {"http": []},
        {"checks": []},
        {"checks": {"x": 5}},
        {"checks": {"x": {"enabled": "yes"}}},
    ],
)
def test_invalid_configs(data):
    with pytest.raises(ConfigError):
        parse_config(data)


def test_root_must_be_mapping():
    with pytest.raises(ConfigError):
        parse_config([1, 2])  # type: ignore[arg-type]


def test_validate_against_unknown_id():
    cfg = parse_config({"checks": {"typo": {}}})
    with pytest.raises(ConfigError, match="typo"):
        cfg.validate_against(["xmlrpc"])


def test_load_none_gives_defaults():
    assert isinstance(load_config(None), Config)


def test_load_missing_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.yml"))


def test_load_invalid_yaml(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("a: [unclosed")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_load_empty_file(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text("")
    assert load_config(str(p)).enabled("xmlrpc")


def test_example_config_is_valid():
    from wp_security_checker.registry import load_builtin_checks

    cfg = load_config(str(EXAMPLE))
    cfg.validate_against(load_builtin_checks().ids())
    assert not cfg.enabled("author-enum")
