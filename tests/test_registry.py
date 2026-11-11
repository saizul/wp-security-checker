import pytest

from wp_security_checker.registry import Check, CheckRegistry, load_builtin_checks, register


def _noop(ctx, options):
    return []


def test_add_and_get():
    reg = CheckRegistry()
    reg.add(Check("a", "fam", "desc", _noop))
    assert "a" in reg and len(reg) == 1
    assert reg.get("a").family == "fam"


def test_duplicate_rejected():
    reg = CheckRegistry()
    reg.add(Check("a", "f", "d", _noop))
    with pytest.raises(ValueError):
        reg.add(Check("a", "f", "d", _noop))


def test_decorator_registers_in_given_registry():
    reg = CheckRegistry()

    @register("zzz", "fam", "desc", registry=reg)
    def fn(ctx, options):
        return []

    assert reg.ids() == ["zzz"]
    assert reg.get("zzz").func is fn


def test_order_and_families():
    reg = CheckRegistry()
    reg.add(Check("b", "two", "", _noop))
    reg.add(Check("a", "one", "", _noop))
    assert reg.ids() == ["b", "a"]
    assert reg.families() == ["one", "two"]


def test_builtin_checks_loaded():
    reg = load_builtin_checks()
    expected = {
        "wp-version",
        "xmlrpc",
        "rest-users",
        "author-enum",
        "directory-listing",
        "sensitive-files",
        "security-headers",
        "https-redirect",
        "login-url",
        "jquery",
        "plugin-versions",
    }
    assert expected <= set(reg.ids())
    assert len(reg.families()) >= 5


def test_load_builtin_is_idempotent():
    assert len(load_builtin_checks()) == len(load_builtin_checks())


def test_plugin_loading_with_callable(monkeypatch):
    from wp_security_checker import registry as r

    class EP:
        name = "demo"

        def load(self):
            return lambda reg: reg.add(Check("demo", "x", "d", _noop))

    class EPs:
        def select(self, group):
            return [EP()] if group == r.ENTRY_POINT_GROUP else []

    from importlib import metadata

    monkeypatch.setattr(metadata, "entry_points", lambda: EPs())
    reg = CheckRegistry()
    assert r.load_plugins(reg) == ["demo"]
    assert "demo" in reg


def test_broken_plugin_is_skipped(monkeypatch, capsys):
    from importlib import metadata

    from wp_security_checker import registry as r

    class EP:
        name = "bad"

        def load(self):
            raise RuntimeError("nope")

    class EPs:
        def select(self, group):
            return [EP()]

    monkeypatch.setattr(metadata, "entry_points", lambda: EPs())
    assert r.load_plugins(CheckRegistry()) == []
    assert "bad" in capsys.readouterr().err
