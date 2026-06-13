"""The `glyphp-hermes` console script: enable/disable/status in Hermes' config.

Every test runs against the isolated HERMES_HOME the conftest sets, so the
real ~/.hermes is never touched.
"""
from __future__ import annotations

import yaml

from glyphp_hermes import setup
from glyphp_hermes.config import hermes_config_path


def _enabled(path) -> list:
    return (yaml.safe_load(path.read_text()) or {}).get("plugins", {}).get("enabled", [])


def test_enable_creates_config_when_missing():
    path = hermes_config_path()
    assert not path.exists()
    assert setup.main(["enable"]) == 0
    assert path.exists()
    assert _enabled(path) == ["glyph"]


def test_enable_defaults_to_enable_subcommand():
    assert setup.main([]) == 0
    assert _enabled(hermes_config_path()) == ["glyph"]


def test_enable_is_idempotent(capsys):
    setup.main(["enable"])
    capsys.readouterr()
    assert setup.main(["enable"]) == 0
    assert "already enabled" in capsys.readouterr().out
    assert _enabled(hermes_config_path()) == ["glyph"]  # not duplicated


def test_enable_preserves_unrelated_keys_and_comments():
    path = hermes_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    original = (
        "# my hermes config\n"
        "model:\n"
        "  name: hermes-4\n"
        "  temperature: 0.7  # tuned\n"
    )
    path.write_text(original)

    assert setup.main(["enable"]) == 0
    text = path.read_text()
    # The whole original block survives verbatim (textual insert, no rewrite).
    assert "# my hermes config" in text
    assert "temperature: 0.7  # tuned" in text
    assert "name: hermes-4" in text
    assert "glyph" in _enabled(path)
    # And a backup was made.
    assert path.with_name("config.yaml.bak").read_text() == original


def test_enable_appends_to_existing_block_style_enabled():
    path = hermes_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("plugins:\n  enabled:\n    - other\n")
    assert setup.main(["enable"]) == 0
    assert _enabled(path) == ["other", "glyph"]
    # Existing item preserved by line insertion.
    assert "- other" in path.read_text()


def test_enable_when_plugins_present_without_enabled():
    path = hermes_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("plugins:\n  autoload: true\n")
    assert setup.main(["enable"]) == 0
    assert "glyph" in _enabled(path)


def test_enable_handles_flow_style_via_rewrite(capsys):
    path = hermes_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("plugins:\n  enabled: [other]\n")
    assert setup.main(["enable"]) == 0
    out = capsys.readouterr().out
    assert "re-serialized" in out  # fell back to structured rewrite
    assert set(_enabled(path)) == {"other", "glyph"}
    assert path.with_name("config.yaml.bak").exists()


def test_disable_removes_only_glyph():
    path = hermes_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("plugins:\n  enabled:\n    - other\n    - glyph\n")
    assert setup.main(["disable"]) == 0
    assert _enabled(path) == ["other"]


def test_disable_noop_when_absent(capsys):
    assert setup.main(["disable"]) == 0
    assert "nothing to disable" in capsys.readouterr().out


def test_status_reports_enabled(capsys):
    setup.main(["enable"])
    capsys.readouterr()
    assert setup.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "glyph in plugins.enabled:  yes" in out
    # entry-point is registered because the package is installed in the test env.
    assert "entry-point registered:    yes" in out


def test_status_reports_not_enabled(capsys):
    assert setup.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "glyph in plugins.enabled:  no" in out
    assert "glyphp-hermes enable" in out
