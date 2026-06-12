"""Config loading, merging, validation, and path isolation."""
from __future__ import annotations

import pytest

from glyphp_hermes.config import (
    ConfigError,
    GlyphConfig,
    ServerConfig,
    TofuPolicy,
    config_path,
    glyph_home,
)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
    return tmp_path


def test_glyph_home_respects_hermes_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "custom"))
    assert glyph_home() == tmp_path / "custom" / "glyph"


def test_missing_config_loads_empty():
    cfg = GlyphConfig.load()
    assert cfg.servers == []


def test_round_trip_save_load():
    cfg = GlyphConfig()
    cfg.add_server(ServerConfig(alias="demo", url="http://127.0.0.1:3100/"))
    path = cfg.save()
    assert path == config_path()

    loaded = GlyphConfig.load()
    assert len(loaded.servers) == 1
    server = loaded.servers[0]
    assert server.alias == "demo"
    assert server.url == "http://127.0.0.1:3100"  # trailing slash stripped
    assert server.tofu == TofuPolicy(enabled=True, max_risk_tier="safe")
    assert server.receipts.on_failure == "block"
    assert server.confirmations.non_interactive == "deny"
    assert server.attestation.require == "none"


def test_defaults_deep_merge_with_per_server_override(tmp_path):
    path = config_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        """
version: 1
defaults:
  tofu: { enabled: true, max_risk_tier: safe }
  receipts: { on_failure: warn }
servers:
  - alias: demo
    url: http://127.0.0.1:3100
    tofu: { max_risk_tier: caution }
  - alias: other
    url: http://127.0.0.1:3200
""",
        encoding="utf-8",
    )
    cfg = GlyphConfig.load()
    demo = cfg.get_server("demo")
    other = cfg.get_server("other")
    # Per-server override wins, but unspecified keys come from defaults.
    assert demo.tofu.max_risk_tier == "caution"
    assert demo.tofu.enabled is True
    assert demo.receipts.on_failure == "warn"
    # Untouched server inherits defaults wholesale.
    assert other.tofu.max_risk_tier == "safe"
    assert other.receipts.on_failure == "warn"


def test_alias_validation():
    cfg = GlyphConfig()
    with pytest.raises(ConfigError):
        cfg.add_server(ServerConfig(alias="Bad Alias!", url="http://x"))
    with pytest.raises(ConfigError):
        cfg.add_server(ServerConfig(alias="", url="http://x"))


def test_duplicate_alias_rejected():
    cfg = GlyphConfig()
    cfg.add_server(ServerConfig(alias="demo", url="http://a"))
    with pytest.raises(ConfigError):
        cfg.add_server(ServerConfig(alias="demo", url="http://b"))


def test_invalid_policy_values_rejected(tmp_path):
    path = config_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        """
servers:
  - alias: demo
    url: http://127.0.0.1:3100
    receipts: { on_failure: explode }
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        GlyphConfig.load()


def test_auth_token_env_resolution(monkeypatch):
    server = ServerConfig(alias="demo", url="http://x", auth_token_env="GLYPH_TEST_TOKEN")
    assert server.auth_token() is None
    monkeypatch.setenv("GLYPH_TEST_TOKEN", "sekrit")
    assert server.auth_token() == "sekrit"


def test_tofu_policy_tiers():
    tofu = TofuPolicy(enabled=True, max_risk_tier="caution")
    assert tofu.allows("safe") and tofu.allows("caution")
    assert not tofu.allows("danger")
    assert not TofuPolicy(enabled=False).allows("safe")
    # Unknown tiers are never auto-trusted.
    assert not tofu.allows("weird")


def test_state_paths_under_glyph_home():
    server = ServerConfig(alias="demo", url="http://x")
    assert server.pin_path() == glyph_home() / "pins" / "demo.json"
    assert server.audit_path() == glyph_home() / "audit" / "demo.jsonl"
    assert server.pending_path() == glyph_home() / "pending" / "demo.json"
