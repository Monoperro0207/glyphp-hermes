"""Full register(ctx): tools, hooks, slash + CLI commands, degraded modes."""
from __future__ import annotations

import json

import pytest

import glyphp_hermes
from glyphp_hermes import plugin
from glyphp_hermes.config import GlyphConfig, ServerConfig, TofuPolicy

from .fake_server import FakeGlyph, FakeGlyphServer, default_glyphs
from .hermes_stubs import FakeContext


@pytest.fixture(autouse=True)
def fresh_runtime():
    yield
    plugin.reset_runtime()


def _write_config(*servers: ServerConfig) -> None:
    cfg = GlyphConfig()
    for server in servers:
        cfg.add_server(server)
    cfg.save()


@pytest.fixture()
def registered(server):
    _write_config(
        ServerConfig(
            alias="demo",
            url=server.url,
            tofu=TofuPolicy(enabled=True, max_risk_tier="caution"),
        )
    )
    ctx = FakeContext()
    glyphp_hermes.register(ctx)
    return ctx, plugin.get_runtime()


def test_register_wires_everything(registered):
    ctx, runtime = registered
    # Tools registered with sanitized names + toolset.
    assert set(ctx.registry.tools) == {
        "glyph_demo_echo",
        "glyph_demo_notes_add",
        "glyph_demo_notes_delete",
    }
    assert ctx.registry.tools["glyph_demo_echo"]["toolset"] == "glyph-demo"
    schema = ctx.registry.tools["glyph_demo_notes_add"]["schema"]
    assert schema["name"] == "glyph_demo_notes_add"
    assert "parameters" in schema
    # Hooks, slash command, CLI command present.
    assert "on_session_start" in ctx.hooks
    assert "post_approval_response" in ctx.hooks
    assert "glyph" in ctx.commands
    assert "glyph" in ctx.cli_commands


def test_dispatch_through_fake_registry(registered):
    ctx, _runtime = registered
    out = json.loads(ctx.registry.dispatch("glyph_demo_echo", {"hi": True}))
    assert out["ok"] is True
    assert out["result"] == {"echo": {"hi": True}}
    assert out["receipt"]["verified"] is True


def test_blocked_danger_tool_registered_but_gated(registered):
    ctx, _ = registered
    out = json.loads(ctx.registry.dispatch("glyph_demo_notes_delete", {"id": 1}))
    assert out["ok"] is False
    assert out["error"]["code"] == "TRUST_REQUIRED"


def test_empty_config_registers_commands_only():
    ctx = FakeContext()
    glyphp_hermes.register(ctx)
    assert ctx.registry.tools == {}
    assert "glyph" in ctx.commands
    assert "glyph" in ctx.cli_commands
    # Slash command answers helpfully instead of crashing.
    out = ctx.commands["glyph"]["handler"]("status")
    assert "No Glyph servers configured" in out


def test_two_servers_two_toolsets():
    extra_glyphs = [FakeGlyph("ping", intent="Pong", risk_tier="safe")]
    with FakeGlyphServer(default_glyphs()) as s1, FakeGlyphServer(extra_glyphs) as s2:
        _write_config(
            ServerConfig(alias="alpha", url=s1.url, tofu=TofuPolicy(max_risk_tier="caution")),
            ServerConfig(alias="beta", url=s2.url),
        )
        ctx = FakeContext()
        glyphp_hermes.register(ctx)
        toolsets = {entry["toolset"] for entry in ctx.registry.tools.values()}
        assert toolsets == {"glyph-alpha", "glyph-beta"}
        assert "glyph_beta_ping" in ctx.registry.tools


def test_one_dead_server_does_not_abort_the_rest(server):
    _write_config(
        ServerConfig(alias="dead", url="http://127.0.0.1:1"),  # nothing listens
        ServerConfig(alias="demo", url=server.url, tofu=TofuPolicy(max_risk_tier="caution")),
    )
    ctx = FakeContext()
    glyphp_hermes.register(ctx)
    assert "glyph_demo_echo" in ctx.registry.tools


def test_entry_point_visible():
    from importlib.metadata import entry_points

    eps = {e.name for e in entry_points(group="hermes_agent.plugins")}
    assert "glyph" in eps
