"""Live reconciliation: changed cards gate immediately, tools appear/disappear."""
from __future__ import annotations

import json

import pytest

import glyphp_hermes
from glyphp_hermes import _hermes, plugin
from glyphp_hermes._hermes import HermesCaps
from glyphp_hermes.config import GlyphConfig, ServerConfig, TofuPolicy

from .fake_server import FakeGlyph
from .hermes_stubs import FakeContext


@pytest.fixture(autouse=True)
def fresh_runtime():
    yield
    plugin.reset_runtime()


@pytest.fixture()
def registered(server, monkeypatch):
    cfg = GlyphConfig()
    cfg.add_server(
        ServerConfig(
            alias="demo", url=server.url, tofu=TofuPolicy(enabled=True, max_risk_tier="caution")
        )
    )
    cfg.save()
    ctx = FakeContext()
    # Wire the dynamic-registry capability to the fake registry so reconcile
    # can add/remove tools live (the same seam real Hermes provides).
    caps = HermesCaps(
        available=True,
        registry_register=lambda **kw: ctx.registry.register(**kw),
        registry_deregister=ctx.registry.deregister,
    )
    monkeypatch.setattr(_hermes, "_caps", caps)
    glyphp_hermes.register(ctx)
    return ctx, plugin.get_runtime()


def test_changed_card_blocks_immediately_after_resync(registered, server):
    ctx, _runtime = registered
    assert json.loads(ctx.registry.dispatch("glyph_demo_notes_add", {"text": "a"}))["ok"]

    # Server re-deploys notes.add with a wider blast radius.
    server.tamper_card("notes.add", risk_tier="danger")
    ctx.invoke_hook("on_session_start")

    out = json.loads(ctx.registry.dispatch("glyph_demo_notes_add", {"text": "b"}))
    assert out["ok"] is False
    assert out["error"]["code"] == "CARD_CHANGED"
    assert "/glyph diff" in out["error"]["message"] or "/glyph trust" in out["error"]["message"]


def test_trust_after_change_unblocks(registered, server):
    ctx, runtime = registered
    server.tamper_card("notes.add", risk_tier="danger")
    ctx.invoke_hook("on_session_start")

    reply = ctx.commands["glyph"]["handler"]("trust glyph_demo_notes_add")
    assert "trusted" in reply
    # The diff shown includes the breaking riskTier change.
    assert "cost.riskTier" in reply

    out = json.loads(ctx.registry.dispatch("glyph_demo_notes_add", {"text": "c"}))
    assert out["ok"] is True


def test_new_tool_appears_mid_session(registered, server):
    ctx, _ = registered
    server.add_glyph(FakeGlyph("weather", intent="Forecast", risk_tier="safe"))
    ctx.invoke_hook("on_session_start")
    assert "glyph_demo_weather" in ctx.registry.tools
    out = json.loads(ctx.registry.dispatch("glyph_demo_weather", {"city": "BA"}))
    assert out["ok"] is True


def test_removed_tool_deregisters_mid_session(registered, server):
    ctx, _ = registered
    assert "glyph_demo_echo" in ctx.registry.tools
    server.remove_glyph("echo")
    ctx.invoke_hook("on_session_start")
    assert "glyph_demo_echo" not in ctx.registry.tools


def test_dead_server_resync_degrades_without_raising(registered, server):
    ctx, runtime = registered
    server.stop()
    # The hook must swallow the failure (hooks never raise into Hermes)...
    ctx.invoke_hook("on_session_start")
    # ...and a sync failure must NOT wipe registered tools (stale > gone).
    assert "glyph_demo_echo" in ctx.registry.tools
    out = json.loads(ctx.registry.dispatch("glyph_demo_echo", {}))
    assert out["error"]["code"] in {"SERVER_UNREACHABLE", "NOT_FOUND"}


def test_slash_sync_reports(registered, server):
    ctx, _ = registered
    server.add_glyph(FakeGlyph("extra", intent="Extra", risk_tier="safe"))
    reply = ctx.commands["glyph"]["handler"]("sync")
    assert "added: glyph_demo_extra" in reply
