"""/glyph slash command surface + the `hermes glyph` CLI."""
from __future__ import annotations

import argparse
import json

import pytest

import glyphp_hermes
from glyphp_hermes import cli, plugin
from glyphp_hermes.config import GlyphConfig, ServerConfig, TofuPolicy

from .hermes_stubs import FakeContext


@pytest.fixture(autouse=True)
def fresh_runtime():
    yield
    plugin.reset_runtime()


@pytest.fixture()
def registered(server):
    cfg = GlyphConfig()
    cfg.add_server(
        ServerConfig(
            alias="demo", url=server.url, tofu=TofuPolicy(enabled=True, max_risk_tier="caution")
        )
    )
    cfg.save()
    ctx = FakeContext()
    glyphp_hermes.register(ctx)
    return ctx, ctx.commands["glyph"]["handler"]


def test_usage_on_empty_and_unknown(registered):
    _, glyph = registered
    assert "usage:" in glyph("")
    assert "usage:" in glyph("frobnicate")


def test_status_lists_tools_and_states(registered):
    _, glyph = registered
    out = glyph("status")
    assert "glyph_demo_echo" in out and "callable" in out
    assert "glyph_demo_notes_delete" in out and "TRUST_REQUIRED" in out


def test_trust_and_revoke_cycle(registered):
    ctx, glyph = registered
    assert "trusted" in glyph("trust glyph_demo_notes_delete")
    assert "TRUST_REQUIRED" not in glyph("status")
    assert "revoked" in glyph("revoke glyph_demo_notes_delete supply chain issue")
    out = json.loads(ctx.registry.dispatch("glyph_demo_notes_delete", {"id": 1}))
    assert out["error"]["code"] == "CARD_REVOKED"


def test_diff_no_pending(registered):
    _, glyph = registered
    assert "no pending changes" in glyph("diff glyph_demo_echo")


def test_diff_renders_pending_change(registered, server):
    ctx, glyph = registered
    server.tamper_card("notes.add", risk_tier="danger")
    ctx.invoke_hook("on_session_start")
    out = glyph("diff glyph_demo_notes_add")
    assert "cost.riskTier" in out
    assert "breaking" in out
    assert "requires approval" in out


def test_audit_tail(registered):
    ctx, glyph = registered
    assert "empty" in glyph("audit")
    ctx.registry.dispatch("glyph_demo_echo", {"x": 1})
    out = glyph("audit 5")
    assert "[ok ]" in out and "glyph_demo_echo" in out


def test_unknown_tool_messages(registered):
    _, glyph = registered
    assert "unknown tool" in glyph("trust nope")
    assert "unknown tool" in glyph("revoke nope")
    assert "unknown tool" in glyph("diff nope")


def test_command_never_raises(registered, monkeypatch):
    _, glyph = registered
    runtime = plugin.get_runtime()
    monkeypatch.setattr(
        runtime, "reconcile", lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    out = glyph("sync")
    assert "failed" in out and "boom" in out


# ---------------------------------------------------------------------------
# CLI (hermes glyph ... / python -m glyphp_hermes.cli)
# ---------------------------------------------------------------------------


def test_cli_add_list_remove(capsys):
    assert cli.main(["add", "demo", "http://127.0.0.1:9", "--tofu-max-risk", "caution"]) == 0
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "demo: http://127.0.0.1:9" in out
    assert "tofu<= caution" in out
    assert cli.main(["remove", "demo"]) == 0
    assert cli.main(["remove", "demo"]) == 1  # already gone


def test_cli_add_duplicate_alias_fails(capsys):
    assert cli.main(["add", "demo", "http://a"]) == 0
    assert cli.main(["add", "demo", "http://b"]) == 2
    assert "config error" in capsys.readouterr().err


def test_cli_sync_and_call(server, capsys):
    assert cli.main(["add", "demo", server.url, "--tofu-max-risk", "caution"]) == 0
    assert cli.main(["sync"]) == 0
    out = capsys.readouterr().out
    assert "3 tools" in out and "glyph_demo_echo: callable" in out

    assert cli.main(["call", "demo", "echo", '{"x": 1}']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True and result["result"] == {"echo": {"x": 1}}


def test_cli_call_confirmation_gate(server, capsys):
    cli.main(["add", "demo", server.url, "--tofu-max-risk", "danger"])
    capsys.readouterr()  # drop the 'added server' line
    # Without --yes the gate fails closed.
    assert cli.main(["call", "demo", "notes.delete", '{"id": 1}']) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"]["code"] == "CONFIRMATION_UNAVAILABLE"
    # With --yes it goes through prepare + call.
    assert cli.main(["call", "demo", "notes.delete", '{"id": 1}', "--yes"]) == 0


def test_cli_audit_verify(server, capsys):
    cli.main(["add", "demo", server.url, "--tofu-max-risk", "caution"])
    cli.main(["call", "demo", "echo", "{}"])
    capsys.readouterr()
    assert cli.main(["audit", "--verify"]) == 0
    out = capsys.readouterr().out
    assert "1/1 receipts verify" in out


def test_cli_bad_json_input(server, capsys):
    cli.main(["add", "demo", server.url])
    assert cli.main(["call", "demo", "echo", "{not json"]) == 2


def test_hermes_handle_raises_on_blocked_call(server, capsys):
    # Hermes' dispatcher discards args.func()'s return value, so a blocked
    # call would exit 0; hermes_handle turns nonzero into SystemExit so
    # scripts and CI see the failure.
    cli.main(["add", "demo", server.url, "--tofu-max-risk", "danger"])
    parser = argparse.ArgumentParser()
    cli.setup(parser)
    blocked = parser.parse_args(["call", "demo", "notes.delete", '{"id": 1}'])
    with pytest.raises(SystemExit) as excinfo:
        cli.hermes_handle(blocked)
    assert excinfo.value.code == 1

    ok = parser.parse_args(["call", "demo", "echo", "{}"])
    assert cli.hermes_handle(ok) == 0  # success must NOT raise
