"""Confirmation gate: approve/deny/pending/timeout/unavailable + server enforcement."""
from __future__ import annotations

import json

import pytest

from glyph_protocol import canonical_hash


@pytest.fixture()
def trusted_delete(bridge, confirmer):
    """Bridge with notes.delete explicitly trusted (still requires confirmation)."""
    bridge.trust_tool("glyph_demo_notes_delete")
    return bridge.make_handler("glyph_demo_notes_delete")


def test_approved_flow_prepares_and_calls_with_token(trusted_delete, confirmer, server):
    confirmer.outcomes = ["approved"]
    server.requests.clear()
    out = json.loads(trusted_delete({"id": 1}))
    assert out["ok"] is True
    paths = [path for _, path in server.requests]
    assert any(path.endswith("/prepare") for path in paths)
    assert any(path.endswith("/call") for path in paths)
    # Confirmer saw an actionable description with the input and risk tier.
    call = confirmer.calls[-1]
    assert "notes.delete" in call["summary"]
    assert "risk danger" in call["description"]
    assert call["approval_key"] == f"glyph:demo:notes.delete:{canonical_hash({'id': 1})}"


def test_denied_flow_never_calls_server(trusted_delete, confirmer, server):
    confirmer.outcomes = ["denied"]
    server.requests.clear()
    out = json.loads(trusted_delete({"id": 2}))
    assert out["error"]["code"] == "USER_DENIED"
    assert "Do NOT retry" in out["error"]["message"]
    assert not any(p.endswith(("/prepare", "/call")) for _, p in server.requests)


def test_pending_flow_instructs_retry(trusted_delete, confirmer, server):
    confirmer.outcomes = ["pending"]
    server.requests.clear()
    out = json.loads(trusted_delete({"id": 3}))
    assert out["error"]["code"] == "CONFIRMATION_PENDING"
    assert "retry" in out["error"]["message"].lower()
    assert not any(p.endswith("/call") for _, p in server.requests)


def test_timeout_flow(trusted_delete, confirmer):
    confirmer.outcomes = ["timeout"]
    out = json.loads(trusted_delete({"id": 4}))
    assert out["error"]["code"] == "CONFIRMATION_TIMEOUT"


def test_unavailable_fails_closed(trusted_delete, confirmer):
    confirmer.outcomes = ["unavailable"]
    out = json.loads(trusted_delete({"id": 5}))
    assert out["error"]["code"] == "CONFIRMATION_UNAVAILABLE"


def test_server_enforces_gate_even_if_plugin_bypassed(bridge, server):
    """Defense in depth: hitting /call without a token is rejected server-side."""
    bridge.trust_tool("glyph_demo_notes_delete")
    binding = bridge.bindings["glyph_demo_notes_delete"]
    import httpx

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        bridge.client.call(binding.glyph_name, {"id": 1})
    assert exc_info.value.response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"


def test_expired_token_maps_readably(trusted_delete, confirmer, server, monkeypatch):
    """An expired/consumed token surfaces as INVALID_CONFIRMATION, not a crash."""
    confirmer.outcomes = ["approved"]
    # Expire every ticket the moment it is issued.
    original_prepare = server._prepare

    def expiring_prepare(name, body):
        status, ticket = original_prepare(name, body)
        server.expire_confirmations()
        return status, ticket

    monkeypatch.setattr(server, "_prepare", expiring_prepare)
    out = json.loads(trusted_delete({"id": 6}))
    assert out["error"]["code"] == "INVALID_CONFIRMATION"


def test_safe_tool_never_asks_confirmation(bridge, confirmer):
    out = json.loads(bridge.make_handler("glyph_demo_echo")({"x": 1}))
    assert out["ok"] is True
    assert confirmer.calls == []
