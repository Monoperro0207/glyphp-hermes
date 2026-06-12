"""Sync/ingestion: naming, schemas, TOFU gating, invalid cards, attestation gate."""
from __future__ import annotations

import json

from glyphp_hermes.bridge import card_to_schema, sanitize_tool_name
from glyphp_hermes.config import AttestationPolicy, TofuPolicy

from .conftest import make_bridge


def test_sanitize_tool_name():
    assert sanitize_tool_name("demo", "notes.add") == "glyph_demo_notes_add"
    assert sanitize_tool_name("demo", "weird name/x") == "glyph_demo_weird_name_x"
    assert sanitize_tool_name("demo-attested", "notes.export") == "glyph_demo_attested_notes_export"
    assert len(sanitize_tool_name("demo", "x" * 200)) <= 64


def test_sync_builds_bindings_with_schemas(bridge):
    names = set(bridge.bindings)
    assert names == {"glyph_demo_echo", "glyph_demo_notes_add", "glyph_demo_notes_delete"}

    binding = bridge.bindings["glyph_demo_notes_add"]
    schema = card_to_schema(binding.tool_name, binding.alias, binding.card)
    assert schema["name"] == "glyph_demo_notes_add"
    assert schema["parameters"] == binding.card["input"]  # exact card input schema
    assert "[glyph:demo]" in schema["description"]
    assert "risk: caution" in schema["description"]

    delete_schema = card_to_schema(
        "glyph_demo_notes_delete", "demo", bridge.bindings["glyph_demo_notes_delete"].card
    )
    assert "requires user confirmation" in delete_schema["description"]


def test_tofu_gating_on_sync(bridge):
    # max_risk_tier=caution: echo + notes.add auto-pinned, notes.delete blocked.
    assert bridge.bindings["glyph_demo_echo"].allowed
    assert bridge.bindings["glyph_demo_notes_add"].allowed
    danger = bridge.bindings["glyph_demo_notes_delete"]
    assert not danger.allowed and danger.blocked_code == "TRUST_REQUIRED"


def test_blocked_tool_returns_instruction_not_call(bridge, server):
    handler = bridge.make_handler("glyph_demo_notes_delete")
    server.requests.clear()
    out = json.loads(handler({"id": 1}))
    assert out["ok"] is False
    assert out["error"]["code"] == "TRUST_REQUIRED"
    assert "/glyph trust" in out["error"]["message"]
    # The handler never touched the network.
    assert not any("/call" in path for _, path in server.requests)


def test_corrupt_card_blocked_as_invalid(server, tmp_path, confirmer):
    server.corrupt_signature("echo")
    bridge = make_bridge(server, tmp_path, confirmer)
    bridge.sync()
    binding = bridge.bindings["glyph_demo_echo"]
    assert not binding.allowed and binding.blocked_code == "CARD_INVALID"
    out = json.loads(bridge.make_handler("glyph_demo_echo")({}))
    assert out["error"]["code"] == "CARD_INVALID"
    bridge.close()


def test_trust_then_call_unblocks_danger_tool(bridge, confirmer):
    confirmer.outcomes = ["approved"]
    msg = bridge.trust_tool("glyph_demo_notes_delete")
    assert "trusted" in msg
    handler = bridge.make_handler("glyph_demo_notes_delete")
    out = json.loads(handler({"id": 1}))
    assert out["ok"] is True


def test_revoke_blocks_pinned_tool(bridge):
    assert "revoked" in bridge.revoke_tool("glyph_demo_echo", "supply-chain incident")
    out = json.loads(bridge.make_handler("glyph_demo_echo")({}))
    assert out["error"]["code"] == "CARD_REVOKED"


def test_attestation_policy_danger_blocks_unattested(server, tmp_path, confirmer):
    bridge = make_bridge(
        server,
        tmp_path,
        confirmer,
        tofu=TofuPolicy(enabled=True, max_risk_tier="danger"),
        attestation=AttestationPolicy(require="danger"),
    )
    bridge.sync()
    danger = bridge.bindings["glyph_demo_notes_delete"]
    assert not danger.allowed and danger.blocked_code == "ATTESTATION_REQUIRED"
    # Safe tools unaffected by the 'danger' policy.
    assert bridge.bindings["glyph_demo_echo"].allowed
    # Explicit trust does NOT bypass the attestation policy.
    msg = bridge.trust_tool("glyph_demo_notes_delete")
    assert "still blocked: ATTESTATION_REQUIRED" in msg
    bridge.close()


def test_sync_failure_degrades_cleanly(server, tmp_path, confirmer):
    bridge = make_bridge(server, tmp_path, confirmer)
    server.stop()
    report = bridge.sync()
    assert report.ok is False and report.error
    assert bridge.bindings == {}
    bridge.close()
