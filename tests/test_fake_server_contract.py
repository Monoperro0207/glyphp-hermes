"""Contract test: the REAL glyph_protocol SDK against the fake server.

If these pass, the fake server speaks enough of the wire protocol that every
downstream plugin test exercises the genuine client + verifier code paths.
"""
from __future__ import annotations

import httpx
import pytest

from glyph_protocol import Client, canonical_hash, verify_glyph, verify_receipt

from .fake_server import FakeGlyphServer, default_glyphs


@pytest.fixture(scope="module")
def server():
    with FakeGlyphServer(default_glyphs()) as srv:
        yield srv


@pytest.fixture()
def client(server):
    with Client(server.url) as c:
        yield c


def test_health_and_handshake(client):
    assert client.health()["ok"] is True
    hs = client.handshake(consumer_id="contract-test")
    assert hs["protocolVersion"] == "1.0"
    names = {e["name"] for e in hs["lexicon"]}
    assert names == {"echo", "notes.add", "notes.delete"}
    delete_entry = next(e for e in hs["lexicon"] if e["name"] == "notes.delete")
    assert delete_entry["requiresConfirmation"] is True
    assert delete_entry["riskTier"] == "danger"


def test_cards_verify_with_real_sdk(client, server):
    for name in server.glyphs:
        card = client.get_card(name)
        assert verify_glyph(card) is True, f"card {name} must verify"


def test_corrupted_card_fails_verification(server):
    server.corrupt_signature("echo")
    try:
        with Client(server.url) as client:
            assert verify_glyph(client.get_card("echo")) is False
    finally:
        server.tamper_card("echo")  # restore via legitimate re-issue


def test_call_returns_verifiable_sealed_envelope(client, server):
    envelope = client.call("echo", {"hello": "world"}, call_id="cid-1")
    assert envelope["payload"] == {"echo": {"hello": "world"}}
    receipt = envelope["receipt"]
    assert verify_receipt(receipt) is True
    assert receipt["glyphId"] == server.cards["echo"]["id"]
    assert receipt["outputHash"] == canonical_hash(envelope["payload"])
    assert receipt["clientCallId"] == "cid-1"


def test_confirmation_flow_round_trip(client):
    # Without token → 403 CONFIRMATION_REQUIRED
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.call("notes.delete", {"id": 1})
    assert exc_info.value.response.status_code == 403
    assert exc_info.value.response.json()["error"]["code"] == "CONFIRMATION_REQUIRED"

    # prepare → call with token → ok
    ticket = client.prepare("notes.delete", {"id": 1})
    envelope = client.call(
        "notes.delete", {"id": 1}, confirmation_token=ticket["confirmationToken"]
    )
    assert "deleted" in envelope["payload"]

    # Token is single-use.
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.call(
            "notes.delete", {"id": 1}, confirmation_token=ticket["confirmationToken"]
        )
    assert exc_info.value.response.json()["error"]["code"] == "INVALID_CONFIRMATION"


def test_confirmation_input_mismatch_rejected(client):
    ticket = client.prepare("notes.delete", {"id": 1})
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.call(
            "notes.delete", {"id": 999}, confirmation_token=ticket["confirmationToken"]
        )
    assert exc_info.value.response.json()["error"]["code"] == "INVALID_CONFIRMATION"


def test_tampered_receipt_fails_verification(client, server):
    server.tamper_receipts(True)
    try:
        envelope = client.call("echo", {"x": 1})
        assert verify_receipt(envelope["receipt"]) is False
    finally:
        server.tamper_receipts(False)


def test_forced_protocol_errors(client, server):
    server.set_error("echo", "RATE_LIMITED", 429)
    try:
        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            client.call("echo", {})
        assert exc_info.value.response.status_code == 429
        assert exc_info.value.response.json()["error"]["code"] == "RATE_LIMITED"
    finally:
        server.clear_error("echo")


def test_unknown_glyph_404(client):
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        client.get_card("nope")
    assert exc_info.value.response.status_code == 404
