"""ReceiptAuditLog + check_envelope + error envelope helpers."""
from __future__ import annotations

import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import canonical_hash

from glyphp_hermes.audit import ReceiptAuditLog, check_envelope
from glyphp_hermes.errors import parse_glyph_error, tool_error

from .cardlab import build_card, build_receipt


@pytest.fixture
def priv():
    return Ed25519PrivateKey.generate()


def _envelope(priv, card, payload):
    receipt = build_receipt(
        priv,
        glyph_id=card["id"],
        glyph_name=card["name"],
        input_hash=canonical_hash({}),
        output_hash=canonical_hash(payload),
    )
    return {"payload": payload, "receipt": receipt, "inspection": {"modified": False, "findings": []}}


def test_check_envelope_all_green(priv):
    card = build_card(priv)
    envelope = _envelope(priv, card, {"result": 42})
    ok, checks = check_envelope(envelope, card)
    assert ok is True
    assert checks == {
        "keyMatchesPin": True,
        "signature": True,
        "glyphIdMatchesPin": True,
        "outputHashMatches": True,
        "inspectionHashMatches": True,
    }


def test_check_envelope_bad_signature(priv):
    card = build_card(priv)
    envelope = _envelope(priv, card, {"result": 42})
    envelope["receipt"]["signature"] = "00" * 64
    ok, checks = check_envelope(envelope, card)
    assert ok is False and checks["signature"] is False


def test_check_envelope_wrong_glyph_id(priv):
    card = build_card(priv)
    other = build_card(priv, name="other", intent="different")
    envelope = _envelope(priv, other, {"result": 42})
    ok, checks = check_envelope(envelope, card)
    assert ok is False and checks["glyphIdMatchesPin"] is False


def test_check_envelope_payload_substitution(priv):
    # A MITM swapping the payload without re-signing breaks outputHash.
    card = build_card(priv)
    envelope = _envelope(priv, card, {"result": 42})
    envelope["payload"] = {"result": "swapped"}
    ok, checks = check_envelope(envelope, card)
    assert ok is False and checks["outputHashMatches"] is False
    assert checks["signature"] is True  # the receipt itself is intact


def test_check_envelope_key_substitution(priv):
    # Adversarial: a receipt signed by a key the attacker controls, naming
    # the pinned card's glyphId and a matching outputHash. Self-consistent
    # (signature verifies under its own key) but NOT signed by the pin.
    card = build_card(priv)
    attacker = Ed25519PrivateKey.generate()
    payload = {"result": "forged"}
    forged = build_receipt(
        attacker,
        glyph_id=card["id"],
        glyph_name=card["name"],
        input_hash=canonical_hash({}),
        output_hash=canonical_hash(payload),
    )
    envelope = {
        "payload": payload,
        "receipt": forged,
        "inspection": {"modified": False, "findings": []},
    }
    ok, checks = check_envelope(envelope, card)
    assert ok is False
    assert checks["keyMatchesPin"] is False
    assert checks["signature"] is True  # self-consistent, hence the pin check


def test_check_envelope_inspection_substitution(priv):
    # Adversarial: swap the inspection for one hiding a critical finding,
    # leaving the signed receipt untouched.
    card = build_card(priv)
    envelope = _envelope(priv, card, {"result": 42})
    envelope["inspection"] = {"modified": True, "findings": []}
    ok, checks = check_envelope(envelope, card)
    assert ok is False and checks["inspectionHashMatches"] is False
    assert checks["signature"] is True


def test_check_envelope_missing_inspection_hash_fails_closed(priv):
    card = build_card(priv)
    envelope = _envelope(priv, card, {"result": 42})
    receipt = {k: v for k, v in envelope["receipt"].items() if k != "inspectionHash"}
    # Re-sign so only the missing field (not the signature) is under test.
    from .cardlab import sign
    base = {k: v for k, v in receipt.items() if k != "signature"}
    receipt = {**base, "signature": sign(priv, canonical_hash(base))}
    envelope["receipt"] = receipt
    ok, checks = check_envelope(envelope, card)
    assert ok is False and checks["inspectionHashMatches"] is False


def test_audit_log_record_and_tail(tmp_path, priv):
    log = ReceiptAuditLog(tmp_path / "audit" / "demo.jsonl")
    card = build_card(priv)
    for i in range(3):
        envelope = _envelope(priv, card, {"i": i})
        ok, checks = check_envelope(envelope, card)
        log.record(
            alias="demo",
            glyph_name="echo",
            tool_name="glyph_demo_echo",
            envelope=envelope,
            verified=ok,
            checks=checks,
            input_value={"i": i},
            pinned_public_key=card["publicKey"],
        )
    entries = log.tail(2)
    assert len(entries) == 2
    assert entries[-1]["verified"] is True
    assert entries[-1]["inputHash"] == canonical_hash({"i": 2})
    assert entries[-1]["receipt"]["glyphName"] == "echo"


def test_audit_verify_all_detects_tamper(tmp_path, priv):
    log = ReceiptAuditLog(tmp_path / "demo.jsonl")
    card = build_card(priv)
    good = _envelope(priv, card, {"ok": 1})
    bad = _envelope(priv, card, {"ok": 2})
    bad["receipt"]["signature"] = "00" * 64
    for envelope in (good, bad):
        ok, checks = check_envelope(envelope, card)
        log.record(
            alias="demo", glyph_name="echo", tool_name="t",
            envelope=envelope, verified=ok, checks=checks, input_value={},
            pinned_public_key=card["publicKey"],
        )
    report = log.verify_all()
    assert report["total"] == 2 and report["ok"] == 1 and report["bad"] == 1
    assert report["failures"][0]["glyphName"] == "echo"


def test_audit_verify_all_rejects_foreign_key(tmp_path, priv):
    # An entry whose receipt verifies under its OWN key but was not signed
    # by the key pinned at call time must count as bad, not ok.
    log = ReceiptAuditLog(tmp_path / "demo.jsonl")
    card = build_card(priv)
    attacker = Ed25519PrivateKey.generate()
    envelope = _envelope(attacker, card, {"ok": 1})
    log.record(
        alias="demo", glyph_name="echo", tool_name="t",
        envelope=envelope, verified=False, checks={}, input_value={},
        pinned_public_key=card["publicKey"],
    )
    report = log.verify_all()
    assert report["total"] == 1 and report["ok"] == 0 and report["bad"] == 1


def test_audit_empty_log(tmp_path):
    log = ReceiptAuditLog(tmp_path / "missing.jsonl")
    assert log.tail() == []
    assert log.verify_all()["total"] == 0


def test_tool_error_shape_and_guidance():
    out = json.loads(tool_error("USER_DENIED", "User declined notes.delete."))
    assert out["ok"] is False
    assert out["error"]["code"] == "USER_DENIED"
    assert "Do NOT retry" in out["error"]["message"]


def test_tool_error_extra_fields():
    out = json.loads(tool_error("CARD_CHANGED", "msg", tool="glyph_demo_echo", diff={"x": 1}))
    assert out["tool"] == "glyph_demo_echo"
    assert out["diff"] == {"x": 1}


def _http_error(status: int, body: dict) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://test/glyphs/x/call")
    response = httpx.Response(status, json=body, request=request)
    return httpx.HTTPStatusError("boom", request=request, response=response)


def test_parse_glyph_error_full_envelope():
    exc = _http_error(
        400,
        {"error": {"code": "VALIDATION_FAILED", "message": "bad input", "details": {"path": "/x"}}},
    )
    parsed = parse_glyph_error(exc)
    assert parsed == {
        "code": "VALIDATION_FAILED",
        "message": "bad input",
        "details": {"path": "/x"},
    }


def test_parse_glyph_error_non_json_body():
    request = httpx.Request("GET", "http://test/health")
    response = httpx.Response(502, text="Bad Gateway", request=request)
    exc = httpx.HTTPStatusError("boom", request=request, response=response)
    parsed = parse_glyph_error(exc)
    assert parsed["code"] == "HTTP_502"
    assert "Bad Gateway" in parsed["message"]
