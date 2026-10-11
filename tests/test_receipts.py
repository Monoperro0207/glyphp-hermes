"""Receipt verification + audit trail on the live call path."""
from __future__ import annotations

import json

from glyphp_hermes.audit import ReceiptAuditLog
from glyphp_hermes.config import ReceiptPolicy

from .conftest import make_bridge


def test_successful_call_appends_verified_audit_entry(bridge, tmp_path):
    out = json.loads(bridge.make_handler("glyph_demo_echo")({"hello": 1}))
    assert out["ok"] is True
    assert out["receipt"]["verified"] is True
    assert out["receipt"]["callId"]
    assert out["inspection"] == {"modified": False, "findings": []}

    entries = ReceiptAuditLog(tmp_path / "audit.jsonl").tail()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["verified"] is True
    assert entry["glyphName"] == "echo"
    assert entry["checks"] == {
        "keyMatchesPin": True,
        "signature": True,
        "glyphIdMatchesPin": True,
        "outputHashMatches": True,
        "inspectionHashMatches": True,
        "callIdMatches": True,
    }
    assert entry["pinnedPublicKey"] == entry["receipt"]["serverPublicKey"]
    assert entry["receipt"]["outputHash"] == out["receipt"]["outputHash"]


def test_tampered_receipt_blocks_payload(server, tmp_path, confirmer):
    bridge = make_bridge(server, tmp_path, confirmer)  # on_failure=block default
    bridge.sync()
    server.tamper_receipts(True)
    try:
        out = json.loads(bridge.make_handler("glyph_demo_echo")({"x": 1}))
        assert out["ok"] is False
        assert out["error"]["code"] == "RECEIPT_INVALID"
        assert "result" not in out  # payload withheld
        # The failure is still on the audit record.
        entry = ReceiptAuditLog(tmp_path / "audit.jsonl").tail()[-1]
        assert entry["verified"] is False
        assert entry["checks"]["signature"] is False
    finally:
        server.tamper_receipts(False)
        bridge.close()


def test_replayed_envelope_blocks_payload(server, tmp_path, confirmer):
    # A MITM records the first response and answers the next call with it.
    bridge = make_bridge(server, tmp_path, confirmer)
    bridge.sync()
    real_call = bridge.client.call
    recorded: list[dict] = []

    def replaying(name, args, **kwargs):
        if not recorded:
            recorded.append(real_call(name, args, **kwargs))
        return recorded[0]

    bridge.client.call = replaying
    try:
        handler = bridge.make_handler("glyph_demo_echo")
        first = json.loads(handler({"x": 1}))
        assert first["ok"] is True and first["result"] == {"echo": {"x": 1}}

        out = json.loads(handler({"x": 2}))
        assert out["ok"] is False
        assert out["error"]["code"] == "RECEIPT_INVALID"
        assert "result" not in out  # the stale payload is withheld
        entry = ReceiptAuditLog(tmp_path / "audit.jsonl").tail()[-1]
        assert entry["verified"] is False
        assert [k for k, v in entry["checks"].items() if not v] == ["callIdMatches"]
    finally:
        bridge.close()


def test_tampered_receipt_warn_policy_returns_payload(server, tmp_path, confirmer):
    bridge = make_bridge(
        server, tmp_path, confirmer, receipts=ReceiptPolicy(verify=True, on_failure="warn")
    )
    bridge.sync()
    server.tamper_receipts(True)
    try:
        out = json.loads(bridge.make_handler("glyph_demo_echo")({"x": 1}))
        assert out["ok"] is True
        assert out["result"] == {"echo": {"x": 1}}
        assert "receipt verification failed" in out["warning"]
        assert out["receipt"]["verified"] is False
    finally:
        server.tamper_receipts(False)
        bridge.close()


def test_verify_disabled_skips_checks(server, tmp_path, confirmer):
    bridge = make_bridge(
        server, tmp_path, confirmer, receipts=ReceiptPolicy(verify=False)
    )
    bridge.sync()
    server.tamper_receipts(True)
    try:
        out = json.loads(bridge.make_handler("glyph_demo_echo")({"x": 1}))
        assert out["ok"] is True
        assert out["receipt"]["verified"] is None
    finally:
        server.tamper_receipts(False)
        bridge.close()


def test_audit_verify_all_over_real_history(bridge, tmp_path, server):
    handler = bridge.make_handler("glyph_demo_echo")
    handler({"a": 1})
    server.tamper_receipts(True)
    handler({"a": 2})
    server.tamper_receipts(False)
    handler({"a": 3})

    report = ReceiptAuditLog(tmp_path / "audit.jsonl").verify_all()
    assert report["total"] == 3
    assert report["ok"] == 2 and report["bad"] == 1
