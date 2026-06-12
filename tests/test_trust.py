"""diff_cards parity with @glyphp/core + TrustManager lifecycle."""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import MemoryPinStore

from glyphp_hermes.config import TofuPolicy
from glyphp_hermes.trust import FIELD_SEVERITY, TrustManager, diff_cards

from .cardlab import build_card


@pytest.fixture
def priv():
    return Ed25519PrivateKey.generate()


def _manager(tofu=None, tmp_path=None, **kwargs) -> TrustManager:
    return TrustManager(
        "demo",
        MemoryPinStore(),
        tofu or TofuPolicy(enabled=True, max_risk_tier="safe"),
        pending_path=(tmp_path / "pending.json") if tmp_path else None,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# diff_cards — parity with the TS severity table
# ---------------------------------------------------------------------------

BREAKING_MUTATIONS = {
    "version": {"version": "2.0.0"},
    "cost.sideEffects": {"side_effects": True},
    "cost.riskTier": {"risk_tier": "danger"},
    "cost.requiresConfirmation": {"requires_confirmation": True},
    "input": {"input_schema": {"type": "object", "properties": {"x": {"type": "string"}}}},
    "output": {"output_schema": {"type": "object", "properties": {"y": {"type": "number"}}}},
    "provider": {"provider": "evil-corp"},
    "attestation": {"attestation": {"type": "digest", "payload": "aaaa"}},
}

REVIEW_MUTATIONS = {
    "intent": {"intent": "Echoes the input, but described differently"},
    "tags": {"tags": ["misc"]},
    "examples": {"examples": [{"input": {}, "output": {}}]},
    "failureModes": {"failureModes": [{"code": "X", "description": "y"}]},
}


@pytest.mark.parametrize("field", sorted(BREAKING_MUTATIONS))
def test_breaking_fields_require_approval(priv, field):
    before = build_card(priv)
    after = build_card(priv, **BREAKING_MUTATIONS[field])
    diff = diff_cards(before, after)
    assert diff["changed"] and diff["idChanged"]
    assert diff["requiresApproval"] is True
    touched = {c["field"] for c in diff["changes"]}
    assert field in touched
    assert FIELD_SEVERITY[field] == "breaking"


@pytest.mark.parametrize("field", sorted(REVIEW_MUTATIONS))
def test_review_fields_do_not_require_approval(priv, field):
    before = build_card(priv)
    after = build_card(priv, **REVIEW_MUTATIONS[field])
    diff = diff_cards(before, after)
    assert diff["changed"]
    assert diff["requiresApproval"] is False
    assert all(c["severity"] == "review" for c in diff["changes"])


def test_identical_cards_no_change(priv):
    card = build_card(priv)
    diff = diff_cards(card, card)
    assert diff == {
        "changed": False,
        "idChanged": False,
        "keyChanged": False,
        "changes": [],
        "requiresApproval": False,
    }


def test_key_swap_detected(priv):
    other = Ed25519PrivateKey.generate()
    before = build_card(priv)
    after = build_card(other)
    diff = diff_cards(before, after)
    assert diff["keyChanged"] is True
    assert diff["requiresApproval"] is True  # publicKey is breaking


# ---------------------------------------------------------------------------
# TrustManager lifecycle
# ---------------------------------------------------------------------------


def test_invalid_signature_never_trusted(priv):
    mgr = _manager()
    card = build_card(priv)
    card["signature"] = "00" * 64
    decision = mgr.evaluate(card)
    assert decision.status == "invalid" and not decision.allowed
    assert mgr.store.get("echo") is None  # never pinned


def test_tofu_auto_pins_safe(priv):
    mgr = _manager()
    decision = mgr.evaluate(build_card(priv, risk_tier="safe"))
    assert decision.status == "pinned" and decision.allowed
    assert mgr.store.get("echo") is not None


def test_tofu_blocks_above_tier(priv):
    mgr = _manager()  # max safe
    decision = mgr.evaluate(build_card(priv, name="rmrf", risk_tier="danger"))
    assert decision.status == "new" and not decision.allowed
    assert mgr.store.get("rmrf") is None


def test_tofu_caution_tier_allows_caution(priv):
    mgr = _manager(tofu=TofuPolicy(enabled=True, max_risk_tier="caution"))
    decision = mgr.evaluate(build_card(priv, risk_tier="caution"))
    assert decision.status == "pinned" and decision.allowed


def test_changed_breaking_blocks_and_queues(priv, tmp_path):
    mgr = _manager(tmp_path=tmp_path)
    mgr.evaluate(build_card(priv))  # pin v1
    changed = build_card(priv, risk_tier="danger")
    decision = mgr.evaluate(changed)
    assert decision.status == "changed" and not decision.allowed
    assert decision.diff["requiresApproval"]
    assert "echo" in mgr.pending()
    # Pending queue survives a new manager instance (persisted to disk).
    mgr2 = TrustManager(
        "demo", mgr.store, TofuPolicy(), pending_path=tmp_path / "pending.json"
    )
    assert "echo" in mgr2.pending()


def test_approve_unblocks_changed_card(priv, tmp_path):
    mgr = _manager(tmp_path=tmp_path)
    mgr.evaluate(build_card(priv))
    changed = build_card(priv, risk_tier="danger")
    assert mgr.evaluate(changed).status == "changed"
    mgr.approve(changed)
    assert mgr.pending() == {}
    decision = mgr.evaluate(changed)
    assert decision.status == "pinned" and decision.allowed


def test_review_only_change_auto_repins(priv):
    mgr = _manager()
    mgr.evaluate(build_card(priv))
    tweaked = build_card(priv, intent="Echoes input verbatim")
    decision = mgr.evaluate(tweaked)
    assert decision.status == "pinned" and decision.allowed
    assert mgr.store.get("echo").card["id"] == tweaked["id"]


def test_review_only_change_blocks_when_auto_repin_off(priv):
    mgr = _manager(auto_repin_review=False)
    mgr.evaluate(build_card(priv))
    decision = mgr.evaluate(build_card(priv, intent="Echoes input verbatim"))
    assert decision.status == "changed" and not decision.allowed


def test_revoke_blocks_even_matching_card(priv):
    mgr = _manager()
    card = build_card(priv)
    mgr.evaluate(card)
    assert mgr.revoke("echo", "compromised provider")
    decision = mgr.evaluate(card)
    assert decision.status == "revoked" and not decision.allowed
    assert "compromised" in decision.reason


def test_approve_refuses_invalid_card(priv):
    mgr = _manager()
    card = build_card(priv)
    card["signature"] = "00" * 64
    with pytest.raises(ValueError):
        mgr.approve(card)


def test_status_rows(priv):
    mgr = _manager()
    mgr.evaluate(build_card(priv))
    rows = mgr.status()
    assert rows[0]["tool"] == "echo"
    assert rows[0]["riskTier"] == "safe"
    assert rows[0]["revoked"] is False
