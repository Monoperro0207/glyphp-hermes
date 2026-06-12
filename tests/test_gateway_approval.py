"""Gateway confirmation flows: tier 1 (blocking), tier 2 (one-shot grants),
fail-closed contexts. The plugin must NEVER session-persist an approval."""
from __future__ import annotations

import json

import pytest

from glyph_protocol import canonical_hash

from glyphp_hermes import _hermes
from glyphp_hermes._hermes import (
    HermesCaps,
    OneShotGrantStore,
    on_post_approval_response,
    request_user_confirmation,
)

from .conftest import make_bridge


@pytest.fixture(autouse=True)
def fresh_grants(monkeypatch):
    store = OneShotGrantStore()
    monkeypatch.setattr(_hermes, "grants", store)
    return store


def _caps(monkeypatch, **kwargs) -> HermesCaps:
    caps = HermesCaps(available=True, **kwargs)
    monkeypatch.setattr(_hermes, "_caps", caps)
    return caps


# ---------------------------------------------------------------------------
# Tier 1 — blocking gateway decision (one-shot by construction)
# ---------------------------------------------------------------------------


def _tier1_caps(monkeypatch, choice, resolved=True):
    decisions = []

    def await_decision(session_key, notify_cb, approval_data, *, surface=""):
        decisions.append(approval_data)
        notify_cb(approval_data)
        return {"resolved": resolved, "choice": choice}

    notify_log = []
    caps = _caps(
        monkeypatch,
        is_gateway_context=lambda: True,
        get_session_key=lambda: "tg-session-1",
        await_gateway_decision=await_decision,
        gateway_notify_cbs={"tg-session-1": notify_log.append},
        submit_pending=lambda *a, **k: pytest.fail("tier 2 must not be used when tier 1 works"),
    )
    return caps, decisions, notify_log


def test_tier1_approved(monkeypatch):
    _tier1_caps(monkeypatch, choice="once")
    assert request_user_confirmation("s", "d", "glyph:demo:x:abc") == "approved"


def test_tier1_denied(monkeypatch):
    _tier1_caps(monkeypatch, choice="deny")
    assert request_user_confirmation("s", "d", "glyph:demo:x:abc") == "denied"


def test_tier1_timeout(monkeypatch):
    _tier1_caps(monkeypatch, choice=None, resolved=False)
    assert request_user_confirmation("s", "d", "glyph:demo:x:abc") == "timeout"


def test_tier1_is_one_shot(monkeypatch):
    """The same call repeated must ask the user again (no session persistence)."""
    _caps_obj, decisions, _ = _tier1_caps(monkeypatch, choice="once")
    request_user_confirmation("s", "d", "glyph:demo:x:abc")
    request_user_confirmation("s", "d", "glyph:demo:x:abc")
    assert len(decisions) == 2  # asked twice — nothing was persisted


def test_tier1_user_notified_with_approval_data(monkeypatch):
    _caps_obj, _, notify_log = _tier1_caps(monkeypatch, choice="once")
    request_user_confirmation("summary!", "desc!", "glyph:demo:x:abc")
    assert notify_log and notify_log[0]["command"] == "summary!"
    assert notify_log[0]["pattern_key"] == "glyph:demo:x:abc"


# ---------------------------------------------------------------------------
# Tier 2 — submit_pending + post_approval_response one-shot grant
# ---------------------------------------------------------------------------


def _tier2_caps(monkeypatch):
    pending = []
    _caps(
        monkeypatch,
        is_gateway_context=lambda: True,
        get_session_key=lambda: "tg-session-2",
        submit_pending=lambda session, approval: pending.append((session, approval)),
    )
    return pending


def test_tier2_first_call_pends(monkeypatch):
    pending = _tier2_caps(monkeypatch)
    outcome = request_user_confirmation("s", "d", "glyph:demo:notes.delete:hash1")
    assert outcome == "pending"
    assert pending[0][0] == "tg-session-2"
    assert pending[0][1]["pattern_key"] == "glyph:demo:notes.delete:hash1"


def test_tier2_grant_consumed_exactly_once(monkeypatch, fresh_grants):
    _tier2_caps(monkeypatch)
    key = "glyph:demo:notes.delete:hash1"
    assert request_user_confirmation("s", "d", key) == "pending"

    # User approves on Telegram → Hermes fires the post_approval_response hook.
    on_post_approval_response(pattern_keys=[key], choice="once", telemetry_schema_version=3)

    # Retry consumes the grant…
    assert request_user_confirmation("s", "d", key) == "approved"
    # …and an identical later call must re-ask (grant is gone).
    assert request_user_confirmation("s", "d", key) == "pending"


def test_tier2_deny_never_grants(monkeypatch, fresh_grants):
    _tier2_caps(monkeypatch)
    key = "glyph:demo:notes.delete:hash2"
    request_user_confirmation("s", "d", key)
    on_post_approval_response(pattern_keys=[key], choice="deny")
    assert request_user_confirmation("s", "d", key) == "pending"  # still not approved


def test_tier2_different_input_different_grant(monkeypatch, fresh_grants):
    _tier2_caps(monkeypatch)
    on_post_approval_response(pattern_keys=["glyph:demo:x:hashA"], choice="once")
    assert request_user_confirmation("s", "d", "glyph:demo:x:hashB") == "pending"


def test_hook_ignores_non_glyph_keys(fresh_grants):
    on_post_approval_response(pattern_keys=["terminal:rm_-rf"], choice="once")
    assert fresh_grants.pending_count() == 0


def test_grant_expires(monkeypatch, fresh_grants):
    fresh_grants.ttl_seconds = -1  # already expired when granted
    fresh_grants.grant("glyph:demo:x:h")
    assert fresh_grants.consume("glyph:demo:x:h") is False


# ---------------------------------------------------------------------------
# Fail-closed contexts
# ---------------------------------------------------------------------------


def test_cron_context_denies(monkeypatch):
    _caps(monkeypatch, is_gateway_context=lambda: False)
    monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    assert request_user_confirmation("s", "d", "glyph:x") == "unavailable"


def test_no_capabilities_fails_closed(monkeypatch):
    _caps(monkeypatch)  # nothing available
    monkeypatch.delenv("HERMES_INTERACTIVE", raising=False)
    assert request_user_confirmation("s", "d", "glyph:x") == "unavailable"


def test_gateway_without_any_tier_fails_closed(monkeypatch):
    _caps(monkeypatch, is_gateway_context=lambda: True)
    assert request_user_confirmation("s", "d", "glyph:x") == "unavailable"


def test_cli_interactive_approval(monkeypatch):
    prompts = []

    def fake_prompt(command, description, allow_permanent=True):
        prompts.append({"command": command, "allow_permanent": allow_permanent})
        return "once"

    _caps(
        monkeypatch,
        is_gateway_context=lambda: False,
        prompt_dangerous_approval=fake_prompt,
    )
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    assert request_user_confirmation("s", "d", "glyph:x") == "approved"
    # 'always' must be hidden: every danger call is its own decision.
    assert prompts[0]["allow_permanent"] is False


def test_cli_always_choice_treated_as_approved_once(monkeypatch):
    _caps(
        monkeypatch,
        is_gateway_context=lambda: False,
        prompt_dangerous_approval=lambda *a, **k: "always",
    )
    monkeypatch.setenv("HERMES_INTERACTIVE", "1")
    # 'always' is not in the accepted set → treated as denied (we asked with
    # allow_permanent=False, so this is a defensive path).
    assert request_user_confirmation("s", "d", "glyph:x") == "denied"


# ---------------------------------------------------------------------------
# End-to-end through the bridge: gateway pending → grant → retry succeeds
# ---------------------------------------------------------------------------


def test_bridge_gateway_round_trip(server, tmp_path, monkeypatch, fresh_grants):
    _tier2_caps(monkeypatch)
    bridge = make_bridge(server, tmp_path, _hermes.request_user_confirmation)
    bridge.sync()
    bridge.trust_tool("glyph_demo_notes_delete")
    handler = bridge.make_handler("glyph_demo_notes_delete")

    first = json.loads(handler({"id": 1}))
    assert first["error"]["code"] == "CONFIRMATION_PENDING"

    key = f"glyph:demo:notes.delete:{canonical_hash({'id': 1})}"
    on_post_approval_response(pattern_keys=[key], choice="once")

    second = json.loads(handler({"id": 1}))
    assert second["ok"] is True

    third = json.loads(handler({"id": 1}))
    assert third["error"]["code"] == "CONFIRMATION_PENDING"  # one-shot, re-asks
    bridge.close()
