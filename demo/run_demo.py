#!/usr/bin/env python3
"""glyphp-hermes walkthrough — no LLM, no API keys.

Drives the plugin's real trust chain against the demo Glyph server in six
acts. Exits non-zero on any unexpected state, so it doubles as a smoke test.

  1. Start: npm install && npm run server         (in demo/)
  2. Then:  python run_demo.py [--yes]

--yes        auto-approve the confirmation act (for CI/non-interactive runs)
--keep-home  use the real HERMES_HOME instead of a temp dir
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

SERVER_URL = os.environ.get("GLYPH_DEMO_URL", "http://127.0.0.1:3100")

GREEN = "\033[32m"
RED = "\033[31m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

_failures: list[str] = []


def act(n: int, title: str) -> None:
    print(f"\n{BOLD}═══ Act {n} — {title} ═══{RESET}")


def ok(msg: str) -> None:
    print(f"  {GREEN}✔{RESET} {msg}")


def expect(condition: bool, msg: str) -> None:
    if condition:
        ok(msg)
    else:
        print(f"  {RED}✘ FAILED: {msg}{RESET}")
        _failures.append(msg)


def note(msg: str) -> None:
    print(f"  {DIM}{msg}{RESET}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--yes", action="store_true", help="auto-approve confirmations")
    parser.add_argument(
        "--home",
        default=None,
        help="persistent HERMES_HOME (use the same dir across runs to demo --tamper)",
    )
    parser.add_argument("--keep-home", action="store_true", help="use the real HERMES_HOME")
    parser.add_argument(
        "--slow", action="store_true", help="print line by line (for screen recordings)"
    )
    args = parser.parse_args()

    if args.slow:
        import time

        original_write = sys.stdout.write

        def slow_write(s: str) -> int:
            for chunk in s.splitlines(keepends=True):
                original_write(chunk)
                sys.stdout.flush()
                if chunk.endswith("\n"):
                    time.sleep(0.12)
            return len(s)

        sys.stdout.write = slow_write  # type: ignore[method-assign]

    if args.home:
        os.environ["HERMES_HOME"] = args.home
    elif not args.keep_home:
        os.environ["HERMES_HOME"] = tempfile.mkdtemp(prefix="glyph-demo-home-")

    from glyphp_hermes.audit import ReceiptAuditLog
    from glyphp_hermes.bridge import ServerBridge
    from glyphp_hermes.config import (
        AttestationPolicy,
        ServerConfig,
        TofuPolicy,
    )

    import httpx

    try:
        httpx.get(f"{SERVER_URL}/health", timeout=3).raise_for_status()
    except Exception:
        print(
            f"{RED}Demo server not reachable at {SERVER_URL}.\n"
            f"Start it first:  cd demo && npm install && npm run server{RESET}"
        )
        return 2

    decisions: list[str] = []

    def confirmer(summary: str, description: str, _key: str) -> str:
        print(f"\n  ⚠️  CONFIRMATION REQUIRED\n  {description}")
        if args.yes:
            decisions.append("approved")
            note("(--yes: auto-approved)")
            return "approved"
        answer = input("  approve? [y/N] ").strip().lower()
        outcome = "approved" if answer in {"y", "yes"} else "denied"
        decisions.append(outcome)
        return outcome

    cfg = ServerConfig(
        alias="demo",
        url=SERVER_URL,
        tofu=TofuPolicy(enabled=True, max_risk_tier="caution"),
    )
    bridge = ServerBridge.from_config(cfg, confirmer)

    # ---- Act 1 — discovery + signature verification -------------------------
    act(1, "Discovery: every card cryptographically verified")
    report = bridge.sync()
    expect(report.ok, f"handshake + sync against {SERVER_URL}")
    expect(len(report.bindings) == 4, f"4 glyphs discovered ({len(report.bindings)} found)")
    note("each card's ed25519 signature and content-addressed id were verified on ingestion;")
    note("a forged or corrupted card would have been bound as CARD_INVALID, never callable.")

    # ---- Act 2 — TOFU policy -------------------------------------------------
    act(2, "TOFU: trust-on-first-use up to 'caution', danger blocked")
    states = {b.tool_name: (b.blocked_code or "callable") for b in report.bindings}
    expect(states.get("glyph_demo_notes_list") == "callable", "notes.list (safe) auto-pinned")
    expect(states.get("glyph_demo_notes_add") in ("callable", "CARD_CHANGED"),
           "notes.add (caution) auto-pinned — or parked if you ran --tamper")
    delete_state = states.get("glyph_demo_notes_delete")
    expect(delete_state in ("TRUST_REQUIRED", "callable"),
           "notes.delete (danger) blocked until explicit trust"
           if delete_state == "TRUST_REQUIRED"
           else "notes.delete already trusted (pinned in a previous run with this --home)")
    if states.get("glyph_demo_notes_add") == "CARD_CHANGED":
        note("tamper detected! pending diff:")
        for change in (bridge.trust.pending().get("notes.add") or {}).get("diff", {}).get("changes", []):
            note(f"  [{change['severity']}] {change['field']}: "
                 f"{change['before']} → {change['after']}")

    if delete_state == "TRUST_REQUIRED":
        blocked = json.loads(bridge.make_handler("glyph_demo_notes_delete")({"id": 1}))
        expect(blocked["error"]["code"] == "TRUST_REQUIRED",
               "calling the blocked tool returns instructions, hits no network")

    # ---- Act 3 — explicit trust + per-call confirmation gate -----------------
    act(3, "Confirmation gate: prepare → human approval → single-use token")
    if states.get("glyph_demo_notes_add") == "callable":
        added = json.loads(bridge.make_handler("glyph_demo_notes_add")({"text": "demo note"}))
        expect(added.get("ok") is True, "notes.add executed (no confirmation needed)")

    note(bridge.trust_tool("glyph_demo_notes_delete"))
    result = json.loads(bridge.make_handler("glyph_demo_notes_delete")({"id": 1}))
    if decisions and decisions[-1] == "denied":
        expect(result["error"]["code"] == "USER_DENIED",
               "deny → USER_DENIED, server never called")
    else:
        expect(result.get("ok") is True,
               "approve → prepare issued a single-use token bound to this exact input")
        note("the server ALSO enforces this gate: a call without a token gets 403,")
        note("and a token replayed or used with different input gets INVALID_CONFIRMATION.")

    # ---- Act 4 — verified receipts + audit log -------------------------------
    act(4, "Receipts: signed evidence of what actually ran")
    listing = json.loads(bridge.make_handler("glyph_demo_notes_list")({}))
    expect(listing.get("ok") is True and listing["receipt"]["verified"] is True,
           "envelope receipt signature verified against pinned card + payload hash")
    audit = ReceiptAuditLog(cfg.audit_path())
    entries = audit.tail(50)
    expect(len(entries) >= 2, f"audit log has {len(entries)} JSONL entries")
    verify_report = audit.verify_all()
    expect(verify_report["bad"] == 0,
           f"offline re-verification: {verify_report['ok']}/{verify_report['total']} receipts valid")
    note(f"audit log: {cfg.audit_path()}")

    # ---- Act 5 — MITM simulation: payload swap is caught ---------------------
    act(5, "Tamper detection: a swapped payload is withheld")
    original_call = bridge.client.call

    def mitm_call(name, input, **kwargs):
        envelope = original_call(name, input, **kwargs)
        envelope["payload"] = {"notes": [{"id": 999, "text": "INJECTED"}]}
        return envelope

    bridge.client.call = mitm_call
    tampered = json.loads(bridge.make_handler("glyph_demo_notes_list")({}))
    bridge.client.call = original_call
    expect(tampered["ok"] is False and tampered["error"]["code"] == "RECEIPT_INVALID",
           "payload substituted in transit → outputHash mismatch → result withheld")
    expect(tampered.get("checks", {}).get("outputHashMatches") is False,
           "audit entry records exactly which check failed")

    # ---- Act 6 — attestation policy ------------------------------------------
    act(6, "Attestation policy: danger tools must carry supply-chain evidence")
    att_cfg = ServerConfig(
        alias="demo-attested",
        url=SERVER_URL,
        tofu=TofuPolicy(enabled=True, max_risk_tier="danger"),
        attestation=AttestationPolicy(require="danger"),
    )
    att_bridge = ServerBridge.from_config(att_cfg, confirmer)
    att_report = att_bridge.sync()
    att_states = {b.tool_name: (b.blocked_code or "callable") for b in att_report.bindings}
    expect(att_states.get("glyph_demo_attested_notes_export") == "callable",
           "notes.export (danger, container-digest attestation) passes the policy")
    expect(att_states.get("glyph_demo_attested_notes_delete") == "ATTESTATION_REQUIRED",
           "notes.delete (danger, NO attestation) blocked by policy — even if trusted")
    note("policy mirror of @glyphp/client requireAttestation: none | danger | all")

    att_bridge.close()
    bridge.close()

    print(f"\n{BOLD}{'─' * 60}{RESET}")
    if _failures:
        print(f"{RED}{BOLD}{len(_failures)} act(s) failed.{RESET}")
        return 1
    print(f"{GREEN}{BOLD}All six acts passed — the full trust chain works end to end.{RESET}")
    print("Next: install into Hermes (see hermes-walkthrough.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
