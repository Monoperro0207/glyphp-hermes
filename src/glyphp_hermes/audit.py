"""Receipt audit log: append-only JSONL evidence of every glyph call.

Each line records the signed receipt plus the verification verdict computed
at call time, so an operator (or ``hermes glyph audit --verify``) can re-check
the whole history offline. Pure Python — no Hermes imports.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from glyph_protocol import canonical_hash, verify_receipt


def check_envelope(envelope: dict, pinned_card: Optional[dict]) -> tuple[bool, dict]:
    """Verify a SealedEnvelope against the pinned card.

    Five checks, mirroring GlyphClient.verifyReceipt in the official TS
    client (packages/client/src/index.ts):
      1. the receipt is signed by the PINNED key — not whatever key the
         receipt itself names (a self-chosen key proves nothing),
      2. the receipt signature verifies under that key,
      3. the receipt is bound to the card we approved (glyphId == pin id),
      4. the receipt's outputHash matches the payload we actually received,
      5. the receipt's inspectionHash matches the inspection we received.
    """
    receipt = envelope.get("receipt") or {}
    inspection = envelope.get("inspection")
    checks = {
        "keyMatchesPin": pinned_card is not None
        and bool(receipt.get("serverPublicKey"))
        and receipt.get("serverPublicKey") == pinned_card.get("publicKey"),
        "signature": bool(receipt) and verify_receipt(receipt),
        "glyphIdMatchesPin": pinned_card is not None
        and receipt.get("glyphId") == pinned_card.get("id"),
        "outputHashMatches": receipt.get("outputHash")
        == canonical_hash(envelope.get("payload")),
        "inspectionHashMatches": receipt.get("inspectionHash")
        == canonical_hash(inspection if inspection is not None else {}),
    }
    return all(checks.values()), checks


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ReceiptAuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def record(
        self,
        *,
        alias: str,
        glyph_name: str,
        tool_name: str,
        envelope: dict,
        verified: bool,
        checks: dict,
        input_value: Any,
        pinned_public_key: Optional[str] = None,
    ) -> dict:
        receipt = envelope.get("receipt") or {}
        entry = {
            "ts": _now_iso(),
            "alias": alias,
            "glyphName": glyph_name,
            "toolName": tool_name,
            "callId": receipt.get("callId"),
            "verified": verified,
            "checks": checks,
            "inputHash": canonical_hash(input_value),
            "inspection": envelope.get("inspection"),
            # The key we trusted at call time — verify_all() re-checks the
            # receipt against THIS, not against the receipt's own key.
            "pinnedPublicKey": pinned_public_key,
            "receipt": receipt,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Single write of one line: atomic enough for an append-only log
        # (POSIX appends of one buffered write do not interleave).
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return entry

    def tail(self, n: int = 20) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def verify_all(self) -> dict:
        """Re-run receipt verification over the entire log.

        A receipt only counts as ok when it is signed by the key that was
        pinned at call time (recorded per entry) — a receipt that verifies
        under some other self-chosen key is a forgery, not evidence.
        """
        total = ok = bad = unparseable = 0
        failures: list[dict] = []
        if not self.path.exists():
            return {"total": 0, "ok": 0, "bad": 0, "unparseable": 0, "failures": []}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            total += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                unparseable += 1
                continue
            receipt = entry.get("receipt") or {}
            pinned_key = entry.get("pinnedPublicKey")
            key_ok = bool(pinned_key) and receipt.get("serverPublicKey") == pinned_key
            if receipt and key_ok and verify_receipt(receipt):
                ok += 1
            else:
                bad += 1
                failures.append(
                    {"callId": entry.get("callId"), "ts": entry.get("ts"),
                     "glyphName": entry.get("glyphName")}
                )
        return {
            "total": total,
            "ok": ok,
            "bad": bad,
            "unparseable": unparseable,
            "failures": failures,
        }
