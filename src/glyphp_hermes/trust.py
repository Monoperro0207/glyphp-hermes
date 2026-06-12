"""Trust engine: card diffing, pinning, TOFU, and re-approval queue.

``diff_cards`` and ``FIELD_SEVERITY`` are a verbatim port of
``@glyphp/core`` (packages/core/src/index.ts) so a Hermes deployment reaches
the same approval decisions as the TypeScript client.

Pure Python — no Hermes imports.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Optional

from glyph_protocol import FilePinStore, MemoryPinStore, Pin, canonicalize, verify_glyph

from .config import TofuPolicy

logger = logging.getLogger("glyphp_hermes.trust")

# How each card field is treated when it changes between an approved card and
# a new one. 'breaking' fields gate execution (need human re-approval);
# 'review' fields are descriptive. Mirrors @glyphp/core FIELD_SEVERITY.
FIELD_SEVERITY: dict[str, str] = {
    "version": "breaking",
    "name": "review",
    "intent": "review",
    "tags": "review",
    "cost.latency": "review",
    "cost.sideEffects": "breaking",
    "cost.reversible": "breaking",
    "cost.riskTier": "breaking",
    "cost.requiresConfirmation": "breaking",
    "idempotent": "breaking",
    "input": "breaking",
    "output": "breaking",
    "examples": "review",
    "failureModes": "review",
    "provider": "breaking",
    "requiredScopes": "breaking",
    "publicKey": "breaking",
    "attestation": "breaking",
}

_COST_KEYS = ("latency", "sideEffects", "reversible", "riskTier", "requiresConfirmation")


def _canon_equal(a: Any, b: Any) -> bool:
    return json.dumps(canonicalize(a), separators=(",", ":")) == json.dumps(
        canonicalize(b), separators=(",", ":")
    )


def diff_cards(approved: dict, next_card: dict) -> dict:
    """Classify every difference between an approved card and a new one.

    Returns ``{changed, idChanged, keyChanged, changes: [{field, severity,
    before, after}], requiresApproval}`` — the same shape as
    ``@glyphp/core diffCards``.
    """
    changes: list[dict] = []

    def record(field: str, before: Any, after: Any) -> None:
        if not _canon_equal(before, after):
            changes.append(
                {
                    "field": field,
                    "severity": FIELD_SEVERITY.get(field, "review"),
                    "before": before,
                    "after": after,
                }
            )

    record("version", approved.get("version"), next_card.get("version"))
    record("name", approved.get("name"), next_card.get("name"))
    record("intent", approved.get("intent"), next_card.get("intent"))
    record("tags", approved.get("tags"), next_card.get("tags"))
    for key in _COST_KEYS:
        record(
            f"cost.{key}",
            (approved.get("cost") or {}).get(key),
            (next_card.get("cost") or {}).get(key),
        )
    record("idempotent", approved.get("idempotent"), next_card.get("idempotent"))
    record("input", approved.get("input"), next_card.get("input"))
    record("output", approved.get("output"), next_card.get("output"))
    record("examples", approved.get("examples"), next_card.get("examples"))
    record("failureModes", approved.get("failureModes"), next_card.get("failureModes"))
    record("provider", approved.get("provider"), next_card.get("provider"))
    record("requiredScopes", approved.get("requiredScopes"), next_card.get("requiredScopes"))
    record("publicKey", approved.get("publicKey"), next_card.get("publicKey"))
    record("attestation", approved.get("attestation"), next_card.get("attestation"))

    return {
        "changed": len(changes) > 0,
        "idChanged": approved.get("id") != next_card.get("id"),
        "keyChanged": approved.get("publicKey") != next_card.get("publicKey"),
        "changes": changes,
        "requiresApproval": any(c["severity"] == "breaking" for c in changes),
    }


TrustStatus = Literal["new", "pinned", "changed", "revoked", "invalid"]


@dataclass
class TrustDecision:
    status: TrustStatus
    allowed: bool
    reason: str
    pin: Optional[Pin] = None
    diff: Optional[dict] = None


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class TrustManager:
    """Pin lifecycle for one Glyph server's cards.

    Decisions:
      - invalid signature  → ``invalid``  (never pinned, never callable)
      - no pin + TOFU ok   → auto-pin → ``pinned``
      - no pin, above TOFU → ``new``     (registered but blocked until trust)
      - pin revoked        → ``revoked`` (blocked)
      - same id + key      → ``pinned``
      - breaking diff      → ``changed`` (blocked, queued for re-approval)
      - review-only diff   → auto re-pin if ``auto_repin_review``
    """

    def __init__(
        self,
        alias: str,
        store: FilePinStore | MemoryPinStore,
        tofu: TofuPolicy,
        *,
        auto_repin_review: bool = True,
        pending_path: Optional[Path] = None,
    ) -> None:
        self.alias = alias
        self.store = store
        self.tofu = tofu
        self.auto_repin_review = auto_repin_review
        self.pending_path = pending_path
        self._pending: dict[str, dict] = self._load_pending()

    # ---- persistence of the re-approval queue ------------------------------

    def _load_pending(self) -> dict[str, dict]:
        if self.pending_path and self.pending_path.exists():
            try:
                return json.loads(self.pending_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                logger.warning("could not read pending queue at %s", self.pending_path)
        return {}

    def _save_pending(self) -> None:
        if not self.pending_path:
            return
        self.pending_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.pending_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._pending, indent=2), encoding="utf-8")
        tmp.replace(self.pending_path)

    # ---- core decision ------------------------------------------------------

    def evaluate(self, card: dict) -> TrustDecision:
        name = card.get("name", "")
        if not verify_glyph(card):
            return TrustDecision(
                status="invalid",
                allowed=False,
                reason="card signature or content hash does not verify",
            )

        pin = self.store.get(name)
        if pin is None:
            tier = (card.get("cost") or {}).get("riskTier", "danger")
            if self.tofu.allows(tier):
                pin = self._pin(card)
                return TrustDecision(
                    status="pinned",
                    allowed=True,
                    reason=f"TOFU auto-pinned (riskTier {tier} <= {self.tofu.max_risk_tier})",
                    pin=pin,
                )
            return TrustDecision(
                status="new",
                allowed=False,
                reason=f"never-seen card above TOFU tier ({tier}); needs explicit trust",
            )

        if pin.revoked_at:
            return TrustDecision(
                status="revoked",
                allowed=False,
                reason=pin.revoke_reason or "pin revoked",
                pin=pin,
            )

        if pin.card.get("id") == card.get("id") and pin.card.get("publicKey") == card.get(
            "publicKey"
        ):
            self._pending.pop(name, None)
            self._save_pending()
            return TrustDecision(status="pinned", allowed=True, reason="matches pin", pin=pin)

        diff = diff_cards(pin.card, card)
        if diff["requiresApproval"]:
            self._pending[name] = {
                "card": card,
                "diff": diff,
                "parkedAt": _now_iso(),
            }
            self._save_pending()
            return TrustDecision(
                status="changed",
                allowed=False,
                reason="breaking change since approval; needs re-approval",
                pin=pin,
                diff=diff,
            )

        if self.auto_repin_review:
            pin = self._pin(card)
            return TrustDecision(
                status="pinned",
                allowed=True,
                reason="review-only change auto re-pinned",
                pin=pin,
                diff=diff,
            )

        self._pending[name] = {"card": card, "diff": diff, "parkedAt": _now_iso()}
        self._save_pending()
        return TrustDecision(
            status="changed",
            allowed=False,
            reason="card changed (review-only) and auto_repin_review is off",
            pin=pin,
            diff=diff,
        )

    # ---- explicit operations -------------------------------------------------

    def _pin(self, card: dict) -> Pin:
        pin = Pin(tool_name=card.get("name", ""), approved_at=_now_iso(), card=card)
        self.store.put(pin)
        return pin

    def approve(self, card: dict) -> Pin:
        """Pin a card now (explicit human approval) and clear its pending entry."""
        if not verify_glyph(card):
            raise ValueError("refusing to approve a card whose signature does not verify")
        pin = self._pin(card)
        self._pending.pop(card.get("name", ""), None)
        self._save_pending()
        return pin

    def revoke(self, tool_name: str, reason: str = "") -> bool:
        pin = self.store.get(tool_name)
        if pin is None:
            return False
        pin.revoked_at = _now_iso()
        pin.revoke_reason = reason or "revoked by operator"
        self.store.put(pin)
        self._pending.pop(tool_name, None)
        self._save_pending()
        return True

    def pending(self) -> dict[str, dict]:
        return dict(self._pending)

    def pending_card(self, glyph_name: str) -> Optional[dict]:
        entry = self._pending.get(glyph_name)
        return entry["card"] if entry else None

    def status(self) -> list[dict]:
        rows = []
        for pin in self.store.all():
            rows.append(
                {
                    "tool": pin.tool_name,
                    "approvedAt": pin.approved_at,
                    "revoked": bool(pin.revoked_at),
                    "riskTier": (pin.card.get("cost") or {}).get("riskTier"),
                    "cardId": pin.card.get("id"),
                }
            )
        return rows
