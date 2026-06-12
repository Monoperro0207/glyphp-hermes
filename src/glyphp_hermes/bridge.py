"""ServerBridge — turns one Glyph server's lexicon into gated Hermes tools.

The bridge owns the full per-call trust chain inside the tool handler itself
(so it applies identically under CLI, gateway, and direct registry dispatch):

    trust state → (confirmation gate) → call → receipt verification → audit log

No Hermes imports: the confirmation seam is an injected callable, so the
bridge is fully testable (and demo-able) outside a Hermes process.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import httpx

from glyph_protocol import Client, FilePinStore, canonical_hash

from .attestation import AttestationVerifierRegistry, default_registry, enforce_policy
from .audit import ReceiptAuditLog, check_envelope
from .config import ServerConfig
from .errors import parse_glyph_error, tool_error
from .trust import TrustDecision, TrustManager

logger = logging.getLogger("glyphp_hermes.bridge")

# Confirmer outcome → how the handler proceeds.
# 'approved'    → prepare + call with token
# 'denied'      → USER_DENIED (model must not retry)
# 'pending'     → CONFIRMATION_PENDING (gateway async: retry after user approves)
# 'timeout'     → CONFIRMATION_TIMEOUT
# 'unavailable' → CONFIRMATION_UNAVAILABLE (fail closed)
Confirmer = Callable[[str, str, str], str]

_TOOL_NAME_MAX = 64


def sanitize_tool_name(alias: str, glyph_name: str) -> str:
    safe_alias = re.sub(r"[^a-zA-Z0-9_]", "_", alias)
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", glyph_name)
    return f"glyph_{safe_alias}_{safe}"[:_TOOL_NAME_MAX]


def assign_tool_names(alias: str, glyph_names: list[str]) -> dict[str, str]:
    """Map glyph name → unique sanitized tool name for one lexicon.

    Sanitization is lossy (``a-b`` and ``a.b`` both become ``a_b``; long
    names truncate), so two glyphs can collide and one would silently shadow
    the other — the model would see one schema and execute another tool.
    When a collision is detected, EVERY member of the colliding group gets a
    stable suffix derived from its original glyph name, so the result does
    not depend on lexicon order. Non-colliding names are unchanged.
    """
    plain: dict[str, list[str]] = {}
    for glyph_name in glyph_names:
        plain.setdefault(sanitize_tool_name(alias, glyph_name), []).append(glyph_name)

    out: dict[str, str] = {}
    for tool_name, members in plain.items():
        if len(members) == 1:
            out[members[0]] = tool_name
            continue
        logger.warning(
            "[%s] glyphs %s sanitize to the same tool name %r; disambiguating with suffixes",
            alias, members, tool_name,
        )
        for glyph_name in members:
            suffix = "_" + hashlib.sha256(glyph_name.encode("utf-8")).hexdigest()[:8]
            base = sanitize_tool_name(alias, glyph_name)[: _TOOL_NAME_MAX - len(suffix)]
            out[glyph_name] = base + suffix
    return out


def card_to_schema(tool_name: str, alias: str, card: dict) -> dict:
    cost = card.get("cost") or {}
    bits = [f"risk: {cost.get('riskTier', 'unknown')}"]
    if cost.get("requiresConfirmation"):
        bits.append("requires user confirmation")
    if cost.get("sideEffects"):
        bits.append("has side effects")
    description = f"[glyph:{alias}] {card.get('intent', '')} ({', '.join(bits)})"
    return {
        "name": tool_name,
        "description": description,
        "parameters": card.get("input") or {"type": "object"},
    }


@dataclass
class ToolBinding:
    tool_name: str
    glyph_name: str
    alias: str
    card: dict
    decision: TrustDecision
    blocked_code: str = ""  # '' when callable; else TRUST_REQUIRED / CARD_* / ATTESTATION_*
    blocked_reason: str = ""

    @property
    def allowed(self) -> bool:
        return not self.blocked_code

    @property
    def requires_confirmation(self) -> bool:
        return bool((self.card.get("cost") or {}).get("requiresConfirmation"))


@dataclass
class SyncReport:
    ok: bool
    alias: str
    bindings: list[ToolBinding] = field(default_factory=list)
    error: str = ""

    def summary(self) -> str:
        if not self.ok:
            return f"[{self.alias}] sync FAILED: {self.error}"
        allowed = sum(1 for b in self.bindings if b.allowed)
        blocked = len(self.bindings) - allowed
        return f"[{self.alias}] {len(self.bindings)} tools ({allowed} callable, {blocked} blocked)"


_STATUS_TO_CODE = {
    "new": "TRUST_REQUIRED",
    "changed": "CARD_CHANGED",
    "revoked": "CARD_REVOKED",
    "invalid": "CARD_INVALID",
}


class ServerBridge:
    def __init__(
        self,
        cfg: ServerConfig,
        *,
        trust: TrustManager,
        audit: ReceiptAuditLog,
        confirmer: Confirmer,
        attestation_registry: Optional[AttestationVerifierRegistry] = None,
    ) -> None:
        self.cfg = cfg
        self.trust = trust
        self.audit = audit
        self.confirmer = confirmer
        self.attestation_registry = attestation_registry or default_registry(
            issuers=cfg.attestation.issuers, identities=cfg.attestation.identities
        )
        self.client = Client(
            cfg.url,
            auth_token=cfg.auth_token(),
            timeout_seconds=cfg.timeout_seconds,
        )
        self.bindings: dict[str, ToolBinding] = {}  # tool_name → binding
        self.last_report: Optional[SyncReport] = None

    @classmethod
    def from_config(cls, cfg: ServerConfig, confirmer: Confirmer) -> "ServerBridge":
        cfg.pin_path().parent.mkdir(parents=True, exist_ok=True)
        trust = TrustManager(
            cfg.alias,
            FilePinStore(str(cfg.pin_path())),
            cfg.tofu,
            auto_repin_review=cfg.auto_repin_review,
            pending_path=cfg.pending_path(),
        )
        return cls(
            cfg,
            trust=trust,
            audit=ReceiptAuditLog(cfg.audit_path()),
            confirmer=confirmer,
        )

    def close(self) -> None:
        self.client.close()

    # ---- sync ----------------------------------------------------------------

    def sync(self) -> SyncReport:
        try:
            handshake = self.client.handshake(consumer_id="hermes-glyph-plugin")
            lexicon = handshake.get("lexicon") or []
        except (httpx.HTTPError, OSError) as exc:
            report = SyncReport(ok=False, alias=self.cfg.alias, error=str(exc))
            self.last_report = report
            return report

        names = assign_tool_names(self.cfg.alias, [e.get("name", "") for e in lexicon])
        bindings: dict[str, ToolBinding] = {}
        for entry in lexicon:
            glyph_name = entry.get("name", "")
            tool_name = names[glyph_name]
            try:
                card = self.client.get_card(glyph_name, depth="rich")
            except (httpx.HTTPError, OSError) as exc:
                logger.warning("[%s] could not fetch card %s: %s", self.cfg.alias, glyph_name, exc)
                continue

            decision = self.trust.evaluate(card)
            blocked_code = "" if decision.allowed else _STATUS_TO_CODE.get(decision.status, "TRUST_REQUIRED")
            blocked_reason = decision.reason if blocked_code else ""

            if not blocked_code:
                att_ok, att_code, att_result = enforce_policy(
                    card, self.cfg.attestation.require, self.attestation_registry
                )
                if not att_ok:
                    blocked_code = att_code
                    blocked_reason = (
                        att_result.error
                        if att_result and att_result.error
                        else f"attestation policy '{self.cfg.attestation.require}' not satisfied"
                    )

            bindings[tool_name] = ToolBinding(
                tool_name=tool_name,
                glyph_name=glyph_name,
                alias=self.cfg.alias,
                card=card,
                decision=decision,
                blocked_code=blocked_code,
                blocked_reason=blocked_reason,
            )

        self.bindings = bindings
        report = SyncReport(ok=True, alias=self.cfg.alias, bindings=list(bindings.values()))
        self.last_report = report
        return report

    # ---- explicit trust operations (used by /glyph and the CLI) ---------------

    def trust_tool(self, tool_name: str) -> str:
        binding = self.bindings.get(tool_name)
        if binding is None:
            return f"unknown tool {tool_name!r}"
        card = self.trust.pending_card(binding.glyph_name) or binding.card
        try:
            self.trust.approve(card)
        except ValueError as exc:
            return str(exc)
        binding.card = card
        binding.blocked_code = ""
        binding.blocked_reason = ""
        # Re-apply the attestation gate: explicit trust does not bypass policy.
        att_ok, att_code, att_result = enforce_policy(
            card, self.cfg.attestation.require, self.attestation_registry
        )
        if not att_ok:
            binding.blocked_code = att_code
            binding.blocked_reason = (
                att_result.error if att_result and att_result.error else "attestation policy"
            )
            return f"pinned, but still blocked: {att_code}"
        return f"trusted {tool_name} (card {card.get('id', '')[:12]}…)"

    def revoke_tool(self, tool_name: str, reason: str = "") -> str:
        binding = self.bindings.get(tool_name)
        if binding is None:
            return f"unknown tool {tool_name!r}"
        if not self.trust.revoke(binding.glyph_name, reason):
            return f"{tool_name} has no pin to revoke"
        binding.blocked_code = "CARD_REVOKED"
        binding.blocked_reason = reason or "revoked by operator"
        return f"revoked {tool_name}"

    # ---- the handler -----------------------------------------------------------

    def make_handler(self, tool_name: str) -> Callable[..., str]:
        """Build the Hermes tool handler for one binding.

        Looks the binding up at call time (not closure-captured) so resyncs
        and /glyph trust/revoke take effect on already-registered tools.
        """

        def handler(args: Optional[dict] = None, **_kwargs: Any) -> str:
            args = args or {}
            binding = self.bindings.get(tool_name)
            if binding is None:
                return tool_error(
                    "NOT_FOUND", f"{tool_name} is no longer bound to a glyph; run /glyph sync."
                )

            if binding.blocked_code:
                return tool_error(
                    binding.blocked_code,
                    f"{tool_name} is blocked: {binding.blocked_reason}. "
                    f"Run /glyph diff {tool_name} to inspect and /glyph trust {tool_name} to approve.",
                    tool=tool_name,
                )

            confirmation_token: Optional[str] = None
            if binding.requires_confirmation:
                outcome, token_or_error = self._confirm(binding, args)
                if outcome != "approved":
                    return token_or_error
                confirmation_token = token_or_error if token_or_error else None

            try:
                envelope = self.client.call(
                    binding.glyph_name,
                    args,
                    confirmation_token=confirmation_token,
                    call_id=str(uuid.uuid4()),
                )
            except httpx.HTTPStatusError as exc:
                parsed = parse_glyph_error(exc)
                return tool_error(parsed["code"], parsed["message"], **(
                    {"details": parsed["details"]} if "details" in parsed else {}
                ))
            except (httpx.TransportError, OSError) as exc:
                return tool_error(
                    "SERVER_UNREACHABLE", f"Glyph server {self.cfg.url} unreachable: {exc}"
                )

            return self._seal(binding, args, envelope)

        handler.__name__ = f"glyph_handler_{tool_name}"
        return handler

    def _confirm(self, binding: ToolBinding, args: dict) -> tuple[str, str]:
        """Run the confirmation gate. Returns (outcome, token | tool_error)."""
        cost = binding.card.get("cost") or {}
        input_hash = canonical_hash(args)
        approval_key = f"glyph:{binding.alias}:{binding.glyph_name}:{input_hash}"
        summary = f"glyph {binding.glyph_name} on server '{binding.alias}'"
        description = (
            f"Glyph tool call requiring confirmation\n"
            f"  tool: {binding.glyph_name} (risk {cost.get('riskTier')}, "
            f"sideEffects={cost.get('sideEffects')}, reversible={cost.get('reversible')})\n"
            f"  input: {json.dumps(args, ensure_ascii=False)[:500]}"
        )
        outcome = self.confirmer(summary, description, approval_key)

        if outcome == "approved":
            try:
                ticket = self.client.prepare(binding.glyph_name, args)
            except httpx.HTTPStatusError as exc:
                parsed = parse_glyph_error(exc)
                return "error", tool_error(parsed["code"], parsed["message"])
            except (httpx.TransportError, OSError) as exc:
                return "error", tool_error(
                    "SERVER_UNREACHABLE", f"Glyph server {self.cfg.url} unreachable: {exc}"
                )
            return "approved", str(ticket.get("confirmationToken", ""))

        if outcome == "denied":
            return outcome, tool_error(
                "USER_DENIED", f"User declined {binding.glyph_name}.", tool=binding.tool_name
            )
        if outcome == "pending":
            return outcome, tool_error(
                "CONFIRMATION_PENDING",
                f"Approval for {binding.glyph_name} was sent to the user.",
                tool=binding.tool_name,
            )
        if outcome == "timeout":
            return outcome, tool_error(
                "CONFIRMATION_TIMEOUT",
                f"No response approving {binding.glyph_name}.",
                tool=binding.tool_name,
            )
        return "unavailable", tool_error(
            "CONFIRMATION_UNAVAILABLE",
            f"{binding.glyph_name} requires confirmation but no approval channel exists here.",
            tool=binding.tool_name,
        )

    def _seal(self, binding: ToolBinding, args: dict, envelope: dict) -> str:
        pinned = self.trust.store.get(binding.glyph_name)
        pinned_card = pinned.card if pinned else binding.card
        verified = True
        checks: dict = {}
        if self.cfg.receipts.verify:
            verified, checks = check_envelope(envelope, pinned_card)

        self.audit.record(
            alias=binding.alias,
            glyph_name=binding.glyph_name,
            tool_name=binding.tool_name,
            envelope=envelope,
            verified=verified,
            checks=checks,
            input_value=args,
            pinned_public_key=pinned_card.get("publicKey"),
        )

        receipt = envelope.get("receipt") or {}
        if self.cfg.receipts.verify and not verified:
            failed = [k for k, v in checks.items() if not v]
            if self.cfg.receipts.on_failure == "block":
                return tool_error(
                    "RECEIPT_INVALID",
                    f"Receipt verification failed ({', '.join(failed)}); result withheld.",
                    tool=binding.tool_name,
                    checks=checks,
                )
            return json.dumps(
                {
                    "ok": True,
                    "result": envelope.get("payload"),
                    "warning": f"receipt verification failed ({', '.join(failed)})",
                    "receipt": {"callId": receipt.get("callId"), "verified": False},
                    "inspection": envelope.get("inspection"),
                }
            )

        return json.dumps(
            {
                "ok": True,
                "result": envelope.get("payload"),
                "receipt": {
                    "callId": receipt.get("callId"),
                    "verified": bool(verified) if self.cfg.receipts.verify else None,
                    "outputHash": receipt.get("outputHash"),
                },
                "inspection": envelope.get("inspection"),
            }
        )
