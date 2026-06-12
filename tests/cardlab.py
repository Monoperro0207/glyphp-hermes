"""Shared fixture helpers: build genuinely signed Glyph cards and receipts.

Mirrors the construction in the Glyph Python SDK's own test suite
(sdks/python/tests/test_verify.py): the card id is the canonical hash of the
base fields, and the ed25519 signature is over the ASCII hex id.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import canonical_hash


def hex_pub(priv: Ed25519PrivateKey) -> str:
    return (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def sign(priv: Ed25519PrivateKey, message: str) -> str:
    return priv.sign(message.encode("ascii")).hex()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_card(
    priv: Ed25519PrivateKey,
    *,
    name: str = "echo",
    intent: str = "Echoes its input",
    risk_tier: str = "safe",
    requires_confirmation: bool = False,
    side_effects: bool = False,
    input_schema: Optional[dict] = None,
    output_schema: Optional[dict] = None,
    attestation: Optional[dict] = None,
    provider: str = "test",
    **overrides: Any,
) -> dict:
    base: dict[str, Any] = {
        "version": "1.0.0",
        "name": name,
        "intent": intent,
        "tags": [],
        "cost": {
            "latency": "fast",
            "sideEffects": side_effects,
            "reversible": not side_effects,
            "riskTier": risk_tier,
            "requiresConfirmation": requires_confirmation,
        },
        "idempotent": not side_effects,
        "input": input_schema or {"type": "object"},
        "output": output_schema or {"type": "object"},
        "examples": [],
        "failureModes": [],
        "provider": provider,
    }
    if attestation is not None:
        base["attestation"] = attestation
    base.update(overrides)
    glyph_id = canonical_hash(base)
    return {
        **base,
        "id": glyph_id,
        "publicKey": hex_pub(priv),
        "signature": sign(priv, glyph_id),
        "createdAt": now_iso(),
    }


def build_receipt(
    priv: Ed25519PrivateKey,
    *,
    glyph_id: str,
    glyph_name: str,
    input_hash: str,
    output_hash: str,
    client_call_id: Optional[str] = None,
    risk_tier: str = "safe",
    provider: str = "test",
) -> dict:
    base: dict[str, Any] = {
        "receiptVersion": "0.3",
        "callId": str(uuid.uuid4()),
        "glyphId": glyph_id,
        "glyphName": glyph_name,
        "inputHash": input_hash,
        "outputHash": output_hash,
        "inspectionHash": canonical_hash({"modified": False, "findings": []}),
        "riskTier": risk_tier,
        "provider": provider,
        "latencyMs": 1,
        "timestamp": now_iso(),
        "serverPublicKey": hex_pub(priv),
    }
    if client_call_id:
        base["clientCallId"] = client_call_id
    return {**base, "signature": sign(priv, canonical_hash(base))}
