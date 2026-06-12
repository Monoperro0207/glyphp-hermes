#!/usr/bin/env python3
"""Live Sigstore e2e for the attestation backend (runs in GitHub Actions).

1. Builds a signed demo glyph card.
2. Signs the card id keyless via Fulcio using the runner's ambient OIDC token.
3. Wraps the resulting sigstore bundle in a glyph-keyless-v1 attestation
   bound to the card (subjectDigest).
4. Verifies it end-to-end through KeylessVerifier + SigstoreBackend against
   the live transparency log — must come back trusted=True.
5. Negative control: the same bundle replayed onto a different card must be
   rejected on the subject-digest binding.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import canonical_hash

from glyphp_hermes.attestation import KeylessVerifier, SigstoreBackend


def build_card(name: str) -> dict:
    priv = Ed25519PrivateKey.generate()
    base = {
        "version": "1.0.0",
        "name": name,
        "intent": "attestation e2e probe",
        "tags": [],
        "cost": {
            "latency": "fast",
            "sideEffects": False,
            "reversible": True,
            "riskTier": "danger",
            "requiresConfirmation": False,
        },
        "idempotent": True,
        "input": {"type": "object"},
        "output": {"type": "object"},
        "examples": [],
        "failureModes": [],
        "provider": "glyphp-hermes-ci",
    }
    glyph_id = canonical_hash(base)
    pub = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        .hex()
    )
    return {
        **base,
        "id": glyph_id,
        "publicKey": pub,
        "signature": priv.sign(glyph_id.encode("ascii")).hex(),
        "createdAt": "2026-01-01T00:00:00.000Z",
    }


def main() -> int:
    from sigstore.oidc import detect_credential
    from sigstore.sign import SigningContext

    card = build_card("e2e.probe")

    token = detect_credential()
    if token is None:
        print("no ambient OIDC credential — must run inside GitHub Actions", file=sys.stderr)
        return 2

    ctx = SigningContext.production()
    with ctx.signer(token) as signer:
        result = signer.sign_artifact(card["id"].encode("ascii"))
    bundle_json = result.to_json()

    # The signing identity GitHub mints for this workflow.
    identity = json.loads(base64.b64decode(token.split(".")[1] + "==")).get("sub", "")
    issuer = "https://token.actions.githubusercontent.com"
    print(f"signed as identity: {identity}")

    keyless_bundle = {
        "bundleVersion": "glyph-keyless-v1",
        "subjectDigest": hashlib.sha256(card["id"].encode()).hexdigest(),
        "issuer": issuer,
        "identity": identity,
        "signingCertificate": bundle_json,
    }
    card["attestation"] = {
        "type": "glyph-keyless-v1",
        "payload": base64.b64encode(json.dumps(keyless_bundle).encode()).decode(),
    }

    verifier = KeylessVerifier(
        issuers=[issuer],
        identities=[identity],
        backend=SigstoreBackend(),
    )
    outcome = verifier.verify(card)
    print(f"verify: valid={outcome.valid} trusted={outcome.trusted} error={outcome.error}")
    if not (outcome.valid and outcome.trusted):
        print("FAIL: live keyless verification did not come back trusted", file=sys.stderr)
        return 1

    # Negative control: replay onto another card → must fail the binding.
    other = build_card("e2e.other")
    other["attestation"] = card["attestation"]
    replay = verifier.verify(other)
    if replay.valid:
        print("FAIL: replayed bundle was accepted on a different card", file=sys.stderr)
        return 1
    print("replay onto another card correctly rejected (subject digest binding)")

    print("attestation e2e: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
