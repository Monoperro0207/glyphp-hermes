#!/usr/bin/env python3
"""Record the offline Sigstore fixture (runs once, in GitHub Actions).

Produces ``tests/fixtures/sigstore/`` so the SigstoreBackend accept path can
be tested deterministically in normal CI, without network or OIDC:

- ``card.json``         deterministic glyph card with a real glyph-keyless-v1
                        attestation attached (sigstore bundle inside)
- ``trusted_root.json`` the production Sigstore trusted root, pinned at
                        recording time (fed to ``TrustedRoot.from_file``)
- ``identity.json``     the exact issuer/identity the certificate carries,
                        for the verification policy in tests

The card is deterministic (fixed ed25519 seed, fixed timestamps) so the
recorded bundle stays bound to the same card id forever. Before writing
anything, the script re-verifies the whole fixture OFFLINE through
KeylessVerifier + SigstoreBackend(trusted_root=...) — a fixture that does
not verify is never written.

Keyless signing needs an ambient OIDC credential, so this only runs inside
GitHub Actions (the attestation-e2e workflow records and commits the fixture
automatically when it is missing).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyph_protocol import canonical_hash

from glyphp_hermes.attestation import KeylessVerifier, SigstoreBackend

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "sigstore"

# Fixture-only key: determinism matters here, secrecy does not.
_SEED = hashlib.sha256(b"glyphp-hermes sigstore fixture v1").digest()


def build_fixture_card() -> dict:
    priv = Ed25519PrivateKey.from_private_bytes(_SEED)
    base = {
        "version": "1.0.0",
        "name": "fixture.probe",
        "intent": "offline sigstore fixture",
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


def keyless_sign(message: bytes) -> tuple[str, str, str]:
    """Keyless-sign *message* with the runner's ambient OIDC credential.

    Returns ``(bundle_json, issuer, identity)``. ``identity`` is the
    certificate SAN (for GitHub Actions, the workflow-ref URI) — the value
    verification policies actually match, NOT the JWT ``sub`` claim.
    """
    from sigstore.models import ClientTrustConfig
    from sigstore.oidc import IdentityToken, detect_credential
    from sigstore.sign import SigningContext

    raw = detect_credential()
    if raw is None:
        raise RuntimeError("no ambient OIDC credential — must run inside GitHub Actions")
    token = IdentityToken(raw)
    ctx = SigningContext.from_trust_config(ClientTrustConfig.production())
    with ctx.signer(token) as signer:
        bundle = signer.sign_artifact(message)
    # The identity that verification policies match is the certificate SAN
    # (for GitHub Actions, the workflow-ref URI) — read it from the minted
    # cert itself rather than guessing from token claims.
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    san = bundle.signing_certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value
    identity = san.get_values_for_type(x509.UniformResourceIdentifier)[0]
    return bundle.to_json(), token.federated_issuer, identity


def fetch_trusted_root_json() -> str:
    from sigstore.models import ClientTrustConfig

    root = ClientTrustConfig.production().trusted_root
    return root._inner.to_json()  # noqa: SLF001 — only serialization hook exposed


def main() -> int:
    card = build_fixture_card()
    print(f"fixture card id: {card['id']}")

    try:
        bundle_json, issuer, identity = keyless_sign(card["id"].encode("ascii"))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
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

    trusted_root_json = fetch_trusted_root_json()

    # Self-check: the fixture must verify OFFLINE (pinned root) before it
    # is allowed to exist.
    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    root_path = FIXTURE_DIR / "trusted_root.json"
    root_path.write_text(trusted_root_json)
    verifier = KeylessVerifier(
        issuers=[issuer],
        identities=[identity],
        backend=SigstoreBackend(trusted_root=root_path),
    )
    outcome = verifier.verify(card)
    print(f"offline verify: valid={outcome.valid} trusted={outcome.trusted} error={outcome.error}")
    if not (outcome.valid and outcome.trusted):
        root_path.unlink()
        print("FAIL: fixture does not verify offline — not writing it", file=sys.stderr)
        return 1

    (FIXTURE_DIR / "card.json").write_text(json.dumps(card, indent=2) + "\n")
    (FIXTURE_DIR / "identity.json").write_text(
        json.dumps({"issuer": issuer, "identity": identity}, indent=2) + "\n"
    )
    print(f"fixture recorded in {FIXTURE_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
