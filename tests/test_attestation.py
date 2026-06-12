"""Attestation port parity: digest, keyless binding, identity policy, gate."""
from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyphp_hermes.attestation import (
    DigestVerifier,
    KeylessVerifier,
    default_registry,
    enforce_policy,
    matches_any,
)

from .cardlab import build_card


@pytest.fixture
def priv():
    return Ed25519PrivateKey.generate()


def keyless_bundle_for(card: dict, *, issuer="https://token.actions.githubusercontent.com",
                       identity="repo:acme/tools:ref:refs/heads/main", **extra) -> dict:
    bundle = {
        "bundleVersion": "glyph-keyless-v1",
        "subjectDigest": hashlib.sha256(card["id"].encode()).hexdigest(),
        "issuer": issuer,
        "identity": identity,
        **extra,
    }
    return bundle


def attach_keyless(priv, bundle_mutator=None, **card_kwargs) -> dict:
    """Build a card whose attestation slot carries a keyless bundle bound to it.

    The attestation is part of the signed content, so we build the card twice:
    once to learn the id, then re-issue with the bundle (whose subjectDigest
    must commit to the *final* id). To keep the fixture simple we bind the
    bundle to the final card id by iterating: build with placeholder, compute
    binding, rebuild, and patch the bundle to the new id.
    """
    # Build the card with a placeholder attestation payload first.
    placeholder = {"type": "glyph-keyless-v1", "payload": ""}
    card = build_card(priv, attestation=placeholder, **card_kwargs)
    bundle = keyless_bundle_for(card)
    if bundle_mutator:
        bundle_mutator(bundle, card)
    payload = base64.b64encode(json.dumps(bundle).encode()).decode()
    # Patch attestation in place: the card id no longer matches, but the
    # KeylessVerifier only checks bundle↔id binding, which is what we want
    # to exercise. (Card signature checks are TrustManager's job.)
    card["attestation"] = {"type": "glyph-keyless-v1", "payload": payload}
    return card


# ---------------------------------------------------------------------------
# matches_any — segment-boundary identity policy (port of keyless.ts tests)
# ---------------------------------------------------------------------------


def test_matches_any_exact():
    assert matches_any("repo:acme/tools", ["repo:acme/tools"])


def test_matches_any_segment_boundary_colon():
    assert matches_any("repo:acme/tools:ref:refs/heads/main", ["repo:acme/tools"])


def test_matches_any_segment_boundary_slash():
    assert matches_any("repo:acme/tools/sub", ["repo:acme/tools"])


def test_matches_any_rejects_prefix_widening():
    assert not matches_any("repo:acme/tools-evil", ["repo:acme/tools"])
    assert not matches_any("repo:acme/toolsX", ["repo:acme/tools"])


def test_matches_any_entry_ending_in_delimiter():
    assert matches_any("repo:acme/anything", ["repo:acme/"])


def test_matches_any_empty_allow_is_unconstrained():
    assert matches_any("whatever", [])
    assert matches_any("whatever", None)


def test_matches_any_empty_entry_never_matches():
    assert not matches_any("whatever", [""])


# ---------------------------------------------------------------------------
# DigestVerifier
# ---------------------------------------------------------------------------


def test_digest_verifier_round_trip(priv):
    digest = "sha256:" + "a" * 64
    card = build_card(
        priv, attestation={"type": "container-digest", "payload": json.dumps({"digest": digest})}
    )
    result = DigestVerifier().verify(card)
    assert result.valid is True
    assert result.details == {"digest": digest}


@pytest.mark.parametrize(
    "payload,expected_error",
    [
        ("not-json", "invalid JSON payload"),
        (json.dumps({}), "payload missing digest field"),
        (json.dumps({"digest": 5}), "digest must be a string"),
        (json.dumps({"digest": "sha256:short"}), "invalid digest format"),
    ],
)
def test_digest_verifier_rejections(priv, payload, expected_error):
    card = build_card(priv, attestation={"type": "container-digest", "payload": payload})
    result = DigestVerifier().verify(card)
    assert result.valid is False
    assert expected_error in result.error


def test_digest_verifier_no_attestation(priv):
    result = DigestVerifier().verify(build_card(priv))
    assert result.valid is False and result.error == "no attestation"


# ---------------------------------------------------------------------------
# KeylessVerifier — binding + recognized/trusted split
# ---------------------------------------------------------------------------


def test_keyless_valid_but_untrusted_without_backend(priv):
    card = attach_keyless(priv)
    result = KeylessVerifier().verify(card)
    assert result.valid is True
    assert result.trusted is False  # no crypto backend → never trusted
    assert result.details["policyOk"] is True


def test_keyless_subject_digest_binding_tamper(priv):
    def reseat(bundle, card):
        bundle["subjectDigest"] = "0" * 64  # replayed onto another card

    card = attach_keyless(priv, bundle_mutator=reseat)
    result = KeylessVerifier().verify(card)
    assert result.valid is False
    assert "subject digest" in result.error


def test_keyless_malformed_payload(priv):
    card = build_card(priv, attestation={"type": "glyph-keyless-v1", "payload": "!!!notb64"})
    result = KeylessVerifier().verify(card)
    assert result.valid is False and "malformed" in result.error


def test_keyless_identity_policy_blocks_trust(priv):
    card = attach_keyless(priv)  # identity repo:acme/tools:ref:...

    class AlwaysTrustedBackend:
        def verify_bundle(self, bundle, card):
            return {"trusted": True, "error": None}

    # Policy allows a different repo: crypto passes, policy fails → untrusted.
    verifier = KeylessVerifier(identities=["repo:other/repo"], backend=AlwaysTrustedBackend())
    result = verifier.verify(card)
    assert result.valid is True
    assert result.trusted is False
    assert result.details["policyOk"] is False


def test_keyless_trusted_with_backend_and_policy(priv):
    card = attach_keyless(priv)

    class AlwaysTrustedBackend:
        def verify_bundle(self, bundle, card):
            return {"trusted": True, "error": None}

    verifier = KeylessVerifier(identities=["repo:acme/tools"], backend=AlwaysTrustedBackend())
    result = verifier.verify(card)
    assert result.trusted is True


def test_keyless_backend_failure_reported(priv):
    card = attach_keyless(priv)

    class FailingBackend:
        def verify_bundle(self, bundle, card):
            return {"trusted": False, "error": "rekor proof invalid"}

    result = KeylessVerifier(backend=FailingBackend()).verify(card)
    assert result.valid is True and result.trusted is False
    assert "rekor" in result.error


# ---------------------------------------------------------------------------
# enforce_policy — the call-path gate (none | danger | all)
# ---------------------------------------------------------------------------


def test_policy_none_gate_off(priv):
    card = build_card(priv, risk_tier="danger")
    allowed, code, _ = enforce_policy(card, "none", default_registry())
    assert allowed and code == ""


def test_policy_danger_blocks_unattested_danger_card(priv):
    card = build_card(priv, risk_tier="danger")
    allowed, code, _ = enforce_policy(card, "danger", default_registry())
    assert not allowed and code == "ATTESTATION_REQUIRED"


def test_policy_danger_ignores_safe_card(priv):
    card = build_card(priv, risk_tier="safe")
    allowed, code, _ = enforce_policy(card, "danger", default_registry())
    assert allowed


def test_policy_all_blocks_any_unattested_card(priv):
    card = build_card(priv, risk_tier="safe")
    allowed, code, _ = enforce_policy(card, "all", default_registry())
    assert not allowed and code == "ATTESTATION_REQUIRED"


def test_policy_all_allows_valid_digest_attestation(priv):
    card = build_card(
        priv,
        attestation={
            "type": "container-digest",
            "payload": json.dumps({"digest": "sha256:" + "b" * 64}),
        },
    )
    allowed, code, result = enforce_policy(card, "all", default_registry())
    assert allowed and result.valid


def test_policy_all_blocks_untrusted_keyless(priv):
    # Keyless without a crypto backend: valid but untrusted → blocked.
    card = attach_keyless(priv)
    allowed, code, result = enforce_policy(card, "all", default_registry())
    assert not allowed and code == "ATTESTATION_UNTRUSTED"
    assert result.valid is True and result.trusted is False


def test_policy_unknown_attestation_type_blocked(priv):
    card = build_card(priv, attestation={"type": "mystery-v9", "payload": "{}"})
    allowed, code, result = enforce_policy(card, "all", default_registry())
    assert not allowed and code == "ATTESTATION_UNTRUSTED"
    assert "no verifier" in result.error


def test_sigstore_backend_without_extra_fails_closed(priv):
    """Without the sigstore package the backend reports untrusted, never raises."""
    from glyphp_hermes.attestation import SigstoreBackend

    card = attach_keyless(priv)
    verifier = KeylessVerifier(backend=SigstoreBackend())
    result = verifier.verify(card)
    assert result.valid is True
    assert result.trusted is False
    # Either sigstore is not installed (error mentions the extra) or it is
    # installed and the empty envelope fails — both are fail-closed.
    assert result.error
