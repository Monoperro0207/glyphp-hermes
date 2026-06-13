"""Attestation port parity: digest, keyless binding, identity policy, gate."""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glyphp_hermes.attestation import (
    DigestVerifier,
    KeylessVerifier,
    SigstoreBackend,
    compute_keyless_subject_digest,
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
        "subjectDigest": compute_keyless_subject_digest(card),
        "issuer": issuer,
        "identity": identity,
        **extra,
    }
    return bundle


def attach_keyless(priv, bundle_mutator=None, **card_kwargs) -> dict:
    """Build a card carrying a keyless bundle bound to its content (RFC-0007).

    The bundle's subjectDigest commits to the **attestation-exclusive** content
    (a probe card without the attestation), and the FINAL card id includes the
    attestation — the real producer shape, where the id contains the very
    bundle that binds it. The result therefore passes both verify_glyph and the
    keyless subject binding (belt-and-suspenders, RFC-0007 §3.2).
    """
    probe = build_card(priv, **card_kwargs)  # attestation-exclusive content
    bundle = keyless_bundle_for(probe)
    if bundle_mutator:
        bundle_mutator(bundle, probe)
    payload = base64.b64encode(json.dumps(bundle).encode()).decode()
    attestation = {"type": "glyph-keyless-v1", "payload": payload}
    # Re-issue with the attestation present: the final id covers it.
    return build_card(priv, attestation=attestation, **card_kwargs)


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


def test_keyless_subject_digest_is_attestation_exclusive(priv):
    """RFC-0007 §3.1: the digest commits to the card content WITHOUT the
    attestation slot, so it is invariant to attaching the bundle. A card whose
    final id includes the attestation still verifies — the case that the old
    sha256(card.id) binding could never satisfy (fixed-point)."""
    from glyph_protocol import verify_glyph

    card = attach_keyless(priv)
    # The final id covers the attestation (real producer shape), yet the
    # bundle's subjectDigest is computed over the attestation-exclusive content.
    bundle = json.loads(base64.b64decode(card["attestation"]["payload"]))
    assert bundle["subjectDigest"] == compute_keyless_subject_digest(card)
    # Belt-and-suspenders: the same card passes the ed25519 content check too.
    assert verify_glyph(card) is True
    result = KeylessVerifier().verify(card)
    assert result.valid is True


def test_keyless_naive_id_binding_is_rejected(priv):
    """A bundle that (wrongly) commits to sha256(final card.id) — the pre-fix
    definition — must NOT verify, since the id includes the attestation."""
    import hashlib

    def naive(bundle, card):
        # `card` here is the attestation-exclusive probe; emulate the old bug by
        # binding to a digest of an id that would include the attestation.
        bundle["subjectDigest"] = hashlib.sha256(b"id-including-attestation").hexdigest()

    card = attach_keyless(priv, bundle_mutator=naive)
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
    card = attach_keyless(priv)
    verifier = KeylessVerifier(backend=SigstoreBackend())
    result = verifier.verify(card)
    assert result.valid is True
    assert result.trusted is False
    # Either sigstore is not installed (error mentions the extra) or it is
    # installed and the empty envelope fails — both are fail-closed.
    assert result.error


# ---------------------------------------------------------------------------
# SigstoreBackend — offline accept path against the recorded fixture
# (real keyless bundle + pinned trusted root, recorded by the attestation-e2e
# workflow via scripts/record_sigstore_fixture.py; no network involved here)
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "sigstore"


def _sigstore_installed() -> bool:
    try:
        import sigstore  # noqa: F401

        return True
    except ImportError:
        return False


offline_fixture = pytest.mark.skipif(
    not (FIXTURE_DIR / "card.json").exists() or not _sigstore_installed(),
    reason="offline sigstore fixture not recorded yet (attestation-e2e workflow records it) "
    "or sigstore extra not installed",
)


@pytest.fixture
def fixture_card() -> dict:
    return json.loads((FIXTURE_DIR / "card.json").read_text())


@pytest.fixture
def fixture_verifier() -> KeylessVerifier:
    ident = json.loads((FIXTURE_DIR / "identity.json").read_text())
    return KeylessVerifier(
        issuers=[ident["issuer"]],
        identities=[ident["identity"]],
        backend=SigstoreBackend(trusted_root=FIXTURE_DIR / "trusted_root.json"),
    )


@offline_fixture
def test_sigstore_offline_accept(fixture_card, fixture_verifier):
    result = fixture_verifier.verify(fixture_card)
    assert result.valid is True
    assert result.trusted is True, result.error


@offline_fixture
def test_sigstore_offline_tampered_signature_untrusted(fixture_card, fixture_verifier):
    bundle = json.loads(base64.b64decode(fixture_card["attestation"]["payload"]))
    envelope = json.loads(bundle["signingCertificate"])
    sig = bytearray(base64.b64decode(envelope["messageSignature"]["signature"]))
    sig[0] ^= 0xFF
    envelope["messageSignature"]["signature"] = base64.b64encode(bytes(sig)).decode()
    bundle["signingCertificate"] = json.dumps(envelope)
    card = dict(fixture_card)
    card["attestation"] = {
        "type": "glyph-keyless-v1",
        "payload": base64.b64encode(json.dumps(bundle).encode()).decode(),
    }
    result = fixture_verifier.verify(card)
    assert result.valid is True  # structure and card binding intact
    assert result.trusted is False  # crypto check fails


@offline_fixture
def test_sigstore_offline_replay_other_card_invalid(priv, fixture_card, fixture_verifier):
    other = build_card(priv)
    other["attestation"] = fixture_card["attestation"]
    result = fixture_verifier.verify(other)
    assert result.valid is False
    assert "subject digest" in result.error


# ---------------------------------------------------------------------------
# default_registry must ACTIVATE the sigstore extra when it is installed —
# a default bridge that always returns ATTESTATION_UNTRUSTED with a valid
# bundle would make the advertised feature unusable.
# ---------------------------------------------------------------------------

sigstore_installed = pytest.mark.skipif(
    not _sigstore_installed(), reason="sigstore extra not installed"
)


@sigstore_installed
def test_default_registry_activates_sigstore_backend():
    registry = default_registry()
    verifier = registry.get("glyph-keyless-v1")
    assert isinstance(verifier.backend, SigstoreBackend)


def test_default_registry_explicit_backend_wins():
    class Stub:
        def verify_bundle(self, bundle, card):
            return {"trusted": True, "error": None}

    stub = Stub()
    registry = default_registry(backend=stub)
    assert registry.get("glyph-keyless-v1").backend is stub


@offline_fixture
def test_default_bridge_registry_verifies_keyless_attestation(tmp_path, fixture_card, monkeypatch):
    """The attestation gate as a DEFAULT bridge runs it: build a ServerBridge
    without injecting a registry, then push the recorded fixture card through
    enforce_policy with the registry the bridge constructed itself — it must
    come back allowed, not ATTESTATION_UNTRUSTED. The trusted root is pinned
    only to keep the crypto offline; the registry/backend wiring is the
    default activation under test.

    (The trust gate is exercised separately: a glyph-keyless-v1 bundle binds
    subjectDigest to the card id, while the id canonically includes the
    attestation slot — RFC-0007's producers attach the bundle post-id, so
    such cards do not pass verify_glyph content integrity. Spec-level issue,
    tracked upstream in the protocol repo.)"""
    import glyphp_hermes.attestation as attestation_mod

    from .conftest import ScriptedConfirmer, make_bridge
    from .fake_server import FakeGlyphServer, default_glyphs
    from glyphp_hermes.config import AttestationPolicy

    monkeypatch.setattr(
        attestation_mod,
        "default_backend",
        lambda: SigstoreBackend(trusted_root=FIXTURE_DIR / "trusted_root.json"),
    )
    ident = json.loads((FIXTURE_DIR / "identity.json").read_text())

    with FakeGlyphServer(default_glyphs()) as server:
        bridge = make_bridge(
            server,
            tmp_path,
            ScriptedConfirmer(),
            attestation=AttestationPolicy(
                require="all",
                issuers=(ident["issuer"],),
                identities=(ident["identity"],),
            ),
        )
        try:
            allowed, code, result = enforce_policy(
                fixture_card, "all", bridge.attestation_registry
            )
            assert allowed, f"{code}: {result.error if result else ''}"
            assert result is not None and result.trusted is True
        finally:
            bridge.close()
