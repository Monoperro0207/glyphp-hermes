"""Attestation verification — Python port of @glyphp/core attestation + keyless.

Faithful port of ``packages/core/src/attestation.ts`` (AttestationResult,
verifier registry, DigestVerifier) and ``packages/core/src/keyless.ts``
(KeylessVerifier for RFC-0007 ``glyph-keyless-v1`` bundles), preserving the
recognized/trusted split: a bundle can be structurally *valid* (well-formed
and bound to the card) without being *trusted* (cryptographic cert/log check
plus identity policy).

The cryptographic half of keyless verification is delegated to a pluggable
backend. ``SigstoreBackend`` (optional, ``pip install glyphp-hermes[sigstore]``)
uses the official ``sigstore`` package; without a backend the attestation is
never marked trusted — structural recognition without false confidence.

Pure Python; the only optional import is ``sigstore`` and it is lazy.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

KEYLESS_TYPE = "glyph-keyless-v1"
DIGEST_TYPE = "container-digest"

_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")

SEGMENT_DELIMITERS = {":", "/"}


@dataclass
class AttestationResult:
    valid: bool
    type: str
    trusted: Optional[bool] = None
    details: dict = field(default_factory=dict)
    error: Optional[str] = None


class AttestationVerifier(Protocol):
    type: str

    def verify(self, card: dict) -> AttestationResult: ...


class AttestationVerifierRegistry:
    def __init__(self) -> None:
        self._verifiers: dict[str, AttestationVerifier] = {}

    def register(self, verifier: AttestationVerifier) -> None:
        self._verifiers[verifier.type] = verifier

    def get(self, type_: str) -> Optional[AttestationVerifier]:
        return self._verifiers.get(type_)

    def list(self) -> list[str]:
        return list(self._verifiers.keys())


# ---------------------------------------------------------------------------
# DigestVerifier — validates container image sha256 digests
# ---------------------------------------------------------------------------


class DigestVerifier:
    type = DIGEST_TYPE

    def verify(self, card: dict) -> AttestationResult:
        attestation = card.get("attestation")
        if not attestation:
            return AttestationResult(valid=False, type=self.type, error="no attestation")
        try:
            parsed = json.loads(attestation.get("payload", ""))
        except (json.JSONDecodeError, TypeError):
            return AttestationResult(valid=False, type=self.type, error="invalid JSON payload")
        if not isinstance(parsed, dict) or "digest" not in parsed:
            return AttestationResult(
                valid=False, type=self.type, error="payload missing digest field"
            )
        digest = parsed["digest"]
        if not isinstance(digest, str):
            return AttestationResult(valid=False, type=self.type, error="digest must be a string")
        if not _DIGEST_RE.match(digest):
            return AttestationResult(
                valid=False,
                type=self.type,
                error=f'invalid digest format: expected sha256:<64 hex chars>, got "{digest}"',
            )
        return AttestationResult(valid=True, type=self.type, details={"digest": digest})


# ---------------------------------------------------------------------------
# Keyless (RFC-0007) — structural verification + pluggable crypto backend
# ---------------------------------------------------------------------------


def matches_any(value: str, allow: tuple[str, ...] | list[str] | None) -> bool:
    """Exact match, or a prefix that ends at a segment boundary (``:`` / ``/``).

    Port of @glyphp/core keyless.ts ``matchesAny``: a bare prefix must not
    widen authorization — ``repo:acme/tools`` matches itself and
    ``repo:acme/tools:ref:...`` but never ``repo:acme/tools-evil``.
    Empty/None allow-list ⇒ unconstrained.
    """
    if not allow:
        return True
    for entry in allow:
        if value == entry:
            return True
        if not entry or not value.startswith(entry):
            continue
        if entry[-1] in SEGMENT_DELIMITERS or value[len(entry)] in SEGMENT_DELIMITERS:
            return True
    return False


class KeylessBackend(Protocol):
    """Cryptographic half of keyless verification (cert chain + log proof)."""

    def verify_bundle(self, bundle: dict, card: dict) -> dict: ...
    # returns {"trusted": bool, "error": str | None}


class KeylessVerifier:
    """Verifies ``glyph-keyless-v1`` attestations (RFC-0007).

    Performs the dependency-free parts — bundle parsing, the subject-digest
    binding (so a bundle cannot be replayed onto another card), and identity
    policy matching — and delegates the certificate/transparency-log check to
    an injected backend. Without a backend the attestation is ``valid`` but
    ``trusted=False``.
    """

    type = KEYLESS_TYPE

    def __init__(
        self,
        *,
        issuers: tuple[str, ...] | list[str] | None = None,
        identities: tuple[str, ...] | list[str] | None = None,
        backend: Optional[KeylessBackend] = None,
    ) -> None:
        self.issuers = tuple(issuers or ())
        self.identities = tuple(identities or ())
        self.backend = backend

    def verify(self, card: dict) -> AttestationResult:
        attestation = card.get("attestation")
        if not attestation or attestation.get("type") != KEYLESS_TYPE:
            return AttestationResult(
                valid=False, type=self.type, error="not a glyph-keyless-v1 attestation"
            )

        try:
            raw = base64.b64decode(attestation.get("payload", ""), validate=True)
            bundle = json.loads(raw.decode("utf-8"))
        except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return AttestationResult(valid=False, type=self.type, error="malformed keyless bundle")

        if (
            not isinstance(bundle, dict)
            or bundle.get("bundleVersion") != KEYLESS_TYPE
            or not isinstance(bundle.get("subjectDigest"), str)
        ):
            return AttestationResult(
                valid=False, type=self.type, error="unsupported or incomplete bundle"
            )

        # Subject binding — the bundle must commit to THIS card's id (§4.2.1).
        expected = hashlib.sha256(str(card.get("id", "")).encode("utf-8")).hexdigest()
        if bundle["subjectDigest"] != expected:
            return AttestationResult(
                valid=False, type=self.type, error="subject digest does not match card id"
            )

        issuer = str(bundle.get("issuer", ""))
        identity = str(bundle.get("identity", ""))
        policy_ok = matches_any(issuer, self.issuers) and matches_any(identity, self.identities)

        crypto_trusted = False
        backend_error: Optional[str] = None
        if self.backend is not None:
            outcome = self.backend.verify_bundle(bundle, card)
            crypto_trusted = bool(outcome.get("trusted"))
            backend_error = outcome.get("error")

        return AttestationResult(
            valid=True,
            type=self.type,
            trusted=crypto_trusted and policy_ok,
            details={"issuer": issuer, "identity": identity, "policyOk": policy_ok},
            error=backend_error,
        )


# ---------------------------------------------------------------------------
# Optional Sigstore backend (extra: glyphp-hermes[sigstore])
# ---------------------------------------------------------------------------


class SigstoreBackend:
    """Verifies the keyless bundle's Sigstore envelope (Fulcio cert chain +
    Rekor transparency log) using the official ``sigstore`` package.

    Expects the RFC-0007 bundle to carry the Sigstore bundle JSON in
    ``signingCertificate`` (a serialized sigstore bundle, as produced by
    ``sigstore sign --bundle``). The signed subject must be the card id
    (the same message the glyph signature covers).

    ``trusted_root`` (optional) pins a Sigstore trusted root for fully
    offline verification — the technique sigstore-python's own tests use.
    """

    def __init__(self, *, trusted_root: Optional[Any] = None, offline: bool = False) -> None:
        self._trusted_root = trusted_root
        self._offline = offline

    def verify_bundle(self, bundle: dict, card: dict) -> dict:
        try:
            from sigstore.models import Bundle
            from sigstore.verify import Verifier
            from sigstore.verify.policy import AnyOf, OIDCIssuer, Identity
        except ImportError:
            return {
                "trusted": False,
                "error": "sigstore extra not installed (pip install glyphp-hermes[sigstore])",
            }

        raw = bundle.get("signingCertificate")
        if not raw:
            return {"trusted": False, "error": "bundle carries no sigstore envelope"}

        try:
            sig_bundle = Bundle.from_json(raw if isinstance(raw, str) else json.dumps(raw))
        except Exception as exc:  # noqa: BLE001 — sigstore raises many types
            return {"trusted": False, "error": f"unparseable sigstore bundle: {exc}"}

        try:
            if self._trusted_root is not None:
                from sigstore._internal.trust import TrustedRoot  # noqa: PLC2701

                root = self._trusted_root
                if not isinstance(root, TrustedRoot):
                    root = TrustedRoot.from_file(str(root), offline=self._offline)
                verifier = Verifier(trusted_root=root)
            else:
                verifier = Verifier.production()

            identity = bundle.get("identity", "")
            issuer = bundle.get("issuer", "")
            policy = AnyOf([Identity(identity=identity, issuer=issuer)]) if identity else AnyOf(
                [OIDCIssuer(issuer)]
            )
            subject = str(card.get("id", "")).encode("ascii")
            verifier.verify_artifact(subject, sig_bundle, policy)
            return {"trusted": True, "error": None}
        except Exception as exc:  # noqa: BLE001 — verification failures are data
            return {"trusted": False, "error": f"sigstore verification failed: {exc}"}


# ---------------------------------------------------------------------------
# Policy enforcement (mirror of @glyphp/client requireAttestation)
# ---------------------------------------------------------------------------


def default_registry(
    *,
    issuers: tuple[str, ...] | list[str] | None = None,
    identities: tuple[str, ...] | list[str] | None = None,
    backend: Optional[KeylessBackend] = None,
) -> AttestationVerifierRegistry:
    registry = AttestationVerifierRegistry()
    registry.register(DigestVerifier())
    registry.register(KeylessVerifier(issuers=issuers, identities=identities, backend=backend))
    return registry


def enforce_policy(
    card: dict,
    require: str,
    registry: AttestationVerifierRegistry,
) -> tuple[bool, str, Optional[AttestationResult]]:
    """Attestation gate, mirroring GlyphClient's call-path check.

    ``require``: 'none' (gate off), 'danger' (gate cards with
    riskTier=danger), 'all' (gate every card).

    Returns ``(allowed, code, result)`` where code is '' when allowed, or
    ATTESTATION_REQUIRED / ATTESTATION_UNTRUSTED when blocked.
    """
    if require == "none":
        return True, "", None
    tier = (card.get("cost") or {}).get("riskTier")
    gated = require == "all" or (require == "danger" and tier == "danger")
    if not gated:
        return True, "", None

    attestation = card.get("attestation")
    if not attestation:
        return False, "ATTESTATION_REQUIRED", None

    verifier = registry.get(str(attestation.get("type")))
    if verifier is None:
        return False, "ATTESTATION_UNTRUSTED", AttestationResult(
            valid=False,
            type=str(attestation.get("type")),
            error="no verifier registered for this attestation type",
        )

    result = verifier.verify(card)
    if not result.valid:
        return False, "ATTESTATION_UNTRUSTED", result
    # Verifiers with a trust dimension (keyless) must be trusted; verifiers
    # without one (digest) pass on validity alone.
    if result.trusted is False:
        return False, "ATTESTATION_UNTRUSTED", result
    return True, "", result
