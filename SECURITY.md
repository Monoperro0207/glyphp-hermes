# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/Monoperro0207/glyphp-hermes/security/advisories/new)
— do **not** open a public issue for security reports. You should receive a
response within 7 days.

Issues in the Glyph Protocol itself (spec, servers, SDKs) belong in the
[glyph-protocol](https://github.com/Monoperro0207/glyph-protocol/security) repo;
issues in the Hermes agent belong upstream at
[NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent).

## Scope and trust model

This plugin is a **verifier, not a signer** — it holds no private keys. What
it defends:

- **Card integrity**: every tool card's ed25519 signature and
  content-addressed id are verified before the tool is callable. Forged or
  tampered cards are bound as `CARD_INVALID` and never dispatch.
- **Change detection**: a re-deployed card with a breaking change (schema,
  risk tier, signing key, provider, attestation…) is parked until a human
  approves the diff. Trust-on-first-use is bounded by `tofu.max_risk_tier`.
- **Confirmation gates**: `requiresConfirmation` tools cannot be called
  without a fresh single-use token bound to the exact input; approvals are
  one-shot and never session-persisted.
- **Receipt integrity**: every result's signed receipt is verified
  (signature, binding to the pinned card, payload hash). A payload tampered
  in transit is withheld (`RECEIPT_INVALID`) under the default policy.
- **Fail-closed degradation**: when an approval channel is unavailable
  (cron, missing upstream API), confirmation-gated calls return
  `CONFIRMATION_UNAVAILABLE` — never auto-approve.

What it does **not** defend:

- A malicious Glyph server returning bad *data* in a correctly signed
  payload — receipts prove integrity and provenance, not truthfulness.
- The host running Hermes: local pin stores and audit logs under
  `~/.hermes/glyph/` are only as safe as the filesystem they live on.
- Compromise of a provider's signing key *before* the first pin (TOFU
  trusts the first signature it sees, bounded by risk tier).

See the protocol's
[threat model](https://github.com/Monoperro0207/glyph-protocol/blob/main/spec/threat-model.md)
for the full STRIDE analysis.

## Supported versions

Only the latest release receives security fixes.
