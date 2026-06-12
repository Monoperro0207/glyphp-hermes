# Changelog

## 0.1.0

Initial release.

- Native Glyph Protocol plugin for hermes-agent (pip entry-point
  `hermes_agent.plugins` → `glyph`, also folder-installable).
- Signed-card verification on ingestion; forged cards never dispatch.
- Pinning + TOFU bounded by risk tier; breaking-change diffs with
  field-level severity (port of `@glyphp/client`'s `diffCards`).
- Confirmation gates mapped to Hermes approvals: blocking CLI prompt,
  gateway blocking decision (tier 1) or pending + one-shot grant via the
  `post_approval_response` hook (tier 2). All approvals one-shot.
- Receipt verification (signature, card binding, payload hash) + JSONL
  audit log re-verifiable offline (`hermes glyph audit --verify`).
- Attestation policy `none|danger|all` with `container-digest` and RFC-0007
  `glyph-keyless-v1` verifiers; optional Sigstore backend (`[sigstore]`
  extra, sigstore 4.x) with pinned-trusted-root offline verification.
- Live registry reconciliation (`/glyph sync`) — tools added/removed
  mid-session without restarting Hermes.
- `/glyph` session commands and `hermes glyph` CLI.
- 164 hermetic tests (in-process fake Glyph server with real ed25519
  signing), upstream contract tests against hermes-agent, weekly drift CI,
  live + offline Sigstore e2e.
