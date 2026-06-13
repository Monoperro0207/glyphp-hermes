# Changelog

## 0.1.0

Frictionless install: a `glyphp-hermes` console script with
`enable` / `disable` / `status`. `glyphp-hermes enable` adds `glyph` to the
`plugins.enabled` allow-list in `~/.hermes/config.yaml` — the opt-in the
Hermes loader honors — idempotently, creating the file if missing and
preserving the rest of the config verbatim (backup at `config.yaml.bak`).
Works around the Hermes CLI-discovery gap where `hermes plugins enable`
doesn't see pip entry-point plugins; `glyphp-hermes status` verifies the
install since `hermes plugins list` won't show it either.

RFC-0007 subject-digest fix: keyless verification now binds the bundle to the
card's **attestation-exclusive** canonical id (`compute_keyless_subject_digest`,
prefers `glyph_protocol`'s implementation when present, local port otherwise)
instead of `sha256(card.id)`. The bundle rides inside `card.attestation`, which
enters the final id, so the old binding was a fixed point no real keyless card
could satisfy; a card whose id includes the attestation now passes both
`verify_glyph` and the subject binding. The recorded Sigstore fixture verifies
unchanged.

Includes the fixes from the 2026-06-12 isolated audit (sandboxed adversarial
review against commit d7d4423):

- **Receipt key pinning (high)**: `check_envelope` now requires the
  receipt's `serverPublicKey` to equal the pinned card's key — a
  self-consistent receipt signed by an attacker-chosen key is rejected.
  The audit log records the pinned key per entry and
  `hermes glyph audit --verify` re-checks it offline.
- **Inspection binding (high)**: `check_envelope` now recomputes the
  canonical hash of the received inspection and requires it to match the
  receipt's `inspectionHash`; a swapped inspection invalidates the result.
- **Sigstore activation (medium)**: `default_registry()` auto-injects
  `SigstoreBackend` when the `[sigstore]` extra is installed, so a default
  bridge can actually mark keyless attestations trusted.
- **Schema refresh on resync (medium)**: `reconcile()` re-registers kept
  tools whose card/schema changed, keeping the schema Hermes shows the
  model in step with the card the handler enforces.
- **Sanitized-name collisions (medium)**: glyphs whose names sanitize to
  the same tool name (`a-b` vs `a.b`, long-name truncation) now all get a
  stable suffix derived from the original name instead of silently
  shadowing each other.
- **Exit codes under `hermes glyph` (medium)**: the Hermes CLI dispatcher
  discards handler return values; the plugin now raises `SystemExit` on
  failure so blocked calls reach the shell as nonzero exits (upstream
  report drafted in `docs/upstream/issue-cli-exit-codes.md`).

Initial feature set:

- Native Glyph Protocol plugin for hermes-agent (pip entry-point
  `hermes_agent.plugins` → `glyph`, also folder-installable).
- Signed-card verification on ingestion; forged cards never dispatch.
- Pinning + TOFU bounded by risk tier; breaking-change diffs with
  field-level severity (port of `@glyphp/client`'s `diffCards`).
- Confirmation gates mapped to Hermes approvals: blocking CLI prompt,
  gateway blocking decision (tier 1) or pending + one-shot grant via the
  `post_approval_response` hook (tier 2). All approvals one-shot.
- Receipt verification (pinned key, signature, card binding, payload hash,
  inspection hash) + JSONL audit log re-verifiable offline
  (`hermes glyph audit --verify`).
- Attestation policy `none|danger|all` with `container-digest` and RFC-0007
  `glyph-keyless-v1` verifiers; optional Sigstore backend (`[sigstore]`
  extra, sigstore 4.x) with pinned-trusted-root offline verification.
- Live registry reconciliation (`/glyph sync`) — tools added/removed
  mid-session without restarting Hermes.
- `/glyph` session commands and `hermes glyph` CLI.
- 164 hermetic tests (in-process fake Glyph server with real ed25519
  signing), upstream contract tests against hermes-agent, weekly drift CI,
  live + offline Sigstore e2e.
