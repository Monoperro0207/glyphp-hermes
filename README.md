# glyphp-hermes

[![CI](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/ci.yml/badge.svg)](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/ci.yml)
[![hermes-contract](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/hermes-contract.yml/badge.svg)](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/hermes-contract.yml)
[![attestation-e2e](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/attestation-e2e.yml/badge.svg)](https://github.com/Monoperro0207/glyphp-hermes/actions/workflows/attestation-e2e.yml)
[![Python 3.11–3.13](https://img.shields.io/badge/python-3.11%E2%80%933.13-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Native [Glyph Protocol](https://github.com/Monoperro0207/glyph-protocol) integration for [hermes-agent](https://github.com/NousResearch/hermes-agent).**

Once installed, Hermes consumes Glyph tools with the **full trust chain** —
not a lossy bridge:

- 🔏 **Signed tool cards, verified on ingestion.** Every card's ed25519
  signature and content-addressed id are checked before a tool is ever
  callable. A forged card is bound as `CARD_INVALID` and never dispatches.
- 📌 **Pinning + TOFU, so auditing tools is not tedious.** Never-seen tools
  up to a configurable risk tier (`safe` by default) are trusted on first
  use. Anything above is registered *blocked* with instructions, one
  `/glyph trust` away. When a provider re-deploys a tool with a **breaking
  change** (schema, risk tier, provider, signing key…), the tool is parked
  and you get a field-by-field severity diff — the same `diffCards`
  semantics as `@glyphp/client`.
- ✅ **Confirmation gates mapped to Hermes approvals.** Tools that declare
  `requiresConfirmation` go through Glyph's prepare→token flow, surfaced as
  a native Hermes approval prompt (CLI) or a platform approval message
  (Telegram/Slack gateway). Approvals are **one-shot**: bound to the exact
  tool + input, consumed on use, never session-persisted.
- 🧾 **Verified receipts as audit evidence.** Every call's signed receipt is
  verified (signature, binding to the pinned card, payload hash) and
  appended to a JSONL audit log you can re-verify offline at any time. A
  payload tampered in transit fails `outputHash` and is withheld.
- 📜 **Attestation policy.** Optionally require supply-chain attestations
  (`container-digest`, RFC-0007 `glyph-keyless-v1`/Sigstore) for danger-tier
  or all tools — mirroring `@glyphp/client`'s `requireAttestation`.

## Install

```bash
# in the environment where hermes-agent runs
pip install glyphp-hermes
```

Entry-point plugins are opt-in. Enable `glyph` by adding it to
`~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - glyph
```

> `hermes plugins enable glyph` does not (yet) discover pip entry-point
> plugins on hermes-agent main — its discovery only scans bundled and
> `~/.hermes/plugins/` directories, while the plugin *loader* fully supports
> entry-points gated on `plugins.enabled`. The config edit above is the
> supported path; alternatively copy `src/glyphp_hermes/` to
> `~/.hermes/plugins/glyph/` (folder install) and `hermes plugins enable
> glyph` works as usual.

Then register a Glyph server and go:

```bash
hermes glyph add demo http://127.0.0.1:3100 --tofu-max-risk caution
hermes glyph sync
```

## How it works

```
        ┌────────────── hermes-agent ──────────────┐
        │  LLM ──► tool call: glyph_demo_notes_add │
        └──────────────────┬───────────────────────┘
                           ▼
   ┌──────────────── glyphp-hermes handler ────────────────┐
   │ 1. trust state   pinned? changed? revoked? attested?  │──✘──► tool_error + /glyph instructions
   │ 2. confirmation  prepare → user approval → token      │──✘──► USER_DENIED / CONFIRMATION_PENDING
   │ 3. call          POST /glyphs/:name/call              │
   │ 4. receipt       verify signature + card + outputHash │──✘──► RECEIPT_INVALID (withheld)
   │ 5. audit         append JSONL evidence                │
   └────────────────────────┬───────────────────────────────┘
                            ▼
                ┌── Glyph server (any impl) ──┐
                │ signed cards · sealed       │
                │ envelopes · signed receipts │
                └─────────────────────────────┘
```

Everything happens **inside the tool handler**, so the chain applies
identically in interactive CLI, gateway platforms, and direct dispatch.

## Why not the MCP bridge?

The Glyph monorepo ships an MCP bridge (`@glyphp/adapter-mcp-server`) that
works with Hermes out of the box — but MCP has no slots for signatures or
receipts, so the cryptographic evidence is consumed at the bridge and the
agent sees only payloads. This plugin speaks the Glyph wire protocol
natively via the official Python SDK, preserving the proof end to end.

## Demo (no LLM, no API keys)

![glyphp-hermes demo: discovery, TOFU, confirmation gate, verified receipts, tamper detection, attestation policy](demo/demo.gif)

```bash
cd demo && npm install && npm run server     # terminal 1
python demo/run_demo.py --yes                # terminal 2
```

Six acts: discovery+verification, TOFU, confirmation gate, receipts+audit,
tamper detection, attestation policy. See [demo/README.md](demo/README.md)
and [demo/hermes-walkthrough.md](demo/hermes-walkthrough.md) for the
live-agent version.

## Configuration (`~/.hermes/glyph/glyph.yaml`)

```yaml
version: 1
defaults:
  tofu: { enabled: true, max_risk_tier: safe }   # safe | caution | danger
  receipts: { verify: true, on_failure: block }  # block | warn
  auto_repin_review: true        # review-only card changes re-pin silently
  confirmations: { non_interactive: deny }       # cron/no-TTY: fail closed
  attestation:
    require: none                # none | danger | all
    issuers: []                  # allow-list, segment-boundary matching
    identities: []               # e.g. "repo:acme/tools" (≠ repo:acme/tools-evil)
servers:
  - alias: demo
    url: http://127.0.0.1:3100
    auth_token_env: GLYPH_DEMO_TOKEN   # optional bearer token env var
    tofu: { max_risk_tier: caution }   # per-server override
```

State lives under `~/.hermes/glyph/`: `pins/<alias>.json` (approved cards),
`audit/<alias>.jsonl` (receipts), `pending/<alias>.json` (parked changes).

## Commands

In-session (`/glyph …`):

| Command | Effect |
|---|---|
| `/glyph status` | every tool, risk tier, trust state, degraded capabilities |
| `/glyph sync` | re-sync + live reconcile (tools added/removed mid-session) |
| `/glyph trust <tool>` | approve a new/changed card (diff shown first) |
| `/glyph revoke <tool> [reason]` | block immediately |
| `/glyph diff <tool>` | pending breaking changes |
| `/glyph audit [n]` | last n receipts with verification verdicts |

CLI (`hermes glyph …`, no agent session needed): `add`, `remove`, `list`,
`sync`, `trust <alias> <glyph>`, `audit [--verify]`,
`call <alias> <glyph> <json> [--yes]`.

## Trust model

| Event | Result |
|---|---|
| Card signature invalid | `CARD_INVALID` — never callable, never pinned |
| New tool ≤ TOFU tier | auto-pinned, callable |
| New tool > TOFU tier | registered blocked (`TRUST_REQUIRED`) |
| Breaking change (input/output schema, riskTier, sideEffects, provider, publicKey, attestation, …) | parked (`CARD_CHANGED`) + severity diff, needs `/glyph trust` |
| Review-only change (intent, tags, examples, …) | auto re-pinned (configurable) |
| Revoked | blocked until re-approved |
| Receipt fails verification | result withheld (`block`) or returned with warning (`warn`) — always audited |
| Attestation policy unsatisfied | `ATTESTATION_REQUIRED` / `ATTESTATION_UNTRUSTED` — explicit trust does **not** bypass policy |

### Fail-closed by design

No approval channel (cron, missing upstream API, outside Hermes) means
confirmation-gated calls return `CONFIRMATION_UNAVAILABLE` — never
auto-approve. Degraded capabilities are reported in `/glyph status`.

## Compatibility

| | version |
|---|---|
| Python | 3.11 – 3.13 (matches hermes-agent) |
| glyph-protocol (PyPI) | ≥ 1.1.0 |
| Glyph wire protocol | 1.0 |
| hermes-agent | tested against [`db7714d`](https://github.com/NousResearch/hermes-agent/commit/db7714d5f17b1c9d009b8e8211a1e8a005295383) (2026-06-11); the weekly [hermes-contract](.github/workflows/hermes-contract.yml) workflow re-tests against `main` — upstream drift turns it red before it reaches you |

Optional extra: `pip install "glyphp-hermes[sigstore]"` (sigstore 4.x)
enables real Fulcio/Rekor verification of keyless attestations — exercised
live in the [attestation-e2e](.github/workflows/attestation-e2e.yml) workflow
via GitHub OIDC (no secrets), and offline in normal CI against a recorded
bundle with a pinned trusted root (`tests/fixtures/sigstore/`).

### Concurrency model

Handlers are synchronous **by design**: Hermes runs the agent turn (and with
it every tool dispatch) in a worker thread — its gateway wraps blocking work
in a thread-pool executor, and its own approval prompts block the same way.
A slow Glyph call therefore never stalls the gateway event loop. Each server
has a configurable HTTP `timeout_seconds`, and confirmation waits are bounded
by Hermes' own gateway timeout.

## Development

```bash
pip install -e ".[test]"
pytest            # hermetic: in-process fake Glyph server with real ed25519
                  # signing — no network, no Node, no Hermes required
```

The fake server (`tests/fake_server.py`) implements the wire contract with
genuinely signed cards/receipts, so the real SDK client and verifiers run
unmodified. Upstream contract tests (`-m hermes_upstream`) run in CI against
a fresh hermes-agent clone.

## License

MIT
