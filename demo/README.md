# glyphp-hermes demo

A complete walkthrough of the trust chain — signed cards, TOFU pinning,
confirmation gates, verified receipts, tamper detection, and attestation
policy — against a real `@glyphp/server` instance. **No LLM, no API keys.**

## Prerequisites

- Node.js ≥ 20 (for the demo Glyph server)
- Python 3.11–3.13 with `glyphp-hermes` installed (`pip install -e ..` from this folder)

## Quick run

```bash
# Terminal 1 — the Glyph server (4 signed tools on port 3100)
cd demo
npm install
npm run server

# Terminal 2 — the six-act walkthrough
python demo/run_demo.py            # interactive confirmation prompt
python demo/run_demo.py --yes      # auto-approve (CI / smoke-test mode)
```

The script exits non-zero if any act fails, so it doubles as an integration
smoke test of the plugin against the real TypeScript server implementation.

## The six acts

| # | Act | What it proves |
|---|-----|----------------|
| 1 | Discovery | Every card's ed25519 signature + content-addressed id verified on ingestion |
| 2 | TOFU | safe/caution auto-pinned; danger registered but blocked until explicit trust |
| 3 | Confirmation | prepare → human approval → single-use token bound to the exact input |
| 4 | Receipts | Signed receipt verified per call; JSONL audit log re-verifiable offline |
| 5 | Tamper detection | A payload swapped in transit fails `outputHash` and is withheld |
| 6 | Attestation | `require: danger` blocks unattested danger tools, passes attested ones |

## The changed-card gate (`--tamper`)

Simulates a provider re-deploying a tool with a wider blast radius:

```bash
# Run 1: pin the tools with a persistent home
python demo/run_demo.py --yes --home /tmp/glyph-demo-home

# Restart the server with notes.add re-issued as riskTier 'danger'
npm run server:tamper

# Run 2: the plugin parks notes.add and shows the breaking diff
python demo/run_demo.py --yes --home /tmp/glyph-demo-home
```

Act 2 of the second run prints:

```
tamper detected! pending diff:
  [breaking] cost.riskTier: "caution" -> "danger"
```

The tool stays blocked until a human re-approves it (`/glyph trust` inside
Hermes, or `hermes glyph trust demo notes.add` from the CLI).

## Running inside the real Hermes agent

See [hermes-walkthrough.md](hermes-walkthrough.md).
