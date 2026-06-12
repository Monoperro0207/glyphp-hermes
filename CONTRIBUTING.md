# Contributing

## Setup

```bash
python3.11 -m venv .venv && source .venv/bin/activate   # 3.11–3.13
pip install -e ".[dev,sigstore]"
```

## Tests

```bash
pytest          # hermetic: in-process fake Glyph server, real ed25519 signing
                # — no network, no Node, no Hermes required
ruff check src tests demo scripts .github/scripts
mypy
```

Two groups of tests skip by default:

- `-m hermes_upstream` — contract tests against a real hermes-agent
  checkout. Run them with hermes-agent on `PYTHONPATH`; CI runs them weekly
  in [hermes-contract.yml](.github/workflows/hermes-contract.yml).
- `sigstore_offline` tests — need `tests/fixtures/sigstore/` (recorded once
  by the [attestation-e2e](.github/workflows/attestation-e2e.yml) workflow,
  which requires GitHub OIDC) plus the `[sigstore]` extra installed.

## Demo

```bash
cd demo && npm install && npm run server    # terminal 1 (real @glyphp/server)
python demo/run_demo.py --yes               # terminal 2 — must exit 0
```

## Design rules worth knowing before a PR

- **Everything fail-closed.** A missing Hermes capability degrades to a
  blocked call with an explanatory error, never to an auto-approval.
- **`_hermes.py` is the only module that imports Hermes.** Everything else
  must stay importable without a Hermes process (that's what keeps the test
  suite hermetic). New upstream symbols go through `HermesCaps`
  feature-detection and get a line in `test_hermes_contract.py`.
- **Every callable handed to Hermes goes through `_safe_callable`** so extra
  kwargs from future Hermes versions can never raise TypeError
  (`test_kwargs_contract.py` enforces this).
- **Approvals are one-shot.** Nothing may persist a confirmation across
  calls — see `OneShotGrantStore` and `test_gateway_approval.py`.

## Releases

See [RELEASING.md](RELEASING.md).
