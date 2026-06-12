# Repo setup status

What is already automated, and the few steps only a human with account
access can do.

## Automated (nothing to do)

- **CI** ([ci.yml](../.github/workflows/ci.yml)): pytest matrix 3.11–3.13
  (with the `[sigstore]` extra so offline-fixture tests run), ruff, mypy.
  Runs on every push/PR.
- **Upstream drift watch**
  ([hermes-contract.yml](../.github/workflows/hermes-contract.yml)): weekly
  clone of hermes-agent@main + the `hermes_upstream` contract tests. Goes
  red when Hermes changes an API we feature-detect — before users feel it.
- **Sigstore e2e + fixture**
  ([attestation-e2e.yml](../.github/workflows/attestation-e2e.yml)): weekly
  live keyless round trip via GitHub OIDC. Its first successful run also
  records `tests/fixtures/sigstore/` (real bundle + pinned trusted root) and
  commits it; from then on normal CI tests the SigstoreBackend accept path
  offline.
- **Release pipeline** ([release.yml](../.github/workflows/release.yml)):
  tag `v*` → full gate → build → PyPI trusted publishing.

## Manual steps remaining (owner account required)

1. **PyPI trusted publisher** — one-time, ~2 minutes, see
   [RELEASING.md](../RELEASING.md). Until then, pushing a tag builds but the
   publish job fails cleanly.
2. **Upstream reports to NousResearch** — two ready-to-paste drafts in
   [docs/upstream/](upstream/):
   - [`hermes plugins enable` doesn't see entry-point plugins](upstream/issue-plugins-enable-entrypoints.md)
     (bug + proposed fix — also the natural way to put this plugin on Nous'
     radar);
   - [public blocking-approval API for plugins](upstream/proposal-public-approval-api.md).
3. **Optional**: branch protection on `main` (require CI), repo topics
   (`hermes-agent`, `glyph-protocol`, `ai-agents`, `tool-use`, `security`)
   for discoverability.
