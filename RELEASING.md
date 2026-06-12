# Releasing

Releases publish to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/)
(GitHub OIDC) — no API tokens anywhere.

## One-time setup (manual, needs your PyPI account)

1. Log in to [pypi.org](https://pypi.org) → **Your projects** → **Publishing**
   (or, before the first release, **Add a new pending publisher**).
2. Register a trusted publisher with:
   - **PyPI project name**: `glyphp-hermes`
   - **Owner**: `Monoperro0207`
   - **Repository**: `glyphp-hermes`
   - **Workflow name**: `release.yml`
   - **Environment**: `pypi`
3. In the GitHub repo: **Settings → Environments → New environment** named
   `pypi` (no secrets needed; optionally add yourself as required reviewer so
   every publish needs a click).

## Every release

```bash
# 1. bump version in pyproject.toml AND src/glyphp_hermes/_version.py
# 2. add a CHANGELOG.md entry
git commit -am "release: vX.Y.Z"
git tag vX.Y.Z
git push origin main --tags
```

The [release workflow](.github/workflows/release.yml) runs the full gate
(pytest + ruff + mypy), builds sdist+wheel, and publishes. If the trusted
publisher isn't configured yet, the publish job fails cleanly and nothing
is uploaded.
