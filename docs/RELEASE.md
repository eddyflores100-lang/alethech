# Release process

This document describes how alethech is released to PyPI and npm, and what
provenance information is recorded for each release.

## Current state (as of 0.8.5)

| Channel | Method | Trusted publishing? |
|---|---|---|
| PyPI | `pypa/gh-action-pypi-publish` in CI workflow (GitHub OIDC) | ✅ since 0.8.5 |
| npm | `npm publish` from local machine | ❌ npm doesn't support trusted publishing |
| GitHub Release | `softprops/action-gh-release@v2` (automatic in CI workflow) | ✅ via OIDC |
| Sigstore signatures | `sigstore sign` in CI workflow | ✅ via OIDC |

**0.8.5 is the first release published entirely through the CI chain.**
No local PyPI token was used. The local PyPI API token used for
transitional uploads of 0.8.0–0.8.4 can be revoked (see
"Rotating the local PyPI token" below).

## How the trusted publishing chain works

The CI workflow `.github/workflows/release.yml` uses
`pypa/gh-action-pypi-publish@release/v1`, which uses GitHub OIDC to
mint a short-lived token from PyPI. The workflow runs on every `v*`
tag push.

The PyPI project `alethech` has a registered GitHub trusted publisher
with these exact claims:

- Owner: `eddyflores100-lang`
- Repository: `alethech`
- Workflow: `release.yml`
- Environment: _(none)_

The full chain:

```
git tag vX.Y.Z + git push origin vX.Y.Z
                ↓
   GitHub Actions release.yml workflow runs
                ↓
   Build package (python -m build)
                ↓
   Sign with Sigstore via GitHub OIDC
                ↓
   Publish to PyPI via pypa/gh-action-pypi-publish (no token)
                ↓
   Create GitHub Release with artifacts + signatures
```

The full chain — `commit → tag → CI build → Sigstore sign → PyPI publish → GitHub Release` — is publicly verifiable with no manual steps.

## Pre-trusted-publishing releases (0.8.0 through 0.8.4)

Releases 0.8.0 through 0.8.4 were uploaded to PyPI via `twine upload`
from a local machine using a project-scoped API token. They are
legitimate but their provenance chain is:

```
local machine → twine → PyPI
```

not

```
git commit → git tag → CI workflow → Sigstore sign → PyPI
```

The git tags `v0.8.2`, `v0.8.3`, and `v0.8.4` exist and point at the
correct commits, but the PyPI artifacts for those versions were not
produced by the CI workflow. This is documented in each release's
CHANGELOG entry.

Starting from 0.8.5, the CI chain is the only path to PyPI, and the
local PyPI API token can be revoked.

## npm releases (alethech-ts)

npm does not support trusted publishing the way PyPI does. Releases
to npm will continue to use `npm publish` with a stored npm token.
The npm token is stored locally in `~/.npmrc` (chmod 600) and is
rotated periodically.

The TypeScript package is published from the same commit as the
Python package, so the git tag (`v0.8.5`) covers both:
- `pip install alethech` → 0.8.5 (PyPI, CI trusted publishing since 0.8.5)
- `npm install alethech-ts` → 0.8.5 (npm, manual publish — npm doesn't support trusted publishing)

Both should match the version in `pyproject.toml` and
`alethech-ts/package.json` at the tagged commit.

## Release checklist

For each release:

1. Update `alethech/__init__.py` `__version__`.
2. Update `pyproject.toml` `version`.
3. Update `alethech-ts/package.json` `version`.
4. Update `README.md` "Version X.Y.Z" line and structure tree.
5. Update `SECURITY.md` supported versions table if needed.
6. Add CHANGELOG entry.
7. Run `python -m pytest tests/ -p no:xdist -q` — must be 230/230 green.
8. Run `python conformance/cross_language_check.py` — must be 0 disagreements.
9. Commit with `release: vX.Y.Z` message.
10. Push to main.
11. Wait for CI to go green (8/8 jobs).
12. Create annotated git tag `vX.Y.Z` and push it.
13. If trusted publishing is configured: the workflow will publish to PyPI automatically.
14. If not yet configured: build locally and `twine upload dist/*` (transitional).
15. `cd alethech-ts && npm publish --access public` (always manual).
16. Create GitHub Release (manually if the workflow didn't, or let `softprops/action-gh-release` do it).
17. Record the SHA-256 of the wheel and sdist in the GitHub Release body.

## Rotating the local PyPI token

Once trusted publishing is operational, the local PyPI API token should
be revoked:

1. Log in to https://pypi.org.
2. Go to https://pypi.org/manage/account/token/.
3. Find the `alethech` project-scoped token.
4. Click "Remove".
5. Delete `~/.pypirc` on the local machine.

Until then, the token is required for transitional uploads.
