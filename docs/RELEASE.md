# Release process

This document describes how alethech is released to PyPI and npm, and what
provenance information is recorded for each release.

## Current state (as of 0.8.4)

| Channel | Method | Trusted publishing? |
|---|---|---|
| PyPI | `twine upload` from local machine | ❌ not yet |
| npm | `npm publish` from local machine | ❌ npm doesn't support trusted publishing |
| GitHub Release | `softprops/action-gh-release@v2` (when CI workflow runs) | ✅ via OIDC |
| Sigstore signatures | `sigstore sign` in CI workflow | ✅ via OIDC |

**The goal** is to move PyPI to trusted publishing so that the entire
release chain is CI-driven and no local tokens are needed.

## What's blocking PyPI trusted publishing

The CI workflow `.github/workflows/release.yml` is already configured
to use `pypa/gh-action-pypi-publish@release/v1`, which uses GitHub
OIDC to mint a short-lived token from PyPI. The workflow runs on
every `v*` tag push.

**What's missing:** the PyPI project `alethech` has not yet been
registered with a "GitHub trusted publisher" entry. Without that
registration, PyPI rejects the OIDC token with:

```
invalid-publisher: valid token, but no corresponding publisher
```

## How to register the trusted publisher (one-time, manual)

Only the PyPI project owner can do this. The steps are:

1. Log in to https://pypi.org with the account that owns `alethech`.
2. Go to https://pypi.org/manage/account/publishing/
3. Click "Add a new publisher" → select **GitHub**.
4. Fill in the form with these exact values:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `alethech` |
   | Owner | `eddyflores100-lang` |
   | Repository name | `alethech` |
   | Workflow name | `release.yml` |
   | Environment name | _(leave empty — we don't use environments)_ |

5. Click "Add publisher".

After this registration, the next `git tag v0.8.5 && git push origin v0.8.5`
will trigger the release workflow, which will:

1. Build the package.
2. Sign it with Sigstore via GitHub OIDC.
3. Publish to PyPI via `pypa/gh-action-pypi-publish` (no stored token).
4. Create a GitHub Release with the artifacts and signatures attached.

The full chain — `commit → tag → CI build → Sigstore sign → PyPI publish → GitHub Release` — will then be publicly verifiable with no manual steps.

## Verifying a release (for consumers)

For any release starting from the first one published via trusted
publishing, consumers can verify the full chain:

```bash
# 1. Download the wheel
pip download alethech==0.8.5 --no-deps -d /tmp/verify

# 2. Compute its SHA-256
sha256sum /tmp/verify/alethech-0.8.5-*.whl

# 3. Compare against the hash in the GitHub Release body
#    https://github.com/eddyflores100-lang/alethech/releases/tag/v0.8.5

# 4. (Optional) Verify the Sigstore signature
sigstore verify /tmp/verify/alethech-0.8.5-*.whl \
    --certificate-identity https://github.com/eddyflores100-lang/alethech/.github/workflows/release.yml@refs/tags/v0.8.5 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The Sigstore signature proves that the artifact was produced by the
`release.yml` workflow on the `v0.8.5` tag — not by an attacker with
PyPI credentials.

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

Starting from the first release after the trusted publisher is
registered (target: 0.8.5), the CI chain will be the only path to
PyPI, and the local PyPI API token can be revoked.

## npm releases (alethech-ts)

npm does not support trusted publishing the way PyPI does. Releases
to npm will continue to use `npm publish` with a stored npm token.
The npm token is stored locally in `~/.npmrc` (chmod 600) and is
rotated periodically.

The TypeScript package is published from the same commit as the
Python package, so the git tag (`v0.8.4`) covers both:
- `pip install alethech` → 0.8.4 (PyPI, manual twine)
- `npm install alethech-ts` → 0.8.4 (npm, manual publish)

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
