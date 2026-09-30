# ALETH002 implementation — 2026-09-30

ALETH002 supports one encrypted portable memory file with local passphrase and
recovery-code access. ALETH001 remains supported. See
[operations](ALETH002_OPERATIONS.md) for CLI, SDK and browser usage.

## Completed scope

- Python, TypeScript and Rust readers, seal/recovery writers and explicit v1
  migration. Migration protects source paths, symlinks and hard-link aliases.
- Full verified-history checks before publishing writer/recovery output,
  including non-HEAD ancestors, evidence and signing-key binding when present.
- Same-directory atomic encrypted-file replacement, private staged files and
  failed-write cleanup. Successful publication is not reported as failed because
  an optional post-commit directory sync is unavailable.
- Strict bounded parsing, canonical base64url, exact schemas, path restrictions
  and rejection of malformed UTF-8. Recovery rejects ambiguous slot layouts.
- Permissionless browser extension: locked recovery, explicit recovery setup
  and rotation, v2-preserving append/writeback/rekey, and local context sharing.
  File changes invalidate stale asynchronous operations.
- Frozen reader/mutation matrix, three-writer interoperability matrix, Rust CLI
  adversarial tests, native WASM tests and real Chromium extension tests in CI.
- Windows portability regression coverage and a dedicated Windows CI job.

## Validation

The final local Python suite passes all 320 tests. TypeScript verification and
writer regressions pass locally. Linux Python and the real browser extension
passed the initial completion CI run; Rust compiled and passed its unit and CLI
security tests. Final CI repeats all checks, including Windows, native WASM and
the complete cross-runtime matrices after the Node 20 test-launch correction.
The pull request checks are the source of the final CI result.

Independent review identified atomic-publication, slot-preservation, snapshot,
migration-alias, UTF-8 and platform issues. Regression fixes are implemented;
the independent rereview reported no residual critical or important findings.

## Operational boundaries

Rust writer/recovery/migration commands require Python with the Alethech package
for full protocol verification; missing verification support fails closed.
The native Rust reader remains independent of Python. Browser operations are
local and do not request network or storage permissions.

Container recovery is distinct from identity/root governance. Old copies remain
decryptable with their original credentials after rotation. Public conformance
fixtures exclude private signing keys; signing tests create disposable keys at
runtime. Context sharing is explicit and excludes private keys.
