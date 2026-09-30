# ALETH002 continuation — 2026-09-30

Goal: one encrypted portable memory file, moved between devices and AI/chat
adapters by drag and drop. No central application or key escrow is required.

Baseline reviewed: `e401df3acd4791a4ad37d5c9a6d3b02a560e67da`.

## Implemented in this continuation

- `drop_context` now uses the public version dispatcher for ALETH001/ALETH002.
- Recovery performs full store verification before writing the replacement.
  Regression tests reject an authenticated envelope carrying a forged commit
  and prove both source and existing destination survive rejection.
- Two historical test fixtures used parent-directory cleanup that deleted
  `/tmp`. Both now use pytest-owned directories without broad cleanup.
- A frozen synthetic ALETH002 vector covers passphrase/recovery reads, exact
  payload equality, wrong credentials, tampering and truncation. CI requires
  all three readers; pytest checks the recovered protocol history as well.
- Updated the recovery specification's stale implementation status.

## Evidence and decisions

- Initial unmodified suite: 106 passed, 11 failed, 155 setup errors after the
  unsafe fixture deleted `/tmp`. After repairing both fixtures: 272 passed.
- New boundary regression tests: 3 failed and 1 passed before production
  fixes; all 4 passed after fixes. Existing recovery tests also pass.
- Final local suite: `python -m pytest -q` — 277 passed, no skips.
- Frozen vector: Python 6/6 and TypeScript 6/6 accepted/rejected as expected.
  TypeScript ran using Node 24 type stripping because the tsx CLI could not
  create its IPC socket here. Rust is not installed locally; the all-runtime
  CI gate is required before claiming Rust validation for this change.
- Ruling: reuse `Alethech.open_aleth` in the drop adapter so version dispatch
  stays in one place. The import is function-local to avoid import cycles.
- Ruling: verify recovery with the same temporary-store verifier already used
  by migration. This adds local disk I/O but enforces the documented contract.
- Ruling: use a committed, frozen random envelope rather than replace secure
  randomness in production with a deterministic test mode.
- Publication review rejected the initial synthetic fixture because it carried
  a disposable private signing key. The publication version excludes every
  `keys/` entry and uses a public all-0xff recovery test value. It tests verified
  read access, not signing continuity; no private signing keys are published.
- Independent review: no critical/important findings. Minor deferred: make the
  forged-history test explicitly target a non-HEAD ancestor; its current
  selection proves verification is required but does not guarantee that case.

## Remaining work

1. TypeScript and Rust ALETH002 seal/recovery writers and cross-writer vectors.
2. Browser extension recovery setup, unlock and local reseal UX without network
   permissions, followed by browser end-to-end tests.
3. Expanded mutation matrix for slots, schemas and size limits across readers.
4. Atomic replacement/crash tests for encrypted output writes.

These items are pending, not certified by the new reader matrix. Container
recovery remains distinct from identity/root governance. Old file copies
remain decryptable using their original credentials after rotation.
