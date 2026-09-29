# Changelog

All notable changes to alethech are documented in this file.

## [0.8.1] — 2026-09-29

### Fixed
- `alethech init` now writes `keys/root.key` (was: only signing + recovery).
  Without this, `alethech key rotate` failed with "root key not available:
  root key not found" on a fresh store.
- `alethech key rotate` now auto-migrates V1 → V2 if no IdentityRecordV2
  is found, instead of erroring with "run `alethech migrate --to v0.2`
  first". This makes the full lifecycle (init → commit → rotate → commit)
  work out of the box.

### Changed
- The V1 signing key is reused as the V2 root during auto-migrate
  (single-key model). If you want a *separate* root key (recommended
  for production), run `alethech migrate --to v0.2` explicitly before
  any rotation.

## [0.8.0] — 2026-09-29

### Added — Fourth audit pass (code-level review)
- Import now verifies all identity/key/commit signatures before writing to the store (was: write-then-verify; now: verify-then-write)
- Checkpoint continuity accepts descendants — a checkpoint from N commits ago still verifies against a HEAD at N+M (was: fail-closed on count mismatch)
- JCS rejects integers outside ±(2^53−1) — fixes cross-language hash divergence (Python int vs IEEE 754 double)

### Changed
- `_detect_cycle` is now iterative (BFS with deque) — was recursive, RecursionError at 1500+ commits
- `ancestry_check` is now O(n) with deque.popleft() — was O(n²) with list.pop(0)
- HEAD writes are atomic via temp file + `os.replace` — was `write_text()`, vulnerable to mid-write truncation
- Import auto-finds DAG tip and sets HEAD — was: left HEAD unset, verify failed post-import
- CLI assigns `sequence` to checkpoints by scanning existing max+1 — was: always 0

### Fixed
- IdentityRecordV2 signature verification (B3) — was passing through unverified
- EvidenceCommit V2 support (B4) — was missing V2 branch
- Checkpoint V2 support (B5) — was missing V2 branch
- Causal continuity check on import — ancestry_check now runs before write
- Symlink rejection, path traversal rejection, archive bomb limits — import hardening
- AlethechExport manifest type (was: MemexExport, backward compatible)

### Security
- 3 HIGH findings fixed (signature verification gaps, checkpoint continuity, JCS integer range)
- 7 MEDIUM findings fixed (algorithmic complexity, atomicity, HEAD management, sequence assignment)
- 7 LOW findings fixed (version sync across all files, CHANGELOG entries, site/llms.txt/agents.md)

### Known limitations (documented, not fixed)
- Rollback of valid IdentityRecord + deleted control_events remains undetectable (architectural, not a bug)
- PEM keys without passphrase (callers responsible)
- Windows atomicity depends on filesystem, not Python

Full audit details: see commit messages `dbc062e`, `3d2cd7e`, `8951779`, `b51f911`.

### Cross-language SDK status
- Python: 230+ tests, 0.8.0
- Rust: 31 tests (alethech-rs)
- TypeScript: 15 tests (alethech-ts, zero dependencies, Web Crypto API)

## [0.7.0] — 2026-09-28

### Added
- Atomic import transaction — staging + verify + atomic write
- Fail-closed checkpoint semantics — count mismatch is error, not warning
- Artifact hash check during import — verify SHA256(content) == filename before writing
- Trust gate for IdentityRecordV2 — `--trust-unknown-identities` now applies to v2 identities
- Renamed manifest type from `MemexExport` to `AlethechExport` (backward compatible)
- Removed all `did:memex` references from spec docs (replaced with `did:alethech`)

## [0.6.0] — 2026-09-28

### Added
- Conformance test vectors directory (`conformance/`) with 15 adversarial vectors
- Import hardening: path traversal rejection, symlink rejection, file size limits (50MB), file count limits (10000), total size limits (500MB)
- Anti-rollback: monotonic `sequence` field in Checkpoint (part of signed payload)
- Backward-compatible: old checkpoints without sequence default to 0

## [0.5.8] — 2026-09-28

### Fixed
- JCS: `-0` now serializes as `"0"` (not `"-0"`) per RFC 8785 erratum
- JCS: positive exponents keep `+` sign (e.g. `"1e+21"`, not `"1e+21"`)
- JCS: negative exponents strip leading zeros (e.g. `"1e-7"`, not `"1e-07"`)

## [0.5.7] — 2026-09-28

### Added
- 56 RFC 8785 JCS conformance test vectors
- canonical.py fixed to match ECMAScript Number.prototype.toString()

## [0.5.6] — 2026-09-28

### Added
- Checkpoint continuity: checkpoint.head_commit_id must be ancestor of current HEAD
- Root binding: explicit root_id binding between RootAuthority, IdentityRecordV2, and ControlEvent

### Fixed
- Reachability guarantee wired into verify_store (was implemented but never called)
- Renamed verdict from `revoked_key_after_cutoff` to `NOT_IN_PROVEN_PRE_ROTATION_HISTORY`

## [0.5.5] — 2026-09-27

### Added
- Cutoff head mismatch defense (second recall-seam defeat)
- IdentityRecord/ControlEvent consistency check

## [0.5.4] — 2026-09-27

### Added
- Recall-seam defense: identity/control-event consistency check
- Active-keys defense: detects K1 moved from revoked_keys to active_keys

## [0.5.2] — 2026-09-27

### Added
- Reachability guarantee enforced via ancestry_check in verify_store
- 5 mutation-guard paths (3 code-level + 2 data-level)

## [0.5.0] — 2026-09-27

### Added
- All 6 bugs fixed from corruption audit
- Threat model document
- Final docs revision

## [0.4.0] — 2026-09-26

### Added
- Atomicity, idempotency, wallet multiple, intra-process lock
- MemexAlethechHook integration

## [0.3.0] — 2026-09-26

### Added
- Rev 3 identity layer: RootAuthority, ControlEvent chain, MigrationRecord
- IdentityRecordV2 with key rotation and revocation

## [0.8.0] — 2026-09-29

### Fixed
- IdentityRecordV2 signature now verified against root in verify_identity_layer
- EvidenceCommit now supports V2 identity lookup (was only legacy)
- Checkpoint now supports V2 identity lookup (was only legacy)
- Import now verifies causal continuity (ancestry_check) before writing
- Import now verifies identity layer objects (root, identity records, control events, migrations) before writing
- Import auto-updates HEAD when store was empty (was leaving store in FAIL state)
- Checkpoint count mismatch: store having MORE commits than checkpoint is now OK (warning, not error) — only data loss (fewer) is an error
- JCS: integers outside ±(2^53-1) now rejected (cross-language consistency)
- ancestry_check: O(1) popleft via deque (was O(n) with list.pop(0)), removed max_depth limit
- _detect_cycle: iterative DFS (was recursive — caused RecursionError on large DAGs)
- CLI now assigns monotonic sequence to checkpoints (was always 0)
- HEAD writes are atomic via os.replace (was plain write_text)
- Spec translated to English (Spanish preserved as spec-es.md)
- "Merkle DAG" → "hash-linked DAG" (no Merkle root exists)
- License text: removed "Todos los derechos reservados" (contradicts MIT)
- pyproject.toml: added readme, classifiers, urls, keywords, SPDX license

### Added
- LangChain integration (AlethechCallbackHandler)
- Sigstore signing in release workflow
- Rust SDK (31 tests)
- TypeScript SDK (15 tests)
- robots.txt, sitemap.xml, llms.txt, agents.md
- Open Graph, Twitter Card, JSON-LD structured data
- SECURITY.md threat model clarifications
- 30 security/pentesting skills installed
