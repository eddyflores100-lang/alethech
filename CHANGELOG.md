# Changelog

All notable changes to alethech are documented in this file.

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
