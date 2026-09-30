# alethech — Protocol Specification

**Status**: CURRENT (rev 2 + rev 3 identity layer)
**Version**: 0.9.0
**License**: MIT

## Overview

alethech is a verifiable agent continuity protocol. It provides Ed25519-signed memory commits, hash-linked DAG, key rotation with reachability guarantee, and offline verification.

## Nine commands

1. `alethech init` — generate identity + genesis commit
2. `alethech commit --content <file>` — create signed MemoryCommit
3. `alethech evidence --tool <name>` — create signed EvidenceCommit
4. `alethech verify` — verify the whole store, offline
5. `alethech export --output <dir>` — portable package
6. `alethech import --input <dir>` — import external memory (verify-before-write)
7. `alethech key rotate` — rotate operational key (atomic)
8. `alethech key revoke --key-id <id>` — revoke a key (emergency)
9. `alethech migrate --to v0.2` — migrate identity layer (v0.1 → v0.2)

## Store layout

```
.alethech/
├── identities/<agent_id>.json    # Identity records (public only)
├── keys/signing.key              # Private signing key (PEM, 0600)
├── keys/recovery.key             # Private recovery key (PEM, 0600)
├── commits/<commit_id>.json      # MemoryCommit files
├── evidence/<commit_id>.json     # EvidenceCommit files
├── artifacts/<hash>              # Raw artifact bytes (named by sha256)
├── control_events/<id>.json      # ControlEvent chain (key rotations)
├── migrations/<id>.json          # MigrationRecord (v0.1 → v0.2)
├── root_authority.json           # RootAuthority (root public key)
├── identity_records_v2/<id>.json # IdentityRecordV2 (root-bound)
└── HEAD                          # Current head commit_id (text file)
```

## Cryptographic primitives

- **Ed25519** (RFC 8032) — signatures
- **SHA-256** (FIPS 180-4) — hashing
- **JCS** (RFC 8785) — JSON canonicalization
- **Base32** (RFC 4648) — agent_id encoding

## Commit structure

```
commit_id = sha256(JCS(object - {commit_id, signature}))
signature = Ed25519_sk(JCS(object + commit_id))
```

The commit_id is the hash of the canonical JSON (excluding commit_id and signature). The signature covers the canonical JSON including commit_id. Both are verified independently.

## Identity derivation

```
agent_id = "did:alethech:" + base32(sha256(JCS(public_key_jwk))[:16])
root_id = "did:alethech:root:" + base32(sha256(JCS(root_public_key_jwk))[:16])
```

The agent_id is NOT declared — it is cryptographically derived from the public key. You cannot claim an agent_id without controlling the corresponding private key.

## Key rotation

When a key is rotated:
1. A ControlEvent (type=key_rotation) is created, signed by the root key
2. The old key is added to IdentityRecordV2.revoked_keys with cutoff_head = current HEAD
3. A new key is generated and added to IdentityRecordV2.active_keys
4. The IdentityRecordV2 is re-signed by the root key

After rotation:
- Commits signed with the old key are checked: if they are in ancestry(cutoff_head) → VALID_HISTORICAL
- Commits signed with the old key NOT in ancestry(cutoff_head) → NOT_IN_PROVEN_PRE_ROTATION_HISTORY

The verifier does NOT claim to prove WHEN the commit was created. Only membership in the causal frontier.

## Checkpoint

A Checkpoint is signed by the agent and preserved externally. It contains:
- head_commit_id
- commit_count
- evidence_count
- sequence (monotonic, for anti-rollback)
- created_at

Verification checks:
1. Checkpoint signature is valid
2. head_commit_id is present in store
3. commit_count matches
4. evidence_count matches
5. head_commit_id is an ancestor of current HEAD (causal continuity)

If all pass: continuity_verified = True.

Anti-rollback (sequence < N) is consumer-side: verify_store cannot detect it without a prior checkpoint.

## What alethech does NOT do

- Prove content truth (only that it was signed)
- Encrypt content at rest
- Detect rollback without external checkpoint
- Delegate permissions between agents
- Call any LLM
- Provide true filesystem atomicity on import (verify-before-write, not transactional)
