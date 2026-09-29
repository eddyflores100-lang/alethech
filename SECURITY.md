# Security Policy

## Supported Versions

| Version | Supported |
|---------|----------|
| 0.8.x   | ✅       |
| < 0.8   | ❌       |

## Reporting a Vulnerability

If you discover a vulnerability in alethech, please report it responsibly.

**DO NOT open a public GitHub issue.**

Instead, email: `security@alicelabs.site`

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

### Response Timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix or mitigation**: within 30 days (severity-dependent)
- **Public disclosure**: after fix is released, coordinated with reporter

## Security Properties

alethech provides:

- **Integrity**: SHA-256 hashing + Ed25519 signatures on every commit
- **Authenticity**: agent_id cryptographically derived from public key
- **Provenance**: Merkle DAG with hash-linked parent chains
- **Key lifecycle**: rotation with cutoff_head reachability guarantee
- **Continuity**: checkpoint ancestry verification (not just presence)

alethech does NOT provide:

- Confidentiality (no encryption at rest)
- Truth verification (only verifies signatures, not content truth)
- Distributed consensus (single-agent, local-first)
- Rollback detection without external checkpoint

## Threat Model

### What alethech protects against

| Threat | Mitigation |
|--------|-----------|
| Content tampering | SHA-256 commit_id + Ed25519 signature |
| Identity forgery | agent_id derived from public key |
| Key compromise after rotation | cutoff_head reachability check |
| Checkpoint rollback | Monotonic sequence field |
| Import of corrupted bundles | Verify-before-write + staged per-file atomic replacement |
| Recall-seam attacks | IdentityRecord ↔ ControlEvent consistency |

### What alethech does NOT protect against

| Threat | Why |
|--------|-----|
| Private key theft | Keys stored as PEM 0600, no HSM |
| Rollback without checkpoint | No external state to compare against |
| Side-channel attacks | Not in scope (local-first) |
| Social engineering | Not a cryptographic problem |

## Cryptographic Primitives

- **Ed25519** (RFC 8032) — signatures
- **SHA-256** (FIPS 180-4) — hashing
- **JCS** (RFC 8785) — JSON canonicalization
- **Base32** (RFC 4648) — agent_id encoding

## Audit History

- **2026-09-27**: External review by tonydzi (Palo Alto AI Research Lab) — [run-llama/llama_index#23122](https://github.com/run-llama/llama_index/issues/23122) (Palo Alto AI Research Lab) — reachability guarantee gap found and fixed
- **2026-09-28**: External review by Kaushalt2004 (CogniCore) — [cognicore-dev/cognicore-env#136](https://github.com/cognicore-dev/cognicore-env/pull/136) — merged, 14/14 passing (CogniCore) — firing test implemented, merged with 14/14 passing

## Contact

- Security email: security@alicelabs.site
- GitHub Security Advisories: https://github.com/eddyflores100-lang/alethech/security/advisories/new

## Clarifications

### Rollback detection

- **With external checkpoint**: `verify_store` checks that `checkpoint.head_commit_id` is an ancestor of the current HEAD via `ancestry_check()`. Count mismatch is a fail-closed error. The `sequence` field is monotonic and signed — a consumer with a prior checkpoint can detect rollback by comparing `sequence` values.
- **Without external checkpoint**: alethech CANNOT detect rollback. There is no internal state to compare against. This is a documented limitation, not a bug.

### Private key storage

- Private keys are stored as PEM with `0600` permissions on POSIX systems (Linux/macOS).
- **Windows**: POSIX permissions do not apply. The PEM file is created without ACL restrictions on Windows. Users on Windows should manually restrict access to the `.alethech/keys/` directory.
- PEM files are **not encrypted with a passphrase**. This is a known limitation. Future versions may add optional passphrase encryption via `--encrypt` flag.

### Timestamps

- All timestamps in alethech are self-declared by the agent. The protocol does NOT anchor to an external time source (NTP, blockchain, or trusted timestamp authority).
- Without an external time anchor, there is **no reliable temporal ordering** between identities or commits from different agents.
- The `sequence` field in Checkpoint provides **monotonic ordering** within a single agent's history, but NOT across agents.

### Import safety

- Import processes untrusted data. Defenses include: symlink rejection, path traversal rejection, file size limits (50MB), file count limits (10000), total size limits (500MB), artifact hash verification before write, and verify-before-write staging.
- Import does NOT provide whole-store filesystem transactionality. Validation completes before mutation, and each destination file is replaced atomically on supported filesystems, but a crash or I/O failure between file replacements can leave a partially applied import. Recovery/whole-store transactions remain outside the current guarantee.
