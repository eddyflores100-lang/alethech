# Security Policy

## Supported Versions

| Version | Supported |
|---------|----------|
| 0.7.x   | ✅       |
| < 0.7   | ❌       |

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
| Import of corrupted bundles | Atomic verify-then-write |
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

- **2026-09-27**: External review by tonydzi (Palo Alto AI Research Lab) — reachability guarantee gap found and fixed
- **2026-09-28**: External review by Kaushalt2004 (CogniCore) — firing test implemented, merged with 14/14 passing

## Contact

- Security email: security@alicelabs.site
- GitHub Security Advisories: https://github.com/eddyflores100-lang/alethech/security/advisories/new
