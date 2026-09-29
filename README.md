# alethech

[![PyPI version](https://img.shields.io/pypi/v/alethech.svg)](https://pypi.org/project/alethech/)
[![Python](https://img.shields.io/pypi/pyversions/alethech.svg)](https://pypi.org/project/alethech/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-230%20passing-brightgreen)](https://github.com/eddyflores100-lang/alethech)
[![CI](https://github.com/eddyflores100-lang/alethech/actions/workflows/ci.yml/badge.svg)](https://github.com/eddyflores100-lang/alethech/actions/workflows/ci.yml)
[![Mutation paths](https://img.shields.io/badge/mutation%20paths-8-blue)](https://github.com/eddyflores100-lang/alethech)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellow)](https://github.com/eddyflores100-lang/alethech)
[![Type hints](https://img.shields.io/badge/type%20hints-100%25-brightgreen)](https://github.com/eddyflores100-lang/alethech)

> Verifiable agent continuity protocol — local-first, zero-LLM, zero-blockchain.
> The art of un-concealing transmission integrity.
>
> © 2026 AliceLabs LLC. Todos los derechos reservados.

From Greek **ἀλήθεια** (aletheia, "truth as un-concealment") + **τέχνη** (techne, "art, craft").
The art of revealing that a memory was not modified after being signed.

This is the reference implementation of the protocol specified in `docs/implementacion-nucleo-minimo.md` (rev 2 + rev 3 identity layer).

## what this is

`alethech` is a Python package that provides **cryptographically verifiable memory continuity for AI agents**. It lets an agent sign its memory commits with Ed25519, link them in a Merkle DAG, rotate keys without losing identity, and prove to a third party that its memory was not tampered with.

**What this repo IS:**
- A cryptographic protocol implementation (Ed25519 + SHA-256 + JCS RFC 8785)
- 9 CLI commands (`init`, `commit`, `evidence`, `verify`, `export`, `import`, `migrate`, `key rotate`, `key revoke`)
- A test suite with mutation-guard paths (each guarantee has a test that fails when the check is defeated)
- MIT licensed, published on PyPI as `alethech`

**What this repo is NOT:**
- It is NOT a memory store or retrieval system
- It is NOT the legacy `memex` project (Python/ChromaDB memory server)
- It has no MCP server, no Docker, no auto-update, no LLM calls
- It depends only on `cryptography` and `click` — no `mem0ai`, no `chromadb`, no `ollama`

The legacy `memex` codebase (167 commits, AliceLabs Proprietary License) is preserved in a **separate repository**: [`eddyflores100-lang/memex-legacy`](https://github.com/eddyflores100-lang/memex-legacy). It is not part of this repo and not installed by `pip install alethech`.

## the property

> **This memory set forms part of a cryptographically verifiable history associated with a determined identity, whose commits can be independently verified with respect to their integrity, cryptographic authorship, and provenance relations.**
>
> **When a reference checkpoint exists, it can additionally be verified that the presented history continues from that checkpoint.**

The protocol does NOT prove that the agent's claims are true — only that they were signed by the identity that claims them. The truth being un-concealed is the truth about transmission integrity, not about content.

## status

Version 0.8.0. 9 commands, 230 tests, 8 mutation-guard paths, 85% coverage. No LLM, no MCP, no network, no P2P, no cloud, no consensus, no trust providers, no marketplace, no skill verification, no multi-agent consensus.

## install

```bash
pip install alethech
```

For development:

```bash
git clone https://github.com/eddyflores100-lang/alethech.git
cd alethech
pip install -e ".[dev]"
```

## usage

```bash
alethech init                              # generate identity + genesis commit
alethech commit --content <json-file>      # create signed MemoryCommit
alethech evidence --tool <name>            # create signed EvidenceCommit
  --input <file> --output <file>
alethech verify                            # verify the whole store, offline
alethech export --output <dir>             # portable package
alethech import --input <dir>              # import external memory
alethech key rotate                        # rotate operational key
alethech key revoke --key-id <id>          # revoke a key
alethech migrate --to v0.2                  # migrate identity layer
```

## what it does NOT do

- It does NOT prove that the agent's claims are true. Only that they were signed by the identity that claims them.
- It does NOT detect rollback without an external checkpoint.
- It does NOT encrypt content at rest.
- It does NOT delegate permissions between agents.
- It does NOT call any LLM.

## what the name means

**alethech** comes from:

- **aletheia (ἀλήθεια)** — Greek for "truth", more precisely "un-concealment" (Heidegger's reading: truth as the act of revealing what was hidden)
- **techne (τέχνη)** — Greek for "art, craft, technique"

So alethech = "the art of un-concealing". The protocol un-conceals:
- whether a memory was modified after being signed
- who signed it
- what signed timestamp was recorded (NOT physical signing time — only the timestamp recorded in the artifact)
- what its provenance is
- whether the chain of custody is intact

It does NOT un-conceal whether the content is true — that's the agent's responsibility, not the protocol's.

## tests

```bash
python -m pytest tests/
```

230 tests covering:
- crypto primitives (Ed25519, SHA-256, base64url, base32)
- JCS canonicalization (RFC 8785) — 56 conformance vectors including:
  - integer/float serialization per ECMAScript Number.prototype.toString()
  - -0 serializes as "0" (per RFC 8785 erratum, NOT preserved)
  - scientific notation format (positive exponents keep '+', negative strip leading zeros)
  - decimal vs scientific threshold (1e21 / 1e-6)
  - UTF-16 key ordering with surrogate pairs
  - string escaping (control chars, non-ASCII preservation)
  - NaN/Infinity rejection
- agent_id derivation (cryptographic binding to public_key)
- MemoryCommit signing, tamper detection, wrong-key rejection
- EvidenceCommit signing (supports both legacy and V2 identity)
- all 9 CLI commands (init, commit, evidence, verify, export, import, migrate, key rotate, key revoke)
- checkpoint emission + rollback detection + **causal continuity** (ancestry check)
- identity_mismatch detection
- export/import roundtrip preservation
- tampered manifest rejection
- key rotation with cutoff_head reachability guarantee
- ancestry_check mutation guard (3 code-level defeats)
- recall-seam defeats (2 data-level mutations: active-keys tampering, cutoff_head mutation)
- **root_id binding** (RootAuthority ↔ IdentityRecord ↔ ControlEvent)
- **checkpoint continuity** (checkpoint HEAD must be ancestor of current HEAD)
- **IdentityRecordV2 signature verification** (against root public key)
- **import causal continuity** (ancestry check before writing)
- **import hardening** (symlinks, path traversal, archive bombs, artifact hash verification)

## repository structure

```
alethech/                    # this repo — cryptographic protocol only
├── alethech/                # source: crypto, objects, store, verify, cli, canonical
│   └── integrations/        # langchain + memex hooks
├── alethech-rs/             # Rust SDK (31 tests, cross-validation)
├── alethech-ts/             # TypeScript SDK (15 tests, Web Crypto API)
├── tests/                   # 230 tests (incl. 56 JCS conformance + 8 mutation-guard paths)
├── conformance/             # 15 adversarial conformance vectors
├── docs/                    # protocol specification
├── examples/                # basic_usage.py
├── INTEGRATION.md           # how to integrate with memex via MemexAlethechHook
├── CHANGELOG.md             # version history
├── SECURITY.md              # threat model + vulnerability policy
├── CONTRIBUTING.md          # dev setup + PR process
├── CODE_OF_CONDUCT.md      # Contributor Covenant
├── CITATION.cff             # academic citation
├── LICENSE                  # MIT
├── README.md                # this file
└── pyproject.toml           # alethech 0.8.0, deps: cryptography + click only
```

## cross-language validation

The protocol is implemented in three independent languages:

| Language | Tests | Dependencies |
|---|---|---|
| Python | 230 | cryptography + click |
| Rust | 31 | ed25519-dalek, sha2, serde |
| TypeScript | 15 | 0 (Web Crypto API only) |

All three use the same NIST SHA-256 test vectors, RFC 4648 base32 vectors, and RFC 8785 JCS conformance vectors. Cross-validation confirms the spec is language-independent.

## license

MIT.

## related repositories

- [`eddyflores100-lang/memex-legacy`](https://github.com/eddyflores100-lang/memex-legacy) — Legacy Memex codebase (167 commits, AliceLabs Proprietary License). Python/ChromaDB memory system with MCP integration. Preserved for historical reference. NOT installed by `pip install alethech`.

---

© 2026 AliceLabs LLC. Todos los derechos reservados. · MIT License
