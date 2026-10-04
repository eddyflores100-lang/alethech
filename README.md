# alethech

[![PyPI version](https://img.shields.io/pypi/v/alethech.svg)](https://pypi.org/project/alethech/)
[![Python](https://img.shields.io/pypi/pyversions/alethech.svg)](https://pypi.org/project/alethech/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/eddyflores100-lang/alethech/actions/workflows/ci.yml/badge.svg)](https://github.com/eddyflores100-lang/alethech/actions/workflows/ci.yml)
[![Mutation paths](https://img.shields.io/badge/mutation%20paths-8-blue)](https://github.com/eddyflores100-lang/alethech)
[![Coverage](https://img.shields.io/badge/coverage-85%25-yellow)](https://github.com/eddyflores100-lang/alethech)
[![Type hints](https://img.shields.io/badge/type%20hints-100%25-brightgreen)](https://github.com/eddyflores100-lang/alethech)
[![GitHub Repo stars](https://img.shields.io/github/stars/eddyflores100-lang/alethech?style=social)](https://github.com/eddyflores100-lang/alethech/stargazers)

> Verifiable agent continuity protocol — local-first, zero-LLM, zero-blockchain.
> The art of un-concealing transmission integrity.
>
> Copyright (c) 2026 AliceLabs LLC.

**Listed in [TeleAI-UAGI/Awesome-Agent-Memory](https://github.com/TeleAI-UAGI/Awesome-Agent-Memory)** (Emerging projects) after a maintainer audit of the claims against the code.

**If alethech is useful to you, a ★ [star](https://github.com/eddyflores100-lang/alethech/stargazers) is how other people — and their agents — find it.**

From Greek **ἀλήθεια** (aletheia, "truth as un-concealment") + **τέχνη** (techne, "art, craft").
The art of revealing that a memory was not modified after being signed.

This is the reference implementation of the protocol specified in `docs/implementacion-nucleo-minimo.md` (rev 2 + rev 3 identity layer).

## what this is

`alethech` provides **cryptographically verifiable, portable memory continuity for AI agents**. It signs memory commits with Ed25519, links them in a hash-linked DAG, rotates keys without losing identity, and can seal a verified history into one encrypted `.aleth` file for transfer between compatible runtimes and devices.

**What this repo IS:**
- A cryptographic protocol implementation (Ed25519 + SHA-256 + JCS RFC 8785)
- An encrypted portable memory container (`.aleth`, scrypt + AES-256-GCM)
- A neutral verified adapter view for plugins and chat integrations
- A read-only MCP stdio bridge (`python -m alethech.mcp_memory`) exposing verified memory context and verification tools — credentials and paths stay configuration, never tool arguments
- 9 CLI commands (`init`, `commit`, `evidence`, `verify`, `export`, `import`, `migrate`, `key rotate`, `key revoke`)
- A test suite with mutation-guard paths (each guarantee has a test that fails when the check is defeated)
- MIT licensed, published on PyPI as `alethech`

**What this repo is NOT:**
- It is NOT a memory store or retrieval system
- It is NOT the legacy `memex` project (Python/ChromaDB memory server)
- It has no Docker, no auto-update, no LLM calls, no required cloud
- It depends only on `cryptography` and `click` — no `mem0ai`, no `chromadb`, no `ollama`

The legacy `memex` codebase (167 commits, AliceLabs Proprietary License) is preserved in a **separate repository**: [`eddyflores100-lang/memex-legacy`](https://github.com/eddyflores100-lang/memex-legacy). It is not part of this repo and not installed by `pip install alethech`.

## the property

> **This memory set forms part of a cryptographically verifiable history associated with a determined identity, whose commits can be independently verified with respect to their integrity, cryptographic authorship, and provenance relations.**
>
> **When a reference checkpoint exists, it can additionally be verified that the presented history continues from that checkpoint.**

The protocol does NOT prove that the agent's claims are true — only that they were signed by the identity that claims them. The truth being un-concealed is the truth about transmission integrity, not about content.

## status

Released version 0.9.1 — portable encrypted memory (`.aleth` v2 with ALETH002 recovery across Python, TypeScript, and Rust) and chat capture into portable memory are live. CI runs the Python suite on 3.10–3.13 plus cross-language conformance and `.aleth` interoperability across Python, Rust, and TypeScript. No LLM, no required cloud, no blockchain, no consensus.

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

## capture a chat, carry the file

Use the Alethech toolbar icon to capture the loaded conversation, review it, and
create an encrypted `.aleth` with a new local identity and recovery code. Carry
that file to another device, chat or IDE. The extension imports it and inserts
selected context into an empty chat editor only on request; it never sends.
For any text-capable client, export `context.txt`. MCP clients can use the local
read-only memory connector. A single offline `alethech.html` also opens/creates
files without installing an extension or registering an account.

See [the complete capture and transfer guide](docs/CHAT_CAPTURE_FLOW.md) and
[IDE/MCP setup](docs/IDE_MEMORY.md). Capture requires only `activeTab` and
`scripting`, with no global host or storage permission. Rendered chat capture
cannot retrieve a provider's hidden memories or unloaded conversation history.

## portable encrypted memory (`.aleth`)

Alethech 0.9 development adds a single encrypted file designed for drag-and-drop transfer:

```python
from alethech import Alethech

agent = Alethech.initialize("./working-store")
agent.commit({"fact": "portable memory"})
agent.seal("memory.aleth", "your-passphrase")

# Plugin-style path: dropped file -> unlock -> verify -> neutral context
context = Alethech.drop_context("memory.aleth", "your-passphrase")
```

The `.aleth` container uses scrypt + AES-256-GCM. Its authenticated payload can be opened byte-exactly by the Python, Rust, and TypeScript implementations in CI. The portable file may carry the encrypted operational signing key so history can continue on another device, but it excludes `root.key` and `recovery.key`.

See [`docs/ALETH_CONTAINER_SPEC.md`](docs/ALETH_CONTAINER_SPEC.md) and [`docs/ADAPTER_CONTRACT.md`](docs/ADAPTER_CONTRACT.md).

## what it does NOT do

- It does NOT prove that the agent's claims are true. Only that they were signed by the identity that claims them.
- It does NOT detect rollback without an external checkpoint.
- The local working store is NOT encrypted at rest; the portable `.aleth` container is encrypted.
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

The Python test suite covers:
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
├── tests/                   # Python behavioral, adversarial, mutation and conformance tests
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
└── pyproject.toml           # alethech 0.9.1, deps: cryptography + click only
```

## cross-language validation

The protocol is implemented in three independent languages:

| Language | Tests | Dependencies |
|---|---|---|
| Python | CI suite | cryptography + click |
| Rust | 31 | ed25519-dalek, sha2, serde |
| TypeScript | 15 | 0 (Web Crypto API only) |

All three use the same NIST SHA-256 test vectors, RFC 4648 base32 vectors, and RFC 8785 JCS conformance vectors. The cross-language claim is backed by an executable harness:

```bash
python conformance/cross_language_check.py
```

This runs all three implementations against the same shared fixtures in `conformance/` and asserts byte-exact agreement on canonical bytes for accepted fixtures. The default run is fail-closed: exit 0 = all three ran and agree, 1 = disagreement, 2 = an implementation/runtime is unavailable. CI builds the Rust helper and executes the three-runtime harness. See [`conformance/CROSS_LANGUAGE.md`](conformance/CROSS_LANGUAGE.md) for the contract and how to add a 4th implementation.

## license

MIT.

## related repositories

- [`eddyflores100-lang/memex-legacy`](https://github.com/eddyflores100-lang/memex-legacy) — Legacy Memex codebase (167 commits, AliceLabs Proprietary License). Python/ChromaDB memory system with MCP integration. Preserved for historical reference. NOT installed by `pip install alethech`.

---

Copyright (c) 2026 AliceLabs LLC. MIT License.
