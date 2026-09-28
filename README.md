# alethech

> Verifiable agent continuity protocol — local-first, zero-LLM, zero-blockchain.
> The art of un-concealing transmission integrity.

From Greek **ἀλήθεια** (aletheia, "truth as un-concealment") + **τέχνη** (techne, "art, craft").
The art of revealing that a memory was not modified after being signed.

This is the reference implementation of the protocol specified in `docs/implementacion-nucleo-minimo.md` (rev 2).

## the property

> **This memory set forms part of a cryptographically verifiable history associated with a determined identity, whose commits can be independently verified with respect to their integrity, cryptographic authorship, and provenance relations.**
>
> **When a reference checkpoint exists, it can additionally be verified that the presented history continues from that checkpoint.**

The protocol does NOT prove that the agent's claims are true — only that they were signed by the identity that claims them. The truth being un-concealed is the truth about transmission integrity, not about content.

## status

Implementation of rev 2 spec. 9 commands, 196 tests (incl. 56 RFC 8785 JCS conformance vectors), 8 mutation-guard paths covering 3 code-level defeats, 2 data-level (recall-seam) defeats, 1 checkpoint continuity defeat, and 2 root-binding defeats. JCS serializer verified against ECMAScript Number.prototype.toString() algorithm. No LLM, no MCP, no MarketNow, no UTA, no network, no P2P, no cloud, no consensus, no trust providers, no marketplace, no skill verification, no multi-agent consensus.

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

196 tests covering:
- crypto primitives (Ed25519, SHA-256, base64url, base32)
- JCS canonicalization (RFC 8785) — 56 conformance vectors including:
  - integer/float serialization per ECMAScript Number.prototype.toString()
  - -0 sign preservation
  - scientific notation format (no '+', no leading zeros in exponent)
  - decimal vs scientific threshold (1e21 / 1e-6)
  - UTF-16 key ordering with surrogate pairs
  - string escaping (control chars, non-ASCII preservation)
  - NaN/Infinity rejection
- agent_id derivation (cryptographic binding to public_key)
- MemoryCommit signing, tamper detection, wrong-key rejection
- EvidenceCommit signing
- all 9 CLI commands (init, commit, evidence, verify, export, import, migrate, key rotate, key revoke)
- checkpoint emission + rollback detection + **causal continuity** (0.5.6)
- identity_mismatch detection
- export/import roundtrip preservation
- tampered manifest rejection
- key rotation with cutoff_head reachability guarantee
- ancestry_check mutation guard (3 code-level defeats)
- recall-seam defeats (2 data-level mutations: active-keys tampering, cutoff_head mutation)
- **root_id binding** (RootAuthority ↔ IdentityRecord ↔ ControlEvent, 0.5.6)
- **checkpoint continuity** (checkpoint HEAD must be ancestor of current HEAD, 0.5.6)

## license

MIT.

## related repositories

- The companion project `memex` (Python/ChromaDB memory system) is a separate layer that handles retrieval, MCP, and graph memory. `alethech` is the cryptographic protocol layer that can sign every memex write via `MemexAlethechHook` to make its memory verifiable. The memex legacy codebase is preserved on the `legacy/memex` branch of this repo (167 commits, untouched).
