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

Implementation of rev 2 spec. Six commands. No LLM, no MCP, no MarketNow, no UTA, no network, no P2P, no cloud, no consensus, no trust providers, no marketplace, no skill verification, no multi-agent consensus.

## install

```bash
pip install alethech
```

For development:

```bash
git clone https://github.com/eddyflores100-lang/alethech.git
cd alethech
git checkout protocol-rev2
pip install -e .
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
- when it was signed
- what its provenance is
- whether the chain of custody is intact

It does NOT un-conceal whether the content is true — that's the agent's responsibility, not the protocol's.

## tests

```bash
python -m pytest tests/
```

34 tests covering:
- crypto primitives (Ed25519, SHA-256, base64url, base32)
- JCS canonicalization (RFC 8785)
- agent_id derivation (cryptographic binding to public_key)
- MemoryCommit signing, tamper detection, wrong-key rejection
- EvidenceCommit signing
- all 6 CLI commands
- checkpoint emission + rollback detection
- identity_mismatch detection
- export/import roundtrip preservation
- tampered manifest rejection

## license

MIT.

## related repositories

- The companion project `memex` (Python/ChromaDB memory system) is a separate layer that handles retrieval, MCP, and graph memory. `alethech` is the cryptographic protocol layer that lives on top of `memex` to make its memory verifiable. The two will eventually converge via a write-hook integration.
