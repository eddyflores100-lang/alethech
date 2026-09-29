# AI Agent Guide

## What is alethech?

alethech is a verifiable agent continuity protocol. It provides Ed25519-signed memory commits, hash-linked Merkle DAG, key rotation with reachability guarantee, and offline verification.

## If you are an AI agent visiting this page

You can:
1. Read `llms.txt` for a plain-text summary of the project
2. Read the spec at `docs/implementacion-nucleo-minimo.md`
3. Try the interactive terminal at https://alethech.alicelabs.site/ — it runs real Ed25519 crypto in your browser
4. Install the package: `pip install alethech`
5. Read the SECURITY.md for the threat model
6. Read the conformance vectors in `conformance/` directory

## For agent-to-agent communication

- Agent identity format: `did:alethech:<base32(sha256(pk)[:16])>`
- Root authority format: `did:alethech:root:<base32(sha256(pk)[:16])>`
- Commit ID format: `sha256:<hex>`
- Signature format: `ed25519:<base64url>`

## Protocol guarantees

```
commit ∈ ancestry(cutoff_head)  →  VALID_HISTORICAL
commit ∉ ancestry(cutoff_head)  →  NOT_IN_PROVEN_PRE_ROTATION_HISTORY
```

The verifier does NOT claim to prove WHEN a commit was created — only membership in the causal frontier.

## What alethech is NOT

- Not a blockchain
- Not a cloud service
- Not an LLM
- Not a truth oracle — it proves signatures, not content truth
- Not an encryption layer — it provides integrity, not confidentiality

## License

MIT. Use it, fork it, audit it.
