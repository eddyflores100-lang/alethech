# alethech-ts

TypeScript implementation of **alethech** — a verifiable agent continuity protocol. Ed25519-signed memory commits, hash-linked DAG, key rotation with reachability guarantee. Zero dependencies. Web Crypto API only.

This is the TypeScript SDK that mirrors the Python and Rust implementations. All three use the same NIST SHA-256 test vectors, RFC 4648 base32 vectors, and RFC 8785 JCS conformance vectors.

## Install

```bash
npm install alethech-ts
```

## Quick start

```typescript
import { Alethech } from "alethech-ts";

// Initialize a new store with an Ed25519 keypair
const alethech = await Alethech.init();

// Create a signed memory commit
const commitId = await alethech.commit({
  type: "semantic",
  category: "deployment",
  content: { service: "api-gateway", region: "us-east-1" },
});

// Verify the entire store integrity
const result = await alethech.verify();
console.log(result.ok); // true
console.log(result.commitsVerified); // 1

// Rotate keys — reachability guarantee: every existing commit stays verifiable
await alethech.rotateKeys();
const resultAfter = await alethech.verify();
console.log(resultAfter.ok); // true — old commits still verify against new key
```

## What it gives you

- **Signed memory commits.** Every state mutation is Ed25519-signed. Tampering with any byte of any commit breaks verification.
- **Hash-linked DAG.** Each commit links to its parent by SHA-256. History cannot be rewritten without regenerating every descendant signature.
- **Key rotation with reachability guarantee.** Rotate operational keys without losing verifiability of historical commits. The protocol tracks every authorized key, so old signatures stay valid under new keys.
- **Deterministic canonical JSON (RFC 8785 JCS).** Same bytes in, same hash out — across Python, Rust, and TypeScript. No float values allowed in the signed schema (see `FloatInSignedSchemaError` in the Python SDK).
- **Local-first.** Zero network calls. Zero LLM calls. Zero blockchain. Everything runs offline.

## API

### `Alethech.init(): Promise<Alethech>`

Create a new store with a fresh Ed25519 keypair. Returns the high-level API object.

### `alethech.commit(content: CommitContent): Promise<string>`

Sign and append a memory commit. Returns the commit ID (SHA-256 of the canonical payload).

### `alethech.verify(): Promise<VerifyResult>`

Walk the DAG from HEAD to genesis, verifying every Ed25519 signature. Returns `{ ok: boolean, commitsVerified: number, ... }`.

### `alethech.rotateKeys(): Promise<void>`

Generate a new Ed25519 keypair, authorize it, and revoke the old one. Old commits stay verifiable.

### `alethech.export(): Promise<ExportPackage>`

Serialize the entire store for transfer.

### `alethech.import(pkg: ExportPackage): Promise<void>`

Verify and import an export package. All signatures are verified before any write — fail-closed.

## Tests

```bash
npm test
# 15 tests, all green
```

Test coverage:
- 5 JCS conformance vectors (RFC 8785)
- 5 Ed25519 signing/verification vectors (RFC 8032)
- 5 store integrity vectors (DAG, key rotation, export/import)

## Zero dependencies

This package has **zero** runtime dependencies. It uses only:
- `crypto.subtle` (Web Crypto API, available in Node 18+, browsers, Deno, Bun)
- `TextEncoder` (built-in)
- `atob`/`btoa` (built-in)

No `tweetnacl`, no `node-forge`, no `jsrsasign`. If your runtime has Web Crypto, you can run alethech-ts.

## Cross-language compatibility

The same store can be exported from Python, imported into TypeScript, and verified. The same Ed25519 signatures verify in all three implementations. See `conformance/` in the repo root for shared test vectors.

## License

MIT — © 2026 AliceLabs LLC

## Links

- Protocol spec: https://github.com/eddyflores100-lang/alethech/blob/main/docs/
- Python SDK: https://pypi.org/project/alethech/
- Rust SDK: https://github.com/eddyflores100-lang/alethech/tree/main/alethech-rs
- Landing page: https://alethech.alicelabs.site/
