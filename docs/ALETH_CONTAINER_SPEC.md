# ALETH Container Format v1 — Draft

Status: **0.9 development contract**. This document defines the portable encrypted
container; it does not replace the Alethech protocol object specifications.

## 1. Goal

A single `.aleth` file MUST be sufficient to move an Alethech memory history
between compatible devices/runtimes without an Alethech account, server, cloud,
LLM, or blockchain. Storage providers may treat the file as an opaque blob.

The container provides **confidentiality and transport integrity**. Existing
Alethech signatures, identities, control events, checkpoints and hash-linked DAG
provide **protocol authenticity and continuity** after decryption. These are
separate guarantees.

## 2. Binary envelope

All integers are unsigned big-endian.

```
offset  size        value
0       8           ASCII "ALETH001"
8       4           header_length
12      N           UTF-8 JCS header
12+N    remaining   AEAD ciphertext || authentication tag
```

The header is authenticated as AEAD associated data and is intentionally small.
It MUST NOT contain memory content, agent_id, filenames, commit IDs, or other
user history.

### Header v1

```json
{
  "cipher": "AES-256-GCM",
  "format": "aleth",
  "kdf": "scrypt",
  "nonce": "<base64url 12 bytes>",
  "salt": "<base64url 16 bytes>",
  "scrypt_n": 32768,
  "scrypt_p": 1,
  "scrypt_r": 8,
  "version": 1
}
```

Readers MUST reject unknown versions, algorithms, invalid parameter sizes, or
unsupported KDF parameters before attempting payload parsing.

## 3. Key derivation and encryption

v1 passphrase mode:

- Passphrase input is UTF-8 encoded.
- KDF: scrypt, N=32768, r=8, p=1, output length=32 bytes.
- Salt: 16 cryptographically random bytes per container.
- AEAD: AES-256-GCM.
- Nonce: 12 cryptographically random bytes per container.
- Associated data: the exact JCS header bytes stored in the envelope.

A wrong passphrase, modified header, modified ciphertext, truncated file, or
modified authentication tag MUST fail closed and MUST expose no plaintext.

No custom cryptographic primitive is defined by Alethech.

## 4. Plaintext payload

After AEAD authentication, plaintext is UTF-8 JCS JSON:

```json
{
  "files": {
    "HEAD": "<base64url bytes>",
    "commits/sha256:....json": "<base64url bytes>"
  },
  "payload_version": 1
}
```

Paths MUST be relative POSIX paths. Readers MUST reject absolute paths, `..`,
empty path components, backslashes, duplicate normalized paths, symlinks, and
entries outside the allow-list.

v1 allow-list:

- `HEAD`
- `root_authority.json` (public record only)
- `identities/*.json`
- `commits/*.json`
- `evidence/*.json`
- `artifacts/*`
- `control_events/*.json`
- `migrations/*.json`
- `checkpoints/*.json`
- `keys/signing.key`

### Private-key rule

`keys/signing.key` MAY be included so the receiving device can continue the
operational history after unlocking the encrypted container.

`keys/root.key` and `keys/recovery.key` MUST NOT be included in a v1 portable
memory container. Root/recovery authority remains separately backed up. A
portable memory file is therefore not a complete identity-recovery backup.

## 5. Open algorithm

A conforming reader MUST perform these stages in order:

1. Validate magic and bounded header length.
2. Parse header and validate exact v1 algorithms/parameters.
3. Derive key and authenticate/decrypt the complete ciphertext.
4. Parse payload and enforce payload limits/path confinement.
5. Materialize only into a new or explicitly empty destination.
6. Run the normal Alethech verifier on the materialized store.
7. Return usable memory only if the verifier succeeds.

No unauthenticated plaintext may be materialized.

## 6. Resource limits

Reference implementations MUST enforce configurable limits before materializing.
Initial reference defaults:

- container: 512 MiB
- header: 16 KiB
- files: 100,000
- decoded single file: 100 MiB
- decoded total payload: 512 MiB

Implementations may choose stricter limits but MUST fail explicitly.

## 7. Threat boundaries

v1 is designed to detect/fail on ciphertext or header modification, wrong
passphrase, truncation, malformed payload, path traversal, unexpected private
keys, protocol-object tampering, and artifact/hash corruption.

v1 does **not** prove physical creation time, prevent an attacker from deleting
all copies, prevent rollback to an older independently valid container without
an external checkpoint, protect plaintext after a trusted host unlocks it, or
recover a forgotten passphrase.

## 8. Interoperability contract

Python, Rust and TypeScript implementations MUST eventually be able to open the
same v1 container and obtain the same payload bytes and protocol-verification
result. Cross-runtime golden containers will become normative before v1 freeze.
