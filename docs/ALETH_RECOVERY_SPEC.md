# ALETH Container Recovery / Unlock v2 — Draft

Status: **partially implemented**. Python supports seal, open, migration and
recovery; TypeScript and Rust have envelope readers. Browser recovery/reseal UX
and TypeScript/Rust writers remain pending. See
[implementation status](ALETH002_PROGRESS.md) for verified scope.

This document defines the next container-envelope evolution needed for
passphrase recovery and future device unlock. It does not change the Alethech
identity/governance protocol.

## 1. Two different meanings of recovery

Alethech MUST keep these authorities separate:

1. **Identity recovery/governance**
   - RootAuthority
   - operational-key rotation/revocation
   - identity migration
   - protocol signatures

2. **Container unlock recovery**
   - decrypting one encrypted `.aleth` file
   - replacing a forgotten passphrase
   - adding/removing future device unlock methods

A container recovery credential MUST NOT authorize identity governance.
An identity root/recovery signing key MUST NOT automatically decrypt a
portable-memory container.

## 2. Why v1 cannot recover a forgotten passphrase

ALETH001 derives the AES-256-GCM payload key directly from the passphrase with
scrypt.

Therefore, if the passphrase is lost and no trusted unlocked session remains,
the payload key is gone. This is deliberate and honest behavior.

Recovery requires a different envelope architecture, so it belongs in v2
rather than a backward-incompatible reinterpretation of ALETH001.

## 3. ALETH002 key hierarchy

ALETH002 introduces a random Data Encryption Key (DEK):

```text
                    random 256-bit DEK
                           |
                           +-----------------------+
                           |                       |
                    payload AES-GCM          wrapped into slots
                                                   |
                               +-------------------+-------------------+
                               |                                       |
                         passphrase slot                         recovery slot
                         scrypt -> KEK                         secret -> HKDF -> KEK
                               |                                       |
                         AES-GCM(DEK)                           AES-GCM(DEK)
```

The payload is encrypted with the DEK.

Unlock credentials never encrypt the memory payload directly. They only unwrap
the DEK.

## 4. Binary envelope

```text
offset  size        value
0       8           ASCII "ALETH002"
8       4           header_length, unsigned big-endian
12      N           UTF-8 JCS header
12+N    remaining   payload AES-GCM ciphertext || tag
```

The exact header is authenticated as associated data by payload AES-GCM.

Changing unlock slots therefore requires resealing the payload. That is an
intentional v2 simplification: mutable unauthenticated slot metadata is not
allowed.

## 5. Header

Illustrative shape:

```json
{
  "container_id": "<base64url 16 random bytes>",
  "format": "aleth",
  "payload_cipher": "AES-256-GCM",
  "payload_nonce": "<base64url 12 random bytes>",
  "slots": [
    {
      "id": "passphrase-1",
      "kdf": "scrypt",
      "nonce": "<base64url 12 bytes>",
      "salt": "<base64url 16 bytes>",
      "scrypt_n": 32768,
      "scrypt_p": 1,
      "scrypt_r": 8,
      "type": "passphrase",
      "wrapped_key": "<base64url AES-GCM(DEK)>"
    },
    {
      "id": "recovery-1",
      "kdf": "HKDF-SHA256",
      "nonce": "<base64url 12 bytes>",
      "salt": "<base64url 16 bytes>",
      "type": "recovery-secret",
      "wrapped_key": "<base64url AES-GCM(DEK)>"
    }
  ],
  "version": 2
}
```

Readers MUST reject:

- unknown mandatory algorithms;
- duplicate slot IDs;
- malformed key/nonce/salt sizes;
- duplicate semantically equivalent slots when prohibited by policy;
- unsupported version;
- non-canonical header bytes.

## 6. Slot wrapping

### 6.1 Passphrase slot

1. UTF-8 encode passphrase.
2. Derive a 32-byte Key Encryption Key (KEK) using scrypt:
   - N=32768
   - r=8
   - p=1
   - per-slot random 16-byte salt
3. Wrap the 32-byte DEK using AES-256-GCM with a per-slot 12-byte nonce.
4. Associated data MUST bind:
   - `container_id`
   - slot `id`
   - slot `type`
   - envelope version

A wrong passphrase MUST fail at DEK unwrap before payload plaintext is exposed.

### 6.2 Recovery-secret slot

On v2 creation, implementations MAY generate one 32-byte cryptographically
random recovery secret.

The recovery secret:

- MUST NOT be stored plaintext inside `.aleth`;
- MUST NOT be uploaded by the permissionless core extension;
- MUST be shown/exported only through an explicit recovery setup action;
- SHOULD be stored offline by the user.

Derive the recovery KEK using HKDF-SHA256:

- input key material: recovery secret
- salt: per-slot random 16 bytes
- info: `"alethech-container-recovery-v1"`
- output: 32 bytes

Wrap the same DEK using AES-256-GCM.

The initial machine-readable representation is:

```text
aleth-recovery-v1:<base64url 32 bytes>
```

Human-friendly checksum/QR/mnemonic encodings may be added later without
changing the underlying 32-byte secret.

## 7. Recovery flow

```text
memory.aleth
    +
recovery secret
    |
unwrap DEK
    |
authenticate/decrypt payload
    |
full Alethech protocol verification
    |
user chooses new passphrase
    |
create new passphrase slot
    |
optionally rotate recovery secret
    |
reseal ALETH002
```

Recovery MUST NOT silently mutate MemoryCommit, EvidenceCommit, identity,
ControlEvent, MigrationRecord, checkpoint, or HEAD.

## 8. Passphrase rotation

With ALETH002, passphrase rotation is a slot-management operation plus payload
reseal:

1. unlock DEK with any currently authorized slot;
2. verify payload;
3. create a fresh passphrase slot with new salt/nonce;
4. remove/disable the old passphrase slot;
5. reseal the same verified payload with authenticated updated header.

A recovery secret may therefore replace a forgotten passphrase without giving
the recovery credential any identity-governance authority.

## 9. Future device slots

v2 reserves the concept of additional unlock slots but does not standardize
them yet.

Potential future slots:

- platform hardware-backed device key;
- OS keychain credential;
- organization-managed recipient key.

No future slot may weaken the rule that provider/chat bridges never receive the
DEK, passphrase, recovery secret, or private operational signing key.

## 10. Threat boundaries

v2 is intended to resist:

- wrong passphrase;
- wrong recovery secret;
- brute-force recovery-code guessing at 256-bit entropy;
- wrapped-DEK modification;
- slot metadata modification;
- slot replay from another container via `container_id` binding;
- header modification;
- payload ciphertext/tag modification;
- recovery secret used as identity authority.

v2 does not protect against:

- malware on a device after the user unlocks the container;
- loss of every unlock credential;
- coercion/social engineering;
- an attacker deleting every copy of the file;
- rollback to an older independently valid container without an external
  checkpoint.

## 11. No escrow

Alethech/AliceLabs MUST NOT require possession of:

- user passphrases;
- recovery secrets;
- DEKs;
- root private keys;
- operational private keys.

If every local unlock credential is lost, the file is unrecoverable by design.

## 12. v1 -> v2 migration

Migration requires a successfully authenticated ALETH001 container.

The implementation MUST:

1. unlock v1 with the existing passphrase;
2. validate the payload structure;
3. run full Alethech protocol verification;
4. generate a random v2 DEK;
5. create a passphrase slot;
6. optionally generate a recovery secret + recovery slot;
7. seal ALETH002;
8. verify/open the produced v2 container before reporting success.

The v1 source file MUST remain untouched unless the user explicitly requests
replacement after v2 verification succeeds.

## 13. Required adversarial tests before implementation is considered complete

- wrong passphrase cannot unwrap DEK;
- wrong recovery secret cannot unwrap DEK;
- modified wrapped key fails;
- modified slot nonce/salt fails;
- passphrase slot copied between containers fails because of container binding;
- recovery slot copied between containers fails;
- modified header fails;
- modified/truncated payload fails;
- v1 -> v2 migration preserves verified memory semantics;
- passphrase recovery preserves HEAD, commit IDs and signatures;
- rotating recovery secret invalidates the old recovery secret;
- Python/TypeScript/Rust produce interoperable v2 containers;
- browser extension can recover/reseal locally with no network permissions;
- recovery credential cannot sign/rotate identity governance objects.

## 14. Implementation gate

Do not implement ALETH002 until this contract is reviewed against:

- existing ALETH001 interoperability guarantees;
- browser WebCrypto availability;
- Rust/Python/TypeScript HKDF + AES-GCM behavior;
- resource limits;
- downgrade handling.

ALETH001 remains supported and valid. ALETH002 is an additive envelope version,
not a reinterpretation of v1.


## 15. Implementation gate review — PASS

Reviewed against the current runtimes before implementation:

- **Python**: the existing `cryptography` dependency already provides
  HKDF-SHA256 and AES-GCM. No new Python dependency is required.
- **Browser / TypeScript**: Web Crypto provides HKDF deriveBits/deriveKey and
  AES-GCM in secure contexts. The extension already uses Web Crypto and remains
  dependency-free at the JavaScript layer.
- **Rust**: existing AES-GCM/scrypt/sha2 support is sufficient except for HKDF.
  Use the RustCrypto `hkdf` crate rather than a custom implementation.
- **Resource limits**: v2 inherits the v1 header/container/file-count/decoded
  payload limits unless a later conformance revision tightens them.
- **Downgrade handling**: readers dispatch strictly by 8-byte magic
  (`ALETH001` vs `ALETH002`). A failed v2 parse MUST NOT retry the bytes as
  v1.
- **Migration**: v1 remains supported. v1 -> v2 is explicit and requires a
  successful v1 unlock + protocol verification.

Implementation order:

1. Python reference + adversarial tests.
2. Stable golden v2 fixture.
3. TypeScript/WebCrypto open + seal + recovery.
4. Rust open + seal + recovery.
5. Browser extension recovery UX.
6. Three-runtime conformance/mutation matrix.

No protocol-object schema changes are required for ALETH002.
