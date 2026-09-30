# Alethech Browser Extension — development shell

This is the first local-only drag-and-drop client for the portable `.aleth`
format.

Security boundary:

1. WASM authenticates/decrypts the encrypted envelope locally.
2. TypeScript verifies the complete supported Alethech history before exposing memory.
3. The popup may append a new MemoryCommit only with the portable operational signing key.
4. The updated payload is verified again before WASM reseals a new encrypted .aleth file.
5. Provider-neutral chat context is generated only from the verified memory view.

The extension has **no host permissions and no network permissions**. It does
not upload the file, passphrase, plaintext, or signing key. The passphrase is
cleared after each unlock/reseal operation. No browser storage APIs are used;
decrypted state exists only in the lifetime of the extension popup.

Current browser verifier scope is fail-closed and covers legacy V1 identities,
IdentityRecordV2 + RootAuthority, ControlEvent governance, bilateral migrations,
MemoryCommit history, EvidenceCommit provenance, artifact hashes, DAG/HEAD,
signed checkpoints, revoked-key cutoff ancestry, and portable signing-key
binding. Root and recovery private keys are forbidden in portable payloads.

Build:

```bash
cargo install wasm-bindgen-cli --version 0.2.129 --locked
bash scripts/build_extension.sh
```

Then load `extension/dist` as an unpacked Manifest V3 extension.


## Neutral context adapter

After cryptographic verification, `alethech-ts/context-adapter.ts` converts the
verified memory view into a backend-neutral `alethech-context` object. It carries
memory content, provenance, timestamps, commit IDs, and the verified source HEAD,
but never private keys or raw protocol files. Future chat/provider adapters should
consume this verified context rather than parsing `.aleth` directly.


## Continue memory locally

After verification, the popup can append one new signed MemoryCommit to the
current history and download a newly encrypted `.aleth`. The operation uses only
the portable operational signing key already inside the encrypted payload; root
and recovery authority remain separate. The updated payload must pass the full
portable verifier before it can be resealed.

The extension does not overwrite the original file. Each continuation produces a
new downloadable `*-updated.aleth` container.

## Cross-platform filenames

Local filesystem stores use percent-encoded physical filenames such as
`sha256%3A...` and `did%3Aalethech%3A...` so they are valid on Windows,
macOS, and Linux. Signed protocol identifiers remain unchanged, and `.aleth`
containers expose the canonical logical paths with `sha256:` / `did:alethech:`.
Legacy stores that used raw colons remain readable.


## Granular sharing

The extension verifies the complete dropped `.aleth` history locally, but chat
bridges only receive the memories the user explicitly selects in the popup.

The verified global `source_head` is still attached to the outgoing
`alethech-context@1` so writeback remains bound to the exact verified history
used to prepare the provider request.

Selection rules:

- unselected memories are omitted from provider context;
- selected commit IDs must exist in the verified memory view;
- unknown IDs fail closed;
- memory type filters are validated;
- selection never exposes raw protocol files or private keys.


## Passphrase rotation

After a container is unlocked and verified locally, the popup can re-encrypt the
same verified payload under a new passphrase and download a new `.aleth`.

This operation changes only the encryption envelope. It does not create a
MemoryCommit, change HEAD, rotate agent keys, or modify provenance.

The new passphrase is used only in memory for the local reseal operation and is
not persisted by the extension.
