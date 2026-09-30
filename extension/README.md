# Alethech Browser Extension — development shell

This is the first local-only drag-and-drop client for the portable `.aleth`
format.

Security boundary:

1. WASM authenticates/decrypts the encrypted envelope locally.
2. TypeScript verifies the supported Alethech protocol history.
3. Only then is a neutral memory view rendered.

The extension has **no host permissions and no network permissions**. It does
not upload the file, passphrase, or plaintext. The passphrase is cleared after
each unlock attempt.

Current browser verifier scope is intentionally fail-closed: legacy V1 identity,
MemoryCommit history, EvidenceCommit provenance, artifact hashes, DAG/HEAD, and
portable signing-key binding are verified locally. V2 governance, migrations,
and checkpoints are still rejected until their browser verifiers are implemented.

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
