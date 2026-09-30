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

Current browser verifier scope is intentionally fail-closed: legacy V1 identity
+ MemoryCommit history. Evidence/V2 governance/checkpoints are rejected until
their browser verifiers are implemented.

Build:

```bash
cargo install wasm-bindgen-cli --version 0.2.129 --locked
bash scripts/build_extension.sh
```

Then load `extension/dist` as an unpacked Manifest V3 extension.
