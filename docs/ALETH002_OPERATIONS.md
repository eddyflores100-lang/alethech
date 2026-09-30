# Portable encrypted memory: operating guide

The portable deliverable is one `.aleth` file. The Python CLI, TypeScript/Rust
helpers and local browser extension operate on that same file. Chat adapters
receive selected verified memories, not the encrypted envelope's credentials.

## Python CLI

Install the current repository version, then create your local identity:

```bash
git clone --branch codex/v090-completion https://github.com/eddyflores100-lang/alethech.git
cd alethech
python -m pip install .
python -m alethech.cli --store ./memory-store init
```

No account registration is required. Use `alethech container --help`. Commands prompt for
credentials without displaying them. For automation, pass credential files
using the options listed by each command's `--help`.

```bash
alethech --store ./memory-store container seal ./memory.aleth --recovery-output ./recovery.txt
alethech container open ./memory.aleth ./opened-store
alethech container recover ./memory.aleth ./recovered.aleth
alethech container rekey ./memory.aleth ./rekeyed.aleth
alethech container upgrade ./legacy.aleth ./upgraded.aleth --recovery-output ./upgrade-recovery.txt
```

Recovery and upgrade verify the entire signed history before saving. Store the
recovery file separately from the encrypted memory file. Recovery rotation is
explicit and requires a destination for the new recovery code. Migration
preserves its source unless `--replace-source` is supplied. Unsupported
multi-credential recovery configurations fail before changing output.

Encrypted files are published through private temporary files and atomic
replacement. Plaintext stores are verified in private staging directories
before they become visible at the requested destination. A successful rename
is the publication boundary; directory fsync is best effort on supported
platforms because a durability warning must not hide a generated credential.

## Browser extension

Build with `bash scripts/build_extension.sh` and load `extension/dist` as an
unpacked Manifest V3 extension, or download the package from the CI artifact.
The build requires Rust, the `wasm32-unknown-unknown` target, Node.js and
`wasm-bindgen-cli` exactly `0.2.129`.

1. Drop a memory file and unlock it with its passphrase.
2. For forgotten-passphrase recovery, use the recovery form while locked.
   Choose a new passphrase and explicitly select code rotation if desired.
3. After verification, add recovery to a legacy file, append signed memory,
   change the passphrase, select memories for chat, or accept reviewed writeback.
4. Save the downloaded file. Subsequent operations in that popup use the latest
   downloaded envelope and its current passphrase.

All operations are local. No network/host permissions or browser storage are
requested. Editing a v2 file preserves its version, container ID and recovery
slot. Choosing a different file invalidates unfinished operations and clears
displayed secrets. Old independent file copies retain their original access
credentials after a new file is created or rotated.

## TypeScript and Rust

The helper CLIs support `open-pass`, `open-recovery`, `seal`, `recover`, and
`migrate`. `seal` accepts a payload JSON file and optional public-format
recovery secret; `recover --rotate-recovery` and `migrate --replace-source` are
explicit operations. SDK envelope readers authenticate/decode; writer
operations verify signed history before any output replacement.

TypeScript uses the portable protocol verifier. The Rust v2 CLI invokes
the matching installed/local Python Alethech verifier through a fixed local
subprocess with payload on stdin. Python 3 and the package are required for
Rust v2 reader/writer/recovery/migration operations; missing verification fails closed.
The ALETH001 envelope reader remains native. This dependency is explicit until
the Rust protocol verifier covers governance, migrations and checkpoints.

## Verification

```bash
python -m pytest -q
python conformance/container_v2/check.py
python conformance/container_v2/writer_matrix.py
node scripts/browser-tests/e2e.mjs
```

Build the Rust helpers and the extension, and install the pinned browser-test
dependencies before those commands. CI runs these prerequisites. The reader
matrix includes authenticated malformed schemas; the writer matrix checks
payload equality and protocol validity across all runtimes, credential rotation,
source preservation and forged-ancestor rejection. The browser suite loads the
actual unpacked extension and independently verifies downloaded files in Python.
