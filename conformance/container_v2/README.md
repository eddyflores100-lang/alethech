# ALETH002 frozen envelope vector

`golden.vector` is JSON containing one frozen, synthetic signed store, its
encrypted envelope, SHA-256 digest, expected decoded payload and public test
credentials. Private signing keys are excluded. Unlock credentials are intentionally public
test values and must never be used for real memory. Do not regenerate this vector in CI: it
must detect compatibility regressions against previously produced bytes.

Run `python conformance/container_v2/check.py` from the repository root after
building the Rust `alethech-container-v2` binary. Python, TypeScript and Rust
are all required by default; a missing runtime fails the check. Each reader
must accept passphrase and recovery, produce the exact frozen payload, and
reject wrong credentials, a modified tag and truncation.

For explicit partial local checks use `--runtime python --runtime typescript`.
Node 24 users can add `--typescript-command 'node --experimental-strip-types'`
to run without the tsx CLI. A partial run does not certify all three runtimes.

Pytest separately opens this vector through the public API and checks the
signed history, HEAD and Unicode memory. Reader conformance alone does not
certify a writer, browser recovery UI or full protocol verification in each
language. The `.vector` suffix keeps this envelope fixture separate from the
protocol-object JSON vector discovery.
