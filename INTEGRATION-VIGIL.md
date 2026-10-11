# Integration: alethech + vigil — fail-closed memory verification for autonomous agents

> Make a watchdog *prove* your memory chain is intact on every pass — and refuse to operate when it isn't.
>
> © 2026 AliceLabs LLC. Todos los derechos reservados.

## STATUS — read this first

**Running in production since 2026-10-10. Chain state at time of writing: 54 commits verified, 0 invalid, vault pointer matching.**

What this pattern adds on top of the protocol:
- A two-layer watchdog where layer 1 runs `alethech verify` **fail-closed** on every pass
- A one-command writeback loop (encrypted vault → signed pointer commit → verify)
- An errors-as-commits discipline: operational lessons become signed procedural commits, so the audit trail covers what the agent *learned*, not just what it *knew*

## Why

An agent that trusts memory without proving integrity will eventually act on tampered, corrupted, or silently drifted state. Classic watchdogs check "is the service up". This pattern checks "is the memory *provable*" — and treats an unverifiable chain exactly like a missing one. The protocol already gives you the guarantees; vigil is the operational harness that keeps those guarantees continuously true instead of occasionally checked.

## The two-layer pattern

| Layer | Where | What it does | Failure semantics |
|---|---|---|---|
| 1 — sandbox vigil | inside the agent host | endpoint checks + `alethech verify` fail-closed + vault integrity probe + reversible level-1 remediation | exit 0 OK / 1 degraded / 2 critical; remediate then re-verify |
| 2 — external watchdog | separate CI runner (zero secrets, zero write access) | re-derives public checks and alarms when layer 1 goes quiet | detects *silence*, not just failure — survives a compromised host |

Design rules (learned the hard way, each one is a signed procedural commit in our chain):

1. **Fail-closed, never fail-open.** If `alethech verify` does not end in `result: OK`, memory is treated as *absent*, not stale. No reads, no writes, no remediation that touches history.
2. **Verify through the real interface.** Run the exact CLI/SDK invocation your agent uses. A subprocess that inherits a different `PATH` can fail to find the CLI and look like a broken chain — test the real call path, not a convenient one.
3. **Write side effects only after verify.** The writeback script aborts *before* signing anything if the chain is not OK. There is never a half-written loop.
4. **Reversible remediation only.** Layer 1 may re-deploy a worker, re-seal a vault pointer, or rebuild a backup — never rewrite, prune, or "repair" history. History integrity is the product.

## The one-command writeback loop

`examples/memory_writeback.sh` closes the loop between the encrypted portable container and the hash-linked chain:

```
[1/3] vault sync      # refresh the encrypted .aleth container, print its new sha256
[2/3] pointer commit  # sign {"type":"memory-vault","vault_sha256":...} into the chain
[3/3] verify          # alethech verify — assert "result: OK" or ABORT
```

Result: the encrypted container and the signed chain always agree. Any disagreement is detected within one watchdog pass (seconds on demand, ≤6h unattended in our production setup).

## Errors become commits

When an operational mistake happens (a false negative, a PATH quirk, a summary that drifted from disk), the fix is captured twice:

- a bullet in the agent's `LESSONS.md` (readable, greppable), and
- a signed **procedural commit** in the alethech chain (tamper-evident).

A later session can `alethech recall` the lesson *with proof it was not edited after the fact*. That is the difference between a notes file and a memory you can defend.

## Minimal harness sketch

```python
import subprocess, sys

def check_chain(store: str) -> bool:
    """Fail-closed: anything that is not 'result: OK' is a failure."""
    r = subprocess.run(
        ["alethech", "--store", store, "verify"],
        capture_output=True, text=True, timeout=120,
    )
    return "result: OK" in (r.stdout + r.stderr)

if not check_chain("/path/to/.alethech"):
    sys.exit(2)   # watchdog: degraded — page, alert, or remediate (reversibly)
```

## What production showed

- 54/54 commits verified across all watchdog passes since activation; zero invalid, zero missing parents.
- The fail-closed check caught a real environment quirk (subprocess `PATH` missing the CLI install dir) on its first pass — a false negative that a naive "exit code only" check would have reported as a healthy chain.
- The external layer runs with zero credentials, so it cannot become a lateral-movement path if the agent host is compromised.

## Files

- `examples/memory_writeback.sh` — the one-command loop (vault sync hook + signed pointer + verify assert)
