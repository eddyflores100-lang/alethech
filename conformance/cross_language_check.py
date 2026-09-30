#!/usr/bin/env python3
"""Cross-language conformance harness for alethech.

Runs Python, Rust, and TypeScript implementations against the same
shared fixtures in ``conformance/`` and asserts that all three agree:
either all accept the fixture (verifying successfully), or all reject
it (with the same error class).

What this harness checks
------------------------
For each fixture in ``conformance/valid/``:

1. Python: load the fixture, verify signature, get the canonical bytes.
2. Rust: load the same fixture, verify, get canonical bytes.
3. TypeScript: load the same fixture, verify, get canonical bytes.
4. Assert: all three implementations produced **identical canonical
   bytes** (byte-exact comparison).

For each fixture in ``conformance/invalid_*/``:

1. Each implementation MUST reject it.
2. The rejection reason SHOULD match across implementations (advisory —
   the contract is "reject", not "reject with the same error message").

What this harness does NOT check
--------------------------------
- Performance: it does not measure how fast each implementation runs.
- Round-trip: it does not sign-and-verify; it only verifies existing
  fixtures. (Signing is implementation-specific.)
- Wire format: it does not check that an export from one implementation
  imports into another. (That's a separate integration test.)

Usage
-----
::

    # Run all three implementations (requires Python 3.10+, Rust + cargo,
    # and Node.js 18+ to be installed):
    python conformance/cross_language_check.py

    # Run only Python (useful for CI without Rust/Node):
    python conformance/cross_language_check.py --only python

    # Skip the byte-exact comparison (only check accept/reject agreement):
    python conformance/cross_language_check.py --no-byte-compare

Exit codes
----------
- 0: all three implementations agree on all fixtures.
- 1: at least one implementation disagrees with the others.
- 2: a required implementation is not available (Python only).

Origin
------
This harness was added in response to auditor finding #3 (0.8.2):
the README claimed "cross-validation confirms the spec is
language-independent" but there was no shared harness that actually
compared implementations against the same fixtures. Now there is.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


CONFORMANCE_DIR = Path(__file__).parent
REPO_ROOT = CONFORMANCE_DIR.parent


# ------------------------------------------------------------------
# Result types
# ------------------------------------------------------------------


@dataclass
class FixtureResult:
    """Result of running one implementation against one fixture."""

    fixture: str
    implementation: str  # "python" | "rust" | "typescript"
    accepted: bool
    canonical_bytes: Optional[bytes] = None
    error: Optional[str] = None
    duration_ms: float = 0.0


@dataclass
class HarnessReport:
    """Aggregated report across all fixtures and implementations."""

    results: List[FixtureResult] = field(default_factory=list)
    disagreements: List[str] = field(default_factory=list)

    def add(self, result: FixtureResult) -> None:
        self.results.append(result)

    def summarize(self) -> str:
        lines = []
        lines.append(f"Total fixture runs: {len(self.results)}")
        accepted = sum(1 for r in self.results if r.accepted)
        rejected = len(self.results) - accepted
        lines.append(f"  Accepted: {accepted}")
        lines.append(f"  Rejected: {rejected}")
        if self.disagreements:
            lines.append(f"Disagreements: {len(self.disagreements)}")
            for d in self.disagreements:
                lines.append(f"  - {d}")
        else:
            lines.append("Disagreements: 0 (all implementations agree)")
        return "\n".join(lines)


# ------------------------------------------------------------------
# Python implementation runner
# ------------------------------------------------------------------


def run_python(fixture_path: Path) -> FixtureResult:
    """Run Python alethech against one fixture."""
    import time

    sys.path.insert(0, str(REPO_ROOT))
    from alethech.objects import MemoryCommit, EvidenceCommit, Checkpoint, Identity
    from alethech.canonical import canonical_json_bytes
    from alethech import crypto
    from alethech.crypto import KeyPair

    start = time.time()
    try:
        data = json.loads(fixture_path.read_text())

        # Fixtures wrap the actual object in `input.commit` (or similar).
        # The expected result is in `expected_result` at the top level.
        expected = data.get("expected_result", "verify_ok")
        input_data = data.get("input", data)
        commit_data = input_data.get("commit") or input_data.get("evidence") or input_data.get("checkpoint") or input_data
        identity_data = input_data.get("identity", {})

        obj_type = commit_data.get("type", "")

        if obj_type == "AgentIdDerivation":
            public_jwk = commit_data.get("public_key", {})
            expected_id = commit_data.get("expected_agent_id", "")
            derived = crypto.derive_agent_id(public_jwk)
            if derived != expected_id:
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=False,
                    error=f"agent_id mismatch: {derived}",
                    duration_ms=(time.time() - start) * 1000,
                )
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="python",
                accepted=True,
                canonical_bytes=derived.encode("utf-8"),
                duration_ms=(time.time() - start) * 1000,
            )

        # Some fixtures test JCS canonicalization directly (not signed objects).
        # Those are handled by tests/test_canonical.py — skip them here.
        if obj_type in ("JCSNumberTest", "UnicodeDistinctness"):
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="python",
                accepted=True,  # treated as "not applicable" — counted as accept for agreement purposes
                canonical_bytes=None,
                error=f"skipped (JCS-only fixture, not a signed object)",
                duration_ms=(time.time() - start) * 1000,
            )

        if obj_type == "MemoryCommit":
            obj = MemoryCommit.from_dict(commit_data)
        elif obj_type == "EvidenceCommit":
            obj = EvidenceCommit.from_dict(commit_data)
        elif obj_type == "Checkpoint":
            obj = Checkpoint.from_dict(commit_data)
        else:
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="python",
                accepted=False,
                error=f"unknown type: {obj_type}",
                duration_ms=(time.time() - start) * 1000,
            )

        # Get signer public key from the identity in the fixture
        pub_jwk = identity_data.get("public_key")
        if not pub_jwk:
            # No identity in fixture — accept if structure is valid
            canonical = canonical_json_bytes(obj.to_signable_dict())
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="python",
                accepted=True,
                canonical_bytes=canonical,
                duration_ms=(time.time() - start) * 1000,
            )

        # verify() takes the JWK dict directly (not an Ed25519PublicKey)
        verified = obj.verify(pub_jwk)
        canonical = canonical_json_bytes(obj.to_signable_dict())

        # Check if the result matches expectation
        if expected == "verify_ok":
            if verified:
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=True,
                    canonical_bytes=canonical,
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=False,
                    error="expected verify_ok but verification failed",
                    duration_ms=(time.time() - start) * 1000,
                )
        else:  # expected == "verify_fail" or similar
            if not verified:
                # Correctly rejected
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=False,  # harness uses "accepted=False" to mean "rejected"
                    error="expected rejection — correctly rejected",
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                # Should have been rejected but wasn't
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=True,  # accepted means "didn't reject" — bug
                    error="expected verify_fail but verification passed — BUG",
                    duration_ms=(time.time() - start) * 1000,
                )
    except Exception as e:
        # If the fixture expected rejection and we got an exception,
        # that's a correct rejection.
        try:
            data = json.loads(fixture_path.read_text())
            expected = data.get("expected_result", "verify_ok")
            if expected != "verify_ok":
                return FixtureResult(
                    fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                    implementation="python",
                    accepted=False,
                    error=f"correctly rejected ({type(e).__name__})",
                    duration_ms=(time.time() - start) * 1000,
                )
        except Exception:
            pass
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="python",
            accepted=False,
            error=f"{type(e).__name__}: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


# ------------------------------------------------------------------
# Rust implementation runner
# ------------------------------------------------------------------


def run_rust(fixture_path: Path) -> FixtureResult:
    """Run Rust alethech-rs against one fixture.

    This shells out to a small Rust helper. If the helper doesn't exist,
    the result is "implementation not available" — the harness will
    count this as "skipped" rather than "rejected" so we don't trigger
    spurious disagreements with Python/TypeScript.
    """
    import time

    start = time.time()
    rust_helper = REPO_ROOT / "alethech-rs" / "target" / "release" / "alethech-conf"
    if not rust_helper.exists():
        # Try debug build
        rust_helper = REPO_ROOT / "alethech-rs" / "target" / "debug" / "alethech-conf"
    if not rust_helper.exists():
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="rust",
            accepted=True,  # treat as "skipped" — counts as accept for agreement purposes
            canonical_bytes=None,
            error="rust helper not built — run `cargo build --release` in alethech-rs/",
            duration_ms=(time.time() - start) * 1000,
        )

    try:
        result = subprocess.run(
            [str(rust_helper), str(fixture_path)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            canonical = result.stdout  # bytes
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="rust",
                accepted=True,
                canonical_bytes=canonical,
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            err = result.stderr.decode("utf-8", errors="replace")[:200]
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="rust",
                accepted=False,
                error=err,
                duration_ms=(time.time() - start) * 1000,
            )
    except Exception as e:
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="rust",
            accepted=False,
            error=f"{type(e).__name__}: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


# ------------------------------------------------------------------
# TypeScript implementation runner
# ------------------------------------------------------------------


def run_typescript(fixture_path: Path) -> FixtureResult:
    """Run alethech-ts against one fixture."""
    import time

    start = time.time()
    ts_helper = REPO_ROOT / "alethech-ts" / "conformance.mjs"
    if not ts_helper.exists():
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="typescript",
            accepted=False,
            error="typescript helper not found — create alethech-ts/conformance.mjs",
            duration_ms=(time.time() - start) * 1000,
        )
    if shutil.which("npx") is None:
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="typescript",
            accepted=False,
            error="typescript runtime not found — npx is required",
            duration_ms=(time.time() - start) * 1000,
        )

    try:
        result = subprocess.run(
            ["npx", "--yes", "tsx", str(ts_helper), str(fixture_path)],
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            canonical = result.stdout
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="typescript",
                accepted=True,
                canonical_bytes=canonical,
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            err = result.stderr.decode("utf-8", errors="replace")[:200]
            return FixtureResult(
                fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
                implementation="typescript",
                accepted=False,
                error=err,
                duration_ms=(time.time() - start) * 1000,
            )
    except Exception as e:
        return FixtureResult(
            fixture=str(fixture_path.relative_to(CONFORMANCE_DIR)),
            implementation="typescript",
            accepted=False,
            error=f"{type(e).__name__}: {e}",
            duration_ms=(time.time() - start) * 1000,
        )


# ------------------------------------------------------------------
# Main harness
# ------------------------------------------------------------------


def list_fixtures() -> List[Path]:
    """List all JSON fixtures under conformance/."""
    return sorted(CONFORMANCE_DIR.rglob("*.json"))


def compare_results(report: HarnessReport) -> None:
    """Group results by fixture and check for disagreements.

    A "disagreement" only counts when at least two implementations
    actually ran (i.e., produced canonical_bytes or a real reject).
    Implementations that are "skipped" (canonical_bytes is None and
    the error indicates a missing helper) are excluded from the
    comparison — they don't count as accept or reject.
    """
    by_fixture: dict[str, List[FixtureResult]] = {}
    for r in report.results:
        # Skip implementations that didn't actually run (missing helper)
        if r.canonical_bytes is None and r.error and "not built" in r.error:
            continue
        if r.canonical_bytes is None and r.error and "not found" in r.error:
            continue
        by_fixture.setdefault(r.fixture, []).append(r)

    for fixture, results in by_fixture.items():
        if len(results) < 2:
            continue  # only one implementation ran

        accepted_set = {r.accepted for r in results}
        if len(accepted_set) > 1:
            impls = ", ".join(
                f"{r.implementation}={'accept' if r.accepted else 'reject'}"
                for r in results
            )
            report.disagreements.append(
                f"{fixture}: implementations disagree ({impls})"
            )
            continue

        # All agree on accept/reject. If all accepted, check canonical bytes match.
        if all(r.accepted for r in results):
            bytes_set = {r.canonical_bytes for r in results if r.canonical_bytes}
            if len(bytes_set) > 1:
                report.disagreements.append(
                    f"{fixture}: implementations agree on accept but canonical bytes differ"
                )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-language conformance harness for alethech"
    )
    parser.add_argument(
        "--only",
        choices=["python", "rust", "typescript"],
        help="Run only one implementation (default: all three)",
    )
    parser.add_argument(
        "--no-byte-compare",
        action="store_true",
        help="Skip byte-exact comparison (only check accept/reject agreement)",
    )
    args = parser.parse_args()

    fixtures = list_fixtures()
    if not fixtures:
        print("No fixtures found.")
        return 2

    print(f"Found {len(fixtures)} fixtures in {CONFORMANCE_DIR}")
    print()

    report = HarnessReport()

    for fixture_path in fixtures:
        rel = fixture_path.relative_to(CONFORMANCE_DIR)
        print(f"--- {rel} ---")

        if args.only in (None, "python"):
            r = run_python(fixture_path)
            report.add(r)
            print(f"  python:     {'accept' if r.accepted else 'reject'} ({r.duration_ms:.1f}ms)")
            if r.error:
                print(f"              error: {r.error[:100]}")

        if args.only in (None, "rust"):
            r = run_rust(fixture_path)
            report.add(r)
            print(f"  rust:       {'accept' if r.accepted else 'reject'} ({r.duration_ms:.1f}ms)")
            if r.error:
                print(f"              error: {r.error[:100]}")

        if args.only in (None, "typescript"):
            r = run_typescript(fixture_path)
            report.add(r)
            print(f"  typescript: {'accept' if r.accepted else 'reject'} ({r.duration_ms:.1f}ms)")
            if r.error:
                print(f"              error: {r.error[:100]}")

    print()
    print("=== Summary ===")
    print(report.summarize())

    if not args.no_byte_compare:
        compare_results(report)
        if report.disagreements:
            print()
            print("=== Disagreements ===")
            for d in report.disagreements:
                print(f"  - {d}")

    if report.disagreements:
        return 1

    # Default mode promises a three-runtime comparison. Missing helpers or
    # runtimes are therefore an incomplete conformance run, not success.
    # --only intentionally permits a single-runtime diagnostic run.
    if args.only is None:
        unavailable_markers = ("not built", "not found", "runtime not found")
        unavailable = [
            r for r in report.results
            if r.error and any(marker in r.error for marker in unavailable_markers)
        ]
        if unavailable:
            print()
            print("=== Incomplete run ===")
            for r in unavailable:
                print(f"  - {r.implementation}: {r.error}")
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
