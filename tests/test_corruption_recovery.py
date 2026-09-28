"""Adversarial tests for corruption and recovery — priority #2.

Central question: does the verifier fail closed, or is there a path
where corrupt data ends up treated as valid?

Tests:
1. Truncated commit JSON
2. Corrupt signature (random bytes)
3. Parent pointing to nonexistent commit
4. Duplicate commit files with different content
5. Corrupt ControlEvent (modified field)
6. Corrupt checkpoint (modified signature)
7. Corrupt incomplete_compensation record
8. Empty commit file
9. Non-JSON content in commit file
10. Missing identity file referenced by commit
"""
import json
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech.cli import cli
from alethech.store import Store
from alethech.verify import verify_store


@pytest.fixture
def tmp_store():
    d = tempfile.mkdtemp(prefix="alethech-corr-")
    p = Path(d) / "alethech"
    yield p
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def populated(tmp_store, runner):
    """Store with init + migrate + commit + evidence."""
    runner.invoke(cli, ["--store", str(tmp_store), "init"])
    runner.invoke(cli, ["--store", str(tmp_store), "migrate", "--to", "v0.2"])
    c = tmp_store / "c.json"
    c.write_text(json.dumps({"v": 1}))
    runner.invoke(cli, ["--store", str(tmp_store), "commit", "--content", str(c)])
    inp = tmp_store / "in.txt"
    out = tmp_store / "out.txt"
    inp.write_text("input")
    out.write_text("output")
    runner.invoke(cli, ["--store", str(tmp_store), "evidence", "--tool", "fs.read", "--input", str(inp), "--output", str(out)])
    return tmp_store


def _verify(store_path):
    """Run verify and return (exit_code, output)."""
    runner = CliRunner()
    r = runner.invoke(cli, ["--store", str(store_path), "verify"])
    return r.exit_code, r.output


# ============ 1. Truncated JSON ============

class TestTruncatedJSON:
    def test_truncated_commit_json_detected(self, populated):
        """Truncated JSON should not crash verify — should report as corrupted."""
        commit_files = list((populated / "commits").glob("*.json"))
        assert len(commit_files) >= 2
        target = commit_files[-1]
        # Truncate to half
        content = target.read_text()
        target.write_text(content[:len(content) // 2])

        code, output = _verify(populated)
        # verify should either FAIL or report error — NOT crash with traceback
        assert code != 0 or "FAIL" in output, f"should detect truncated JSON: {output}"

    def test_empty_commit_file_detected(self, populated):
        """Empty commit file should be detected as corrupted."""
        commit_files = list((populated / "commits").glob("*.json"))
        target = commit_files[-1]
        target.write_text("")

        code, output = _verify(populated)
        assert code != 0 or "FAIL" in output, f"should detect empty file: {output}"


# ============ 2. Corrupt signature ============

class TestCorruptSignature:
    def test_random_bytes_signature_detected(self, populated):
        """Signature with random bytes should fail verification."""
        commit_files = list((populated / "commits").glob("*.json"))
        target = commit_files[-1]
        data = json.loads(target.read_text())
        data["signature"] = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        target.write_text(json.dumps(data, indent=2))

        code, output = _verify(populated)
        assert "signature_invalid" in output or "FAIL" in output, \
            f"should detect corrupt signature: {output}"


# ============ 3. Parent pointing to nonexistent commit ============

class TestMissingParent:
    def test_nonexistent_parent_detected(self, populated):
        """Commit with parent pointing to nonexistent commit should be detected."""
        commit_files = list((populated / "commits").glob("*.json"))
        target = commit_files[-1]
        data = json.loads(target.read_text())
        data["parents"] = ["sha256:nonexistent000000000000000000000000000000000000000000000000"]
        # Re-sign not needed — we're testing verify, not signing
        # But commit_id will mismatch because content changed
        # So verify will report content_modified, which is also a failure
        target.write_text(json.dumps(data, indent=2))

        code, output = _verify(populated)
        assert "FAIL" in output or "content_modified" in output or "parent_missing" in output, \
            f"should detect bad parent: {output}"


# ============ 4. Duplicate commit files with different content ============

class TestDuplicateDifferentContent:
    def test_two_files_same_id_different_content(self, populated):
        """FIXED: load_commits() now detects duplicate commit_ids and raises StoreError.
        
        Two files with same commit_id but different content now cause
        verify to fail with 'duplicate commit_id' error.
        """
        commit_files = list((populated / "commits").glob("*.json"))
        target = commit_files[-1]
        data = json.loads(target.read_text())
        data["content"] = {"tampered": True}
        dup = populated / "commits" / f"dup_{target.name}"
        dup.write_text(json.dumps(data, indent=2))

        code, output = _verify(populated)
        assert "FAIL" in output or code != 0, \
            f"should detect duplicate commit_id: {output}"


# ============ 5. Corrupt ControlEvent ============

class TestCorruptControlEvent:
    def test_modified_control_event_field(self, populated):
        """FIXED: verify_store now calls verify_identity_layer.
        
        A modified ControlEvent (changed field, same signature) is now
        detected because verify checks the ControlEvent chain.
        """
        ce_dir = populated / "control_events"
        if not ce_dir.is_dir() or not list(ce_dir.glob("*.json")):
            pytest.skip("no control events in store")
        ce_file = list(ce_dir.glob("*.json"))[0]
        data = json.loads(ce_file.read_text())
        data["reason"] = "compromise"
        ce_file.write_text(json.dumps(data, indent=2))

        code, output = _verify(populated)
        assert "FAIL" in output or "control_chain" in output or "signature_invalid" in output, \
            f"should detect corrupt ControlEvent: {output}"


# ============ 6. Corrupt checkpoint ============

class TestCorruptCheckpoint:
    def test_modified_checkpoint_signature(self, populated, runner):
        """Create a checkpoint, then modify its signature — verify should reject."""
        cp_path = populated.parent / "cp.json"
        r = runner.invoke(cli, ["--store", str(populated), "verify", "--emit-checkpoint", str(cp_path)])
        if r.exit_code != 0 or not cp_path.is_file():
            pytest.skip("checkpoint generation failed")

        data = json.loads(cp_path.read_text())
        data["signature"] = "ed25519:AAAA"
        cp_path.write_text(json.dumps(data, indent=2))

        r = runner.invoke(cli, ["--store", str(populated), "verify", "--checkpoint", str(cp_path)])
        assert r.exit_code != 0
        assert "checkpoint_signature_invalid" in r.output or "FAIL" in r.output, \
            f"should detect corrupt checkpoint: {r.output}"


# ============ 7. Corrupt incomplete_compensation ============

class TestCorruptIncompleteCompensation:
    def test_corrupt_incomplete_compensation_doesnt_crash(self, populated):
        """A corrupt incomplete_compensation file should not crash the hook."""
        comp_dir = populated / "incomplete_compensations"
        comp_dir.mkdir(parents=True, exist_ok=True)
        # Write a corrupt file
        (comp_dir / "corrupt.json").write_text("{invalid json")

        # Verify should still work (incomplete_compensations are not part of verify)
        code, output = _verify(populated)
        # verify doesn't check incomplete_compensations, so it should pass
        # as long as the rest of the store is OK
        assert "result: OK" in output or code == 0, \
            f"verify should ignore corrupt incomplete_compensation: {output}"


# ============ 8. Non-JSON content ============

class TestNonJSONContent:
    def test_non_json_commit_file(self, populated):
        """A commit file with non-JSON content should be handled gracefully."""
        commit_files = list((populated / "commits").glob("*.json"))
        target = commit_files[-1]
        target.write_text("this is not json at all {{{{ ")

        code, output = _verify(populated)
        assert code != 0 or "FAIL" in output, f"should handle non-JSON: {output}"
        # Should NOT be an unhandled crash — should report as corrupted
        assert "Traceback" not in output or "corrupted" in output.lower(), \
            f"should report corruption, not crash: {output[:200]}"


# ============ 9. Missing identity file ============

class TestMissingIdentity:
    def test_identity_file_deleted(self, populated):
        """If identity file is deleted, verify should report it."""
        id_files = list((populated / "identities").glob("*.json"))
        assert len(id_files) >= 1
        id_files[0].unlink()

        code, output = _verify(populated)
        assert "FAIL" in output or "unknown_identity" in output or code != 0, \
            f"should detect missing identity: {output}"


# ============ 10. Verify fails closed (summary test) ============

class TestFailClosed:
    """Meta-test: verify should NEVER return OK when there's corruption."""

    @pytest.mark.parametrize("corruption", [
        "truncate_commit",
        "empty_commit",
        "corrupt_sig",
        "non_json",
        "delete_identity",
    ])
    def test_verify_fails_closed(self, populated, corruption):
        """For each corruption type, verify must NOT return OK."""
        commit_files = list((populated / "commits").glob("*.json"))
        id_files = list((populated / "identities").glob("*.json"))

        if corruption == "truncate_commit" and commit_files:
            c = commit_files[-1].read_text()
            commit_files[-1].write_text(c[:len(c) // 2])
        elif corruption == "empty_commit" and commit_files:
            commit_files[-1].write_text("")
        elif corruption == "corrupt_sig" and commit_files:
            data = json.loads(commit_files[-1].read_text())
            data["signature"] = "ed25519:AAAA"
            commit_files[-1].write_text(json.dumps(data, indent=2))
        elif corruption == "non_json" and commit_files:
            commit_files[-1].write_text("not json {{{")
        elif corruption == "delete_identity" and id_files:
            id_files[0].unlink()

        code, output = _verify(populated)
        assert "result: OK" not in output, \
            f"verify returned OK with corruption={corruption} — FAIL CLOSED violated!"
