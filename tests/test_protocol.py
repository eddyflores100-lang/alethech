"""Tests for the alethech protocol — rev 2 spec.

Each test verifies a specific property of the spec.
"""
import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech import crypto
from alethech.canonical import canonical_json, canonical_json_bytes
from alethech.cli import cli
from alethech.objects import Identity, MemoryCommit, EvidenceCommit, Checkpoint
from alethech.store import Store
from alethech.verify import verify_store


# ---------- fixtures ----------

@pytest.fixture
def tmp_store_dir():
    d = tempfile.mkdtemp(prefix="alethech-test-")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def initialized_store(tmp_store_dir, runner):
    """Run `alethech init` in tmp_store_dir and return the path."""
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "init"])
    assert result.exit_code == 0, result.output
    return tmp_store_dir


# ---------- crypto primitives ----------

def test_sha256_is_deterministic():
    a = crypto.sha256_hex(b"hello")
    b = crypto.sha256_hex(b"hello")
    assert a == b
    assert a == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_sha256_differs_on_input():
    assert crypto.sha256_hex(b"hello") != crypto.sha256_hex(b"world")


def test_ed25519_sign_verify_roundtrip():
    kp = crypto.KeyPair.generate()
    msg = b"test message"
    sig = kp.sign(msg)
    assert crypto.KeyPair.verify(kp.public, sig, msg) is True


def test_ed25519_rejects_tampered_signature():
    kp = crypto.KeyPair.generate()
    msg = b"test message"
    sig = kp.sign(msg)
    # Flip a byte
    tampered = bytes([sig[0] ^ 1]) + sig[1:]
    assert crypto.KeyPair.verify(kp.public, tampered, msg) is False


def test_agent_id_derivation_is_deterministic():
    kp = crypto.KeyPair.generate()
    jwk = kp.public_jwk()
    a1 = crypto.derive_agent_id(jwk)
    a2 = crypto.derive_agent_id(jwk)
    assert a1 == a2
    assert a1.startswith("did:alethech:")


def test_agent_id_changes_with_different_key():
    kp1 = crypto.KeyPair.generate()
    kp2 = crypto.KeyPair.generate()
    a1 = crypto.derive_agent_id(kp1.public_jwk())
    a2 = crypto.derive_agent_id(kp2.public_jwk())
    assert a1 != a2


def test_agent_id_does_not_match_with_wrong_public_key():
    """corrección 1: agent_id must derive from public_key."""
    kp1 = crypto.KeyPair.generate()
    kp2 = crypto.KeyPair.generate()
    jwk1 = kp1.public_jwk()
    jwk2 = kp2.public_jwk()
    a1 = crypto.derive_agent_id(jwk1)
    a2 = crypto.derive_agent_id(jwk2)
    assert a1 != a2  # different keys → different agent_ids


# ---------- JCS canonicalization ----------

def test_canonical_json_sorts_keys():
    obj = {"b": 1, "a": 2, "c": 3}
    assert canonical_json(obj) == '{"a":2,"b":1,"c":3}'


def test_canonical_json_no_whitespace():
    obj = {"a": 1, "b": [1, 2, 3]}
    assert canonical_json(obj) == '{"a":1,"b":[1,2,3]}'


def test_canonical_json_nested_objects():
    obj = {"outer": {"inner_b": 2, "inner_a": 1}}
    assert canonical_json(obj) == '{"outer":{"inner_a":1,"inner_b":2}}'


def test_canonical_json_escapes_strings():
    obj = {"key": 'hello "world"'}
    assert canonical_json(obj) == '{"key":"hello \\"world\\""}'


def test_canonical_json_unicode_preserved():
    """Non-ASCII chars are emitted as UTF-8 (not escaped)."""
    obj = {"key": "café"}
    assert canonical_json(obj) == '{"key":"café"}'


# ---------- MemoryCommit signing ----------

def test_memory_commit_signature_validates():
    kp = crypto.KeyPair.generate()
    agent_id = crypto.derive_agent_id(kp.public_jwk())
    mc = MemoryCommit(
        agent_id=agent_id,
        parents=[],
        content={"type": "genesis"},
    )
    mc.sign(kp)
    assert mc.verify(kp.public_jwk()) is True


def test_memory_commit_signature_rejects_tampered_content():
    kp = crypto.KeyPair.generate()
    agent_id = crypto.derive_agent_id(kp.public_jwk())
    mc = MemoryCommit(
        agent_id=agent_id,
        parents=[],
        content={"type": "genesis"},
    )
    mc.sign(kp)
    # Tamper
    mc.content = {"type": "tampered"}
    assert mc.verify(kp.public_jwk()) is False


def test_memory_commit_id_changes_with_content():
    kp = crypto.KeyPair.generate()
    agent_id = crypto.derive_agent_id(kp.public_jwk())
    mc1 = MemoryCommit(agent_id=agent_id, parents=[], content={"v": 1})
    mc2 = MemoryCommit(agent_id=agent_id, parents=[], content={"v": 2})
    mc1.sign(kp)
    mc2.sign(kp)
    assert mc1.commit_id != mc2.commit_id


def test_memory_commit_signature_rejects_wrong_key():
    """A signature from kp1 should not validate against kp2."""
    kp1 = crypto.KeyPair.generate()
    kp2 = crypto.KeyPair.generate()
    agent_id = crypto.derive_agent_id(kp1.public_jwk())
    mc = MemoryCommit(agent_id=agent_id, parents=[], content={"v": 1})
    mc.sign(kp1)
    # Should NOT verify with kp2's public key
    assert mc.verify(kp2.public_jwk()) is False


# ---------- init command ----------

def test_init_creates_all_expected_files(tmp_store_dir, runner):
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "init"])
    assert result.exit_code == 0
    assert (tmp_store_dir / "identities").is_dir()
    assert (tmp_store_dir / "keys" / "signing.key").is_file()
    assert (tmp_store_dir / "keys" / "recovery.key").is_file()
    assert (tmp_store_dir / "commits").is_dir()
    assert (tmp_store_dir / "evidence").is_dir()
    assert (tmp_store_dir / "artifacts").is_dir()
    assert (tmp_store_dir / "HEAD").is_file()
    # Genesis commit should be present
    commits = list((tmp_store_dir / "commits").glob("*.json"))
    assert len(commits) == 1


def test_init_fails_if_directory_not_empty(tmp_store_dir, runner):
    (tmp_store_dir / "some_file.txt").write_text("hello")
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "init"])
    assert result.exit_code != 0


def test_init_agent_id_is_deterministic(tmp_store_dir, runner):
    """Reload identity from disk and verify agent_id matches."""
    runner.invoke(cli, ["--store", str(tmp_store_dir), "init"])
    ident_files = list((tmp_store_dir / "identities").glob("*.json"))
    assert len(ident_files) == 1
    ident = Identity.from_dict(json.loads(ident_files[0].read_text()))
    assert ident.verify_self() is True


# ---------- commit command ----------

def test_commit_creates_signed_commit(tmp_store_dir, runner, initialized_store):
    content_path = tmp_store_dir / "content.json"
    content_path.write_text(json.dumps({"message": "hello"}))
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(content_path)])
    assert result.exit_code == 0, result.output
    # Should have 2 commits now (genesis + new)
    commits = list((tmp_store_dir / "commits").glob("*.json"))
    assert len(commits) == 2


def test_commit_fails_with_invalid_content(tmp_store_dir, runner, initialized_store):
    bad = tmp_store_dir / "bad.json"
    bad.write_text("not json")
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(bad)])
    assert result.exit_code != 0


def test_commit_fails_with_non_object_content(tmp_store_dir, runner, initialized_store):
    arr = tmp_store_dir / "arr.json"
    arr.write_text("[1, 2, 3]")
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(arr)])
    assert result.exit_code != 0


# ---------- evidence command ----------

def test_evidence_creates_signed_evidence(tmp_store_dir, runner, initialized_store):
    inp = tmp_store_dir / "in.txt"
    out = tmp_store_dir / "out.txt"
    inp.write_text("input data")
    out.write_text("output data")
    result = runner.invoke(cli, [
        "--store", str(tmp_store_dir), "evidence",
        "--tool", "filesystem.read",
        "--input", str(inp),
        "--output", str(out),
    ])
    assert result.exit_code == 0, result.output
    ev_files = list((tmp_store_dir / "evidence").glob("*.json"))
    assert len(ev_files) == 1


def test_evidence_fails_with_missing_input(tmp_store_dir, runner, initialized_store):
    out = tmp_store_dir / "out.txt"
    out.write_text("output")
    result = runner.invoke(cli, [
        "--store", str(tmp_store_dir), "evidence",
        "--tool", "filesystem.read",
        "--input", "/nonexistent",
        "--output", str(out),
    ])
    assert result.exit_code != 0


# ---------- verify command ----------

def test_verify_passes_after_init(tmp_store_dir, runner, initialized_store):
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "verify"])
    assert result.exit_code == 0, result.output
    assert "result: OK" in result.output


def test_verify_detects_tampered_commit(tmp_store_dir, runner, initialized_store):
    # Add a commit
    content = tmp_store_dir / "c.json"
    content.write_text(json.dumps({"x": 1}))
    runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(content)])
    # Tamper with the commit file
    commit_files = list((tmp_store_dir / "commits").glob("*.json"))
    # The genesis is first; tamper the second one
    target = commit_files[1] if len(commit_files) > 1 else commit_files[0]
    data = json.loads(target.read_text())
    data["content"] = {"x": 999}  # tampered
    target.write_text(json.dumps(data, indent=2))
    # Verify should fail
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "verify"])
    assert result.exit_code != 0
    assert "FAIL" in result.output


def test_verify_detects_missing_parent(tmp_store_dir, runner, initialized_store):
    """If we delete the genesis commit, the second commit's parent won't resolve."""
    content = tmp_store_dir / "c.json"
    content.write_text(json.dumps({"x": 1}))
    runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(content)])
    # Delete the genesis commit (the older one)
    commits = sorted((tmp_store_dir / "commits").glob("*.json"), key=lambda p: p.stat().st_mtime)
    genesis_file = commits[0]
    genesis_file.unlink()
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "verify"])
    assert result.exit_code != 0
    assert "parent_missing" in result.output or "head_invalid" in result.output


def test_verify_detects_identity_mismatch(tmp_store_dir, runner, initialized_store):
    """corrección 1: changing agent_id without changing public_key must fail."""
    ident_files = list((tmp_store_dir / "identities").glob("*.json"))
    ident = Identity.from_dict(json.loads(ident_files[0].read_text()))
    # Tamper: change agent_id but keep public_key
    data = json.loads(ident_files[0].read_text())
    data["agent_id"] = "did:alethech:faketamperedagentid"
    # Write a new identity file with the tampered id (don't overwrite the original)
    (tmp_store_dir / "identities" / "did:alethech:faketamperedagentid.json").write_text(json.dumps(data, indent=2))
    # Remove the original
    ident_files[0].unlink()
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "verify"])
    assert result.exit_code != 0
    assert "identity_mismatch" in result.output or "signature_invalid" in result.output


# ---------- export + import roundtrip ----------

def test_export_then_import_preserves_state(tmp_store_dir, runner, initialized_store):
    # Add a commit and evidence
    content = tmp_store_dir / "c.json"
    content.write_text(json.dumps({"x": 1}))
    runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(content)])

    inp = tmp_store_dir / "in.txt"
    out = tmp_store_dir / "out.txt"
    inp.write_text("input")
    out.write_text("output")
    runner.invoke(cli, [
        "--store", str(tmp_store_dir), "evidence",
        "--tool", "fs.read",
        "--input", str(inp),
        "--output", str(out),
    ])

    # Export
    export_dir = tmp_store_dir.parent / "export"
    result = runner.invoke(cli, ["--store", str(tmp_store_dir), "export", "--output", str(export_dir)])
    assert result.exit_code == 0, result.output

    # Import into a fresh store
    target = tmp_store_dir.parent / "imported"
    result = runner.invoke(cli, [
        "--store", str(target),
        "import", "--input", str(export_dir),
        "--trust-unknown-identities",
    ])
    assert result.exit_code == 0, result.output

    # Verify imported store (HEAD is intentionally not updated by import,
    # so we set it manually to the head from the exported manifest)
    manifest = json.loads((export_dir / "manifest.json").read_text())
    head = manifest["head_commit_id"]
    (target / "HEAD").write_text(head + "\n")

    result = runner.invoke(cli, ["--store", str(target), "verify"])
    assert result.exit_code == 0, result.output
    assert "result: OK" in result.output


def test_import_rejects_tampered_manifest(tmp_store_dir, runner, initialized_store):
    # Export
    export_dir = tmp_store_dir.parent / "export"
    runner.invoke(cli, ["--store", str(tmp_store_dir), "export", "--output", str(export_dir)])
    # Tamper manifest hash
    manifest_path = export_dir / "manifest.json"
    data = json.loads(manifest_path.read_text())
    data["manifest_hash"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    manifest_path.write_text(json.dumps(data, indent=2))

    target = tmp_store_dir.parent / "imported"
    result = runner.invoke(cli, [
        "--store", str(target),
        "import", "--input", str(export_dir),
        "--trust-unknown-identities",
    ])
    assert result.exit_code != 0
    assert "manifest_hash mismatch" in result.output


# ---------- checkpoint / continuity ----------

def test_emit_checkpoint_creates_signed_file(tmp_store_dir, runner, initialized_store):
    cp_path = tmp_store_dir.parent / "cp.json"
    result = runner.invoke(cli, [
        "--store", str(tmp_store_dir), "verify",
        "--emit-checkpoint", str(cp_path),
    ])
    assert result.exit_code == 0, result.output
    assert cp_path.is_file()
    cp_data = json.loads(cp_path.read_text())
    assert cp_data["type"] == "Checkpoint"
    assert cp_data["head_commit_id"]


def test_verify_with_checkpoint_passes_when_consistent(tmp_store_dir, runner, initialized_store):
    cp_path = tmp_store_dir.parent / "cp.json"
    runner.invoke(cli, [
        "--store", str(tmp_store_dir), "verify",
        "--emit-checkpoint", str(cp_path),
    ])
    result = runner.invoke(cli, [
        "--store", str(tmp_store_dir), "verify",
        "--checkpoint", str(cp_path),
    ])
    assert result.exit_code == 0
    assert "continuity: verified" in result.output


def test_verify_with_checkpoint_detects_rollback(tmp_store_dir, runner, initialized_store):
    # Add commit, emit checkpoint
    content = tmp_store_dir / "c.json"
    content.write_text(json.dumps({"x": 1}))
    runner.invoke(cli, ["--store", str(tmp_store_dir), "commit", "--content", str(content)])
    cp_path = tmp_store_dir.parent / "cp.json"
    runner.invoke(cli, [
        "--store", str(tmp_store_dir), "verify",
        "--emit-checkpoint", str(cp_path),
    ])
    # Now delete the latest commit (simulating rollback)
    commits = sorted((tmp_store_dir / "commits").glob("*.json"), key=lambda p: p.stat().st_mtime)
    commits[-1].unlink()
    # Reset HEAD to genesis
    genesis = commits[0].stem
    (tmp_store_dir / "HEAD").write_text(genesis + "\n")
    # Verify with old checkpoint should detect rollback
    result = runner.invoke(cli, [
        "--store", str(tmp_store_dir), "verify",
        "--checkpoint", str(cp_path),
    ])
    assert result.exit_code != 0
    assert "rollback_detected" in result.output


# ---------- store layout ----------

def test_store_layout_after_init(tmp_store_dir):
    Store.init(tmp_store_dir)
    assert (tmp_store_dir / "identities").is_dir()
    assert (tmp_store_dir / "keys").is_dir()
    assert (tmp_store_dir / "commits").is_dir()
    assert (tmp_store_dir / "evidence").is_dir()
    assert (tmp_store_dir / "artifacts").is_dir()
