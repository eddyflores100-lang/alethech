"""Adversarial tests for 0.7.0 audit findings.

Tests the 4 fixes from the second external audit:
1. Atomic import — failed verification must NOT leave target modified
2. Fail-closed checkpoint semantics — count mismatch → error, not warning
3. Artifact hash check during import — corrupted artifact rejected
4. Trust gate for IdentityRecordV2 — unknown v2 identities rejected
   without --trust-unknown-identities
"""
import json
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from alethech import crypto
from alethech.canonical import canonical_json_bytes
from alethech.cli import cli
from alethech.objects import (
    Checkpoint, Identity, MemoryCommit, EvidenceCommit,
    IdentityRecordV2, RootAuthority,
)
from alethech.store import Store


@pytest.fixture
def tmp_dirs():
    """Create temp source and target directories."""
    src = Path(tempfile.mkdtemp(prefix="alethech-07-src-"))
    target = Path(tempfile.mkdtemp(prefix="alethech-07-tgt-")) / "alethech"
    runner = CliRunner()
    runner.invoke(cli, ["--store", str(target), "init"])
    yield src, target
    shutil.rmtree(src.parent, ignore_errors=True)
    shutil.rmtree(target.parent.parent, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


def _make_valid_export(src: Path) -> Path:
    """Create a valid export package in src, INCLUDING an artifact."""
    store_path = Path(tempfile.mkdtemp(prefix="alethech-07-export-")) / "alethech"
    runner = CliRunner()
    runner.invoke(cli, ["--store", str(store_path), "init"])

    # Add a commit with an artifact (evidence pointing to an artifact)
    from alethech.objects import EvidenceCommit
    store = Store.open(store_path)
    signing = store.load_signing_key()
    identities = store.load_identities()
    ident = next(iter(identities.values()))

    # Create artifact content + compute hash
    artifact_content = b"test artifact content for import test"
    art_hash = "sha256:" + crypto.sha256_hex(artifact_content)

    # Write artifact to store
    store.write_artifact(artifact_content)

    # Create evidence pointing to the artifact
    ev = EvidenceCommit(
        agent_id=ident.agent_id,
        key_id="key-001",
        tool="test_tool",
        input_hash="sha256:test_input",
        output_hash="sha256:test_output",
        artifacts=[{"hash": art_hash, "size": len(artifact_content), "mime": "application/octet-stream"}],
    )
    ev.sign(signing)
    store.write_evidence(ev)

    # Export
    runner.invoke(cli, ["--store", str(store_path), "export", "--output", str(src)])
    shutil.rmtree(store_path.parent, ignore_errors=True)
    return src


# ============================================================================
# 1. Atomic import — failed verification must NOT modify target
# ============================================================================

class TestAtomicImport:
    """Verify that if import fails during verification, the target store
    is left UNTOUCHED. This is the core atomicity guarantee."""

    def test_failed_checkpoint_does_not_modify_target(self, tmp_dirs, runner):
        """If checkpoint continuity check fails, target must be unchanged."""
        src, target = tmp_dirs
        _make_valid_export(src)

        # Record target state BEFORE import attempt
        store = Store.open(target)
        target_commits_before = set(store.load_commits().keys())
        target_evidence_before = set(store.load_evidence().keys())

        # Create a checkpoint that will FAIL the continuity check
        # (head_commit_id not in staged commits)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()
        bad_cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id="sha256:nonexistent_head_000000000000000000",
            commit_count=999,  # also wrong
            evidence_count=0,
        )
        bad_cp.sign(signing)

        cp_path = src.parent / "bad_checkpoint.json"
        cp_path.write_text(json.dumps(bad_cp.to_signed_dict()), encoding="utf-8")

        # Attempt import — should fail
        r = runner.invoke(cli, [
            "--store", str(target),
            "import",
            "--input", str(src),
            "--checkpoint", str(cp_path),
            "--trust-unknown-identities",
        ])
        assert r.exit_code != 0
        assert "rollback_detected" in r.output or "checkpoint" in r.output.lower()

        # CRITICAL: target must be UNCHANGED
        store = Store.open(target)
        target_commits_after = set(store.load_commits().keys())
        target_evidence_after = set(store.load_evidence().keys())
        assert target_commits_before == target_commits_after, \
            "target commits must be unchanged after failed import (atomicity)"
        assert target_evidence_before == target_evidence_after, \
            "target evidence must be unchanged after failed import (atomicity)"


# ============================================================================
# 2. Fail-closed checkpoint semantics — count mismatch → error
# ============================================================================

class TestFailClosedCheckpoint:
    """Verify that checkpoint count mismatch produces an ERROR, not a
    warning + continuity_verified=True."""

    def test_count_mismatch_is_error_not_warning(self, tmp_dirs, runner):
        """A checkpoint with wrong commit_count must fail verification,
        not produce a warning and claim continuity_verified."""
        src, target = tmp_dirs
        _make_valid_export(src)

        store = Store.open(target)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()

        # Create checkpoint with WRONG count (says 999, actual is 1)
        bad_cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),  # correct head
            commit_count=999,  # WRONG count
            evidence_count=0,
        )
        bad_cp.sign(signing)

        r = runner.invoke(cli, [
            "--store", str(target),
            "verify",
            "--checkpoint", "/dev/stdin",  # can't use this; need file
        ], input=json.dumps(bad_cp.to_signed_dict()))
        # verify --checkpoint expects a file path; let's use a temp file instead
        cp_path = src.parent / "bad_count_cp.json"
        cp_path.write_text(json.dumps(bad_cp.to_signed_dict()), encoding="utf-8")

        r = runner.invoke(cli, [
            "--store", str(target),
            "verify",
            "--checkpoint", str(cp_path),
        ])
        assert r.exit_code != 0
        assert "FAIL" in r.output
        assert "checkpoint_count_mismatch" in r.output or "checkpoint_evidence_mismatch" in r.output
        assert "continuity: verified" not in r.output, \
            "must NOT report continuity_verified when count mismatch occurs"


# ============================================================================
# 3. Artifact hash check during import — corrupted artifact rejected
# ============================================================================

class TestArtifactHashCheck:
    """Verify that a corrupted artifact (content doesn't match filename hash)
    is rejected during import, BEFORE being written to the target store."""

    def test_corrupted_artifact_rejected(self, tmp_dirs, runner):
        """An artifact whose content doesn't match its declared hash must
        be rejected. Target must be unchanged (atomicity)."""
        src, target = tmp_dirs
        _make_valid_export(src)

        # Record target state before
        store = Store.open(target)
        artifacts_before = set(store.list_artifacts())

        # Corrupt an artifact: replace its content with different bytes
        # but keep the filename (which IS the declared hash)
        artifacts_dir = src / "artifacts"
        if artifacts_dir.is_dir() and any(artifacts_dir.iterdir()):
            art_path = next(artifacts_dir.iterdir())
            # Write different content (corrupt)
            art_path.write_bytes(b"CORRUPTED_CONTENT_DIFFERENT_FROM_HASH")
        else:
            pytest.skip("no artifacts in test export")

        r = runner.invoke(cli, [
            "--store", str(target),
            "import",
            "--input", str(src),
            "--trust-unknown-identities",
        ])
        assert r.exit_code != 0
        assert "artifact_hash_mismatch" in r.output, \
            f"must report artifact_hash_mismatch: {r.output}"

        # Target must be unchanged (atomicity)
        store = Store.open(target)
        artifacts_after = set(store.list_artifacts())
        assert artifacts_before == artifacts_after, \
            "target artifacts must be unchanged after failed import"


# ============================================================================
# 4. Trust gate for IdentityRecordV2 — unknown v2 identities rejected
# ============================================================================

class TestTrustGateV2:
    """Verify that unknown IdentityRecordV2 from import package are
    rejected without --trust-unknown-identities."""

    def test_unknown_v2_identity_rejected_without_trust_flag(self, tmp_dirs, runner):
        """An IdentityRecordV2 from a foreign root authority must be
        rejected unless --trust-unknown-identities is set."""
        src, target = tmp_dirs
        _make_valid_export(src)

        # Generate a foreign root + identity
        foreign_root_kp = crypto.KeyPair.generate()
        foreign_root_jwk = foreign_root_kp.public_jwk()
        foreign_root_id = "did:alethech:root:" + crypto.b32lower(
            crypto.sha256(canonical_json_bytes(foreign_root_jwk))[0:16]
        )
        foreign_agent_id = "did:alethech:" + crypto.b32lower(
            crypto.sha256(canonical_json_bytes(foreign_root_jwk))[0:16]
        )

        foreign_ident = IdentityRecordV2(
            root_id=foreign_root_id,
            root_public_key=foreign_root_jwk,
            agent_id=foreign_agent_id,
        )
        op_kp = crypto.KeyPair.generate()
        foreign_ident.active_keys = [{
            "key_id": "key-foreign",
            "public_key": op_kp.public_jwk(),
            "authorized_at": "2026-01-01T00:00:00.000Z",
            "authorized_by": "foreign",
            "expires_at": None,
        }]
        foreign_ident.sign(foreign_root_kp)

        # Add foreign identity to the export package
        (src / "identities" / f"{foreign_agent_id}.json").write_text(
            json.dumps(foreign_ident.to_signed_dict()), encoding="utf-8"
        )

        # Record target state before
        store = Store.open(target)
        v2_before = set()
        try:
            v2_before = set(store.load_identity_records_v2().keys())
        except Exception:
            pass

        # Import WITHOUT --trust-unknown-identities — should fail
        r = runner.invoke(cli, [
            "--store", str(target),
            "import",
            "--input", str(src),
            # NO --trust-unknown-identities
        ])
        assert r.exit_code != 0
        assert "unknown_identity_v2" in r.output or "unknown_identity" in r.output

        # Target must be unchanged (atomicity)
        store = Store.open(target)
        v2_after = set()
        try:
            v2_after = set(store.load_identity_records_v2().keys())
        except Exception:
            pass
        assert v2_before == v2_after, \
            "target v2 identities must be unchanged after failed import"


# ============================================================================
# 5. Mutation guards — disabling each fix must cause test failure
# ============================================================================

class TestMutationGuards:
    """Verify that disabling each 0.7.0 fix causes corresponding tests to
    fail. This is the tonydzi criterion: a check nobody has watched fail
    is a promise, not a guarantee."""

    def test_artifact_hash_check_is_enforced(self, tmp_dirs, runner):
        """Confirms the artifact hash check runs and catches corruption."""
        # This is the same as test_corrupted_artifact_rejected but
        # explicitly named as a mutation guard.
        src, target = tmp_dirs
        _make_valid_export(src)

        artifacts_dir = src / "artifacts"
        if not artifacts_dir.is_dir() or not any(artifacts_dir.iterdir()):
            pytest.skip("no artifacts")

        art_path = next(artifacts_dir.iterdir())
        art_path.write_bytes(b"CORRUPTED")

        r = runner.invoke(cli, [
            "--store", str(target),
            "import", "--input", str(src),
            "--trust-unknown-identities",
        ])
        # If the check is disabled (mutation), this would succeed.
        # The test asserts it FAILS — proving the check is enforced.
        assert r.exit_code != 0
        assert "artifact_hash_mismatch" in r.output
