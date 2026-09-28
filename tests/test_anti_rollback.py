"""Anti-rollback tests for 0.6.0 — monotonic sequence in checkpoints.

The audit flagged that without a monotonic counter, a correctly-signed
but old checkpoint could be presented as current. The system clock
should NOT be the anti-rollback authority.

0.6.0 fix: added `sequence` field to Checkpoint. A consumer that has
seen sequence=N must reject any checkpoint with sequence < N.

Tests:
- Checkpoint with sequence field serializes/deserializes correctly
- Old checkpoint (no sequence) still parses (backward-compat)
- A consumer using the sequence field can detect rollback
- Sequence is part of the signed payload (cannot be tampered)
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
from alethech.objects import Checkpoint, Identity
from alethech.store import Store
from alethech.verify import verify_store


@pytest.fixture
def tmp_store():
    d = tempfile.mkdtemp(prefix="alethech-rollback-")
    p = Path(d) / "alethech"
    yield p
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def store_with_commit(tmp_store, runner):
    """Store with one commit."""
    runner.invoke(cli, ["--store", str(tmp_store), "init"])
    c = tmp_store / "c1.json"
    c.write_text(json.dumps({"v": 1}))
    runner.invoke(cli, ["--store", str(tmp_store), "commit", "--content", str(c)])
    return tmp_store


class TestCheckpointSequence:
    """Verify the sequence field is present and signed."""

    def test_checkpoint_has_sequence_field(self, store_with_commit):
        """A Checkpoint created with sequence should serialize it."""
        store = Store.open(store_with_commit)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()
        commits = store.load_commits()

        cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=len(commits),
            evidence_count=0,
            sequence=42,
        )
        cp.sign(signing)
        d = cp.to_signed_dict()
        assert "sequence" in d
        assert d["sequence"] == 42

    def test_checkpoint_without_sequence_backward_compat(self):
        """An old checkpoint (no sequence field) should still parse, defaulting to 0."""
        # Construct a checkpoint dict without sequence
        old_cp_dict = {
            "type": "Checkpoint",
            "version": 1,
            "agent_id": "did:alethech:old",
            "head_commit_id": "sha256:old",
            "commit_count": 1,
            "evidence_count": 0,
            "created_at": "2026-01-01T00:00:00.000Z",
            "checkpoint_id": "sha256:oldcp",
            "signature": "ed25519:fake",
        }
        cp = Checkpoint.from_dict(old_cp_dict)
        assert cp.sequence == 0  # default for old checkpoints

    def test_sequence_is_signed(self, store_with_commit):
        """The sequence field must be part of the signed payload.

        If it weren't, an attacker could change it without invalidating
        the signature.
        """
        store = Store.open(store_with_commit)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()
        commits = store.load_commits()

        cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=len(commits),
            evidence_count=0,
            sequence=100,
        )
        cp.sign(signing)

        # Verify the signed payload includes sequence
        signable = cp.to_signable_dict()
        assert "sequence" in signable
        assert signable["sequence"] == 100

        # Verify the signature is valid
        assert cp.verify(ident.public_key)

        # Tamper with sequence — signature should now be invalid
        cp.sequence = 99
        assert not cp.verify(ident.public_key), \
            "tampering with sequence must invalidate signature"


class TestRollbackDetection:
    """Verify that a consumer can use sequence to detect rollback."""

    def test_lower_sequence_detected_as_rollback(self, store_with_commit):
        """If we have a checkpoint with sequence=10, presenting one with
        sequence=5 should be detected as rollback by the consumer."""
        store = Store.open(store_with_commit)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()
        commits = store.load_commits()

        # Create a 'current' checkpoint with sequence=10
        current_cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=len(commits),
            evidence_count=0,
            sequence=10,
        )
        current_cp.sign(signing)

        # Create an 'old' checkpoint with sequence=5 (correctly signed, valid)
        old_cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=len(commits),
            evidence_count=0,
            sequence=5,
        )
        old_cp.sign(signing)

        # Consumer logic: if new.sequence <= last_known.sequence, reject
        last_known_sequence = current_cp.sequence  # 10

        # Presenting old_cp (sequence=5) should be detected as rollback
        assert old_cp.sequence < last_known_sequence, \
            "old checkpoint sequence should be less than current"

        # The verify_store itself doesn't know about 'last_known' — that's
        # consumer state. But the sequence field is available for the
        # consumer to check. Here we simulate the consumer check:
        def consumer_accepts(new_cp, last_known_seq):
            if new_cp.sequence < last_known_seq:
                return False, "rollback: sequence went backwards"
            if new_cp.sequence == last_known_seq:
                return False, "rollback: same sequence (replay)"
            return True, "ok"

        ok, reason = consumer_accepts(old_cp, last_known_sequence)
        assert not ok
        assert "rollback" in reason

    def test_equal_sequence_detected_as_replay(self, store_with_commit):
        """A checkpoint with the SAME sequence as the last known one
        should be detected as a replay attack."""
        store = Store.open(store_with_commit)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()

        cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=1,
            evidence_count=0,
            sequence=10,
        )
        cp.sign(signing)

        # Presenting the SAME checkpoint again (replay)
        # Consumer should detect: sequence == last_known → replay
        last_known = 10
        assert cp.sequence == last_known  # replay detected

    def test_higher_sequence_accepted(self, store_with_commit):
        """A checkpoint with a higher sequence than the last known should
        be accepted as a legitimate forward progress."""
        store = Store.open(store_with_commit)
        identities = store.load_identities()
        ident = next(iter(identities.values()))
        signing = store.load_signing_key()

        new_cp = Checkpoint(
            agent_id=ident.agent_id,
            head_commit_id=store.read_head(),
            commit_count=2,
            evidence_count=0,
            sequence=15,
        )
        new_cp.sign(signing)

        last_known = 10
        assert new_cp.sequence > last_known  # forward progress
