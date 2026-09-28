"""Tests for rev 3 — identity layer."""
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
    Identity, IdentityRecordV2, ControlEvent, MigrationRecord,
    RootAuthority, MemoryCommit,
)
from alethech.store import Store
from alethech.verify import (
    verify_store, verify_identity_layer,
    check_commit_against_governance, ancestry_check,
)


@pytest.fixture
def tmp_store():
    d = tempfile.mkdtemp(prefix="alethech-rev3-")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def v01_store(tmp_store, runner):
    result = runner.invoke(cli, ["--store", str(tmp_store), "init"])
    assert result.exit_code == 0, result.output
    return tmp_store


@pytest.fixture
def v02_store(v01_store, runner):
    result = runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    assert result.exit_code == 0, result.output
    return v01_store


# ---------- RootAuthority ----------

def test_root_authority_self_verify():
    kp = crypto.KeyPair.generate()
    jwk = kp.public_jwk()
    root_id = "did:alethech:root:" + crypto.b32lower(crypto.sha256(canonical_json_bytes(jwk))[0:16])
    root = RootAuthority(root_id=root_id, root_public_key=jwk)
    assert root.verify_self() is True


def test_root_authority_detects_mismatch():
    kp = crypto.KeyPair.generate()
    jwk = kp.public_jwk()
    root = RootAuthority(root_id="did:alethech:root:fakefakefakefake", root_public_key=jwk)
    assert root.verify_self() is False


# ---------- Migration ----------

def test_migrate_produces_bilateral_signatures(v01_store, runner):
    result = runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    assert result.exit_code == 0, result.output
    store = Store.open(v01_store)
    migrations = store.load_migration_records()
    assert len(migrations) == 1
    mig = next(iter(migrations.values()))
    assert mig.legacy_signature.startswith("ed25519:")
    assert mig.signature.startswith("ed25519:")
    assert mig.verify_both(mig.legacy_public_key, mig.new_root_public_key) is True


def test_migrate_creates_root_authority(v01_store, runner):
    runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    store = Store.open(v01_store)
    root = store.load_root_authority()
    assert root.verify_self() is True


def test_migrate_creates_genesis_control_event(v01_store, runner):
    runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    store = Store.open(v01_store)
    events = store.load_control_events()
    assert len(events) == 1
    ev = next(iter(events.values()))
    assert ev.event_type == "key_grant"
    assert ev.sequence == 1
    assert ev.previous_control_hash == ""
    assert ev.key_id == "key-001"


def test_migrate_preserves_legacy_agent_id(v01_store, runner):
    store = Store.open(v01_store)
    legacy_identities = store.load_identities()
    legacy_agent_id = next(iter(legacy_identities.values())).agent_id
    runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    store = Store.open(v01_store)
    legacy_identities = store.load_identities()
    assert legacy_agent_id in legacy_identities


def test_migrate_creates_new_agent_id_derived_from_root(v01_store, runner):
    runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    store = Store.open(v01_store)
    v2_identities = store.load_identity_records_v2()
    assert len(v2_identities) == 1
    new_identity = next(iter(v2_identities.values()))
    assert new_identity.verify_self() is True
    root = store.load_root_authority()
    assert new_identity.root_public_key == root.root_public_key


# ---------- Key rotation ----------

def test_key_rotate_produces_atomic_control_event(v02_store, runner):
    result = runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    assert result.exit_code == 0, result.output
    store = Store.open(v02_store)
    events = store.load_control_events()
    assert len(events) == 2  # genesis + rotation
    rotations = [e for e in events.values() if e.event_type == "key_rotation"]
    assert len(rotations) == 1
    rot = rotations[0]
    assert rot.old_key_id == "key-001"
    assert rot.key_id == "key-002"
    assert rot.cutoff_head


def test_key_rotate_preserves_history(v02_store, runner):
    runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    store = Store.open(v02_store)
    identities = store.load_identity_records_v2()
    ident = next(iter(identities.values()))
    assert len(ident.active_keys) == 1
    assert ident.active_keys[0]["key_id"] == "key-002"
    assert len(ident.revoked_keys) == 1
    assert ident.revoked_keys[0]["key_id"] == "key-001"
    assert ident.revoked_keys[0]["cutoff_head"]


def test_key_rotate_increments_sequence(v02_store, runner):
    runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    store = Store.open(v02_store)
    events = store.load_control_events()
    rot = [e for e in events.values() if e.event_type == "key_rotation"][0]
    assert rot.sequence == 2


def test_key_rotate_chain_links(v02_store, runner):
    runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    store = Store.open(v02_store)
    events = store.load_control_events()
    sorted_events = sorted(events.values(), key=lambda e: e.sequence)
    assert sorted_events[1].previous_control_hash == sorted_events[0].commit_id


# ---------- Governance state checks ----------

def test_check_commit_with_active_key_returns_VALID(v02_store, runner):
    content = v02_store / "c.json"
    content.write_text(json.dumps({"msg": "hello"}))
    result = runner.invoke(cli, ["--store", str(v02_store), "commit", "--content", str(content)])
    assert result.exit_code == 0
    store = Store.open(v02_store)
    identities = store.load_identity_records_v2()
    events = store.load_control_events()
    commits = store.load_commits()
    # Find the commit that uses the v0.2 agent_id (not the legacy genesis)
    v2_agent_ids = set(identities.keys())
    latest = None
    for c in commits.values():
        if c.agent_id in v2_agent_ids:
            latest = c
            break
    assert latest is not None, "no commit with v0.2 agent_id found"
    state = check_commit_against_governance(latest, identities, events)
    assert state == "VALID"


def test_check_commit_with_unknown_key_returns_UNKNOWN_KEY(v02_store, runner):
    fake_kp = crypto.KeyPair.generate()
    store = Store.open(v02_store)
    identities = store.load_identity_records_v2()
    ident = next(iter(identities.values()))
    fake_commit = MemoryCommit(
        agent_id=ident.agent_id,
        key_id="key-fake",
        parents=[],
        content={"fake": True},
    )
    fake_commit.sign(fake_kp)
    events = store.load_control_events()
    state = check_commit_against_governance(fake_commit, identities, events)
    assert state == "UNKNOWN_KEY"


def test_ancestry_check_basic():
    class MockCommit:
        def __init__(self, cid, parents):
            self.commit_id = cid
            self.parents = parents
    commits = {
        "A": MockCommit("A", []),
        "B": MockCommit("B", ["A"]),
        "C": MockCommit("C", ["B"]),
    }
    assert ancestry_check("C", "C", commits) is True
    assert ancestry_check("A", "C", commits) is True
    assert ancestry_check("C", "A", commits) is False
    assert ancestry_check("B", "C", commits) is True


def test_ancestry_check_dag_with_branches():
    class MockCommit:
        def __init__(self, cid, parents):
            self.commit_id = cid
            self.parents = parents
    commits = {
        "C0": MockCommit("C0", []),
        "C1": MockCommit("C1", ["C0"]),
        "B1": MockCommit("B1", ["C0"]),
        "B2": MockCommit("B2", ["B1"]),
        "M":  MockCommit("M", ["C1", "B2"]),
    }
    assert ancestry_check("B2", "M", commits) is True
    assert ancestry_check("B1", "M", commits) is True
    assert ancestry_check("C1", "M", commits) is True
    assert ancestry_check("C0", "M", commits) is True
    commits["X1"] = MockCommit("X1", ["C0"])
    commits["X2"] = MockCommit("X2", ["X1"])
    assert ancestry_check("X2", "M", commits) is False


# ---------- Control chain integrity ----------

def test_control_chain_detects_broken_link(v02_store, runner):
    runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    store = Store.open(v02_store)
    events = store.load_control_events()
    rot = [e for e in events.values() if e.event_type == "key_rotation"][0]
    rot.previous_control_hash = "sha256:fake"
    store.write_control_event(rot)
    from alethech.verify import VerifyReport
    report = verify_identity_layer(store, VerifyReport())
    assert any("control_chain_invalid" in e or "signature_invalid" in e for e in report.errors)


def test_control_chain_detects_sequence_gap(v02_store, runner):
    runner.invoke(cli, ["--store", str(v02_store), "key", "rotate"])
    store = Store.open(v02_store)
    events = store.load_control_events()
    rot = [e for e in events.values() if e.event_type == "key_rotation"][0]
    rot.sequence = 5
    store.write_control_event(rot)
    from alethech.verify import VerifyReport
    report = verify_identity_layer(store, VerifyReport())
    assert any("control_chain_invalid" in e for e in report.errors)


# ---------- identity list ----------

def test_identity_list_shows_v01_and_v02(v01_store, runner):
    runner.invoke(cli, ["--store", str(v01_store), "migrate", "--to", "v0.2"])
    result = runner.invoke(cli, ["--store", str(v01_store), "identity", "list"])
    assert result.exit_code == 0
    assert "[v0.1]" in result.output
    assert "[v0.2]" in result.output


# ---------- identity publish ----------

def test_identity_publish_creates_signed_file(v02_store, runner):
    out = v02_store / "pub.json"
    result = runner.invoke(cli, ["--store", str(v02_store), "identity", "publish", "--output", str(out)])
    assert result.exit_code == 0, result.output
    assert out.is_file()
    pub = json.loads(out.read_text())
    assert pub["type"] == "AlethechIdentityPublication"
    assert pub["publication_signature"].startswith("ed25519:")
    assert "identity_hash" in pub
