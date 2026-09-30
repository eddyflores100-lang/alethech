"""Behavioral tests for the public, Click-free Python API."""
import pytest
from alethech.api import Alethech, AlethechError

def test_initialize_commit_verify_roundtrip(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    genesis = client.head
    commit = client.commit({"fact": "portable API"}, memory_type="semantic", session_id="api-test")
    assert commit.parents == [genesis]
    assert client.head == commit.commit_id
    report = client.verify()
    assert report.ok, report.summary()
    assert report.commits_total == 2

def test_open_existing_store(tmp_path):
    created = Alethech.initialize(tmp_path / "store")
    reopened = Alethech.open(tmp_path / "store")
    assert reopened.head == created.head
    assert reopened.verify().ok

def test_commit_rejects_missing_evidence(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    with pytest.raises(AlethechError, match="evidence_id not found"):
        client.commit({"x": 1}, evidence_refs=["sha256:not-present"])

def test_commit_rejects_invalid_memory_type(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    with pytest.raises(AlethechError, match="unsupported memory_type"):
        client.commit({"x": 1}, memory_type="unknown")

def test_initialize_refuses_nonempty_directory(tmp_path):
    path = tmp_path / "store"
    path.mkdir()
    (path / "foreign.txt").write_text("do not overwrite")
    with pytest.raises(AlethechError, match="directory not empty"):
        Alethech.initialize(path)


def test_portable_aleth_public_api(tmp_path):
    source = Alethech.initialize(tmp_path / "source")
    source.commit({"memory": "moves between devices"})
    container = source.seal(tmp_path / "memory.aleth", "portable-secret")

    target = Alethech.open_aleth(container, tmp_path / "device-b", "portable-secret")

    assert target.head == source.head
    assert target.verify().ok
    continued = target.commit({"memory": "continued on device B"})
    assert continued.parents == [source.head]
    assert target.verify().ok


def test_public_api_context_view(tmp_path):
    agent = Alethech.initialize(tmp_path / "store")
    agent.commit({"fact": "portable context"}, session_id="ctx")

    context = agent.context()

    assert context["format"] == "alethech-memory-view"
    assert context["version"] == 1
    assert context["head"] == agent.head
    assert len(context["entries"]) == 1
    assert context["entries"][0]["content"] == {"fact": "portable context"}


def test_programmatic_evidence_roundtrip(tmp_path):
    client = Alethech.initialize(tmp_path / "store")
    ev = client.evidence(
        tool="filesystem.read",
        input_bytes=b"request",
        output_bytes=b"response",
        artifacts={"proof.txt": b"artifact bytes"},
    )
    commit = client.commit({"fact": "backed by evidence"}, evidence_refs=[ev.commit_id])

    report = client.verify()
    assert report.ok, report.summary()
    assert ev.commit_id in client.store.load_evidence()
    assert commit.provenance["evidence_refs"] == [ev.commit_id]
    assert len(client.store.list_artifacts()) == 1


def test_public_api_aleth_v2_recovery_flow(tmp_path):
    source = Alethech.initialize(tmp_path / "source-v2")
    source.commit({"memory": "public v2 api"})
    path, recovery = source.seal_v2(
        tmp_path / "memory-v2.aleth",
        "original-passphrase",
        create_recovery=True,
    )
    assert recovery is not None

    by_pass = Alethech.open_aleth(
        path,
        tmp_path / "opened-by-pass",
        "original-passphrase",
    )
    assert by_pass.head == source.head
    assert by_pass.verify().ok

    by_recovery = Alethech.open_aleth_v2(
        path,
        tmp_path / "opened-by-recovery",
        recovery_code=recovery,
    )
    assert by_recovery.head == source.head
    assert by_recovery.verify().ok

    recovered_path, same_recovery = Alethech.recover_aleth_v2(
        path,
        tmp_path / "recovered-v2.aleth",
        recovery,
        "replacement-passphrase",
    )
    assert same_recovery == recovery
    recovered = Alethech.open_aleth(
        recovered_path,
        tmp_path / "opened-recovered",
        "replacement-passphrase",
    )
    assert recovered.head == source.head
    assert recovered.verify().ok


def test_public_api_v1_to_v2_migration_preserves_head(tmp_path):
    source = Alethech.initialize(tmp_path / "source-v1")
    source.commit({"memory": "migrate through public api"})
    v1 = source.seal(tmp_path / "memory-v1.aleth", "v1-passphrase")

    v2, recovery = Alethech.migrate_aleth_v1_to_v2(
        v1,
        tmp_path / "memory-v2.aleth",
        "v1-passphrase",
        "v2-passphrase",
        create_recovery=True,
    )
    assert recovery is not None

    migrated = Alethech.open_aleth(
        v2,
        tmp_path / "opened-migrated",
        "v2-passphrase",
    )
    assert migrated.head == source.head
    assert migrated.verify().ok
