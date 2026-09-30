"""Adversarial tests for the encrypted .aleth portable container."""
import pytest
from alethech import crypto
from alethech.api import Alethech
from alethech.container import ContainerError, inspect_container, open_container, seal_store
from alethech.verify import verify_store

def _sealed(tmp_path):
    client=Alethech.initialize(tmp_path/"source")
    client.commit({"memory":"portable"})
    out=tmp_path/"memory.aleth"
    seal_store(client.store,out,"correct horse battery staple")
    return client,out

def test_seal_open_roundtrip(tmp_path):
    source,container=_sealed(tmp_path)
    restored=open_container(container,tmp_path/"restored","correct horse battery staple")
    assert restored.read_head()==source.head
    assert len(restored.load_commits())==2
    assert not (tmp_path/"restored"/"keys"/"root.key").exists()
    assert not (tmp_path/"restored"/"keys"/"recovery.key").exists()
    assert (tmp_path/"restored"/"keys"/"signing.key").exists()

def test_wrong_passphrase_fails_without_plaintext(tmp_path):
    _,container=_sealed(tmp_path)
    dest=tmp_path/"restored"
    with pytest.raises(ContainerError,match="authentication failed"):
        open_container(container,dest,"wrong")
    assert not dest.exists()

@pytest.mark.parametrize("offset", [20,-1])
def test_tampering_fails_closed(tmp_path,offset):
    _,container=_sealed(tmp_path)
    data=bytearray(container.read_bytes())
    data[offset]^=1
    container.write_bytes(data)
    dest=tmp_path/"restored"
    with pytest.raises(ContainerError):
        open_container(container,dest,"correct horse battery staple")
    assert not dest.exists()

def test_truncated_container_fails(tmp_path):
    _,container=_sealed(tmp_path)
    container.write_bytes(container.read_bytes()[:-12])
    with pytest.raises(ContainerError):
        open_container(container,tmp_path/"restored","correct horse battery staple")

def test_refuses_invalid_source_store(tmp_path):
    client=Alethech.initialize(tmp_path/"source")
    (client.store.root/"HEAD").write_text("sha256:not-real")
    with pytest.raises(ContainerError,match="refusing to seal invalid store"):
        seal_store(client.store,tmp_path/"bad.aleth","passphrase")


def test_refuses_mismatched_portable_signing_key(tmp_path):
    client = Alethech.initialize(tmp_path / "source")
    client.store.write_signing_key(crypto.KeyPair.generate())

    with pytest.raises(ContainerError, match="signing key does not match identity"):
        seal_store(client.store, tmp_path / "mismatched.aleth", "passphrase")


def test_portable_filesystem_names_preserve_logical_container_paths(tmp_path):
    client = Alethech.initialize(tmp_path / "source")
    ev = client.evidence(
        tool="portable-filenames",
        input_bytes=b"in",
        output_bytes=b"out",
        artifacts={"proof.bin": b"portable-artifact"},
    )
    client.commit({"memory": "cross-platform"}, evidence_refs=[ev.commit_id])

    # Physical store names must be valid on Windows too: protocol ':' stays
    # inside signed objects, not in local filenames.
    for directory in ("identities", "commits", "evidence", "artifacts"):
        for path in (client.store.root / directory).iterdir():
            if path.is_file():
                assert ":" not in path.name
    assert any("%3A" in p.name for p in (client.store.root / "commits").iterdir())

    out = tmp_path / "portable.aleth"
    seal_store(client.store, out, "portable-passphrase")
    meta = inspect_container(out, "portable-passphrase")

    # The encrypted container contract remains logical/canonical and therefore
    # unchanged for TypeScript/Rust/browser consumers.
    assert any(p.startswith("identities/did:alethech:") for p in meta["files"])
    assert any(p.startswith("commits/sha256:") for p in meta["files"])
    assert any(p.startswith("evidence/sha256:") for p in meta["files"])
    assert any(p.startswith("artifacts/sha256:") for p in meta["files"])
    assert not any("%3A" in p for p in meta["files"])

    restored = open_container(out, tmp_path / "restored", "portable-passphrase")
    report = verify_store(restored)
    assert report.ok, report.summary()
    for directory in ("identities", "commits", "evidence", "artifacts"):
        for path in (restored.root / directory).iterdir():
            if path.is_file():
                assert ":" not in path.name

    artifact_hash = ev.artifacts[0]["hash"]
    assert restored.read_artifact(artifact_hash) == b"portable-artifact"
