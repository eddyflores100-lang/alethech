"""Adversarial tests for the encrypted .aleth portable container."""
import pytest
from alethech.api import Alethech
from alethech.container import ContainerError, open_container, seal_store

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
