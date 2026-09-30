"""Regression coverage for portable public API verification boundaries."""
import json

import pytest

from alethech import Alethech
from alethech.container import ContainerError
from alethech.container_v2 import _parse_v2, _seal_payload_v2, decode_recovery_secret
from alethech.crypto import b64url, b64url_decode


@pytest.mark.parametrize("version", [1, 2])
def test_drop_context_accepts_both_envelopes(tmp_path, version):
    source = Alethech.initialize(tmp_path / "source")
    source.commit({"memory": "portable across envelopes"})
    path = tmp_path / "memory.aleth"
    if version == 1:
        source.seal(path, "passphrase")
    else:
        source.seal_v2(path, "passphrase")
    context = Alethech.drop_context(path, "passphrase")
    assert context["head"] == source.head
    assert context["entries"][0]["content"] == {"memory": "portable across envelopes"}


@pytest.mark.parametrize("existing_output", [False, True])
def test_recovery_rejects_authenticated_but_invalid_history(tmp_path, existing_output):
    source = Alethech.initialize(tmp_path / "source")
    ancestor = source.commit({"memory": "ancestor"})
    head = source.commit({"memory": "original"})
    path, recovery = source.seal_v2(tmp_path / "memory.aleth", "passphrase")
    payload, _ = _parse_v2(path.read_bytes(), passphrase="passphrase")
    assert ancestor.commit_id != head.commit_id
    commit_path = "commits/" + ancestor.commit_id + ".json"
    commit = json.loads(b64url_decode(payload["files"][commit_path]))
    commit["content"] = {"memory": "forged without signature"}
    payload["files"][commit_path] = b64url(json.dumps(commit).encode())
    path.write_bytes(_seal_payload_v2(
        payload, "passphrase", recovery_secret=decode_recovery_secret(recovery)
    ))
    before = path.read_bytes()
    output = tmp_path / "recovered.aleth"
    if existing_output:
        output.write_bytes(b"existing output must survive")
    with pytest.raises(ContainerError, match="verification"):
        Alethech.recover_aleth_v2(path, output, recovery, "new-passphrase")
    assert path.read_bytes() == before
    if existing_output:
        assert output.read_bytes() == b"existing output must survive"
    else:
        assert not output.exists()
