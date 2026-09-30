"""The frozen envelope must keep opening after implementation changes."""
import hashlib
import json
from pathlib import Path

from alethech import Alethech
from alethech.container_v2 import _parse_v2
from alethech.crypto import b64url_decode


def test_frozen_v2_vector_preserves_payload_and_verified_history(tmp_path):
    fixture = json.loads((Path(__file__).parents[1] /
                         "conformance/container_v2/golden.vector").read_text())
    blob = b64url_decode(fixture["container_base64url"])
    assert hashlib.sha256(blob).hexdigest() == fixture["sha256"]
    path = tmp_path / "golden.aleth"
    path.write_bytes(blob)
    for credential in ("passphrase", "recovery_code"):
        kwargs = {credential: fixture[credential]}
        payload, header = _parse_v2(blob, **kwargs)
        assert payload == fixture["expected"]["payload"]
        assert not any(name.startswith("keys/") for name in payload["files"])
        assert header["container_id"] == fixture["expected"]["container_id"]
        agent = Alethech.open_aleth_v2(path, tmp_path / credential, **kwargs)
        assert agent.head == fixture["head"]
        assert agent.verify().ok
        assert agent.context()["entries"][0]["content"] == {
            "memory": "Golden ALETH002: memoria portable — 日本語"
        }
