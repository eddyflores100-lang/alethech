"""Adversarial tests for ALETH002 recovery/unlock envelope."""
import json
import os
import struct

import pytest

from alethech import Alethech
from alethech.canonical import canonical_json_bytes
from alethech.container import ContainerError, inspect_container, seal_store
from alethech.container_v2 import (
    MAGIC_V2,
    decode_recovery_secret,
    encode_recovery_secret,
    inspect_container_v2,
    migrate_v1_to_v2,
    open_container_v2,
    recover_container_v2,
    seal_store_v2,
)


def _source(tmp_path):
    agent = Alethech.initialize(tmp_path / "source")
    ev = agent.evidence(
        tool="v2-test",
        input_bytes=b"request",
        output_bytes=b"response",
        artifacts={"proof.bin": b"proof"},
    )
    agent.commit({"memory": "recoverable"}, evidence_refs=[ev.commit_id])
    return agent


def _header_and_ciphertext(path):
    blob = path.read_bytes()
    assert blob[:8] == MAGIC_V2
    hlen = struct.unpack(">I", blob[8:12])[0]
    header = json.loads(blob[12:12 + hlen].decode())
    ciphertext = blob[12 + hlen:]
    return header, ciphertext


def _rewrite_header(path, header, ciphertext):
    hb = canonical_json_bytes(header)
    path.write_bytes(MAGIC_V2 + struct.pack(">I", len(hb)) + hb + ciphertext)


def test_v2_passphrase_and_recovery_open_same_verified_history(tmp_path):
    agent = _source(tmp_path)
    path = tmp_path / "memory-v2.aleth"
    path, recovery = seal_store_v2(agent.store, path, "passphrase-v2")

    assert recovery is not None
    assert recovery.startswith("aleth-recovery-v1:")
    assert recovery.encode() not in path.read_bytes()
    assert decode_recovery_secret(recovery) not in path.read_bytes()

    by_pass = inspect_container_v2(path, passphrase="passphrase-v2")
    by_recovery = inspect_container_v2(path, recovery_code=recovery)

    assert by_pass == by_recovery
    assert by_pass["version"] == 2
    assert by_pass["slot_types"] == ["passphrase", "recovery-secret"]

    store_a = open_container_v2(
        path, tmp_path / "opened-pass", passphrase="passphrase-v2"
    )
    store_b = open_container_v2(
        path, tmp_path / "opened-recovery", recovery_code=recovery
    )
    assert store_a.read_head() == agent.head == store_b.read_head()


def test_v2_wrong_credentials_fail_without_plaintext(tmp_path):
    agent = _source(tmp_path)
    path, recovery = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "correct"
    )
    assert recovery is not None

    with pytest.raises(ContainerError, match="passphrase unlock failed"):
        open_container_v2(path, tmp_path / "wrong-pass", passphrase="wrong")
    assert not (tmp_path / "wrong-pass").exists()

    wrong_recovery = encode_recovery_secret(os.urandom(32))
    with pytest.raises(ContainerError, match="recovery unlock failed"):
        open_container_v2(
            path, tmp_path / "wrong-recovery", recovery_code=wrong_recovery
        )
    assert not (tmp_path / "wrong-recovery").exists()


def test_recovery_replaces_forgotten_passphrase_and_preserves_history(tmp_path):
    agent = _source(tmp_path)
    original, recovery = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "forgotten"
    )
    assert recovery is not None
    before = inspect_container_v2(original, passphrase="forgotten")

    recovered, same_recovery = recover_container_v2(
        original,
        tmp_path / "recovered.aleth",
        recovery,
        "replacement-passphrase",
    )
    after = inspect_container_v2(recovered, passphrase="replacement-passphrase")

    assert same_recovery == recovery
    assert before["container_id"] == after["container_id"]
    assert before["plaintext_sha256"] == after["plaintext_sha256"]
    assert before["files"] == after["files"]

    with pytest.raises(ContainerError, match="passphrase unlock failed"):
        inspect_container_v2(recovered, passphrase="forgotten")

    via_recovery = inspect_container_v2(recovered, recovery_code=recovery)
    assert via_recovery["plaintext_sha256"] == before["plaintext_sha256"]


def test_recovery_secret_rotation_invalidates_old_code(tmp_path):
    agent = _source(tmp_path)
    original, old_code = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "old-pass"
    )
    assert old_code is not None

    rotated, new_code = recover_container_v2(
        original,
        tmp_path / "rotated-recovery.aleth",
        old_code,
        "new-pass",
        rotate_recovery=True,
    )
    assert new_code != old_code
    inspect_container_v2(rotated, passphrase="new-pass")
    inspect_container_v2(rotated, recovery_code=new_code)

    with pytest.raises(ContainerError, match="recovery unlock failed"):
        inspect_container_v2(rotated, recovery_code=old_code)


def test_v2_tampered_ciphertext_and_header_fail(tmp_path):
    agent = _source(tmp_path)
    path, recovery = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "correct"
    )
    assert recovery is not None

    tampered = tmp_path / "tampered-ciphertext.aleth"
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    tampered.write_bytes(data)
    with pytest.raises(ContainerError, match="payload authentication failed"):
        inspect_container_v2(tampered, passphrase="correct")

    header_bad = tmp_path / "tampered-header.aleth"
    header, ciphertext = _header_and_ciphertext(path)
    header["payload_nonce"] = header["payload_nonce"][:-1] + (
        "A" if header["payload_nonce"][-1] != "A" else "B"
    )
    _rewrite_header(header_bad, header, ciphertext)
    with pytest.raises(ContainerError):
        inspect_container_v2(header_bad, passphrase="correct")


def test_v2_tampered_wrapped_recovery_key_fails(tmp_path):
    agent = _source(tmp_path)
    path, recovery = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "correct"
    )
    assert recovery is not None

    header, ciphertext = _header_and_ciphertext(path)
    recovery_slot = next(s for s in header["slots"] if s["type"] == "recovery-secret")
    wrapped = recovery_slot["wrapped_key"]
    recovery_slot["wrapped_key"] = wrapped[:-1] + ("A" if wrapped[-1] != "A" else "B")
    bad = tmp_path / "bad-wrapped-key.aleth"
    _rewrite_header(bad, header, ciphertext)

    with pytest.raises(ContainerError, match="recovery unlock failed"):
        inspect_container_v2(bad, recovery_code=recovery)


def test_v2_recovery_slot_replay_between_containers_fails(tmp_path):
    a = _source(tmp_path / "a")
    b = _source(tmp_path / "b")
    path_a, code_a = seal_store_v2(a.store, tmp_path / "a.aleth", "pass-a")
    path_b, code_b = seal_store_v2(b.store, tmp_path / "b.aleth", "pass-b")
    assert code_a and code_b

    header_a, ciphertext_a = _header_and_ciphertext(path_a)
    header_b, _ = _header_and_ciphertext(path_b)
    slot_b = next(s for s in header_b["slots"] if s["type"] == "recovery-secret")
    header_a["slots"] = [
        s for s in header_a["slots"] if s["type"] != "recovery-secret"
    ] + [slot_b]

    replayed = tmp_path / "replayed-slot.aleth"
    _rewrite_header(replayed, header_a, ciphertext_a)

    with pytest.raises(ContainerError):
        inspect_container_v2(replayed, recovery_code=code_b)


def test_v1_to_v2_migration_preserves_logical_payload_and_source(tmp_path):
    agent = _source(tmp_path)
    v1 = tmp_path / "memory-v1.aleth"
    seal_store(agent.store, v1, "v1-pass")
    v1_meta = inspect_container(v1, "v1-pass")
    v1_bytes = v1.read_bytes()

    v2, recovery = migrate_v1_to_v2(
        v1,
        tmp_path / "memory-v2.aleth",
        "v1-pass",
        "v2-pass",
        create_recovery=True,
    )
    assert recovery is not None
    v2_meta = inspect_container_v2(v2, passphrase="v2-pass")

    assert v1_meta["plaintext_sha256"] == v2_meta["plaintext_sha256"]
    assert v1_meta["files"] == v2_meta["files"]
    assert v1.read_bytes() == v1_bytes
    assert inspect_container(v1, "v1-pass") == v1_meta

    restored = open_container_v2(v2, tmp_path / "restored", passphrase="v2-pass")
    assert restored.read_head() == agent.head


def test_v2_without_recovery_slot_remains_passphrase_only(tmp_path):
    agent = _source(tmp_path)
    path, recovery = seal_store_v2(
        agent.store,
        tmp_path / "no-recovery.aleth",
        "pass-only",
        create_recovery=False,
    )
    assert recovery is None
    meta = inspect_container_v2(path, passphrase="pass-only")
    assert meta["slot_types"] == ["passphrase"]

    with pytest.raises(ContainerError, match="recovery unlock failed"):
        inspect_container_v2(
            path,
            recovery_code=encode_recovery_secret(os.urandom(32)),
        )


def test_v2_requires_exactly_one_unlock_credential(tmp_path):
    agent = _source(tmp_path)
    path, recovery = seal_store_v2(
        agent.store, tmp_path / "memory-v2.aleth", "pass"
    )
    assert recovery is not None

    with pytest.raises(ContainerError, match="exactly one"):
        inspect_container_v2(path)
    with pytest.raises(ContainerError, match="exactly one"):
        inspect_container_v2(path, passphrase="pass", recovery_code=recovery)
