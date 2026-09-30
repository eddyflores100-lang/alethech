"""ALETH002 encrypted container reference implementation.

ALETH002 separates payload encryption from unlock credentials:
a random 256-bit DEK encrypts the payload, while passphrase and recovery slots
wrap only that DEK. Container recovery is intentionally separate from Alethech
identity/root authority.

ALETH001 remains implemented in alethech.container.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .canonical import canonical_json_bytes
from .container import (
    ContainerError,
    MAX_CONTAINER,
    MAX_FILES,
    MAX_HEADER,
    MAX_TOTAL,
    _collect,
    _decode_payload_files,
    _physical_rel_from_logical,
    _verify_portable_signing_key,
)
from .crypto import b64url, b64url_decode, sha256_hex
from .store import Store
from .verify import verify_store

MAGIC_V2 = b"ALETH002"
RECOVERY_PREFIX = "aleth-recovery-v1:"
RECOVERY_INFO = b"alethech-container-recovery-v1"
MAX_SLOTS = 16


def _derive_passphrase_kek(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ContainerError("passphrase must be a non-empty string")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


def _derive_recovery_kek(secret: bytes, salt: bytes) -> bytes:
    if len(secret) != 32:
        raise ContainerError("recovery secret must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=RECOVERY_INFO,
    ).derive(secret)


def encode_recovery_secret(secret: bytes) -> str:
    if len(secret) != 32:
        raise ContainerError("recovery secret must be 32 bytes")
    return RECOVERY_PREFIX + b64url(secret)


def decode_recovery_secret(code: str) -> bytes:
    if not isinstance(code, str) or not code.startswith(RECOVERY_PREFIX):
        raise ContainerError("invalid recovery code")
    try:
        secret = b64url_decode(code[len(RECOVERY_PREFIX):])
    except Exception as exc:
        raise ContainerError("invalid recovery code") from exc
    if len(secret) != 32:
        raise ContainerError("invalid recovery code")
    return secret


def _slot_aad(container_id: str, slot_id: str, slot_type: str) -> bytes:
    return canonical_json_bytes({
        "container_id": container_id,
        "envelope_version": 2,
        "slot_id": slot_id,
        "slot_type": slot_type,
    })


def _wrap_dek(
    dek: bytes,
    kek: bytes,
    *,
    container_id: str,
    slot_id: str,
    slot_type: str,
    nonce: bytes,
) -> str:
    return b64url(
        AESGCM(kek).encrypt(
            nonce,
            dek,
            _slot_aad(container_id, slot_id, slot_type),
        )
    )


def _unwrap_dek(
    wrapped_key: str,
    kek: bytes,
    *,
    container_id: str,
    slot_id: str,
    slot_type: str,
    nonce: bytes,
) -> bytes:
    try:
        wrapped = b64url_decode(wrapped_key)
    except Exception as exc:
        raise ContainerError("invalid wrapped key") from exc
    if len(wrapped) != 48:
        raise ContainerError("invalid wrapped key")
    try:
        dek = AESGCM(kek).decrypt(
            nonce,
            wrapped,
            _slot_aad(container_id, slot_id, slot_type),
        )
    except InvalidTag as exc:
        raise ContainerError("unlock credential invalid") from exc
    if len(dek) != 32:
        raise ContainerError("invalid unwrapped data key")
    return dek


def _passphrase_slot(dek: bytes, passphrase: str, container_id: str) -> dict[str, Any]:
    salt, nonce = os.urandom(16), os.urandom(12)
    slot_id = "passphrase-1"
    kek = _derive_passphrase_kek(passphrase, salt)
    return {
        "id": slot_id,
        "kdf": "scrypt",
        "nonce": b64url(nonce),
        "salt": b64url(salt),
        "scrypt_n": 32768,
        "scrypt_p": 1,
        "scrypt_r": 8,
        "type": "passphrase",
        "wrapped_key": _wrap_dek(
            dek,
            kek,
            container_id=container_id,
            slot_id=slot_id,
            slot_type="passphrase",
            nonce=nonce,
        ),
    }


def _recovery_slot(dek: bytes, secret: bytes, container_id: str) -> dict[str, Any]:
    salt, nonce = os.urandom(16), os.urandom(12)
    slot_id = "recovery-1"
    kek = _derive_recovery_kek(secret, salt)
    return {
        "id": slot_id,
        "kdf": "HKDF-SHA256",
        "nonce": b64url(nonce),
        "salt": b64url(salt),
        "type": "recovery-secret",
        "wrapped_key": _wrap_dek(
            dek,
            kek,
            container_id=container_id,
            slot_id=slot_id,
            slot_type="recovery-secret",
            nonce=nonce,
        ),
    }


def _validate_slot(slot: Any) -> None:
    if not isinstance(slot, dict):
        raise ContainerError("invalid unlock slot")
    slot_type = slot.get("type")
    if slot_type == "passphrase":
        expected = {
            "id", "kdf", "nonce", "salt", "scrypt_n", "scrypt_p",
            "scrypt_r", "type", "wrapped_key",
        }
        if set(slot) != expected:
            raise ContainerError("invalid passphrase slot schema")
        if (
            slot.get("kdf") != "scrypt"
            or slot.get("scrypt_n") != 32768
            or slot.get("scrypt_p") != 1
            or slot.get("scrypt_r") != 8
        ):
            raise ContainerError("unsupported passphrase slot parameters")
    elif slot_type == "recovery-secret":
        expected = {"id", "kdf", "nonce", "salt", "type", "wrapped_key"}
        if set(slot) != expected:
            raise ContainerError("invalid recovery slot schema")
        if slot.get("kdf") != "HKDF-SHA256":
            raise ContainerError("unsupported recovery slot parameters")
    else:
        raise ContainerError("unsupported unlock slot type")

    if not isinstance(slot.get("id"), str) or not slot["id"]:
        raise ContainerError("invalid slot id")
    try:
        nonce = b64url_decode(slot["nonce"])
        salt = b64url_decode(slot["salt"])
        wrapped = b64url_decode(slot["wrapped_key"])
    except Exception as exc:
        raise ContainerError("invalid unlock slot encoding") from exc
    if len(nonce) != 12 or len(salt) != 16 or len(wrapped) != 48:
        raise ContainerError("invalid unlock slot sizes")


def _validate_header(header: Any) -> None:
    if not isinstance(header, dict):
        raise ContainerError("invalid v2 header")
    expected = {
        "container_id",
        "format",
        "payload_cipher",
        "payload_nonce",
        "slots",
        "version",
    }
    if set(header) != expected:
        raise ContainerError("invalid v2 header schema")
    if (
        header.get("format") != "aleth"
        or header.get("payload_cipher") != "AES-256-GCM"
        or header.get("version") != 2
    ):
        raise ContainerError("unsupported v2 container parameters")
    try:
        container_id = b64url_decode(header["container_id"])
        payload_nonce = b64url_decode(header["payload_nonce"])
    except Exception as exc:
        raise ContainerError("invalid v2 header encoding") from exc
    if len(container_id) != 16 or len(payload_nonce) != 12:
        raise ContainerError("invalid v2 header sizes")

    slots = header.get("slots")
    if not isinstance(slots, list) or not slots or len(slots) > MAX_SLOTS:
        raise ContainerError("invalid unlock slots")
    seen: set[str] = set()
    for slot in slots:
        _validate_slot(slot)
        if slot["id"] in seen:
            raise ContainerError("duplicate unlock slot id")
        seen.add(slot["id"])


def _seal_payload_v2(
    payload: dict,
    passphrase: str,
    *,
    recovery_secret: bytes | None = None,
    container_id: bytes | None = None,
) -> bytes:
    _decode_payload_files(payload)
    if container_id is None:
        container_id = os.urandom(16)
    if len(container_id) != 16:
        raise ContainerError("container_id must be 16 bytes")

    dek = os.urandom(32)
    container_id_s = b64url(container_id)
    slots = [_passphrase_slot(dek, passphrase, container_id_s)]
    if recovery_secret is not None:
        if len(recovery_secret) != 32:
            raise ContainerError("recovery secret must be 32 bytes")
        slots.append(_recovery_slot(dek, recovery_secret, container_id_s))

    payload_nonce = os.urandom(12)
    header = {
        "container_id": container_id_s,
        "format": "aleth",
        "payload_cipher": "AES-256-GCM",
        "payload_nonce": b64url(payload_nonce),
        "slots": slots,
        "version": 2,
    }
    _validate_header(header)
    hb = canonical_json_bytes(header)
    if len(hb) > MAX_HEADER:
        raise ContainerError("header too large")
    plain = canonical_json_bytes(payload)
    if len(plain) > MAX_TOTAL:
        raise ContainerError("payload too large")

    encrypted = AESGCM(dek).encrypt(payload_nonce, plain, hb)
    blob = MAGIC_V2 + struct.pack(">I", len(hb)) + hb + encrypted
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    return blob


def seal_store_v2(
    store: Store,
    output: str | Path,
    passphrase: str,
    *,
    create_recovery: bool = True,
) -> tuple[Path, str | None]:
    """Seal a verified store as ALETH002 and optionally return a recovery code."""
    report = verify_store(store)
    if not report.ok:
        raise ContainerError("refusing to seal invalid store: " + report.summary())
    _verify_portable_signing_key(store)
    payload = {"files": _collect(store.root), "payload_version": 1}
    recovery_secret = os.urandom(32) if create_recovery else None
    blob = _seal_payload_v2(
        payload,
        passphrase,
        recovery_secret=recovery_secret,
    )
    output = Path(output)
    output.write_bytes(blob)
    return output, (
        encode_recovery_secret(recovery_secret)
        if recovery_secret is not None
        else None
    )


def _parse_header_v2(blob: bytes) -> tuple[dict, bytes, bytes]:
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    if len(blob) < 12 or blob[:8] != MAGIC_V2:
        raise ContainerError("invalid ALETH002 magic")
    hlen = struct.unpack(">I", blob[8:12])[0]
    if hlen == 0 or hlen > MAX_HEADER or 12 + hlen >= len(blob):
        raise ContainerError("invalid header length")

    hb = blob[12:12 + hlen]
    encrypted = blob[12 + hlen:]
    if len(encrypted) < 16:
        raise ContainerError("truncated ciphertext")
    try:
        header = json.loads(hb.decode("utf-8"))
    except Exception as exc:
        raise ContainerError("invalid v2 header") from exc
    _validate_header(header)
    if canonical_json_bytes(header) != hb:
        raise ContainerError("v2 header is not canonical JCS")
    return header, hb, encrypted


def _unlock_dek_with_passphrase(header: dict, passphrase: str) -> bytes:
    for slot in header["slots"]:
        if slot["type"] != "passphrase":
            continue
        try:
            salt = b64url_decode(slot["salt"])
            nonce = b64url_decode(slot["nonce"])
            kek = _derive_passphrase_kek(passphrase, salt)
            return _unwrap_dek(
                slot["wrapped_key"],
                kek,
                container_id=header["container_id"],
                slot_id=slot["id"],
                slot_type=slot["type"],
                nonce=nonce,
            )
        except ContainerError:
            continue
    raise ContainerError("passphrase unlock failed")


def _unlock_dek_with_recovery(header: dict, recovery_code: str) -> bytes:
    secret = decode_recovery_secret(recovery_code)
    for slot in header["slots"]:
        if slot["type"] != "recovery-secret":
            continue
        try:
            salt = b64url_decode(slot["salt"])
            nonce = b64url_decode(slot["nonce"])
            kek = _derive_recovery_kek(secret, salt)
            return _unwrap_dek(
                slot["wrapped_key"],
                kek,
                container_id=header["container_id"],
                slot_id=slot["id"],
                slot_type=slot["type"],
                nonce=nonce,
            )
        except ContainerError:
            continue
    raise ContainerError("recovery unlock failed")


def _parse_v2(
    blob: bytes,
    *,
    passphrase: str | None = None,
    recovery_code: str | None = None,
) -> tuple[dict, dict]:
    if (passphrase is None) == (recovery_code is None):
        raise ContainerError("provide exactly one unlock credential")

    header, hb, encrypted = _parse_header_v2(blob)
    if passphrase is not None:
        dek = _unlock_dek_with_passphrase(header, passphrase)
    else:
        assert recovery_code is not None
        dek = _unlock_dek_with_recovery(header, recovery_code)

    try:
        nonce = b64url_decode(header["payload_nonce"])
        plain = AESGCM(dek).decrypt(nonce, encrypted, hb)
    except InvalidTag as exc:
        raise ContainerError("payload authentication failed") from exc

    try:
        payload = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise ContainerError("invalid encrypted payload") from exc
    _decode_payload_files(payload)
    return payload, header


def inspect_container_v2(
    path: str | Path,
    *,
    passphrase: str | None = None,
    recovery_code: str | None = None,
) -> dict:
    payload, header = _parse_v2(
        Path(path).read_bytes(),
        passphrase=passphrase,
        recovery_code=recovery_code,
    )
    return {
        "version": 2,
        "container_id": header["container_id"],
        "payload_version": payload["payload_version"],
        "files": sorted(payload["files"]),
        "plaintext_sha256": sha256_hex(canonical_json_bytes(payload)),
        "slot_types": sorted(slot["type"] for slot in header["slots"]),
    }


def _materialize_payload(payload: dict, destination: Path) -> Store:
    if destination.exists() and any(destination.iterdir()):
        raise ContainerError("destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    decoded = _decode_payload_files(payload)
    try:
        for rel, data in decoded.items():
            physical_rel = _physical_rel_from_logical(rel)
            target = destination / PurePosixPath(physical_rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        store = Store.open(destination)
        report = verify_store(store)
        if not report.ok:
            raise ContainerError(
                "decrypted store failed verification: " + report.summary()
            )
        return store
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def open_container_v2(
    path: str | Path,
    destination: str | Path,
    *,
    passphrase: str | None = None,
    recovery_code: str | None = None,
) -> Store:
    payload, _ = _parse_v2(
        Path(path).read_bytes(),
        passphrase=passphrase,
        recovery_code=recovery_code,
    )
    return _materialize_payload(payload, Path(destination))


def recover_container_v2(
    path: str | Path,
    output: str | Path,
    recovery_code: str,
    new_passphrase: str,
    *,
    rotate_recovery: bool = False,
) -> tuple[Path, str]:
    """Recover ALETH002 and replace its passphrase."""
    payload, header = _parse_v2(
        Path(path).read_bytes(),
        recovery_code=recovery_code,
    )
    # Envelope authentication does not establish protocol validity. Verify
    # signatures and history before writing any replacement container.
    with tempfile.TemporaryDirectory(prefix="alethech-recovery-") as tmp:
        _materialize_payload(payload, Path(tmp) / "store")

    current_secret = decode_recovery_secret(recovery_code)
    next_secret = os.urandom(32) if rotate_recovery else current_secret
    container_id = b64url_decode(header["container_id"])
    blob = _seal_payload_v2(
        payload,
        new_passphrase,
        recovery_secret=next_secret,
        container_id=container_id,
    )
    output = Path(output)
    output.write_bytes(blob)
    return output, encode_recovery_secret(next_secret)


def migrate_v1_to_v2(
    path: str | Path,
    output: str | Path,
    old_passphrase: str,
    new_passphrase: str,
    *,
    create_recovery: bool = True,
) -> tuple[Path, str | None]:
    """Explicitly migrate an authenticated ALETH001 container to ALETH002."""
    from .container import _parse

    payload = _parse(Path(path).read_bytes(), old_passphrase)

    # Full protocol verification before changing envelope versions.
    with tempfile.TemporaryDirectory(prefix="alethech-v1-v2-") as tmp:
        _materialize_payload(payload, Path(tmp) / "store")

    recovery_secret = os.urandom(32) if create_recovery else None
    blob = _seal_payload_v2(
        payload,
        new_passphrase,
        recovery_secret=recovery_secret,
    )
    output = Path(output)
    output.write_bytes(blob)

    # Do not report success until the produced v2 container re-opens.
    inspect_container_v2(output, passphrase=new_passphrase)
    return output, (
        encode_recovery_secret(recovery_secret)
        if recovery_secret is not None
        else None
    )
