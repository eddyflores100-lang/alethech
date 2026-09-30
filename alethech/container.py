"""Encrypted portable .aleth container (draft v1 reference implementation)."""
from __future__ import annotations
import json, os, struct
from pathlib import Path, PurePosixPath
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .canonical import canonical_json_bytes
from .crypto import b64url, b64url_decode, sha256_hex
from .store import Store
from .verify import verify_store

MAGIC = b"ALETH001"
MAX_HEADER = 16 * 1024
MAX_CONTAINER = 512 * 1024 * 1024
MAX_FILES = 100_000
MAX_FILE = 100 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024

class ContainerError(Exception):
    pass

def _derive(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ContainerError("passphrase must be a non-empty string")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(passphrase.encode("utf-8"))

def _allowed(rel: str) -> bool:
    p = PurePosixPath(rel)
    if not rel or "\\" in rel or p.is_absolute() or any(x in ("", ".", "..") for x in p.parts):
        return False
    if rel in {"HEAD", "root_authority.json", "keys/signing.key"}:
        return True
    if len(p.parts) != 2:
        return False
    return p.parts[0] in {"identities","commits","evidence","artifacts","control_events","migrations","checkpoints"}

def _collect(root: Path) -> dict[str, str]:
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ContainerError(f"symlink not allowed: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in {"keys/root.key", "keys/recovery.key"}:
            continue
        if not _allowed(rel):
            continue
        data = path.read_bytes()
        if len(data) > MAX_FILE:
            raise ContainerError(f"file too large: {rel}")
        total += len(data)
        if total > MAX_TOTAL:
            raise ContainerError("payload too large")
        files[rel] = b64url(data)
        if len(files) > MAX_FILES:
            raise ContainerError("too many files")
    return files

def seal_store(store: Store, output: str | Path, passphrase: str) -> Path:
    """Seal a store into one authenticated encrypted .aleth file."""
    report = verify_store(store)
    if not report.ok:
        raise ContainerError("refusing to seal invalid store: " + report.summary())
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"cipher":"AES-256-GCM","format":"aleth","kdf":"scrypt",
              "nonce":b64url(nonce),"salt":b64url(salt),
              "scrypt_n":32768,"scrypt_p":1,"scrypt_r":8,"version":1}
    hb = canonical_json_bytes(header)
    payload = canonical_json_bytes({"files": _collect(store.root), "payload_version": 1})
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, payload, hb)
    blob = MAGIC + struct.pack(">I", len(hb)) + hb + ciphertext
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    output = Path(output)
    output.write_bytes(blob)
    return output

def _parse(blob: bytes, passphrase: str) -> dict:
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    if len(blob) < 12 or blob[:8] != MAGIC:
        raise ContainerError("invalid .aleth magic")
    hlen = struct.unpack(">I", blob[8:12])[0]
    if hlen == 0 or hlen > MAX_HEADER or 12 + hlen >= len(blob):
        raise ContainerError("invalid header length")
    hb, ciphertext = blob[12:12+hlen], blob[12+hlen:]
    try:
        header = json.loads(hb.decode("utf-8"))
    except Exception as exc:
        raise ContainerError("invalid header") from exc
    expected = {"cipher":"AES-256-GCM","format":"aleth","kdf":"scrypt",
                "scrypt_n":32768,"scrypt_p":1,"scrypt_r":8,"version":1}
    if any(header.get(k) != v for k,v in expected.items()):
        raise ContainerError("unsupported container parameters")
    if canonical_json_bytes(header) != hb:
        raise ContainerError("header is not canonical JCS")
    try:
        salt, nonce = b64url_decode(header["salt"]), b64url_decode(header["nonce"])
    except Exception as exc:
        raise ContainerError("invalid header encoding") from exc
    if len(salt) != 16 or len(nonce) != 12:
        raise ContainerError("invalid salt or nonce size")
    try:
        plain = AESGCM(_derive(passphrase, salt)).decrypt(nonce, ciphertext, hb)
    except InvalidTag as exc:
        raise ContainerError("authentication failed") from exc
    try:
        payload = json.loads(plain.decode("utf-8"))
    except Exception as exc:
        raise ContainerError("invalid encrypted payload") from exc
    if payload.get("payload_version") != 1 or not isinstance(payload.get("files"), dict):
        raise ContainerError("unsupported payload")
    return payload

def inspect_container(path: str | Path, passphrase: str) -> dict:
    """Authenticate/decrypt without materializing; return stable interop metadata."""
    payload = _parse(Path(path).read_bytes(), passphrase)
    return {
        "payload_version": payload["payload_version"],
        "files": sorted(payload["files"].keys()),
        "plaintext_sha256": sha256_hex(canonical_json_bytes(payload)),
    }

def open_container(path: str | Path, destination: str | Path, passphrase: str) -> Store:
    """Authenticate, decrypt, safely materialize, then verify a .aleth file."""
    payload = _parse(Path(path).read_bytes(), passphrase)
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ContainerError("destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    files = payload["files"]
    if len(files) > MAX_FILES:
        raise ContainerError("too many files")
    decoded = {}
    total = 0
    for rel, encoded in files.items():
        if not isinstance(rel, str) or not isinstance(encoded, str) or not _allowed(rel):
            raise ContainerError(f"invalid payload path: {rel!r}")
        try:
            data = b64url_decode(encoded)
        except Exception as exc:
            raise ContainerError(f"invalid payload encoding: {rel}") from exc
        if len(data) > MAX_FILE:
            raise ContainerError(f"file too large: {rel}")
        total += len(data)
        if total > MAX_TOTAL:
            raise ContainerError("payload too large")
        decoded[rel] = data
    try:
        for rel, data in decoded.items():
            target = destination / PurePosixPath(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        store = Store.open(destination)
        report = verify_store(store)
        if not report.ok:
            raise ContainerError("decrypted store failed verification: " + report.summary())
        return store
    except Exception:
        # Never leave a partially accepted plaintext store behind.
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise
