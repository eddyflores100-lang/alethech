"""Encrypted portable .aleth container (draft v1 reference implementation)."""
from __future__ import annotations
import json, os, struct, shutil, tempfile, sys
from pathlib import Path, PurePosixPath
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from .canonical import canonical_json_bytes
from .crypto import b64url, b64url_decode, sha256_hex
from .store import Store, portable_fs_name, logical_id_from_fs_name
from .verify import verify_store

MAGIC = b"ALETH001"
MAX_HEADER = 16 * 1024
MAX_CONTAINER = 512 * 1024 * 1024
MAX_FILES = 100_000
MAX_FILE = 100 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024

class ContainerError(Exception):
    pass

def _read_container(path: str | Path) -> bytes:
    with Path(path).open("rb") as handle:
        blob = handle.read(MAX_CONTAINER + 1)
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    return blob


def _atomic_write(output: Path, blob: bytes) -> None:
    """Publish a flushed private file. Rename is the commit point.

    Parent-directory fsync is best effort after commit: a durability failure
    cannot roll back publication and must not discard a generated credential.
    """
    fd, name = tempfile.mkstemp(prefix="." + output.name + ".", suffix=".tmp", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            if hasattr(os, "fchmod"):
                os.fchmod(handle.fileno(), 0o600)
            handle.write(blob)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
        # Directory durability is best effort once replacement has committed.
        if os.name == "posix":
            try:
                directory_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
    finally:
        temporary.unlink(missing_ok=True)


def _strict_b64(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64url must be a string")
    decoded = b64url_decode(value)
    if b64url(decoded) != value:
        raise ValueError("base64url must be canonical unpadded encoding")
    return decoded


def _derive(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise ContainerError("passphrase must be a non-empty string")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(passphrase.encode("utf-8"))

def _allowed(rel: str) -> bool:
    p = PurePosixPath(rel)
    if not rel or "\x00" in rel or p.as_posix() != rel or "\\" in rel or p.is_absolute() or any(x in ("", ".", "..") for x in p.parts):
        return False
    if rel in {"HEAD", "root_authority.json", "keys/signing.key"}:
        return True
    if len(p.parts) != 2:
        return False
    return p.parts[0] in {"identities","commits","evidence","artifacts","control_events","migrations","checkpoints"}

def _logical_rel_from_physical(rel: str) -> str:
    """Map portable/legacy physical store paths to canonical .aleth logical paths."""
    p = PurePosixPath(rel)
    if len(p.parts) != 2:
        return rel
    directory, name = p.parts
    if directory in {"identities", "commits", "evidence", "control_events", "migrations", "checkpoints"}:
        if name.endswith(".json"):
            stem = name[:-5]
            return f"{directory}/{logical_id_from_fs_name(stem)}.json"
    if directory == "artifacts":
        return f"artifacts/{logical_id_from_fs_name(name)}"
    return rel


def _physical_rel_from_logical(rel: str) -> str:
    """Map canonical .aleth logical paths to portable cross-platform filenames."""
    p = PurePosixPath(rel)
    if len(p.parts) != 2:
        return rel
    directory, name = p.parts
    if directory in {"identities", "commits", "evidence", "control_events", "migrations", "checkpoints"}:
        if name.endswith(".json"):
            stem = name[:-5]
            return f"{directory}/{portable_fs_name(stem)}.json"
    if directory == "artifacts":
        return f"artifacts/{portable_fs_name(name)}"
    return rel


def _collect(root: Path) -> dict[str, str]:
    files = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ContainerError(f"symlink not allowed: {path}")
        if not path.is_file():
            continue
        physical_rel = path.relative_to(root).as_posix()
        if physical_rel in {"keys/root.key", "keys/recovery.key"}:
            continue
        rel = _logical_rel_from_physical(physical_rel)
        if not _allowed(rel):
            continue
        with path.open("rb") as handle:
            data = handle.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ContainerError(f"file too large: {rel}")
        total += len(data)
        if total > MAX_TOTAL:
            raise ContainerError("payload too large")
        files[rel] = b64url(data)
        if len(files) > MAX_FILES:
            raise ContainerError("too many files")
    return files

def _verify_portable_signing_key(store: Store) -> None:
    """Ensure the operational private key belongs to the identity being moved."""
    try:
        signing_jwk = store.load_signing_key().public_jwk()
    except Exception as exc:
        raise ContainerError("portable signing key unavailable") from exc

    v2 = store.load_identity_records_v2()
    if v2:
        if len(v2) != 1:
            raise ContainerError("portable v1 requires exactly one current identity")
        identity = next(iter(v2.values()))
        matches = [
            item for item in identity.active_keys
            if isinstance(item, dict) and item.get("public_key") == signing_jwk
        ]
        if not matches:
            raise ContainerError("signing key does not match an active identity key")
        return

    legacy = store.load_identities()
    if len(legacy) != 1:
        raise ContainerError("portable v1 requires exactly one legacy identity")
    identity = next(iter(legacy.values()))
    if identity.public_key != signing_jwk:
        raise ContainerError("signing key does not match identity")


def _decode_payload_files(payload: dict) -> dict[str, bytes]:
    """Validate the logical v1 payload and decode every file fail-closed."""
    if (not isinstance(payload, dict) or set(payload) != {"payload_version", "files"}
            or type(payload.get("payload_version")) is not int or payload["payload_version"] != 1
            or not isinstance(payload.get("files"), dict)):
        raise ContainerError("unsupported payload")
    files = payload["files"]
    if len(files) > MAX_FILES:
        raise ContainerError("too many files")

    decoded: dict[str, bytes] = {}
    total = 0
    for rel, encoded in files.items():
        if not isinstance(rel, str) or not isinstance(encoded, str) or not _allowed(rel):
            raise ContainerError(f"invalid payload path: {rel!r}")
        if len(encoded) > (MAX_FILE * 4 + 2) // 3:
            raise ContainerError(f"file too large: {rel}")
        try:
            data = _strict_b64(encoded)
        except Exception as exc:
            raise ContainerError(f"invalid payload encoding: {rel}") from exc
        if len(data) > MAX_FILE:
            raise ContainerError(f"file too large: {rel}")
        total += len(data)
        if total > MAX_TOTAL:
            raise ContainerError("payload too large")
        decoded[rel] = data
    return decoded


def _seal_payload_bytes(payload: dict, passphrase: str) -> bytes:
    """Encrypt one already-formed logical payload as an ALETH001 container."""
    _decode_payload_files(payload)
    salt, nonce = os.urandom(16), os.urandom(12)
    header = {"cipher":"AES-256-GCM","format":"aleth","kdf":"scrypt",
              "nonce":b64url(nonce),"salt":b64url(salt),
              "scrypt_n":32768,"scrypt_p":1,"scrypt_r":8,"version":1}
    hb = canonical_json_bytes(header)
    plain = canonical_json_bytes(payload)
    if len(plain) > MAX_TOTAL:
        raise ContainerError("payload too large")
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, plain, hb)
    blob = MAGIC + struct.pack(">I", len(hb)) + hb + ciphertext
    if len(blob) > MAX_CONTAINER:
        raise ContainerError("container too large")
    return blob


def seal_store(store: Store, output: str | Path, passphrase: str) -> Path:
    """Seal a store into one authenticated encrypted .aleth file."""
    report = verify_store(store)
    if not report.ok:
        raise ContainerError("refusing to seal invalid store: " + report.summary())
    _verify_portable_signing_key(store)
    payload = {"files": _collect(store.root), "payload_version": 1}
    _verify_payload(payload)
    blob = _seal_payload_bytes(payload, passphrase)
    _parse(blob, passphrase)
    output = Path(output)
    _atomic_write(output, blob)
    return output


def rekey_container(
    path: str | Path,
    output: str | Path,
    old_passphrase: str,
    new_passphrase: str,
) -> Path:
    """Rotate the encryption of a fully verified ALETH001 payload."""
    payload = _parse(_read_container(path), old_passphrase)
    with tempfile.TemporaryDirectory(prefix="alethech-rekey-") as tmp:
        _materialize_payload(payload, Path(tmp) / "store")
    blob = _seal_payload_bytes(payload, new_passphrase)
    _parse(blob, new_passphrase)
    target = Path(output)
    _atomic_write(target, blob)
    return target

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
    if (not isinstance(header, dict) or set(header) != set(expected) | {"salt", "nonce"}
            or any(type(header.get(k)) is not type(v) or header[k] != v for k, v in expected.items())):
        raise ContainerError("unsupported container parameters")
    if canonical_json_bytes(header) != hb:
        raise ContainerError("header is not canonical JCS")
    try:
        salt, nonce = _strict_b64(header["salt"]), _strict_b64(header["nonce"])
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
    if (not isinstance(payload, dict) or set(payload) != {"payload_version", "files"}
            or type(payload.get("payload_version")) is not int or payload["payload_version"] != 1
            or not isinstance(payload.get("files"), dict)):
        raise ContainerError("unsupported payload")
    _decode_payload_files(payload)
    return payload

def inspect_container(path: str | Path, passphrase: str) -> dict:
    """Authenticate/decrypt without materializing; return stable interop metadata."""
    payload = _parse(_read_container(path), passphrase)
    return {
        "payload_version": payload["payload_version"],
        "files": sorted(payload["files"].keys()),
        "plaintext_sha256": sha256_hex(canonical_json_bytes(payload)),
    }

def open_container(path: str | Path, destination: str | Path, passphrase: str) -> Store:
    """Authenticate, decrypt, safely materialize, then verify a .aleth file."""
    payload = _parse(_read_container(path), passphrase)
    return _materialize_payload(payload, Path(destination))


def _materialize_payload(payload: dict, destination: Path) -> Store:
    """Verify in a private sibling directory before publishing plaintext."""
    if destination.is_symlink() or (destination.exists() and
            (not destination.is_dir() or any(destination.iterdir()))):
        raise ContainerError("destination must be empty")
    decoded = _decode_payload_files(payload)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix="." + destination.name + ".", dir=destination.parent))
    try:
        physical_paths: set[str] = set()
        for rel, data in decoded.items():
            physical_rel = _physical_rel_from_logical(rel)
            if physical_rel in physical_paths:
                raise ContainerError("colliding payload paths")
            physical_paths.add(physical_rel)
            target = stage / PurePosixPath(physical_rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                if hasattr(os, "fchmod"):
                    os.fchmod(handle.fileno(), 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        store = Store.open(stage)
        report = verify_store(store)
        if not report.ok:
            raise ContainerError("decrypted store failed verification: " + report.summary())
        if "keys/signing.key" in decoded:
            _verify_portable_signing_key(store)
        removed_empty_destination = False
        if sys.platform == "win32" and destination.exists():
            # Windows cannot replace an existing directory, even when empty.
            # Remove it only after full validation; restore it on rename failure.
            destination.rmdir()
            removed_empty_destination = True
        try:
            os.replace(stage, destination)
        except Exception:
            if removed_empty_destination and not destination.exists():
                destination.mkdir()
            raise
        return Store.open(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def _verify_payload(payload: dict) -> None:
    """Verify the immutable snapshot which will actually be encrypted."""
    with tempfile.TemporaryDirectory(prefix="alethech-snapshot-") as tmp:
        _materialize_payload(payload, Path(tmp) / "store")
