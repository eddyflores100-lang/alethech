use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use alethech::canonical::canonical_json;
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{env, fs, io::{Read, Write}, path::Path, process::{self, Command, Stdio}};

const MAGIC: &[u8; 8] = b"ALETH002";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;
const MAX_FILE: usize = 100 * 1024 * 1024;
const MAX_TOTAL: usize = 512 * 1024 * 1024;
const MAX_FILES: usize = 100_000;
const RECOVERY_PREFIX: &str = "aleth-recovery-v1:";
const RECOVERY_INFO: &[u8] = b"alethech-container-recovery-v1";

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn decode_b64(s: &str, what: &str) -> Vec<u8> {
    let decoded = Base64UrlUnpadded::decode_vec(s).unwrap_or_else(|_| fail(what));
    if Base64UrlUnpadded::encode_string(&decoded) != s {
        fail(what);
    }
    decoded
}

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != expected.len() {
        return false;
    }
    expected.iter().all(|k| obj.contains_key(*k))
}

fn allowed_path(rel: &str) -> bool {
    if rel.is_empty()
        || rel.contains('\\')
        || rel.contains('\0')
        || rel.starts_with('/')
        || rel.split('/').any(|p| p.is_empty() || p == "." || p == "..")
    {
        return false;
    }
    if matches!(rel, "HEAD" | "root_authority.json" | "keys/signing.key") {
        return true;
    }
    let parts: Vec<&str> = rel.split('/').collect();
    parts.len() == 2
        && matches!(
            parts[0],
            "identities"
                | "commits"
                | "evidence"
                | "artifacts"
                | "control_events"
                | "migrations"
                | "checkpoints"
        )
}

fn validate_slot(slot: &Value) {
    let Some(obj) = slot.as_object() else {
        fail("invalid unlock slot");
    };
    let slot_type = obj
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("invalid unlock slot type"));

    match slot_type {
        "passphrase" => {
            let expected = [
                "id",
                "kdf",
                "nonce",
                "salt",
                "scrypt_n",
                "scrypt_p",
                "scrypt_r",
                "type",
                "wrapped_key",
            ];
            if !exact_keys(slot, &expected) {
                fail("invalid passphrase slot schema");
            }
            if obj.get("kdf").and_then(Value::as_str) != Some("scrypt")
                || obj.get("scrypt_n").and_then(Value::as_u64) != Some(32768)
                || obj.get("scrypt_r").and_then(Value::as_u64) != Some(8)
                || obj.get("scrypt_p").and_then(Value::as_u64) != Some(1)
            {
                fail("unsupported passphrase slot parameters");
            }
        }
        "recovery-secret" => {
            let expected = ["id", "kdf", "nonce", "salt", "type", "wrapped_key"];
            if !exact_keys(slot, &expected) {
                fail("invalid recovery slot schema");
            }
            if obj.get("kdf").and_then(Value::as_str) != Some("HKDF-SHA256") {
                fail("unsupported recovery slot parameters");
            }
        }
        _ => fail("unsupported unlock slot type"),
    }

    if obj.get("id").and_then(Value::as_str).unwrap_or("").is_empty() {
        fail("invalid slot id");
    }
    let nonce = decode_b64(
        obj.get("nonce").and_then(Value::as_str).unwrap_or(""),
        "invalid unlock slot encoding",
    );
    let salt = decode_b64(
        obj.get("salt").and_then(Value::as_str).unwrap_or(""),
        "invalid unlock slot encoding",
    );
    let wrapped = decode_b64(
        obj.get("wrapped_key").and_then(Value::as_str).unwrap_or(""),
        "invalid unlock slot encoding",
    );
    if nonce.len() != 12 || salt.len() != 16 || wrapped.len() != 48 {
        fail("invalid unlock slot sizes");
    }
}

fn validate_header(header: &Value) {
    let expected = [
        "container_id",
        "format",
        "payload_cipher",
        "payload_nonce",
        "slots",
        "version",
    ];
    if !exact_keys(header, &expected) {
        fail("invalid v2 header schema");
    }
    if header.get("format").and_then(Value::as_str) != Some("aleth")
        || header.get("payload_cipher").and_then(Value::as_str) != Some("AES-256-GCM")
        || header.get("version").and_then(Value::as_u64) != Some(2)
    {
        fail("unsupported v2 container parameters");
    }

    let container_id = decode_b64(
        header
            .get("container_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "invalid v2 header encoding",
    );
    let payload_nonce = decode_b64(
        header
            .get("payload_nonce")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "invalid v2 header encoding",
    );
    if container_id.len() != 16 || payload_nonce.len() != 12 {
        fail("invalid v2 header sizes");
    }

    let slots = header
        .get("slots")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("invalid unlock slots"));
    if slots.is_empty() || slots.len() > 16 {
        fail("invalid unlock slots");
    }
    let mut ids = std::collections::HashSet::new();
    for slot in slots {
        validate_slot(slot);
        let id = slot
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("invalid slot id"));
        if !ids.insert(id.to_string()) {
            fail("duplicate unlock slot id");
        }
    }
}

fn slot_aad(container_id: &str, slot_id: &str, slot_type: &str) -> Vec<u8> {
    canonical_json(&json!({
        "container_id": container_id,
        "envelope_version": 2,
        "slot_id": slot_id,
        "slot_type": slot_type,
    }))
    .into_bytes()
}

fn derive_passphrase_kek(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    if passphrase.is_empty() {
        fail("passphrase must be non-empty");
    }
    let params = Params::new(15, 8, 1, 32).unwrap_or_else(|_| fail("invalid scrypt params"));
    let mut out = [0u8; 32];
    scrypt(passphrase.as_bytes(), salt, &params, &mut out)
        .unwrap_or_else(|_| fail("scrypt failed"));
    out
}

fn derive_recovery_kek(secret: &[u8], salt: &[u8]) -> [u8; 32] {
    if secret.len() != 32 {
        fail("recovery secret must be 32 bytes");
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = [0u8; 32];
    hk.expand(RECOVERY_INFO, &mut out)
        .unwrap_or_else(|_| fail("HKDF failed"));
    out
}

fn decode_recovery_code(code: &str) -> Vec<u8> {
    let encoded = code
        .strip_prefix(RECOVERY_PREFIX)
        .unwrap_or_else(|| fail("invalid recovery code"));
    let secret = decode_b64(encoded, "invalid recovery code");
    if secret.len() != 32 {
        fail("invalid recovery code");
    }
    secret
}

fn unwrap_dek(slot: &Value, kek: &[u8; 32], container_id: &str) -> Option<[u8; 32]> {
    let slot_id = slot.get("id")?.as_str()?;
    let slot_type = slot.get("type")?.as_str()?;
    let nonce = Base64UrlUnpadded::decode_vec(slot.get("nonce")?.as_str()?).ok()?;
    let wrapped = Base64UrlUnpadded::decode_vec(slot.get("wrapped_key")?.as_str()?).ok()?;
    if nonce.len() != 12 || wrapped.len() != 48 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(kek).ok()?;
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &wrapped,
                aad: &slot_aad(container_id, slot_id, slot_type),
            },
        )
        .ok()?;
    if plain.len() != 32 {
        return None;
    }
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plain);
    Some(dek)
}

fn unlock_passphrase(header: &Value, passphrase: &str) -> [u8; 32] {
    let container_id = header
        .get("container_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("invalid container id"));
    let slots = header
        .get("slots")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("invalid unlock slots"));
    for slot in slots {
        if slot.get("type").and_then(Value::as_str) != Some("passphrase") {
            continue;
        }
        let salt = Base64UrlUnpadded::decode_vec(
            slot.get("salt").and_then(Value::as_str).unwrap_or("")
        )
        .unwrap_or_default();
        if salt.len() != 16 {
            continue;
        }
        let kek = derive_passphrase_kek(passphrase, &salt);
        if let Some(dek) = unwrap_dek(slot, &kek, container_id) {
            return dek;
        }
    }
    fail("passphrase unlock failed");
}

fn unlock_recovery(header: &Value, recovery_code: &str) -> [u8; 32] {
    let secret = decode_recovery_code(recovery_code);
    let container_id = header
        .get("container_id")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("invalid container id"));
    let slots = header
        .get("slots")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("invalid unlock slots"));
    for slot in slots {
        if slot.get("type").and_then(Value::as_str) != Some("recovery-secret") {
            continue;
        }
        let salt = Base64UrlUnpadded::decode_vec(
            slot.get("salt").and_then(Value::as_str).unwrap_or("")
        )
        .unwrap_or_default();
        if salt.len() != 16 {
            continue;
        }
        let kek = derive_recovery_kek(&secret, &salt);
        if let Some(dek) = unwrap_dek(slot, &kek, container_id) {
            return dek;
        }
    }
    fail("recovery unlock failed");
}

fn validate_payload(payload: &Value) {
    if !exact_keys(payload, &["payload_version", "files"])
        || payload.get("payload_version").and_then(Value::as_u64) != Some(1) {
        fail("unsupported payload");
    }
    let files = payload
        .get("files")
        .and_then(Value::as_object)
        .unwrap_or_else(|| fail("unsupported payload"));
    if files.len() > MAX_FILES {
        fail("too many files");
    }
    let mut total = 0usize;
    for (rel, encoded) in files {
        if !allowed_path(rel) {
            fail("invalid payload path");
        }
        let encoded = encoded.as_str().unwrap_or_else(|| fail("invalid payload encoding"));
        if encoded.len() > (MAX_FILE * 4 + 2) / 3 {
            fail("file too large");
        }
        let data = decode_b64(encoded, "invalid payload encoding");
        if data.len() > MAX_FILE {
            fail("file too large");
        }
        total += data.len();
        if total > MAX_TOTAL {
            fail("payload too large");
        }
    }
}

/// Required dependency: Python 3 and the matching installed/local alethech package.
/// The native verifier currently covers only part of the protocol. Never substitute
/// it for full store history verification, including current private-key binding.
fn verify_full_payload(payload: &Value) {
    validate_payload(payload);
    const BRIDGE: &str = r#"
import json, sys, tempfile
from pathlib import Path
from alethech.container_v2 import _materialize_payload
from alethech.container import _verify_portable_signing_key
with tempfile.TemporaryDirectory(prefix='alethech-rust-verify-') as temporary:
    store = _materialize_payload(json.load(sys.stdin), Path(temporary) / 'store')
    # Read-only archives may omit the operational key; supplied keys must bind.
    if (store.root / 'keys' / 'signing.key').exists():
        _verify_portable_signing_key(store)
"#;
    // Fixed program and arguments; payload only travels through stdin, no shell.
    let mut child = Command::new("python3")
        .args(["-c", BRIDGE])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap_or_else(|_| fail("full verification requires Python 3 and the alethech package"));
    let write_ok = serde_json::to_writer(child.stdin.take().unwrap(), payload).is_ok();
    let status = child.wait().unwrap_or_else(|_| fail("full payload verification failed"));
    if !write_ok || !status.success() {
        fail("full payload verification failed (Python 3 and matching alethech package required)");
    }
}

fn read_bounded(path: &Path, limit: usize) -> Vec<u8> {
    let file = fs::File::open(path).unwrap_or_else(|_| fail("failed to read input"));
    let mut data = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut data)
        .unwrap_or_else(|_| fail("failed to read input"));
    if data.len() > limit { fail("input too large"); }
    data
}

fn atomic_write(path: &Path, blob: &[u8]) {
    use rand::RngCore;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut random = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut random);
    let temporary = parent.join(format!(".alethech-{}.tmp", hex::encode(random)));
    let mut created = false;
    let result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        created = true;
        file.write_all(blob)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        // The rename commits the result. Directory sync is best-effort: a
        // post-commit error must not suppress generated recovery credentials.
        #[cfg(unix)] {
            let _ = fs::File::open(parent).and_then(|directory| directory.sync_all());
        }
        Ok(())
    })();
    if result.is_err() {
        if created { let _ = fs::remove_file(&temporary); }
        fail("failed to atomically write output");
    }
}

fn decrypt_v2(path: &Path, mode: &str, credential: &str) -> (Value, Value) {

    let blob = read_bounded(path, MAX_CONTAINER);
    if blob.len() > MAX_CONTAINER {
        fail("container too large");
    }
    if blob.len() < 12 || &blob[..8] != MAGIC {
        fail("invalid ALETH002 magic");
    }
    let hlen = u32::from_be_bytes(
        blob[8..12]
            .try_into()
            .unwrap_or_else(|_| fail("invalid header length"))
    ) as usize;
    if hlen == 0 || hlen > MAX_HEADER || 12 + hlen >= blob.len() {
        fail("invalid header length");
    }

    let header_bytes = &blob[12..12 + hlen];
    let encrypted = &blob[12 + hlen..];
    if encrypted.len() < 16 {
        fail("truncated ciphertext");
    }

    let header: Value =
        serde_json::from_slice(header_bytes).unwrap_or_else(|_| fail("invalid v2 header"));
    validate_header(&header);
    if canonical_json(&header).as_bytes() != header_bytes {
        fail("v2 header is not canonical JCS");
    }

    let dek = match mode {
        "open-pass" => unlock_passphrase(&header, credential),
        "open-recovery" => unlock_recovery(&header, credential),
        _ => fail("unknown open mode"),
    };

    let payload_nonce = decode_b64(
        header
            .get("payload_nonce")
            .and_then(Value::as_str)
            .unwrap_or(""),
        "invalid payload nonce",
    );
    let cipher =
        Aes256Gcm::new_from_slice(&dek).unwrap_or_else(|_| fail("invalid AES key"));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&payload_nonce),
            Payload {
                msg: encrypted,
                aad: header_bytes,
            },
        )
        .unwrap_or_else(|_| fail("payload authentication failed"));

    let payload: Value =
        serde_json::from_slice(&plaintext).unwrap_or_else(|_| fail("invalid encrypted payload"));
    verify_full_payload(&payload);
    (payload, header)
}

fn open(path: &Path, mode: &str, credential: &str) {
    let (payload, header) = decrypt_v2(path, mode, credential);
    let mut slot_types: Vec<String> = header
        .get("slots")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|s| {
            s.get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .collect();
    slot_types.sort();

    let out = json!({
        "payload": payload,
        "container_id": header.get("container_id").and_then(Value::as_str).unwrap_or(""),
        "slot_types": slot_types,
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}

// ============================================================
// seal / recover / migrate — write-side ALETH002 operations
// ============================================================

fn encode_recovery_secret(secret: &[u8]) -> String {
    assert!(secret.len() == 32, "recovery secret must be 32 bytes");
    format!("{}{}", RECOVERY_PREFIX, Base64UrlUnpadded::encode_string(&secret))
}

fn wrap_dek(
    dek: &[u8; 32],
    kek: &[u8; 32],
    container_id: &str,
    slot_id: &str,
    slot_type: &str,
) -> (Vec<u8>, Vec<u8>) {
    // Returns (nonce, wrapped_key) where wrapped_key includes the GCM tag.
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(kek).unwrap();
    let aad = slot_aad(container_id, slot_id, slot_type);
    let wrapped = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: dek, aad: &aad },
        )
        .unwrap_or_else(|_| fail("internal: DEK wrap failed"));
    assert!(wrapped.len() == 48, "internal: wrapped DEK size mismatch");
    (nonce_bytes.to_vec(), wrapped)
}

fn build_passphrase_slot(
    dek: &[u8; 32],
    passphrase: &str,
    container_id: &str,
) -> Value {
    if passphrase.is_empty() {
        fail("passphrase must be non-empty");
    }
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_passphrase_kek(passphrase, &salt);
    let slot_id = "passphrase-1";
    let (nonce, wrapped) = wrap_dek(dek, &kek, container_id, slot_id, "passphrase");
    json!({
        "id": slot_id,
        "kdf": "scrypt",
        "nonce": Base64UrlUnpadded::encode_string(&nonce),
        "salt": Base64UrlUnpadded::encode_string(&salt),
        "scrypt_n": 32768,
        "scrypt_p": 1,
        "scrypt_r": 8,
        "type": "passphrase",
        "wrapped_key": Base64UrlUnpadded::encode_string(&wrapped),
    })
}

fn build_recovery_slot(
    dek: &[u8; 32],
    secret: &[u8],
    container_id: &str,
) -> Value {
    if secret.len() != 32 {
        fail("recovery secret must be 32 bytes");
    }
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let kek = derive_recovery_kek(secret, &salt);
    let slot_id = "recovery-1";
    let (nonce, wrapped) = wrap_dek(dek, &kek, container_id, slot_id, "recovery-secret");
    json!({
        "id": slot_id,
        "kdf": "HKDF-SHA256",
        "nonce": Base64UrlUnpadded::encode_string(&nonce),
        "salt": Base64UrlUnpadded::encode_string(&salt),
        "type": "recovery-secret",
        "wrapped_key": Base64UrlUnpadded::encode_string(&wrapped),
    })
}

/// Seal a payload (already a serde_json::Value with payload_version=1 and files)
/// as ALETH002 and write to `output`.
///
/// If `recovery_secret` is Some, a recovery slot is added and the recovery code
/// is returned. Otherwise None.
///
/// If `container_id` is Some(16 bytes), it is used; otherwise a fresh random
/// one is generated.
fn seal_payload_v2(
    payload: &Value,
    passphrase: &str,
    recovery_secret: Option<&[u8]>,
    container_id: Option<&[u8]>,
) -> (Vec<u8>, Option<String>, String) {
    // Returns (blob, recovery_code, container_id_str)
    verify_full_payload(payload);
    use rand::RngCore;

    let cid = match container_id {
        Some(c) if c.len() == 16 => c.to_vec(),
        _ => {
            let mut buf = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        }
    };
    let container_id_str = Base64UrlUnpadded::encode_string(&cid);

    let mut dek = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut dek);

    let mut slots: Vec<Value> = vec![build_passphrase_slot(&dek, passphrase, &container_id_str)];
    let mut recovery_code: Option<String> = None;
    if let Some(secret) = recovery_secret {
        slots.push(build_recovery_slot(&dek, secret, &container_id_str));
        recovery_code = Some(encode_recovery_secret(secret));
    }

    let mut payload_nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut payload_nonce);

    let header = json!({
        "container_id": container_id_str,
        "format": "aleth",
        "payload_cipher": "AES-256-GCM",
        "payload_nonce": Base64UrlUnpadded::encode_string(&payload_nonce),
        "slots": slots,
        "version": 2,
    });
    let header_canonical = canonical_json(&header);
    let header_bytes = header_canonical.as_bytes();
    if header_bytes.len() > MAX_HEADER {
        fail("header too large");
    }
    let plain = canonical_json(payload);
    let plain_bytes = plain.as_bytes();
    if plain_bytes.len() > MAX_TOTAL {
        fail("payload too large");
    }

    let cipher = Aes256Gcm::new_from_slice(&dek).unwrap();
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&payload_nonce),
            Payload { msg: plain_bytes, aad: header_bytes },
        )
        .unwrap_or_else(|_| fail("payload encryption failed"));

    let mut blob = Vec::with_capacity(12 + header_bytes.len() + encrypted.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(header_bytes);
    blob.extend_from_slice(&encrypted);
    if blob.len() > MAX_CONTAINER {
        fail("container too large");
    }
    (blob, recovery_code, container_id_str)
}

/// Read a payload from a JSON file. The payload must be:
///   { "payload_version": 1, "files": { "rel/path": "base64url-bytes", ... } }
fn read_payload(path: &Path) -> Value {
    let content = read_bounded(path, MAX_TOTAL);
    let payload: Value = serde_json::from_slice(&content).unwrap_or_else(|_| fail("invalid payload JSON"));
    validate_payload(&payload);
    payload
}

fn cmd_seal(payload_path: &Path, out_path: &Path, passphrase: &str, recovery_arg: Option<&str>) {
    let payload = read_payload(payload_path);
    let recovery_secret: Option<Vec<u8>> = match recovery_arg {
        Some(s) => Some(decode_b64(s, "invalid recovery secret").clone()),
        None => None,
    };
    let (blob, recovery_code, container_id) = seal_payload_v2(
        &payload,
        passphrase,
        recovery_secret.as_deref(),
        None,
    );
    atomic_write(out_path, &blob);
    let out = json!({
        "recoveryCode": recovery_code,
        "containerId": container_id,
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}

fn cmd_recover(
    in_path: &Path,
    out_path: &Path,
    recovery_code: &str,
    new_passphrase: &str,
    rotate_recovery: bool,
) {
    let (payload, header) = decrypt_v2(in_path, "open-recovery", recovery_code);
    let slots = header["slots"].as_array().unwrap();
    if slots.len() != 2
        || slots.iter().filter(|slot| slot["type"] == "passphrase").count() != 1
        || slots.iter().filter(|slot| slot["type"] == "recovery-secret").count() != 1
    {
        fail("recovery supports exactly one passphrase and one recovery slot");
    }
    let container_id_str = header["container_id"].as_str().unwrap().to_owned();
    let container_id_bytes = decode_b64(&container_id_str, "invalid container_id");

    // Decide next recovery secret
    use rand::RngCore;
    let next_secret: Vec<u8> = if rotate_recovery {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        buf.to_vec()
    } else {
        decode_recovery_code(recovery_code)
    };

    let (new_blob, new_recovery_code, _) = seal_payload_v2(
        &payload,
        new_passphrase,
        Some(&next_secret),
        Some(&container_id_bytes),
    );
    atomic_write(out_path, &new_blob);
    let out = json!({
        "recoveryCode": new_recovery_code,
        "containerId": container_id_str,
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}

/// Canonical paths catch symlinks; device/inode identity catches Unix hard links.
fn guard_migration_source(in_path: &Path, out_path: &Path) {
    let source = fs::canonicalize(in_path).unwrap_or_else(|_| fail("failed to resolve migration source"));
    if !out_path.exists() { return; }
    let target = fs::canonicalize(out_path).unwrap_or_else(|_| fail("failed to resolve migration output"));
    let mut same = source == target;
    #[cfg(unix)] {
        use std::os::unix::fs::MetadataExt;
        let source_meta = fs::metadata(in_path).unwrap_or_else(|_| fail("failed to inspect migration source"));
        let target_meta = fs::metadata(out_path).unwrap_or_else(|_| fail("failed to inspect migration output"));
        same |= source_meta.dev() == target_meta.dev() && source_meta.ino() == target_meta.ino();
    }
    #[cfg(not(unix))] {
        // Python samefile provides platform file identity on non-Unix systems.
        let status = Command::new("python3").args(["-c",
            "import os,sys; sys.exit(2 if os.path.samefile(sys.argv[1],sys.argv[2]) else 0)"])
            .arg(in_path).arg(out_path).stdin(Stdio::null())
            .stdout(Stdio::null()).stderr(Stdio::null()).status()
            .unwrap_or_else(|_| fail("migration source identity check requires Python 3"));
        if status.code() == Some(2) { same = true; }
        else if !status.success() { fail("failed to check migration source identity"); }
    }
    if same { fail("migration requires --replace-source to replace its v1 source"); }
}

fn cmd_migrate(
    in_path: &Path,
    out_path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    create_recovery: bool,
    replace_source: bool,
) {
    if !replace_source { guard_migration_source(in_path, out_path); }
    let blob = read_bounded(in_path, MAX_CONTAINER);
    let magic_v1: &[u8; 8] = b"ALETH001";
    if blob.len() < 12 || &blob[..8] != magic_v1 {
        fail("input is not an ALETH001 container");
    }
    let hlen = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    if hlen == 0 || hlen > MAX_HEADER || 12 + hlen >= blob.len() {
        fail("invalid v1 header length");
    }
    let header_bytes = &blob[12..12 + hlen];
    let encrypted = &blob[12 + hlen..];
    let header: Value = serde_json::from_slice(header_bytes).unwrap_or_else(|_| fail("invalid v1 header"));

    // Validate v1 header
    let expected_keys = ["cipher", "format", "kdf", "nonce", "salt", "scrypt_n", "scrypt_p", "scrypt_r", "version"];
    if !exact_keys(&header, &expected_keys) {
        fail("invalid v1 header schema");
    }
    if canonical_json(&header).as_bytes() != header_bytes {
        fail("v1 header is not canonical JCS");
    }
    if encrypted.len() < 16 { fail("truncated ciphertext"); }
    if old_passphrase.is_empty() { fail("passphrase must be non-empty"); }
    if header.get("cipher").and_then(Value::as_str) != Some("AES-256-GCM")
        || header.get("format").and_then(Value::as_str) != Some("aleth")
        || header.get("kdf").and_then(Value::as_str) != Some("scrypt")
        || header.get("version").and_then(Value::as_i64) != Some(1)
        || header.get("scrypt_n").and_then(Value::as_i64) != Some(32768)
        || header.get("scrypt_p").and_then(Value::as_i64) != Some(1)
        || header.get("scrypt_r").and_then(Value::as_i64) != Some(8)
    {
        fail("unsupported v1 container parameters");
    }
    let salt = decode_b64(header.get("salt").and_then(Value::as_str).unwrap_or(""), "invalid salt");
    let nonce = decode_b64(header.get("nonce").and_then(Value::as_str).unwrap_or(""), "invalid nonce");
    if salt.len() != 16 || nonce.len() != 12 {
        fail("invalid v1 salt or nonce size");
    }

    // Derive passphrase KEK using scrypt(log_n=15, r=8, p=1) — matches the v2 reader.
    // Note: Params::new takes log_n (the logarithm base 2 of N), not N itself.
    // scrypt N=32768 = 2^15, so log_n=15.
    let mut key = [0u8; 32];
    let params = Params::new(15, 8, 1, 32).unwrap_or_else(|_| fail("invalid scrypt params"));
    scrypt(old_passphrase.as_bytes(), &salt, &params, &mut key)
        .unwrap_or_else(|_| fail("scrypt failed"));
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: encrypted, aad: header_bytes },
        )
        .unwrap_or_else(|_| fail("v1 authentication failed"));
    let payload: Value = serde_json::from_slice(&plaintext).unwrap_or_else(|_| fail("invalid v1 payload"));
    validate_payload(&payload);

    // Generate recovery secret if requested
    use rand::RngCore;
    let recovery_secret: Option<Vec<u8>> = if create_recovery {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Some(buf.to_vec())
    } else {
        None
    };

    let (new_blob, recovery_code, container_id) = seal_payload_v2(
        &payload,
        new_passphrase,
        recovery_secret.as_deref(),
        None,
    );
    atomic_write(out_path, &new_blob);

    let out = json!({
        "recoveryCode": recovery_code,
        "containerId": container_id,
    });
    println!("{}", serde_json::to_string(&out).unwrap());
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        fail("usage: alethech-container-v2 <open-pass|open-recovery|seal|recover|migrate> ...args");
    }
    let mode = &args[1];

    match mode.as_str() {
        "open-pass" | "open-recovery" => {
            if args.len() != 4 {
                fail(&format!(
                    "usage: alethech-container-v2 {} <file.aleth> <credential>",
                    mode
                ));
            }
            open(Path::new(&args[2]), mode, &args[3]);
        }
        "seal" => {
            // seal <payload.json> <out.aleth> <passphrase> [recovery-secret-base64url]
            if !(5..=6).contains(&args.len()) {
                fail("usage: alethech-container-v2 seal <payload.json> <out.aleth> <passphrase> [recovery-secret-base64url]");
            }
            let recovery_arg = if args.len() >= 6 { Some(args[5].as_str()) } else { None };
            cmd_seal(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                recovery_arg,
            );
        }
        "recover" => {
            // recover <in.aleth> <out.aleth> <recovery-code> <new-passphrase> [--rotate-recovery]
            if !(6..=7).contains(&args.len()) || (args.len() == 7 && args[6] != "--rotate-recovery") {
                fail("usage: alethech-container-v2 recover <in.aleth> <out.aleth> <recovery-code> <new-passphrase> [--rotate-recovery]");
            }
            let rotate_recovery = args.len() == 7;
            cmd_recover(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                &args[5],
                rotate_recovery,
            );
        }
        "migrate" => {
            // migrate <in-v1.aleth> <out-v2.aleth> <old-pass> <new-pass> [--no-recovery] [--replace-source]
            let mut create_recovery = true;
            let mut replace_source = false;
            if !(6..=8).contains(&args.len()) {
                fail("usage: alethech-container-v2 migrate <in-v1.aleth> <out-v2.aleth> <old-pass> <new-pass> [--no-recovery] [--replace-source]");
            }
            for flag in &args[6..] {
                match flag.as_str() {
                    "--no-recovery" if create_recovery => create_recovery = false,
                    "--replace-source" if !replace_source => replace_source = true,
                    _ => fail("unknown or duplicate migration flag"),
                }
            }
            cmd_migrate(
                Path::new(&args[2]),
                Path::new(&args[3]),
                &args[4],
                &args[5],
                create_recovery,
                replace_source,
            );
        }
        _ => {
            fail("usage: alethech-container-v2 <open-pass|open-recovery|seal|recover|migrate> ...args");
        }
    }
}
