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
use std::{env, fs, path::Path, process};

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
    Base64UrlUnpadded::decode_vec(s).unwrap_or_else(|_| fail(what))
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
    if payload.get("payload_version").and_then(Value::as_u64) != Some(1) {
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
        let data = Base64UrlUnpadded::decode_vec(
            encoded.as_str().unwrap_or_else(|| fail("invalid payload encoding"))
        )
        .unwrap_or_else(|_| fail("invalid payload encoding"));
        if data.len() > MAX_FILE {
            fail("file too large");
        }
        total += data.len();
        if total > MAX_TOTAL {
            fail("payload too large");
        }
    }
}

fn open(path: &Path, mode: &str, credential: &str) {
    let blob = fs::read(path).unwrap_or_else(|_| fail("failed to read container"));
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
    validate_payload(&payload);

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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        fail("usage: alethech-container-v2 <open-pass|open-recovery> <file.aleth> <credential>");
    }
    let mode = &args[1];
    if mode != "open-pass" && mode != "open-recovery" {
        fail("usage: alethech-container-v2 <open-pass|open-recovery> <file.aleth> <credential>");
    }
    open(Path::new(&args[2]), mode, &args[3]);
}
