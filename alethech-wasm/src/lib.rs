//! Browser-local authenticated decryptor for .aleth v1 and v2.
//!
//! v1: passphrase-only envelope (ALETH001).
//! v2: DEK + 2-slot envelope (ALETH002) with optional recovery slot.
//!
//! This module does NOT claim protocol verification. It only validates the
//! envelope/KDF parameters and returns plaintext after successful AEAD auth.
//! JavaScript must run the Alethech protocol verifier before exposing memory.

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use scrypt::{scrypt, Params};
use serde_json::{json, Value};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

const MAGIC_V1: &[u8; 8] = b"ALETH001";
const MAGIC_V2: &[u8; 8] = b"ALETH002";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;
const MAX_TOTAL: usize = 512 * 1024 * 1024;
const RECOVERY_PREFIX: &str = "aleth-recovery-v1:";
const RECOVERY_INFO: &[u8] = b"alethech-container-recovery-v1";

fn err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], JsValue> {
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }
    let params = Params::new(15, 8, 1, 32).map_err(|_| err("invalid scrypt params"))?;
    let mut key = [0u8; 32];
    scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .map_err(|_| err("scrypt failed"))?;
    Ok(key)
}

/// Authenticate and decrypt one .aleth v1 container.
///
/// Success means only that the encrypted envelope authenticated. The returned
/// bytes MUST still be parsed and protocol-verified before memory is exposed.
///
/// Note: callers should prefer `open_aleth_payload` (below), which auto-detects
/// v1 vs v2 from the magic bytes. This function is kept for explicit v1 use.
#[wasm_bindgen]
pub fn open_aleth_v1(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    if blob.len() > MAX_CONTAINER {
        return Err(err("container too large"));
    }
    if blob.len() < 12 || &blob[..8] != MAGIC_V1 {
        return Err(err("invalid .aleth magic"));
    }

    let hlen = u32::from_be_bytes(
        blob[8..12].try_into().map_err(|_| err("invalid header length"))?
    ) as usize;
    if hlen == 0 || hlen > MAX_HEADER || 12 + hlen >= blob.len() {
        return Err(err("invalid header length"));
    }

    let header_bytes = &blob[12..12 + hlen];
    let encrypted = &blob[12 + hlen..];
    if encrypted.len() < 16 {
        return Err(err("truncated ciphertext"));
    }

    let header: Value =
        serde_json::from_slice(header_bytes).map_err(|_| err("invalid header"))?;
    let expected = [
        ("cipher", json!("AES-256-GCM")),
        ("format", json!("aleth")),
        ("kdf", json!("scrypt")),
        ("scrypt_n", json!(32768)),
        ("scrypt_p", json!(1)),
        ("scrypt_r", json!(8)),
        ("version", json!(1)),
    ];
    for (key, value) in expected {
        if header.get(key) != Some(&value) {
            return Err(err("unsupported container parameters"));
        }
    }

    // serde_json's default map is ordered. Re-serializing therefore enforces
    // the same compact, sorted-key representation used by the v1 flat header.
    let canonical = serde_json::to_vec(&header).map_err(|_| err("invalid header"))?;
    if canonical.as_slice() != header_bytes {
        return Err(err("header is not canonical JCS"));
    }

    let salt_s = header.get("salt").and_then(Value::as_str).ok_or_else(|| err("invalid salt"))?;
    let nonce_s = header.get("nonce").and_then(Value::as_str).ok_or_else(|| err("invalid nonce"))?;
    let salt = Base64UrlUnpadded::decode_vec(salt_s).map_err(|_| err("invalid salt"))?;
    let nonce = Base64UrlUnpadded::decode_vec(nonce_s).map_err(|_| err("invalid nonce"))?;
    if salt.len() != 16 || nonce.len() != 12 {
        return Err(err("invalid salt or nonce size"));
    }

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| err("invalid AES key"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: encrypted,
                aad: header_bytes,
            },
        )
        .map_err(|_| err("authentication failed"))
}


/// Seal an already protocol-verified plaintext payload as .aleth v1.
///
/// The caller MUST verify the plaintext payload before calling this function.
/// This function provides confidentiality + authenticated transport only.
#[wasm_bindgen]
pub fn seal_aleth_payload(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    if plaintext.len() > MAX_CONTAINER {
        return Err(err("payload too large"));
    }
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }

    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut salt).map_err(|_| err("random generation failed"))?;
    getrandom::getrandom(&mut nonce).map_err(|_| err("random generation failed"))?;

    // All keys are ASCII and serde_json's default map ordering is sorted,
    // which matches JCS ordering for this fixed v1 header.
    let header = json!({
        "cipher": "AES-256-GCM",
        "format": "aleth",
        "kdf": "scrypt",
        "nonce": Base64UrlUnpadded::encode_string(&nonce),
        "salt": Base64UrlUnpadded::encode_string(&salt),
        "scrypt_n": 32768,
        "scrypt_p": 1,
        "scrypt_r": 8,
        "version": 1
    });
    let header_bytes = serde_json::to_vec(&header).map_err(|_| err("header serialization failed"))?;
    if header_bytes.len() > MAX_HEADER {
        return Err(err("header too large"));
    }

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| err("invalid AES key"))?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| err("encryption failed"))?;

    let total_len = 12usize
        .checked_add(header_bytes.len())
        .and_then(|n| n.checked_add(encrypted.len()))
        .ok_or_else(|| err("container too large"))?;
    if total_len > MAX_CONTAINER {
        return Err(err("container too large"));
    }

    let mut blob = Vec::with_capacity(total_len);
    blob.extend_from_slice(MAGIC_V1);
    blob.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(&encrypted);
    Ok(blob)
}


// ============================================================
// ALETH002 — DEK + 2-slot envelope (passphrase + optional recovery)
// ============================================================

fn canonical_json(value: &Value) -> String {
    // Reuse serde_json's default ordering, which is sorted for object keys.
    // For our fixed-shape headers/payloads this matches JCS RFC 8785.
    serde_json::to_string(value).unwrap_or_default()
}

fn derive_recovery_kek(secret: &[u8], salt: &[u8]) -> Result<[u8; 32], JsValue> {
    if secret.len() != 32 {
        return Err(err("recovery secret must be 32 bytes"));
    }
    let base = hkdf::Hkdf::<Sha256>::new(Some(salt), secret);
    let mut out = [0u8; 32];
    base.expand(RECOVERY_INFO, &mut out)
        .map_err(|_| err("HKDF expand failed"))?;
    Ok(out)
}

fn slot_aad(container_id: &str, slot_id: &str, slot_type: &str) -> Vec<u8> {
    let aad = json!({
        "container_id": container_id,
        "envelope_version": 2,
        "slot_id": slot_id,
        "slot_type": slot_type,
    });
    canonical_json(&aad).into_bytes()
}

fn validate_v2_header(header: &Value) -> Result<(), JsValue> {
    let expected_keys = [
        "container_id", "format", "payload_cipher", "payload_nonce",
        "slots", "version",
    ];
    let obj = header.as_object().ok_or_else(|| err("invalid v2 header"))?;
    if obj.len() != expected_keys.len() {
        return Err(err("invalid v2 header schema"));
    }
    for k in &expected_keys {
        if !obj.contains_key(*k) {
            return Err(err("invalid v2 header schema"));
        }
    }
    if header.get("format") != Some(&json!("aleth"))
        || header.get("payload_cipher") != Some(&json!("AES-256-GCM"))
        || header.get("version") != Some(&json!(2))
    {
        return Err(err("unsupported v2 container parameters"));
    }
    let cid = header.get("container_id").and_then(Value::as_str).ok_or_else(|| err("invalid container_id"))?;
    if Base64UrlUnpadded::decode_vec(cid).map_err(|_| err("invalid container_id"))?.len() != 16 {
        return Err(err("invalid container_id size"));
    }
    let pn = header.get("payload_nonce").and_then(Value::as_str).ok_or_else(|| err("invalid payload_nonce"))?;
    if Base64UrlUnpadded::decode_vec(pn).map_err(|_| err("invalid payload_nonce"))?.len() != 12 {
        return Err(err("invalid payload_nonce size"));
    }
    let slots = header.get("slots").and_then(Value::as_array).ok_or_else(|| err("invalid slots"))?;
    if slots.is_empty() || slots.len() > 16 {
        return Err(err("invalid unlock slots"));
    }
    for slot in slots {
        let s = slot.as_object().ok_or_else(|| err("invalid slot"))?;
        let stype = slot.get("type").and_then(Value::as_str).unwrap_or("");
        if stype == "passphrase" {
            let expected = ["id","kdf","nonce","salt","scrypt_n","scrypt_p","scrypt_r","type","wrapped_key"];
            if s.len() != expected.len() || !expected.iter().all(|k| s.contains_key(*k)) {
                return Err(err("invalid passphrase slot schema"));
            }
            if slot.get("kdf") != Some(&json!("scrypt"))
                || slot.get("scrypt_n") != Some(&json!(32768))
                || slot.get("scrypt_r") != Some(&json!(8))
                || slot.get("scrypt_p") != Some(&json!(1))
            {
                return Err(err("unsupported passphrase slot parameters"));
            }
        } else if stype == "recovery-secret" {
            let expected = ["id","kdf","nonce","salt","type","wrapped_key"];
            if s.len() != expected.len() || !expected.iter().all(|k| s.contains_key(*k)) {
                return Err(err("invalid recovery slot schema"));
            }
            if slot.get("kdf") != Some(&json!("HKDF-SHA256")) {
                return Err(err("unsupported recovery slot parameters"));
            }
        } else {
            return Err(err("unsupported unlock slot type"));
        }
        // Check nonce/salt/wrapped_key sizes
        let nonce = Base64UrlUnpadded::decode_vec(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid slot nonce"))?;
        let salt = Base64UrlUnpadded::decode_vec(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid slot salt"))?;
        let wrapped = Base64UrlUnpadded::decode_vec(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
        if nonce.len() != 12 || salt.len() != 16 || wrapped.len() != 48 {
            return Err(err("invalid unlock slot sizes"));
        }
    }
    Ok(())
}

fn unlock_dek_with_passphrase_v2(header: &Value, passphrase: &str) -> Result<[u8; 32], JsValue> {
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }
    let container_id = header.get("container_id").and_then(Value::as_str).unwrap_or("");
    let slots = header.get("slots").and_then(Value::as_array).ok_or_else(|| err("invalid slots"))?;
    let mut last_err = err("passphrase unlock failed");
    for slot in slots {
        if slot.get("type").and_then(Value::as_str) != Some("passphrase") {
            continue;
        }
        let salt = Base64UrlUnpadded::decode_vec(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid salt"))?;
        let kek = derive_key(passphrase, &salt)?;
        let slot_id = slot.get("id").and_then(Value::as_str).unwrap_or("");
        let aad = slot_aad(container_id, slot_id, "passphrase");
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| err("invalid AES key"))?;
        let nonce_bytes = Base64UrlUnpadded::decode_vec(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid nonce"))?;
        let wrapped = Base64UrlUnpadded::decode_vec(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
        match cipher.decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &wrapped, aad: &aad }) {
            Ok(dek) if dek.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&dek);
                return Ok(out);
            }
            Ok(_) => { last_err = err("invalid unwrapped data key size"); }
            Err(_) => { last_err = err("unlock credential invalid"); }
        }
    }
    Err(last_err)
}

fn unlock_dek_with_recovery_v2(header: &Value, recovery_code: &str) -> Result<[u8; 32], JsValue> {
    if !recovery_code.starts_with(RECOVERY_PREFIX) {
        return Err(err("invalid recovery code"));
    }
    let secret_b64 = &recovery_code[RECOVERY_PREFIX.len()..];
    let secret = Base64UrlUnpadded::decode_vec(secret_b64).map_err(|_| err("invalid recovery code"))?;
    if secret.len() != 32 {
        return Err(err("invalid recovery code"));
    }
    let container_id = header.get("container_id").and_then(Value::as_str).unwrap_or("");
    let slots = header.get("slots").and_then(Value::as_array).ok_or_else(|| err("invalid slots"))?;
    let mut last_err = err("recovery unlock failed");
    for slot in slots {
        if slot.get("type").and_then(Value::as_str) != Some("recovery-secret") {
            continue;
        }
        let salt = Base64UrlUnpadded::decode_vec(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid salt"))?;
        let kek = derive_recovery_kek(&secret, &salt)?;
        let slot_id = slot.get("id").and_then(Value::as_str).unwrap_or("");
        let aad = slot_aad(container_id, slot_id, "recovery-secret");
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| err("invalid AES key"))?;
        let nonce_bytes = Base64UrlUnpadded::decode_vec(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid nonce"))?;
        let wrapped = Base64UrlUnpadded::decode_vec(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
        match cipher.decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &wrapped, aad: &aad }) {
            Ok(dek) if dek.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&dek);
                return Ok(out);
            }
            Ok(_) => { last_err = err("invalid unwrapped data key size"); }
            Err(_) => { last_err = err("recovery unlock failed"); }
        }
    }
    Err(last_err)
}

fn parse_v2_header(blob: &[u8]) -> Result<(Value, Vec<u8>, Vec<u8>), JsValue> {
    if blob.len() > MAX_CONTAINER {
        return Err(err("container too large"));
    }
    if blob.len() < 12 || &blob[..8] != MAGIC_V2 {
        return Err(err("invalid ALETH002 magic"));
    }
    let hlen = u32::from_be_bytes(blob[8..12].try_into().map_err(|_| err("invalid header length"))?) as usize;
    if hlen == 0 || hlen > MAX_HEADER || 12 + hlen >= blob.len() {
        return Err(err("invalid header length"));
    }
    let header_bytes = blob[12..12 + hlen].to_vec();
    let encrypted = blob[12 + hlen..].to_vec();
    if encrypted.len() < 16 {
        return Err(err("truncated ciphertext"));
    }
    let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| err("invalid v2 header"))?;
    validate_v2_header(&header)?;
    if canonical_json(&header).as_bytes() != header_bytes.as_slice() {
        return Err(err("v2 header is not canonical JCS"));
    }
    Ok((header, header_bytes, encrypted))
}

fn decrypt_v2_payload(header: &Value, header_bytes: &[u8], encrypted: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, JsValue> {
    let payload_nonce = Base64UrlUnpadded::decode_vec(header.get("payload_nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid payload nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| err("invalid AES key"))?;
    cipher.decrypt(Nonce::from_slice(&payload_nonce), Payload { msg: encrypted, aad: header_bytes })
        .map_err(|_| err("payload authentication failed"))
}

/// Authenticate and decrypt one .aleth v2 container using the passphrase.
///
/// Returns the plaintext payload bytes. JavaScript must still parse and
/// protocol-verify before exposing memory.
#[wasm_bindgen]
pub fn open_aleth_v2_passphrase(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    let dek = unlock_dek_with_passphrase_v2(&header, passphrase)?;
    decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)
}

/// Authenticate and decrypt one .aleth v2 container using the recovery code.
#[wasm_bindgen]
pub fn open_aleth_v2_recovery(blob: &[u8], recovery_code: &str) -> Result<Vec<u8>, JsValue> {
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    let dek = unlock_dek_with_recovery_v2(&header, recovery_code)?;
    decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)
}

/// Detect the container format by its magic bytes and dispatch to the
/// correct opener. Returns the plaintext payload bytes.
///
/// If the container is v2 and has both a passphrase slot and a recovery
/// slot, this function tries the passphrase first (which is what users
/// normally want). For recovery-code unlock of a v2 container, call
/// open_aleth_v2_recovery directly.
#[wasm_bindgen]
pub fn open_aleth_payload(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    if blob.len() < 8 {
        return Err(err("container too small"));
    }
    if &blob[..8] == MAGIC_V1 {
        open_aleth_v1(blob, passphrase)
    } else if &blob[..8] == MAGIC_V2 {
        open_aleth_v2_passphrase(blob, passphrase)
    } else {
        Err(err("invalid .aleth magic"))
    }
}

// ----- v2 seal / recover -----

fn random_bytes(len: usize) -> Result<Vec<u8>, JsValue> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|_| err("random generation failed"))?;
    Ok(buf)
}

fn wrap_dek_v2(dek: &[u8; 32], kek: &[u8; 32], container_id: &str, slot_id: &str, slot_type: &str) -> Result<(Vec<u8>, Vec<u8>), JsValue> {
    let nonce = random_bytes(12)?;
    let aad = slot_aad(container_id, slot_id, slot_type);
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| err("invalid AES key"))?;
    let wrapped = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: dek, aad: &aad })
        .map_err(|_| err("DEK wrap failed"))?;
    if wrapped.len() != 48 {
        return Err(err("internal: wrapped DEK size mismatch"));
    }
    Ok((nonce, wrapped))
}

fn build_passphrase_slot_v2(dek: &[u8; 32], passphrase: &str, container_id: &str) -> Result<Value, JsValue> {
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }
    let salt = random_bytes(16)?;
    let kek = derive_key(passphrase, &salt)?;
    let slot_id = "passphrase-1";
    let (nonce, wrapped) = wrap_dek_v2(dek, &kek, container_id, slot_id, "passphrase")?;
    Ok(json!({
        "id": slot_id,
        "kdf": "scrypt",
        "nonce": Base64UrlUnpadded::encode_string(&nonce),
        "salt": Base64UrlUnpadded::encode_string(&salt),
        "scrypt_n": 32768,
        "scrypt_p": 1,
        "scrypt_r": 8,
        "type": "passphrase",
        "wrapped_key": Base64UrlUnpadded::encode_string(&wrapped),
    }))
}

fn build_recovery_slot_v2(dek: &[u8; 32], secret: &[u8], container_id: &str) -> Result<Value, JsValue> {
    if secret.len() != 32 {
        return Err(err("recovery secret must be 32 bytes"));
    }
    let salt = random_bytes(16)?;
    let kek = derive_recovery_kek(secret, &salt)?;
    let slot_id = "recovery-1";
    let (nonce, wrapped) = wrap_dek_v2(dek, &kek, container_id, slot_id, "recovery-secret")?;
    Ok(json!({
        "id": slot_id,
        "kdf": "HKDF-SHA256",
        "nonce": Base64UrlUnpadded::encode_string(&nonce),
        "salt": Base64UrlUnpadded::encode_string(&salt),
        "type": "recovery-secret",
        "wrapped_key": Base64UrlUnpadded::encode_string(&wrapped),
    }))
}

fn encode_recovery_secret(secret: &[u8]) -> String {
    format!("{}{}", RECOVERY_PREFIX, Base64UrlUnpadded::encode_string(secret))
}

/// Seal an already protocol-verified plaintext payload as .aleth v2.
///
/// If `recovery_secret_b64` is a non-empty string, it must be the base64url
/// encoding of a 32-byte recovery secret. A recovery slot is added and the
/// recovery code string is returned via the `recovery_code` field of the
/// returned JSON.
///
/// Returns a JSON string: {"blob": "<base64url>", "recovery_code": "<string or null>", "container_id": "<string>"}
#[wasm_bindgen]
pub fn seal_aleth_v2(plaintext: &[u8], passphrase: &str, recovery_secret_b64: &str) -> Result<String, JsValue> {
    if plaintext.len() > MAX_TOTAL {
        return Err(err("payload too large"));
    }
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }

    let container_id = random_bytes(16)?;
    let container_id_str = Base64UrlUnpadded::encode_string(&container_id);

    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek).map_err(|_| err("random generation failed"))?;

    let mut slots: Vec<Value> = vec![build_passphrase_slot_v2(&dek, passphrase, &container_id_str)?];
    let mut recovery_code: Option<String> = None;
    if !recovery_secret_b64.is_empty() {
        let secret = Base64UrlUnpadded::decode_vec(recovery_secret_b64).map_err(|_| err("invalid recovery secret"))?;
        if secret.len() != 32 {
            return Err(err("recovery secret must be 32 bytes"));
        }
        slots.push(build_recovery_slot_v2(&dek, &secret, &container_id_str)?);
        recovery_code = Some(encode_recovery_secret(&secret));
    }

    let payload_nonce = random_bytes(12)?;
    let header = json!({
        "container_id": container_id_str,
        "format": "aleth",
        "payload_cipher": "AES-256-GCM",
        "payload_nonce": Base64UrlUnpadded::encode_string(&payload_nonce),
        "slots": slots,
        "version": 2,
    });
    let header_bytes = canonical_json(&header).into_bytes();
    if header_bytes.len() > MAX_HEADER {
        return Err(err("header too large"));
    }

    let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|_| err("invalid AES key"))?;
    let encrypted = cipher.encrypt(Nonce::from_slice(&payload_nonce), Payload { msg: plaintext, aad: &header_bytes })
        .map_err(|_| err("encryption failed"))?;

    let mut blob = Vec::with_capacity(12 + header_bytes.len() + encrypted.len());
    blob.extend_from_slice(MAGIC_V2);
    blob.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(&encrypted);
    if blob.len() > MAX_CONTAINER {
        return Err(err("container too large"));
    }

    let result = json!({
        "blob": Base64UrlUnpadded::encode_string(&blob),
        "recovery_code": recovery_code,
        "container_id": container_id_str,
    });
    Ok(result.to_string())
}

/// Generate a fresh 32-byte recovery secret, return as base64url string.
/// Used by the UI when the user wants to create a new recovery code.
#[wasm_bindgen]
pub fn generate_recovery_secret() -> String {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    Base64UrlUnpadded::encode_string(&buf)
}

/// Recover a v2 container: decrypt with recovery_code, re-seal with new_passphrase.
///
/// If `rotate_recovery` is true, a fresh recovery secret is generated and the
/// returned recovery_code is the new one. Otherwise the same recovery_code is
/// returned.
///
/// Returns a JSON string: {"blob": "<base64url>", "recovery_code": "<string>", "container_id": "<string>"}
#[wasm_bindgen]
pub fn recover_aleth_v2(blob: &[u8], recovery_code: &str, new_passphrase: &str, rotate_recovery: bool) -> Result<String, JsValue> {
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    let dek = unlock_dek_with_recovery_v2(&header, recovery_code)?;
    let plaintext = decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)?;
    let container_id_str = header.get("container_id").and_then(Value::as_str).unwrap_or("").to_string();
    let container_id = Base64UrlUnpadded::decode_vec(&container_id_str).map_err(|_| err("invalid container_id"))?;

    let next_secret_b64 = if rotate_recovery {
        generate_recovery_secret()
    } else {
        // Extract secret from recovery_code
        if !recovery_code.starts_with(RECOVERY_PREFIX) {
            return Err(err("invalid recovery code"));
        }
        let secret = Base64UrlUnpadded::decode_vec(&recovery_code[RECOVERY_PREFIX.len()..]).map_err(|_| err("invalid recovery code"))?;
        Base64UrlUnpadded::encode_string(&secret)
    };

    // Re-seal: we need to call seal_aleth_v2 but with a specific container_id.
    // Since seal_aleth_v2 generates a fresh container_id, we need a variant
    // that accepts one. For simplicity, we inline the seal logic here with
    // the preserved container_id.
    let secret_bytes = Base64UrlUnpadded::decode_vec(&next_secret_b64).map_err(|_| err("invalid recovery secret"))?;
    let mut new_dek = [0u8; 32];
    getrandom::getrandom(&mut new_dek).map_err(|_| err("random generation failed"))?;

    let mut slots: Vec<Value> = vec![build_passphrase_slot_v2(&new_dek, new_passphrase, &container_id_str)?];
    slots.push(build_recovery_slot_v2(&new_dek, &secret_bytes, &container_id_str)?);
    let new_recovery_code = encode_recovery_secret(&secret_bytes);

    let payload_nonce = random_bytes(12)?;
    let new_header = json!({
        "container_id": container_id_str,
        "format": "aleth",
        "payload_cipher": "AES-256-GCM",
        "payload_nonce": Base64UrlUnpadded::encode_string(&payload_nonce),
        "slots": slots,
        "version": 2,
    });
    let new_header_bytes = canonical_json(&new_header).into_bytes();
    let cipher = Aes256Gcm::new_from_slice(&new_dek).map_err(|_| err("invalid AES key"))?;
    let new_encrypted = cipher.encrypt(Nonce::from_slice(&payload_nonce), Payload { msg: &plaintext, aad: &new_header_bytes })
        .map_err(|_| err("encryption failed"))?;

    let mut new_blob = Vec::with_capacity(12 + new_header_bytes.len() + new_encrypted.len());
    new_blob.extend_from_slice(MAGIC_V2);
    new_blob.extend_from_slice(&(new_header_bytes.len() as u32).to_be_bytes());
    new_blob.extend_from_slice(&new_header_bytes);
    new_blob.extend_from_slice(&new_encrypted);

    let result = json!({
        "blob": Base64UrlUnpadded::encode_string(&new_blob),
        "recovery_code": new_recovery_code,
        "container_id": container_id_str,
    });
    Ok(result.to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let sealed = seal_aleth_payload(plaintext, "test-passphrase")
            .expect("seal must succeed");
        assert!(sealed.starts_with(MAGIC_V1));
        assert_ne!(sealed.windows(plaintext.len()).any(|w| w == plaintext), true);
        let opened = open_aleth_payload(&sealed, "test-passphrase")
            .expect("open must succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn v2_seal_open_passphrase_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret();
        let result_json = seal_aleth_v2(plaintext, "test-pass", &secret_b64).expect("seal must succeed");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        assert!(blob.starts_with(MAGIC_V2));
        let opened = open_aleth_v2_passphrase(&blob, "test-pass").expect("open must succeed");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_seal_open_recovery_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret();
        let result_json = seal_aleth_v2(plaintext, "test-pass", &secret_b64).expect("seal must succeed");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        let recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap();
        let opened = open_aleth_v2_recovery(&blob, recovery_code).expect("recovery open must succeed");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_recover_preserves_payload_and_container_id() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret();
        let result_json = seal_aleth_v2(plaintext, "orig-pass", &secret_b64).expect("seal");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap().to_string();
        let blob = Base64UrlUnpadded::decode_vec(&blob_b64).unwrap();
        let orig_container_id = result.get("container_id").and_then(Value::as_str).unwrap().to_string();
        let orig_recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap().to_string();

        let recovered_json = recover_aleth_v2(&blob, &orig_recovery_code, "new-pass", false).expect("recover");
        let recovered: Value = serde_json::from_str(&recovered_json).unwrap();
        let new_blob_b64 = recovered.get("blob").and_then(Value::as_str).unwrap();
        let new_blob = Base64UrlUnpadded::decode_vec(new_blob_b64).unwrap();
        let new_container_id = recovered.get("container_id").and_then(Value::as_str).unwrap();
        let new_recovery_code = recovered.get("recovery_code").and_then(Value::as_str).unwrap();

        assert_eq!(new_container_id, &orig_container_id);
        assert_eq!(new_recovery_code, &orig_recovery_code);
        let opened = open_aleth_v2_passphrase(&new_blob, "new-pass").expect("open recovered");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_recover_with_rotate_changes_recovery_code() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret();
        let result_json = seal_aleth_v2(plaintext, "orig-pass", &secret_b64).expect("seal");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        let orig_recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap();

        let recovered_json = recover_aleth_v2(&blob, orig_recovery_code, "new-pass", true).expect("recover");
        let recovered: Value = serde_json::from_str(&recovered_json).unwrap();
        let new_recovery_code = recovered.get("recovery_code").and_then(Value::as_str).unwrap();
        assert_ne!(new_recovery_code, orig_recovery_code);
    }

    #[test]
    fn open_aleth_payload_dispatches_v1_and_v2() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let v1_blob = seal_aleth_payload(plaintext, "pass").unwrap();
        let opened_v1 = open_aleth_payload(&v1_blob, "pass").expect("v1 open");
        assert_eq!(opened_v1, plaintext.to_vec());

        let secret_b64 = generate_recovery_secret();
        let v2_json = seal_aleth_v2(plaintext, "pass", &secret_b64).unwrap();
        let v2_result: Value = serde_json::from_str(&v2_json).unwrap();
        let v2_blob = Base64UrlUnpadded::decode_vec(v2_result.get("blob").and_then(Value::as_str).unwrap()).unwrap();
        let opened_v2 = open_aleth_payload(&v2_blob, "pass").expect("v2 open via dispatch");
        assert_eq!(opened_v2, plaintext.to_vec());
    }
}
