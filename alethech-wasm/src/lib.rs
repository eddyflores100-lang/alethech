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

use scrypt::{scrypt, Params};
use serde_json::{json, Value};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

const MAGIC_V1: &[u8; 8] = b"ALETH001";
const MAGIC_V2: &[u8; 8] = b"ALETH002";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;
const MAX_TOTAL: usize = MAX_CONTAINER - MAX_HEADER - 28;
const RECOVERY_PREFIX: &str = "aleth-recovery-v1:";
const RECOVERY_INFO: &[u8] = b"alethech-container-recovery-v1";

fn err(msg: &str) -> String {
    msg.to_owned()
}


fn decode_b64(encoded: &str) -> Result<Vec<u8>, String> {
    // Every envelope field is at most a wrapped 32-byte key (48 bytes).
    if encoded.len() > 64 { return Err(err("invalid base64url size")); }
    let decoded = Base64UrlUnpadded::decode_vec(encoded).map_err(|_| err("invalid base64url"))?;
    if Base64UrlUnpadded::encode_string(&decoded) != encoded {
        return Err(err("noncanonical base64url"));
    }
    Ok(decoded)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
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
fn open_aleth_v1_inner(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
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
    if header.as_object().map(|obj| obj.len()) != Some(9) {
        return Err(err("invalid v1 header schema"));
    }
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
    let salt = decode_b64(salt_s).map_err(|_| err("invalid salt"))?;
    let nonce = decode_b64(nonce_s).map_err(|_| err("invalid nonce"))?;
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
fn seal_aleth_payload_inner(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_TOTAL {
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

fn derive_recovery_kek(secret: &[u8], salt: &[u8]) -> Result<[u8; 32], String> {
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

fn validate_v2_header(header: &Value) -> Result<(), String> {
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
    if decode_b64(cid).map_err(|_| err("invalid container_id"))?.len() != 16 {
        return Err(err("invalid container_id size"));
    }
    let pn = header.get("payload_nonce").and_then(Value::as_str).ok_or_else(|| err("invalid payload_nonce"))?;
    if decode_b64(pn).map_err(|_| err("invalid payload_nonce"))?.len() != 12 {
        return Err(err("invalid payload_nonce size"));
    }
    let slots = header.get("slots").and_then(Value::as_array).ok_or_else(|| err("invalid slots"))?;
    if slots.is_empty() || slots.len() > 16 {
        return Err(err("invalid unlock slots"));
    }
    let mut seen = std::collections::HashSet::new();
    for slot in slots {
        let id = slot.get("id").and_then(Value::as_str).filter(|id| !id.is_empty())
            .ok_or_else(|| err("invalid slot id"))?;
        if !seen.insert(id) { return Err(err("duplicate unlock slot id")); }
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
        let nonce = decode_b64(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid slot nonce"))?;
        let salt = decode_b64(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid slot salt"))?;
        let wrapped = decode_b64(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
        if nonce.len() != 12 || salt.len() != 16 || wrapped.len() != 48 {
            return Err(err("invalid unlock slot sizes"));
        }
    }
    Ok(())
}

fn unlock_dek_with_passphrase_v2(header: &Value, passphrase: &str) -> Result<[u8; 32], String> {
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
        let salt = decode_b64(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid salt"))?;
        let kek = derive_key(passphrase, &salt)?;
        let slot_id = slot.get("id").and_then(Value::as_str).unwrap_or("");
        let aad = slot_aad(container_id, slot_id, "passphrase");
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| err("invalid AES key"))?;
        let nonce_bytes = decode_b64(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid nonce"))?;
        let wrapped = decode_b64(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
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

fn unlock_dek_with_recovery_v2(header: &Value, recovery_code: &str) -> Result<[u8; 32], String> {
    if !recovery_code.starts_with(RECOVERY_PREFIX) {
        return Err(err("invalid recovery code"));
    }
    let secret_b64 = &recovery_code[RECOVERY_PREFIX.len()..];
    let secret = decode_b64(secret_b64).map_err(|_| err("invalid recovery code"))?;
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
        let salt = decode_b64(slot.get("salt").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid salt"))?;
        let kek = derive_recovery_kek(&secret, &salt)?;
        let slot_id = slot.get("id").and_then(Value::as_str).unwrap_or("");
        let aad = slot_aad(container_id, slot_id, "recovery-secret");
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| err("invalid AES key"))?;
        let nonce_bytes = decode_b64(slot.get("nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid nonce"))?;
        let wrapped = decode_b64(slot.get("wrapped_key").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid wrapped key"))?;
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

fn parse_v2_header(blob: &[u8]) -> Result<(Value, Vec<u8>, Vec<u8>), String> {
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

fn decrypt_v2_payload(header: &Value, header_bytes: &[u8], encrypted: &[u8], dek: &[u8; 32]) -> Result<Vec<u8>, String> {
    let payload_nonce = decode_b64(header.get("payload_nonce").and_then(Value::as_str).unwrap_or("")).map_err(|_| err("invalid payload nonce"))?;
    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| err("invalid AES key"))?;
    cipher.decrypt(Nonce::from_slice(&payload_nonce), Payload { msg: encrypted, aad: header_bytes })
        .map_err(|_| err("payload authentication failed"))
}

/// Authenticate and decrypt one .aleth v2 container using the passphrase.
///
/// Returns the plaintext payload bytes. JavaScript must still parse and
/// protocol-verify before exposing memory.
fn open_aleth_v2_passphrase_inner(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    let dek = unlock_dek_with_passphrase_v2(&header, passphrase)?;
    decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)
}

/// Authenticate and decrypt one .aleth v2 container using the recovery code.
fn open_aleth_v2_recovery_inner(blob: &[u8], recovery_code: &str) -> Result<Vec<u8>, String> {
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
fn open_aleth_payload_inner(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if blob.len() < 8 {
        return Err(err("container too small"));
    }
    if &blob[..8] == MAGIC_V1 {
        open_aleth_v1_inner(blob, passphrase)
    } else if &blob[..8] == MAGIC_V2 {
        open_aleth_v2_passphrase_inner(blob, passphrase)
    } else {
        Err(err("invalid .aleth magic"))
    }
}

// ----- v2 seal / recover -----

fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; len];
    getrandom::getrandom(&mut buf).map_err(|_| err("random generation failed"))?;
    Ok(buf)
}

fn wrap_dek_v2(dek: &[u8; 32], kek: &[u8; 32], container_id: &str, slot_id: &str, slot_type: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
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

fn build_passphrase_slot_v2(dek: &[u8; 32], passphrase: &str, container_id: &str) -> Result<Value, String> {
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

fn build_recovery_slot_v2(dek: &[u8; 32], secret: &[u8], container_id: &str) -> Result<Value, String> {
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
fn seal_aleth_v2_inner(plaintext: &[u8], passphrase: &str, recovery_secret_b64: &str) -> Result<String, String> {
    if plaintext.len() > MAX_TOTAL {
        return Err(err("payload too large"));
    }
    if passphrase.is_empty() {
        return Err(err("passphrase must be non-empty"));
    }

    let container_id_str = Base64UrlUnpadded::encode_string(&random_bytes(16)?);
    reseal_aleth_v2_inner(plaintext, passphrase, recovery_secret_b64, &container_id_str)
}

fn reseal_aleth_v2_inner(plaintext: &[u8], passphrase: &str, recovery_secret_b64: &str, container_id_str: &str) -> Result<String, String> {
    if plaintext.len() > MAX_TOTAL { return Err(err("payload too large")); }
    if decode_b64(container_id_str)?.len() != 16 { return Err(err("invalid container_id size")); }

    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek).map_err(|_| err("random generation failed"))?;

    let mut slots: Vec<Value> = vec![build_passphrase_slot_v2(&dek, passphrase, &container_id_str)?];
    let mut recovery_code: Option<String> = None;
    if !recovery_secret_b64.is_empty() {
        let secret = decode_b64(recovery_secret_b64).map_err(|_| err("invalid recovery secret"))?;
        if secret.len() != 32 {
            return Err(err("recovery secret must be 32 bytes"));
        }
        slots.push(build_recovery_slot_v2(&dek, &secret, &container_id_str)?);
        recovery_code = Some(encode_recovery_secret(&secret));
    }

    encode_v2(plaintext, &dek, container_id_str, slots, recovery_code)
}

fn encode_v2(plaintext: &[u8], dek: &[u8; 32], container_id_str: &str, slots: Vec<Value>, recovery_code: Option<String>) -> Result<String, String> {
    if plaintext.len() > MAX_CONTAINER.saturating_sub(MAX_HEADER + 28) {
        return Err(err("payload too large"));
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
    validate_v2_header(&header)?;
    let header_bytes = canonical_json(&header).into_bytes();
    if header_bytes.len() > MAX_HEADER {
        return Err(err("header too large"));
    }

    let cipher = Aes256Gcm::new_from_slice(dek).map_err(|_| err("invalid AES key"))?;
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
pub fn generate_recovery_secret() -> Result<String, JsValue> {
    generate_recovery_secret_inner().map_err(|message| JsValue::from_str(&message))
}

fn generate_recovery_secret_inner() -> Result<String, String> {
    Ok(Base64UrlUnpadded::encode_string(&random_bytes(32)?))
}

/// Authenticate and rewrap a v2 envelope with a new passphrase.
/// This does not verify the plaintext history; callers must fully verify before output.
///
/// If `rotate_recovery` is true, a fresh recovery secret is generated and the
/// returned recovery_code is the new one. Otherwise the same recovery_code is
/// returned.
///
/// Returns a JSON string: {"blob": "<base64url>", "recovery_code": "<string>", "container_id": "<string>"}
fn recover_aleth_v2_inner(blob: &[u8], recovery_code: &str, new_passphrase: &str, rotate_recovery: bool) -> Result<String, String> {
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    let slots = header["slots"].as_array().ok_or_else(|| err("invalid slots"))?;
    if slots.len() != 2
        || slots.iter().filter(|slot| slot["type"].as_str() == Some("passphrase")).count() != 1
        || slots.iter().filter(|slot| slot["type"].as_str() == Some("recovery-secret")).count() != 1
    {
        return Err(err("unsupported recovery slot topology"));
    }

    let dek = unlock_dek_with_recovery_v2(&header, recovery_code)?;
    let plaintext = decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)?;
    let container_id_str = header.get("container_id").and_then(Value::as_str).unwrap_or("").to_string();
    let next_secret_b64 = if rotate_recovery {
        Base64UrlUnpadded::encode_string(&random_bytes(32)?)
    } else {
        recovery_code.strip_prefix(RECOVERY_PREFIX).ok_or_else(|| err("invalid recovery code"))?.to_owned()
    };
    reseal_aleth_v2_inner(&plaintext, new_passphrase, &next_secret_b64, &container_id_str)
}




/// Authenticate the original envelope before replacing caller-verified plaintext.
/// Preserve v2 identity and recovery wraps by default. A nonempty recovery secret
/// explicitly replaces recovery slots. Empty new_passphrase retains the current one.
fn rewrite_aleth_payload_inner(blob: &[u8], current_passphrase: &str, plaintext: &[u8], new_passphrase: &str, recovery_secret_b64: &str) -> Result<String, String> {
    let next_passphrase = if new_passphrase.is_empty() { current_passphrase } else { new_passphrase };
    if blob.starts_with(MAGIC_V1) {
        open_aleth_v1_inner(blob, current_passphrase)?;
        if !recovery_secret_b64.is_empty() {
            return seal_aleth_v2_inner(plaintext, next_passphrase, recovery_secret_b64);
        }
        let sealed = seal_aleth_payload_inner(plaintext, next_passphrase)?;
        return Ok(json!({"blob": Base64UrlUnpadded::encode_string(&sealed), "container_id": null, "recovery_code": null}).to_string());
    }
    let (header, header_bytes, encrypted) = parse_v2_header(blob)?;
    if header["slots"].as_array().ok_or_else(|| err("invalid slots"))?.iter()
        .filter(|slot| slot["type"].as_str() == Some("passphrase")).count() != 1
    {
        return Err(err("unsupported passphrase rewrite slot topology"));
    }

    let dek = unlock_dek_with_passphrase_v2(&header, current_passphrase)?;
    decrypt_v2_payload(&header, &header_bytes, &encrypted, &dek)?;
    let cid = header["container_id"].as_str().ok_or_else(|| err("invalid container_id"))?;
    if !recovery_secret_b64.is_empty() {
        // Rotation gets a fresh DEK and therefore invalidates every old recovery wrap.
        return reseal_aleth_v2_inner(plaintext, next_passphrase, recovery_secret_b64, cid);
    }
    let mut slots = vec![build_passphrase_slot_v2(&dek, next_passphrase, cid)?];
    for slot in header["slots"].as_array().ok_or_else(|| err("invalid slots"))? {
        if slot["type"].as_str() == Some("recovery-secret") { slots.push(slot.clone()); }
    }
    // Preserve arbitrary valid recovery slot ids without colliding with our pass slot.
    let mut id = "passphrase-1".to_owned();
    while slots.iter().skip(1).any(|slot| slot["id"].as_str() == Some(id.as_str())) { id.push('1'); }
    if slots[0]["id"].as_str() != Some(id.as_str()) {
        // A wrap's AAD binds its id; rebuild instead of renaming an authenticated wrap.
        let salt = random_bytes(16)?;
        let kek = derive_key(next_passphrase, &salt)?;
        let (nonce, wrapped) = wrap_dek_v2(&dek, &kek, cid, &id, "passphrase")?;
        slots[0]["id"] = json!(id);
        slots[0]["salt"] = json!(Base64UrlUnpadded::encode_string(&salt));
        slots[0]["nonce"] = json!(Base64UrlUnpadded::encode_string(&nonce));
        slots[0]["wrapped_key"] = json!(Base64UrlUnpadded::encode_string(&wrapped));
    }
    encode_v2(plaintext, &dek, cid, slots, None)
}

// Keep JS-facing errors at this boundary so native validation tests can exercise failures.
#[wasm_bindgen]
pub fn open_aleth_v1(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    open_aleth_v1_inner(blob, passphrase).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn seal_aleth_payload(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    seal_aleth_payload_inner(plaintext, passphrase).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn open_aleth_v2_passphrase(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    open_aleth_v2_passphrase_inner(blob, passphrase).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn open_aleth_v2_recovery(blob: &[u8], recovery_code: &str) -> Result<Vec<u8>, JsValue> {
    open_aleth_v2_recovery_inner(blob, recovery_code).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn open_aleth_payload(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    open_aleth_payload_inner(blob, passphrase).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn seal_aleth_v2(plaintext: &[u8], passphrase: &str, recovery_secret_b64: &str) -> Result<String, JsValue> {
    seal_aleth_v2_inner(plaintext, passphrase, recovery_secret_b64).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn reseal_aleth_v2(plaintext: &[u8], passphrase: &str, recovery_secret_b64: &str, container_id_b64: &str) -> Result<String, JsValue> {
    reseal_aleth_v2_inner(plaintext, passphrase, recovery_secret_b64, container_id_b64).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn recover_aleth_v2(blob: &[u8], recovery_code: &str, new_passphrase: &str, rotate_recovery: bool) -> Result<String, JsValue> {
    recover_aleth_v2_inner(blob, recovery_code, new_passphrase, rotate_recovery).map_err(|message| JsValue::from_str(&message))
}

#[wasm_bindgen]
pub fn rewrite_aleth_payload(blob: &[u8], current_passphrase: &str, plaintext: &[u8], new_passphrase: &str, recovery_secret_b64: &str) -> Result<String, JsValue> {
    rewrite_aleth_payload_inner(blob, current_passphrase, plaintext, new_passphrase, recovery_secret_b64).map_err(|message| JsValue::from_str(&message))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let sealed = seal_aleth_payload_inner(plaintext, "test-passphrase")
            .expect("seal must succeed");
        assert!(sealed.starts_with(MAGIC_V1));
        assert_ne!(sealed.windows(plaintext.len()).any(|w| w == plaintext), true);
        let opened = open_aleth_payload_inner(&sealed, "test-passphrase")
            .expect("open must succeed");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn v2_seal_open_passphrase_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret_inner().unwrap();
        let result_json = seal_aleth_v2_inner(plaintext, "test-pass", &secret_b64).expect("seal must succeed");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        assert!(blob.starts_with(MAGIC_V2));
        let opened = open_aleth_v2_passphrase_inner(&blob, "test-pass").expect("open must succeed");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_seal_open_recovery_roundtrip() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret_inner().unwrap();
        let result_json = seal_aleth_v2_inner(plaintext, "test-pass", &secret_b64).expect("seal must succeed");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        let recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap();
        let opened = open_aleth_v2_recovery_inner(&blob, recovery_code).expect("recovery open must succeed");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_recover_preserves_payload_and_container_id() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret_inner().unwrap();
        let result_json = seal_aleth_v2_inner(plaintext, "orig-pass", &secret_b64).expect("seal");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap().to_string();
        let blob = Base64UrlUnpadded::decode_vec(&blob_b64).unwrap();
        let orig_container_id = result.get("container_id").and_then(Value::as_str).unwrap().to_string();
        let orig_recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap().to_string();

        let recovered_json = recover_aleth_v2_inner(&blob, &orig_recovery_code, "new-pass", false).expect("recover");
        let recovered: Value = serde_json::from_str(&recovered_json).unwrap();
        let new_blob_b64 = recovered.get("blob").and_then(Value::as_str).unwrap();
        let new_blob = Base64UrlUnpadded::decode_vec(new_blob_b64).unwrap();
        let new_container_id = recovered.get("container_id").and_then(Value::as_str).unwrap();
        let new_recovery_code = recovered.get("recovery_code").and_then(Value::as_str).unwrap();

        assert_eq!(new_container_id, &orig_container_id);
        assert_eq!(new_recovery_code, &orig_recovery_code);
        let opened = open_aleth_v2_passphrase_inner(&new_blob, "new-pass").expect("open recovered");
        assert_eq!(opened, plaintext.to_vec());
    }

    #[test]
    fn v2_recover_with_rotate_changes_recovery_code() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let secret_b64 = generate_recovery_secret_inner().unwrap();
        let result_json = seal_aleth_v2_inner(plaintext, "orig-pass", &secret_b64).expect("seal");
        let result: Value = serde_json::from_str(&result_json).unwrap();
        let blob_b64 = result.get("blob").and_then(Value::as_str).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(blob_b64).unwrap();
        let orig_recovery_code = result.get("recovery_code").and_then(Value::as_str).unwrap();

        let recovered_json = recover_aleth_v2_inner(&blob, orig_recovery_code, "new-pass", true).expect("recover");
        let recovered: Value = serde_json::from_str(&recovered_json).unwrap();
        let new_recovery_code = recovered.get("recovery_code").and_then(Value::as_str).unwrap();
        assert_ne!(new_recovery_code, orig_recovery_code);
    }

    #[test]
    fn open_aleth_payload_dispatches_v1_and_v2() {
        let plaintext = br#"{"files":{"HEAD":"dGVzdAo"},"payload_version":1}"#;
        let v1_blob = seal_aleth_payload_inner(plaintext, "pass").unwrap();
        let opened_v1 = open_aleth_payload_inner(&v1_blob, "pass").expect("v1 open");
        assert_eq!(opened_v1, plaintext.to_vec());

        let result: Value = serde_json::from_str(&seal_aleth_v2_inner(plaintext, "pass", "").unwrap()).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(result["blob"].as_str().unwrap()).unwrap();
        assert_eq!(open_aleth_payload_inner(&blob, "pass").unwrap(), plaintext);
    }
    fn decode_result(result: &str) -> (Value, Vec<u8>) {
        let parsed: Value = serde_json::from_str(result).unwrap();
        let blob = Base64UrlUnpadded::decode_vec(parsed["blob"].as_str().unwrap()).unwrap();
        (parsed, blob)
    }

    fn replace_header(blob: &[u8], header: &Value) -> Vec<u8> {
        let old_len = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
        let bytes = canonical_json(header).into_bytes();
        let mut out = MAGIC_V2.to_vec();
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&bytes);
        out.extend_from_slice(&blob[12 + old_len..]);
        out
    }

    #[test]
    fn native_negative_validation_does_not_construct_jsvalue() {
        assert!(open_aleth_payload_inner(b"", "pass").is_err());
        assert!(derive_key("", &[0; 16]).is_err());
        assert!(decode_b64("AA=").is_err());
        assert!(decode_b64("AB").is_err()); // unused trailing bits
        assert!(decode_b64(&"A".repeat(65)).is_err());
        let (_, blob) = decode_result(&seal_aleth_v2_inner(b"payload", "pass", "").unwrap());
        let (header, _, _) = parse_v2_header(&blob).unwrap();
        let mut bad = header.clone();
        bad["slots"][0]["id"] = json!("");
        assert!(parse_v2_header(&replace_header(&blob, &bad)).is_err());
        let mut bad = header.clone();
        let duplicate = bad["slots"][0].clone();
        bad["slots"].as_array_mut().unwrap().push(duplicate);
        assert!(parse_v2_header(&replace_header(&blob, &bad)).is_err());
        let mut bad = header.clone();
        bad["slots"][0]["scrypt_n"] = json!(1048576);
        assert!(parse_v2_header(&replace_header(&blob, &bad)).is_err());
        let mut bad = header.clone();
        bad["extra"] = json!(true);
        assert!(parse_v2_header(&replace_header(&blob, &bad)).is_err());
        let mut bad = blob.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_v2_header(&bad).is_err());
        let mut noncanonical = blob.clone();
        let len = u32::from_be_bytes(blob[8..12].try_into().unwrap());
        noncanonical.insert(12, b' ');
        noncanonical[8..12].copy_from_slice(&(len + 1).to_be_bytes());
        assert!(parse_v2_header(&noncanonical).is_err());
        assert!(open_aleth_v2_passphrase_inner(&blob, "wrong").is_err());
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_aleth_v2_passphrase_inner(&tampered, "pass").is_err());
        assert!(rewrite_aleth_payload_inner(&tampered, "pass", b"edit", "", "").is_err());
    }

    #[test]
    fn rewrite_preserves_recovery_and_identity_then_rotates_explicitly() {
        let secret = Base64UrlUnpadded::encode_string(&[7; 32]);
        let (original, blob) = decode_result(&seal_aleth_v2_inner(b"old", "old-pass", &secret).unwrap());
        let code = original["recovery_code"].as_str().unwrap();
        let (updated, edited) = decode_result(&rewrite_aleth_payload_inner(&blob, "old-pass", b"new", "new-pass", "").unwrap());
        assert_eq!(original["container_id"], updated["container_id"]);
        assert!(edited.starts_with(MAGIC_V2));
        assert_eq!(open_aleth_v2_recovery_inner(&edited, code).unwrap(), b"new");
        assert_eq!(open_aleth_v2_passphrase_inner(&edited, "new-pass").unwrap(), b"new");
        assert!(open_aleth_v2_passphrase_inner(&edited, "old-pass").is_err());
        let old_header = parse_v2_header(&blob).unwrap().0;
        let new_header = parse_v2_header(&edited).unwrap().0;
        assert_eq!(old_header["slots"][1], new_header["slots"][1]);
        assert_ne!(old_header["payload_nonce"], new_header["payload_nonce"]);
        let fresh = Base64UrlUnpadded::encode_string(&[9; 32]);
        let (rotated, rotated_blob) = decode_result(&rewrite_aleth_payload_inner(&edited, "new-pass", b"next", "", &fresh).unwrap());
        assert_eq!(rotated["container_id"], original["container_id"]);
        assert!(open_aleth_v2_recovery_inner(&rotated_blob, code).is_err());
        assert_eq!(open_aleth_v2_recovery_inner(&rotated_blob, rotated["recovery_code"].as_str().unwrap()).unwrap(), b"next");
    }

    #[test]
    fn recovery_rotation_revokes_old_credential() {
        let secret = Base64UrlUnpadded::encode_string(&[42; 32]);
        let (original, blob) = decode_result(&seal_aleth_v2_inner(b"payload", "pass", &secret).unwrap());
        let old_code = original["recovery_code"].as_str().unwrap();
        let mut changed_header = parse_v2_header(&blob).unwrap().0;
        changed_header["container_id"] = json!(Base64UrlUnpadded::encode_string(&[1; 16]));
        assert!(open_aleth_v2_recovery_inner(&replace_header(&blob, &changed_header), old_code).is_err());
        let mut changed_header = parse_v2_header(&blob).unwrap().0;
        changed_header["payload_nonce"] = json!(Base64UrlUnpadded::encode_string(&[1; 12]));
        assert!(open_aleth_v2_recovery_inner(&replace_header(&blob, &changed_header), old_code).is_err());
        let (rotated, next) = decode_result(&recover_aleth_v2_inner(&blob, old_code, "new", true).unwrap());
        assert_eq!(original["container_id"], rotated["container_id"]);
        assert!(open_aleth_v2_recovery_inner(&next, old_code).is_err());
        assert_eq!(open_aleth_v2_recovery_inner(&next, rotated["recovery_code"].as_str().unwrap()).unwrap(), b"payload");
        assert!(open_aleth_v2_passphrase_inner(&next, "pass").is_err());
    }

    #[test]
    fn recovery_rejects_authenticated_multiple_slots_without_dropping_credentials() {
        let dek = [3; 32];
        let cid = Base64UrlUnpadded::encode_string(&[4; 16]);
        let secret = [5; 32];
        let other_secret = [6; 32];
        let pass = build_passphrase_slot_v2(&dek, "pass", &cid).unwrap();
        let recovery = build_recovery_slot_v2(&dek, &secret, &cid).unwrap();
        let mut other_recovery = build_recovery_slot_v2(&dek, &other_secret, &cid).unwrap();
        let salt = decode_b64(other_recovery["salt"].as_str().unwrap()).unwrap();
        let kek = derive_recovery_kek(&other_secret, &salt).unwrap();
        let (nonce, wrapped) = wrap_dek_v2(&dek, &kek, &cid, "recovery-2", "recovery-secret").unwrap();
        other_recovery["id"] = json!("recovery-2");
        other_recovery["nonce"] = json!(Base64UrlUnpadded::encode_string(&nonce));
        other_recovery["wrapped_key"] = json!(Base64UrlUnpadded::encode_string(&wrapped));
        let (_, blob) = decode_result(&encode_v2(b"payload", &dek, &cid, vec![pass, recovery, other_recovery], None).unwrap());
        let code = encode_recovery_secret(&secret);
        // Both recovery slots and the full payload authenticate; mutation must still reject.
        assert_eq!(open_aleth_v2_recovery_inner(&blob, &code).unwrap(), b"payload");
        assert_eq!(open_aleth_v2_recovery_inner(&blob, &encode_recovery_secret(&other_secret)).unwrap(), b"payload");
        assert_eq!(recover_aleth_v2_inner(&blob, &code, "new", false).unwrap_err(), "unsupported recovery slot topology");
        assert_eq!(recover_aleth_v2_inner(&blob, &code, "new", true).unwrap_err(), "unsupported recovery slot topology");
    }

}
