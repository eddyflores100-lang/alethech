//! Browser-local authenticated decryptor for .aleth v1.
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
use wasm_bindgen::prelude::*;

const MAGIC: &[u8; 8] = b"ALETH001";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;

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
#[wasm_bindgen]
pub fn open_aleth_payload(blob: &[u8], passphrase: &str) -> Result<Vec<u8>, JsValue> {
    if blob.len() > MAX_CONTAINER {
        return Err(err("container too large"));
    }
    if blob.len() < 12 || &blob[..8] != MAGIC {
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
