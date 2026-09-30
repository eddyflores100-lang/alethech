//! Cryptographic primitives: Ed25519, SHA-256, base64url, base32.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};
use base64ct::{Base64UrlUnpadded, Encoding};
use hex;
use thiserror::Error;
use crate::canonical::canonical_json;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("invalid Ed25519 key: {0}")]
    InvalidKey(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// An Ed25519 key pair for signing and verification.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    /// Get the public key as 32 raw bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign a message with Ed25519.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// Verify an Ed25519 signature.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        let verifying_key = self.signing_key.verifying_key();
        let sig = Signature::from_bytes(signature);
        verifying_key.verify(message, &sig).is_ok()
    }

    /// Verify a signature against a raw public key.
    pub fn verify_with_public_key(
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        if let Ok(vk) = VerifyingKey::from_bytes(public_key) {
            let sig = Signature::from_bytes(signature);
            return vk.verify(message, &sig).is_ok();
        }
        false
    }
}

/// SHA-256 hash of data, returned as raw 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// SHA-256 hash as lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// SHA-256 hash with "sha256:" prefix (alethech format).
pub fn sha256_prefixed(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

/// Base64url encode (no padding).
pub fn b64url_encode(data: &[u8]) -> String {
    use base64ct::Encoding;
    let mut buf = vec![0u8; data.len() * 2];
    let encoded = Base64UrlUnpadded::encode(data, &mut buf).unwrap_or("");
    encoded.to_string()
}

/// Base64url decode (no padding).
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    Base64UrlUnpadded::decode_vec(s)
        .map_err(|e| CryptoError::Encoding(e.to_string()))
}

/// Base32 lowercase encoding (RFC 4648, no padding) for agent_id derivation.
pub fn b32lower_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_left = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u32;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1f) as usize;
            result.push(ALPHABET[index]);
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        result.push(ALPHABET[index]);
    }

    String::from_utf8(result).unwrap()
}

/// Derive agent_id from a public key.
/// agent_id = "did:alethech:" + base32(sha256(canonical_jwk(pk))[:16])
pub fn derive_agent_id(public_key: &[u8; 32]) -> String {
    let x = b64url_encode(public_key);
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    });
    let canonical = canonical_json(&jwk);
    let hash = sha256(canonical.as_bytes());
    let b32 = b32lower_encode(&hash[..16]);
    format!("did:alethech:{}", b32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generate_sign_verify() {
        let kp = KeyPair::generate();
        let msg = b"hello alethech";
        let sig = kp.sign(msg);
        assert!(kp.verify(msg, &sig));
    }

    #[test]
    fn test_keypair_tamper_detected() {
        let kp = KeyPair::generate();
        let msg = b"hello alethech";
        let mut sig = kp.sign(msg);
        sig[0] ^= 0x01; // tamper
        assert!(!kp.verify(msg, &sig));
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let result = sha256_hex(b"abc");
        assert_eq!(result, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = sha256_hex(b"");
        assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_b64url_roundtrip() {
        let data = b"hello world";
        let encoded = b64url_encode(data);
        let decoded = b64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_b32lower() {
        // RFC 4648 test vector: "foobar" → "mzxw6ytboi"
        let result = b32lower_encode(b"foobar");
        assert_eq!(result, "mzxw6ytboi");
    }

    #[test]
    fn test_derive_agent_id_deterministic() {
        let pk = [42u8; 32];
        let id1 = derive_agent_id(&pk);
        let id2 = derive_agent_id(&pk);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("did:alethech:"));
        assert_eq!(id1, "did:alethech:jcsjojphm7rtqmxq2hrrf7ooni");
    }

    #[test]
    fn test_verify_with_public_key() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let msg = b"test message";
        let sig = kp.sign(msg);
        assert!(KeyPair::verify_with_public_key(&pk, msg, &sig));
    }
}
