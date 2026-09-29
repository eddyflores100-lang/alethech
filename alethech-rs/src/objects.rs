//! Core objects: Identity, MemoryCommit.

use serde::{Deserialize, Serialize};
use crate::crypto::{sha256_hex, b64url_encode, derive_agent_id};
use crate::canonical::canonical_json;

/// Agent identity — public only, private key lives in keys/ dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    #[serde(rename = "type")]
    pub obj_type: String,
    pub version: u32,
    pub agent_id: String,
    pub public_key: PublicKeyJwk,
    pub key_id: String,
    pub created_at: String,
    #[serde(default)]
    pub recovery_root: String,
}

/// JWK representation of a public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl Identity {
    /// Create a new Identity from a 32-byte Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32], key_id: &str) -> Self {
        let x = b64url_encode(public_key);
        let jwk = PublicKeyJwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x,
        };
        let agent_id = derive_agent_id(public_key);

        Self {
            obj_type: "Identity".to_string(),
            version: 1,
            agent_id,
            public_key: jwk,
            key_id: key_id.to_string(),
            created_at: chrono_now(),
            recovery_root: String::new(),
        }
    }

    /// Verify that agent_id derives from the public key.
    pub fn verify_self(&self) -> bool {
        if self.public_key.kty != "OKP" || self.public_key.crv != "Ed25519" {
            return false;
        }
        // Decode x from base64url
        let pk_bytes = match crate::crypto::b64url_decode(&self.public_key.x) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        if pk_bytes.len() != 32 {
            return false;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let derived = derive_agent_id(&pk);
        derived == self.agent_id
    }
}

/// A signed memory commit linked to parents in the DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCommit {
    #[serde(rename = "type")]
    pub obj_type: String,
    pub version: u32,
    pub agent_id: String,
    pub key_id: String,
    pub parents: Vec<String>,
    pub timestamp: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default = "default_memory_type")]
    pub memory_type: String,
    pub content: serde_json::Value,
    #[serde(default)]
    pub provenance: serde_json::Value,
    pub commit_id: String,
    #[serde(default)]
    pub signature: String,
}

fn default_memory_type() -> String {
    "semantic".to_string()
}

impl MemoryCommit {
    /// Create a new unsigned commit.
    pub fn new(
        agent_id: &str,
        key_id: &str,
        parents: Vec<String>,
        content: serde_json::Value,
    ) -> Self {
        let mut commit = Self {
            obj_type: "MemoryCommit".to_string(),
            version: 1,
            agent_id: agent_id.to_string(),
            key_id: key_id.to_string(),
            parents,
            timestamp: chrono_now(),
            session_id: String::new(),
            memory_type: "semantic".to_string(),
            content,
            provenance: serde_json::json!({}),
            commit_id: String::new(),
            signature: String::new(),
        };
        commit.compute_commit_id();
        commit
    }

    /// Compute commit_id = sha256(canonical_json(self without commit_id and signature)).
    pub fn compute_commit_id(&mut self) {
        let signable = serde_json::json!({
            "type": self.obj_type,
            "version": self.version,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "parents": self.parents,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "provenance": self.provenance,
        });
        let canonical = canonical_json(&signable);
        self.commit_id = format!("sha256:{}", sha256_hex(canonical.as_bytes()));
    }

    /// Sign this commit with an Ed25519 keypair.
    pub fn sign(&mut self, keypair: &crate::crypto::KeyPair) {
        self.compute_commit_id();
        let signable = serde_json::json!({
            "type": self.obj_type,
            "version": self.version,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "parents": self.parents,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "provenance": self.provenance,
            "commit_id": self.commit_id,
        });
        let canonical = canonical_json(&signable);
        let sig = keypair.sign(canonical.as_bytes());
        self.signature = format!("ed25519:{}", b64url_encode(&sig));
    }

    /// Verify the signature of this commit.
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        if !self.signature.starts_with("ed25519:") {
            return false;
        }
        let sig_b64 = &self.signature[8..];
        let sig_bytes = match crate::crypto::b64url_decode(sig_b64) {
            Ok(b) => b,
            Err(_) => return false,
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        let signable = serde_json::json!({
            "type": self.obj_type,
            "version": self.version,
            "agent_id": self.agent_id,
            "key_id": self.key_id,
            "parents": self.parents,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "provenance": self.provenance,
            "commit_id": self.commit_id,
        });
        let canonical = canonical_json(&signable);

        crate::crypto::KeyPair::verify_with_public_key(
            public_key,
            canonical.as_bytes(),
            &sig,
        )
    }
}

fn chrono_now() -> String {
    // Simple ISO 8601 UTC timestamp
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Convert epoch to date (simplified — not full chrono)
    let (year, month, day, hour, min, sec) = epoch_to_ymd_hms(secs);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hour, min, sec, millis
    )
}

fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86400;
    let remainder = secs % 86400;
    let hour = (remainder / 3600) as u32;
    let min = ((remainder % 3600) / 60) as u32;
    let sec = (remainder % 60) as u32;

    // Days since 1970-01-01 to date
    let mut year = 1970u32;
    let mut remaining_days = days;

    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let month_days = [31, if is_leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u32;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = (remaining_days + 1) as u32;

    (year, month, day, hour, min, sec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use serde_json::json;

    #[test]
    fn test_identity_derivation() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");
        assert!(ident.verify_self());
        assert!(ident.agent_id.starts_with("did:alethech:"));
    }

    #[test]
    fn test_commit_sign_and_verify() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut commit = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"test": true}),
        );
        commit.sign(&kp);
        assert!(commit.verify(&pk));
    }

    #[test]
    fn test_commit_tamper_detected() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let mut commit = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"test": true}),
        );
        commit.sign(&kp);

        // Tamper with content
        commit.content = json!({"test": false});
        assert!(!commit.verify(&pk));
    }

    #[test]
    fn test_commit_id_changes_with_content() {
        let kp = KeyPair::generate();
        let pk = kp.public_key_bytes();
        let ident = Identity::from_public_key(&pk, "key-001");

        let commit1 = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"v": 1}),
        );
        let commit2 = MemoryCommit::new(
            &ident.agent_id,
            "key-001",
            vec![],
            json!({"v": 2}),
        );
        assert_ne!(commit1.commit_id, commit2.commit_id);
    }
}
