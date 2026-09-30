//! alethech — verifiable agent continuity protocol.
//!
//! Ed25519-signed memory commits, hash-linked DAG, key rotation
//! with reachability guarantee.
//!
//! # Quick start
//!
//! ```
//! use alethech::crypto::KeyPair;
//! use alethech::canonical::canonical_json_bytes;
//! use alethech::crypto::sha256_hex;
//!
//! let kp = KeyPair::generate();
//! let data = br#"{"test":true}"#;
//! let canonical = canonical_json_bytes(data);
//! let hash = sha256_hex(&canonical);
//! let sig = kp.sign(&canonical);
//! assert!(kp.verify(&canonical, &sig));
//! ```

pub mod crypto;
pub mod canonical;
pub mod objects;
pub mod verify;

pub use crypto::KeyPair;
pub use canonical::canonical_json_bytes;
pub use objects::{MemoryCommit, Identity};
pub use verify::verify_commit;
