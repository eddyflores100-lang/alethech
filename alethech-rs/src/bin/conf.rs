//! alethech-conf — cross-language conformance helper (Rust side).
//!
//! Takes a fixture path as its single argument, reads the JSON,
//! verifies the signature against the fixture's identity public key,
//! and on success writes the canonical bytes of the signed payload to
//! stdout (exit 0). On failure writes the error to stderr (exit 1).
//!
//! This binary is invoked by `conformance/cross_language_check.py` as
//! the Rust runner. The contract is documented in
//! `conformance/CROSS_LANGUAGE.md`.

use std::env;
use std::fs;
use std::process::exit;

use serde_json::Value;

use alethech::canonical::canonical_json;
use alethech::crypto::{b64url_decode, derive_agent_id};
use alethech::objects::MemoryCommit;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: alethech-conf <fixture.json>");
        exit(2);
    }

    let fixture_path = &args[1];
    let content = match fs::read_to_string(fixture_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot read fixture {}: {}", fixture_path, e);
            exit(2);
        }
    };

    let data: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid JSON in fixture: {}", e);
            exit(2);
        }
    };

    // Fixtures wrap the actual object in input.commit (or similar).
    let expected = data
        .get("expected_result")
        .and_then(|v| v.as_str())
        .unwrap_or("verify_ok");

    let input = data.get("input").unwrap_or(&data);
    let commit_data = input
        .get("commit")
        .or_else(|| input.get("evidence"))
        .or_else(|| input.get("checkpoint"))
        .unwrap_or(input);
    let identity_data = input.get("identity").cloned().unwrap_or_default();

    let obj_type = commit_data
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if obj_type == "AgentIdDerivation" {
        let pub_jwk = commit_data
            .get("public_key")
            .unwrap_or_else(|| {
                eprintln!("error: public_key missing");
                exit(1);
            });
        let x = pub_jwk
            .get("x")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                eprintln!("error: public_key.x missing");
                exit(1);
            });
        let bytes = b64url_decode(x).unwrap_or_else(|_| {
            eprintln!("error: invalid public key encoding");
            exit(1);
        });
        if bytes.len() != 32 {
            eprintln!("error: public key is {} bytes, expected 32", bytes.len());
            exit(1);
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        let derived = derive_agent_id(&pk);
        let expected_id = commit_data
            .get("expected_agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if derived != expected_id {
            eprintln!("error: agent_id mismatch: {}", derived);
            exit(1);
        }
        print!("{}", derived);
        exit(0);
    }

    // Skip fixtures that test JCS canonicalization directly (not signed objects).
    if obj_type == "JCSNumberTest" || obj_type == "UnicodeDistinctness" {
        // Acknowledge the fixture but produce no canonical bytes —
        // the harness counts this as "skipped (JCS-only)".
        println!("skipped: JCS-only fixture");
        exit(0);
    }

    if obj_type != "MemoryCommit" {
        eprintln!("error: unsupported object type: {} (only MemoryCommit supported in this runner)", obj_type);
        exit(1);
    }

    // Parse the commit
    let commit_json = serde_json::to_string(commit_data).unwrap_or_default();
    let commit: MemoryCommit = match serde_json::from_str(&commit_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: cannot parse MemoryCommit: {}", e);
            exit(1);
        }
    };

    // Get the signer public key from the fixture's identity
    let pub_jwk = match identity_data.get("public_key") {
        Some(pk) => pk,
        None => {
            // No identity in fixture — accept if structure is valid.
            // Compute canonical bytes of the signable dict (without commit_id, signature).
            let signable = serde_json::json!({
                "type": commit.obj_type,
                "version": commit.version,
                "agent_id": commit.agent_id,
                "key_id": commit.key_id,
                "parents": commit.parents,
                "timestamp": commit.timestamp,
                "session_id": commit.session_id,
                "memory_type": commit.memory_type,
                "content": commit.content,
                "provenance": commit.provenance,
            });
            let canonical = canonical_json(&signable);
            print!("{}", canonical);
            exit(0);
        }
    };

    let x_b64 = match pub_jwk.get("x").and_then(|v| v.as_str()) {
        Some(x) => x,
        None => {
            eprintln!("error: identity.public_key.x missing");
            exit(1);
        }
    };

    let pub_bytes = match b64url_decode(x_b64) {
        Ok(b) => {
            if b.len() != 32 {
                eprintln!("error: public key is {} bytes, expected 32", b.len());
                exit(1);
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        Err(e) => {
            eprintln!("error: cannot decode public key: {}", e);
            exit(1);
        }
    };

    let verified = commit.verify(&pub_bytes);

    if expected == "verify_ok" {
        if verified {
            // Compute canonical bytes of the signable dict
            let signable = serde_json::json!({
                "type": commit.obj_type,
                "version": commit.version,
                "agent_id": commit.agent_id,
                "key_id": commit.key_id,
                "parents": commit.parents,
                "timestamp": commit.timestamp,
                "session_id": commit.session_id,
                "memory_type": commit.memory_type,
                "content": commit.content,
                "provenance": commit.provenance,
            });
            let canonical = canonical_json(&signable);
            print!("{}", canonical);
            exit(0);
        } else {
            eprintln!("error: expected verify_ok but verification failed");
            exit(1);
        }
    } else {
        // expected == verify_fail
        if !verified {
            eprintln!("correctly rejected (expected verify_fail)");
            exit(1);
        } else {
            eprintln!("error: expected verify_fail but verification passed — BUG");
            exit(1);
        }
    }
}
