use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use scrypt::{scrypt, Params};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, process};

const MAGIC: &[u8; 8] = b"ALETH001";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        fail("usage: alethech-container <file.aleth> <passphrase>");
    }
    let blob = fs::read(&args[1]).unwrap_or_else(|_| fail("failed to read container"));
    if blob.len() > MAX_CONTAINER {
        fail("container too large");
    }
    if blob.len() < 12 || &blob[..8] != MAGIC {
        fail("invalid .aleth magic");
    }

    let hlen = u32::from_be_bytes(blob[8..12].try_into().unwrap()) as usize;
    if hlen == 0 || hlen > MAX_HEADER || 12 + hlen >= blob.len() {
        fail("invalid header length");
    }
    let header_bytes = &blob[12..12 + hlen];
    let encrypted = &blob[12 + hlen..];
    if encrypted.len() < 16 {
        fail("truncated ciphertext");
    }

    let header: Value =
        serde_json::from_slice(header_bytes).unwrap_or_else(|_| fail("invalid header"));
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
            fail("unsupported container parameters");
        }
    }

    let salt_s = header
        .get("salt")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("invalid salt"));
    let nonce_s = header
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("invalid nonce"));
    let salt = Base64UrlUnpadded::decode_vec(salt_s).unwrap_or_else(|_| fail("invalid salt"));
    let nonce = Base64UrlUnpadded::decode_vec(nonce_s).unwrap_or_else(|_| fail("invalid nonce"));
    if salt.len() != 16 || nonce.len() != 12 {
        fail("invalid salt or nonce size");
    }

    let params = Params::new(15, 8, 1, 32).unwrap_or_else(|_| fail("invalid scrypt params"));
    let mut key = [0u8; 32];
    scrypt(args[2].as_bytes(), &salt, &params, &mut key)
        .unwrap_or_else(|_| fail("scrypt failed"));

    let cipher = Aes256Gcm::new_from_slice(&key).unwrap_or_else(|_| fail("invalid AES key"));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: encrypted,
                aad: header_bytes,
            },
        )
        .unwrap_or_else(|_| fail("authentication failed"));

    let payload: Value =
        serde_json::from_slice(&plaintext).unwrap_or_else(|_| fail("invalid encrypted payload"));
    if payload.get("payload_version") != Some(&json!(1)) {
        fail("unsupported payload");
    }
    let files_obj = payload
        .get("files")
        .and_then(Value::as_object)
        .unwrap_or_else(|| fail("unsupported payload"));
    let mut files: Vec<String> = files_obj.keys().cloned().collect();
    files.sort();

    let digest = Sha256::digest(&plaintext);
    let out = json!({
        "payload_version": 1,
        "files": files,
        "plaintext_sha256": hex::encode(digest),
    });
    print!("{}", serde_json::to_string(&out).unwrap());
}
