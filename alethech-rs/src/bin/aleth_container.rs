use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use alethech::canonical::canonical_json;
use base64ct::{Base64UrlUnpadded, Encoding};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process,
};

const MAGIC: &[u8; 8] = b"ALETH001";
const MAX_HEADER: usize = 16 * 1024;
const MAX_CONTAINER: usize = 512 * 1024 * 1024;
const MAX_FILE: usize = 100 * 1024 * 1024;
const MAX_TOTAL: usize = 512 * 1024 * 1024;
const MAX_FILES: usize = 100_000;

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    process::exit(1);
}

fn allowed_path(rel: &str) -> bool {
    if rel.is_empty()
        || rel.contains('\')
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

fn walk_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|_| fail("failed to read source directory"));
    for entry in entries {
        let entry = entry.unwrap_or_else(|_| fail("failed to read source entry"));
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).unwrap_or_else(|_| fail("failed to stat source entry"));
        if meta.file_type().is_symlink() {
            fail("symlink not allowed");
        }
        if meta.is_dir() {
            walk_files(root, &path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

fn collect_files(root: &Path) -> Value {
    let mut paths = Vec::new();
    walk_files(root, root, &mut paths);
    paths.sort();

    let mut files = Map::new();
    let mut total = 0usize;
    for path in paths {
        let rel = path
            .strip_prefix(root)
            .unwrap_or_else(|_| fail("source path escaped root"))
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");

        if matches!(rel.as_str(), "keys/root.key" | "keys/recovery.key") {
            continue;
        }
        if !allowed_path(&rel) {
            continue;
        }
        let data = fs::read(&path).unwrap_or_else(|_| fail("failed to read source file"));
        if data.len() > MAX_FILE {
            fail("file too large");
        }
        total += data.len();
        if total > MAX_TOTAL {
            fail("payload too large");
        }
        files.insert(rel, Value::String(Base64UrlUnpadded::encode_string(&data)));
        if files.len() > MAX_FILES {
            fail("too many files");
        }
    }
    Value::Object(files)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    if passphrase.is_empty() {
        fail("passphrase must be non-empty");
    }
    let params = Params::new(15, 8, 1, 32).unwrap_or_else(|_| fail("invalid scrypt params"));
    let mut key = [0u8; 32];
    scrypt(passphrase.as_bytes(), salt, &params, &mut key)
        .unwrap_or_else(|_| fail("scrypt failed"));
    key
}

fn seal(source: &Path, output: &Path, passphrase: &str) {
    if !source.is_dir() {
        fail("source must be a directory");
    }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

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
    let header_bytes = canonical_json(&header).into_bytes();
    let payload = json!({
        "files": collect_files(source),
        "payload_version": 1
    });
    let plaintext = canonical_json(&payload).into_bytes();

    let key = derive_key(passphrase, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap_or_else(|_| fail("invalid AES key"));
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &header_bytes,
            },
        )
        .unwrap_or_else(|_| fail("encryption failed"));

    let mut blob = Vec::with_capacity(12 + header_bytes.len() + encrypted.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    blob.extend_from_slice(&header_bytes);
    blob.extend_from_slice(&encrypted);
    if blob.len() > MAX_CONTAINER {
        fail("container too large");
    }
    fs::write(output, blob).unwrap_or_else(|_| fail("failed to write container"));
}

fn open(path: &Path, passphrase: &str) {
    let blob = fs::read(path).unwrap_or_else(|_| fail("failed to read container"));
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
    if canonical_json(&header).as_bytes() != header_bytes {
        fail("header is not canonical JCS");
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

    let key = derive_key(passphrase, &salt);
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

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seal") => {
            if args.len() != 5 {
                fail("usage: alethech-container seal <store-dir> <out.aleth> <passphrase>");
            }
            seal(Path::new(&args[2]), Path::new(&args[3]), &args[4]);
        }
        Some("open") => {
            if args.len() != 4 {
                fail("usage: alethech-container open <file.aleth> <passphrase>");
            }
            open(Path::new(&args[2]), &args[3]);
        }
        _ if args.len() == 3 => open(Path::new(&args[1]), &args[2]),
        _ => fail("usage: alethech-container <open|seal> ..."),
    }
}
