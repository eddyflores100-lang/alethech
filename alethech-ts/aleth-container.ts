// Portable .aleth v1 reader for Node.js.
// Decrypts the exact container produced by the Python reference implementation.
import { readFile } from "node:fs/promises";
import { scrypt as scryptCb, webcrypto } from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCb);
const subtle = globalThis.crypto?.subtle ?? webcrypto.subtle;
const MAGIC = Buffer.from("ALETH001", "ascii");
const MAX_HEADER = 16 * 1024;
const MAX_CONTAINER = 512 * 1024 * 1024;

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export interface AlethPayload {
  payload_version: number;
  files: Record<string, string>;
}

export async function openAleth(path: string, passphrase: string): Promise<AlethPayload> {
  const blob = await readFile(path);
  if (blob.length > MAX_CONTAINER) throw new Error("container too large");
  if (blob.length < 12 || !blob.subarray(0, 8).equals(MAGIC)) throw new Error("invalid .aleth magic");
  const hlen = blob.readUInt32BE(8);
  if (hlen === 0 || hlen > MAX_HEADER || 12 + hlen >= blob.length) throw new Error("invalid header length");
  const hb = blob.subarray(12, 12 + hlen);
  const encrypted = blob.subarray(12 + hlen);
  const header = JSON.parse(hb.toString("utf8"));
  const expected: Record<string, unknown> = {
    cipher:"AES-256-GCM", format:"aleth", kdf:"scrypt",
    scrypt_n:32768, scrypt_p:1, scrypt_r:8, version:1
  };
  for (const [k,v] of Object.entries(expected)) if (header[k] !== v) throw new Error("unsupported container parameters");
  const salt=b64urlDecode(header.salt), nonce=b64urlDecode(header.nonce);
  if (salt.length !== 16 || nonce.length !== 12) throw new Error("invalid salt or nonce size");
  if (encrypted.length < 16) throw new Error("truncated ciphertext");

  const keyBytes = await scrypt(passphrase, salt, 32, { N:32768, r:8, p:1, maxmem:64*1024*1024 }) as Buffer;
  const key = await subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["decrypt"]);
  // Python cryptography appends the 16-byte GCM tag to ciphertext; WebCrypto expects the same concatenation.
  let plain: ArrayBuffer;
  try {
    plain = await subtle.decrypt(
      {name:"AES-GCM", iv:nonce, additionalData:hb, tagLength:128},
      key,
      encrypted
    );
  } catch {
    throw new Error("authentication failed");
  }
  const payload = JSON.parse(new TextDecoder().decode(plain)) as AlethPayload;
  if (payload.payload_version !== 1 || typeof payload.files !== "object" || payload.files === null) {
    throw new Error("unsupported payload");
  }
  return payload;
}

if (process.argv[1]?.endsWith("aleth-container.ts")) {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) throw new Error("usage: aleth-container.ts <file.aleth> <passphrase>");
  const payload = await openAleth(path, passphrase);
  process.stdout.write(JSON.stringify({payload_version:payload.payload_version, files:Object.keys(payload.files).sort()}));
}
