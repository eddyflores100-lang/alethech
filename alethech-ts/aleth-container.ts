// Portable .aleth v1 reader for Node.js.
// Decrypts the exact container produced by the Python reference implementation.
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { createHash, randomBytes, scrypt as scryptCb, webcrypto } from "node:crypto";
import { promisify } from "node:util";
import { join, relative, sep } from "node:path";
import { bytesToBase64Url, canonicalizeJson } from "./index.ts";

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

export interface AlethOpened {
  payload: AlethPayload;
  plaintext_sha256: string;
}


function allowedPath(rel: string): boolean {
  if (!rel || rel.includes("\\") || rel.startsWith("/") || rel.split("/").some(p => !p || p === "." || p === "..")) return false;
  if (["HEAD","root_authority.json","keys/signing.key"].includes(rel)) return true;
  const parts = rel.split("/");
  return parts.length === 2 && ["identities","commits","evidence","artifacts","control_events","migrations","checkpoints"].includes(parts[0]);
}

function logicalizePhysicalPath(rel: string): string {
  const parts=rel.split("/");
  if(parts.length!==2) return rel;
  const [dir,name]=parts;
  const jsonDirs=new Set(["identities","commits","evidence","control_events","migrations","checkpoints"]);
  if(jsonDirs.has(dir) && name.endsWith(".json")){
    const stem=name.slice(0,-5);
    let decoded:string;
    try { decoded=decodeURIComponent(stem); }
    catch { throw new Error(`invalid portable filesystem encoding: ${rel}`); }
    return `${dir}/${decoded}.json`;
  }
  if(dir==="artifacts"){
    let decoded:string;
    try { decoded=decodeURIComponent(name); }
    catch { throw new Error(`invalid portable filesystem encoding: ${rel}`); }
    return `artifacts/${decoded}`;
  }
  return rel;
}

async function collectFiles(root: string): Promise<Record<string,string>> {
  const files: Record<string,string> = {};
  let total = 0;
  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(dir, entry.name);
      const st = await lstat(full);
      if (st.isSymbolicLink()) throw new Error("symlink not allowed");
      if (st.isDirectory()) { await walk(full); continue; }
      if (!st.isFile()) continue;
      const physicalRel = relative(root, full).split(sep).join("/");
      if (physicalRel === "keys/root.key" || physicalRel === "keys/recovery.key") continue;
      const rel = logicalizePhysicalPath(physicalRel);
      if (!allowedPath(rel)) continue;
      const data = await readFile(full);
      if (data.length > 100 * 1024 * 1024) throw new Error("file too large");
      total += data.length;
      if (total > 512 * 1024 * 1024) throw new Error("payload too large");
      files[rel] = bytesToBase64Url(data);
      if (Object.keys(files).length > 100000) throw new Error("too many files");
    }
  }
  await walk(root);
  return files;
}

export async function sealAlethPayload(payload: AlethPayload, output: string, passphrase: string): Promise<void> {
  if (!passphrase) throw new Error("passphrase must be non-empty");
  if (payload.payload_version !== 1 || typeof payload.files !== "object" || payload.files === null) {
    throw new Error("unsupported payload");
  }
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const header = {
    cipher:"AES-256-GCM", format:"aleth", kdf:"scrypt",
    nonce:bytesToBase64Url(nonce), salt:bytesToBase64Url(salt),
    scrypt_n:32768, scrypt_p:1, scrypt_r:8, version:1
  };
  const hb = Buffer.from(canonicalizeJson(header), "utf8");
  const plain = Buffer.from(canonicalizeJson(payload), "utf8");
  if (plain.length > MAX_CONTAINER) throw new Error("payload too large");
  const keyBytes = await scrypt(passphrase, salt, 32, { N:32768, r:8, p:1, maxmem:64*1024*1024 }) as Buffer;
  const key = await subtle.importKey("raw", keyBytes, {name:"AES-GCM"}, false, ["encrypt"]);
  const encrypted = Buffer.from(await subtle.encrypt(
    {name:"AES-GCM", iv:nonce, additionalData:hb, tagLength:128},
    key,
    plain
  ));
  const len = Buffer.alloc(4); len.writeUInt32BE(hb.length, 0);
  const blob=Buffer.concat([MAGIC, len, hb, encrypted]);
  if(blob.length>MAX_CONTAINER) throw new Error("container too large");
  await writeFile(output, blob);
}

export async function sealAlethDirectory(source: string, output: string, passphrase: string): Promise<void> {
  const payload = { files: await collectFiles(source), payload_version: 1 };
  await sealAlethPayload(payload, output, passphrase);
}

export async function openAleth(path: string, passphrase: string): Promise<AlethOpened> {
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
  return { payload, plaintext_sha256: createHash("sha256").update(Buffer.from(plain)).digest("hex") };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args[0] === "seal") {
    const [, source, output, passphrase] = args;
    if (!source || !output || !passphrase) throw new Error("usage: aleth-container.ts seal <store-dir> <out.aleth> <passphrase>");
    await sealAlethDirectory(source, output, passphrase);
    return;
  }
  const openArgs = args[0] === "open" ? args.slice(1) : args;
  const [path, passphrase] = openArgs;
  if (!path || !passphrase) throw new Error("usage: aleth-container.ts open <file.aleth> <passphrase>");
  const opened = await openAleth(path, passphrase);
  process.stdout.write(JSON.stringify({
    payload_version: opened.payload.payload_version,
    files: Object.keys(opened.payload.files).sort(),
    plaintext_sha256: opened.plaintext_sha256,
  }));
}

if (process.argv[1]?.endsWith("aleth-container.ts")) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  });
}
