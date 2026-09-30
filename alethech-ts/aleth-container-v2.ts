import { open, rename, unlink, stat } from "node:fs/promises";
import { dirname, join, basename, resolve } from "node:path";
import { verifyPortablePayload } from "./portable-verifier.ts";
import { randomBytes, scrypt as scryptCb, webcrypto } from "node:crypto";
import { promisify } from "node:util";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalizeJson,
} from "./index.ts";

const scrypt = promisify(scryptCb);
const subtle = globalThis.crypto?.subtle ?? webcrypto.subtle;
const MAGIC = Buffer.from("ALETH002", "ascii");
const MAX_HEADER = 16 * 1024;
const MAX_CONTAINER = 512 * 1024 * 1024;
const MAX_TOTAL = 512 * 1024 * 1024;
const MAX_FILES = 100_000;
const MAX_FILE = 100 * 1024 * 1024;
const RECOVERY_PREFIX = "aleth-recovery-v1:";
const RECOVERY_INFO = new TextEncoder().encode("alethech-container-recovery-v1");

export interface AlethV2Payload {
  payload_version: number;
  files: Record<string,string>;
}

export interface AlethV2OpenResult {
  payload: AlethV2Payload;
  container_id: string;
  slot_types: string[];
}

type Unlock =
  | {passphrase:string;recovery_code?:never}
  | {passphrase?:never;recovery_code:string};

function exactKeys(value:Record<string,unknown>, expected:string[]):boolean{
  const actual=Object.keys(value).sort();
  const wanted=[...expected].sort();
  return actual.length===wanted.length && actual.every((k,i)=>k===wanted[i]);
}

function decodeCanonicalBase64Url(value: unknown): Uint8Array {
  if(typeof value!=="string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length%4===1) {
    throw new Error("invalid payload/header encoding");
  }
  const bytes=Buffer.from(value,"base64url");
  if(bytes.toString("base64url")!==value) throw new Error("invalid payload/header encoding");
  return bytes;
}

function validatePayload(payload:unknown):asserts payload is AlethV2Payload {
  if(!payload || typeof payload!=="object" || Array.isArray(payload)) throw new Error("unsupported payload");
  const p=payload as Record<string,unknown>;
  if(!exactKeys(p,["payload_version","files"]) || p.payload_version!==1 || !p.files || typeof p.files!=="object" || Array.isArray(p.files)) {
    throw new Error("unsupported payload schema");
  }
  const entries=Object.entries(p.files);
  if(entries.length>MAX_FILES) throw new Error("too many files");
  let total=0;
  for(const [path,encoded] of entries){
    if(path==="keys/root.key" || path==="keys/recovery.key") throw new Error("forbidden authority key in portable payload");
    const parts=path.split("/");
    const allowed=path==="HEAD" || path==="root_authority.json" || path==="keys/signing.key" ||
      (parts.length===2 && ["identities","commits","evidence","artifacts","control_events","migrations","checkpoints"].includes(parts[0]));
    if(!allowed || path.includes("\\") || path.includes("\0") || parts.some(p=>!p || p==="." || p==="..")) throw new Error(`invalid payload path: ${path}`);
    if(typeof encoded!=="string") throw new Error(`invalid payload encoding: ${path}`);
    // Reject excessive allocation before decoding.
    if(encoded.length>Math.ceil(MAX_FILE*4/3)) throw new Error(`file too large: ${path}`);
    const bytes=decodeCanonicalBase64Url(encoded);
    if(bytes.length>MAX_FILE) throw new Error(`file too large: ${path}`);
    total+=bytes.length;
    if(total>MAX_TOTAL) throw new Error("payload too large");
  }
}

function validateUnlock(unlock:unknown):asserts unlock is Unlock {
  if(!unlock || typeof unlock!=="object" || Array.isArray(unlock)) throw new Error("exactly one unlock credential required");
  const value=unlock as Record<string,unknown>;
  const keys=Object.keys(value);
  if(keys.length!==1 || !["passphrase","recovery_code"].includes(keys[0]) || typeof value[keys[0]]!=="string" || !value[keys[0]]) {
    throw new Error("exactly one non-empty unlock credential required");
  }
}

async function readContainer(path:string):Promise<Buffer>{
  const file=await open(path,"r");
  try{
    const size=(await file.stat()).size;
    if(size>MAX_CONTAINER) throw new Error("container too large");
    // Bound the read even if another process grows the file after stat.
    const blob=Buffer.alloc(size);
    let offset=0;
    while(offset<size){
      const {bytesRead}=await file.read(blob,offset,size-offset,offset);
      if(!bytesRead) throw new Error("container changed during read");
      offset+=bytesRead;
    }
    const extra=Buffer.alloc(1);
    if((await file.read(extra,0,1,size)).bytesRead) throw new Error("container changed during read");
    return blob;
  }finally{await file.close();}
}

function validateSlot(slot:unknown):asserts slot is Record<string,any>{
  if(!slot || typeof slot!=="object" || Array.isArray(slot)) throw new Error("invalid unlock slot");
  const s=slot as Record<string,any>;
  if(s.type==="passphrase"){
    if(!exactKeys(s,["id","kdf","nonce","salt","scrypt_n","scrypt_p","scrypt_r","type","wrapped_key"])){
      throw new Error("invalid passphrase slot schema");
    }
    if(s.kdf!=="scrypt"||s.scrypt_n!==32768||s.scrypt_r!==8||s.scrypt_p!==1){
      throw new Error("unsupported passphrase slot parameters");
    }
  }else if(s.type==="recovery-secret"){
    if(!exactKeys(s,["id","kdf","nonce","salt","type","wrapped_key"])){
      throw new Error("invalid recovery slot schema");
    }
    if(s.kdf!=="HKDF-SHA256") throw new Error("unsupported recovery slot parameters");
  }else{
    throw new Error("unsupported unlock slot type");
  }
  if(typeof s.id!=="string"||!s.id) throw new Error("invalid slot id");
  const nonce=decodeCanonicalBase64Url(s.nonce);
  const salt=decodeCanonicalBase64Url(s.salt);
  const wrapped=decodeCanonicalBase64Url(s.wrapped_key);
  if(nonce.length!==12||salt.length!==16||wrapped.length!==48){
    throw new Error("invalid unlock slot sizes");
  }
}

function validateHeader(header:unknown):asserts header is Record<string,any>{
  if(!header||typeof header!=="object"||Array.isArray(header)) throw new Error("invalid v2 header");
  const h=header as Record<string,any>;
  if(!exactKeys(h,["container_id","format","payload_cipher","payload_nonce","slots","version"])){
    throw new Error("invalid v2 header schema");
  }
  if(h.format!=="aleth"||h.payload_cipher!=="AES-256-GCM"||h.version!==2){
    throw new Error("unsupported v2 container parameters");
  }
  if(decodeCanonicalBase64Url(h.container_id).length!==16||decodeCanonicalBase64Url(h.payload_nonce).length!==12){
    throw new Error("invalid v2 header sizes");
  }
  if(!Array.isArray(h.slots)||h.slots.length===0||h.slots.length>16){
    throw new Error("invalid unlock slots");
  }
  const ids=new Set<string>();
  for(const slot of h.slots){
    validateSlot(slot);
    if(ids.has(slot.id)) throw new Error("duplicate unlock slot id");
    ids.add(slot.id);
  }
}

function slotAad(containerId:string,slotId:string,slotType:string):Uint8Array{
  return new TextEncoder().encode(canonicalizeJson({
    container_id:containerId,
    envelope_version:2,
    slot_id:slotId,
    slot_type:slotType,
  }));
}

async function derivePassphraseKek(passphrase:string,salt:Uint8Array):Promise<Uint8Array>{
  if(typeof passphrase!=="string" || !passphrase) throw new Error("passphrase must be non-empty");
  const out=await scrypt(passphrase,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024}) as Buffer;
  return new Uint8Array(out);
}

async function deriveRecoveryKek(secret:Uint8Array,salt:Uint8Array):Promise<Uint8Array>{
  if(secret.length!==32) throw new Error("recovery secret must be 32 bytes");
  const base=await subtle.importKey("raw",secret,{name:"HKDF"},false,["deriveBits"]);
  const bits=await subtle.deriveBits(
    {name:"HKDF",hash:"SHA-256",salt,info:RECOVERY_INFO},
    base,
    256,
  );
  return new Uint8Array(bits);
}

function decodeRecoveryCode(code:string):Uint8Array{
  if(typeof code!=="string"||!code.startsWith(RECOVERY_PREFIX)) throw new Error("invalid recovery code");
  const secret=decodeCanonicalBase64Url(code.slice(RECOVERY_PREFIX.length));
  if(secret.length!==32) throw new Error("invalid recovery code");
  return secret;
}

async function unwrapDek(
  slot:Record<string,any>,
  kek:Uint8Array,
  containerId:string,
):Promise<Uint8Array>{
  const key=await subtle.importKey("raw",kek,{name:"AES-GCM"},false,["decrypt"]);
  try{
    const plain=await subtle.decrypt(
      {
        name:"AES-GCM",
        iv:base64UrlToBytes(slot.nonce),
        additionalData:slotAad(containerId,slot.id,slot.type),
        tagLength:128,
      },
      key,
      base64UrlToBytes(slot.wrapped_key),
    );
    const dek=new Uint8Array(plain);
    if(dek.length!==32) throw new Error("invalid unwrapped data key");
    return dek;
  }catch{
    throw new Error("unlock credential invalid");
  }
}

async function unlockDek(header:Record<string,any>,unlock:Unlock):Promise<Uint8Array>{
  if("passphrase" in unlock && typeof unlock.passphrase==="string"){
    for(const slot of header.slots){
      if(slot.type!=="passphrase") continue;
      try{
        const kek=await derivePassphraseKek(unlock.passphrase,base64UrlToBytes(slot.salt));
        return await unwrapDek(slot,kek,header.container_id);
      }catch{}
    }
    throw new Error("passphrase unlock failed");
  }

  const code=(unlock as {recovery_code:string}).recovery_code;
  const secret=decodeRecoveryCode(code);
  for(const slot of header.slots){
    if(slot.type!=="recovery-secret") continue;
    try{
      const kek=await deriveRecoveryKek(secret,base64UrlToBytes(slot.salt));
      return await unwrapDek(slot,kek,header.container_id);
    }catch{}
  }
  throw new Error("recovery unlock failed");
}

export async function openAlethV2(path:string,unlock:Unlock):Promise<AlethV2OpenResult>{
  validateUnlock(unlock);
  const blob=await readContainer(path);
  if(blob.length>MAX_CONTAINER) throw new Error("container too large");
  if(blob.length<12||!blob.subarray(0,8).equals(MAGIC)) throw new Error("invalid ALETH002 magic");
  const hlen=blob.readUInt32BE(8);
  if(hlen===0||hlen>MAX_HEADER||12+hlen>=blob.length) throw new Error("invalid header length");
  const hb=blob.subarray(12,12+hlen);
  const encrypted=blob.subarray(12+hlen);
  if(encrypted.length<16) throw new Error("truncated ciphertext");

  let header:unknown;
  try{header=JSON.parse(hb.toString("utf8"));}
  catch{throw new Error("invalid v2 header");}
  validateHeader(header);
  if(Buffer.from(canonicalizeJson(header),"utf8").compare(hb)!==0){
    throw new Error("v2 header is not canonical JCS");
  }

  const dek=await unlockDek(header,unlock);
  const key=await subtle.importKey("raw",dek,{name:"AES-GCM"},false,["decrypt"]);
  let plaintext:ArrayBuffer;
  try{
    plaintext=await subtle.decrypt(
      {
        name:"AES-GCM",
        iv:base64UrlToBytes(header.payload_nonce),
        additionalData:hb,
        tagLength:128,
      },
      key,
      encrypted,
    );
  }catch{
    throw new Error("payload authentication failed");
  }

  let payload:unknown;
  try{payload=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(plaintext));}
  catch{throw new Error("invalid encrypted payload");}
  if(plaintext.byteLength>MAX_TOTAL) throw new Error("payload too large");
  validatePayload(payload);

  return {
    payload,
    container_id:header.container_id,
    slot_types:header.slots.map((s:Record<string,any>)=>String(s.type)).sort(),
  };
}

// ============================================================
// seal / recover / migrate — write-side ALETH002 operations
// ============================================================

function encodeRecoverySecret(secret: Uint8Array): string {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error("recovery secret must be 32 bytes");
  return RECOVERY_PREFIX + Buffer.from(secret).toString("base64url");
}

function randomContainerId(): Uint8Array {
  return randomBytes(16);
}

async function wrapDek(
  dek: Uint8Array,
  kek: Uint8Array,
  containerId: string,
  slotId: string,
  slotType: "passphrase" | "recovery-secret",
): Promise<{ slot: Record<string, any>; nonce: Uint8Array }> {
  if (dek.length !== 32) throw new Error("DEK must be 32 bytes");
  const key = await subtle.importKey("raw", kek, { name: "AES-GCM" }, false, ["encrypt"]);
  const nonce = randomBytes(12);
  const aad = slotAad(containerId, slotId, slotType);
  const wrapped = new Uint8Array(
    await subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      dek,
    ),
  );
  if (wrapped.length !== 48) throw new Error("internal: wrapped DEK size mismatch");
  return { slot: { nonce, wrapped }, nonce };
}

async function passphraseSlot(
  dek: Uint8Array,
  passphrase: string,
  containerId: string,
): Promise<Record<string, any>> {
  if (typeof passphrase!=="string" || !passphrase) throw new Error("passphrase must be non-empty");
  const salt = randomBytes(16);
  const kek = await derivePassphraseKek(passphrase, salt);
  const slotId = "passphrase-1";
  const { slot } = await wrapDek(dek, kek, containerId, slotId, "passphrase");
  return {
    id: slotId,
    kdf: "scrypt",
    nonce: bytesToBase64Url(slot.nonce),
    salt: bytesToBase64Url(salt),
    scrypt_n: 32768,
    scrypt_p: 1,
    scrypt_r: 8,
    type: "passphrase",
    wrapped_key: bytesToBase64Url(slot.wrapped),
  };
}

async function recoverySlot(
  dek: Uint8Array,
  secret: Uint8Array,
  containerId: string,
): Promise<Record<string, any>> {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error("recovery secret must be 32 bytes");
  const salt = randomBytes(16);
  const kek = await deriveRecoveryKek(secret, salt);
  const slotId = "recovery-1";
  const { slot } = await wrapDek(dek, kek, containerId, slotId, "recovery-secret");
  return {
    id: slotId,
    kdf: "HKDF-SHA256",
    nonce: bytesToBase64Url(slot.nonce),
    salt: bytesToBase64Url(salt),
    type: "recovery-secret",
    wrapped_key: bytesToBase64Url(slot.wrapped),
  };
}

/**
 * Seal a payload as ALETH002.
 *
 * Mirrors Python `seal_store_v2` (more precisely, `_seal_payload_v2`).
 * The caller is responsible for assembling the payload dict in the
 * expected shape:
 *
 *   { payload_version: 1, files: { "rel/path": "base64url-bytes", ... } }
 *
 * If `recoverySecret` is provided, a recovery slot is added and the
 * recovery code string is returned. Otherwise `recoveryCode` is null.
 *
 * If `containerId` is provided, it must be 16 bytes; otherwise a fresh
 * random one is generated. Reusing the container_id is required for
 * `recoverAlethV2`. Migration generates a fresh container identifier.
 */
export async function sealAlethV2(
  payload: AlethV2Payload,
  output: string,
  passphrase: string,
  options: {
    recoverySecret?: Uint8Array | null;
    containerId?: Uint8Array | null;
  } = {},
): Promise<{ recoveryCode: string | null; containerId: string }> {
  if (typeof passphrase!=="string" || !passphrase) throw new Error("passphrase must be non-empty");
  validatePayload(payload);
  // Freeze a JSON snapshot before asynchronous verification and encryption.
  const checkedPayload=JSON.parse(canonicalizeJson(payload)) as AlethV2Payload;
  await verifyPortablePayload(checkedPayload);

  const containerId = options.containerId ?? randomContainerId();
  if (!(containerId instanceof Uint8Array) || containerId.length !== 16) throw new Error("container_id must be 16 bytes");
  const containerIdStr = bytesToBase64Url(containerId);

  // File encodings and decoded size limits were checked before verification.
  const dek = randomBytes(32);
  const slots: Record<string, any>[] = [await passphraseSlot(dek, passphrase, containerIdStr)];
  let recoveryCode: string | null = null;
  if (options.recoverySecret) {
    slots.push(await recoverySlot(dek, options.recoverySecret, containerIdStr));
    recoveryCode = encodeRecoverySecret(options.recoverySecret);
  }

  const payloadNonce = randomBytes(12);
  const header: Record<string, any> = {
    container_id: containerIdStr,
    format: "aleth",
    payload_cipher: "AES-256-GCM",
    payload_nonce: bytesToBase64Url(payloadNonce),
    slots,
    version: 2,
  };
  validateHeader(header);
  const hb = Buffer.from(canonicalizeJson(header), "utf8");
  if (hb.length > MAX_HEADER) throw new Error("header too large");
  const plain = Buffer.from(canonicalizeJson(checkedPayload), "utf8");
  if (plain.length > MAX_TOTAL) throw new Error("payload too large");

  const key = await subtle.importKey("raw", dek, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = Buffer.from(
    await subtle.encrypt(
      { name: "AES-GCM", iv: payloadNonce, additionalData: hb, tagLength: 128 },
      key,
      plain,
    ),
  );
  const len = Buffer.alloc(4);
  len.writeUInt32BE(hb.length, 0);
  const blob = Buffer.concat([MAGIC, len, hb, encrypted]);
  if (blob.length > MAX_CONTAINER) throw new Error("container too large");

  const temporary=join(dirname(output),`.${basename(output)}.${randomBytes(16).toString("hex")}.tmp`);
  let created=false;
  try{
    const file=await open(temporary,"wx",0o600);
    created=true;
    try{await file.writeFile(blob);await file.sync();}finally{await file.close();}
    const reopened=await openAlethV2(temporary,{passphrase});
    await verifyPortablePayload(reopened.payload);
    if(recoveryCode) {
      const recoveryOpened=await openAlethV2(temporary,{recovery_code:recoveryCode});
      await verifyPortablePayload(recoveryOpened.payload);
    }
    await rename(temporary,output);
    created=false;
  }finally{if(created) await unlink(temporary);}

  return { recoveryCode, containerId: containerIdStr };
}

/**
 * Recover an ALETH002 container using the recovery code, and write a
 * new ALETH002 container protected by `newPassphrase`.
 *
 * Mirrors Python `recover_container_v2`.
 *
 * The new container preserves the same `container_id` so that any
 * external reference to the original container's identity still
 * applies. If `rotateRecovery` is true, a fresh recovery secret is
 * generated and the returned `recoveryCode` is the new one; otherwise
 * the same recovery code is returned. Recovery accepts exactly one passphrase
 * slot and one recovery slot so that other credentials cannot be silently lost.
 *
 * The source history and the temporary replacement are verified before
 * atomically replacing the destination.
 */
export async function recoverAlethV2(
  inputPath: string,
  outputPath: string,
  recoveryCode: string,
  newPassphrase: string,
  options: { rotateRecovery?: boolean } = {},
): Promise<{ recoveryCode: string; containerId: string }> {
  // Read and decrypt the original payload using the recovery code.
  const opened = await openAlethV2(inputPath, { recovery_code: recoveryCode });
  if(opened.slot_types.length!==2 || opened.slot_types[0]!=="passphrase" || opened.slot_types[1]!=="recovery-secret") {
    throw new Error("recovery requires exactly one passphrase slot and one recovery slot; refusing to discard other credentials");
  }
  // Preserve the original container_id so the new container is bound
  // to the same identity.
  const containerId = base64UrlToBytes(opened.container_id);
  const nextSecret = options.rotateRecovery ? randomBytes(32) : decodeRecoveryCode(recoveryCode);
  const result = await sealAlethV2(opened.payload, outputPath, newPassphrase, {
    recoverySecret: nextSecret,
    containerId,
  });
  return { recoveryCode: result.recoveryCode!, containerId: result.containerId };
}

/**
 * Migrate an ALETH001 (v1) container to ALETH002 (v2).
 *
 * Mirrors Python `migrate_v1_to_v2`.
 *
 * Reads the v1 container using `oldPassphrase`, then writes a new
 * ALETH002 container protected by `newPassphrase`. If `createRecovery`
 * is true (default), a fresh recovery secret is generated and the
 * recovery code is returned; otherwise `recoveryCode` is null.
 *
 * The decrypted source history is verified before writing, and the
 * replacement is verified before atomically replacing the destination.
 * Replacing the source itself requires `replaceSource: true`.
 */
export async function migrateAlethV1ToV2(
  inputPath: string,
  outputPath: string,
  oldPassphrase: string,
  newPassphrase: string,
  options: { createRecovery?: boolean; replaceSource?: boolean } = {},
): Promise<{ recoveryCode: string | null; containerId: string }> {
  if(options.replaceSource!==true){
    let sameSource=resolve(inputPath)===resolve(outputPath);
    if(!sameSource){
      try{
        const source=await stat(inputPath),destination=await stat(outputPath);
        sameSource=source.dev===destination.dev && source.ino===destination.ino;
      }catch(error){if((error as NodeJS.ErrnoException).code!=="ENOENT") throw error;}
    }
    if(sameSource) throw new Error("migration requires replaceSource=true to replace its v1 source");
  }
  // Import openAleth from the v1 module. We use a dynamic import to
  // avoid a circular dependency if the v1 module imports anything from
  // here in the future.
  const { openAleth } = await import("./aleth-container.ts");
  const opened = await openAleth(inputPath, oldPassphrase);
  const recoverySecret = options.createRecovery !== false ? randomBytes(32) : null;
  const result = await sealAlethV2(opened.payload, outputPath, newPassphrase, {
    recoverySecret,
  });
  return { recoveryCode: result.recoveryCode, containerId: result.containerId };
}

if(process.argv[1]?.endsWith("aleth-container-v2.ts")){
  const [mode,path,credential]=process.argv.slice(2);
  (async()=>{
    if(mode==="open-pass"){
      if(!path||!credential) throw new Error("usage: aleth-container-v2.ts open-pass <file> <passphrase>");
      const result=await openAlethV2(path,{passphrase:credential});
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="open-recovery"){
      if(!path||!credential) throw new Error("usage: aleth-container-v2.ts open-recovery <file> <recovery-code>");
      const result=await openAlethV2(path,{recovery_code:credential});
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="seal"){
      // seal <payload.json> <out.aleth> <passphrase> [recovery-code]
      const [payloadPath,outFile,pass,recoveryArg]=[path,credential,process.argv[5],process.argv[6]];
      if(!payloadPath||!outFile||!pass) throw new Error("usage: aleth-container-v2.ts seal <payload.json> <out.aleth> <passphrase> [recovery-code]");
      const payload=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(await readContainer(payloadPath)));
      const recoverySecret=recoveryArg?(recoveryArg.startsWith(RECOVERY_PREFIX)?decodeRecoveryCode(recoveryArg):decodeCanonicalBase64Url(recoveryArg)):null;
      const result=await sealAlethV2(payload,outFile,pass,{recoverySecret});
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="recover"){
      const [inFile,outFile,recCode,newPass]=[path,credential,process.argv[5],process.argv[6]];
      if(!inFile||!outFile||!recCode||!newPass) throw new Error("usage: aleth-container-v2.ts recover <in.aleth> <out.aleth> <recovery-code> <new-passphrase> [--rotate-recovery]");
      if(process.argv[7] && process.argv[7]!=="--rotate-recovery") throw new Error("unknown recovery option");
      const result=await recoverAlethV2(inFile,outFile,recCode,newPass,{rotateRecovery:process.argv[7]==="--rotate-recovery"});
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="migrate"){
      const [inFile,outFile,oldPass,newPass]=[path,credential,process.argv[5],process.argv[6]];
      if(!inFile||!outFile||!oldPass||!newPass) throw new Error("usage: aleth-container-v2.ts migrate <in-v1.aleth> <out-v2.aleth> <old-pass> <new-pass> [--replace-source]");
      if(process.argv[7] && process.argv[7]!=="--replace-source") throw new Error("unknown migration option");
      const result=await migrateAlethV1ToV2(inFile,outFile,oldPass,newPass,{replaceSource:process.argv[7]==="--replace-source"});
      process.stdout.write(JSON.stringify(result));
    }else{
      throw new Error("usage: aleth-container-v2.ts <open-pass|open-recovery|seal|recover|migrate> ...args");
    }
  })().catch(e=>{
    console.error(e.message);
    process.exit(1);
  });
}
