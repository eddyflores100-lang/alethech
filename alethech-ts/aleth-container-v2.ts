import { readFile, writeFile } from "node:fs/promises";
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
  const nonce=base64UrlToBytes(s.nonce);
  const salt=base64UrlToBytes(s.salt);
  const wrapped=base64UrlToBytes(s.wrapped_key);
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
  if(base64UrlToBytes(h.container_id).length!==16||base64UrlToBytes(h.payload_nonce).length!==12){
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
  if(!passphrase) throw new Error("passphrase must be non-empty");
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
  const secret=base64UrlToBytes(code.slice(RECOVERY_PREFIX.length));
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
  const blob=await readFile(path);
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
  try{payload=JSON.parse(new TextDecoder().decode(plaintext));}
  catch{throw new Error("invalid encrypted payload");}
  if(!payload||typeof payload!=="object"||Array.isArray(payload)){
    throw new Error("unsupported payload");
  }
  const p=payload as Record<string,any>;
  if(p.payload_version!==1||!p.files||typeof p.files!=="object"||Array.isArray(p.files)){
    throw new Error("unsupported payload");
  }

  return {
    payload:p as AlethV2Payload,
    container_id:header.container_id,
    slot_types:header.slots.map((s:Record<string,any>)=>String(s.type)).sort(),
  };
}

// ============================================================
// seal / recover / migrate — write-side ALETH002 operations
// ============================================================

function encodeRecoverySecret(secret: Uint8Array): string {
  if (secret.length !== 32) throw new Error("recovery secret must be 32 bytes");
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
  if (!passphrase) throw new Error("passphrase must be non-empty");
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
  if (secret.length !== 32) throw new Error("recovery secret must be 32 bytes");
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
 * `recoverAlethV2` and `migrateAlethV1ToV2` so that the new container
 * is cryptographically bound to the same identity as the source.
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
  if (!passphrase) throw new Error("passphrase must be non-empty");
  if (payload.payload_version !== 1 || typeof payload.files !== "object" || payload.files === null) {
    throw new Error("unsupported payload");
  }

  const containerId = options.containerId ?? randomContainerId();
  if (containerId.length !== 16) throw new Error("container_id must be 16 bytes");
  const containerIdStr = bytesToBase64Url(containerId);

  // Decode payload files (base64url -> bytes) before canonical JSON.
  // Python does _decode_payload_files here. We mirror that: the caller
  // passes already-encoded base64url strings (consistent with the open
  // path), so the payload dict goes through canonical JSON as-is.
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
  // validateHeader is called by openAlethV2 when this container is read back;
  // for seal we trust the construction above matches the schema.
  const hb = Buffer.from(canonicalizeJson(header), "utf8");
  if (hb.length > MAX_HEADER) throw new Error("header too large");
  const plain = Buffer.from(canonicalizeJson(payload), "utf8");
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

  await writeFile(output, blob);
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
 * the same recovery code is returned.
 *
 * The payload is NOT re-verified here. The Python implementation
 * materializes the payload into a Store and runs verify_store on it
 * before writing the replacement container. That step requires the
 * full alethech runtime (DAG verification, signature checks, etc.),
 * which is out of scope for this container-format module. Callers
 * that need protocol-level verification should do it after calling
 * this function, by reading back the output and running their own
 * verifier.
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
 * Like `recoverAlethV2`, this function does NOT re-verify the
 * payload's cryptographic history. Python does that via
 * `_materialize_payload` + `verify_store`; callers that need that
 * should do it themselves after this call.
 */
export async function migrateAlethV1ToV2(
  inputPath: string,
  outputPath: string,
  oldPassphrase: string,
  newPassphrase: string,
  options: { createRecovery?: boolean } = {},
): Promise<{ recoveryCode: string | null; containerId: string }> {
  // Import openAleth from the v1 module. We use a dynamic import to
  // avoid a circular dependency if the v1 module imports anything from
  // here in the future.
  const { openAleth } = await import("./aleth-container.ts");
  const opened = await openAleth(inputPath, oldPassphrase);
  const recoverySecret = options.createRecovery !== false ? randomBytes(32) : null;
  const result = await sealAlethV2(opened.payload, outputPath, newPassphrase, {
    recoverySecret,
  });
  // Sanity: re-open the v2 container we just wrote, to confirm it round-trips.
  // Python does this via `inspect_container_v2(output, passphrase=new_passphrase)`.
  await openAlethV2(outputPath, { passphrase: newPassphrase });
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
      const {readFileSync}=await import("node:fs");
      const payload=JSON.parse(readFileSync(payloadPath,"utf8"));
      const recoverySecret=recoveryArg?Buffer.from(recoveryArg,"base64url"):null;
      const result=await sealAlethV2(payload,outFile,pass,{recoverySecret});
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="recover"){
      const [inFile,outFile,recCode,newPass]=[path,credential,process.argv[5],process.argv[6]];
      if(!inFile||!outFile||!recCode||!newPass) throw new Error("usage: aleth-container-v2.ts recover <in.aleth> <out.aleth> <recovery-code> <new-passphrase>");
      const result=await recoverAlethV2(inFile,outFile,recCode,newPass);
      process.stdout.write(JSON.stringify(result));
    }else if(mode==="migrate"){
      const [inFile,outFile,oldPass,newPass]=[path,credential,process.argv[5],process.argv[6]];
      if(!inFile||!outFile||!oldPass||!newPass) throw new Error("usage: aleth-container-v2.ts migrate <in-v1.aleth> <out-v2.aleth> <old-pass> <new-pass>");
      const result=await migrateAlethV1ToV2(inFile,outFile,oldPass,newPass);
      process.stdout.write(JSON.stringify(result));
    }else{
      throw new Error("usage: aleth-container-v2.ts <open-pass|open-recovery|seal|recover|migrate> ...args");
    }
  })().catch(e=>{
    console.error(e.message);
    process.exit(1);
  });
}
