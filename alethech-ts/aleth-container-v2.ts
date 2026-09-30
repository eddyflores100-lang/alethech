import { readFile } from "node:fs/promises";
import { scrypt as scryptCb, webcrypto } from "node:crypto";
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

if(process.argv[1]?.endsWith("aleth-container-v2.ts")){
  const [mode,path,credential]=process.argv.slice(2);
  if(mode==="open-pass"){
    if(!path||!credential) throw new Error("usage: aleth-container-v2.ts open-pass <file> <passphrase>");
    const result=await openAlethV2(path,{passphrase:credential});
    process.stdout.write(JSON.stringify(result));
  }else if(mode==="open-recovery"){
    if(!path||!credential) throw new Error("usage: aleth-container-v2.ts open-recovery <file> <recovery-code>");
    const result=await openAlethV2(path,{recovery_code:credential});
    process.stdout.write(JSON.stringify(result));
  }else{
    throw new Error("usage: aleth-container-v2.ts <open-pass|open-recovery> <file> <credential>");
  }
}
