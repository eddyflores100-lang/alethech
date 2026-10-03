import {
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalizeJson,
  sha256Hex,
  verify,
  type Identity,
  type MemoryCommit,
} from "./index.ts";
import {
  verifyPortablePayload,
  type PortableIdentityV2,
  type PortablePayload,
} from "./portable-verifier.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function decodeText(encoded: string): string {
  return decoder.decode(base64UrlToBytes(encoded));
}

function parseJson<T>(files: Record<string,string>, path: string): T {
  const value=files[path];
  if(typeof value!=="string") throw new Error(`missing file: ${path}`);
  try{return JSON.parse(decodeText(value)) as T;}
  catch{throw new Error(`invalid JSON: ${path}`);}
}

function pemToPkcs8(pem:string):Uint8Array{
  const body=pem
    .replace(/-----BEGIN PRIVATE KEY-----/g,"")
    .replace(/-----END PRIVATE KEY-----/g,"")
    .replace(/\s+/g,"");
  if(!body) throw new Error("invalid signing key PEM");
  const binary=atob(body);
  const out=new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) out[i]=binary.charCodeAt(i);
  return out;
}

async function importSigningKey(files:Record<string,string>):Promise<CryptoKey>{
  const encoded=files["keys/signing.key"];
  if(typeof encoded!=="string") throw new Error("portable memory is read-only: signing key missing");
  try{
    return await crypto.subtle.importKey(
      "pkcs8",
      pemToPkcs8(decodeText(encoded)),
      {name:"Ed25519"},
      false,
      ["sign"],
    );
  }catch{
    throw new Error("portable signing key invalid");
  }
}

async function keyMatches(privateKey:CryptoKey,jwk:any):Promise<boolean>{
  if(!jwk||jwk.kty!=="OKP"||jwk.crv!=="Ed25519"||typeof jwk.x!=="string") return false;
  const raw=base64UrlToBytes(jwk.x);
  if(raw.length!==32) return false;
  const challenge=encoder.encode("alethech-portable-editor-key-binding-v1");
  const signature=new Uint8Array(await crypto.subtle.sign("Ed25519",privateKey,challenge));
  const pub=await crypto.subtle.importKey("raw",raw,{name:"Ed25519"},false,["verify"]);
  return verify(pub,signature,challenge);
}

async function resolveCurrentSigner(
  payload:PortablePayload,
  privateKey:CryptoKey,
):Promise<{agent_id:string;key_id:string}>{
  const identityPaths=Object.keys(payload.files)
    .filter(p=>p.startsWith("identities/")&&p.endsWith(".json"));

  const v2:PortableIdentityV2[]=[];
  const legacy:Identity[]=[];
  for(const path of identityPaths){
    const obj=parseJson<any>(payload.files,path);
    if(obj.type==="IdentityRecordV2") v2.push(obj as PortableIdentityV2);
    else if(obj.type==="Identity") legacy.push(obj as Identity);
  }

  if(v2.length){
    if(v2.length!==1) throw new Error("portable editor requires exactly one current V2 identity");
    for(const key of v2[0].active_keys){
      if(await keyMatches(privateKey,key.public_key)){
        if(typeof key.key_id!=="string"||!key.key_id) throw new Error("active key missing key_id");
        return {agent_id:v2[0].agent_id,key_id:key.key_id};
      }
    }
    throw new Error("portable signing key does not match an active V2 key");
  }

  if(legacy.length!==1) throw new Error("portable editor requires exactly one legacy identity");
  if(!(await keyMatches(privateKey,legacy[0].public_key))){
    throw new Error("portable signing key does not match legacy identity");
  }
  return {agent_id:legacy[0].agent_id,key_id:legacy[0].key_id};
}

export interface AppendMemoryOptions {
  memory_type?: "semantic"|"episodic"|"procedural";
  evidence_refs?: string[];
  session_id?: string;
  source?: string;
  confidence?: number;
}

export interface AppendMemoryResult {
  payload: PortablePayload;
  commit: MemoryCommit;
}

/**
 * Append one signed MemoryCommit to an already-verifiable portable payload.
 *
 * The returned payload is accepted only after the complete portable verifier
 * succeeds again. Root/recovery authority is never required or exposed.
 */
export async function appendPortableMemory(
  payload:PortablePayload,
  content:Record<string,unknown>,
  options:AppendMemoryOptions={},
):Promise<AppendMemoryResult>{
  if(!content||typeof content!=="object"||Array.isArray(content)) throw new Error("content must be an object");

  // Approval and the source history refer to the inputs at invocation, not to
  // caller changes made while key import, hashing and signing are awaiting.
  payload=structuredClone(payload);
  content=structuredClone(content);
  options=structuredClone(options);
  const before=await verifyPortablePayload(payload);
  const privateKey=await importSigningKey(payload.files);
  const signer=await resolveCurrentSigner(payload,privateKey);

  const memoryType=options.memory_type??"semantic";
  if(!["semantic","episodic","procedural"].includes(memoryType)) throw new Error("unsupported memory_type");
  const confidence=options.confidence??1.0;
  if(typeof confidence!=="number"||confidence<0||confidence>1) throw new Error("confidence must be between 0 and 1");

  const evidenceRefs=[...(options.evidence_refs??[])];
  const timestamp=new Date().toISOString();
  const signable={
    type:"MemoryCommit",
    version:1,
    agent_id:signer.agent_id,
    key_id:signer.key_id,
    parents:[before.head],
    timestamp,
    session_id:options.session_id??crypto.randomUUID(),
    memory_type:memoryType,
    content,
    provenance:{
      source:options.source??"agent_observation",
      source_id:crypto.randomUUID(),
      evidence_refs:evidenceRefs,
      confidence,
    },
  };

  const commitId=`sha256:${await sha256Hex(encoder.encode(canonicalizeJson(signable)))}`;
  const signedBytes=encoder.encode(canonicalizeJson({...signable,commit_id:commitId}));
  const signature=new Uint8Array(await crypto.subtle.sign("Ed25519",privateKey,signedBytes));
  const commit={
    ...signable,
    commit_id:commitId,
    signature:`ed25519:${bytesToBase64Url(signature)}`,
  } as MemoryCommit;

  const updated=structuredClone(payload) as PortablePayload;
  updated.files[`commits/${commitId}.json`]=bytesToBase64Url(
    encoder.encode(JSON.stringify(commit))
  );
  updated.files.HEAD=bytesToBase64Url(encoder.encode(commitId+"\n"));

  const after=await verifyPortablePayload(updated);
  if(after.head!==commitId) throw new Error("portable append failed to advance verified HEAD");
  return {payload:updated,commit};
}

export function canonicalPortablePayloadBytes(payload:PortablePayload):Uint8Array{
  return encoder.encode(canonicalizeJson(payload));
}
