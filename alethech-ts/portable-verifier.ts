import {
  base64UrlToBytes,
  bytesToBase32Lower,
  canonicalizeJson,
  deriveAgentId,
  sha256,
  sha256Hex,
  verify,
  verifyCommit,
  type Identity,
  type MemoryCommit,
} from "./index.ts";

export interface PortablePayload {
  payload_version: number;
  files: Record<string, string>;
}

export interface PortableRootAuthority {
  type: "RootAuthority";
  version: number;
  root_id: string;
  root_public_key: {kty:string;crv:string;x:string};
  created_at: string;
  recovery_quorum: Record<string, unknown>;
  commit_id: string;
  signature: string;
}

export interface PortableIdentityV2 {
  type: "IdentityRecordV2";
  version: number;
  agent_id: string;
  root_id: string;
  root_public_key: {kty:string;crv:string;x:string};
  active_keys: Array<Record<string, any>>;
  revoked_keys: Array<Record<string, any>>;
  created_at: string;
  commit_id: string;
  signature: string;
}

export interface PortableControlEvent {
  type: "ControlEvent";
  version: number;
  root_id: string;
  sequence: number;
  previous_control_hash: string;
  event_type: string;
  key_id: string;
  public_key: Record<string, unknown>;
  old_key_id: string;
  cutoff_head: string;
  reason: string;
  timestamp: string;
  migration_record_id: string;
  commit_id: string;
  signature: string;
}

export interface PortableEvidenceCommit {
  type: "EvidenceCommit";
  version: number;
  agent_id: string;
  key_id: string;
  timestamp: string;
  event_type: string;
  tool: string;
  tool_version: string;
  input_hash: string;
  output_hash: string;
  artifacts: Array<{name?: string; hash?: string; size?: number}>;
  result: string;
  commit_id: string;
  signature: string;
}

export interface PortableMemoryEntry {
  commit_id: string;
  agent_id: string;
  key_id: string;
  memory_type: string;
  session_id: string;
  content: Record<string, unknown>;
  provenance: Record<string, unknown>;
  timestamp: string;
}

export interface VerifiedPortableView {
  format: "alethech-memory-view";
  version: 1;
  head: string;
  entries: PortableMemoryEntry[];
}

const decoder = new TextDecoder();

function decodeText(encoded: string): string {
  return decoder.decode(base64UrlToBytes(encoded));
}

function safePath(path: string): boolean {
  if (!path || path.includes("\\") || path.startsWith("/")) return false;
  const parts = path.split("/");
  if (parts.some(p => !p || p === "." || p === "..")) return false;
  if (path === "HEAD" || path === "keys/signing.key") return true;
  return parts.length === 2 && ["identities", "commits", "evidence", "artifacts"].includes(parts[0]);
}

function pemToPkcs8(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  if (!body) throw new Error("invalid signing key PEM");
  const binary = atob(body);
  const out = new Uint8Array(binary.length);
  for (let i=0;i<binary.length;i++) out[i]=binary.charCodeAt(i);
  return out;
}

async function verifyPortableSigningKey(files: Record<string,string>, identity: Identity, publicBytes: Uint8Array): Promise<void> {
  const encoded = files["keys/signing.key"];
  if (typeof encoded !== "string") return; // read-only portable memories are allowed
  let privateKey: CryptoKey;
  try {
    const pem = decodeText(encoded);
    privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pemToPkcs8(pem),
      {name:"Ed25519"},
      false,
      ["sign"],
    );
  } catch {
    throw new Error("portable signing key invalid");
  }
  const challenge = new TextEncoder().encode("alethech-portable-key-binding-v1");
  const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, challenge));
  const pubKey = await crypto.subtle.importKey("raw", publicBytes, {name:"Ed25519"}, false, ["verify"]);
  if (!(await verify(pubKey, signature, challenge))) {
    throw new Error("portable signing key does not match identity");
  }
}

async function deriveRootId(jwk: {kty:string;crv:string;x:string}): Promise<string> {
  const bytes=new TextEncoder().encode(canonicalizeJson(jwk));
  const digest=await sha256(bytes);
  return "did:alethech:root:"+bytesToBase32Lower(digest.slice(0,16));
}

function jwkPublicBytes(jwk: any): Uint8Array {
  if(!jwk || jwk.kty!=="OKP" || jwk.crv!=="Ed25519" || typeof jwk.x!=="string") {
    throw new Error("invalid Ed25519 JWK");
  }
  const raw=base64UrlToBytes(jwk.x);
  if(raw.length!==32) throw new Error("invalid Ed25519 public key length");
  return raw;
}

async function verifyPortableSigningKeyV2(
  files: Record<string,string>,
  activeKeys: Array<Record<string,any>>,
): Promise<void> {
  const encoded=files["keys/signing.key"];
  if(typeof encoded!=="string") return;
  let privateKey: CryptoKey;
  try {
    privateKey=await crypto.subtle.importKey(
      "pkcs8",
      pemToPkcs8(decodeText(encoded)),
      {name:"Ed25519"},
      false,
      ["sign"],
    );
  } catch {
    throw new Error("portable signing key invalid");
  }
  const challenge=new TextEncoder().encode("alethech-portable-key-binding-v1");
  const signature=new Uint8Array(await crypto.subtle.sign("Ed25519",privateKey,challenge));
  for(const key of activeKeys){
    try{
      const raw=jwkPublicBytes(key.public_key);
      const pub=await crypto.subtle.importKey("raw",raw,{name:"Ed25519"},false,["verify"]);
      if(await verify(pub,signature,challenge)) return;
    }catch{}
  }
  throw new Error("portable signing key does not match an active identity key");
}

async function verifySignedPortableRecord(
  record: Record<string, unknown> & {commit_id: string; signature: string},
  publicBytes: Uint8Array,
): Promise<boolean> {
  if (typeof record.signature !== "string" || !record.signature.startsWith("ed25519:")) return false;
  const sigBytes = base64UrlToBytes(record.signature.slice(8));
  if (sigBytes.length !== 64) return false;
  const {signature, commit_id, ...body} = record;
  const bodyBytes = new TextEncoder().encode(canonicalizeJson(body));
  const expectedId = `sha256:${await sha256Hex(bodyBytes)}`;
  if (commit_id !== expectedId) return false;
  const signedBytes = new TextEncoder().encode(canonicalizeJson({...body, commit_id}));
  const pubKey = await crypto.subtle.importKey("raw", publicBytes, {name:"Ed25519"}, false, ["verify"]);
  return verify(pubKey, sigBytes, signedBytes);
}

async function verifyArtifacts(files: Record<string,string>): Promise<void> {
  for (const [path, encoded] of Object.entries(files)) {
    if (!path.startsWith("artifacts/")) continue;
    const name = path.slice("artifacts/".length);
    const actual = `sha256:${await sha256Hex(base64UrlToBytes(encoded))}`;
    if (name !== actual) throw new Error(`artifact hash mismatch: ${name}`);
  }
}

function parseJsonFile<T>(files: Record<string,string>, path: string): T {
  const encoded = files[path];
  if (typeof encoded !== "string") throw new Error(`missing file: ${path}`);
  try {
    return JSON.parse(decodeText(encoded)) as T;
  } catch {
    throw new Error(`invalid JSON: ${path}`);
  }
}

function assertSupportedPayload(payload: PortablePayload): void {
  if (payload.payload_version !== 1 || !payload.files || typeof payload.files !== "object") {
    throw new Error("unsupported payload");
  }
  for (const path of Object.keys(payload.files)) {
    if (path === "keys/root.key" || path === "keys/recovery.key") {
      throw new Error("forbidden authority key in portable payload");
    }
    if (
      path.startsWith("migrations/") ||
      path.startsWith("checkpoints/")
    ) {
      throw new Error(`unsupported browser verifier layer: ${path}`);
    }
    if (!safePath(path)) throw new Error(`invalid portable path: ${path}`);
  }
}

function checkDag(commits: Map<string,MemoryCommit>): void {
  for (const [id, commit] of commits) {
    for (const parent of commit.parents) {
      if (!commits.has(parent)) throw new Error(`missing parent ${parent} for ${id}`);
    }
  }

  const WHITE=0, GRAY=1, BLACK=2;
  const state = new Map<string,number>();
  for (const start of commits.keys()) {
    if ((state.get(start) ?? WHITE) !== WHITE) continue;
    const stack: Array<[string,number]> = [[start,0]];
    state.set(start,GRAY);
    while (stack.length) {
      const top = stack[stack.length-1];
      const commit = commits.get(top[0])!;
      if (top[1] >= commit.parents.length) {
        state.set(top[0],BLACK);
        stack.pop();
        continue;
      }
      const parent = commit.parents[top[1]++];
      const ps = state.get(parent) ?? WHITE;
      if (ps === GRAY) throw new Error("cycle detected");
      if (ps === WHITE) {
        state.set(parent,GRAY);
        stack.push([parent,0]);
      }
    }
  }
}

function reachableParentFirst(head:string, commits:Map<string,MemoryCommit>): string[] {
  const ordered:string[]=[];
  const seen=new Set<string>();
  const stack:Array<[string,boolean]>=[[head,false]];
  while(stack.length){
    const [id,expanded]=stack.pop()!;
    if(expanded){
      if(!seen.has(id)){seen.add(id);ordered.push(id);}
      continue;
    }
    if(seen.has(id)) continue;
    const commit=commits.get(id);
    if(!commit) throw new Error(`HEAD/reachable commit missing: ${id}`);
    stack.push([id,true]);
    for(const parent of [...commit.parents].sort().reverse()){
      if(!seen.has(parent)) stack.push([parent,false]);
    }
  }
  return ordered;
}

/// Verify a decrypted legacy-v1 portable payload before exposing memory.
///
/// This intentionally rejects protocol layers not yet implemented in the browser
/// verifier. Fail-closed is part of the contract.
export async function verifyPortableLegacyPayload(payload: PortablePayload): Promise<VerifiedPortableView> {
  assertSupportedPayload(payload);
  const files=payload.files;

  const identityPaths=Object.keys(files).filter(p=>p.startsWith("identities/") && p.endsWith(".json"));
  if(identityPaths.length!==1) throw new Error("legacy browser verifier requires exactly one identity");
  const identity=parseJsonFile<Identity>(files,identityPaths[0]);
  if(identity.type!=="Identity" || identity.version!==1) throw new Error("unsupported identity type");
  if(identityPaths[0] !== `identities/${identity.agent_id}.json`) throw new Error("identity filename mismatch");
  if(identity.public_key?.kty!=="OKP" || identity.public_key?.crv!=="Ed25519") throw new Error("invalid identity public key");

  const pubBytes=base64UrlToBytes(identity.public_key.x);
  if(pubBytes.length!==32) throw new Error("invalid identity public key");
  const derived=await deriveAgentId(pubBytes);
  if(derived!==identity.agent_id) throw new Error("identity_mismatch");
  await verifyPortableSigningKey(files, identity, pubBytes);
  await verifyArtifacts(files);

  const evidencePaths=Object.keys(files).filter(p=>p.startsWith("evidence/") && p.endsWith(".json")).sort();
  const evidence=new Map<string,PortableEvidenceCommit>();
  for(const path of evidencePaths){
    const ev=parseJsonFile<PortableEvidenceCommit>(files,path);
    if(ev.type!=="EvidenceCommit" || ev.version!==1) throw new Error(`unsupported evidence: ${path}`);
    if(ev.agent_id!==identity.agent_id || ev.key_id!==identity.key_id) throw new Error(`evidence identity mismatch: ${path}`);
    if(evidence.has(ev.commit_id)) throw new Error(`duplicate evidence commit_id: ${ev.commit_id}`);
    if(path!==`evidence/${ev.commit_id}.json`) throw new Error(`evidence filename mismatch: ${path}`);
    if(!(await verifySignedPortableRecord(ev as unknown as Record<string,unknown> & {commit_id:string;signature:string},pubBytes))) {
      throw new Error(`evidence verification failed: ${ev.commit_id}`);
    }
    for(const art of ev.artifacts ?? []){
      if(typeof art.hash!=="string") throw new Error(`evidence artifact hash missing: ${ev.commit_id}`);
      const encoded=files[`artifacts/${art.hash}`];
      if(typeof encoded!=="string") throw new Error(`evidence artifact missing: ${art.hash}`);
      const actual=`sha256:${await sha256Hex(base64UrlToBytes(encoded))}`;
      if(actual!==art.hash) throw new Error(`evidence artifact hash mismatch: ${art.hash}`);
    }
    evidence.set(ev.commit_id,ev);
  }

  const commitPaths=Object.keys(files).filter(p=>p.startsWith("commits/") && p.endsWith(".json")).sort();
  if(commitPaths.length===0) throw new Error("no commits");
  const commits=new Map<string,MemoryCommit>();
  for(const path of commitPaths){
    const commit=parseJsonFile<MemoryCommit>(files,path);
    if(commit.type!=="MemoryCommit" || commit.version!==1) throw new Error(`unsupported commit: ${path}`);
    if(commit.agent_id!==identity.agent_id || commit.key_id!==identity.key_id) throw new Error(`commit identity mismatch: ${path}`);
    if(commits.has(commit.commit_id)) throw new Error(`duplicate commit_id: ${commit.commit_id}`);
    const expectedPath=`commits/${commit.commit_id}.json`;
    if(path!==expectedPath) throw new Error(`commit filename mismatch: ${path}`);
    if(!(await verifyCommit(commit,pubBytes))) throw new Error(`commit verification failed: ${commit.commit_id}`);
    const evidenceRefs = Array.isArray((commit.provenance as any)?.evidence_refs)
      ? (commit.provenance as any).evidence_refs
      : [];
    for (const ref of evidenceRefs) {
      if (typeof ref !== "string" || !evidence.has(ref)) {
        throw new Error(`missing evidence reference: ${String(ref)}`);
      }
    }
    commits.set(commit.commit_id,commit);
  }

  checkDag(commits);

  const head=decodeText(files.HEAD ?? "").trim();
  if(!head || !commits.has(head)) throw new Error("HEAD invalid");

  const ordered=reachableParentFirst(head,commits);
  const entries:PortableMemoryEntry[]=[];
  for(const id of ordered){
    const commit=commits.get(id)!;
    const isGenesis=JSON.stringify(commit.content)===JSON.stringify({type:"genesis"});
    if(isGenesis) continue;
    entries.push({
      commit_id:commit.commit_id,
      agent_id:commit.agent_id,
      key_id:commit.key_id,
      memory_type:commit.memory_type,
      session_id:commit.session_id,
      content:commit.content,
      provenance:commit.provenance,
      timestamp:commit.timestamp,
    });
  }
  return {format:"alethech-memory-view",version:1,head,entries};
}


/** Verify a decrypted V2 portable payload (root + governance + memory/evidence).
 * Migrations and checkpoints remain fail-closed until their browser rules land.
 */
export async function verifyPortableV2Payload(payload: PortablePayload): Promise<VerifiedPortableView> {
  assertSupportedPayload(payload);
  const files=payload.files;
  if(typeof files["root_authority.json"]!=="string") throw new Error("missing root authority");
  const root=parseJsonFile<PortableRootAuthority>(files,"root_authority.json");
  if(root.type!=="RootAuthority" || root.version!==1) throw new Error("unsupported root authority");
  const rootBytes=jwkPublicBytes(root.root_public_key);
  if(await deriveRootId(root.root_public_key)!==root.root_id) throw new Error("root_authority_mismatch");
  if(!(await verifySignedPortableRecord(root as any,rootBytes))) throw new Error("root_authority_signature_invalid");

  const identityPaths=Object.keys(files).filter(p=>p.startsWith("identities/")&&p.endsWith(".json"));
  const v2Paths=identityPaths.filter(p=>{
    try{return parseJsonFile<any>(files,p).type==="IdentityRecordV2";}catch{return false;}
  });
  if(v2Paths.length!==1) throw new Error("V2 browser verifier requires exactly one IdentityRecordV2");
  const identity=parseJsonFile<PortableIdentityV2>(files,v2Paths[0]);
  if(identity.version!==2) throw new Error("unsupported IdentityRecordV2 version");
  if(v2Paths[0]!==`identities/${identity.agent_id}.json`) throw new Error("identity filename mismatch");
  if(identity.root_id!==root.root_id || canonicalizeJson(identity.root_public_key)!==canonicalizeJson(root.root_public_key)) {
    throw new Error("identity_root_binding_failed");
  }
  if(await deriveAgentId(jwkPublicBytes(identity.root_public_key))!==identity.agent_id) throw new Error("identity_v2_mismatch");
  if(!(await verifySignedPortableRecord(identity as any,rootBytes))) throw new Error("identity_v2_signature_invalid");

  const eventPaths=Object.keys(files).filter(p=>p.startsWith("control_events/")&&p.endsWith(".json")).sort();
  const events:PortableControlEvent[]=[];
  for(const path of eventPaths){
    const ev=parseJsonFile<PortableControlEvent>(files,path);
    if(ev.type!=="ControlEvent" || ev.version!==1) throw new Error(`unsupported control event: ${path}`);
    if(path!==`control_events/${ev.commit_id}.json`) throw new Error(`control event filename mismatch: ${path}`);
    if(ev.root_id!==root.root_id) throw new Error(`control_event_root_binding_failed: ${ev.commit_id}`);
    if(!(await verifySignedPortableRecord(ev as any,rootBytes))) throw new Error(`control_event_signature_invalid: ${ev.commit_id}`);
    events.push(ev);
  }
  events.sort((a,b)=>a.sequence-b.sequence);
  let previous="", expectedSeq=1;
  for(const ev of events){
    if(ev.sequence!==expectedSeq) throw new Error(`control_chain_invalid: expected sequence ${expectedSeq}, got ${ev.sequence}`);
    if(ev.previous_control_hash!==previous) throw new Error(`control_chain_invalid: previous hash mismatch at ${ev.commit_id}`);
    previous=ev.commit_id; expectedSeq++;
  }

  for(const ev of events){
    if(ev.event_type!=="key_rotation" && ev.event_type!=="key_revoke") continue;
    const revokedId=ev.event_type==="key_rotation"?ev.old_key_id:ev.key_id;
    if(!revokedId) continue;
    const matching=identity.revoked_keys.some(k=>k.key_id===revokedId && k.cutoff_head===ev.cutoff_head);
    const mismatched=identity.revoked_keys.some(k=>k.key_id===revokedId && k.cutoff_head!==ev.cutoff_head);
    const active=identity.active_keys.some(k=>k.key_id===revokedId);
    if(active&&!matching) throw new Error(`identity_control_event_mismatch: revoked key ${revokedId} listed active`);
    if(mismatched&&!matching) throw new Error(`identity_control_event_mismatch: cutoff mismatch for ${revokedId}`);
  }

  await verifyPortableSigningKeyV2(files,identity.active_keys);
  await verifyArtifacts(files);

  const evidencePaths=Object.keys(files).filter(p=>p.startsWith("evidence/")&&p.endsWith(".json")).sort();
  const evidence=new Map<string,PortableEvidenceCommit>();
  const allKeys=[...identity.active_keys,...identity.revoked_keys];
  for(const path of evidencePaths){
    const ev=parseJsonFile<PortableEvidenceCommit>(files,path);
    if(ev.type!=="EvidenceCommit" || ev.version!==1) throw new Error(`unsupported evidence: ${path}`);
    if(ev.agent_id!==identity.agent_id) throw new Error(`evidence identity mismatch: ${path}`);
    const key=allKeys.find(k=>k.key_id===ev.key_id);
    if(!key) throw new Error(`unknown evidence key: ${ev.key_id}`);
    if(path!==`evidence/${ev.commit_id}.json`) throw new Error(`evidence filename mismatch: ${path}`);
    if(!(await verifySignedPortableRecord(ev as any,jwkPublicBytes(key.public_key)))) throw new Error(`evidence verification failed: ${ev.commit_id}`);
    for(const art of ev.artifacts??[]){
      if(typeof art.hash!=="string") throw new Error(`evidence artifact hash missing: ${ev.commit_id}`);
      const encoded=files[`artifacts/${art.hash}`];
      if(typeof encoded!=="string") throw new Error(`evidence artifact missing: ${art.hash}`);
      if(`sha256:${await sha256Hex(base64UrlToBytes(encoded))}`!==art.hash) throw new Error(`evidence artifact hash mismatch: ${art.hash}`);
    }
    evidence.set(ev.commit_id,ev);
  }

  const commitPaths=Object.keys(files).filter(p=>p.startsWith("commits/")&&p.endsWith(".json")).sort();
  if(commitPaths.length===0) throw new Error("no commits");
  const commits=new Map<string,MemoryCommit>();
  const keyState=new Map<string,{state:"active"|"revoked";cutoff?:string;public_key:any}>();
  for(const k of identity.active_keys) keyState.set(k.key_id,{state:"active",public_key:k.public_key});
  for(const k of identity.revoked_keys) keyState.set(k.key_id,{state:"revoked",cutoff:k.cutoff_head,public_key:k.public_key});

  for(const path of commitPaths){
    const commit=parseJsonFile<MemoryCommit>(files,path);
    if(commit.type!=="MemoryCommit"||commit.version!==1) throw new Error(`unsupported commit: ${path}`);
    if(commit.agent_id!==identity.agent_id) throw new Error(`commit identity mismatch: ${path}`);
    const state=keyState.get(commit.key_id);
    if(!state) throw new Error(`unknown commit key: ${commit.key_id}`);
    if(path!==`commits/${commit.commit_id}.json`) throw new Error(`commit filename mismatch: ${path}`);
    if(!(await verifyCommit(commit,jwkPublicBytes(state.public_key)))) throw new Error(`commit verification failed: ${commit.commit_id}`);
    if(commits.has(commit.commit_id)) throw new Error(`duplicate commit_id: ${commit.commit_id}`);
    commits.set(commit.commit_id,commit);
  }

  checkDag(commits);

  for(const ev of events){
    if(ev.event_type==="key_rotation" && ev.cutoff_head && !commits.has(ev.cutoff_head)) {
      throw new Error(`missing_cutoff_head: ${ev.cutoff_head}`);
    }
  }
  for(const commit of commits.values()){
    const state=keyState.get(commit.key_id)!;
    if(state.state==="revoked"){
      if(!state.cutoff || !ancestryCheck(commit.commit_id,state.cutoff,commits)) {
        throw new Error(`not_in_proven_pre_rotation_history: ${commit.commit_id}`);
      }
    }
    const refs=Array.isArray((commit.provenance as any)?.evidence_refs)?(commit.provenance as any).evidence_refs:[];
    for(const ref of refs) if(typeof ref!=="string"||!evidence.has(ref)) throw new Error(`missing evidence reference: ${String(ref)}`);
  }

  const head=decodeText(files.HEAD??"").trim();
  if(!head||!commits.has(head)) throw new Error("HEAD invalid");
  const ordered=reachableParentFirst(head,commits);
  const entries:PortableMemoryEntry[]=[];
  for(const id of ordered){
    const commit=commits.get(id)!;
    if(JSON.stringify(commit.content)===JSON.stringify({type:"genesis"})) continue;
    entries.push({
      commit_id:commit.commit_id,agent_id:commit.agent_id,key_id:commit.key_id,
      memory_type:commit.memory_type,session_id:commit.session_id,content:commit.content,
      provenance:commit.provenance,timestamp:commit.timestamp,
    });
  }
  return {format:"alethech-memory-view",version:1,head,entries};
}

export async function verifyPortablePayload(payload: PortablePayload): Promise<VerifiedPortableView> {
  const identityPaths=Object.keys(payload.files??{}).filter(p=>p.startsWith("identities/")&&p.endsWith(".json"));
  const types=identityPaths.map(p=>{
    try{return parseJsonFile<any>(payload.files,p).type;}catch{return "";}
  });
  if(types.includes("IdentityRecordV2")) return verifyPortableV2Payload(payload);
  return verifyPortableLegacyPayload(payload);
}
