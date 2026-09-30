import {
  base64UrlToBytes,
  deriveAgentId,
  verifyCommit,
  type Identity,
  type MemoryCommit,
} from "./index.ts";

export interface PortablePayload {
  payload_version: number;
  files: Record<string, string>;
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
  return parts.length === 2 && ["identities", "commits", "artifacts"].includes(parts[0]);
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
      path === "root_authority.json" ||
      path.startsWith("control_events/") ||
      path.startsWith("migrations/") ||
      path.startsWith("checkpoints/") ||
      path.startsWith("evidence/")
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
  if(identity.public_key?.kty!=="OKP" || identity.public_key?.crv!=="Ed25519") throw new Error("invalid identity public key");

  const pubBytes=base64UrlToBytes(identity.public_key.x);
  if(pubBytes.length!==32) throw new Error("invalid identity public key");
  const derived=await deriveAgentId(pubBytes);
  if(derived!==identity.agent_id) throw new Error("identity_mismatch");

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
