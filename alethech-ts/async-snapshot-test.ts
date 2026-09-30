import assert from "node:assert/strict";
import { createPortableMemory } from "./portable-create.ts";
import { verifyPortablePayload, verifyPortableLegacyPayload, verifyPortableV2Payload } from "./portable-verifier.ts";
import { bytesToBase64Url, canonicalizeJson, createCommit, deriveAgentId, generateKeyPair, sha256Hex, verifyCommit } from "./index.ts";
import { appendPortableMemory } from "./portable-editor.ts";
import { acceptWritebackProposal } from "./provider-writeback.ts";
import { createWritebackProposal } from "./chat-adapter-contract.ts";
import { createPluginSession, acceptPluginWriteback, preparePluginRequest } from "./plugin-api.ts";

const original=await createPortableMemory({accepted:"original"},{session_id:"snapshot-regression"});
const initial=await verifyPortablePayload(original);
const genesisPath=Object.keys(original.files).filter(p=>p.startsWith("commits/")).find(p=>{
  const record=JSON.parse(Buffer.from(original.files[p],"base64url").toString("utf8"));
  return record.content.type==="genesis";
})!;
const genesis=genesisPath.slice("commits/".length,-".json".length);
const changeHead=(p:typeof original)=>{p.files.HEAD=Buffer.from(genesis+"\n").toString("base64url");};
// Read-only V2 fixture uses fresh root/operational keypairs and signed authority
// records, so direct V2 verification exercises the same snapshot boundary.
const rootKey=await generateKeyPair(),operationalKey=await generateKeyPair();
const agentId=await deriveAgentId(rootKey.publicKeyBytes),rootId=agentId.replace("did:alethech:","did:alethech:root:");
const rootJwk={kty:"OKP",crv:"Ed25519",x:bytesToBase64Url(rootKey.publicKeyBytes)};
const operationalJwk={kty:"OKP",crv:"Ed25519",x:bytesToBase64Url(operationalKey.publicKeyBytes)};
async function signedAuthority(body:Record<string,unknown>){
  const commit_id=`sha256:${await sha256Hex(new TextEncoder().encode(canonicalizeJson(body)))}`;
  const signed={...body,commit_id};
  return {...signed,signature:`ed25519:${bytesToBase64Url(new Uint8Array(await crypto.subtle.sign("Ed25519",rootKey.privateKey,new TextEncoder().encode(canonicalizeJson(signed)))))}`};
}
const root=await signedAuthority({type:"RootAuthority",version:1,root_id:rootId,root_public_key:rootJwk,created_at:"2026-01-01T00:00:00.000Z",recovery_quorum:{}});
const identity=await signedAuthority({type:"IdentityRecordV2",version:2,agent_id:agentId,root_id:rootId,root_public_key:rootJwk,active_keys:[{key_id:"operational-key",public_key:operationalJwk}],revoked_keys:[],created_at:"2026-01-01T00:00:00.000Z"});
const v2Commit=await createCommit(agentId,"operational-key",[],{accepted:"v2"},operationalKey);
const encode=(value:unknown)=>Buffer.from(JSON.stringify(value)).toString("base64url");
const v2Payload={payload_version:1,files:{"root_authority.json":encode(root),[`identities/${agentId}.json`]:encode(identity),[`commits/${v2Commit.commit_id}.json`]:encode(v2Commit),HEAD:Buffer.from(v2Commit.commit_id+"\n").toString("base64url")}};
assert.equal((await verifyPortableV2Payload(v2Payload)).entries.length,1);
const failures:string[]=[];
async function check(name:string,run:()=>Promise<void>){
  try{await run();}catch(error){failures.push(`${name}: ${error instanceof Error?error.message:String(error)}`);}
}

for(const verify of [verifyPortablePayload,verifyPortableLegacyPayload]){
  await check(`verifier ${verify.name} snapshots before awaiting`,async()=>{
    const source=structuredClone(original),pending=verify(source);changeHead(source);
    const view=await pending;assert.equal(view.head,initial.head);assert.equal(view.entries.length,1);
  });
}
for(const verify of [verifyPortablePayload,verifyPortableV2Payload]){
  await check(`V2 verifier ${verify.name} snapshots before awaiting`,async()=>{
    const source=structuredClone(v2Payload),pending=verify(source);source.files.HEAD=Buffer.from("sha256:changed\n").toString("base64url");
    const view=await pending;assert.equal(view.head,v2Commit.commit_id);assert.equal(view.entries.length,1);
  });
}
await check("plugin snapshots the same payload it verified",async()=>{
  const source=structuredClone(original),pending=createPluginSession(source);
  source.files["keys/root.key"]=Buffer.from("authority must not enter a verified session").toString("base64url");
  changeHead(source);
  const session=await pending;
  assert.equal(session.view.head,initial.head);
  assert.deepEqual(session.payload,original);
  assert.deepEqual(await verifyPortablePayload(session.payload),session.view);
});
await check("editor snapshots source, accepted content and signing options",async()=>{
  const source=structuredClone(original),content={accepted:{text:"reviewed"}},options={memory_type:"semantic" as const,session_id:"reviewed-session",source:"reviewed-source",confidence:0.9};
  const pending=appendPortableMemory(source,content,options);
  changeHead(source);content.accepted.text="changed after approval";options.session_id="changed-session";options.source="changed-source";options.confidence=0.1;
  const result=await pending;
  assert.deepEqual(result.commit.parents,[initial.head]);assert.equal((result.commit.content.accepted as any).text,"reviewed");
  assert.equal(result.commit.session_id,"reviewed-session");assert.equal(result.commit.provenance.source,"reviewed-source");assert.equal(result.commit.provenance.confidence,0.9);
  content.accepted.text="changed after return";
  assert.equal((result.commit.content.accepted as any).text,"reviewed");
  assert.equal((await verifyPortablePayload(result.payload)).head,result.commit.commit_id);
});
await check("writeback signs the proposal accepted at invocation",async()=>{
  const source=structuredClone(original),proposal=createWritebackProposal(initial.head,[{memory_type:"semantic",content:{accepted:{text:"reviewed"}},source:"reviewed",confidence:0.9}]);
  const pending=acceptWritebackProposal(source,proposal);
  proposal.items[0].content={accepted:{text:"changed after approval"}};proposal.items[0].memory_type="procedural";proposal.items[0].source="changed";proposal.items[0].confidence=0.1;
  const accepted=await pending;
  assert.equal((accepted.commits[0].content.accepted as any).text,"reviewed");assert.equal(accepted.commits[0].memory_type,"semantic");assert.equal(accepted.commits[0].provenance.source,"reviewed");assert.equal(accepted.commits[0].provenance.confidence,0.9);
});
await check("writeback snapshots current payload before await",async()=>{
  const source=structuredClone(original),proposal=createWritebackProposal(initial.head,[{memory_type:"semantic",content:{accepted:"reviewed"}}]);
  const pending=acceptWritebackProposal(source,proposal);changeHead(source);
  const accepted=await pending;assert.deepEqual(accepted.commits[0].parents,[initial.head]);
});
await check("plugin sessions remain immutable after return and acceptance",async()=>{
  const session=await createPluginSession(original);
  assert.throws(()=>{session.view.entries[0].content.accepted="unverified injection";},TypeError);
  assert.throws(()=>{session.payload.files.HEAD="unverified injection";},TypeError);
  assert.throws(()=>{(session as any).view={...session.view,head:genesis};},TypeError);
  const proposal=createWritebackProposal(session.view.head,[{memory_type:"semantic",content:{accepted:"reviewed"}}]);
  const pending=acceptPluginWriteback(session,proposal);proposal.items[0].content.accepted="changed after approval";
  const next=await pending;assert.equal(next.view.entries.at(-1)!.content.accepted,"reviewed");
  assert.throws(()=>{next.view.entries.at(-1)!.content.accepted="unverified injection";},TypeError);
  assert.throws(()=>{next.payload.files.HEAD="unverified injection";},TypeError);
  assert.deepEqual(await verifyPortablePayload(next.payload),next.view);
  const request=preparePluginRequest(next,"local","use accepted memory");assert.ok(JSON.stringify(request).includes("reviewed"));
});
await check("core commit signing snapshots approved content, parents and keypair",async()=>{
  const content={accepted:{text:"reviewed"}},parents=[initial.head],keys={...operationalKey};
  const pending=createCommit(agentId,"operational-key",parents,content,keys);
  content.accepted.text="changed after approval";parents[0]=genesis;keys.privateKey=rootKey.privateKey;
  const commit=await pending;
  assert.equal((commit.content.accepted as any).text,"reviewed");assert.deepEqual(commit.parents,[initial.head]);
  assert.equal(await verifyCommit(commit,operationalKey.publicKeyBytes),true);
});
await check("core commit verification snapshots record and public key",async()=>{
  const record=structuredClone(v2Commit),publicKey=operationalKey.publicKeyBytes.slice();
  const pending=verifyCommit(record,publicKey);record.content.accepted="changed while verifying";publicKey.fill(0);
  assert.equal(await pending,true);
});
assert.deepEqual(failures,[]);
console.log("SDK async snapshots: verifier, plugin session, editor and accepted writeback passed");
