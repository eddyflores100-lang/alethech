import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, readdir, stat, rm, symlink, link } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, scryptSync, webcrypto } from "node:crypto";
import { execFileSync } from "node:child_process";
import { canonicalizeJson, generateKeyPair, createIdentity, createCommit } from "./index.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";
import { openAlethV2, sealAlethV2, recoverAlethV2, migrateAlethV1ToV2 } from "./aleth-container-v2.ts";

const dir=await mkdtemp(join(tmpdir(),"aleth-v2-writer-"));
const vector=JSON.parse(await readFile(new URL("../conformance/container_v2/golden.vector",import.meta.url),"utf8"));
const golden=join(dir,"golden.aleth");
await writeFile(golden,Buffer.from(vector.container_base64url,"base64url"));
const {payload}=await openAlethV2(golden,{passphrase:vector.passphrase});
const encode=(v:unknown)=>Buffer.from(typeof v==="string"?v:JSON.stringify(v)).toString("base64url");

// Deliberately bypass the production writer to create authenticated invalid sources.
async function unsafeContainer(p:unknown,path:string,v1=false,extraRecovery=false){
  const dek=randomBytes(32),salt=randomBytes(16),nonce=randomBytes(12);
  const kek=scryptSync(vector.passphrase,salt,32,{N:32768,r:8,p:1,maxmem:64*1024*1024});
  const cid=randomBytes(16).toString("base64url");
  const encrypt=async(key:Uint8Array,iv:Uint8Array,aad:Uint8Array,data:Uint8Array)=>Buffer.from(await webcrypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:aad,tagLength:128},await webcrypto.subtle.importKey("raw",key,"AES-GCM",false,["encrypt"]),data));
  const header:any=v1?{cipher:"AES-256-GCM",format:"aleth",kdf:"scrypt",nonce:nonce.toString("base64url"),salt:salt.toString("base64url"),scrypt_n:32768,scrypt_p:1,scrypt_r:8,version:1}:{container_id:cid,format:"aleth",payload_cipher:"AES-256-GCM",payload_nonce:nonce.toString("base64url"),slots:[],version:2};
  if(!v1){
    let slotIndex=0;
    for(const recovery of [false,true,...(extraRecovery?[true]:[])]){
      ++slotIndex;
      const slotNonce=randomBytes(12),slotSalt=recovery?randomBytes(16):salt;
      const id=recovery?`recovery-${slotIndex-1}`:"passphrase-1",type=recovery?"recovery-secret":"passphrase";
      const secret=slotIndex===3?randomBytes(32):Buffer.from(vector.recovery_code.split(":")[1],"base64url");
      const slotKey=recovery?new Uint8Array(await webcrypto.subtle.deriveBits({name:"HKDF",hash:"SHA-256",salt:slotSalt,info:Buffer.from("alethech-container-recovery-v1")},await webcrypto.subtle.importKey("raw",secret,"HKDF",false,["deriveBits"]),256)):kek;
      const wrapped=await encrypt(slotKey,slotNonce,Buffer.from(canonicalizeJson({container_id:cid,envelope_version:2,slot_id:id,slot_type:type})),dek);
      header.slots.push({id,type,kdf:recovery?"HKDF-SHA256":"scrypt",nonce:slotNonce.toString("base64url"),salt:slotSalt.toString("base64url"),wrapped_key:wrapped.toString("base64url"),...(!recovery?{scrypt_n:32768,scrypt_p:1,scrypt_r:8}:{})});
    }
  }
  const hb=Buffer.from(canonicalizeJson(header)),len=Buffer.alloc(4);len.writeUInt32BE(hb.length);
  await writeFile(path,Buffer.concat([Buffer.from(v1?"ALETH001":"ALETH002"),len,hb,await encrypt(v1?kek:dek,nonce,hb,Buffer.from(canonicalizeJson(p)))]));
}

try{
  const out=join(dir,"out.aleth"),sentinel=Buffer.from("previous destination");
  await writeFile(out,sentinel);
  const badHead=structuredClone(payload);badHead.files.HEAD=encode("sha256:missing\n");
  await assert.rejects(sealAlethV2(badHead,out,"new-pass"),/HEAD/);
  assert.deepEqual(await readFile(out),sentinel);
  await assert.rejects(openAlethV2(golden,{passphrase:vector.passphrase,recovery_code:vector.recovery_code} as any),/exactly one/);
  await assert.rejects(openAlethV2(golden,{} as any),/exactly one/);
  const leaked=structuredClone(payload);leaked.files["keys/root.key"]=encode("secret");
  await assert.rejects(sealAlethV2(leaked,out,"new-pass"),/forbidden authority/);
  const badEncoding=structuredClone(payload);badEncoding.files.HEAD="a=";
  await assert.rejects(sealAlethV2(badEncoding,out,"new-pass"),/encoding/);
  const oversized=structuredClone(payload);for(let i=0;i<100001;i++)oversized.files[`artifacts/${i}`]="";
  await assert.rejects(sealAlethV2(oversized,out,"new-pass"),/too many files/);
  for(const malformed of [{...payload,extra:true},{payload_version:1,files:[]},{payload_version:1,files:{HEAD:42}}]){
    await unsafeContainer(malformed,join(dir,"malformed.aleth"));
    await assert.rejects(openAlethV2(join(dir,"malformed.aleth"),{passphrase:vector.passphrase}),/payload/);
    await assert.rejects(sealAlethV2(malformed as any,out,"new-pass"),/payload/);
  }
  await unsafeContainer(badHead,join(dir,"bad-v2.aleth"));
  await assert.rejects(recoverAlethV2(join(dir,"bad-v2.aleth"),out,vector.recovery_code,"new-pass"),/HEAD/);
  await unsafeContainer(badHead,join(dir,"bad-v1.aleth"),true);
  await assert.rejects(migrateAlethV1ToV2(join(dir,"bad-v1.aleth"),out,vector.passphrase,"new-pass"),/HEAD/);
  assert.deepEqual(await readFile(out),sentinel);
  const failures:string[]=[];
  async function rejected(action:Promise<unknown>,label:string){
    try{await assert.rejects(action);}catch{failures.push(label);}
  }
  const kp=await generateKeyPair(),identity=await createIdentity(kp,"utf8-key");
  const signed=await createCommit(identity.agent_id,identity.key_id,[],{text:"\ufffd"},kp);
  const signedPath=`commits/${signed.commit_id}.json`;
  const utf8Payload={payload_version:1,files:{HEAD:encode(signed.commit_id),[`identities/${identity.agent_id}.json`]:encode(identity),[signedPath]:encode(signed)}};
  await verifyPortablePayload(utf8Payload);
  const invalidUtf8=structuredClone(utf8Payload),recordBytes=Buffer.from(JSON.stringify(signed));
  const replacement=recordBytes.indexOf(Buffer.from("\ufffd"));assert.notEqual(replacement,-1);
  invalidUtf8.files[signedPath]=Buffer.concat([recordBytes.subarray(0,replacement),Buffer.from([0xff]),recordBytes.subarray(replacement+3)]).toString("base64url");
  await rejected(verifyPortablePayload(invalidUtf8),"signed malformed UTF-8 accepted through replacement decoding");
  await unsafeContainer(payload,join(dir,"multi-recovery.aleth"),false,true);
  await rejected(recoverAlethV2(join(dir,"multi-recovery.aleth"),out,vector.recovery_code,"new-pass"),"extra recovery credential silently dropped");
  await unsafeContainer(payload,join(dir,"same-v1.aleth"),true);
  const sourceBefore=await readFile(join(dir,"same-v1.aleth"));
  await rejected(migrateAlethV1ToV2(join(dir,"same-v1.aleth"),join(dir,".","same-v1.aleth"),vector.passphrase,"new-pass"),"migration source replaced without permission");
  if(!failures.length)assert.deepEqual(await readFile(join(dir,"same-v1.aleth")),sourceBefore);
  assert.deepEqual(failures,[]);
  const sourcePath=join(dir,"same-v1.aleth");
  const symlinkPath=join(dir,"symlink-v1.aleth"),hardlinkPath=join(dir,"hardlink-v1.aleth");
  await symlink("same-v1.aleth",symlinkPath);await link(sourcePath,hardlinkPath);
  for(const alias of [symlinkPath,hardlinkPath]){
    await assert.rejects(migrateAlethV1ToV2(sourcePath,alias,vector.passphrase,"new-pass"),/replaceSource/);
    assert.deepEqual(await readFile(alias),sourceBefore);
  }
  await migrateAlethV1ToV2(join(dir,"same-v1.aleth"),join(dir,"same-v1.aleth"),vector.passphrase,"new-pass",{replaceSource:true});
  assert.deepEqual((await openAlethV2(join(dir,"same-v1.aleth"),{passphrase:"new-pass"})).payload,payload);
  const secret=Buffer.from(vector.recovery_code.split(":")[1],"base64url");
  const sealed=await sealAlethV2(payload,out,"new-pass",{recoverySecret:secret});
  assert.deepEqual((await openAlethV2(out,{passphrase:"new-pass"})).payload,payload);
  assert.equal((await stat(out)).mode & 0o777,0o600);
  const recovered=await recoverAlethV2(out,out,sealed.recoveryCode!,"next-pass",{rotateRecovery:true});
  assert.equal(recovered.containerId,sealed.containerId);assert.notEqual(recovered.recoveryCode,sealed.recoveryCode);
  await assert.rejects(openAlethV2(out,{recovery_code:sealed.recoveryCode!}));
  assert.deepEqual((await openAlethV2(out,{recovery_code:recovered.recoveryCode})).payload,payload);
  await unsafeContainer(payload,join(dir,"valid-v1.aleth"),true);
  await migrateAlethV1ToV2(join(dir,"valid-v1.aleth"),out,vector.passphrase,"migrated-pass");
  assert.deepEqual((await openAlethV2(out,{passphrase:"migrated-pass"})).payload,payload);
  await assert.rejects(sealAlethV2(payload,dir,"new-pass"));
  assert.equal((await readdir(dir)).filter(n=>n.includes(".tmp")).length,0);
  const payloadPath=join(dir,"payload.json");await writeFile(payloadPath,JSON.stringify(payload));
  const cli=(...args:string[])=>JSON.parse(execFileSync(process.execPath,["--experimental-strip-types",new URL("./aleth-container-v2.ts",import.meta.url).pathname,...args],{encoding:"utf8"}));
  for(const arg of [secret.toString("base64url"),vector.recovery_code]){
    const result=cli("seal",payloadPath,out,"cli-pass",arg);assert.equal(result.recoveryCode,vector.recovery_code);
  }
  const cliRecovery=cli("recover",out,out,vector.recovery_code,"cli-next","--rotate-recovery");
  assert.notEqual(cliRecovery.recoveryCode,vector.recovery_code);
  const cliV1=join(dir,"cli-v1.aleth");await unsafeContainer(payload,cliV1,true);
  cli("migrate",cliV1,cliV1,vector.passphrase,"cli-migrated","--replace-source");
  assert.deepEqual((await openAlethV2(cliV1,{passphrase:"cli-migrated"})).payload,payload);
  console.log("ALETH002 writer tests passed (verification, schemas, atomic replacement, migration, recovery, CLI)");
}finally{await rm(dir,{recursive:true,force:true});}
