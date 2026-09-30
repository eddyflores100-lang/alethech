import { openAleth } from "./aleth-container.ts";
import { bytesToBase64Url } from "./index.ts";
import { verifyPortableLegacyPayload, type PortablePayload } from "./portable-verifier.ts";
import { toAlethechContext } from "./context-adapter.ts";

async function mustReject(payload: PortablePayload, label: string): Promise<void> {
  try {
    await verifyPortableLegacyPayload(payload);
  } catch {
    return;
  }
  throw new Error(`mutation was accepted: ${label}`);
}

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) throw new Error("usage: portable-verifier-test.ts <file.aleth> <passphrase>");

  const opened=await openAleth(path,passphrase);
  const view=await verifyPortableLegacyPayload(opened.payload);
  if(view.entries.length!==1) throw new Error(`expected 1 memory entry, got ${view.entries.length}`);
  if(typeof (view.entries[0].content as any).interop!=="string") throw new Error("unexpected memory content");

  const tampered=structuredClone(opened.payload);
  const commitPath=Object.keys(tampered.files)
    .filter(p=>p.startsWith("commits/"))
    .find(p=>{
      const obj=JSON.parse(new TextDecoder().decode(Buffer.from(tampered.files[p],"base64url")));
      return obj.content?.type!=="genesis";
    });
  if(!commitPath) throw new Error("non-genesis commit missing");
  const commit=JSON.parse(new TextDecoder().decode(Buffer.from(tampered.files[commitPath],"base64url")));
  commit.content={tampered:true};
  tampered.files[commitPath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(commit)));
  await mustReject(tampered,"tampered commit content");

  const badHead=structuredClone(opened.payload);
  badHead.files.HEAD=bytesToBase64Url(new TextEncoder().encode("sha256:not-real\n"));
  await mustReject(badHead,"invalid HEAD");

  const evidencePath=Object.keys(opened.payload.files).find(p=>p.startsWith("evidence/"));
  if(!evidencePath) throw new Error("expected evidence fixture in portable payload");

  const tamperedEvidence=structuredClone(opened.payload);
  const ev=JSON.parse(new TextDecoder().decode(Buffer.from(tamperedEvidence.files[evidencePath],"base64url")));
  ev.tool="tampered.tool";
  tamperedEvidence.files[evidencePath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(ev)));
  await mustReject(tamperedEvidence,"tampered evidence content");

  const missingEvidence=structuredClone(opened.payload);
  delete missingEvidence.files[evidencePath];
  await mustReject(missingEvidence,"missing evidence reference");

  const authorityLeak=structuredClone(opened.payload);
  authorityLeak.files["keys/root.key"]=bytesToBase64Url(new Uint8Array([1,2,3]));
  await mustReject(authorityLeak,"root authority key leak");

  const wrongSigningKey=structuredClone(opened.payload);
  wrongSigningKey.files["keys/signing.key"]=bytesToBase64Url(
    new TextEncoder().encode("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
  );
  await mustReject(wrongSigningKey,"mismatched signing key");

  const badArtifact=structuredClone(opened.payload);
  const artifactPath=Object.keys(badArtifact.files).find(p=>p.startsWith("artifacts/"));
  if(!artifactPath) throw new Error("expected artifact fixture in portable payload");
  badArtifact.files[artifactPath]=bytesToBase64Url(new TextEncoder().encode("tampered artifact bytes"));
  await mustReject(badArtifact,"artifact hash mismatch");

  const context=toAlethechContext(view);
  const contextText=JSON.stringify(context);
  if(context.source_head!==view.head || context.items.length!==view.entries.length) {
    throw new Error("context adapter lost verified memory data");
  }
  if(contextText.includes("PRIVATE KEY") || contextText.includes("signing.key") || contextText.includes("root.key")) {
    throw new Error("context leaked private key material");
  }

  process.stdout.write(JSON.stringify(view));
}

main().catch(e=>{console.error(e instanceof Error?e.message:String(e));process.exit(1);});
