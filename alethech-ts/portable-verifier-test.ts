import { openAleth } from "./aleth-container.ts";
import { bytesToBase64Url } from "./index.ts";
import { verifyPortablePayload, type PortablePayload } from "./portable-verifier.ts";
import { toAlethechContext } from "./context-adapter.ts";

async function mustReject(payload: PortablePayload, label: string): Promise<void> {
  try {
    await verifyPortablePayload(payload);
  } catch {
    return;
  }
  throw new Error(`mutation was accepted: ${label}`);
}

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) throw new Error("usage: portable-verifier-test.ts <file.aleth> <passphrase>");

  const opened=await openAleth(path,passphrase);
  const view=await verifyPortablePayload(opened.payload);
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

  if (typeof opened.payload.files["root_authority.json"] === "string") {
    const badRoot=structuredClone(opened.payload);
    const root=JSON.parse(new TextDecoder().decode(Buffer.from(badRoot.files["root_authority.json"],"base64url")));
    root.created_at="2099-01-01T00:00:00.000Z";
    badRoot.files["root_authority.json"]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(root)));
    await mustReject(badRoot,"tampered V2 root authority");

    const controlPath=Object.keys(opened.payload.files).find(p=>p.startsWith("control_events/"));
    if(!controlPath) throw new Error("V2 payload missing control event");
    const badControl=structuredClone(opened.payload);
    const control=JSON.parse(new TextDecoder().decode(Buffer.from(badControl.files[controlPath],"base64url")));
    control.sequence=control.sequence+7;
    badControl.files[controlPath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(control)));
    await mustReject(badControl,"tampered V2 control chain");

    const migrationPath=Object.keys(opened.payload.files).find(p=>p.startsWith("migrations/"));
    if(migrationPath){
      const badMigration=structuredClone(opened.payload);
      const migration=JSON.parse(new TextDecoder().decode(Buffer.from(badMigration.files[migrationPath],"base64url")));
      migration.migration_timestamp="2099-01-01T00:00:00.000Z";
      badMigration.files[migrationPath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(migration)));
      await mustReject(badMigration,"tampered bilateral MigrationRecord");
    }

    const checkpointPath=Object.keys(opened.payload.files).find(p=>p.startsWith("checkpoints/"));
    if(checkpointPath){
      const badCheckpoint=structuredClone(opened.payload);
      const checkpoint=JSON.parse(new TextDecoder().decode(Buffer.from(badCheckpoint.files[checkpointPath],"base64url")));
      checkpoint.head_commit_id="sha256:not-in-history";
      badCheckpoint.files[checkpointPath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(checkpoint)));
      await mustReject(badCheckpoint,"tampered signed checkpoint");

      const regressedCheckpoint=structuredClone(opened.payload);
      const checkpoint2=JSON.parse(new TextDecoder().decode(Buffer.from(regressedCheckpoint.files[checkpointPath],"base64url")));
      checkpoint2.commit_count=999999;
      regressedCheckpoint.files[checkpointPath]=bytesToBase64Url(new TextEncoder().encode(JSON.stringify(checkpoint2)));
      await mustReject(regressedCheckpoint,"checkpoint count regression");
    }
  }

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
