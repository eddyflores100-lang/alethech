import { openAleth } from "./aleth-container.ts";
import { createChatEnvelope } from "./chat-adapter-contract.ts";
import { toAlethechContext } from "./context-adapter.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

async function main():Promise<void>{
  const [path,passphrase]=process.argv.slice(2);
  if(!path||!passphrase) throw new Error("usage: chat-envelope-dump.ts <file.aleth> <passphrase>");
  const opened=await openAleth(path,passphrase);
  const view=await verifyPortablePayload(opened.payload);
  const envelope=createChatEnvelope(toAlethechContext(view));
  process.stdout.write(JSON.stringify(envelope));
}
main().catch((e)=>{
  console.error(e instanceof Error?e.message:String(e));
  process.exit(1);
});
