import { readFile } from "node:fs/promises";
import { openAleth } from "./aleth-container.ts";
import { verifyPortableLegacyPayload } from "./portable-verifier.ts";

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) throw new Error("usage: portable-verifier-test.ts <file.aleth> <passphrase>");
  await readFile(path); // explicit existence check
  const opened=await openAleth(path,passphrase);
  const view=await verifyPortableLegacyPayload(opened.payload);
  if(view.entries.length!==1) throw new Error(`expected 1 memory entry, got ${view.entries.length}`);
  if((view.entries[0].content as any).interop!=="browser-verifier") throw new Error("unexpected memory content");
  process.stdout.write(JSON.stringify(view));
}

main().catch(e=>{console.error(e instanceof Error?e.message:String(e));process.exit(1);});
