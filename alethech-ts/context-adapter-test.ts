import { openAleth } from "./aleth-container.ts";
import { toAlethechContext, toContextText } from "./context-adapter.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) {
    throw new Error("usage: context-adapter-test.ts <file.aleth> <passphrase>");
  }

  const opened = await openAleth(path, passphrase);
  const view = await verifyPortablePayload(opened.payload);
  const context = toAlethechContext(view, { limit: 20 });
  const text = toContextText(view, { limit: 20 });

  if (context.format !== "alethech-context" || context.version !== 1) {
    throw new Error("unexpected context envelope");
  }
  if (context.source_head !== view.head) {
    throw new Error("context source_head mismatch");
  }
  if (context.items.length !== Math.min(20, view.entries.length)) {
    throw new Error("context item count mismatch");
  }

  const forbidden = ["PRIVATE KEY", "signing.key", "root.key", "recovery.key"];
  for (const needle of forbidden) {
    if (text.includes(needle)) throw new Error(`context leaked forbidden material: ${needle}`);
  }

  process.stdout.write(text);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
