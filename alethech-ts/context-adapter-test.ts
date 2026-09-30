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

  // granular selection: exact IDs, preserved order, and fail-closed unknown IDs.
  if (view.entries.length > 0) {
    const chosen = view.entries.slice(-1).map((entry) => entry.commit_id);
    const selected = toAlethechContext(view, { include_ids: chosen });
    if (selected.items.length !== 1 || selected.items[0].id !== chosen[0]) {
      throw new Error("granular selection did not preserve exact selected commit");
    }

    let unknownRejected = false;
    try {
      toAlethechContext(view, { include_ids: ["sha256:" + "0".repeat(64)] });
    } catch {
      unknownRejected = true;
    }
    if (!unknownRejected) throw new Error("unknown selected memory id was accepted");

    const typed = toAlethechContext(view, {
      memory_types: [view.entries[0].memory_type as "semantic" | "episodic" | "procedural"],
    });
    if (typed.items.some((item) => item.memory_type !== view.entries[0].memory_type)) {
      throw new Error("memory_type filter leaked a different memory type");
    }
  }
  for (const needle of forbidden) {
    if (text.includes(needle)) throw new Error(`context leaked forbidden material: ${needle}`);
  }

  process.stdout.write(text);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
