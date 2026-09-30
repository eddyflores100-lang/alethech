import { openAleth, sealAlethPayload } from "./aleth-container.ts";
import { appendPortableMemory } from "./portable-editor.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

async function main(): Promise<void> {
  const [input, output, passphrase] = process.argv.slice(2);
  if (!input || !output || !passphrase) {
    throw new Error("usage: portable-editor-test.ts <in.aleth> <out.aleth> <passphrase>");
  }

  const opened = await openAleth(input, passphrase);
  const before = await verifyPortablePayload(opened.payload);
  const { payload, commit } = await appendPortableMemory(
    opened.payload,
    { browser_continuation: "works" },
    { source: "browser_extension_test", session_id: "browser-continuation-test" },
  );
  const after = await verifyPortablePayload(payload);

  if (after.entries.length !== before.entries.length + 1) {
    throw new Error("append did not add exactly one verified memory");
  }
  if (after.head !== commit.commit_id) {
    throw new Error("append did not advance HEAD");
  }
  if ((after.entries.at(-1)?.content as any)?.browser_continuation !== "works") {
    throw new Error("new memory content missing after verification");
  }

  await sealAlethPayload(payload, output, passphrase);
  process.stdout.write(JSON.stringify({
    old_head: before.head,
    new_head: after.head,
    entries_before: before.entries.length,
    entries_after: after.entries.length,
  }));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
