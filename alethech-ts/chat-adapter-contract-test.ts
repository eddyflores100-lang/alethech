import { openAleth } from "./aleth-container.ts";
import { toAlethechContext } from "./context-adapter.ts";
import {
  assertWritebackCurrent,
  createChatEnvelope,
  createWritebackProposal,
  validateChatEnvelope,
  validateWritebackProposal,
} from "./chat-adapter-contract.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) {
    throw new Error("usage: chat-adapter-contract-test.ts <file.aleth> <passphrase>");
  }

  const opened = await openAleth(path, passphrase);
  const view = await verifyPortablePayload(opened.payload);
  const context = toAlethechContext(view, { limit: 20 });
  const envelope = createChatEnvelope(context);
  validateChatEnvelope(envelope);

  if (envelope.source_head !== view.head) throw new Error("chat envelope lost source HEAD");

  const proposal = createWritebackProposal(view.head, [{
    memory_type: "semantic",
    content: { provider_summary: "candidate memory" },
    source: "test_provider",
    confidence: 0.9,
  }]);
  validateWritebackProposal(proposal);
  assertWritebackCurrent(proposal, view.head);

  let staleRejected = false;
  try {
    assertWritebackCurrent(proposal, "sha256:" + "0".repeat(64));
  } catch {
    staleRejected = true;
  }
  if (!staleRejected) throw new Error("stale writeback proposal was accepted");

  const serialized = JSON.stringify({ envelope, proposal });
  for (const forbidden of ["PRIVATE KEY", "signing.key", "root.key", "recovery.key"]) {
    if (serialized.includes(forbidden)) throw new Error(`adapter leaked forbidden material: ${forbidden}`);
  }

  process.stdout.write(JSON.stringify({
    format: envelope.format,
    source_head: envelope.source_head,
    context_items: envelope.context.items.length,
    writeback_items: proposal.items.length,
    stale_rejected: staleRejected,
  }));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
