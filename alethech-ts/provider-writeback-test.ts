import { openAleth } from "./aleth-container.ts";
import { createWritebackProposal } from "./chat-adapter-contract.ts";
import { acceptWritebackProposal } from "./provider-writeback.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

async function main(): Promise<void> {
  const [path, passphrase] = process.argv.slice(2);
  if (!path || !passphrase) {
    throw new Error("usage: provider-writeback-test.ts <file.aleth> <passphrase>");
  }

  const opened = await openAleth(path, passphrase);
  const before = await verifyPortablePayload(opened.payload);

  const proposal = createWritebackProposal(before.head, [
    {
      memory_type: "semantic",
      content: { remembered_fact: "alpha" },
      source: "test_provider",
      confidence: 0.95,
    },
    {
      memory_type: "episodic",
      content: { remembered_event: "beta" },
      source: "test_provider",
      confidence: 0.8,
    },
  ]);

  const accepted = await acceptWritebackProposal(opened.payload, proposal);
  if (accepted.commits.length !== 2) throw new Error("expected two local commits");
  if (accepted.view.entries.length !== before.entries.length + 2) {
    throw new Error("writeback did not add exactly two memories");
  }
  if (accepted.commits[0].parents[0] !== before.head) {
    throw new Error("first writeback commit not anchored to source HEAD");
  }
  if (accepted.commits[1].parents[0] !== accepted.commits[0].commit_id) {
    throw new Error("second writeback commit not chained to first");
  }

  let staleRejected = false;
  const stale = createWritebackProposal("sha256:" + "0".repeat(64), [{
    memory_type: "semantic",
    content: { stale: true },
  }]);
  try {
    await acceptWritebackProposal(opened.payload, stale);
  } catch {
    staleRejected = true;
  }
  if (!staleRejected) throw new Error("stale provider writeback was accepted");

  process.stdout.write(JSON.stringify({
    before_head: before.head,
    after_head: accepted.view.head,
    commits_added: accepted.commits.length,
    entries_before: before.entries.length,
    entries_after: accepted.view.entries.length,
    stale_rejected: staleRejected,
  }));
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
