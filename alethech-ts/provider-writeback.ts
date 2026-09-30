import type { MemoryCommit } from "./index.ts";
import {
  assertWritebackCurrent,
  validateWritebackProposal,
  type AlethechWritebackProposal,
} from "./chat-adapter-contract.ts";
import {
  appendPortableMemory,
  type AppendMemoryResult,
} from "./portable-editor.ts";
import {
  verifyPortablePayload,
  type PortablePayload,
  type VerifiedPortableView,
} from "./portable-verifier.ts";

export interface AcceptedWriteback {
  payload: PortablePayload;
  commits: MemoryCommit[];
  view: VerifiedPortableView;
}

/**
 * Convert one untrusted provider proposal into locally signed Alethech memory.
 *
 * Trust boundary:
 * - proposal is schema-validated but not trusted;
 * - source_head must equal the current verified HEAD before any write;
 * - every MemoryCommit is created/signed by the local portable editor;
 * - the complete resulting payload is verified again before return.
 *
 * The caller is responsible for obtaining explicit user approval before calling
 * this function. Provider bridges must never auto-accept writeback.
 */
export async function acceptWritebackProposal(
  payload: PortablePayload,
  proposal: AlethechWritebackProposal,
): Promise<AcceptedWriteback> {
  validateWritebackProposal(proposal);

  const before = await verifyPortablePayload(payload);
  assertWritebackCurrent(proposal, before.head);

  let current = structuredClone(payload) as PortablePayload;
  const commits: MemoryCommit[] = [];

  for (const item of proposal.items) {
    const result: AppendMemoryResult = await appendPortableMemory(
      current,
      item.content,
      {
        memory_type: item.memory_type,
        source: item.source ?? "provider_proposal",
        confidence: item.confidence ?? 1.0,
      },
    );
    current = result.payload;
    commits.push(result.commit);
  }

  const after = await verifyPortablePayload(current);
  if (commits.length !== proposal.items.length) {
    throw new Error("writeback commit count mismatch");
  }
  if (commits.length === 0 || after.head !== commits[commits.length - 1].commit_id) {
    throw new Error("writeback did not advance verified HEAD");
  }

  // Ensure the proposal was appended as one linear local continuation.
  let expectedParent = before.head;
  for (const commit of commits) {
    if (commit.parents.length !== 1 || commit.parents[0] !== expectedParent) {
      throw new Error("writeback commit chain is not linear from source_head");
    }
    expectedParent = commit.commit_id;
  }

  return { payload: current, commits, view: after };
}
