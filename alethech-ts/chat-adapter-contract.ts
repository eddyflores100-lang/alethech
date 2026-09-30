import type { AlethechContext, AlethechContextItem } from "./context-adapter.ts";

export interface AlethechChatEnvelope {
  format: "alethech-chat-envelope";
  version: 1;
  source_head: string;
  context: AlethechContext;
}

export interface AlethechWritebackItem {
  memory_type: "semantic" | "episodic" | "procedural";
  content: Record<string, unknown>;
  source?: string;
  confidence?: number;
}

export interface AlethechWritebackProposal {
  format: "alethech-writeback-proposal";
  version: 1;
  source_head: string;
  items: AlethechWritebackItem[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isSha256Id(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value);
}

function validateContextItem(item: unknown): asserts item is AlethechContextItem {
  if (!isRecord(item)) throw new Error("invalid context item");
  if (!isSha256Id(item.id)) throw new Error("invalid context item id");
  if (!["semantic","episodic","procedural"].includes(String(item.memory_type))) {
    throw new Error("invalid context memory_type");
  }
  if (typeof item.timestamp !== "string" || !item.timestamp) throw new Error("invalid context timestamp");
  if (!isRecord(item.content)) throw new Error("invalid context content");
  if (!isRecord(item.provenance)) throw new Error("invalid context provenance");
}

export function validateAlethechContext(value: unknown): asserts value is AlethechContext {
  if (!isRecord(value)) throw new Error("invalid alethech-context");
  if (value.format !== "alethech-context" || value.version !== 1) {
    throw new Error("unsupported alethech-context");
  }
  if (!isSha256Id(value.source_head)) throw new Error("invalid context source_head");
  if (!Array.isArray(value.items)) throw new Error("invalid context items");
  if (value.items.length > 10_000) throw new Error("context item limit exceeded");
  for (const item of value.items) validateContextItem(item);
}

export function createChatEnvelope(context: AlethechContext): AlethechChatEnvelope {
  validateAlethechContext(context);
  return {
    format: "alethech-chat-envelope",
    version: 1,
    source_head: context.source_head,
    context: structuredClone(context),
  };
}

export function validateChatEnvelope(value: unknown): asserts value is AlethechChatEnvelope {
  if (!isRecord(value)) throw new Error("invalid chat envelope");
  if (value.format !== "alethech-chat-envelope" || value.version !== 1) {
    throw new Error("unsupported chat envelope");
  }
  if (!isSha256Id(value.source_head)) throw new Error("invalid envelope source_head");
  validateAlethechContext(value.context);
  if (value.source_head !== value.context.source_head) {
    throw new Error("chat envelope source_head mismatch");
  }
}

export function createWritebackProposal(
  sourceHead: string,
  items: AlethechWritebackItem[],
): AlethechWritebackProposal {
  if (!isSha256Id(sourceHead)) throw new Error("invalid writeback source_head");
  if (!Array.isArray(items) || items.length === 0) throw new Error("writeback requires at least one item");
  if (items.length > 100) throw new Error("writeback item limit exceeded");

  const normalized = items.map((item) => {
    if (!isRecord(item) || !isRecord(item.content)) throw new Error("invalid writeback item");
    if (!["semantic","episodic","procedural"].includes(item.memory_type)) {
      throw new Error("invalid writeback memory_type");
    }
    const confidence = item.confidence ?? 1.0;
    if (typeof confidence !== "number" || confidence < 0 || confidence > 1) {
      throw new Error("invalid writeback confidence");
    }
    return {
      memory_type: item.memory_type,
      content: structuredClone(item.content),
      source: item.source ?? "provider_proposal",
      confidence,
    };
  });

  return {
    format: "alethech-writeback-proposal",
    version: 1,
    source_head: sourceHead,
    items: normalized,
  };
}

export function validateWritebackProposal(value: unknown): asserts value is AlethechWritebackProposal {
  if (!isRecord(value)) throw new Error("invalid writeback proposal");
  if (value.format !== "alethech-writeback-proposal" || value.version !== 1) {
    throw new Error("unsupported writeback proposal");
  }
  if (!isSha256Id(value.source_head)) throw new Error("invalid writeback source_head");
  if (!Array.isArray(value.items) || value.items.length === 0 || value.items.length > 100) {
    throw new Error("invalid writeback items");
  }
  for (const item of value.items) {
    if (!isRecord(item) || !isRecord(item.content)) throw new Error("invalid writeback item");
    if (!["semantic","episodic","procedural"].includes(String(item.memory_type))) {
      throw new Error("invalid writeback memory_type");
    }
    if (item.source !== undefined && typeof item.source !== "string") {
      throw new Error("invalid writeback source");
    }
    if (
      item.confidence !== undefined &&
      (typeof item.confidence !== "number" || item.confidence < 0 || item.confidence > 1)
    ) {
      throw new Error("invalid writeback confidence");
    }
  }
}

/**
 * A provider proposal is intentionally unsigned and untrusted. Before local
 * acceptance, the proposal must still refer to the currently verified HEAD.
 * This prevents silently applying a stale response to a history that advanced
 * while the provider was generating its answer.
 */
export function assertWritebackCurrent(
  proposal: AlethechWritebackProposal,
  currentHead: string,
): void {
  validateWritebackProposal(proposal);
  if (proposal.source_head !== currentHead) {
    throw new Error("stale writeback proposal: source_head no longer current");
  }
}
