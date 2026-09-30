import type { VerifiedPortableView } from "./portable-verifier.ts";

export interface AlethechContextItem {
  id: string;
  memory_type: string;
  timestamp: string;
  content: Record<string, unknown>;
  provenance: Record<string, unknown>;
}

export interface AlethechContext {
  format: "alethech-context";
  version: 1;
  source_head: string;
  items: AlethechContextItem[];
}

export interface ContextSelectionOptions {
  limit?: number;
  include_ids?: string[];
  memory_types?: Array<"semantic" | "episodic" | "procedural">;
}

/**
 * Convert a cryptographically verified portable view into a backend-neutral
 * context object. This adapter deliberately carries no private keys and no
 * protocol internals; consumers receive only verified memory content plus
 * provenance and a source HEAD they can retain for audit/debugging.
 */
export function toAlethechContext(
  view: VerifiedPortableView,
  options: ContextSelectionOptions = {},
): AlethechContext {
  const limit = options.limit ?? view.entries.length;
  if (!Number.isInteger(limit) || limit < 0) throw new Error("limit must be a non-negative integer");

  let selected = [...view.entries];

  if (options.memory_types !== undefined) {
    if (!Array.isArray(options.memory_types) || options.memory_types.length === 0) {
      throw new Error("memory_types must be a non-empty array when provided");
    }
    const allowed = new Set(["semantic", "episodic", "procedural"]);
    for (const value of options.memory_types) {
      if (!allowed.has(value)) throw new Error("invalid memory_type selection");
    }
    const selectedTypes = new Set(options.memory_types);
    selected = selected.filter((entry) => selectedTypes.has(entry.memory_type as any));
  }

  if (options.include_ids !== undefined) {
    if (!Array.isArray(options.include_ids)) throw new Error("include_ids must be an array");
    const unique = new Set(options.include_ids);
    if (unique.size !== options.include_ids.length) throw new Error("duplicate include_ids");
    const known = new Set(view.entries.map((entry) => entry.commit_id));
    for (const id of unique) {
      if (!known.has(id)) throw new Error(`unknown selected memory id: ${id}`);
    }
    selected = selected.filter((entry) => unique.has(entry.commit_id));
  }

  selected = limit === 0 ? [] : selected.slice(-limit);
  return {
    format: "alethech-context",
    version: 1,
    source_head: view.head,
    items: selected.map((entry) => ({
      id: entry.commit_id,
      memory_type: entry.memory_type,
      timestamp: entry.timestamp,
      content: entry.content,
      provenance: entry.provenance,
    })),
  };
}

/**
 * Portable text form for chat adapters that only accept text context.
 * It is intentionally generated from an already verified view.
 */
export function toContextText(view: VerifiedPortableView, options: ContextSelectionOptions = {}): string {
  const context = toAlethechContext(view, options);
  return JSON.stringify(context);
}
