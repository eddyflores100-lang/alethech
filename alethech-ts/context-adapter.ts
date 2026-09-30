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

/**
 * Convert a cryptographically verified portable view into a backend-neutral
 * context object. This adapter deliberately carries no private keys and no
 * protocol internals; consumers receive only verified memory content plus
 * provenance and a source HEAD they can retain for audit/debugging.
 */
export function toAlethechContext(
  view: VerifiedPortableView,
  options: { limit?: number } = {},
): AlethechContext {
  const limit = options.limit ?? view.entries.length;
  if (!Number.isInteger(limit) || limit < 0) throw new Error("limit must be a non-negative integer");
  const selected = limit === 0 ? [] : view.entries.slice(-limit);
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
export function toContextText(view: VerifiedPortableView, options: { limit?: number } = {}): string {
  const context = toAlethechContext(view, options);
  return JSON.stringify(context);
}
