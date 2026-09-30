import {
  bytesToBase64Url, canonicalizeJson, createCommit, createIdentity,
  generateKeyPair,
} from "./index.ts";
import { appendPortableMemory } from "./portable-editor.ts";
import { verifyPortablePayload, type PortablePayload } from "./portable-verifier.ts";

const encoder = new TextEncoder();
// A 2 MiB transcript can also occur in the reviewed text and message records;
// leave room for both representations and JSON escaping in the signed snapshot.
export const MAX_CAPTURE_CONTENT_BYTES = 8 * 1024 * 1024;

export interface CreatePortableMemoryOptions {
  memory_type?: "semantic" | "episodic" | "procedural";
  session_id?: string;
}

// Snapshot before the first await: caller mutation must never change the capture.
// Reject values JSON.stringify would silently omit, coerce, or invoke via toJSON.
function snapshotContent(content: Record<string, unknown>): Record<string, unknown> {
  const seen = new Set<object>();
  let nodes = 0;
  function walk(value: unknown, depth: number): unknown {
    if (++nodes > 100000 || depth > 64) throw new Error("capture content is too complex");
    if (value === null || typeof value === "boolean") return value;
    if (typeof value === "string") {
      if (!value.isWellFormed()) throw new Error("capture content contains invalid Unicode");
      return value;
    }
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value !== "object" || !value) throw new Error("capture content must contain only JSON values");
    if (seen.has(value)) throw new Error("capture content must not contain cycles");
    const proto = Object.getPrototypeOf(value);
    if (!Array.isArray(value) && proto !== Object.prototype && proto !== null) {
      throw new Error("capture content must contain plain JSON objects");
    }
    if (Object.getOwnPropertySymbols(value).length) throw new Error("capture content must contain only JSON properties");
    seen.add(value);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    let result: unknown;
    if (Array.isArray(value)) {
      if (Object.keys(value).length !== value.length) throw new Error("capture arrays must be dense JSON arrays");
      result = Array.from({length:value.length}, (_, i) => {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !("value" in descriptor)) throw new Error("capture content must not contain accessors");
        return walk(descriptor.value, depth + 1);
      });
    } else {
      const copy = Object.create(null) as Record<string, unknown>;
      for (const key of Object.keys(value)) {
        if (!key.isWellFormed()) throw new Error("capture content contains invalid Unicode");
        const descriptor = descriptors[key];
        if (!("value" in descriptor)) throw new Error("capture content must not contain accessors");
        copy[key] = walk(descriptor.value, depth + 1);
      }
      result = copy;
    }
    seen.delete(value);
    return result;
  }
  if (!content || typeof content !== "object" || Array.isArray(content) || !Object.keys(content).length) {
    throw new Error("capture content must be a nonempty JSON object");
  }
  const snapshot = walk(content, 0) as Record<string, unknown>;
  const serialized = canonicalizeJson(snapshot);
  if (encoder.encode(serialized).length > MAX_CAPTURE_CONTENT_BYTES) throw new Error("capture content is too large");
  // The verifier treats this reserved exact object as the genesis marker.
  if (serialized === '{"type":"genesis"}') throw new Error("capture content cannot be a genesis marker");
  return snapshot;
}

function encodeFile(value: unknown): string {
  return bytesToBase64Url(encoder.encode(canonicalizeJson(value)));
}

/**
 * Create a standalone writable portable memory entirely with browser WebCrypto.
 * Signatures attest this user's accepted capture, not the chat provider's origin.
 * The payload contains an operational signing key; encrypt it before persistence.
 * Legacy Identity self-verification binds its DID to its public JWK. The signed
 * genesis binds that identity to the memory; no root/recovery keys are generated.
 */
export async function createPortableMemory(
  content: Record<string, unknown>,
  options: CreatePortableMemoryOptions = {},
): Promise<PortablePayload> {
  const snapshot = snapshotContent(content);
  const memoryType = options.memory_type ?? "episodic";
  if (!["semantic", "episodic", "procedural"].includes(memoryType)) throw new Error("unsupported memory_type");
  const sessionId = options.session_id ?? crypto.randomUUID();
  if (typeof sessionId !== "string" || !sessionId || sessionId.length > 256 || !sessionId.isWellFormed()) {
    throw new Error("session_id must be a nonempty string of at most 256 characters");
  }
  const kp = await generateKeyPair();
  const identity = await createIdentity(kp, "key-001");
  const genesis = await createCommit(identity.agent_id, identity.key_id, [], {type:"genesis"}, kp);
  const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const base64 = bytesToBase64Url(privateBytes).replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const pem = `-----BEGIN PRIVATE KEY-----\n${padded.match(/.{1,64}/g)!.join("\n")}\n-----END PRIVATE KEY-----\n`;
  privateBytes.fill(0);
  const payload: PortablePayload = {payload_version:1, files:{
    [`identities/${identity.agent_id}.json`]:encodeFile(identity),
    [`commits/${genesis.commit_id}.json`]:encodeFile(genesis),
    "keys/signing.key":bytesToBase64Url(encoder.encode(pem)),
    HEAD:bytesToBase64Url(encoder.encode(genesis.commit_id + "\n")),
  }};
  const appended = await appendPortableMemory(payload, snapshot, {
    memory_type:memoryType, session_id:sessionId, source:"user_accepted_chat_capture",
  });
  await verifyPortablePayload(appended.payload);
  return appended.payload;
}
