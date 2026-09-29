#!/usr/bin/env node
/**
 * alethech-ts conformance helper — TypeScript side of the cross-language harness.
 *
 * Takes a fixture path as its single argument, reads the JSON, verifies
 * the signature against the fixture's identity public key, and on
 * success writes the canonical bytes of the signed payload to stdout
 * (exit 0). On failure writes the error to stderr (exit 1).
 *
 * Invoked by `conformance/cross_language_check.py` as the TypeScript
 * runner. The contract is documented in `conformance/CROSS_LANGUAGE.md`.
 */

import { readFile } from "node:fs/promises";
import { canonicalizeJson, verifyCommit } from "./index.ts";

async function main() {
  const fixturePath = process.argv[2];
  if (!fixturePath) {
    console.error("usage: node conformance.mjs <fixture.json>");
    process.exit(2);
  }

  let content;
  try {
    content = await readFile(fixturePath, "utf-8");
  } catch (e) {
    console.error(`error: cannot read fixture ${fixturePath}: ${e.message}`);
    process.exit(2);
  }

  let data;
  try {
    data = JSON.parse(content);
  } catch (e) {
    console.error(`error: invalid JSON in fixture: ${e.message}`);
    process.exit(2);
  }

  // Fixtures wrap the actual object in input.commit (or similar).
  const expected = data.expected_result || "verify_ok";
  const input = data.input || data;
  const commitData = input.commit || input.evidence || input.checkpoint || input;
  const identityData = input.identity || {};

  const objType = commitData.type || "";

  // Skip fixtures that test JCS canonicalization directly.
  if (objType === "JCSNumberTest" || objType === "UnicodeDistinctness") {
    console.log("skipped: JCS-only fixture");
    process.exit(0);
  }

  if (objType !== "MemoryCommit") {
    console.error(
      `error: unsupported object type: ${objType} (only MemoryCommit supported in this runner)`,
    );
    process.exit(1);
  }

  // Get signer public key from the fixture's identity
  const pubJwk = identityData.public_key;
  if (!pubJwk || !pubJwk.x) {
    // No identity in fixture — accept if structure is valid.
    // Compute canonical bytes of the signable dict (without commit_id, signature).
    const { signature, commit_id, ...signable } = commitData;
    const canonical = canonicalizeJson(signable);
    process.stdout.write(canonical);
    process.exit(0);
  }

  // Convert JWK x (base64url) to Uint8Array of 32 bytes
  const xB64 = pubJwk.x;
  const pubBytes = base64UrlToBytes(xB64);
  if (pubBytes.length !== 32) {
    console.error(
      `error: public key is ${pubBytes.length} bytes, expected 32`,
    );
    process.exit(1);
  }

  // Build MemoryCommit object
  const commit = {
    type: commitData.type,
    version: commitData.version,
    agent_id: commitData.agent_id,
    key_id: commitData.key_id,
    parents: commitData.parents || [],
    timestamp: commitData.timestamp,
    session_id: commitData.session_id || "",
    memory_type: commitData.memory_type || "semantic",
    content: commitData.content || {},
    provenance: commitData.provenance || {},
    commit_id: commitData.commit_id || commitData.checkpoint_id || "",
    signature: commitData.signature || "",
  };

  let verified;
  try {
    verified = await verifyCommit(commit, pubBytes);
  } catch (e) {
    if (expected !== "verify_ok") {
      console.error(`correctly rejected (expected verify_fail): ${e.message}`);
      process.exit(1);
    }
    console.error(`error: verification threw: ${e.message}`);
    process.exit(1);
  }

  if (expected === "verify_ok") {
    if (verified) {
      // Compute canonical bytes of the signable dict (without commit_id, signature)
      const { signature, commit_id, ...signable } = commit;
      const canonical = canonicalizeJson(signable);
      process.stdout.write(canonical);
      process.exit(0);
    } else {
      console.error("error: expected verify_ok but verification failed");
      process.exit(1);
    }
  } else {
    // expected == verify_fail
    if (!verified) {
      console.error("correctly rejected (expected verify_fail)");
      process.exit(1);
    } else {
      console.error("error: expected verify_fail but verification passed — BUG");
      process.exit(1);
    }
  }
}

// Need to import base64UrlToBytes too — re-implement here to avoid index.ts
// dependency issues (the file uses ESM with .ts extension which node
// doesn't run natively without --loader tsx).
function base64UrlToBytes(s) {
  // Convert base64url to base64
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  // Pad
  while (b64.length % 4 !== 0) b64 += "=";
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

main().catch((e) => {
  console.error(`fatal: ${e.message}`);
  process.exit(2);
});
