import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { base64UrlToBytes, bytesToBase64Url } from "./index.ts";
import { createPortableMemory, MAX_CAPTURE_CONTENT_BYTES } from "./portable-create.ts";
import { appendPortableMemory } from "./portable-editor.ts";
import { verifyPortablePayload } from "./portable-verifier.ts";

const content = {
  capture: {provider:"chatgpt", messages:[{role:"user",text:"Explain μ and 🧭"}, {role:"assistant",text:"Captured text"}]},
  accepted_by_user:true,
  canonical_numbers:[0.25, 1e-7, -0, 1e21],
};
const pending = createPortableMemory(content, {session_id:"creation-test"});
content.capture.messages[0].text = "mutated after invocation";
const payload = await pending;
const initial = await verifyPortablePayload(payload);
assert.equal(initial.entries.length, 1);
assert.equal((initial.entries[0].content.capture as any).messages[0].text, "Explain μ and 🧭");
assert.equal(initial.entries[0].provenance.source, "user_accepted_chat_capture");
assert.equal(initial.entries[0].session_id, "creation-test");
assert.equal(initial.entries[0].memory_type, "episodic");
assert.deepEqual(Object.keys(payload.files).filter(p=>p.startsWith("keys/")), ["keys/signing.key"]);
assert.equal(Object.keys(payload.files).length, 5);
const second = await createPortableMemory({text:"Independent identity"});
assert.notEqual(Object.keys(payload.files).find(p=>p.startsWith("identities/")),
  Object.keys(second.files).find(p=>p.startsWith("identities/")));
assert.notEqual(payload.files["keys/signing.key"], second.files["keys/signing.key"]);

// A capture near the UI's 2 MiB UTF-8 transcript limit remains valid when the
// reviewed text is duplicated in message records and escaped for signed JSON.
const largeText = "μ\n".repeat(Math.floor((2 * 1024 * 1024) / 3));
assert.ok(new TextEncoder().encode(largeText).length <= 2 * 1024 * 1024);
const largePayload = await createPortableMemory({text:largeText, messages:[{role:"user", text:largeText}]});
assert.equal((await verifyPortablePayload(largePayload)).entries[0].content.text, largeText);

const appended = await appendPortableMemory(payload, {continuation:"browser works"});
assert.equal((await verifyPortablePayload(appended.payload)).entries.length, 2);
assert.equal((await verifyPortablePayload(payload)).entries.length, 1);

for (const invalid of [null, [], {}, {type:"genesis"}, {x:undefined}, {x:NaN}, {x:Infinity},
  {x:BigInt(1)}, {x:new Date()}, {x:"\ud800"}, {x:Array(2)}, {x:"a".repeat(MAX_CAPTURE_CONTENT_BYTES)}]) {
  await assert.rejects(createPortableMemory(invalid as any));
}
const cyclic: any = {}; cyclic.x = cyclic;
await assert.rejects(createPortableMemory(cyclic));
let getterCalled = false;
await assert.rejects(createPortableMemory({get text(){getterCalled=true; return "hidden";}}));
assert.equal(getterCalled, false);
await assert.rejects(createPortableMemory({text:"hello"}, {session_id:""}));
await assert.rejects(createPortableMemory({text:"hello"}, {memory_type:"invalid" as any}));
const tampered = structuredClone(payload);
const headPath = `commits/${initial.head}.json`;
const head = JSON.parse(new TextDecoder().decode(base64UrlToBytes(tampered.files[headPath])));
head.content.accepted_by_user = false;
tampered.files[headPath] = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(head)));
await assert.rejects(verifyPortablePayload(tampered), /verification failed/);

// Independent Python implementation materializes the browser-created payload,
// verifies every signature and operational key, appends with that generated key,
// then returns its own portable serialization for browser verification.
const python = spawnSync(process.env.PYTHON ?? "python", ["-c", `
import json, sys, tempfile
from pathlib import Path
from alethech.container import _materialize_payload, _collect
from alethech.api import Alethech
from alethech.verify import verify_store
payload=json.load(sys.stdin)
with tempfile.TemporaryDirectory() as tmp:
    store=_materialize_payload(payload, Path(tmp)/"memory")
    assert verify_store(store).ok
    api=Alethech(store)
    api.commit({"continuation":"python works"}, source="cross_implementation_test")
    assert verify_store(store).ok
    json.dump({"payload_version":1,"files":_collect(store.root)},sys.stdout)
`], {cwd:fileURLToPath(new URL("../", import.meta.url)), input:JSON.stringify(appended.payload), encoding:"utf8"});
assert.equal(python.status, 0, python.stderr);
const roundtrip = await verifyPortablePayload(JSON.parse(python.stdout));
assert.equal(roundtrip.entries.length, 3);
assert.equal(roundtrip.entries.at(-1)!.content.continuation, "python works");
process.stdout.write("portable creation: snapshot, validation, fresh keys, tamper rejection, browser append and Python roundtrip passed\n");
