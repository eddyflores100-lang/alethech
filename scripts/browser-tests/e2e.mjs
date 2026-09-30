// Exercise the built, permissionless extension with its actual WASM module.
import { chromium } from "playwright";
import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdtemp, cp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";

const root = resolve(import.meta.dirname, "../..");
const temp = await mkdtemp(join(tmpdir(), "alethech-browser-"));
let context;
function python(source, args = []) {
  const result = spawnSync("python", ["-c", source, ...args], { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || "Python verification failed");
  return JSON.parse(result.stdout);
}
const fixture = python(`
import json,sys
from pathlib import Path
from alethech import Alethech
from alethech.container import _collect
from alethech.container_v2 import _seal_payload_v2
from alethech.crypto import b64url,b64url_decode
p=Path(sys.argv[1]);a=Alethech.initialize(p/'store')
a.commit({'memory':'browser recovery fixture'})
a.seal(p/'v1.aleth','initial-pass')
_,code=a.seal_v2(p/'v2.aleth','initial-pass')
payload={'payload_version':1,'files':_collect(a.path)}
name=next(n for n in payload['files'] if n.startswith('commits/'))
commit=json.loads(b64url_decode(payload['files'][name]));commit['content']={'forged':True}
payload['files'][name]=b64url(json.dumps(commit).encode())
badcode='aleth-recovery-v1:'+b64url(bytes([255])*32)
(p/'forged.aleth').write_bytes(_seal_payload_v2(payload,'initial-pass',recovery_secret=bytes([255])*32))
print(json.dumps({'head':a.head,'code':code,'badcode':badcode}))
`, [temp]);
function inspect(path, passphrase, recoveryCode) {
  return python(`
import sys,json,tempfile
from pathlib import Path
from alethech import Alethech
from alethech.container_v2 import inspect_container_v2
meta=inspect_container_v2(sys.argv[1],passphrase=sys.argv[2])
if sys.argv[3]:
 assert inspect_container_v2(sys.argv[1],recovery_code=sys.argv[3])==meta
with tempfile.TemporaryDirectory() as d:
 a=Alethech.open_aleth(sys.argv[1],Path(d)/'store',sys.argv[2])
 assert a.verify().ok
 meta['head']=a.head;meta['entries']=a.context()['entries']
print(json.dumps(meta))
`, [path, passphrase, recoveryCode ?? ""]);
}
try {
  const extension = join(temp, "extension");
  await cp(join(root, "extension/dist"), extension, { recursive: true });
  const manifest = JSON.parse(await readFile(join(extension, "manifest.json"), "utf8"));
  assert.equal((manifest.permissions ?? []).length, 0);
  assert.equal((manifest.host_permissions ?? []).length, 0);
  // A temporary public manifest key gives the unpacked test extension a stable id.
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const der = publicKey.export({ type: "spki", format: "der" });
  manifest.key = der.toString("base64");
  const id = createHash("sha256").update(der).digest("hex").slice(0, 32)
    .replace(/[0-9a-f]/g, c => String.fromCharCode(97 + parseInt(c, 16)));
  await writeFile(join(extension, "manifest.json"), JSON.stringify(manifest));
  context = await chromium.launchPersistentContext(join(temp, "profile"), {
    channel: "chromium", headless: true,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const externalRequests = [];
  page.on("request", r => { if (/^https?:/.test(r.url())) externalRequests.push(r.url()); });
  await page.goto(`chrome-extension://${id}/popup.html`);
  await page.locator("#file").setInputFiles(join(temp, "v1.aleth"));
  await page.locator("#passphrase").fill("initial-pass");
  await page.locator("#open").click();
  await page.locator("#result").waitFor({ state: "visible" });
  let sequence = 0;
  async function download(button) {
    const waiting = page.waitForEvent("download");
    await page.locator(button).click();
    const event = await waiting;
    const path = join(temp, `download-${++sequence}.aleth`);
    await event.saveAs(path);
    await page.waitForFunction(() => !document.querySelector("#passphrase").value);
    return path;
  }
  await page.locator("#passphrase").fill("initial-pass");
  const upgraded = await download("#create-recovery");
  const recovery = await page.locator("#recovery-code-text").inputValue();
  assert.match(recovery, /^aleth-recovery-v1:/);
  const before = inspect(upgraded, "initial-pass", recovery);
  assert.equal(before.head, fixture.head);
  await page.locator("#new-memory").fill("continued in actual extension");
  await page.locator("#passphrase").fill("initial-pass");
  const appended = await download("#save");
  const appendedMeta = inspect(appended, "initial-pass", recovery);
  assert.equal(appendedMeta.version, 2);
  assert.equal(appendedMeta.container_id, before.container_id);
  assert.notEqual(appendedMeta.head, before.head);
  // A real unsigned provider proposal becomes signed only on explicit acceptance.
  await page.locator("#provider-response").fill(JSON.stringify({
    alethech_writeback: [{ memory_type: "semantic", content: { text: "accepted provider memory" }, confidence: 0.9 }],
  }));
  await page.locator("#review-writeback").click();
  assert.equal(await page.locator("#accept-writeback").isEnabled(), true);
  await page.locator("#passphrase").fill("initial-pass");
  const writeback = await download("#accept-writeback");
  const writebackMeta = inspect(writeback, "initial-pass", recovery);
  assert.equal(writebackMeta.version, 2);
  assert.equal(writebackMeta.container_id, before.container_id);
  assert.notEqual(writebackMeta.head, appendedMeta.head);
  assert.equal(writebackMeta.entries.length, appendedMeta.entries.length + 1);
  assert(writebackMeta.entries.some(entry => entry.content.text === "accepted provider memory"));
  assert.equal(await page.locator("#accept-writeback").isEnabled(), false);
  assert.equal(await page.locator("#provider-response").inputValue(), "");
  await page.locator("#passphrase").fill("initial-pass");
  await page.locator("#new-passphrase").fill("next-pass");
  await page.locator("#confirm-passphrase").fill("next-pass");
  const rekeyed = await download("#rekey");
  assert.equal(inspect(rekeyed, "next-pass", recovery).head, writebackMeta.head);
  await page.locator("#passphrase").fill("next-pass");
  const rotated = await download("#rotate-recovery");
  const newRecovery = await page.locator("#rotated-recovery-text").inputValue();
  assert.notEqual(newRecovery, recovery);
  assert.equal(inspect(rotated, "next-pass", newRecovery).container_id, before.container_id);
  await page.locator("#prepare-context").click();
  const shared = await page.locator("#chat-context").inputValue();
  assert(!/PRIVATE KEY|signing\.key|root\.key|recovery\.key/.test(shared));

  // Recovery is reachable while locked, preserves the credential by default.
  await page.locator("#file").setInputFiles(join(temp, "v2.aleth"));
  await page.locator("#recovery-input").fill(fixture.code);
  await page.locator("#recover-new-pass").fill("recovered-pass");
  await page.locator("#recover-confirm-pass").fill("recovered-pass");
  const recovered = await download("#recover-btn");
  assert.equal(inspect(recovered, "recovered-pass", fixture.code).head, fixture.head);

  // Explicit locked recovery rotation retains identity/history and rejects the old code.
  const originalV2 = inspect(join(temp, "v2.aleth"), "initial-pass", fixture.code);
  await page.locator("#file").setInputFiles(join(temp, "v2.aleth"));
  assert.equal(await page.locator("#result").isVisible(), false);
  await page.locator("#recovery-input").fill(fixture.code);
  await page.locator("#recover-new-pass").fill("rotated-recovered-pass");
  await page.locator("#recover-confirm-pass").fill("rotated-recovered-pass");
  await page.locator("#recover-rotate").check();
  const recoveredRotated = await download("#recover-btn");
  const rotatedCode = await page.locator("#rotated-recovery-text").inputValue();
  assert.match(rotatedCode, /^aleth-recovery-v1:/);
  assert.notEqual(rotatedCode, fixture.code);
  const recoveredRotatedMeta = inspect(recoveredRotated, "rotated-recovered-pass", rotatedCode);
  assert.equal(recoveredRotatedMeta.container_id, originalV2.container_id);
  assert.equal(recoveredRotatedMeta.head, originalV2.head);
  assert.deepEqual(recoveredRotatedMeta.entries, originalV2.entries);
  assert.equal(python(`
import sys,json
from alethech.container import ContainerError
from alethech.container_v2 import inspect_container_v2
try:
 inspect_container_v2(sys.argv[1],recovery_code=sys.argv[2])
except ContainerError:
 print(json.dumps(True))
else:
 print(json.dumps(False))
`, [recoveredRotated, fixture.code]), true);
  // Rotation does not revoke a previously retained file copy.
  assert.equal(inspect(join(temp, "v2.aleth"), "initial-pass", fixture.code).head, fixture.head);
  await page.locator("#recover-rotate").uncheck();

  // An authenticated but forged history must produce no downloadable output.
  await page.locator("#file").setInputFiles(join(temp, "forged.aleth"));
  await page.locator("#recovery-input").fill(fixture.badcode);
  await page.locator("#recover-new-pass").fill("must-not-save");
  await page.locator("#recover-confirm-pass").fill("must-not-save");
  let forbiddenDownload = false;
  const detect = () => { forbiddenDownload = true; };
  page.on("download", detect);
  await page.locator("#recover-btn").click();
  await page.locator("#status.error").waitFor();
  assert.equal(forbiddenDownload, false);
  assert.equal(await page.locator("#result").isVisible(), false);
  page.off("download", detect);
  assert.deepEqual(externalRequests, []);
  assert.equal(await page.locator("#recovery-input").inputValue(), "");
  console.log("Browser: upgrade, append, accepted provider writeback, passphrase rotation, recovery rotation, locked recovery preservation/rotation, old-code rejection, sharing and forged-history rejection passed");
} finally {
  await context?.close();
  await rm(temp, { recursive: true, force: true });
}
