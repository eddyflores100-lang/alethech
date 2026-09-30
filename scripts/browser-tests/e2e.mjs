// Exercise the built extension and offline HTML with actual Chrome scripting and WASM.
import { chromium } from "playwright";
import { generateKeyPairSync, createHash } from "node:crypto";
import { mkdtemp, cp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "../..");
const temp = await mkdtemp(join(tmpdir(), "alethech-browser-"));
let context;
const fixtureRequests = [];
const chatServer = createServer((request, response) => {
  fixtureRequests.push(request.url);
  response.writeHead(200, {"Content-Type": "text/html; charset=utf-8"});
  const second = request.url.startsWith("/other");
  response.end(`<!doctype html><title>${second ? "Second conversation" : "Captured conversation"}</title>
    <main>
      <div data-message-author-role="user"><p>${second ? "Continue with my saved context." : "Remember my favorite language is Python."}</p>
        <span hidden>HIDDEN_SECRET</span><span style="display:none">CSS_SECRET</span>
        <input type="password" value="PASSWORD_SECRET"><span data-sensitive>SENSITIVE_SECRET</span></div>
      <div data-message-author-role="assistant"><p>${second ? "I will continue from that memory." : "I will remember Python for future examples."}</p></div>
      <form id="chat-form"><textarea id="prompt-textarea" aria-label="Message"></textarea><button id="send">Send</button></form>
      <input type="password" value="OUTSIDE_PASSWORD_SECRET">
    </main><script>
      window.sends=0; window.inputEvents=0; window.keyEvents=0;
      document.querySelector('#chat-form').addEventListener('submit',e=>{e.preventDefault();window.sends++;fetch('/send');});
      document.querySelector('#prompt-textarea').addEventListener('input',()=>window.inputEvents++);
      document.querySelector('#prompt-textarea').addEventListener('keydown',()=>window.keyEvents++);
    </script>`);
});
await new Promise(resolve => chatServer.listen(0, "127.0.0.1", resolve));
const fixtureOrigin = `http://127.0.0.1:${chatServer.address().port}`;
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
  assert.deepEqual([...(manifest.permissions ?? [])].sort(), ["activeTab"]);
  assert.equal((manifest.optional_permissions ?? []).length, 0);
  assert.equal((manifest.optional_host_permissions ?? []).length, 0);
  assert.equal((manifest.host_permissions ?? []).length, 0);
  // A tab opened as popup.html does not receive the toolbar's activeTab grant.
  // Grant only the local fixture in the temporary copy, after production assertions.
  manifest.host_permissions = ["http://127.0.0.1/*"];
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
  // Real executeScript captures visible role wrappers after an explicit popup action.
  const sourceChat = await context.newPage();
  await sourceChat.goto(`${fixtureOrigin}/chat?secret=URL_SECRET#HASH_SECRET`);
  await sourceChat.locator("#prompt-textarea").fill("UNSENT_DRAFT_SECRET");
  async function activePopupAction(selector, target = sourceChat) {
    await target.bringToFront();
    await page.evaluate(selector => document.querySelector(selector).click(), selector);
  }
  await activePopupAction("#capture-chat");
  await page.waitForFunction(() => document.querySelector("#capture-review").value.includes("Remember my favorite"));
  const reviewed = await page.locator("#capture-review").inputValue();
  assert.equal(reviewed, "user:\nRemember my favorite language is Python.\n\nassistant:\nI will remember Python for future examples.");
  assert(!/SECRET/.test(reviewed));
  assert.match(await page.locator("#capture-warning").textContent(), /loaded|cargados|rendered/i);
  let sequence = 0;
  async function downloadFrom(target, button, suffix = "aleth") {
    const waiting = target.waitForEvent("download");
    await target.locator(button).click();
    const event = await waiting;
    const path = join(temp, `download-${++sequence}.${suffix}`);
    await event.saveAs(path);
    return {path, name: event.suggestedFilename()};
  }
  await page.locator("#capture-name").fill("independent-chat");
  await page.locator("#capture-passphrase").fill("capture-pass");
  await page.locator("#capture-confirm-passphrase").fill("capture-pass");
  const capturedFile = await downloadFrom(page, "#capture-save");
  assert.equal(capturedFile.name, "independent-chat.aleth");
  await page.waitForFunction(() => !document.querySelector("#capture-passphrase").value);
  const captureCode = await page.locator("#recovery-code-text").inputValue();
  const captureMeta = inspect(capturedFile.path, "capture-pass", captureCode);
  assert.equal(captureMeta.entries.length, 1);
  assert.equal(captureMeta.entries[0].content.text, reviewed);
  assert.equal(captureMeta.entries[0].content.capture.user_reviewed, true);
  assert.equal(captureMeta.entries[0].content.capture.title, "Captured conversation");
  assert.equal(captureMeta.entries[0].content.capture.url, `${fixtureOrigin}/chat`);
  assert(!JSON.stringify(captureMeta.entries).includes("SECRET"));
  assert.notEqual(captureMeta.head, fixture.head);
  const otherChat = await context.newPage();
  await otherChat.goto(`${fixtureOrigin}/other`);
  // Selecting and unlocking the downloaded file is the complete cross-page workflow.
  await page.locator("#file").setInputFiles(capturedFile.path);
  await page.locator("#passphrase").fill("capture-pass");
  await page.locator("#open").click();
  await page.locator("#result").waitFor({state: "visible"});
  await activePopupAction("#insert-context", otherChat);
  await otherChat.waitForFunction(() => document.querySelector("#prompt-textarea").value.includes("Remember my favorite"));
  const inserted = await otherChat.locator("#prompt-textarea").inputValue();
  assert.match(inserted, /I will remember Python/);
  assert(!/PRIVATE KEY|signing\.key|root\.key|recovery\.key|SECRET/.test(inserted));
  assert.deepEqual(await otherChat.evaluate(() => ({sends, inputEvents, keyEvents})), {sends: 0, inputEvents: 1, keyEvents: 0});
  await activePopupAction("#insert-context", otherChat);
  await page.locator("#status.error").waitFor();
  assert.equal(await otherChat.locator("#prompt-textarea").inputValue(), inserted);
  await otherChat.evaluate(() => {const editor=document.querySelector('#prompt-textarea');editor.value='';editor.readOnly=true;});
  await activePopupAction("#insert-context", otherChat);
  await page.locator("#status.error").waitFor();
  assert.equal(await otherChat.locator("#prompt-textarea").inputValue(), "");
  await activePopupAction("#capture-chat", otherChat);
  await page.waitForFunction(() => document.querySelector("#capture-review").value.includes("Continue with my saved"));
  await page.locator("#passphrase").fill("capture-pass");
  const capturedAppend = await downloadFrom(page, "#capture-append");
  const continuedMeta = inspect(capturedAppend.path, "capture-pass", captureCode);
  assert.equal(continuedMeta.container_id, captureMeta.container_id);
  assert.equal(continuedMeta.entries.length, 2);
  assert.deepEqual(continuedMeta.entries[0], captureMeta.entries[0]);
  assert.match(continuedMeta.entries[1].content.text, /user:\nContinue with my saved context/);
  assert.notEqual(continuedMeta.head, captureMeta.head);
  assert(!fixtureRequests.some(url => url.startsWith("/send")));

  await page.locator("#file").setInputFiles(join(temp, "v1.aleth"));
  await page.locator("#passphrase").fill("initial-pass");
  await page.locator("#open").click();
  await page.locator("#result").waitFor({ state: "visible" });
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
  // Native selection is reset while the File object is held in memory, allowing
  // the same original file to be explicitly selected again after a download.
  assert.equal(await page.locator("#file").inputValue(), "");
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
  // The shipped single HTML runs from file:// with network unavailable.
  const offline = await context.newPage();
  const offlineRequests = [];
  offline.on("request", request => {
    if (/^https?:/.test(request.url())) offlineRequests.push(request.url());
  });
  await context.setOffline(true);
  await offline.goto(pathToFileURL(join(root, "standalone/dist/alethech.html")).href);
  assert.equal(await offline.locator("#capture-chat").isVisible(), false);
  assert.equal(await offline.locator("#insert-context").isVisible(), false);
  const pasted = "user:\nOffline browser memory.\n\nassistant:\nSaved without a server.";
  await offline.locator("#capture-review").fill(pasted);
  await offline.locator("#capture-name").fill("offline-memory");
  await offline.locator("#capture-passphrase").fill("offline-pass");
  await offline.locator("#capture-confirm-passphrase").fill("offline-pass");
  const offlineFile = await downloadFrom(offline, "#capture-save");
  assert.equal(offlineFile.name, "offline-memory.aleth");
  await offline.locator("#result").waitFor({state: "visible"});
  const offlineCode = await offline.locator("#recovery-code-text").inputValue();
  const offlineMeta = inspect(offlineFile.path, "offline-pass", offlineCode);
  assert.equal(offlineMeta.entries[0].content.text, pasted);
  assert.notEqual(offlineMeta.container_id, captureMeta.container_id);
  await offline.reload();
  await offline.locator("#file").setInputFiles(offlineFile.path);
  await offline.locator("#passphrase").fill("offline-pass");
  await offline.locator("#open").click();
  await offline.locator("#result").waitFor({state: "visible"});
  const exported = await downloadFrom(offline, "#download-context", "txt");
  assert.equal(exported.name, "context.txt");
  const offlineContext = await readFile(exported.path, "utf8");
  assert.match(offlineContext, /Offline browser memory/);
  assert.match(offlineContext, /Saved without a server/);
  assert(!/PRIVATE KEY|signing\.key|root\.key|recovery\.key/.test(offlineContext));
  assert.deepEqual(offlineRequests, []);
  console.log("Browser: actual page capture, independent identity, cross-page draft insertion, guarded editors, capture append, offline HTML create/reopen/export passed");
  console.log("Browser: upgrade, append, accepted provider writeback, passphrase rotation, recovery rotation, locked recovery preservation/rotation, old-code rejection, sharing and forged-history rejection passed");
} finally {
  await context?.close();
  await new Promise(resolve => chatServer.close(resolve));
  await rm(temp, { recursive: true, force: true });
}
