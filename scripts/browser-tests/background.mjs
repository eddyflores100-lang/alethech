/** Node regression checks against the built extension worker. No browser/network required. */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import vm from "node:vm";

const workerPath = new URL("../../extension/dist/background.js", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("../../extension/dist/manifest.json", import.meta.url), "utf8"));
const source = readFileSync(workerPath, "utf8");
const extensionId = "background-regression-test";
const popup = `chrome-extension://${extensionId}/popup.html`;
const sourcePage = "https://chatgpt.com/c/regression";
const TTL = 5 * 60 * 1000;
const fixture = (overrides = {}) => ({
  title: "Capture\u0000 title", url: sourcePage, provider: "unknown",
  captured_at: "2020-01-01T00:00:00.000Z", scope: "current-page-dom",
  messages: [{ role: "user", content: "A visible conversation" }], ...overrides,
});
const sourceSender = (overrides = {}) => ({
  id: extensionId, frameId: 0, tab: { id: 1, url: sourcePage }, url: sourcePage, ...overrides,
});

function harness() {
  let onMessage, onRemoved, onUpdated;
  let now = Date.parse("2026-09-30T12:00:00.000Z");
  let timerId = 0;
  const timers = new Map();
  const creates = [];
  class ClockDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  const chrome = {
    runtime: {
      id: extensionId, getURL: path => `chrome-extension://${extensionId}/${path}`,
      getManifest: () => manifest, onMessage: { addListener: fn => { onMessage = fn; } },
    },
    tabs: {
      create: options => new Promise((resolve, reject) => { creates.push({ ...options, resolve, reject }); }),
      onRemoved: { addListener: fn => { onRemoved = fn; } },
      onUpdated: { addListener: fn => { onUpdated = fn; } },
    },
  };
  vm.runInNewContext(source, {
    chrome, crypto: webcrypto, URL, TextEncoder, Date: ClockDate,
    setTimeout: (fn, delay) => { const id = ++timerId; timers.set(id, { fn, when: now + delay }); return id; },
    clearTimeout: id => timers.delete(id),
  }, { filename: workerPath.pathname });
  const send = (message, sender) => new Promise(resolve => {
    assert.equal(onMessage(message, sender, resolve), true, "recognized requests must keep the response channel open");
  });
  const begin = (capture = fixture(), sender = sourceSender()) => {
    const opening = send({ type: "alethech.open-capture", capture }, sender);
    const created = creates.at(-1);
    assert.ok(created, "valid capture should create a review tab");
    assert.equal(created.active, true);
    assert.equal(created.url.split("#")[0], popup);
    const token = new URL(created.url).hash.slice("#capture=".length);
    assert.match(token, /^[a-f0-9-]{36}$/);
    return { opening, created, token };
  };
  const take = (token, tabId = 20, overrides = {}) => send({ type: "alethech.take-capture", token }, {
    id: extensionId, frameId: 0, tab: { id: tabId }, url: `${popup}#capture=${token}`, ...overrides,
  });
  return {
    send, begin, take, creates, timers,
    remove: id => onRemoved(id), navigate: (id, url) => onUpdated(id, { url }),
    ignore: message => onMessage(message, sourceSender(), () => { throw new Error("Unknown request was answered"); }),
    advance: (ms, fireTimers = true) => {
      now += ms;
      if (fireTimers) for (const [id, timer] of timers) if (timer.when <= now) { timers.delete(id); timer.fn(); }
    },
  };
}
async function open(h, capture = fixture(), sender = sourceSender()) {
  const request = h.begin(capture, sender);
  request.created.resolve({ id: 20 });
  assert.equal((await request.opening).ok, true);
  return request.token;
}
const rejected = async (response, reason) => assert.equal((await response).ok, false, reason);
const check = async (label, test) => { await test(); console.log(`PASS ${label}`); };

await check("wrong tab cannot consume; rightful tab gets sanitized sender-bound metadata; replay denied", async () => {
  const h = harness();
  const token = await open(h, fixture({ url: `${sourcePage}?capture=ignored#secret` }),
    sourceSender({ tab: { id: 1, url: `${sourcePage}?api_key=secret#private` }, url: `${sourcePage}?other=ignored#private` }));
  await rejected(h.take(token, 21), "wrong tab must fail before the rightful tab consumes");
  const result = await h.take(token);
  assert.equal(result.ok, true);
  assert.equal(result.capture.url, sourcePage);
  assert.equal(result.capture.provider, "chatgpt", "provider comes from sender URL, not submitted metadata");
  assert.equal(result.capture.captured_at, "2026-09-30T12:00:00.000Z");
  assert.equal(result.capture.title, "Capture  title");
  assert.equal(result.capture.messages[0].content, "A visible conversation");
  assert.equal(h.timers.size, 0, "consuming cancels the expiry timer");
  await rejected(h.take(token), "replay must fail");
});

await check("retrieval waits for tab assignment; concurrent rightful requests yield exactly one capture", async () => {
  const h = harness();
  const { token, opening, created } = h.begin();
  let settled = false;
  const first = h.take(token).then(value => { settled = true; return value; });
  const second = h.take(token);
  await Promise.resolve();
  assert.equal(settled, false, "capture must wait until tabs.create assigns the authorized tab");
  created.resolve({ id: 20 });
  assert.equal((await opening).ok, true);
  const responses = await Promise.all([first, second]);
  assert.equal(responses.filter(response => response.ok).length, 1);
  assert.equal(responses.filter(response => !response.ok).length, 1);
});

await check("source sender identity, frame, actual source URL and manifest paths are enforced", async () => {
  const invalid = [
    [fixture(), sourceSender({ id: "another-extension" })],
    [fixture(), sourceSender({ frameId: 1 })],
    [fixture(), sourceSender({ tab: undefined })],
    [fixture(), sourceSender({ url: "https://claude.ai/" })],
    [fixture({ url: "https://claude.ai/" }), sourceSender()],
    [fixture({ url: "https://evil.example/" }), sourceSender({ tab: { id: 1, url: "https://evil.example/" }, url: "https://evil.example/" })],
    [fixture({ url: "https://www.bing.com/search" }), sourceSender({ tab: { id: 1, url: "https://www.bing.com/search" }, url: "https://www.bing.com/search" })],
    [fixture({ url: "file:///private" }), sourceSender({ tab: { id: 1, url: "file:///private" }, url: "file:///private" })],
  ];
  for (const [capture, sender] of invalid) {
    const h = harness();
    await rejected(h.send({ type: "alethech.open-capture", capture }, sender), "invalid source should fail");
    assert.equal(h.creates.length, 0, "invalid capture must not create a tab");
  }
  for (const url of ["http://localhost/", "http://127.0.0.1:8123/transcript", "https://www.bing.com/chat/conversation"]) {
    const h = harness();
    const token = await open(h, fixture({ url }), sourceSender({ tab: { id: 1, url }, url }));
    assert.equal((await h.take(token)).capture.url, url);
  }
});

await check("review origin, exact popup path, query, frame and extension identity are enforced without consumption", async () => {
  const h = harness();
  const token = await open(h);
  for (const overrides of [
    { id: "another-extension" }, { frameId: 1 }, { tab: undefined },
    { url: "https://chatgpt.com/popup.html" },
    { url: `chrome-extension://another-extension/popup.html#capture=${token}` },
    { url: `chrome-extension://${extensionId}/other.html#capture=${token}` },
    { url: `${popup}?redirect=1#capture=${token}` },
  ]) await rejected(h.take(token, 20, overrides), "invalid review sender must fail");
  assert.equal((await h.take(token)).ok, true, "rejected requests must leave the rightful capture available");
});

await check("invalid roles and schemas rejected; encoded byte limit enforced", async () => {
  for (const capture of [
    fixture({ scope: "all-history" }), fixture({ captured_at: "invalid" }), fixture({ provider: "invented" }),
    fixture({ messages: [] }), fixture({ messages: [{ role: "system", content: "no" }] }),
    fixture({ messages: [{ role: "user", content: 7 }] }), fixture({ title: "x".repeat(1001) }),
    fixture({ messages: [{ role: "user", content: "😀".repeat(600000) }] }),
  ]) {
    const h = harness();
    await rejected(h.send({ type: "alethech.open-capture", capture }, sourceSender()), "invalid capture must fail");
    assert.equal(h.creates.length, 0);
  }
});

await check("expiry rejects even before its timer fires; timer releases retained capture", async () => {
  const h = harness();
  const token = await open(h);
  h.advance(TTL, false);
  await rejected(h.take(token), "expired token must fail independently of timer scheduling");
  h.advance(0);
  assert.equal(h.timers.size, 0);
  await rejected(h.take(token), "expired capture must remain unavailable");
});

await check("closing or navigating review tab discards pending capture", async () => {
  for (const event of [h => h.remove(20), h => h.navigate(20, "https://chatgpt.com/")]) {
    const h = harness();
    const token = await open(h);
    event(h);
    await Promise.resolve();
    assert.equal(h.timers.size, 0);
    await rejected(h.take(token), "closed or navigated capture must fail");
  }
});

await check("failed tab creation discards capture; unrelated runtime messages are ignored", async () => {
  const h = harness();
  const { token, created, opening } = h.begin();
  created.reject(new Error("Browser refused tab"));
  await rejected(opening, "failed tab creation must fail closed");
  assert.equal(h.timers.size, 0);
  await rejected(h.take(token), "failed creation must discard its token");
  assert.equal(h.ignore({ type: "unrelated" }), false);
});
console.log("Background capture handoff regression checks passed.");
