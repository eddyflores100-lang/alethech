// Build the self-contained helpers, then run with Node >= 20 and Playwright:
//   npx --yes esbuild@0.25.10 extension/src/chat-page-bridge.ts --bundle --format=iife --global-name=AlethechChatBridge --outfile=extension/dist/chat-page-bridge-test.js
//   cd scripts/browser-tests && node chat-page-bridge.mjs
// Optional: PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chromium
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import vm from "node:vm";

const bundle = await readFile(new URL("../../extension/dist/chat-page-bridge-test.js", import.meta.url), "utf8");
const { captureChatFromPage, insertContextIntoPage } = vm.runInNewContext(`${bundle}\n;AlethechChatBridge;`);

const require = createRequire(import.meta.url);
let playwright;
try { playwright = require("playwright"); }
catch (error) {
  if (!process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES) throw error;
  playwright = require(join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, "playwright"));
}
const browser = await playwright.chromium.launch({
  headless: true,
  ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE } : {}),
});
try {
  const page = await browser.newPage();
  // Fulfill all requests locally: fixtures never contact a provider.
  await page.route("**/*", route => route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Fixture chat</title>" }));
  await page.goto("https://chatgpt.com/c/local?token=secret#secret");
  await page.setContent(`<title>Fixture chat</title><main>
    <article data-message-author-role="user">First question<form><input type="password" value="secret"><textarea>private draft</textarea></form><span style="display:none">hidden secret</span></article>
    <article data-message-author-role="assistant"><div data-message-author-role="assistant">First answer <pre>code()</pre><button>Copy</button></div></article>
    <article data-message-author-role="user" hidden>Hidden history</article>
    <textarea id="prompt-textarea"></textarea><button id="send">Send</button>
  </main>`);
  // evaluate serializes the functions just like chrome.scripting.executeScript:
  // imported runtime dependencies would fail inside this page.
  let capture = await page.evaluate(captureChatFromPage);
  assert.equal(capture.provider, "chatgpt");
  assert.equal(capture.url, "https://chatgpt.com/c/local");
  assert.equal(capture.scope, "current-page-dom");
  assert.deepEqual(capture.messages, [
    { role: "user", content: "First question" },
    { role: "assistant", content: "First answer\ncode()" },
  ]);
  assert.match(capture.warning, /earlier history/);
  await page.evaluate(() => {
    window.inputCount = 0; window.sendCount = 0;
    document.querySelector("#prompt-textarea").addEventListener("input", () => window.inputCount++);
    document.querySelector("#send").addEventListener("click", () => window.sendCount++);
  });
  assert.deepEqual(await page.evaluate(insertContextIntoPage, "Imported context"), { ok: true, insertedCharacters: 16 });
  assert.equal(await page.locator("#prompt-textarea").inputValue(), "Imported context");
  assert.deepEqual(await page.evaluate(() => [window.inputCount, window.sendCount]), [1, 0]);
  assert.equal((await page.evaluate(insertContextIntoPage, "overwrite")).ok, false);
  assert.equal(await page.locator("#prompt-textarea").inputValue(), "Imported context");
  assert.equal((await page.evaluate(insertContextIntoPage, "x".repeat(2 * 1024 * 1024 + 1))).ok, false);
  assert.equal((await page.evaluate(insertContextIntoPage, "")).ok, false);

  await page.goto("https://claude.ai/chat/local?token=secret#secret");
  await page.setContent(`<main><div class="font-user-message">Claude question</div><div class="font-claude-message">Claude answer</div></main>`);
  capture = await page.evaluate(captureChatFromPage);
  assert.equal(capture.provider, "claude");
  assert.deepEqual(capture.messages.map(m => m.role), ["user", "assistant"]);
  await page.goto("https://gemini.google.com/app/local?token=secret#secret");
  await page.setContent(`<main><user-query>Gemini question</user-query><model-response>Gemini answer</model-response></main>`);
  capture = await page.evaluate(captureChatFromPage);
  assert.equal(capture.provider, "gemini");
  assert.deepEqual(capture.messages.map(m => m.role), ["user", "assistant"]);

  await page.setContent(`<main><p>Generic transcript</p><input value="key"><form>Secret form</form><div style="visibility:hidden">Secret hidden</div><div contenteditable="true">Unsent draft</div></main>`);
  capture = await page.evaluate(captureChatFromPage);
  assert.deepEqual(capture.messages, [{ role: "unknown", content: "Generic transcript" }]);
  assert.match(capture.warning, /generic fallback/);
  await page.evaluate(() => {
    const range = document.createRange();
    range.selectNodeContents(document.querySelector("main"));
    window.getSelection().addRange(range);
  });
  assert.deepEqual((await page.evaluate(captureChatFromPage)).messages, [{ role: "unknown", content: "Generic transcript" }]);

  await page.setContent(`<main><div contenteditable="true" role="textbox"></div><button id="send">Send</button></main>`);
  assert.equal((await page.evaluate(insertContextIntoPage, "Draft only")).ok, true);
  assert.equal(await page.locator("[contenteditable]").textContent(), "Draft only");
  assert.equal((await page.evaluate(insertContextIntoPage, "replacement")).ok, false);
  await page.setContent(`<textarea></textarea><textarea></textarea>`);
  assert.equal((await page.evaluate(insertContextIntoPage, "ambiguous")).ok, false);
  await page.locator("textarea").nth(1).focus();
  assert.equal((await page.evaluate(insertContextIntoPage, "focused")).ok, true);
  assert.deepEqual(await page.locator("textarea").evaluateAll(nodes => nodes.map(n => n.value)), ["", "focused"]);
  await page.setContent(`<textarea id="api-key"></textarea>`);
  assert.equal((await page.evaluate(insertContextIntoPage, "private context")).ok, false);
  await page.setContent(`<textarea disabled></textarea><textarea readonly></textarea><textarea style="display:none"></textarea>`);
  assert.equal((await page.evaluate(insertContextIntoPage, "private context")).ok, false);
  await page.setContent(`<textarea> </textarea>`);
  assert.equal((await page.evaluate(insertContextIntoPage, "replacement")).ok, false);

  await page.setContent(`<main><div data-message-author-role="assistant"></div></main>`);
  await page.locator("[data-message-author-role]").evaluate(node => { node.textContent = "🧠".repeat(600000); });
  await assert.rejects(page.evaluate(captureChatFromPage), /2 MiB limit/);
  assert.equal((await page.evaluate(insertContextIntoPage, "🧠".repeat(600000))).ok, false);
  await page.setContent(`<main><form>Only a form</form></main>`);
  await assert.rejects(page.evaluate(captureChatFromPage), /No visible conversation/);
  console.log("chat-page-bridge DOM fixtures passed");
} finally {
  await browser.close();
}
