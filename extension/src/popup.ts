import { canonicalizeJson } from "../../alethech-ts/index.ts";
import { createPortableMemory, MAX_CAPTURE_CONTENT_BYTES } from "../../alethech-ts/portable-create.ts";
import { captureChatFromPage, insertContextIntoPage } from "./chat-page-bridge.ts";
import initWasm, { open_aleth_payload, seal_aleth_payload, seal_aleth_v2, open_aleth_v2_recovery, recover_aleth_v2, generate_recovery_secret, rewrite_aleth_payload } from "./vendor/wasm/alethech_wasm.js";
import { verifyPortablePayload, type PortablePayload, type VerifiedPortableView } from "../../alethech-ts/portable-verifier.ts";
import { appendPortableMemory, canonicalPortablePayloadBytes } from "../../alethech-ts/portable-editor.ts";
import { toContextText } from "../../alethech-ts/context-adapter.ts";
import type { AlethechWritebackProposal } from "../../alethech-ts/chat-adapter-contract.ts";
import {
  acceptPluginWriteback,
  preparePluginRequest,
  reviewPluginWriteback,
  type PluginProviderKind,
} from "../../alethech-ts/plugin-api.ts";

let selectedFile: File | null = null;
let wasmReady: Promise<unknown> | null = null;
let verifiedPayload: PortablePayload | null = null;
let verifiedView: VerifiedPortableView | null = null;
let currentBlob: Uint8Array | null = null;
let generation = 0;
let busy = false;
const MAX_FILE_SIZE = 512 * 1024 * 1024;
let pendingWriteback: AlethechWritebackProposal | null = null;

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const drop = el<HTMLElement>("drop");
const fileInput = el<HTMLInputElement>("file");
const passphrase = el<HTMLInputElement>("passphrase");
const openButton = el<HTMLButtonElement>("open");
const filename = el<HTMLElement>("filename");
const status = el<HTMLElement>("status");
const result = el<HTMLElement>("result");
const newMemory = el<HTMLTextAreaElement>("new-memory");
const saveButton = el<HTMLButtonElement>("save");
const prepareContextButton = el<HTMLButtonElement>("prepare-context");
const chatContext = el<HTMLTextAreaElement>("chat-context");
const contextHint = el<HTMLElement>("context-hint");
const providerMode = el<HTMLSelectElement>("provider-mode");
const contextLimit = el<HTMLInputElement>("context-limit");
const userPrompt = el<HTMLTextAreaElement>("user-prompt");
const generateRequestButton = el<HTMLButtonElement>("generate-request");
const providerRequest = el<HTMLTextAreaElement>("provider-request");
const providerResponse = el<HTMLTextAreaElement>("provider-response");
const reviewWritebackButton = el<HTMLButtonElement>("review-writeback");
const writebackSummary = el<HTMLElement>("writeback-summary");
const acceptWritebackButton = el<HTMLButtonElement>("accept-writeback");
const selectAllButton = el<HTMLButtonElement>("select-all-memories");
const clearSelectionButton = el<HTMLButtonElement>("clear-memory-selection");
const newPassphrase = el<HTMLInputElement>("new-passphrase");
const confirmPassphrase = el<HTMLInputElement>("confirm-passphrase");
const rekeyButton = el<HTMLButtonElement>("rekey");
const createRecoveryButton = el<HTMLButtonElement>("create-recovery");
const recoveryCodeDisplay = el<HTMLElement>("recovery-code-display");
const recoveryCodeText = el<HTMLTextAreaElement>("recovery-code-text");
const copyRecoveryButton = el<HTMLButtonElement>("copy-recovery-code");
const rotateRecoveryButton = el<HTMLButtonElement>("rotate-recovery");
const rotatedRecoveryDisplay = el<HTMLElement>("rotated-recovery-display");
const rotatedRecoveryText = el<HTMLTextAreaElement>("rotated-recovery-text");
const copyRotatedRecoveryButton = el<HTMLButtonElement>("copy-rotated-recovery");
const recoveryInput = el<HTMLTextAreaElement>("recovery-input");
const recoverNewPass = el<HTMLInputElement>("recover-new-pass");
const recoverConfirmPass = el<HTMLInputElement>("recover-confirm-pass");
const recoverButton = el<HTMLButtonElement>("recover-btn");

function ensureWasm(): Promise<unknown> {
  if (!wasmReady) wasmReady = initWasm().catch((error: unknown) => { wasmReady = null; throw error; });
  return wasmReady;
}

function selectedMemoryIds(): string[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>(".memory-select:checked"))
    .map((node) => node.dataset.commitId ?? "")
    .filter(Boolean);
}

function renderView(view: VerifiedPortableView): void {
  el<HTMLElement>("head").textContent = view.head.slice(0, 20) + "…";
  el<HTMLElement>("count").textContent = String(view.entries.length);
  const memories = el<HTMLElement>("memories");
  memories.replaceChildren();
  for (const entry of view.entries.slice(-20)) {
    const row = document.createElement("label");
    row.className = "memory memory-select-row";

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "memory-select";
    checkbox.dataset.commitId = entry.commit_id;
    checkbox.checked = true;

    const content = document.createElement("span");
    content.className = "memory-content";
    content.textContent = JSON.stringify(entry.content, null, 2);

    row.append(checkbox, content);
    memories.appendChild(row);
  }
  updateButtons();
}

function clearVerifiedState(): void {
  verifiedPayload = null;
  verifiedView = null;
  el<HTMLElement>("memories").replaceChildren();
  el<HTMLElement>("head").textContent = "";
  el<HTMLElement>("count").textContent = "";
  newMemory.value = "";
  saveButton.disabled = true;
  chatContext.value = "";
  clearContextFile();
  chatContext.hidden = true;
  contextHint.hidden = true;
  providerRequest.value = "";
  providerResponse.value = "";
  writebackSummary.textContent = "";
  pendingWriteback = null;
  acceptWritebackButton.disabled = true;
  newPassphrase.value = "";
  confirmPassphrase.value = "";
  rekeyButton.disabled = true;
}

type SealResult = { blob: string; recovery_code: string | null; container_id: string };
function decodeBlob(value: string): Uint8Array {
  return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}
function envelope(): { version: number; recovery: boolean } {
  if (!currentBlob) return { version: 0, recovery: false };
  const length = new DataView(currentBlob.buffer, currentBlob.byteOffset, currentBlob.byteLength).getUint32(8);
  const header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(currentBlob.subarray(12, 12 + length)));
  return { version: header.version, recovery: Array.isArray(header.slots) && header.slots.some((s: {type: string}) => s.type === "recovery-secret") };
}
function assertCurrent(token: number): void {
  if (token !== generation) throw new Error("Selection changed; operation cancelled.");
}
function report(error: unknown, token: number): void {
  if (token !== generation) return;
  status.className = "status error";
  status.textContent = error instanceof Error ? error.message : String(error);
}
function startOperation(): number | null {
  if (busy) return null;
  busy = true;
  updateButtons();
  status.className = "status";
  return generation;
}
function finishOperation(token: number): void {
  if (token !== generation) return;
  busy = false;
  passphrase.value = "";
  newPassphrase.value = "";
  confirmPassphrase.value = "";
  recoveryInput.value = "";
  recoverNewPass.value = "";
  recoverConfirmPass.value = "";
  capturePassphrase.value = "";
  captureConfirmPassphrase.value = "";
  updateButtons();
}
function updateButtons(): void {
  openButton.disabled = busy || !selectedFile;
  saveButton.disabled = busy || !verifiedPayload || !newMemory.value.trim();
  acceptWritebackButton.disabled = busy || !pendingWriteback;
  updateRekeyButton();
  updateRecoveryButtons();
  captureButton.disabled = busy;
  el<HTMLButtonElement>("save-current-chat").disabled = busy;
  captureReview.readOnly = busy;
  capturePassphrase.disabled = busy;
  captureConfirmPassphrase.disabled = busy;
  captureSave.disabled = busy || !captureReview.value.trim();
  captureAppend.disabled = busy || !verifiedPayload || !captureReview.value.trim();
  for (const id of ["insert-context", "copy-context", "download-context", "prepare-context"]) {
    el<HTMLButtonElement>(id).disabled = busy || !verifiedView;
  }
}
function downloadBlob(blob: Uint8Array, suffix: string, token: number): void {
  assertCurrent(token);
  if (!selectedFile) throw new Error("No source .aleth selected.");
  const name = (selectedFile.name.replace(/\.aleth$/i, "") || "memory") + suffix + ".aleth";
  const file = new File([blob], name, { type: "application/octet-stream" });
  const href = URL.createObjectURL(file);
  const link = document.createElement("a");
  link.href = href;
  link.download = name;
  link.click();
  // Keep the latest encrypted output as the source for every subsequent operation.
  currentBlob?.fill(0);
  currentBlob = blob.slice();
  selectedFile = file;
  filename.textContent = name;
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
async function sourceBlob(token: number): Promise<Uint8Array> {
  if (!selectedFile) throw new Error("No source .aleth selected.");
  if (selectedFile.size > MAX_FILE_SIZE) throw new Error("File exceeds the 512 MiB container limit.");
  const file = selectedFile;
  if (!currentBlob) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (token !== generation) { bytes.fill(0); assertCurrent(token); }
    currentBlob = bytes;
  }
  return currentBlob;
}
async function verifiedPlaintext(plaintext: Uint8Array): Promise<{payload: PortablePayload; view: VerifiedPortableView}> {
  const payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)) as PortablePayload;
  const view = await verifyPortablePayload(payload);
  return {payload, view};
}
async function downloadUpdatedAleth(payload: PortablePayload, secret: string, suffix: string, token: number, next = secret, recoverySecret = ""): Promise<SealResult> {
  await ensureWasm();
  const blob = await sourceBlob(token);
  assertCurrent(token);
  // Authenticate the current credential and verify the current history before changing any envelope.
  const opened = open_aleth_payload(blob, secret);
  try { await verifiedPlaintext(opened); } finally { opened.fill(0); }
  const view = await verifyPortablePayload(payload);
  assertCurrent(token);
  const plaintext = canonicalPortablePayloadBytes(payload);
  let sealed: Uint8Array | null = null;
  try {
    const metadata = envelope();
    let output: SealResult;
    if (metadata.version === 1 && recoverySecret) {
      output = JSON.parse(seal_aleth_v2(plaintext, next, recoverySecret));
    } else {
      output = JSON.parse(rewrite_aleth_payload(blob, secret, plaintext, next, recoverySecret));
    }
    sealed = decodeBlob(output.blob);
    downloadBlob(sealed, suffix, token);
    verifiedPayload = payload;
    verifiedView = view;
    pendingWriteback = null;
    writebackSummary.textContent = "";
    providerRequest.value = "";
    chatContext.value = "";
    chatContext.hidden = true;
    contextHint.hidden = true;
    clearContextFile();
    renderView(view);
    return output;
  } finally {
    plaintext.fill(0);
    sealed?.fill(0);
  }
}

function selectedContextLimit(): number {
  const parsed = Number.parseInt(contextLimit.value, 10);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > 1000) {
    throw new Error("Context limit must be between 1 and 1000.");
  }
  return parsed;
}

function updateRekeyButton(): void {
  rekeyButton.disabled =
    busy || !verifiedPayload ||
    !newPassphrase.value ||
    !confirmPassphrase.value;
}

newPassphrase.addEventListener("input", updateRekeyButton);
confirmPassphrase.addEventListener("input", updateRekeyButton);

function choose(file: File | null): void {
  generation++;
  busy = false;
  currentBlob?.fill(0);
  currentBlob = null;
  clearVerifiedState();
  passphrase.value = "";
  capturePassphrase.value = "";
  captureConfirmPassphrase.value = "";
  recoveryInput.value = "";
  recoverNewPass.value = "";
  recoverConfirmPass.value = "";
  recoveryCodeText.value = "";
  rotatedRecoveryText.value = "";
  recoveryCodeDisplay.hidden = true;
  rotatedRecoveryDisplay.hidden = true;
  selectedFile = file && file.size <= MAX_FILE_SIZE ? file : null;
  if (file) el<HTMLDetailsElement>("existing-memory").open = true;
  // Reset native selection so choosing the same original file again emits change.
  // The File object is retained above; generated outputs become the active source.
  fileInput.value = "";
  filename.textContent = file ? file.name : "";
  result.hidden = true;
  status.className = file && !selectedFile ? "status error" : "status";
  status.textContent = file && !selectedFile ? "File exceeds the 512 MiB container limit." : file ? "Ready to unlock or recover locally." : "No memory loaded.";
  updateButtons();
}

fileInput.addEventListener("change", () => choose(fileInput.files?.[0] ?? null));
newMemory.addEventListener("input", updateButtons);
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("drag"); });
drop.addEventListener("dragleave", () => drop.classList.remove("drag"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("drag");
  choose(e.dataTransfer?.files?.[0] ?? null);
});

openButton.addEventListener("click", async () => {
  if (!selectedFile || busy) return;
  const secret = passphrase.value;
  if (!secret) { report(new Error("Enter the passphrase."), generation); return; }
  const token = startOperation()!;
  clearVerifiedState();
  result.hidden = true;
  status.textContent = "Authenticating and verifying…";
  let plaintext: Uint8Array | null = null;
  try {
    await ensureWasm();
    const blob = await sourceBlob(token);
    assertCurrent(token);
    plaintext = open_aleth_payload(blob, secret);
    const verified = await verifiedPlaintext(plaintext);
    assertCurrent(token);
    verifiedPayload = verified.payload;
    verifiedView = verified.view;
    renderView(verified.view);
    status.textContent = "Container authenticated. Protocol history verified.";
    result.hidden = false;
  } catch (e) { report(e, token); }
  finally { plaintext?.fill(0); finishOperation(token); }
});

saveButton.addEventListener("click", async () => {
  if (!verifiedPayload || !verifiedView || !selectedFile || busy) return;
  const text = newMemory.value.trim();
  const secret = passphrase.value;
  if (!text) return;
  if (!secret) { report(new Error("Re-enter the current passphrase to encrypt the updated memory."), generation); return; }
  const payload = verifiedPayload;
  const token = startOperation()!;
  status.textContent = "Signing, verifying, and encrypting updated memory…";
  try {
    const appended = await appendPortableMemory(payload, { text }, { source: "browser_extension" });
    assertCurrent(token);
    await downloadUpdatedAleth(appended.payload, secret, "-updated", token);
    newMemory.value = "";
    status.textContent = "Updated memory verified and downloaded. Recovery access preserved.";
  } catch (e) { report(e, token); }
  finally { finishOperation(token); }
});

prepareContextButton.addEventListener("click", () => {
  if (busy) return;
  if (!verifiedView) {
    status.className = "status error";
    status.textContent = "Unlock and verify a memory first.";
    return;
  }
  const ids = selectedMemoryIds();
  if (ids.length === 0) {
    status.className = "status error";
    status.textContent = "Select at least one memory to share.";
    return;
  }
  chatContext.value = toContextText(verifiedView, { include_ids: ids });
  refreshContextFile(chatContext.value);
  chatContext.hidden = false;
  contextHint.hidden = false;
  chatContext.focus();
  chatContext.select();
  status.className = "status";
  status.textContent = "Verified chat context prepared locally.";
});


generateRequestButton.addEventListener("click", () => {
  if (busy) return;
  if (!verifiedView) {
    status.className = "status error";
    status.textContent = "Unlock and verify a memory first.";
    return;
  }
  const prompt = userPrompt.value.trim();
  if (!prompt) {
    status.className = "status error";
    status.textContent = "Enter the message you want to send to the chat.";
    return;
  }
  try {
    if (selectedMemoryIds().length === 0) {
      throw new Error("No memories selected for provider request.");
    }
    const request = preparePluginRequest(
      { payload: verifiedPayload!, view: verifiedView },
      providerMode.value as PluginProviderKind,
      prompt,
      { limit: selectedContextLimit(), include_ids: selectedMemoryIds() },
    );
    providerRequest.value = JSON.stringify(request, null, 2);
    providerRequest.focus();
    providerRequest.select();
    status.className = "status";
    status.textContent = "Provider request prepared locally. Nothing was sent.";
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  }
});

reviewWritebackButton.addEventListener("click", () => {
  if (busy) return;
  if (!verifiedView) {
    status.className = "status error";
    status.textContent = "Unlock and verify a memory first.";
    return;
  }
  try {
    pendingWriteback = reviewPluginWriteback(
      { payload: verifiedPayload!, view: verifiedView },
      providerResponse.value,
    );
    writebackSummary.textContent =
      pendingWriteback.items.length === 1
        ? "1 proposed memory ready for local review."
        : `${pendingWriteback.items.length} proposed memories ready for local review.`;
    acceptWritebackButton.disabled = false;
    status.className = "status";
    status.textContent = "Proposal parsed. Nothing has been written or signed.";
  } catch (e) {
    pendingWriteback = null;
    acceptWritebackButton.disabled = true;
    writebackSummary.textContent = "";
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  }
});

acceptWritebackButton.addEventListener("click", async () => {
  if (!verifiedPayload || !verifiedView || !pendingWriteback || busy) return;
  const secret = passphrase.value;
  if (!secret) { report(new Error("Re-enter the current passphrase to encrypt the accepted writeback."), generation); return; }
  const unlocked = {payload: verifiedPayload, view: verifiedView};
  const proposal = pendingWriteback;
  const token = startOperation()!;
  status.textContent = "Signing accepted writeback locally and reverifying…";
  try {
    const accepted = await acceptPluginWriteback(unlocked, proposal);
    assertCurrent(token);
    await downloadUpdatedAleth(accepted.payload, secret, "-writeback", token);
    providerResponse.value = "";
    status.textContent = "Writeback signed locally, verified, and downloaded. Recovery access preserved.";
  } catch (e) { report(e, token); }
  finally { finishOperation(token); }
});

selectAllButton.addEventListener("click", () => {
  if (busy) return;
  for (const input of document.querySelectorAll<HTMLInputElement>(".memory-select")) {
    input.checked = true;
  }
  status.className = "status";
  chatContext.value = "";
  chatContext.hidden = true;
  clearContextFile();
  status.textContent = "All visible memories selected.";
});

clearSelectionButton.addEventListener("click", () => {
  if (busy) return;
  for (const input of document.querySelectorAll<HTMLInputElement>(".memory-select")) {
    input.checked = false;
  }
  status.className = "status";
  chatContext.value = "";
  chatContext.hidden = true;
  clearContextFile();
  status.textContent = "Memory sharing selection cleared.";
});


rekeyButton.addEventListener("click", async () => {
  if (!verifiedPayload || !selectedFile || busy) return;
  const next = newPassphrase.value;
  const secret = passphrase.value;
  if (!secret) { report(new Error("Re-enter the current passphrase before changing it."), generation); return; }
  if (!next || next !== confirmPassphrase.value) { report(new Error("New passphrases do not match."), generation); return; }
  const payload = verifiedPayload;
  const token = startOperation()!;
  status.textContent = "Re-encrypting verified memory…";
  try {
    await downloadUpdatedAleth(payload, secret, "-rekeyed", token, next);
    status.textContent = "Passphrase changed. Recovery access and verified memory history preserved.";
  } catch (e) { report(e, token); }
  finally { finishOperation(token); }
});

function updateRecoveryButtons(): void {
  const metadata = verifiedPayload ? envelope() : {version: 0, recovery: false};
  const ready = !!verifiedPayload && !!selectedFile && !busy;
  createRecoveryButton.disabled = !ready || metadata.recovery;
  rotateRecoveryButton.disabled = !ready || !metadata.recovery;
  recoverButton.disabled = busy || !selectedFile || !recoveryInput.value.trim() || !recoverNewPass.value || recoverNewPass.value !== recoverConfirmPass.value;
}
recoveryInput.addEventListener("input", updateRecoveryButtons);
recoverNewPass.addEventListener("input", updateRecoveryButtons);
recoverConfirmPass.addEventListener("input", updateRecoveryButtons);
async function changeRecovery(rotate: boolean): Promise<void> {
  if (!verifiedPayload || !selectedFile || busy) return;
  if (envelope().recovery !== rotate) { report(new Error(rotate ? "Create a recovery code first." : "Recovery already exists; use explicit rotation."), generation); return; }
  const secret = passphrase.value;
  if (!secret) { report(new Error("Re-enter the current passphrase to change recovery access."), generation); return; }
  const payload = verifiedPayload;
  const token = startOperation()!;
  status.textContent = rotate ? "Rotating recovery code…" : "Creating recovery code…";
  try {
    await ensureWasm();
    assertCurrent(token);
    const output = await downloadUpdatedAleth(payload, secret, rotate ? "-rotated-recovery" : "-with-recovery", token, secret, generate_recovery_secret());
    if (!output.recovery_code) throw new Error("Recovery code was not generated.");
    recoveryCodeText.value = "";
    rotatedRecoveryText.value = "";
    recoveryCodeDisplay.hidden = true;
    rotatedRecoveryDisplay.hidden = true;
    (rotate ? rotatedRecoveryText : recoveryCodeText).value = output.recovery_code;
    (rotate ? rotatedRecoveryDisplay : recoveryCodeDisplay).hidden = false;
    status.textContent = rotate ? "Recovery code rotated for the downloaded file. Earlier copies still accept their original code." : "Recovery code created for the downloaded file. Save the code separately.";
  } catch (e) { report(e, token); }
  finally { finishOperation(token); }
}
createRecoveryButton.addEventListener("click", () => void changeRecovery(false));
rotateRecoveryButton.addEventListener("click", () => void changeRecovery(true));
function copyCode(field: HTMLTextAreaElement): void {
  field.select();
  status.className = "status";
  status.textContent = document.execCommand("copy") ? "Recovery code copied to clipboard." : "Select and copy the recovery code manually.";
}
copyRecoveryButton.addEventListener("click", () => copyCode(recoveryCodeText));
copyRotatedRecoveryButton.addEventListener("click", () => copyCode(rotatedRecoveryText));
recoverButton.addEventListener("click", async () => {
  if (!selectedFile || busy) return;
  const code = recoveryInput.value.trim();
  const next = recoverNewPass.value;
  if (!code || !next || next !== recoverConfirmPass.value) { report(new Error("Enter a recovery code and matching new passphrases."), generation); return; }
  const rotate = el<HTMLInputElement>("recover-rotate").checked;
  const token = startOperation()!;
  clearVerifiedState();
  result.hidden = true;
  status.textContent = "Authenticating recovery code and verifying complete history…";
  let plaintext: Uint8Array | null = null;
  let sealed: Uint8Array | null = null;
  try {
    await ensureWasm();
    const blob = await sourceBlob(token);
    assertCurrent(token);
    plaintext = open_aleth_v2_recovery(blob, code);
    // No download or envelope rewrite until the entire protocol history passes.
    const verified = await verifiedPlaintext(plaintext);
    assertCurrent(token);
    const output = JSON.parse(recover_aleth_v2(blob, code, next, rotate)) as SealResult;
    sealed = decodeBlob(output.blob);
    downloadBlob(sealed, "-recovered", token);
    verifiedPayload = verified.payload;
    verifiedView = verified.view;
    renderView(verified.view);
    result.hidden = false;
    recoveryCodeText.value = "";
    recoveryCodeDisplay.hidden = true;
    rotatedRecoveryText.value = rotate ? output.recovery_code ?? "" : "";
    rotatedRecoveryDisplay.hidden = !rotate;
    status.textContent = rotate ? "History verified. Access recovered with a new passphrase and recovery code. Earlier file copies remain unchanged." : "History verified. Access recovered with a new passphrase. Existing recovery code preserved.";
  } catch (e) { report(e, token); }
  finally { plaintext?.fill(0); sealed?.fill(0); finishOperation(token); }
});

providerResponse.addEventListener("input", () => { pendingWriteback = null; acceptWritebackButton.disabled = true; writebackSummary.textContent = ""; });


// Only activeTab and scripting are required; capture always follows a user click.
type BrowserApi = {
  tabs: { query(options: {active: boolean; currentWindow: boolean}): Promise<Array<{id?: number; url?: string}>> };
  scripting: { executeScript(options: {target: {tabId: number}; func: (...args: any[]) => any; args?: any[]}): Promise<Array<{result?: any}>> };
  runtime: {sendMessage(message: unknown): Promise<{ok: boolean; capture?: ReturnType<typeof captureChatFromPage>; error?: string}>};
};
const browserApi = (globalThis as unknown as {chrome?: BrowserApi}).chrome;
const browserAvailable = !!browserApi?.tabs?.query && !!browserApi?.scripting?.executeScript;
const captureButton = el<HTMLButtonElement>("capture-chat");
const captureReview = el<HTMLTextAreaElement>("capture-review");
const captureSave = el<HTMLButtonElement>("capture-save");
const captureAppend = el<HTMLButtonElement>("capture-append");
const capturePassphrase = el<HTMLInputElement>("capture-passphrase");
const captureConfirmPassphrase = el<HTMLInputElement>("capture-confirm-passphrase");
const captureName = el<HTMLInputElement>("capture-name");
const captureWarning = el<HTMLElement>("capture-warning");
const MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024;
let captureMetadata: Record<string, unknown> = {provider: "manual", scope: "user-supplied-transcript"};
let contextFileUrl: string | null = null;

function clearContextFile(): void {
  if (contextFileUrl) URL.revokeObjectURL(contextFileUrl);
  contextFileUrl = null;
  const link = el<HTMLAnchorElement>("context-file-link");
  link.hidden = true;
  link.removeAttribute("href");
}
function refreshContextFile(text: string): void {
  clearContextFile();
  contextFileUrl = URL.createObjectURL(new Blob([text], {type: "text/plain;charset=utf-8"}));
  const link = el<HTMLAnchorElement>("context-file-link");
  link.href = contextFileUrl;
  link.download = "context.txt";
  link.hidden = false;
}
function downloadText(text: string, name: string): void {
  const url = URL.createObjectURL(new Blob([text], {type: "text/plain;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function reviewedCapture(): Record<string, unknown> {
  const text = captureReview.value.trim();
  const encoder = new TextEncoder();
  if (encoder.encode(text).byteLength > MAX_TRANSCRIPT_BYTES) throw new Error("La conversación revisada supera el límite de 2 MiB. Reduce el texto antes de guardarlo.");
  const messages: Array<{role: string; content: string}> = [];
  const headers = Array.from(text.matchAll(/^(user|assistant|unknown):\s*$/gm));
  for (let i = 0; i < headers.length; i++) {
    const header = headers[i];
    const end = headers[i + 1]?.index ?? text.length;
    const content = text.slice(header.index! + header[0].length, end).trim();
    if (content) messages.push({role: header[1], content});
  }
  if (!messages.length || (headers[0]?.index ?? 0) > 0) {
    messages.splice(0, messages.length, {role: "unknown", content: text});
  }
  const snapshot = {text, messages, capture: {...captureMetadata, reviewed_at: new Date().toISOString(), user_reviewed: true, attribution: "user-reviewed snapshot; page origin is not provider verification"}};
  if (encoder.encode(canonicalizeJson(snapshot)).byteLength > MAX_CAPTURE_CONTENT_BYTES) throw new Error("El contenido de la memoria supera el límite de 8 MiB. Reduce la conversación antes de guardarla.");
  return snapshot;
}
async function activeChatTab(): Promise<number> {
  if (!browserAvailable) throw new Error("Esta acción necesita la extensión. Copia el contexto o descarga context.txt.");
  const [tab] = await browserApi!.tabs.query({active: true, currentWindow: true});
  if (tab?.id === undefined) throw new Error("No se encontró una pestaña activa.");
  return tab.id;
}
captureReview.addEventListener("input", () => {
  captureMetadata = {...captureMetadata, edited: true};
  captureWarning.textContent = "Texto editado por ti. El origen indica la página capturada; no acredita la autoría ni la verificación del proveedor.";
  updateButtons();
});
function installCapturedChat(captured: ReturnType<typeof captureChatFromPage>): void {
  if (!captured?.messages?.length) throw new Error("No se encontraron mensajes. Pega o importa la conversación para continuar.");
  captureReview.value = captured.messages.map(message => `${message.role}:\n${message.content}`).join("\n\n");
  captureMetadata = {title: captured.title, url: captured.url, provider: captured.provider, captured_at: captured.captured_at, scope: captured.scope, warning: captured.warning ?? null};
  el<HTMLElement>("capture-meta").textContent = `${captured.provider} · ${captured.title} · ${captured.url} · ${captured.captured_at}`;
  captureWarning.textContent = captured.warning || "Solo mensajes cargados en la página. Revisa el resultado: puede faltar historial.";
  captureName.value = captured.title.slice(0, 100) || "mi-memoria";
  el<HTMLElement>("capture-summary").textContent = `✓ ${captured.messages.length} mensajes capturados de «${captured.title}». No necesitas ningún archivo previo.`;
  status.textContent = "Chat capturado. Revisa el texto, elige una contraseña y pulsa «Cifrar este chat y descargar mi memoria».";
}
async function captureCurrentChat(automatic = false): Promise<boolean> {
  const token = startOperation();
  if (token === null) return false;
  status.textContent = "Leyendo los mensajes cargados en esta página…";
  try {
    const [tab] = await browserApi!.tabs.query({active: true, currentWindow: true});
    if (!tab?.id) throw new Error("No se encontró una pestaña de chat abierta.");
    if (tab.url && /^(chrome-extension:|chrome:|edge:|about:)/.test(tab.url)) {
      throw new Error("Abre tu conversación de IA y pulsa el icono ✋ de Alethech en esa pestaña. No necesitas crear ni seleccionar un archivo.");
    }
    const tabId = tab.id;
    assertCurrent(token);
    const [execution] = await browserApi!.scripting.executeScript({target: {tabId}, func: captureChatFromPage});
    assertCurrent(token);
    const captured = execution?.result as ReturnType<typeof captureChatFromPage> | undefined;
    if (!captured) throw new Error("No se recibió la captura de la página.");
    installCapturedChat(captured);
    if (!automatic) captureReview.focus();
    return true;
  } catch (error) {
    report(error, token);
    if (token === generation) el<HTMLElement>("capture-summary").textContent = "No se pudo leer este chat. Puedes volver a capturarlo o pegar aquí su conversación.";
    return false;
  }
  finally { finishOperation(token); }
}
captureButton.addEventListener("click", () => { void captureCurrentChat(); });
el<HTMLButtonElement>("save-current-chat").addEventListener("click", async () => {
  if (busy) return;
  if (!captureReview.value.trim() && !(await captureCurrentChat())) return;
  capturePassphrase.focus();
  capturePassphrase.scrollIntoView({block: "center", behavior: "smooth"});
  status.className = "status";
  status.textContent = "Solo falta elegir una contraseña y repetirla. Después pulsa «Cifrar este chat y descargar mi memoria».";
});
el<HTMLInputElement>("transcript-file").addEventListener("change", async event => {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file || busy) return;
  const token = startOperation();
  if (token === null) return;
  try {
    if (file.size > MAX_TRANSCRIPT_BYTES) throw new Error("La conversación debe ser menor de 2 MiB.");
    const text = await file.text();
    assertCurrent(token);
    if (!text.trim()) throw new Error("La conversación está vacía.");
    captureReview.value = text;
    captureMetadata = {provider: "manual", scope: "user-supplied-transcript", source_filename: file.name, captured_at: new Date().toISOString()};
    captureName.value = file.name.replace(/\.(txt|json)$/i, "");
    el<HTMLElement>("capture-meta").textContent = `Importado: ${file.name}`;
    captureWarning.textContent = "Conversación importada. Revisa el texto completo y elimina lo que no quieras guardar.";
    el<HTMLElement>("capture-summary").textContent = "Conversación importada: lista para crear tu primera memoria.";
    status.textContent = "Importación lista para revisar.";
  } catch (error) { report(error, token); }
  finally { finishOperation(token); }
});
captureSave.addEventListener("click", async () => {
  if (busy || !captureReview.value.trim()) return;
  const secret = capturePassphrase.value;
  if (!secret || secret !== captureConfirmPassphrase.value) { report(new Error("Introduce una contraseña y repítela exactamente."), generation); return; }
  let content: Record<string, unknown>;
  try { content = reviewedCapture(); }
  catch (error) { report(error, generation); return; }
  const name = (captureName.value.trim().replace(/\.aleth$/i, "").replace(/[<>:"/\\|?*\x00-\x1f]/g, "-").slice(0,100) || "mi-memoria") + ".aleth";
  const token = startOperation()!;
  status.textContent = "Creando identidad local, firmando y cifrando la memoria…";
  let plaintext: Uint8Array | null = null;
  let sealed: Uint8Array | null = null;
  try {
    const payload = await createPortableMemory(content);
    const view = await verifyPortablePayload(payload);
    await ensureWasm();
    assertCurrent(token);
    plaintext = canonicalPortablePayloadBytes(payload);
    const output = JSON.parse(seal_aleth_v2(plaintext, secret, generate_recovery_secret())) as SealResult;
    if (!output.recovery_code) throw new Error("No se pudo crear el código de recuperación.");
    sealed = decodeBlob(output.blob);
    // Install the new container only after signing, verification and sealing succeed.
    selectedFile = new File([sealed], name, {type: "application/octet-stream"});
    downloadBlob(sealed, "", token);
    clearVerifiedState();
    verifiedPayload = payload;
    verifiedView = view;
    recoveryCodeText.value = output.recovery_code;
    recoveryCodeDisplay.hidden = false;
    rotatedRecoveryText.value = "";
    rotatedRecoveryDisplay.hidden = true;
    renderView(view);
    result.hidden = false;
    status.textContent = "Archivo .aleth descargado. Guarda también el código de recuperación por separado.";
  } catch (error) { report(error, token); }
  finally { plaintext?.fill(0); sealed?.fill(0); finishOperation(token); }
});
captureAppend.addEventListener("click", async () => {
  if (busy || !verifiedPayload || !captureReview.value.trim()) return;
  const secret = passphrase.value;
  if (!secret) { report(new Error("Vuelve a introducir la contraseña de la memoria abierta."), generation); return; }
  let content: Record<string, unknown>;
  try { content = reviewedCapture(); }
  catch (error) { report(error, generation); return; }
  const payload = verifiedPayload;
  const token = startOperation()!;
  try {
    const appended = await appendPortableMemory(payload, content, {source: "browser_capture_reviewed"});
    assertCurrent(token);
    await downloadUpdatedAleth(appended.payload, secret, "-updated", token);
    status.textContent = "Conversación añadida y archivo descargado. Recuperación conservada.";
  } catch (error) { report(error, token); }
  finally { finishOperation(token); }
});
function contextForSharing(): string {
  if (!verifiedView) throw new Error("Abre y verifica una memoria primero.");
  const ids = selectedMemoryIds();
  if (!ids.length) throw new Error("Selecciona al menos una memoria para compartir.");
  const text = toContextText(verifiedView, {include_ids: ids});
  chatContext.value = text;
  chatContext.hidden = false;
  contextHint.hidden = false;
  refreshContextFile(text);
  return text;
}
el<HTMLButtonElement>("insert-context").addEventListener("click", async () => {
  if (busy) return;
  const token = startOperation()!;
  try {
    const text = contextForSharing();
    const tabId = await activeChatTab();
    assertCurrent(token);
    const [execution] = await browserApi!.scripting.executeScript({target: {tabId}, func: insertContextIntoPage, args: [text]});
    assertCurrent(token);
    if (!execution?.result?.ok) throw new Error(execution?.result?.reason || "No se pudo insertar. Copia el contexto o adjunta context.txt.");
    status.textContent = "Contexto insertado como borrador. Revísalo y envíalo desde la IA cuando quieras.";
  } catch (error) { report(error, token); }
  finally { finishOperation(token); }
});
el<HTMLButtonElement>("copy-context").addEventListener("click", () => {
  if (busy) return;
  try {
    contextForSharing();
    chatContext.focus();
    chatContext.select();
    status.textContent = document.execCommand("copy") ? "Contexto copiado. Pégalo en otra IA o IDE." : "Selecciona el texto y cópialo manualmente.";
  } catch (error) { report(error, generation); }
});
el<HTMLButtonElement>("download-context").addEventListener("click", () => {
  if (busy) return;
  try { downloadText(contextForSharing(), "context.txt"); status.textContent = "context.txt descargado para adjuntar a otra IA o IDE."; }
  catch (error) { report(error, generation); }
});
el<HTMLAnchorElement>("context-file-link").addEventListener("dragstart", event => {
  if (!contextFileUrl || busy) { event.preventDefault(); return; }
  event.dataTransfer?.setData("DownloadURL", `text/plain:context.txt:${contextFileUrl}`);
});
el<HTMLButtonElement>("download-recovery-code").addEventListener("click", () => {
  if (recoveryCodeText.value) downloadText(recoveryCodeText.value + "\n", "aleth-recovery-code.txt");
});
el<HTMLButtonElement>("download-rotated-recovery").addEventListener("click", () => {
  if (rotatedRecoveryText.value) downloadText(rotatedRecoveryText.value + "\n", "aleth-recovery-code.txt");
});
if (!browserAvailable) {
  document.body.classList.add("standalone");
  captureButton.hidden = true;
  el<HTMLButtonElement>("save-current-chat").hidden = true;
  el<HTMLButtonElement>("insert-context").hidden = true;
  captureWarning.textContent = "Pega o importa una conversación, revisa el contenido y crea tu archivo .aleth local.";
  el<HTMLElement>("capture-heading").textContent = "✋ Crea tu primera memoria";
  el<HTMLElement>("first-memory-help").textContent = "Este archivo HTML no puede leer otra pestaña. Para capturar el chat automáticamente, usa el icono de la extensión en tu conversación. Aquí puedes pegar un chat y cifrarlo sin tener ningún archivo previo.";
  el<HTMLElement>("capture-summary").textContent = "Pega aquí tu conversación para crear y descargar su memoria cifrada.";
  captureReview.placeholder = "Pega aquí tu chat. No necesitas un archivo de memoria previo.";
}
document.addEventListener("change", event => {
  if ((event.target as HTMLElement)?.classList?.contains("memory-select")) {
    chatContext.value = "";
    chatContext.hidden = true;
    clearContextFile();
  }
});
window.addEventListener("pagehide", () => {
  generation++;
  currentBlob?.fill(0);
  currentBlob = null;
  clearVerifiedState();
  captureReview.value = "";
  capturePassphrase.value = "";
  captureConfirmPassphrase.value = "";
  passphrase.value = "";
  recoveryInput.value = "";
  recoverNewPass.value = "";
  recoverConfirmPass.value = "";
  recoveryCodeText.value = "";
  rotatedRecoveryText.value = "";
});
updateButtons();
// Opening the toolbar action is the user gesture that grants temporary activeTab
// access. Read into the local preview; sign, encrypt and download only on Save.
if (browserAvailable) {
  const pendingCapture = new URLSearchParams(location.hash.slice(1)).get("capture");
  if (pendingCapture) {
    // The floating brain passes only captured text through the extension worker.
    // Passwords and signing keys remain inside this isolated extension page.
    const token = startOperation()!;
    void (async () => {
      try {
        const response = await browserApi!.runtime.sendMessage({type: "alethech.take-capture", token: pendingCapture});
        assertCurrent(token);
        if (!response?.ok || !response.capture) throw new Error("La captura ya no está disponible. Vuelve al chat y pulsa su cerebro flotante.");
        installCapturedChat(response.capture);
        history.replaceState(null, "", location.pathname);
      } catch (error) { report(error, token); }
      finally { finishOperation(token); }
    })();
  } else void captureCurrentChat(true);
}
