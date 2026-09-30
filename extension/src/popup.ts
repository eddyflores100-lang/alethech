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
  updateButtons();
}
function updateButtons(): void {
  openButton.disabled = busy || !selectedFile;
  saveButton.disabled = busy || !verifiedPayload || !newMemory.value.trim();
  acceptWritebackButton.disabled = busy || !pendingWriteback;
  updateRekeyButton();
  updateRecoveryButtons();
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
  recoveryInput.value = "";
  recoverNewPass.value = "";
  recoverConfirmPass.value = "";
  recoveryCodeText.value = "";
  rotatedRecoveryText.value = "";
  recoveryCodeDisplay.hidden = true;
  rotatedRecoveryDisplay.hidden = true;
  selectedFile = file && file.size <= MAX_FILE_SIZE ? file : null;
  filename.textContent = file ? file.name : "";
  result.hidden = true;
  status.className = file && !selectedFile ? "status error" : "status";
  status.textContent = file && !selectedFile ? "File exceeds the 512 MiB container limit." : file ? "Ready to unlock or recover locally." : "No memory loaded.";
  updateButtons();
}

fileInput.addEventListener("change", () => choose(fileInput.files?.[0] ?? null));
newMemory.addEventListener("input", () => { saveButton.disabled = !verifiedPayload || !newMemory.value.trim(); });
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
  status.textContent = "All visible memories selected.";
});

clearSelectionButton.addEventListener("click", () => {
  if (busy) return;
  for (const input of document.querySelectorAll<HTMLInputElement>(".memory-select")) {
    input.checked = false;
  }
  status.className = "status";
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
