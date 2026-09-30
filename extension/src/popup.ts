import initWasm, { open_aleth_payload, seal_aleth_payload, seal_aleth_v2, open_aleth_v2_recovery, recover_aleth_v2, generate_recovery_secret } from "./vendor/wasm/alethech_wasm.js";
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
  if (!wasmReady) wasmReady = initWasm();
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
  saveButton.disabled = !verifiedPayload || !newMemory.value.trim();
  updateRecoveryButtons();
}

function clearVerifiedState(): void {
  verifiedPayload = null;
  verifiedView = null;
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

async function downloadUpdatedAleth(
  payload: PortablePayload,
  secret: string,
  suffix: string,
): Promise<void> {
  if (!selectedFile) throw new Error("No source .aleth selected.");
  await ensureWasm();
  const plaintext = canonicalPortablePayloadBytes(payload);
  let sealed: Uint8Array | null = null;
  try {
    sealed = seal_aleth_payload(plaintext, secret);
    const blob = new Blob([sealed], { type: "application/octet-stream" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const base = selectedFile.name.replace(/\.aleth$/i, "") || "memory";
    link.href = href;
    link.download = base + suffix + ".aleth";
    link.click();
    URL.revokeObjectURL(href);
  } finally {
    plaintext.fill(0);
    if (sealed) sealed.fill(0);
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
    !verifiedPayload ||
    !newPassphrase.value ||
    !confirmPassphrase.value;
}

newPassphrase.addEventListener("input", updateRekeyButton);
confirmPassphrase.addEventListener("input", updateRekeyButton);

function choose(file: File | null): void {
  clearVerifiedState();
  selectedFile = file;
  filename.textContent = file ? file.name : "";
  openButton.disabled = !file;
  result.hidden = true;
  status.className = "status";
  status.textContent = file ? "Ready to unlock locally." : "No memory loaded.";
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
  if (!selectedFile) return;
  const secret = passphrase.value;
  if (!secret) {
    status.className = "status error";
    status.textContent = "Enter the passphrase.";
    return;
  }

  openButton.disabled = true;
  status.className = "status";
  status.textContent = "Authenticating and verifying…";
  result.hidden = true;

  let plaintext: Uint8Array | null = null;
  try {
    await ensureWasm();
    const blob = new Uint8Array(await selectedFile.arrayBuffer());
    plaintext = open_aleth_payload(blob, secret);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as PortablePayload;
    const view = await verifyPortablePayload(payload);
    verifiedPayload = payload;
    verifiedView = view;
    renderView(view);

    status.textContent = "Container authenticated. Protocol history verified.";
    result.hidden = false;
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    if (plaintext) plaintext.fill(0);
    passphrase.value = "";
    openButton.disabled = !selectedFile;
  }
});


saveButton.addEventListener("click", async () => {
  if (!verifiedPayload || !verifiedView || !selectedFile) return;
  const text = newMemory.value.trim();
  const secret = passphrase.value;
  if (!text) return;
  if (!secret) {
    status.className = "status error";
    status.textContent = "Re-enter the passphrase to encrypt the updated memory.";
    return;
  }

  saveButton.disabled = true;
  status.className = "status";
  status.textContent = "Signing, verifying, and encrypting updated memory…";

  let plaintext: Uint8Array | null = null;
  let sealed: Uint8Array | null = null;
  try {
    await ensureWasm();
    const appended = await appendPortableMemory(
      verifiedPayload,
      { text },
      { source: "browser_extension" },
    );
    const view = await verifyPortablePayload(appended.payload);
    plaintext = canonicalPortablePayloadBytes(appended.payload);
    sealed = seal_aleth_payload(plaintext, secret);

    const blob = new Blob([sealed], { type: "application/octet-stream" });
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    const base = selectedFile.name.replace(/\.aleth$/i, "") || "memory";
    link.href = href;
    link.download = base + "-updated.aleth";
    link.click();
    URL.revokeObjectURL(href);

    verifiedPayload = appended.payload;
    verifiedView = view;
    newMemory.value = "";
    renderView(view);
    status.textContent = "Updated memory verified and downloaded.";
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    if (plaintext) plaintext.fill(0);
    if (sealed) sealed.fill(0);
    passphrase.value = "";
    saveButton.disabled = !verifiedPayload || !newMemory.value.trim();
  }
});


prepareContextButton.addEventListener("click", () => {
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
  if (!verifiedPayload || !verifiedView || !pendingWriteback) return;
  const secret = passphrase.value;
  if (!secret) {
    status.className = "status error";
    status.textContent = "Re-enter the passphrase to encrypt the accepted writeback.";
    return;
  }

  acceptWritebackButton.disabled = true;
  status.className = "status";
  status.textContent = "Signing accepted writeback locally and reverifying…";
  try {
    const accepted = await acceptPluginWriteback(
      { payload: verifiedPayload, view: verifiedView },
      pendingWriteback,
    );
    await downloadUpdatedAleth(accepted.payload, secret, "-writeback");
    verifiedPayload = accepted.payload;
    verifiedView = accepted.view;
    pendingWriteback = null;
    providerResponse.value = "";
    writebackSummary.textContent = "";
    renderView(accepted.view);
    status.textContent = "Writeback signed locally, verified, and downloaded.";
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    passphrase.value = "";
    acceptWritebackButton.disabled = !pendingWriteback;
  }
});


selectAllButton.addEventListener("click", () => {
  for (const input of document.querySelectorAll<HTMLInputElement>(".memory-select")) {
    input.checked = true;
  }
  status.className = "status";
  status.textContent = "All visible memories selected.";
});

clearSelectionButton.addEventListener("click", () => {
  for (const input of document.querySelectorAll<HTMLInputElement>(".memory-select")) {
    input.checked = false;
  }
  status.className = "status";
  status.textContent = "Memory sharing selection cleared.";
});


rekeyButton.addEventListener("click", async () => {
  if (!verifiedPayload || !selectedFile) return;
  const next = newPassphrase.value;
  const confirm = confirmPassphrase.value;
  if (!next) {
    status.className = "status error";
    status.textContent = "Enter a new passphrase.";
    return;
  }
  if (next !== confirm) {
    status.className = "status error";
    status.textContent = "New passphrases do not match.";
    return;
  }

  rekeyButton.disabled = true;
  status.className = "status";
  status.textContent = "Re-encrypting the same verified memory with a new passphrase…";
  try {
    await downloadUpdatedAleth(verifiedPayload, next, "-rekeyed");
    status.textContent = "Passphrase rotated locally. Memory history was not changed.";
    newPassphrase.value = "";
    confirmPassphrase.value = "";
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    newPassphrase.value = "";
    confirmPassphrase.value = "";
    updateRekeyButton();
  }
});

// ============================================================
// Recovery code handlers
// ============================================================

function updateRecoveryButtons(): void {
  // "Create recovery code" is enabled only when a verified payload is loaded.
  // "Rotate recovery code" is enabled only when a verified payload is loaded
  // and the user has NOT yet created a recovery code in this session.
  // "Recover access" button is enabled when the recovery-input field has
  // content and the new passphrase fields match.
  const canCreate = !!verifiedPayload && !!selectedFile;
  createRecoveryButton.disabled = !canCreate || !recoveryCodeDisplay.hidden;
  rotateRecoveryButton.disabled = !canCreate;

  const rc = recoveryInput.value.trim();
  const np = recoverNewPass.value;
  const cp = recoverConfirmPass.value;
  recoverButton.disabled = !rc || !np || np !== cp;
}

recoveryInput.addEventListener("input", updateRecoveryButtons);
recoverNewPass.addEventListener("input", updateRecoveryButtons);
recoverConfirmPass.addEventListener("input", updateRecoveryButtons);

async function downloadRecoveryAleth(
  plaintext: Uint8Array,
  passphrase: string,
  recoverySecretB64: string,
  suffix: string,
): Promise<{ recoveryCode: string; containerId: string }> {
  if (!selectedFile) throw new Error("No source .aleth selected.");
  await ensureWasm();
  const resultJson = seal_aleth_v2(plaintext, passphrase, recoverySecretB64);
  const result = JSON.parse(resultJson) as { blob: string; recovery_code: string | null; container_id: string };
  if (!result.recovery_code) throw new Error("Internal: recovery code was not generated.");

  // Decode the blob from base64url to Uint8Array
  const blob = Uint8Array.from(
    atob(result.blob.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
  const url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  const base = (selectedFile.name.replace(/\.aleth$/i, "") || "memory");
  link.href = url;
  link.download = base + suffix + ".aleth";
  link.click();
  URL.revokeObjectURL(url);

  return { recoveryCode: result.recovery_code, containerId: result.container_id };
}

createRecoveryButton.addEventListener("click", async () => {
  if (!verifiedPayload || !selectedFile) return;
  const pass = passphrase.value;
  if (!pass) {
    status.className = "status error";
    status.textContent = "Re-enter the current passphrase to create a recovery code.";
    return;
  }

  createRecoveryButton.disabled = true;
  status.className = "status";
  status.textContent = "Generating recovery code…";

  let plaintext: Uint8Array | null = null;
  try {
    await ensureWasm();
    plaintext = canonicalPortablePayloadBytes(verifiedPayload);
    const secret = generate_recovery_secret();
    const { recoveryCode } = await downloadRecoveryAleth(plaintext, pass, secret, "-with-recovery");

    recoveryCodeText.value = recoveryCode;
    recoveryCodeDisplay.hidden = false;
    status.textContent = "Recovery code created. Downloaded a new .aleth with the recovery slot added.";
    status.className = "status";
    updateRecoveryButtons();
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    if (plaintext) plaintext.fill(0);
    passphrase.value = "";
    createRecoveryButton.disabled = false;
  }
});

copyRecoveryButton.addEventListener("click", () => {
  recoveryCodeText.select();
  document.execCommand("copy");
  status.textContent = "Recovery code copied to clipboard.";
});

rotateRecoveryButton.addEventListener("click", async () => {
  if (!verifiedPayload || !selectedFile) return;
  const pass = passphrase.value;
  if (!pass) {
    status.className = "status error";
    status.textContent = "Re-enter the current passphrase to rotate the recovery code.";
    return;
  }

  rotateRecoveryButton.disabled = true;
  status.className = "status";
  status.textContent = "Rotating recovery code…";

  let plaintext: Uint8Array | null = null;
  try {
    await ensureWasm();
    plaintext = canonicalPortablePayloadBytes(verifiedPayload);
    const secret = generate_recovery_secret();
    const { recoveryCode } = await downloadRecoveryAleth(plaintext, pass, secret, "-rotated-recovery");

    rotatedRecoveryText.value = recoveryCode;
    rotatedRecoveryDisplay.hidden = false;
    status.textContent = "Recovery code rotated. The old recovery code no longer works.";
    status.className = "status";
    updateRecoveryButtons();
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    if (plaintext) plaintext.fill(0);
    passphrase.value = "";
    rotateRecoveryButton.disabled = false;
  }
});

copyRotatedRecoveryButton.addEventListener("click", () => {
  rotatedRecoveryText.select();
  document.execCommand("copy");
  status.textContent = "New recovery code copied to clipboard.";
});

recoverButton.addEventListener("click", async () => {
  if (!selectedFile) return;
  const code = recoveryInput.value.trim();
  const newPass = recoverNewPass.value;
  const confirmPass = recoverConfirmPass.value;
  if (!code) {
    status.className = "status error";
    status.textContent = "Enter the recovery code.";
    return;
  }
  if (!newPass) {
    status.className = "status error";
    status.textContent = "Enter a new passphrase.";
    return;
  }
  if (newPass !== confirmPass) {
    status.className = "status error";
    status.textContent = "New passphrases do not match.";
    return;
  }

  recoverButton.disabled = true;
  status.className = "status";
  status.textContent = "Recovering access…";

  try {
    await ensureWasm();
    const blob = new Uint8Array(await selectedFile.arrayBuffer());

    // Use recover_aleth_v2 to decrypt with recovery code and re-seal with new passphrase.
    // rotate_recovery=true so the old recovery code is invalidated.
    const resultJson = recover_aleth_v2(blob, code, newPass, true);
    const result = JSON.parse(resultJson) as { blob: string; recovery_code: string; container_id: string };

    // Decode the new blob
    const newBlob = Uint8Array.from(
      atob(result.blob.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );

    // Download the new .aleth
    const url = URL.createObjectURL(new Blob([newBlob], { type: "application/octet-stream" }));
    const link = document.createElement("a");
    const base = selectedFile.name.replace(/\.aleth$/i, "") || "memory";
    link.href = url;
    link.download = base + "-recovered.aleth";
    link.click();
    URL.revokeObjectURL(url);

    // Show the new recovery code
    rotatedRecoveryText.value = result.recovery_code;
    rotatedRecoveryDisplay.hidden = false;

    status.textContent = "Access recovered. A new .aleth was downloaded with the new passphrase and a new recovery code. The old recovery code is invalid.";
    status.className = "status";

    // Clear the recovery form
    recoveryInput.value = "";
    recoverNewPass.value = "";
    recoverConfirmPass.value = "";
    updateRecoveryButtons();
  } catch (e) {
    status.className = "status error";
    status.textContent = e instanceof Error ? e.message : String(e);
  } finally {
    recoverButton.disabled = false;
  }
});
