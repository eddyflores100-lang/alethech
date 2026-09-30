import initWasm, { open_aleth_payload, seal_aleth_payload } from "./vendor/wasm/alethech_wasm.js";
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

function ensureWasm(): Promise<unknown> {
  if (!wasmReady) wasmReady = initWasm();
  return wasmReady;
}

function renderView(view: VerifiedPortableView): void {
  el<HTMLElement>("head").textContent = view.head.slice(0, 20) + "…";
  el<HTMLElement>("count").textContent = String(view.entries.length);
  const memories = el<HTMLElement>("memories");
  memories.replaceChildren();
  for (const entry of view.entries.slice(-20)) {
    const node = document.createElement("div");
    node.className = "memory";
    node.textContent = JSON.stringify(entry.content, null, 2);
    memories.appendChild(node);
  }
  saveButton.disabled = !verifiedPayload || !newMemory.value.trim();
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
  chatContext.value = toContextText(verifiedView, { limit: 20 });
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
    const request = preparePluginRequest(
      { payload: verifiedPayload!, view: verifiedView },
      providerMode.value as PluginProviderKind,
      prompt,
      { limit: selectedContextLimit() },
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
