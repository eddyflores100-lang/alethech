import initWasm, { open_aleth_payload, seal_aleth_payload } from "./vendor/wasm/alethech_wasm.js";
import { verifyPortablePayload, type PortablePayload, type VerifiedPortableView } from "../../alethech-ts/portable-verifier.ts";
import { appendPortableMemory, canonicalPortablePayloadBytes } from "../../alethech-ts/portable-editor.ts";

let selectedFile: File | null = null;
let wasmReady: Promise<unknown> | null = null;
let verifiedPayload: PortablePayload | null = null;
let verifiedView: VerifiedPortableView | null = null;

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
