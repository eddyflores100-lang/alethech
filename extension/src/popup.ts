import initWasm, { open_aleth_payload } from "./vendor/wasm/alethech_wasm.js";
import { verifyPortableLegacyPayload } from "../../alethech-ts/portable-verifier.ts";

let selectedFile: File | null = null;
let wasmReady: Promise<unknown> | null = null;

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const drop = el<HTMLElement>("drop");
const fileInput = el<HTMLInputElement>("file");
const passphrase = el<HTMLInputElement>("passphrase");
const openButton = el<HTMLButtonElement>("open");
const filename = el<HTMLElement>("filename");
const status = el<HTMLElement>("status");
const result = el<HTMLElement>("result");

function ensureWasm(): Promise<unknown> {
  if (!wasmReady) wasmReady = initWasm();
  return wasmReady;
}

function choose(file: File | null): void {
  selectedFile = file;
  filename.textContent = file ? file.name : "";
  openButton.disabled = !file;
  result.hidden = true;
  status.className = "status";
  status.textContent = file ? "Ready to unlock locally." : "No memory loaded.";
}

fileInput.addEventListener("change", () => choose(fileInput.files?.[0] ?? null));
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
    const payload = JSON.parse(new TextDecoder().decode(plaintext));
    const view = await verifyPortableLegacyPayload(payload);

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
