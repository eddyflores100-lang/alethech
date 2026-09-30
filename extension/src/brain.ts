/**
 * Alethech Brain — floating draggable content script.
 *
 * Injects a small animated brain into every page. The user can drag it
 * around the screen. Clicking the brain reads the page's text and opens
 * an inline panel to review, encrypt, and download a .aleth file.
 *
 * No WASM needed — uses Web Crypto API + scrypt-js from CDN (same as
 * capture.html). Everything is self-contained in this script.
 *
 * The brain is the "hand" the user asked for — it sits on the page,
 * you move it where you want, click it, and it "eats" the conversation.
 */

// ============================================================
// State
// ============================================================

let brainEl: HTMLDivElement | null = null;
let panelEl: HTMLDivElement | null = null;
let isDragging = false;
let dragOffset = { x: 0, y: 0 };
let panelOpen = false;

// ============================================================
// Brain creation
// ============================================================

function createBrain(): HTMLDivElement {
  const brain = document.createElement("div");
  brain.id = "alethech-brain";
  brain.style.cssText = `
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    z-index: 2147483647 !important;
    width: 48px !important;
    height: 48px !important;
    border-radius: 50% !important;
    background: linear-gradient(135deg, #7c5cff, #9d7fff) !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-size: 24px !important;
    cursor: grab !important;
    user-select: none !important;
    box-shadow: 0 4px 20px rgba(124, 92, 255, 0.5) !important;
    transition: transform 0.15s ease, box-shadow 0.15s ease !important;
    opacity: 0.85 !important;
    font-family: Arial, sans-serif !important;
  `;
  brain.innerHTML = "🧠";
  brain.title = "Alethech — Arrástrame y haz click para guardar esta página";

  // Hover effect
  brain.addEventListener("mouseenter", () => {
    brain.style.opacity = "1";
    brain.style.transform = "scale(1.1)";
    brain.style.boxShadow = "0 6px 30px rgba(124, 92, 255, 0.7)";
  });
  brain.addEventListener("mouseleave", () => {
    if (!isDragging) {
      brain.style.opacity = "0.85";
      brain.style.transform = "scale(1)";
      brain.style.boxShadow = "0 4px 20px rgba(124, 92, 255, 0.5)";
    }
  });

  // Dragging
  brain.addEventListener("mousedown", startDrag);
  brain.addEventListener("touchstart", startDragTouch, { passive: false });

  // Click to capture (but not after a drag)
  let mouseDownPos = { x: 0, y: 0 };
  brain.addEventListener("mousedown", (e) => {
    mouseDownPos = { x: e.clientX, y: e.clientY };
  });
  brain.addEventListener("mouseup", (e) => {
    const dx = Math.abs(e.clientX - mouseDownPos.x);
    const dy = Math.abs(e.clientY - mouseDownPos.y);
    if (dx < 5 && dy < 5) {
      // It was a click, not a drag
      togglePanel();
    }
  });

  // Touch click
  let touchStartPos = { x: 0, y: 0 };
  brain.addEventListener("touchstart", (e) => {
    const t = e.touches[0];
    touchStartPos = { x: t.clientX, y: t.clientY };
  }, { passive: false });
  brain.addEventListener("touchend", (e) => {
    const t = e.changedTouches[0];
    const dx = Math.abs(t.clientX - touchStartPos.x);
    const dy = Math.abs(t.clientY - touchStartPos.y);
    if (dx < 10 && dy < 10) {
      e.preventDefault();
      togglePanel();
    }
  });

  // Pulse animation
  setInterval(() => {
    if (!isDragging && !panelOpen) {
      brain.style.transform = "scale(1.05)";
      setTimeout(() => {
        if (!isDragging && !panelOpen) {
          brain.style.transform = "scale(1)";
        }
      }, 800);
    }
  }, 3000);

  return brain;
}

// ============================================================
// Dragging
// ============================================================

function startDrag(e: MouseEvent) {
  e.preventDefault();
  isDragging = true;
  brainEl!.style.cursor = "grabbing";
  brainEl!.style.transform = "scale(1.15)";
  const rect = brainEl!.getBoundingClientRect();
  dragOffset = {
    x: e.clientX - rect.left,
    y: e.clientY - rect.top,
  };
  document.addEventListener("mousemove", onDrag);
  document.addEventListener("mouseup", endDrag);
}

function startDragTouch(e: TouchEvent) {
  e.preventDefault();
  isDragging = true;
  brainEl!.style.cursor = "grabbing";
  const t = e.touches[0];
  const rect = brainEl!.getBoundingClientRect();
  dragOffset = {
    x: t.clientX - rect.left,
    y: t.clientY - rect.top,
  };
  document.addEventListener("touchmove", onDragTouch, { passive: false });
  document.addEventListener("touchend", endDrag);
}

function onDrag(e: MouseEvent) {
  if (!isDragging || !brainEl) return;
  let x = e.clientX - dragOffset.x;
  let y = e.clientY - dragOffset.y;
  // Keep within viewport
  x = Math.max(0, Math.min(x, window.innerWidth - 48));
  y = Math.max(0, Math.min(y, window.innerHeight - 48));
  brainEl.style.left = x + "px";
  brainEl.style.top = y + "px";
  brainEl.style.right = "auto";
  brainEl.style.bottom = "auto";
}

function onDragTouch(e: TouchEvent) {
  if (!isDragging || !brainEl) return;
  e.preventDefault();
  const t = e.touches[0];
  let x = t.clientX - dragOffset.x;
  let y = t.clientY - dragOffset.y;
  x = Math.max(0, Math.min(x, window.innerWidth - 48));
  y = Math.max(0, Math.min(y, window.innerHeight - 48));
  brainEl.style.left = x + "px";
  brainEl.style.top = y + "px";
  brainEl.style.right = "auto";
  brainEl.style.bottom = "auto";
}

function endDrag() {
  isDragging = false;
  if (brainEl) {
    brainEl.style.cursor = "grab";
    brainEl.style.transform = panelOpen ? "scale(1.1)" : "scale(1)";
  }
  document.removeEventListener("mousemove", onDrag);
  document.removeEventListener("touchmove", onDragTouch);
  document.removeEventListener("mouseup", endDrag);
  document.removeEventListener("touchend", endDrag);
}

// ============================================================
// Panel (inline overlay)
// ============================================================

function togglePanel() {
  if (panelOpen) {
    closePanel();
  } else {
    openPanel();
  }
}

function openPanel() {
  panelOpen = true;
  if (brainEl) {
    brainEl.style.transform = "scale(1.1)";
    brainEl.innerHTML = "✨";
  }

  // Read page text
  const pageText = readPageText();

  // Create panel
  panelEl = document.createElement("div");
  panelEl.id = "alethech-panel";
  panelEl.style.cssText = `
    position: fixed !important;
    top: 50% !important;
    left: 50% !important;
    transform: translate(-50%, -50%) !important;
    z-index: 2147483647 !important;
    width: 420px !important;
    max-width: 90vw !important;
    max-height: 80vh !important;
    overflow-y: auto !important;
    background: #0d1117 !important;
    border: 1px solid #29384c !important;
    border-radius: 16px !important;
    padding: 20px !important;
    box-shadow: 0 20px 60px rgba(0,0,0,0.6) !important;
    font-family: Inter, ui-sans-serif, system-ui, sans-serif !important;
    color: #e8edf6 !important;
  `;

  panelEl.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-size:20px;">🧠</span>
        <strong style="font-size:15px;color:#7de2a8;">Alethech — Guardar esta página</strong>
      </div>
      <button id="alethech-close" style="background:none;border:none;color:#8492a8;font-size:20px;cursor:pointer;padding:4px 8px;">✕</button>
    </div>
    <p style="font-size:12px;color:#65758d;margin:0 0 12px;">El cerebro leyó el texto visible de esta página. Revísalo, pon contraseña y descarga tu memoria cifrada.</p>
    <label style="display:block;font-size:12px;color:#94a1b5;margin-bottom:6px;">Texto de la conversación</label>
    <textarea id="alethech-content" rows="8" style="width:100%;border-radius:10px;border:1px solid #29384c;background:#08111e;color:white;padding:10px;font:12px/1.5 monospace;outline:none;resize:vertical;min-height:100px;">${escapeHtml(pageText.slice(0, 500000))}</textarea>
    <div style="display:flex;gap:8px;margin-top:8px;">
      <input id="alethech-filename" placeholder="Nombre" value="mi-memoria" style="flex:1;border-radius:8px;border:1px solid #29384c;background:#08111e;color:white;padding:8px;font:12px monospace;outline:none;height:36px;">
      <input id="alethech-pass" type="password" placeholder="Contraseña (8+)" style="flex:1;border-radius:8px;border:1px solid #29384c;background:#08111e;color:white;padding:8px;font:12px monospace;outline:none;height:36px;">
    </div>
    <input id="alethech-pass2" type="password" placeholder="Repite contraseña" style="width:100%;margin-top:8px;border-radius:8px;border:1px solid #29384c;background:#08111e;color:white;padding:8px;font:12px monospace;outline:none;height:36px;">
    <button id="alethech-encrypt" style="width:100%;height:42px;margin-top:12px;border:0;border-radius:10px;background:#7c5cff;color:white;font-weight:700;font-size:13px;cursor:pointer;" disabled>🔒 Cifrar y descargar .aleth</button>
    <div id="alethech-status" style="margin-top:8px;font-size:12px;color:#aeb9ca;min-height:16px;"></div>
    <p style="font-size:10px;color:#536279;margin:8px 0 0;text-align:center;">Todo se cifra en tu navegador. Nada se envía a internet.</p>
  `;

  document.body.appendChild(panelEl);

  // Close button
  document.getElementById("alethech-close")!.addEventListener("click", closePanel);

  // Enable/disable encrypt button
  const content = document.getElementById("alethech-content") as HTMLTextAreaElement;
  const pass = document.getElementById("alethech-pass") as HTMLInputElement;
  const pass2 = document.getElementById("alethech-pass2") as HTMLInputElement;
  const btn = document.getElementById("alethech-encrypt") as HTMLButtonElement;
  const status = document.getElementById("alethech-status")!;
  const name = document.getElementById("alethech-filename") as HTMLInputElement;

  function updateBtn() {
    btn.disabled = !content.value.trim() || pass.value.length < 8 || pass.value !== pass2.value;
  }
  [content, pass, pass2].forEach(e => e.addEventListener("input", updateBtn));

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.textContent = "Cifrando…";
    status.style.color = "#aeb9ca";
    try {
      const blob = await encryptText(content.value, pass.value);
      const filename = (name.value.trim() || "mi-memoria") + ".aleth";
      const url = URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
      status.textContent = "✓ Descargado: " + filename;
      status.style.color = "#7de2a8";
      pass.value = "";
      pass2.value = "";
      updateBtn();
    } catch (e: any) {
      status.textContent = "Error: " + (e.message || String(e));
      status.style.color = "#ff9b9b";
      btn.disabled = false;
    }
  });
}

function closePanel() {
  panelOpen = false;
  if (panelEl) {
    panelEl.remove();
    panelEl = null;
  }
  if (brainEl) {
    brainEl.style.transform = "scale(1)";
    brainEl.innerHTML = "🧠";
  }
}

// ============================================================
// Page text reader
// ============================================================

function readPageText(): string {
  // Try provider-specific selectors first
  const selectors = [
    "[data-message-author-role]",
    "[data-testid='user-message']",
    "[data-testid='assistant-message']",
    "[data-role='user']",
    "[data-role='assistant']",
    ".font-user-message",
    ".font-claude-message",
    "user-query",
    "model-response",
  ];

  const candidates = document.querySelectorAll(selectors.join(","));
  if (candidates.length > 0) {
    const parts: string[] = [];
    candidates.forEach((node) => {
      const el = node as HTMLElement;
      const role = el.getAttribute("data-message-author-role")
        || el.getAttribute("data-role")
        || (el.matches("[data-testid='user-message'],.font-user-message,user-query") ? "user" : "assistant");
      const text = el.innerText.trim();
      if (text) parts.push(role + ": " + text);
    });
    if (parts.length > 0) return parts.join("\n\n");
  }

  // Fallback: read body text (capped)
  return document.body.innerText.slice(0, 500000);
}

// ============================================================
// Encryption (Web Crypto + scrypt-js, same as capture.html)
// ============================================================

const MAGIC = new TextEncoder().encode("ALETH001");

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function canon(obj: any): string {
  if (obj === null) return "null";
  if (typeof obj !== "object") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canon).join(",") + "]";
  return "{" + Object.keys(obj).sort().map(k => JSON.stringify(k) + ":" + canon(obj[k])).join(",") + "}";
}

let scryptLib: any = null;
async function loadScrypt(): Promise<any> {
  if (scryptLib) return scryptLib;
  await new Promise<void>((res, rej) => {
    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/scrypt-js@3.0.1/scrypt.min.js";
    s.onload = () => res();
    s.onerror = () => rej(new Error("No se pudo cargar el módulo de cifrado. ¿Sin internet?"));
    document.head.appendChild(s);
  });
  scryptLib = (window as any).scrypt;
  return scryptLib;
}

async function encryptText(text: string, passphrase: string): Promise<Uint8Array> {
  const payload = {
    payload_version: 1,
    files: {
      "HEAD": b64url(new TextEncoder().encode("sha256:memory")),
      "commits/memory.json": b64url(new TextEncoder().encode(JSON.stringify({
        type: "MemoryCommit", version: 1, agent_id: "did:alethech:brain",
        key_id: "key-brain", parents: [], timestamp: new Date().toISOString(),
        session_id: crypto.randomUUID(), memory_type: "episodic",
        content: { conversation: text.slice(0, 500000) },
        provenance: { source: "brain_content_script", source_id: null, evidence_refs: [], confidence: 1.0 },
      }))),
    },
  };

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const header = {
    cipher: "AES-256-GCM", format: "aleth", kdf: "scrypt",
    nonce: b64url(nonce), salt: b64url(salt),
    scrypt_n: 32768, scrypt_p: 1, scrypt_r: 8, version: 1,
  };
  const headerBytes = new TextEncoder().encode(canon(header));
  const payloadBytes = new TextEncoder().encode(canon(payload));

  const scrypt = await loadScrypt();
  const keyBytes = new Uint8Array(scrypt(
    new TextEncoder().encode(passphrase), salt,
    { N: 32768, r: 8, p: 1, dkLen: 32, maxmem: 64 * 1024 * 1024 }
  ));

  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: headerBytes, tagLength: 128 },
    cryptoKey, payloadBytes
  ));

  const hlen = new Uint8Array(4);
  new DataView(hlen.buffer).setUint32(0, headerBytes.length, false);

  const blob = new Uint8Array(8 + 4 + headerBytes.length + encrypted.length);
  blob.set(MAGIC, 0);
  blob.set(hlen, 8);
  blob.set(headerBytes, 12);
  blob.set(encrypted, 12 + headerBytes.length);

  keyBytes.fill(0);
  return blob;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ============================================================
// Init
// ============================================================

// Only inject on HTTP(S) pages (not chrome://, not file://)
if (location.protocol === "http:" || location.protocol === "https:") {
  // Avoid double-injection
  if (!document.getElementById("alethech-brain")) {
    brainEl = createBrain();
    document.body.appendChild(brainEl);
  }
}
