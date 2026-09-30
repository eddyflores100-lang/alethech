/** A page-side capture shortcut. Secrets and encryption stay in extension pages. */
import { captureChatFromPage } from "./chat-page-bridge.ts";

function installBrain(): void {
  if (!/^https?:$/.test(location.protocol) || document.getElementById("alethech-brain")) return;
  const lifetime = new AbortController();
  const button = document.createElement("button");
  button.id = "alethech-brain";
  button.type = "button";
  button.dataset.sensitive = "true";
  button.textContent = "🧠";
  button.title = "Alethech — arrastra para mover; pulsa para revisar y guardar la conversación";
  button.setAttribute("aria-label", "Capturar conversación con Alethech");
  button.style.cssText = "all:initial!important;position:fixed!important;z-index:2147483647!important;width:48px!important;height:48px!important;border-radius:50%!important;background:#7c5cff!important;color:white!important;border:2px solid #fff!important;box-shadow:0 4px 20px #0006!important;display:grid!important;place-items:center!important;font:24px sans-serif!important;cursor:grab!important;touch-action:none!important;user-select:none!important;";
  const status = document.createElement("div");
  status.dataset.sensitive = "true";
  status.setAttribute("role", "status");
  status.style.cssText = "position:fixed!important;bottom:76px!important;right:20px!important;z-index:2147483647!important;max-width:280px!important;background:#0d1117!important;color:#fff!important;padding:8px!important;border-radius:8px!important;font:12px/1.5 sans-serif!important;";
  status.hidden = true;
  let x = Math.max(0, innerWidth - 68), y = Math.max(0, innerHeight - 68);
  let pointer: { id: number; startX: number; startY: number; x: number; y: number } | null = null;
  let dragged = false;
  let pending = false;
  const position = () => {
    x = Math.max(0, Math.min(x, innerWidth - 48));
    y = Math.max(0, Math.min(y, innerHeight - 48));
    button.style.setProperty("left", `${x}px`, "important");
    button.style.setProperty("top", `${y}px`, "important");
  };
  position();
  const options = { signal: lifetime.signal };
  button.addEventListener("focus", () => button.style.setProperty("outline", "3px solid #7de2a8", "important"), options);
  button.addEventListener("blur", () => button.style.setProperty("outline", "none", "important"), options);
  button.addEventListener("pointerdown", (event) => {
    if (!event.isTrusted || !event.isPrimary || event.button !== 0) return;
    dragged = false;
    pointer = { id: event.pointerId, startX: event.clientX, startY: event.clientY, x, y };
    button.setPointerCapture(event.pointerId);
  }, options);
  button.addEventListener("pointermove", (event) => {
    if (!pointer || event.pointerId !== pointer.id) return;
    if (Math.hypot(event.clientX - pointer.startX, event.clientY - pointer.startY) > 5) dragged = true;
    if (dragged) {
      x = pointer.x + event.clientX - pointer.startX;
      y = pointer.y + event.clientY - pointer.startY;
      position();
    }
  }, options);
  button.addEventListener("pointerup", () => { pointer = null; }, options);
  button.addEventListener("pointercancel", () => { pointer = null; dragged = true; }, options);
  button.addEventListener("lostpointercapture", () => { pointer = null; }, options);
  button.addEventListener("click", async (event) => {
    if (!event.isTrusted || pending) return;
    if (dragged && event.detail !== 0) { dragged = false; return; }
    dragged = false;
    pending = true;
    button.setAttribute("aria-busy", "true");
    status.hidden = true;
    try {
      const capture = captureChatFromPage();
      const response = await chrome.runtime.sendMessage({ type: "alethech.open-capture", capture });
      if (!response?.ok) throw new Error("No se pudo abrir la revisión. Vuelve a intentarlo.");
    } catch (error) {
      // Only a bounded plain-text error appears on the host page.
      status.textContent = error instanceof Error ? error.message.slice(0, 240) : "No se pudo capturar la conversación.";
      status.hidden = false;
    } finally {
      pending = false;
      button.removeAttribute("aria-busy");
    }
  }, options);
  window.addEventListener("resize", position, options);
  window.addEventListener("pagehide", () => {
    lifetime.abort();
    button.remove();
    status.remove();
  }, { once: true, signal: lifetime.signal });
  document.body.append(button, status);
}
installBrain();
window.addEventListener("pageshow", installBrain);
