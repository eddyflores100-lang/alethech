/** These functions are serialized by chrome.scripting.executeScript. Keep all
 * runtime dependencies inside each function; module imports are not available
 * in the target page's isolated world. No network, storage, or send actions. */
export type CapturedChatMessage = { role: "user" | "assistant" | "unknown"; content: string };
export type CaptureChatResult = {
  title: string;
  url: string;
  provider: "chatgpt" | "claude" | "gemini" | "unknown";
  captured_at: string;
  messages: CapturedChatMessage[];
  scope: "current-page-dom";
  warning?: string;
};
export type InsertContextResult = { ok: boolean; reason?: string; insertedCharacters?: number };

/** Capture rendered, currently loaded transcript text, never backend history. */
export function captureChatFromPage(): CaptureChatResult {
  const limit = 2 * 1024 * 1024;
  const encoder = new TextEncoder();
  const visible = (node: Element): boolean => {
    for (let current: Element | null = node; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      if (current.hasAttribute("hidden") || current.getAttribute("aria-hidden") === "true"
        || style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    }
    return true;
  };
  const excluded = "form,input,textarea,select,button,[contenteditable]:not([contenteditable='false']),script,style,noscript,[hidden],[aria-hidden='true'],[data-sensitive],[autocomplete='current-password'],[autocomplete='new-password']";
  const cleanText = (node: Element): string => {
    // Walk the original tree so CSS-hidden descendants cannot reappear in a clone.
    const chunks: string[] = [];
    const visit = (item: Node): void => {
      if (item.nodeType === Node.TEXT_NODE) {
        if (item.textContent) chunks.push(item.textContent);
        return;
      }
      if (!(item instanceof Element) || item.matches(excluded) || !visible(item)) return;
      const block = /^(DIV|P|PRE|LI|UL|OL|H[1-6]|BLOCKQUOTE|BR|SECTION|ARTICLE)$/.test(item.tagName);
      if (block) chunks.push("\n");
      for (const child of item.childNodes) visit(child);
      if (block) chunks.push("\n");
    };
    visit(node);
    return chunks.join("").replace(/\r/g, "").replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  };
  const url = new URL(location.href);
  url.search = "";
  url.hash = "";
  url.username = "";
  url.password = "";
  const host = url.hostname;
  const provider: CaptureChatResult["provider"] = /(^|\.)(chatgpt\.com|chat\.openai\.com)$/.test(host) ? "chatgpt"
    : /(^|\.)claude\.ai$/.test(host) ? "claude"
    : host === "gemini.google.com" ? "gemini" : "unknown";
  const result: CaptureChatResult = {
    title: document.title.slice(0, 1000), url: url.href, provider,
    captured_at: new Date().toISOString(), messages: [], scope: "current-page-dom",
    warning: "Only rendered messages currently loaded on this page are captured; earlier history and provider memory may be absent.",
  };
  const selectors = "[data-message-author-role='user'],[data-message-author-role='assistant'],[data-testid='user-message'],[data-testid='assistant-message'],[data-role='user'],[data-role='assistant'],.font-user-message,.font-claude-message,user-query,model-response";
  const candidates = Array.from(document.querySelectorAll(selectors));
  for (const node of candidates) {
    // Prefer the outer message when provider markup nests equivalent wrappers.
    if (node.parentElement?.closest(selectors) || !visible(node) || node.closest(excluded)) continue;
    const content = cleanText(node);
    if (!content) continue;
    const roleAttr = node.getAttribute("data-message-author-role") ?? node.getAttribute("data-role");
    const role: CapturedChatMessage["role"] = roleAttr === "user" || node.matches("[data-testid='user-message'],.font-user-message,user-query") ? "user" : "assistant";
    result.messages.push({ role, content });
    if (encoder.encode(JSON.stringify(result)).byteLength > limit) throw new Error("Current-page capture exceeds the 2 MiB limit. Select a smaller transcript.");
  }
  if (!result.messages.length) {
    // Unknown page layouts are explicitly labeled and never assigned invented roles.
    const selection = window.getSelection();
    let content = "";
    if (selection && !selection.isCollapsed && selection.rangeCount) {
      // Rebuild selection text from allowed text nodes rather than reading raw
      // selection.toString(), which can include hidden or editable descendants.
      const range = selection.getRangeAt(0);
      const root = range.commonAncestorContainer.nodeType === Node.ELEMENT_NODE
        ? range.commonAncestorContainer as Element : range.commonAncestorContainer.parentElement;
      if (root && !root.closest(excluded) && visible(root)) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        const chunks: string[] = [];
        let item: Node | null;
        while ((item = walker.nextNode())) {
          const parent = item.parentElement;
          if (!parent || parent.closest(excluded) || !visible(parent) || !range.intersectsNode(item)) continue;
          const value = item.textContent ?? "";
          const start = item === range.startContainer ? range.startOffset : 0;
          const end = item === range.endContainer ? range.endOffset : value.length;
          chunks.push(value.slice(start, end));
        }
        content = chunks.join("\n").trim();
      }
    }
    if (content) result.warning += " Selected page text was captured with unknown speaker roles.";
    else {
      const main = document.querySelector("main,[role='main']");
      if (main && visible(main)) content = cleanText(main);
      if (content) result.warning += " Main-page text was captured as a generic fallback with unknown speaker roles; review it before saving.";
    }
    if (content) result.messages.push({ role: "unknown", content });
  }
  if (!result.messages.length) throw new Error("No visible conversation text found on this page.");
  if (encoder.encode(JSON.stringify(result)).byteLength > limit) throw new Error("Current-page capture exceeds the 2 MiB limit. Select a smaller transcript.");
  return result;
}

/** Called only after an explicit user action. Inserts a draft and never sends it. */
export function insertContextIntoPage(text: string): InsertContextResult {
  if (typeof text !== "string" || !text.trim()) return { ok: false, reason: "Context text is empty." };
  if (new TextEncoder().encode(text).byteLength > 2 * 1024 * 1024) return { ok: false, reason: "Context exceeds the 2 MiB limit." };
  const visible = (node: Element): boolean => {
    for (let current: Element | null = node; current; current = current.parentElement) {
      const style = getComputedStyle(current);
      if (current.hasAttribute("hidden") || current.getAttribute("aria-hidden") === "true"
        || style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return false;
    }
    return true;
  };
  const usable = (node: Element): node is HTMLTextAreaElement | HTMLElement => {
    if (!visible(node) || node.closest("[inert],[data-sensitive]")) return false;
    const purpose = ["id", "name", "aria-label", "placeholder", "autocomplete"].map(name => node.getAttribute(name) ?? "").join(" ");
    if (/password|passphrase|api[-_ ]?key|secret|access[-_ ]?token/i.test(purpose)) return false;
    if (node instanceof HTMLTextAreaElement) return !node.disabled && !node.readOnly;
    return node instanceof HTMLElement && node.isContentEditable && node.getAttribute("aria-disabled") !== "true";
  };
  const selectors = "textarea,[contenteditable='true'],[contenteditable='plaintext-only']";
  const all = Array.from(document.querySelectorAll(selectors)).filter(usable);
  const focused = document.activeElement?.closest(selectors);
  const known = all.filter(node => node.matches("#prompt-textarea,[data-testid='chat-input'],[data-placeholder*='Reply'],[aria-label*='prompt' i],[aria-label*='message' i],.ProseMirror,.ql-editor"));
  const target = focused && usable(focused) ? focused : known.length === 1 ? known[0] : all.length === 1 ? all[0] : null;
  if (!target) return { ok: false, reason: "Focus an empty chat editor; no unambiguous writable editor was found." };
  const existing = target instanceof HTMLTextAreaElement ? target.value : target.textContent ?? "";
  if (existing.length) return { ok: false, reason: "The editor already contains text. Clear it before inserting context." };
  target.focus();
  if (target instanceof HTMLTextAreaElement) {
    const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")?.set;
    if (!setter) return { ok: false, reason: "The editor value setter is unavailable." };
    setter.call(target, text);
  } else {
    target.textContent = text;
  }
  target.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: text }));
  return { ok: true, insertedCharacters: text.length };
}
