import type { CaptureChatResult } from "./chat-page-bridge.ts";

const LIMIT = 2 * 1024 * 1024;
const TTL = 5 * 60 * 1000;
const POPUP = chrome.runtime.getURL("popup.html");
type PendingCapture = { capture: CaptureChatResult; tab: Promise<number>; expires: number; timer: ReturnType<typeof setTimeout> };
// Intentionally volatile: a worker restart discards pending captures and fails closed.
const pending = new Map<string, PendingCapture>();

function sourceUrl(value: unknown): URL {
  if (typeof value !== "string") throw new Error("Missing source URL.");
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) throw new Error("Invalid source URL.");
  url.username = ""; url.password = ""; url.search = ""; url.hash = "";
  return url;
}
function allowedSource(url: URL): boolean {
  return (chrome.runtime.getManifest().content_scripts ?? []).some(script => script.matches?.some(pattern => {
    // Manifest patterns are trusted configuration; preserve their path restrictions.
    const expression = pattern.replace(":*", "__PORT_WILDCARD__")
      .replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")
      .replace("__PORT_WILDCARD__", "(?::[0-9]+)?");
    return new RegExp(`^${expression}$`).test(url.href);
  }));
}
function validatedCapture(input: unknown, source: URL): CaptureChatResult {
  if (!input || typeof input !== "object") throw new Error("Invalid capture.");
  const raw = input as Record<string, unknown>;
  if (raw.scope !== "current-page-dom" || typeof raw.title !== "string" || raw.title.length > 1000
    || typeof raw.url !== "string" || raw.url.length > 16384 || typeof raw.captured_at !== "string"
    || raw.captured_at.length > 64 || !Number.isFinite(Date.parse(raw.captured_at))
    || !["chatgpt", "claude", "gemini", "unknown"].includes(raw.provider as string)
    || !Array.isArray(raw.messages) || !raw.messages.length || raw.messages.length > 10000) throw new Error("Invalid capture schema.");
  if (sourceUrl(raw.url).href !== source.href) throw new Error("Capture source mismatch.");
  const messages: CaptureChatResult["messages"] = [];
  let bytes = 0;
  const encoder = new TextEncoder();
  for (const message of raw.messages) {
    if (!message || typeof message !== "object" || !["user", "assistant", "unknown"].includes(message.role)
      || typeof message.content !== "string" || !message.content.trim() || message.content.length > LIMIT) throw new Error("Invalid capture message.");
    bytes += encoder.encode(message.content).byteLength;
    if (bytes > LIMIT) throw new Error("Capture exceeds 2 MiB.");
    messages.push({ role: message.role, content: message.content });
  }
  const host = source.hostname;
  const provider = /^(chatgpt\.com|chat\.openai\.com)$/.test(host) ? "chatgpt"
    : host === "claude.ai" ? "claude" : host === "gemini.google.com" ? "gemini" : "unknown";
  const capture: CaptureChatResult = {
    title: raw.title.replace(/[\u0000-\u001f\u007f]/g, " "), url: source.href, provider,
    captured_at: new Date().toISOString(), messages, scope: "current-page-dom",
    warning: "Only rendered text currently loaded on the source page was captured. Review speaker roles and content before saving; earlier history and provider memory may be absent.",
  };
  if (encoder.encode(JSON.stringify(capture)).byteLength > LIMIT) throw new Error("Capture exceeds 2 MiB.");
  return capture;
}
function discard(token: string): void {
  const entry = pending.get(token);
  if (entry) clearTimeout(entry.timer);
  pending.delete(token);
}
async function handle(message: any, sender: chrome.runtime.MessageSender): Promise<unknown> {
  if (sender.id !== chrome.runtime.id) throw new Error("Invalid sender.");
  if (message.type === "alethech.open-capture") {
    if (sender.frameId !== 0 || typeof sender.tab?.id !== "number" || !sender.tab.url) throw new Error("Capture requires the source tab.");
    const source = sourceUrl(sender.tab.url);
    if (!allowedSource(source) || sourceUrl(sender.url).href !== source.href) throw new Error("Source is not supported.");
    const capture = validatedCapture(message.capture, source);
    // Bound retained content even if a compromised supported page repeats requests.
    if (pending.size >= 8) throw new Error("Too many pending captures. Close a review tab first.");
    const token = crypto.randomUUID();
    let resolveTab!: (id: number) => void;
    let rejectTab!: (reason: Error) => void;
    const tab = new Promise<number>((resolve, reject) => { resolveTab = resolve; rejectTab = reject; });
    void tab.catch(() => {});
    const entry: PendingCapture = { capture, tab, expires: Date.now() + TTL, timer: setTimeout(() => discard(token), TTL) };
    pending.set(token, entry);
    try {
      const created = await chrome.tabs.create({ url: `${POPUP}#capture=${token}`, active: true });
      if (typeof created.id !== "number") throw new Error("No review tab was created.");
      resolveTab(created.id);
      return { ok: true };
    } catch (error) {
      rejectTab(new Error("Review tab could not be opened."));
      discard(token);
      throw error;
    }
  }
  if (message.type === "alethech.take-capture") {
    if (typeof message.token !== "string" || !/^[a-f0-9-]{36}$/.test(message.token)
      || !sender.tab || typeof sender.tab.id !== "number" || sender.frameId !== 0 || typeof sender.url !== "string") throw new Error("Invalid review request.");
    const url = new URL(sender.url);
    if (url.href.split("#")[0] !== POPUP || url.search) throw new Error("Capture is restricted to its review page.");
    const entry = pending.get(message.token);
    if (!entry || entry.expires <= Date.now()) throw new Error("Capture expired or already used.");
    // Wait for tabs.create to finish if the page asks before its tab ID is assigned.
    const tabId = await entry.tab;
    if (sender.tab.id !== tabId || pending.get(message.token) !== entry || entry.expires <= Date.now()) throw new Error("Invalid or expired review tab.");
    discard(message.token);
    return { ok: true, capture: entry.capture };
  }
  throw new Error("Unknown request.");
}
chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (!message || !["alethech.open-capture", "alethech.take-capture"].includes(message.type)) return false;
  void handle(message, sender).then(respond, () => respond({ ok: false, error: "Capture unavailable. Capture the source page again." }));
  return true;
});
chrome.tabs.onRemoved.addListener(tabId => {
  for (const [token, entry] of pending) void entry.tab.then(id => { if (id === tabId) discard(token); }, () => {});
});
chrome.tabs.onUpdated.addListener((tabId, change) => {
  if (!change.url) return;
  for (const [token, entry] of pending) void entry.tab.then(id => {
    if (id === tabId && change.url && change.url.split("#")[0] !== POPUP) discard(token);
  }, () => {});
});
