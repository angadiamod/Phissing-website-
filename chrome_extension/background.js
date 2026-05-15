// PhishSentinel — background service worker
const DEFAULT_API = "https://smart-share-hub-2.preview.emergentagent.com/api";

async function getApiBase() {
  const { apiBase } = await chrome.storage.sync.get("apiBase");
  return apiBase || DEFAULT_API;
}

async function scanUrl(url) {
  const API = await getApiBase();
  const res = await fetch(`${API}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`scan ${res.status}`);
  return res.json();
}

// In-memory cache of recent verdicts (per host, 1h TTL)
const cache = new Map();
const TTL = 60 * 60 * 1000;

function cacheGet(host) {
  const hit = cache.get(host);
  if (hit && Date.now() - hit.ts < TTL) return hit.data;
  return null;
}
function cacheSet(host, data) {
  cache.set(host, { ts: Date.now(), data });
}

// Auto-scan when user navigates to a non-search top-level URL
chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !tab.url) return;
  try {
    const u = new URL(tab.url);
    if (!["http:", "https:"].includes(u.protocol)) return;
    if (/google\.com|bing\.com|duckduckgo\.com|emergentagent\.com|github\.com/.test(u.hostname)) return;

    const cached = cacheGet(u.hostname);
    let result = cached;
    if (!result) {
      result = await scanUrl(tab.url);
      cacheSet(u.hostname, result);
    }

    // Update badge
    const color = result.verdict === "PHISHING" ? "#FF3333"
                : result.verdict === "SUSPICIOUS" ? "#FFB800"
                : "#00FF66";
    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setBadgeText({ tabId, text: String(Math.round(result.final_score)) });

    // Notify on PHISHING verdict
    if (result.verdict === "PHISHING") {
      chrome.notifications.create(`phish-${u.hostname}`, {
        type: "basic",
        iconUrl: "icon.png",
        title: "⚠️ PhishSentinel — Phishing Detected",
        message: `${u.hostname} scored ${result.final_score} — likely phishing.`,
        priority: 2,
      });
    }
  } catch (e) {
    // Silently ignore — backend may be offline
    console.warn("PhishSentinel scan failed:", e.message);
  }
});

// Message handler for popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "scan") {
    scanUrl(msg.url).then(sendResponse).catch((e) => sendResponse({ error: e.message }));
    return true;
  }
  if (msg.type === "cached") {
    sendResponse(cacheGet(msg.host));
  }
});
