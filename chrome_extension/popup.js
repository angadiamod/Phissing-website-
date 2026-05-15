const COLORS = { SAFE: "#00FF66", SUSPICIOUS: "#FFB800", PHISHING: "#FF3333" };
const root = document.getElementById("root");

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c]));
}

function renderResult(r) {
  const color = COLORS[r.verdict] || "#FFB800";
  root.innerHTML = `
    <div class="card" style="border-color:${color}66;">
      <div class="muted">VERDICT</div>
      <div class="verdict" style="color:${color}">${r.verdict}</div>
      <div class="muted">Final score <strong style="color:${color}">${r.final_score}</strong> / 100</div>
      <div class="score-row">
        <div class="score"><div class="score-label">ML</div><div class="score-value" style="color:#FF3333">${r.ml_score}</div></div>
        <div class="score"><div class="score-label">CNN</div><div class="score-value" style="color:#FFB800">${r.cnn_score}</div></div>
        <div class="score"><div class="score-label">DB</div><div class="score-value" style="color:#3388FF">${r.db_score}</div></div>
      </div>
      ${r.visual?.cloned_brand ? `
        <div class="brand-row">
          impersonates <strong>${escapeHtml(r.visual.cloned_brand)}</strong>
          · similarity <strong>${r.visual.similarity}%</strong>
          ${(r.visual.suspicious_elements||[]).map(s=>`<span class="tag" style="color:${color};border-color:${color}66">${escapeHtml(s)}</span>`).join("")}
        </div>` : ""}
    </div>
    <div class="url">${escapeHtml(r.url)}</div>
  `;
}

function renderError(msg) {
  root.innerHTML = `<div class="error">${escapeHtml(msg)}</div>
    <div class="muted" style="margin-top:8px">Check the backend URL in ⚙ options.</div>`;
}

async function getCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function scan(force = false) {
  const tab = await getCurrentTab();
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    renderError("Only http(s) pages can be scanned.");
    return;
  }
  const host = new URL(tab.url).hostname;

  if (!force) {
    const cached = await new Promise((res) => chrome.runtime.sendMessage({ type: "cached", host }, res));
    if (cached) { renderResult(cached); return; }
  }

  root.innerHTML = `<div class="card"><div class="spinner"></div><div class="muted">Running 22-feature ML · Gemini visual · DB lookup…</div></div>`;
  chrome.runtime.sendMessage({ type: "scan", url: tab.url }, (res) => {
    if (!res || res.error) { renderError(res?.error || "Scan failed"); return; }
    renderResult(res);
  });
}

document.getElementById("rescan-btn").addEventListener("click", () => scan(true));
document.getElementById("report-btn").addEventListener("click", async () => {
  const tab = await getCurrentTab();
  chrome.tabs.create({ url: `https://smart-share-hub-2.preview.emergentagent.com?report=${encodeURIComponent(tab.url)}` });
});
document.getElementById("options-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());

scan(false);
