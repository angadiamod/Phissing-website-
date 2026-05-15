const DEFAULT = "https://smart-share-hub-2.preview.emergentagent.com/api";
const $ = (id) => document.getElementById(id);

chrome.storage.sync.get("apiBase", ({ apiBase }) => {
  $("api-base").value = apiBase || DEFAULT;
});

$("save").addEventListener("click", () => {
  const v = $("api-base").value.trim().replace(/\/$/, "");
  chrome.storage.sync.set({ apiBase: v }, () => {
    $("status").textContent = "✓ Saved. Reload tab to apply.";
    $("status").style.color = "#00FF66";
  });
});
