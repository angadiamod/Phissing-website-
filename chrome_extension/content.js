// Minimal content script — lets the page query PhishSentinel via window.postMessage
window.addEventListener("message", (e) => {
  if (e.source !== window) return;
  if (e.data?.type !== "phishsentinel:scan") return;
  chrome.runtime.sendMessage({ type: "scan", url: e.data.url }, (res) => {
    window.postMessage({ type: "phishsentinel:result", payload: res }, "*");
  });
});
