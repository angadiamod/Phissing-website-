# PhishSentinel Chrome Extension

Manifest V3 browser extension that auto-scans every page you visit using the
PhishSentinel backend (URL + visual cloning + DB + crawler intel).

## Features
- Auto-scans every http(s) page on load (1-hour cache per host)
- Action badge shows the final risk score with traffic-light color
- Desktop notification on PHISHING verdict
- Popup with full breakdown (ML / CNN / DB) and impersonated brand
- One-click report → opens the PhishSentinel dashboard
- Configurable backend URL in extension options

## Install (Developer Mode, Chrome / Edge / Brave)

1. Open `chrome://extensions` (or `edge://extensions`)
2. Toggle **Developer mode** ON (top-right)
3. Click **Load unpacked**
4. Select this folder (`chrome_extension/`)
5. The PhishSentinel icon appears in your toolbar — pin it

## Configure
Right-click the icon → **Options** → set the API base URL if your backend is
elsewhere (default points to the Emergent preview).

## Files
- `manifest.json` — Manifest V3 declaration
- `background.js` — Service worker, runs auto-scans + caches
- `popup.html / popup.js / popup.css` — Toolbar popup UI
- `options.html / options.js` — Settings page
- `content.js` — Lets web pages query the scanner via `window.postMessage`
- `icon.png` — 128×128 logo (add your own)

## Add the icon
Drop any 128×128 PNG named `icon.png` into this folder. A simple shield logo
works great. The extension still loads without it but Chrome will show a
placeholder icon.

## Example: scan from any page (via content script)
```js
window.postMessage({ type: "phishsentinel:scan", url: location.href }, "*");
window.addEventListener("message", (e) => {
  if (e.data?.type === "phishsentinel:result") console.log(e.data.payload);
});
```
