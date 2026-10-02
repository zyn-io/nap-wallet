# napbrowser — the Nap browser (DECISIONS §152)

Sites open in a web view of their own, beside the wallet, the way Phantom's
and Jupiter's apps do it:

- **Separate web view, no app access.** A plain WKWebView (iOS) / WebView in a
  full-screen dialog (Android) — not Tauri's. No IPC, no wallet origin, no
  `napvault`. Its one door is the provider bridge.
- **Provider:** injected at document start into the main frame of https pages
  (http only on localhost): `nap:announceProvider` + `window.zyn`, the same
  interface as the extension and Nap in the browser (apps/nap-connect).
- **Origin from the platform:** `WKScriptMessage.frameInfo.securityOrigin` /
  androidx.webkit `WebMessageListener` source origin, main frame only. A page
  cannot claim another site's origin.
- **Requests** reach the wallet page as `request` events and are served by
  `apps/nap-web/src/nap-browser.js` with connect-ops' methods. Connecting and
  every write are approved in a native sheet over the site; Approve arms after
  0.8 s.

Commands (`plugin:napbrowser|…`): `open {url}` ('' = start page), `close`,
`respond {id, json}`, `approve {kicker, title, rows, note, danger}` →
`{approved}`; event `request {id, origin, method, params}`.

The app's own view never navigates away (`src-tauri/src/lib.rs`): outside
links and new windows open here instead — off the UI thread, since waiting
for the browser on it froze Android.

Checked 25 Sep 2026: Android emulator end to end with Cave Jade on testnet
(`tests/browser.android.e2e.mjs`: start page, separate web view, provider
without app internals, Jade finds "Nap Wallet · Nap app", connect and buy
approved in native sheets, filled); outside navigation routed here. iOS 26.2
simulator: start page, Cave Jade under the address bar, the approval sheet,
and a site's `nap_session`/`zyn_curves` reaching the wallet with the origin
WebKit reported and the answers reaching the page.
