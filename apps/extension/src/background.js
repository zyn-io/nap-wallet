// The extension's background: it opens Nap's connect window, and nothing else.
//
// The wallet lives in the extension's own pages (the popup, and connect.html
// for sites), which hold the keys; sites talk to connect.html directly over a
// runtime port from the content script. This worker keeps no state a site
// depends on, so the browser may stop it between events without dropping a
// request — only the window's id is kept, in session storage, to focus the
// window rather than open a second one.

const CONNECT = 'connect.html';

/// One window, however many tabs ask at once: a second call waits for the
/// first rather than opening another (two windows would both answer).
let opening = null;
function openConnect() {
  if (!opening) opening = openConnectNow().finally(() => { opening = null; });
  return opening;
}

async function openConnectNow() {
  // One already open (say the worker restarted and lost its note): focus it.
  // getContexts lists this extension's own pages with no extra permission
  // (Chrome 116+); Firefox goes by the note alone.
  const url = chrome.runtime.getURL(CONNECT);
  const found = chrome.runtime.getContexts
    ? (await chrome.runtime.getContexts({ contextTypes: ['TAB'], documentUrls: [url] }).catch(() => []))[0]
    : null;
  if (found && found.windowId >= 0) {
    await chrome.windows.update(found.windowId, { focused: true });
    await chrome.storage.session.set({ connectWindow: found.windowId });
    return;
  }
  const { connectWindow } = await chrome.storage.session.get('connectWindow');
  if (connectWindow != null) {
    try {
      await chrome.windows.update(connectWindow, { focused: true });
      return;
    } catch { /* closed since; open another */ }
  }
  const win = await chrome.windows.create({ url: chrome.runtime.getURL(CONNECT), type: 'popup', width: 440, height: 680, focused: true });
  await chrome.storage.session.set({ connectWindow: win.id });
}

chrome.windows.onRemoved.addListener(async (id) => {
  const { connectWindow } = await chrome.storage.session.get('connectWindow');
  if (connectWindow === id) await chrome.storage.session.remove('connectWindow');
});

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  // Only a site's content script asks, and only to have the window opened.
  if (!msg || msg.kind !== 'nap:open' || !sender.tab) return false;
  openConnect().then(() => reply({ ok: true }), (e) => reply({ error: e.message }));
  return true;
});
