// Bridges a page's Nap provider (inpage.js) to Nap's connect window.
//
// Requests go over a runtime port to connect.html, the extension page that
// holds the keys and asks the holder; the browser tells that page which
// origin the port belongs to. If the window is not open, the background opens
// it and this script connects once it answers. Closing the window rejects
// whatever was waiting, as closing Nap in the browser does.

const s = document.createElement('script');
s.src = chrome.runtime.getURL('inpage.js');
s.onload = () => s.remove();
(document.head || document.documentElement).appendChild(s);

const pending = new Map(); // page request id -> { approved }, while Nap holds it
let port = null;
const toPage = (msg) => window.postMessage({ target: 'nap-inpage', ...msg }, location.origin);

/// After an extension update this page's script is cut off from Nap.
const cutOff = (e) => /context invalidated/i.test(String(e?.message || e));
const CUT_OFF = 'Nap was updated. Reload this page to reach it again.';

/// One attempt to reach an open connect window: resolves once it says ready.
function tryConnect() {
  return new Promise((resolve, reject) => {
    let p;
    try { p = chrome.runtime.connect({ name: 'nap-site' }); } catch (e) { reject(e); return; }
    const timer = setTimeout(() => { try { p.disconnect(); } catch { /* gone */ } reject(new Error('no answer')); }, 1500);
    p.onDisconnect.addListener(() => { clearTimeout(timer); void chrome.runtime.lastError; reject(new Error('closed')); });
    p.onMessage.addListener(function first(m) {
      if (!m || m.nap !== 'ready') return;
      clearTimeout(timer);
      p.onMessage.removeListener(first);
      resolve(p);
    });
  });
}

function adopt(p) {
  port = p;
  p.onMessage.addListener((m) => {
    if (!m) return;
    // The holder approved: if the window closes now, say so.
    if (m.nap === 'progress' && pending.has(m.id)) { pending.get(m.id).approved = true; return; }
    // The window needs the holder: bring it forward.
    if (m.nap === 'attention') { try { chrome.runtime.sendMessage({ kind: 'nap:open' }).catch(() => {}); } catch { /* cut off */ } return; }
    if (m.nap !== 'response' || !pending.has(m.id)) return;
    pending.delete(m.id);
    toPage({ id: m.id, result: m.result, error: m.error });
  });
  p.onDisconnect.addListener(() => {
    if (port === p) port = null;
    for (const [id, job] of pending) {
      toPage({ id, error: { code: 4900, message: job.approved ? "Nap's window was closed after you approved. Check your wallet before trying again." : "Nap's window was closed. Nothing was approved." } });
    }
    pending.clear();
  });
  return p;
}

/// The port to Nap, opening its window first when `open` is set. One attempt
/// at a time: requests fired together share it, so they cannot open two
/// windows.
let reaching = null;
function reach(open) {
  if (port) return Promise.resolve(port);
  if (reaching && (!open || reaching.open)) return reaching.promise;
  const promise = (async () => {
    try { return adopt(await tryConnect()); } catch (e) { if (cutOff(e)) throw new Error(CUT_OFF); }
    if (!open) return null;
    let r;
    try { r = await chrome.runtime.sendMessage({ kind: 'nap:open' }); } catch (e) { throw new Error(cutOff(e) ? CUT_OFF : "Nap's window did not open"); }
    if (r && r.error) throw new Error(r.error);
    for (let i = 0; i < 20; i++) {
      try { return adopt(await tryConnect()); } catch { await new Promise((ok) => setTimeout(ok, 300)); }
    }
    throw new Error("Nap's window did not open");
  })().finally(() => { if (reaching?.promise === promise) reaching = null; });
  reaching = { open, promise };
  return promise;
}

window.addEventListener('message', async (ev) => {
  if (ev.source !== window || !ev.data || ev.data.target !== 'nap-content') return;
  const { id, method, params } = ev.data;
  if (typeof method !== 'string') return;
  try {
    // Asking whether a session exists, or forgetting the site, never opens a
    // window by itself: with no window there is no session to report or end.
    const quiet = method === 'nap_session' || method === 'nap_disconnect';
    const p = await reach(!quiet);
    if (!p) { toPage({ id, result: method === 'nap_disconnect' ? true : null }); return; }
    pending.set(id, { approved: false });
    p.postMessage({ nap: 'request', id, method, params: params && typeof params === 'object' ? params : {} });
  } catch (e) {
    pending.delete(id);
    toPage({ id, error: { code: 4900, message: e.message || 'Nap could not be reached' } });
  }
});
