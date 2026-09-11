// Bridges the page's window.zyn to the extension's background worker.
const s = document.createElement('script');
s.src = chrome.runtime.getURL('inpage.js');
s.onload = () => s.remove();
(document.head || document.documentElement).appendChild(s);

window.addEventListener('message', async (ev) => {
  if (ev.source !== window || !ev.data || ev.data.target !== 'zyn-content') return;
  const { id, method, params } = ev.data;
  try {
    const result = await chrome.runtime.sendMessage({ kind: 'provider', method, params, origin: location.origin });
    if (result && result.error) throw new Error(result.error);
    window.postMessage({ target: 'zyn-inpage', id, result }, '*');
  } catch (e) {
    window.postMessage({ target: 'zyn-inpage', id, error: e.message }, '*');
  }
});
