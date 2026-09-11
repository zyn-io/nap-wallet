// window.zyn — what a site sees. Every call goes to the extension, which
// asks the local wallet app; anything that moves value first opens an
// approval window the site cannot see or dismiss.
(() => {
  if (window.zyn) return;
  let seq = 0;
  const pending = new Map();
  window.addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.target !== 'zyn-inpage') return;
    const p = pending.get(ev.data.id);
    if (!p) return;
    pending.delete(ev.data.id);
    ev.data.error ? p.reject(new Error(ev.data.error)) : p.resolve(ev.data.result);
  });
  const request = ({ method, params }) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    window.postMessage({ target: 'zyn-content', id, method, params: params || {} }, '*');
  });
  Object.defineProperty(window, 'zyn', { value: Object.freeze({ isZynZap: true, request }), writable: false, configurable: false });
  window.dispatchEvent(new Event('zyn#initialized'));
})();
