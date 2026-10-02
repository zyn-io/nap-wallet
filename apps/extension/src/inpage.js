// What a site sees: Nap's provider, announced the way EIP-6963 has wallets do
// it (`nap:requestProvider` / `nap:announceProvider`, see apps/nap-connect),
// and as `window.zyn` for older pages. Every call goes to Nap's own window in
// the extension, which asks the holder before anything about them is shared
// or anything moves.
(() => {
  if (window.zyn) return;
  let seq = 0;
  const pending = new Map();
  class NapError extends Error {
    constructor(code, message) { super(message); this.code = code; }
  }
  window.addEventListener('message', (ev) => {
    if (ev.source !== window || !ev.data || ev.data.target !== 'nap-inpage') return;
    const p = pending.get(ev.data.id);
    if (!p) return;
    pending.delete(ev.data.id);
    const e = ev.data.error;
    if (e) p.reject(new NapError(Number(e.code) || -32603, String(e.message || 'Nap refused')));
    else p.resolve(ev.data.result === undefined ? null : ev.data.result);
  });
  const request = ({ method, params } = {}) => new Promise((resolve, reject) => {
    if (typeof method !== 'string') { reject(new NapError(-32602, 'method is required')); return; }
    const id = `${Date.now().toString(36)}.${++seq}`;
    pending.set(id, { resolve, reject });
    window.postMessage({ target: 'nap-content', id, method, params: params || {} }, location.origin);
  });
  const provider = Object.freeze({ isNap: true, isNapExtension: true, request });
  Object.defineProperty(window, 'zyn', { value: provider, writable: false, configurable: false });
  window.dispatchEvent(new Event('zyn#initialized'));
  const info = Object.freeze({ uuid: crypto.randomUUID(), name: 'Nap Wallet', detail: 'Extension', rdns: 'win.cavebro.nap.extension', icon: '' });
  const announce = () => window.dispatchEvent(new CustomEvent('nap:announceProvider', { detail: Object.freeze({ info, provider }) }));
  window.addEventListener('nap:requestProvider', announce);
  announce();
})();
