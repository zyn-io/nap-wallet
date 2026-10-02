// The Nap browser's wallet half (DECISIONS §152) — the phone app only.
//
// Sites open in the app's own browser (the `napbrowser` plugin), a web view
// beside this one. Their requests arrive here as `request` events, named by
// the origin the platform reported for the page's main frame, and are served
// by the same methods Nap Connect serves everywhere else (connect-ops.js):
// public ones answer at once, anything about the holder needs the site
// connected first, and every write is shown as the chain prices it in a
// native sheet over the site before it is signed here.

import { ERR, METHODS, ProviderError, session } from './connect-ops.js';

const CONNECTED_KEY = 'nap.connected.v1';
const invoke = (cmd, args = {}) => window.__TAURI__.core.invoke(`plugin:napbrowser|${cmd}`, args);

const read = () => { try { return JSON.parse(localStorage.getItem(CONNECTED_KEY) || '{}') || {}; } catch { return {}; } };
const isConnected = (origin, net) => read()[origin]?.network === net;
function remember(origin, net) { const c = read(); c[origin] = { network: net, at: Date.now() }; try { localStorage.setItem(CONNECTED_KEY, JSON.stringify(c)); } catch { /* this session only */ } }
function forget(origin) { const c = read(); delete c[origin]; try { localStorage.setItem(CONNECTED_KEY, JSON.stringify(c)); } catch { /* nothing to forget */ } }

let current = null; // () => ({ config, identity, zec }) while the wallet is open, else null
let queue = Promise.resolve();

/// Start answering the browser. `state` says what is open right now.
export async function startBrowser(state) {
  current = state;
  await window.__TAURI__.core.addPluginListener('napbrowser', 'request', (ev) => {
    // One at a time: a second site's approval never covers the first's.
    queue = queue.then(() => serve(ev)).catch(() => {});
  });
}

export const openBrowser = (url = '') => invoke('open', { url });
export const closeBrowser = () => invoke('close').catch(() => {});

async function serve({ id, origin, method, params }) {
  let result;
  let error = null;
  try {
    let p = {};
    try { p = JSON.parse(params || '{}'); } catch { throw new ProviderError(ERR.PARAMS, 'params must be an object'); }
    result = await handle(String(origin), String(method), p && typeof p === 'object' ? p : {});
  } catch (e) {
    error = { code: e.code || -32603, message: String(e.message || e).slice(0, 300) };
  }
  await invoke('respond', { id, json: JSON.stringify(error ? { error } : { result: result === undefined ? null : result }) });
}

/// The wallet page's own Zcash account serves sites too — there is one
/// worker and one wallet in it. Its address is shared once the wallet has
/// opened it (until then a site is connected without one), and a payment
/// waits for the wallet's sync like any Send.
function context(config, identity, account) {
  const opened = () => account?.view && account.network === (config.zcashPrefix === 'u1' ? 'mainnet' : 'testnet');
  return {
    config,
    identity,
    zec: opened() ? async () => account.view : null,
    zecReady: account ? async () => {
      if (!opened()) throw new ProviderError(ERR.UNAUTHORIZED, "Nap's Zcash wallet is still opening. Try again in a moment.");
      return account;
    } : null,
  };
}

async function handle(origin, method, params) {
  const m = METHODS[method];
  if (!m) throw new ProviderError(ERR.UNSUPPORTED, `Nap does not do ${method}`);
  const host = new URL(origin).host;
  if (method === 'nap_disconnect') { forget(origin); return true; }
  const open = current?.();
  if (!open) {
    if (method === 'nap_session') return null;
    throw new ProviderError(ERR.UNAUTHORIZED, 'Nap is locked. Open it and try again.');
  }
  const { config, identity } = open;
  const ctx = context(config, identity, open.zec);
  if (method === 'nap_session') return isConnected(origin, config.id) ? session(ctx) : null;
  if (method === 'nap_connect' && params.network && params.network !== config.id) {
    throw new ProviderError(ERR.PARAMS, `Nap is on ${config.network}. Switch networks in Nap to use this site on ${params.network}.`);
  }
  if (m.kind === 'public') return m.run(ctx, params);

  if (!isConnected(origin, config.id)) {
    const { approved } = await invoke('approve', {
      kicker: `${host} asks`,
      title: `Connect ${host} to Nap`,
      rows: [
        ['It will see', `Your Zyn account ID${identity.zec ? ' and Zcash address' : ''}`],
        ['When it asks', 'Your ZEC.zy and token balances, your items, what you are owed, your sale tickets and the coins you made'],
        ['It will not see', 'Your keys or your recovery phrase'],
        ['Network', `${config.network} · ${config.zcash}`],
      ],
      note: 'It can ask you to approve payments and trades. Nothing moves unless you approve it here.',
      danger: false,
    });
    if (!approved) throw new ProviderError(ERR.REJECTED, 'The holder did not connect');
    remember(origin, config.id);
  }
  if (method === 'nap_connect') return session(ctx);
  if (m.kind === 'read' || m.kind === 'auto') return m.run(ctx, params);

  const plan = await m.prepare(ctx, params);
  const { approved } = await invoke('approve', {
    kicker: `${host} asks`,
    title: String(plan.title),
    rows: (plan.rows || []).map(([k, v]) => [String(k), String(v)]),
    note: String(plan.note || ''),
    danger: !!plan.danger,
  });
  if (!approved) throw new ProviderError(ERR.REJECTED, 'The holder rejected the request');
  return plan.run(() => {});
}
