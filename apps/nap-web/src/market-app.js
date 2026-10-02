// Nap Market: swap, pools and launches on the object ledger, from the browser.
//
// The same origin as the wallet, on purpose: the kept key, the chain route and
// the content policy are the wallet's, so this page is not a second place a key
// can live or a second endpoint a holder has to trust.
//
// Nothing here asks the chain what an account holds. Balances come from opening
// published notes with the holder's own viewing key; what the market owes comes
// from claim ids only this wallet can derive. The node learns what a sequencer
// must — the intents — and the public learns pool reserves and sale totals.

import { endSession, loadSession, saveSession } from './session.js';
import { checkedEpoch, deriveIdentity, forgetIdentity, openSealedWallet, parseAmount } from './core.js';
import { hex, nullifierOf, scan, unhex } from './object.js';
import * as ledger from './ledger.js';
import { isHex, isInt, isSmall, validOffer, PER_CLAIM } from './ledger.js';
import * as mk from './market.js';
import { bindNetworkPick, networkPill, rememberNetwork } from './netpick.js';
import { endpoint } from './origin.js';
import { installTips, tip } from './tip.js';
import './styles.css';
import './market.css';
import './moved-banner.js';

const root = document.querySelector('#app');
installTips();
const KEPT_KEY = 'nap.kept.v1';
const NETWORK_KEY = 'nap.network';
let config;
let identity = null;
let view = 'swap';
/// Where to go back to after the wallet opens for an action that needed it.
let returnTo = 'swap';
const emptyState = () => ({ epoch: 0n, epochSeconds: 0, pools: [], launches: [], curves: [], held: [], balances: new Map(), owed: [], offers: [], collections: [], items: new Map(), bridged: [] });
let state = emptyState();
/// Whether the chain has answered once on this network: until it has, an empty
/// list means "not read yet", not "there are none".
let loaded = false;
/// Bumped on a network switch, so an answer from the old chain is dropped.
let generation = 0;
let busy = false;
let timer = null;
const ui = { pool: null, sellA: true, slippage: 100 };

// ---------------------------------------------------------------------------
// Small things.
// ---------------------------------------------------------------------------

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (h) => `${h.slice(0, 6)}…${h.slice(-4)}`;
const $ = (sel) => root.querySelector(sel);
const read = (key) => { try { return localStorage.getItem(key); } catch { return null; } };
const write = (key, v) => { try { localStorage.setItem(key, v); } catch { /* this session only */ } };

/// A WAD amount as a decimal, trimmed, to `places` decimals. Never through a
/// double: the balance is shown exactly or not at all.
function fmt(raw, places = 6) {
  const v = BigInt(raw);
  const neg = v < 0n;
  const a = neg ? -v : v;
  const whole = a / mk.WAD;
  let frac = (a % mk.WAD).toString().padStart(18, '0').slice(0, places).replace(/0+$/, '');
  const w = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${neg ? '−' : ''}${w}${frac ? '.' + frac : ''}`;
}

/// `num/den` as a decimal with `places`, for prices.
function ratio(num, den, places = 6) {
  if (den === 0n) return '—';
  return fmt((num * mk.WAD) / den, places);
}

/// A price that stays readable when it is tiny: more places until something
/// shows, rather than a "0" that reads as worthless.
function price(num, den) {
  if (den === 0n) return '—';
  for (const places of [6, 10, 14, 18]) {
    const t = ratio(num, den, places);
    if (/[1-9]/.test(t) || num === 0n) return t;
  }
  return '< 0.000000000000000001';
}

/// An amount that stays readable when it is tiny: more places until a digit
/// shows, so a real amount never reads "0".
function amt(raw) {
  const v = BigInt(raw);
  if (v === 0n) return '0';
  for (const places of [6, 10, 14, 18]) {
    const t = fmt(v, places);
    if (/[1-9]/.test(t)) return t;
  }
  return fmt(v, 18);
}

function parse(value) {
  const s = String(value || '').trim().replace(/,/g, '');
  return parseAmount(s);
}

/// A collection's name as the deployment knows it, else its short id.
function collectionName(id) {
  const c = (config.collections || []).find((x) => String(x.id).toLowerCase() === id);
  return c ? String(c.name) : short(id);
}

function name(assetHex) {
  if (assetHex === config.zecAsset) return 'ZEC.zy';
  const bridged = state.bridged.find((b) => b.asset === assetHex);
  if (bridged) return ledger.bridgedName(config, bridged);
  const item = state.items.get(assetHex);
  if (item) return `${collectionName(item.collection)} #${item.serial}`;
  // Tickers are not unique: one that repeats, or that dresses up as a coin
  // it is not, carries its address, so a copycat never reads as the original.
  const tagged = (sym) => {
    const clash = [...state.launches, ...state.curves].filter((x) => x.symbol === sym).length > 1 || /^(ZEC|SOL|ETH|BTC)(\.?ZY)?$/i.test(sym);
    return clash ? `${sym} · ${assetHex.slice(0, 6)}` : sym;
  };
  const launch = state.launches.find((l) => l.token === assetHex);
  if (launch) return launch.symbol ? tagged(launch.symbol) : short(assetHex);
  const curve = state.curves.find((c) => c.token === assetHex);
  if (curve) return curve.symbol ? tagged(curve.symbol) : short(assetHex);
  const pool = state.pools.find((p) => p.lp === assetHex);
  if (pool) return `LP ${name(pool.a)}/${name(pool.b)}`;
  return short(assetHex);
}

const balance = (assetHex) => state.balances.get(assetHex) || 0n;

/// Epochs as wall-clock time. An epoch is at most `epoch_seconds` long while
/// a sale is open — the node seals on the clock then — so this is an upper
/// bound, and said as one.
function span(epochs) {
  const secs = Number(epochs) * state.epochSeconds;
  if (!state.epochSeconds || secs <= 0) return '';
  if (secs < 90) return `≤ ${secs}s`;
  if (secs < 5400) return `≤ ${Math.round(secs / 60)} min`;
  if (secs < 172800) return `≤ ${Math.round(secs / 3600)} h`;
  return `≤ ${Math.round(secs / 86400)} days`;
}

// ---------------------------------------------------------------------------
// Configuration and identity — the wallet's, read the wallet's way.
// ---------------------------------------------------------------------------

async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();
  const networks = Array.isArray(value.networks) && value.networks.length ? value.networks : [{ id: 'default', ...value }];
  const wanted = read(NETWORK_KEY);
  const chosen = networks.find((n) => n.id === wanted) || networks.find((n) => n.chain === value.chain) || networks[0];
  return checkedNetwork(chosen, networks);
}

function checkedNetwork(chosen, networks) {
  const rpcUrl = endpoint(chosen.rpcUrl, 'rpcUrl');
  if (chosen.kind !== 'object') throw new Error('The market runs on an object ledger, and this network is not one');
  if (!/^[0-9a-f]{64}$/.test(String(chosen.zecAsset))) throw new Error('This network names no ZEC asset');
  return { ...chosen, rpcUrl, networks };
}

/// Move to another chain, the wallet's way: the key stays open — the same
/// words are the same account on either chain — and every answer from the old
/// chain goes, including any still in flight.
function switchNetwork(id) {
  const next = config.networks.find((n) => n.id === id);
  if (!next || next.id === config.id) return true;
  if (busy) { notice('One moment — the last action is still settling. Switch networks once it has.'); return false; }
  let checked;
  try { checked = checkedNetwork(next, config.networks); } catch (e) { notice(e.message, true); return false; }
  rememberNetwork(checked.id);
  config = checked;
  generation++;
  state = emptyState();
  loaded = false;
  ui.pool = null;
  frame();
  render();
  notice(`On ${config.network} now. Reading the chain…`);
  refresh();
  return true;
}

const keptWallet = () => { try { return JSON.parse(read(KEPT_KEY) || 'null'); } catch { return null; } };

function lock() {
  forgetIdentity(identity);
  identity = null;
  void endSession();
  state = { ...state, held: [], balances: new Map(), owed: [] };
  frame();
  render();
}

/// The market is public; only acting needs a key. Returns whether a wallet
/// is open, and when it is not, sends the holder to open one and back.
function requireWallet() {
  if (identity) return true;
  if (view !== 'wallet') returnTo = view;
  view = 'wallet';
  render();
  notice('Open your wallet to do that. Browsing needs nothing; signing needs your key.');
  return false;
}

// ---------------------------------------------------------------------------
// Talking to the chain.
// ---------------------------------------------------------------------------

const call = (method, fields = {}) => ledger.call(config, method, fields);
const loadOwed = () => ledger.loadOwed(config, identity);

/// A pool is what its assets say it is: its id and share asset derive from
/// its pair (ordered by bytes), so a node cannot relabel one pool as another.
const validPool = (p) => ['id', 'a', 'b', 'lp'].every((k) => isHex(p[k]))
  && ['reserve_a', 'reserve_b', 'shares', 'locked'].every((k) => isInt(p[k]))
  && BigInt(p.reserve_a) > 0n && BigInt(p.reserve_b) > 0n && BigInt(p.shares) > 0n && isSmall(p.fee_bps)
  && mk.compareBytes(unhex(p.a), unhex(p.b)) < 0
  && hex(mk.poolId(unhex(p.a), unhex(p.b))) === p.id && hex(mk.lpAsset(unhex(p.id))) === p.lp;
const validLaunch = (l) => ['token', 'quote', 'meta'].every((k) => isHex(l[k]))
  && ['total_supply', 'sale_supply', 'pool_supply', 'soft_cap', 'hard_cap', 'raised'].every((k) => isInt(l[k]))
  && ['open', 'graduated', 'failed'].includes(l.state) && isSmall(l.closes_at_epoch) && isSmall(l.pool_bps) && isSmall(l.fee_bps);

/// Whether the holder is in the middle of something on the page: the cursor
/// in a field, or an add/remove form open. A timed refresh must not redraw over that — it wiped a half-typed
/// amount and closed the open form every 20 seconds.
function editing() {
  const view = $('#view');
  if (!view) return false;
  const a = document.activeElement;
  if (view.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName)) return true;
  return [...view.querySelectorAll('form.mk-inline')].some((f) => !f.hidden);
}

/// `timed`: a background refresh. It updates what the page knows, but leaves
/// the view alone while the holder is editing; the next render shows it.
async function refresh(quiet = false, timed = false) {
  // Pinned for the whole read: a network switch mid-flight must not mix chains.
  const cfg = config, gen = generation;
  const call = (method, fields = {}) => ledger.call(cfg, method, fields);
  try {
    const status = await call('zyn_status');
    const epoch = checkedEpoch(status, cfg.chain);
    const me = identity;
    const [market, published, owed, offerBook, bridged] = await Promise.all([
      call('zyn_market'),
      me ? call('zyn_published') : null,
      me ? ledger.loadOwed(cfg, me) : [],
      call('zyn_offers').catch(() => ({ offers: [] })),
      ledger.loadBridged(cfg),
    ]);
    if (gen !== generation) return;
    // The wallet may have been locked while this was in flight.
    const mine = me && identity === me;
    const { held, balances } = mine && published
      ? scan(published, { secret: me.viewing, nkey: me.nullifier, owner: me.account })
      : { held: [], balances: new Map() };
    state = {
      epoch,
      epochSeconds: isSmall(market.epoch_seconds) ? market.epoch_seconds : 0,
      pools: (market.pools || []).filter(validPool).map((p) => ({ ...p, pending: Number(p.pending) || 0 })),
      launches: (market.launches || []).filter(validLaunch).map((l) => ({ ...l, ...(mk.decodeMeta(l.meta) || {}) })),
      // Bonding-curve tokens (§141): named from their own meta, so a graduated
      // one reads as its ticker in the pools it trades in.
      curves: (market.curves || []).filter((c) => isHex(c.token) && isHex(c.meta) && isSmall(c.sold)).map((c) => ({ ...c, ...(mk.decodeMeta(c.meta) || {}) })),
      held,
      balances,
      owed: mine ? owed : [],
      offers: (offerBook?.offers || []).filter(validOffer),
      collections: (market.collections || []).filter((c) => isHex(c.asset) && isHex(c.quote) && isInt(c.floor) && isSmall(c.fee_bps)),
      items: new Map(),
      bridged,
    };
    // Which held assets, and which listed ones, are items: asked by asset,
    // which says nothing an item's own listing or manifest does not.
    for (const o of state.offers) if (o.serial >= 0) state.items.set(o.asset, { collection: o.collection, serial: o.serial });
    const unknown = [...new Set(held.map((h) => h.asset))].filter((a) => a !== config.zecAsset && !state.items.has(a) && !bridged.some((b) => b.asset === a));
    if (unknown.length) {
      const found = await call('zyn_items', { assets: unknown.slice(0, 500).join(',') }).catch(() => []);
      if (gen !== generation) return;
      for (const i of Array.isArray(found) ? found : []) {
        if (isHex(i.asset) && isHex(i.collection) && isSmall(i.serial)) state.items.set(i.asset, { collection: i.collection, serial: i.serial });
      }
    }
    loaded = true;
    if (!ui.pool && state.pools.length) ui.pool = state.pools[0].id;
    if (timed && editing()) {
      const e = $('#epoch');
      if (e) e.textContent = `epoch ${state.epoch}`;
    } else {
      render();
    }
    if (!quiet) notice(`Up to date at epoch ${epoch}.`);
  } catch (e) {
    if (gen !== generation) return;
    notice(e.message === 'Failed to fetch' ? 'The chain is not answering. Nothing was sent.' : e.message, true);
  }
}

/// Sign an intent and hand it to the holders' door. A refusal inside the
/// receipts is an error here too — the frame was accepted, the intent was not.
/// `intent` is the bytes, or — for an intent that carries a nonce — a
/// function from nonce to bytes, so a nonce another device used can be
/// stepped over.
async function submit(intent, what) {
  // Said, not swallowed: a click that silently does nothing reads as broken.
  if (busy) { notice('One moment — the last action is still settling. Try again in a few seconds.'); return false; }
  busy = true;
  setBusy(true);
  try {
    if (typeof intent === 'function') await ledger.submitFresh(config, identity, intent);
    else await ledger.submitIntent(config, identity, intent);
    // Redrawn whatever is open: a form left filled and armed after it went
    // through is a second order one click away.
    await refresh(true, false);
    notice(what);
    return true;
  } catch (e) {
    notice(/fewer shares than the minimum|less out than the minimum/.test(e.message)
      ? 'The pool moved since you filled this in, past your minimum. Nothing was spent — check the new numbers and try again.'
      : /too many objects/.test(e.message)
        ? 'This needs more notes than one step can spend. Swap or send a small amount to yourself to merge them, then try again.'
        : e.message, true);
    return false;
  } finally {
    busy = false;
    setBusy(false);
  }
}

// ---------------------------------------------------------------------------
// Screens.
// ---------------------------------------------------------------------------

function shell(content) {
  root.innerHTML = `<div class="grain"></div>
  <header class="mk-header">
    <a class="brand" href="/" aria-label="Nap Wallet"><img src="/nap-mark.png" alt=""><span>Nap</span><em>Market</em></a>
    <div class="mk-head-right">
      ${networkPill(config)}
      <a class="mk-link" href="/">Wallet →</a>
    </div>
  </header>${content}
  <footer><span>Keys stay in this tab. Orders clear together, once an epoch.</span><span>Nap Market · Zyn</span></footer>`;
  bindNetworkPick(root, config, switchNetwork);
}

/// Opening the wallet, as a view inside the market rather than a gate in
/// front of it.
function renderWallet(error = '') {
  // Unlocked already in this browser session (the extension): straight in.
  if (!error && !renderWallet.asked) {
    renderWallet.asked = true;
    loadSession().then((held) => { if (held && !identity) begin(held.identity); });
  }
  const kept = keptWallet();
  $('#view').innerHTML = `<div class="mk-grid mk-unlock">
    <section class="entry panel mk-entry">
      ${kept ? `<form id="kept-form"><h2>Unlock</h2><label>Password<input id="kept-password" type="password" autocomplete="current-password" autofocus></label><button class="primary" type="submit">Open <span>→</span></button></form><p class="muted"><a href="" id="use-phrase">Use a recovery phrase instead</a></p>` : ''}
      <form id="phrase-form" ${kept ? 'hidden' : ''}><h2>Restore wallet</h2><label>24-word recovery phrase<textarea id="words" rows="4" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></label><div class="split"><label>Passphrase<input id="passphrase" type="password" autocomplete="off" placeholder="Blank if unused"></label><label>Account<input id="account-index" type="number" min="0" value="0"></label></div><button class="primary" type="submit">Open <span>→</span></button></form>
      <p class="error" id="form-error" role="alert">${esc(error)}</p>
      <div class="scope"><b>${esc(config.network)}</b><span>Same account as your wallet.${tip('The key stays in this tab and only signs. Prices, pools and sales are public. Balances are read from your own notes, and what you are owed is found by IDs only your key derives. Nothing new is stored.')}</span></div>
    </section>
  </div>`;
  $('#use-phrase')?.addEventListener('click', (e) => { e.preventDefault(); $('#phrase-form').hidden = false; $('#kept-form').hidden = true; });
  $('#kept-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const opened = await openSealedWallet(keptWallet(), $('#kept-password').value);
      await saveSession(opened.identity, opened.receiving);
      begin(opened.identity);
    } catch (err) { $('#form-error').textContent = err.message; }
  });
  $('#phrase-form').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
      const id = deriveIdentity($('#words').value, $('#passphrase').value, Number($('#account-index').value));
      $('#words').value = '';
      begin(id);
    } catch (err) { $('#form-error').textContent = err.message; }
  });
}

function begin(id) {
  if (!id.viewing || !id.nullifier) {
    renderWallet('This kept wallet predates the object ledger. Open it with the recovery phrase once.');
    return;
  }
  identity = id;
  view = returnTo || 'swap';
  frame();
  render();
  refresh();
}

function frame() {
  shell(`<main class="wallet mk">
    <aside class="rail">
      <div>${identity
        ? `<p class="kicker">TRADING AS</p><b class="mk-account">${short(identity.accountHex)}</b>`
        : '<p class="kicker">BROWSING</p><button class="mk-act mk-open" id="open-wallet">Open wallet</button>'}<p class="mk-epoch" id="epoch">epoch —</p></div>
      <nav id="tabs">
        ${['swap', 'pools', 'launchpad', 'owed'].map((t) => `<button data-view="${t}">${t === 'owed' ? 'Owed' : t[0].toUpperCase() + t.slice(1)}<span class="mk-badge" id="badge-${t}"></span></button>`).join('')}
      </nav>
      ${identity ? '<button class="quiet" id="lock">Lock</button>' : ''}
    </aside>
    <section class="content">
      <div class="notice" id="notice" role="status"></div>
      <div id="view"></div>
    </section>
  </main>`);
  $('#lock')?.addEventListener('click', lock);
  $('#open-wallet')?.addEventListener('click', () => { if (view !== 'wallet') returnTo = view; view = 'wallet'; render(); });
  root.querySelectorAll('#tabs [data-view]').forEach((b) => { b.onclick = () => { view = b.dataset.view; render(); }; });
}

function notice(text, bad = false) {
  const el = $('#notice');
  if (!el) return;
  el.textContent = text;
  el.classList.add('show');
  el.classList.toggle('bad', bad);
}

function setBusy(on) {
  root.querySelectorAll('.primary, .mk-act').forEach((b) => { b.disabled = on; });
}

function render() {
  if (!$('#view')) return;
  $('#epoch').textContent = loaded ? `epoch ${state.epoch}` : 'epoch —';
  root.querySelectorAll('#tabs [data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  const owedBadge = $('#badge-owed');
  owedBadge.textContent = state.owed.length ? String(state.owed.length) : '';
  const open = state.launches.filter((l) => l.state === 'open').length;
  $('#badge-launchpad').textContent = open ? String(open) : '';
  if (view === 'wallet' && identity) view = returnTo || 'swap';
  ({ swap: renderSwap, pools: renderPools, launchpad: renderLaunchpad, owed: renderOwed, wallet: renderWallet })[view]();
}

// ---------------------------------------------------------------------------
// Swap.
// ---------------------------------------------------------------------------

function renderSwap() {
  const pools = state.pools;
  if (!pools.length && !loaded) {
    $('#view').innerHTML = `${heading('Swap')}<div class="mk-empty"><p>Loading pools…</p></div>`;
    return;
  }
  if (!pools.length) {
    $('#view').innerHTML = `${heading('Swap')}<div class="mk-empty"><p>No pools yet.</p><button class="mk-act" id="go-pools">Open a pool →</button></div>`;
    $('#go-pools').onclick = () => { view = 'pools'; render(); };
    return;
  }
  const pool = pools.find((p) => p.id === ui.pool) || pools[0];
  ui.pool = pool.id;
  const sell = ui.sellA ? pool.a : pool.b;
  const buy = ui.sellA ? pool.b : pool.a;
  $('#view').innerHTML = `${heading('Swap', 'All orders in an epoch clear together at one price: p = (y + 2b′) / (x + 2a′). There is no order within the batch, so nothing to sandwich. Who traded is not public; the operator sees it.')}
  <div class="mk-grid">
    <form class="mk-card mk-swap" id="swap-form">
      <label class="mk-field"><span>Pair</span><select id="pool-pick">${pools.map((p) => `<option value="${p.id}" ${p.id === pool.id ? 'selected' : ''}>${esc(name(p.a))} / ${esc(name(p.b))}</option>`).join('')}</select></label>
      <div class="mk-leg">
        <div class="mk-leg-top"><span>You sell</span>${identity ? `<button type="button" class="mk-max" id="max">Balance ${amt(balance(sell))}</button>` : '<span>open your wallet to trade</span>'}</div>
        <div class="mk-leg-row"><input id="amount" inputmode="decimal" autocomplete="off" placeholder="0.0"><b>${esc(name(sell))}</b></div>
      </div>
      <button type="button" class="mk-flip" id="flip" aria-label="Swap direction">⇅</button>
      <div class="mk-leg mk-leg-out">
        <div class="mk-leg-top"><span>You receive, if alone in the batch</span><span id="impact"></span></div>
        <div class="mk-leg-row"><output id="quote">0</output><b>${esc(name(buy))}</b></div>
      </div>
      <div class="mk-slip"><span>Accept at worst</span>${[50, 100, 300].map((b) => `<button type="button" data-slip="${b}" class="${ui.slippage === b ? 'on' : ''}">${b / 100}%</button>`).join('')}<span class="mk-min" id="min"></span></div>
      <button class="primary mk-act" type="submit">Place in batch #${state.epoch} <span>→</span></button>
      <p class="mk-fine">Your ${esc(name(sell))} is held in the batch now. At the epoch's seal every order in this pool clears at one price; if that price is worse than your minimum you get everything back. Either way it arrives under <b>Owed to you</b>.</p>
    </form>
    <aside class="mk-card mk-side">
      ${poolFacts(pool)}
    </aside>
  </div>`;
  const amount = $('#amount');
  let confirmedFor = '';
  const impactBps = (raw) => {
    const q = mk.quoteAlone(pool, ui.sellA, raw);
    const x = BigInt(pool.reserve_a), y = BigInt(pool.reserve_b);
    const spot = ui.sellA ? (raw * y) / x : (raw * x) / y;
    return spot > 0n ? Number(((spot - q) * 10000n) / spot) : 0;
  };
  const update = () => {
    let raw = 0n;
    try { raw = amount.value ? parse(amount.value) : 0n; } catch { raw = 0n; }
    const q = raw > 0n ? mk.quoteAlone(pool, ui.sellA, raw) : 0n;
    $('#quote').textContent = amt(q);
    const min = mk.withSlippage(q, ui.slippage);
    $('#min').textContent = raw > 0n ? `min ${amt(min)} ${name(buy)}` : '';
    const bps = raw > 0n ? impactBps(raw) : 0;
    const imp = $('#impact');
    imp.textContent = raw > 0n ? `${(bps / 100).toFixed(2)}% below spot${bps >= 500 ? ' — a large share of this pool' : ''}` : '';
    imp.classList.toggle('mk-warn', bps >= 500);
    confirmedFor = '';
    $('#swap-form button[type=submit]').innerHTML = `Place in batch #${state.epoch} <span>→</span>`;
  };
  amount.oninput = update;
  if ($('#max')) $('#max').onclick = () => { amount.value = fmt(balance(sell), 18).replace(/,/g, ''); update(); };
  amount.value ||= '';
  $('#flip').onclick = () => { ui.sellA = !ui.sellA; renderSwap(); };
  $('#pool-pick').onchange = (e) => { ui.pool = e.target.value; renderSwap(); };
  root.querySelectorAll('[data-slip]').forEach((b) => { b.onclick = () => { ui.slippage = Number(b.dataset.slip); root.querySelectorAll('[data-slip]').forEach((x) => x.classList.toggle('on', x === b)); update(); }; });
  $('#swap-form').onsubmit = async (e) => {
    e.preventDefault();
    if (!requireWallet()) return;
    try {
      const raw = parse(amount.value);
      if (raw > balance(sell)) throw new Error(`You hold ${amt(balance(sell))} ${name(sell)}`);
      // The pool as it is now, not as it was when this form was drawn.
      const now = state.pools.find((q) => q.id === pool.id);
      if (!now || now.reserve_a !== pool.reserve_a || now.reserve_b !== pool.reserve_b) {
        renderSwap();
        notice('The pool moved since this was drawn; the numbers are updated. Check them and place it again.', true);
        return;
      }
      if (mk.quoteAlone(pool, ui.sellA, raw) <= 0n) throw new Error('Too small to trade in this pool');
      // A trade that moves the pool a lot is asked twice.
      const bps = impactBps(raw);
      if (bps >= 1500 && confirmedFor !== amount.value) {
        confirmedFor = amount.value;
        $('#swap-form button[type=submit]').innerHTML = `Confirm: ${(bps / 100).toFixed(1)}% below spot <span>→</span>`;
        notice(`This fills ${(bps / 100).toFixed(1)}% below the pool's price — it is a large share of the pool. Press again to place it anyway.`, true);
        return;
      }
      const minOut = mk.withSlippage(mk.quoteAlone(pool, ui.sellA, raw), ui.slippage);
      const { inputs, change } = mk.fund(identity, state.held, unhex(sell), raw);
      await submit((nonce) => mk.swapIntent({ trader: identity.account, pool: unhex(pool.id), sellA: ui.sellA, amountIn: raw, minOut, inputs, change, nonce }),
        `Order placed in batch #${state.epoch}. It clears at the seal; collect it under Owed to you.`);
    } catch (err) { notice(err.message, true); }
  };
}

function poolFacts(p) {
  const x = BigInt(p.reserve_a), y = BigInt(p.reserve_b);
  const mine = balance(p.lp);
  const shares = BigInt(p.shares);
  return `<dl class="mk-facts">
    <dt>Price</dt><dd>1 ${esc(name(p.a))} = ${price(y, x)} ${esc(name(p.b))}</dd>
    <dt>Reserves</dt><dd>${fmt(x, 4)} ${esc(name(p.a))}<br>${fmt(y, 4)} ${esc(name(p.b))}</dd>
    <dt>Fee</dt><dd>${(p.fee_bps / 100).toFixed(2)}% to liquidity</dd>
    <dt>This batch</dt><dd>${p.pending ? `${p.pending} order${p.pending === 1 ? '' : 's'} waiting` : 'empty so far'}</dd>
    ${mine > 0n ? `<dt>Your share</dt><dd>${ratio(mine * 100n, shares, 3)}%</dd>` : ''}
    ${BigInt(p.locked) === shares ? '<dt>Liquidity</dt><dd>locked for good</dd>' : ''}
  </dl>`;
}

/// A page's heading: its name, and an "i" when something needs explaining.
function heading(title, explain = '') {
  return `<div class="topline"><div><h1 class="mk-h1">${title}${explain ? tip(explain) : ''}</h1></div><button class="refresh" id="refresh" aria-label="Refresh"><span aria-hidden="true">↻</span><span class="refresh-word">Refresh</span></button></div>`;
}

// ---------------------------------------------------------------------------
// Pools.
// ---------------------------------------------------------------------------

function renderPools() {
  // Items trade through listings (their fee and floor split live there), and a
  // pool share in a pool is a loop: neither is offered here.
  const assets = [...new Set([config.zecAsset, ...state.held.map((h) => h.asset)])]
    .filter((a) => !state.items.has(a) && !state.pools.some((p) => p.lp === a));
  $('#view').innerHTML = `${heading('Pools')}
  <section class="mk-list">${state.pools.length ? state.pools.map((p) => `
    <article class="mk-card mk-pool">
      <header><h3>${esc(name(p.a))} <span>/</span> ${esc(name(p.b))}</h3><span class="mk-pill">${(p.fee_bps / 100).toFixed(2)}%</span></header>
      ${poolFacts(p)}
      <div class="mk-row">
        <button class="mk-act" data-trade="${p.id}">Trade</button>
        <button class="mk-act" data-add="${p.id}">Add</button>
        ${balance(p.lp) > 0n ? `<button class="mk-act" data-remove="${p.id}">Remove</button>` : ''}
      </div>
      <form class="mk-inline" id="add-${p.id}" hidden>
        <label class="mk-field"><span>${esc(name(p.a))}${identity ? ` · you hold ${fmt(balance(p.a), 4)}` : ''}</span><input name="a" inputmode="decimal" autocomplete="off" placeholder="0.0"></label>
        <label class="mk-field"><span>${esc(name(p.b))}${identity ? ` · you hold ${fmt(balance(p.b), 4)}` : ''}</span><input name="b" inputmode="decimal" autocomplete="off" placeholder="matched to the ratio"></label>
        <p class="mk-fine" data-preview></p>
        <button class="primary mk-act" type="submit">Add liquidity <span>→</span></button>
      </form>
      <form class="mk-inline" id="remove-${p.id}" hidden>
        <label class="mk-field"><span>Shares (you hold ${amt(balance(p.lp))}) <button type="button" class="mk-max" data-max-lp="${p.id}">Max</button></span><input name="s" inputmode="decimal" autocomplete="off"></label>
        <p class="mk-fine" data-remove-preview></p>
        <button class="primary mk-act" type="submit">Remove <span>→</span></button>
      </form>
    </article>`).join('') : `<div class="mk-empty"><p>${loaded ? 'No pools yet. Open the first one below.' : 'Reading the pools…'}</p></div>`}</section>
  <form class="mk-card mk-create" id="create-pool">
    <h2>Open a pool${tip('What you put in sets the first price. A small part of the first shares is locked for good, so the pool can never be emptied and restarted at another price.')}</h2>
    <div class="mk-two">
      <label class="mk-field"><span>First asset</span><select name="a">${assets.map((a) => `<option value="${a}">${esc(name(a))} · ${fmt(balance(a), 4)}</option>`).join('')}</select></label>
      <label class="mk-field"><span>Amount</span><input name="amount_a" inputmode="decimal" autocomplete="off"></label>
      <label class="mk-field"><span>Second asset</span><select name="b">${assets.map((a, i) => `<option value="${a}" ${i === 1 ? 'selected' : ''}>${esc(name(a))} · ${fmt(balance(a), 4)}</option>`).join('')}</select></label>
      <label class="mk-field"><span>Amount</span><input name="amount_b" inputmode="decimal" autocomplete="off"></label>
    </div>
    <label class="mk-field"><span>Fee</span><select name="fee"><option value="5">0.05%</option><option value="30" selected>0.30%</option><option value="100">1.00%</option></select></label>
    <p class="mk-fine" id="create-preview"></p>
    <button class="primary mk-act" type="submit">Open pool <span>→</span></button>
  </form>`;
  root.querySelectorAll('[data-trade]').forEach((b) => { b.onclick = () => { ui.pool = b.dataset.trade; view = 'swap'; render(); }; });
  root.querySelectorAll('[data-add]').forEach((b) => { b.onclick = () => { const f = $(`#add-${b.dataset.add}`); f.hidden = !f.hidden; }; });
  root.querySelectorAll('[data-remove]').forEach((b) => { b.onclick = () => { const f = $(`#remove-${b.dataset.remove}`); f.hidden = !f.hidden; }; });

  for (const p of state.pools) {
    const add = $(`#add-${p.id}`);
    const x = BigInt(p.reserve_a), y = BigInt(p.reserve_b);
    add.elements.a.oninput = () => {
      try {
        const a = parse(add.elements.a.value);
        add.elements.b.value = fmt((a * y + x - 1n) / x, 18).replace(/,/g, '');
        const pv = mk.liquidityPreview(p, a, parse(add.elements.b.value));
        add.querySelector('[data-preview]').textContent = `≈ ${ratio(pv.shares * 100n, BigInt(p.shares) + pv.shares, 3)}% of the pool. Anything the ratio does not use comes back under Owed to you.`;
      } catch { add.querySelector('[data-preview]').textContent = ''; }
    };
    add.onsubmit = async (e) => {
      e.preventDefault();
      if (!requireWallet()) return;
      try {
        const now = state.pools.find((q) => q.id === p.id);
        if (!now || now.reserve_a !== p.reserve_a || now.reserve_b !== p.reserve_b) { render(); notice('The pool moved since this was drawn; the numbers are updated. Check them and add again.', true); return; }
        const typedA = parse(add.elements.a.value), typedB = parse(add.elements.b.value);
        const pv = mk.liquidityPreview(p, typedA, typedB);
        if (pv.shares <= 0n) throw new Error('Too little to earn a share of this pool');
        // Only what the ratio uses is signed: nothing left over to come back as
        // dust claims and notes.
        const a = pv.usedA, b = pv.usedB;
        if (a > balance(p.a) || b > balance(p.b)) throw new Error(`That needs ${amt(a)} ${name(p.a)} and ${amt(b)} ${name(p.b)}`);
        const taken = new Set();
        const fa = mk.fund(identity, state.held, unhex(p.a), a, taken);
        const fb = mk.fund(identity, state.held, unhex(p.b), b, taken);
        if (fa.inputs.length + fb.inputs.length > 16) throw new Error('This needs more notes than one step can spend (16). Send a small amount to yourself to merge them, then try again.');
        await submit((nonce) => mk.addLiquidityIntent({
          provider: identity.account, pool: unhex(p.id), amountA: a, amountB: b,
          minShares: mk.withSlippage(pv.shares, 100), inputs: [...fa.inputs, ...fb.inputs], change: [...fa.change, ...fb.change], nonce,
        }), 'Liquidity added. Your shares are under Owed to you.');
      } catch (err) { notice(err.message, true); }
    };
    const rm = $(`#remove-${p.id}`);
    const rmPreview = () => {
      try {
        const s_ = parse(rm.elements.s.value);
        const shares = BigInt(p.shares);
        rm.querySelector('[data-remove-preview]').textContent = `≈ ${amt((s_ * x) / shares)} ${name(p.a)} and ${amt((s_ * y) / shares)} ${name(p.b)}, at least 99% of that.`;
      } catch { rm.querySelector('[data-remove-preview]').textContent = ''; }
    };
    rm.elements.s.oninput = rmPreview;
    rm.querySelector('[data-max-lp]')?.addEventListener('click', () => { rm.elements.s.value = fmt(balance(p.lp), 18).replace(/,/g, ''); rmPreview(); });
    rm.onsubmit = async (e) => {
      e.preventDefault();
      if (!requireWallet()) return;
      try {
        const now = state.pools.find((q) => q.id === p.id);
        if (!now || now.reserve_a !== p.reserve_a || now.reserve_b !== p.reserve_b) { render(); notice('The pool moved since this was drawn; the numbers are updated. Check them and remove again.', true); return; }
        const s = parse(rm.elements.s.value);
        if (s > balance(p.lp)) throw new Error(`You hold ${amt(balance(p.lp))} shares`);
        const shares = BigInt(p.shares);
        const f = mk.fund(identity, state.held, unhex(p.lp), s);
        await submit((nonce) => mk.removeLiquidityIntent({
          provider: identity.account, pool: unhex(p.id), shares: s,
          minA: mk.withSlippage((s * x) / shares, 100), minB: mk.withSlippage((s * y) / shares, 100),
          inputs: f.inputs, change: f.change, nonce,
        }), 'Liquidity removed. Both sides are under Owed to you.');
      } catch (err) { notice(err.message, true); }
    };
  }

  const cf = $('#create-pool');
  const createPreview = () => {
    const f = cf.elements;
    const out = $('#create-preview');
    try {
      const a = f.a.value, b = f.b.value;
      if (a === b) { out.textContent = 'Choose two different assets.'; return; }
      const existing = state.pools.find((q) => q.id === hex(mk.poolId(unhex(a), unhex(b))));
      if (existing) { out.textContent = `${name(a)} / ${name(b)} already has a pool — use Add on it above.`; return; }
      const amountA = parse(f.amount_a.value), amountB = parse(f.amount_b.value);
      const shares = mk.geometricMean(amountA, amountB) - mk.MINIMUM_LIQUIDITY;
      out.textContent = shares > 0n
        ? `Opens at 1 ${name(a)} = ${price(amountB, amountA)} ${name(b)}. That price is yours to set: if it is off, the first traders take the difference.`
        : 'Too little to open a pool: the first shares must be more than the locked sliver.';
    } catch { out.textContent = ''; }
  };
  cf.querySelectorAll('select, input').forEach((x) => x.addEventListener('input', createPreview));
  cf.onsubmit = async (e) => {
    e.preventDefault();
    if (!requireWallet()) return;
    const f = e.target.elements;
    try {
      let a = f.a.value, b = f.b.value;
      let amountA = parse(f.amount_a.value), amountB = parse(f.amount_b.value);
      if (a === b) throw new Error('A pool needs two different assets');
      if (state.pools.some((q) => q.id === hex(mk.poolId(unhex(a), unhex(b))))) throw new Error('That pool exists already — use Add on it above.');
      if (mk.geometricMean(amountA, amountB) <= mk.MINIMUM_LIQUIDITY) throw new Error('Too little to open a pool: the first shares must be more than the locked sliver.');
      if (amountA > balance(a) || amountB > balance(b)) throw new Error(`You hold ${amt(balance(a))} ${name(a)} and ${amt(balance(b))} ${name(b)}`);
      // The VM names a pool's assets in byte order.
      if (mk.compareBytes(unhex(a), unhex(b)) > 0) { [a, b] = [b, a]; [amountA, amountB] = [amountB, amountA]; }
      const taken = new Set();
      const fa = mk.fund(identity, state.held, unhex(a), amountA, taken);
      const fb = mk.fund(identity, state.held, unhex(b), amountB, taken);
      if (fa.inputs.length + fb.inputs.length > 16) throw new Error('This needs more notes than one step can spend (16). Send a small amount to yourself to merge them, then try again.');
      await submit((nonce) => mk.createPoolIntent({
        provider: identity.account, assetA: unhex(a), assetB: unhex(b), amountA, amountB, feeBps: Number(f.fee.value),
        inputs: [...fa.inputs, ...fb.inputs], change: [...fa.change, ...fb.change], nonce,
      }), 'Pool open. Your shares are under Owed to you.');
    } catch (err) { notice(err.message, true); }
  };
}

// ---------------------------------------------------------------------------
// Launchpad.
// ---------------------------------------------------------------------------

function renderLaunchpad() {
  const order = { open: 0, graduated: 1, failed: 2 };
  const launches = [...state.launches].sort((p, q) => order[p.state] - order[q.state] || q.closes_at_epoch - p.closes_at_epoch);
  const jade = config.launchpadUrl ? new URL(config.launchpadUrl) : null;
  const trading = state.curves.filter((c) => !c.graduated).length;
  $('#view').innerHTML = `${heading('Launchpad')}
  ${jade ? `<div class="mk-empty mk-jade"><p><b>Bonding-curve launches are on Jade.</b>${tip('Anyone can create a token. It trades at once on a bonding curve, at one price per epoch, and graduates into a locked pool that trades here.')} ${state.curves.length ? `${trading} on a curve, ${state.curves.length - trading} graduated.` : ''}</p><a class="mk-act" href="${esc(jade.href)}" target="_blank" rel="noopener">Open Cave Jade →</a></div>` : ''}
  <h2 class="mk-sub">Fixed-price sales${tip('Everyone who commits before the close pays the same price.')}</h2>
  <section class="mk-list">${launches.length ? launches.map(launchCard).join('') : `<div class="mk-empty"><p>${loaded ? 'No sales yet. Start the first one below.' : 'Reading the sales…'}</p></div>`}</section>
  ${createLaunchForm()}`;
  for (const l of launches) {
    const form = $(`#commit-${l.token}`);
    if (!form) continue;
    form.onsubmit = async (e) => {
      e.preventDefault();
      if (!requireWallet()) return;
      try {
        const amount = parse(form.elements.amount.value);
        const f = mk.fund(identity, state.held, unhex(l.quote), amount);
        await submit((nonce) => mk.commitIntent({ buyer: identity.account, launch: unhex(l.token), amount, inputs: f.inputs, change: f.change, nonce }),
          `Committed to ${l.symbol || 'the sale'}. At the close your tokens — and any refund — arrive under Owed to you.`);
      } catch (err) { notice(err.message, true); }
    };
  }
  bindCreateLaunch();
}

function launchCard(l) {
  const raised = BigInt(l.raised), soft = BigInt(l.soft_cap), hard = BigInt(l.hard_cap), sale = BigInt(l.sale_supply);
  const left = BigInt(l.closes_at_epoch) - state.epoch;
  const title = l.symbol ? `${esc(l.symbol)} <span>${esc(l.name)}</span>` : `<span>${short(l.token)}</span>`;
  const accepted = raised < hard ? raised : hard;
  const price = sale > 0n && accepted > 0n ? ratio(accepted, sale, 8) : '—';
  const pct = (v) => (hard > 0n ? Number((v * 1000n) / hard) / 10 : 0);
  const status = l.state === 'open'
    ? (left >= 0n ? `closes after epoch ${l.closes_at_epoch} · ${span(left + 1n) || `${left} to go`}` : 'closing at the next seal')
    : l.state === 'graduated' ? 'sold · trading in its pool' : 'missed its soft cap · refunded';
  return `<article class="mk-card mk-launch mk-${l.state}">
    <header><h3>${title}</h3><span class="mk-pill">${l.state}</span></header>
    <div class="mk-raise">
      <div class="mk-raise-top"><b>${fmt(raised, 4)}</b><span>of ${fmt(hard, 4)} ${esc(name(l.quote))}</span></div>
      <meter min="0" max="100" low="${pct(soft)}" optimum="100" value="${Math.min(100, pct(raised))}"></meter>
      <div class="mk-raise-marks"><span>soft cap ${fmt(soft, 4)}</span><span>${status}</span></div>
    </div>
    <dl class="mk-facts">
      <dt>For sale</dt><dd>${fmt(sale, 0)} of ${fmt(BigInt(l.total_supply), 0)}</dd>
      <dt>${l.state === 'open' ? 'Price if it closed now' : l.state === 'graduated' ? 'Sold at' : 'Would have sold at'}</dt><dd>${price} ${esc(name(l.quote))}</dd>
      <dt>To the pool</dt><dd>${l.pool_bps / 100}% of the raise + ${fmt(BigInt(l.pool_supply), 0)} tokens, locked</dd>
    </dl>
    ${l.state === 'open' && left >= 0n ? `<form class="mk-inline" id="commit-${l.token}"><label class="mk-field"><span>Commit ${esc(name(l.quote))} · you hold ${fmt(balance(l.quote), 4)}</span><input name="amount" inputmode="decimal" autocomplete="off" placeholder="0.0"></label><button class="primary mk-act" type="submit">Commit <span>→</span></button><p class="mk-fine">Held until the close, then everyone pays one price. Over the hard cap, each commitment is filled in the same proportion and the rest refunded.</p></form>` : ''}
  </article>`;
}

function createLaunchForm() {
  return `<form class="mk-card mk-create" id="create-launch">
    <h2>Start a sale</h2>
    <p class="mk-fine">The whole supply is issued into escrow. If the raise misses its soft cap everyone is refunded and the token is burned — yours too.</p>
    <div class="mk-two">
      <label class="mk-field"><span>Symbol</span><input name="symbol" maxlength="8" autocomplete="off" placeholder="MOLE"></label>
      <label class="mk-field"><span>Name</span><input name="name" maxlength="24" autocomplete="off" placeholder="Nap Mole"></label>
      <label class="mk-field"><span>Total supply</span><input name="total" inputmode="decimal" value="1000000"></label>
      <label class="mk-field"><span>For sale (%)</span><input name="sale" inputmode="numeric" value="60"></label>
      <label class="mk-field"><span>Soft cap (ZEC.zy)</span><input name="soft" inputmode="decimal" value="10"></label>
      <label class="mk-field"><span>Hard cap (ZEC.zy)</span><input name="hard" inputmode="decimal" value="100"></label>
      <label class="mk-field"><span>Tokens to the pool (%)</span><input name="pool" inputmode="numeric" value="20"></label>
      <label class="mk-field"><span>Raise to the pool (%)</span><input name="pool_raise" inputmode="numeric" value="50"></label>
      <label class="mk-field"><span>Open for (epochs)</span><input name="epochs" inputmode="numeric" value="60"></label>
      <label class="mk-field"><span>Pool fee</span><select name="fee"><option value="30" selected>0.30%</option><option value="100">1.00%</option></select></label>
    </div>
    <p class="mk-fine" id="launch-preview"></p>
    <button class="primary mk-act" type="submit">Start sale <span>→</span></button>
  </form>`;
}

function bindCreateLaunch() {
  const form = $('#create-launch');
  const f = form.elements;
  const pctOf = (total, p) => (total * BigInt(p)) / 100n;
  const preview = () => {
    try {
      const total = parse(f.total.value);
      const sale = pctOf(total, f.sale.value), pool = pctOf(total, f.pool.value);
      const mine = total - sale - pool;
      $('#launch-preview').textContent = mine < 0n
        ? 'The sale and the pool are more than the supply.'
        : `Open ${span(f.epochs.value) || `${f.epochs.value} epochs`}. You keep ${fmt(mine, 0)} tokens. At the hard cap they sell at ${ratio(parse(f.hard.value), sale, 8)} ZEC.zy each; the pool opens at ${ratio(pctOf(parse(f.hard.value), f.pool_raise.value), pool || 1n, 8)}.`;
    } catch { $('#launch-preview').textContent = ''; }
  };
  form.oninput = preview;
  preview();
  form.onsubmit = async (e) => {
    e.preventDefault();
    if (!requireWallet()) return;
    try {
      const total = parse(f.total.value);
      const salePct = Number(f.sale.value), poolPct = Number(f.pool.value), raisePct = Number(f.pool_raise.value);
      for (const v of [salePct, poolPct, raisePct]) if (!Number.isInteger(v) || v < 0 || v > 100) throw new Error('Percentages are whole numbers from 0 to 100');
      if (salePct === 0) throw new Error('A sale sells something');
      if ((poolPct === 0) !== (raisePct === 0)) throw new Error('A pool needs both tokens and part of the raise, or neither');
      const epochs = Number(f.epochs.value);
      if (!Number.isInteger(epochs) || epochs < 1 || epochs > 100000) throw new Error('Open for 1 to 100,000 epochs');
      await submit((nonce) => mk.createLaunchIntent({
        creator: identity.account, nonce, quote: unhex(config.zecAsset),
        totalSupply: total, saleSupply: pctOf(total, salePct), poolSupply: pctOf(total, poolPct),
        softCap: parse(f.soft.value), hardCap: parse(f.hard.value), poolBps: raisePct * 100, feeBps: Number(f.fee.value),
        closesAtEpoch: state.epoch + BigInt(epochs), meta: mk.encodeMeta({ symbol: f.symbol.value, name: f.name.value }),
      }), `Sale open. It closes after epoch ${state.epoch + BigInt(epochs)}; your share arrives under Owed to you then.`);
    } catch (err) { notice(err.message, true); }
  };
}

// ---------------------------------------------------------------------------
// Owed.
// ---------------------------------------------------------------------------

function renderOwed() {
  if (!identity) {
    $('#view').innerHTML = `${heading('Owed', 'Swap proceeds, refunds, pool shares and sale allocations wait here until you collect them. They are found by IDs derived from your key; nobody else can look them up.')}
    <div class="mk-empty"><p>Open your wallet to see what you are owed.</p><button class="mk-act" id="owed-open">Open wallet →</button></div>`;
    $('#owed-open').onclick = () => requireWallet();
    return;
  }
  // What each claim is: a swap that filled is not a swap that came back.
  const byKind = new Map();
  for (const c of state.owed) {
    const key = `${c.kind || 'Owed'}\u0000${c.asset}`;
    byKind.set(key, (byKind.get(key) || 0n) + BigInt(c.amount));
  }
  $('#view').innerHTML = `${heading('Owed', 'Swap proceeds, refunds, pool shares and sale allocations wait here until you collect them. They are found by IDs derived from your key; nobody else can look them up.')}
  ${state.owed.length ? `<section class="coins">${[...byKind].map(([k, v]) => { const [kind, a] = k.split('\u0000'); return `<div class="coin"><div><span>${esc(kind)}</span><b>${amt(v)} ${esc(name(a))}</b></div></div>`; }).join('')}</section>
  <button class="primary mk-act mk-collect" id="collect">Collect all ${state.owed.length} <span>→</span></button>`
    : `<div class="mk-empty"><p>${loaded ? 'Nothing owed right now. Orders settle at the end of the epoch they were placed in.' : 'Looking for what the market owes you…'}</p></div>`}
  <p class="mk-fine">Traded from another device? This one only looks a little past what it has used. <button type="button" class="mk-link-btn" id="look-further">Look further back</button></p>`;
  $('#look-further')?.addEventListener('click', async () => {
    const b = $('#look-further');
    b.disabled = true; b.textContent = 'Looking…';
    try { await ledger.recoverNonces(config, identity, { gap: 1024 }); await refresh(true, false); notice('Looked 1,024 steps further back.'); }
    catch (e) { notice(e.message, true); } finally { if ($('#look-further')) { $('#look-further').disabled = false; $('#look-further').textContent = 'Look further back'; } }
  });
  $('#collect')?.addEventListener('click', async () => {
    if (!requireWallet()) return;
    const all = [...state.owed];
    for (let i = 0; i < all.length; i += PER_CLAIM) {
      const batch = all.slice(i, i + PER_CLAIM);
      const ok = await submit(mk.claimIntent(mk.redeem(identity, batch)), `Collected ${Math.min(i + PER_CLAIM, all.length)} of ${all.length}. They are in your wallet now.`);
      if (!ok) break;
    }
  });
}

// Refresh buttons live inside each view.
root.addEventListener('click', (e) => { if (e.target.closest('#refresh')) refresh(); });

(async () => {
  try {
    config = await loadConfig();
    // Unlocked already (the extension, the phone app): open straight in.
    const held = await loadSession();
    if (held?.identity.viewing) begin(held.identity);
    else { frame(); render(); refresh(true); }
    timer = setInterval(() => { if (!document.hidden && !busy) refresh(true, true); }, 20000);
  } catch (e) {
    root.innerHTML = `<main class="fatal"><img src="/nap-mark.png" alt=""><h1>Market unavailable.</h1><p>${esc(e.message)}</p></main>`;
  }
})();
