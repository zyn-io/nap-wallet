// Nap's connect window: how a site reaches the browser wallet.
//
// A site opens this page in a popup (`nap-connect.js` does it) and talks to it
// with postMessage. The keys never leave this origin: the site sends a
// request, the holder sees who is asking and what it would do — in a window
// the site cannot draw on or script — and the site gets back an answer.
//
// In the extension the same page is the extension's own window, and sites
// reach it through the extension's content script over a runtime port; the
// browser, not the page, names each port's origin.
//
// The rules this page keeps:
// - On the web it answers only the window that opened it, and only at the
//   origin that window had when it first spoke. A message from anywhere else
//   is dropped. In the extension it answers each site on that site's port.
// - It will not run inside a frame, where a site could dress it up.
// - Connecting shows the site the Zyn account and a Zcash address, nothing
//   else. Every write is approved one at a time, and the approval describes
//   what the chain says, not what the site says.
// - A read that says more than a connection does (private-channel notes,
//   lending positions) waits for the holder to allow it to that site, once,
//   on a card naming exactly what goes (connect-grants.js).
// - Public answers (markets, the bridges' state) need no wallet: they never
//   read the session. Only the holder's own actions here — unlocking, a click
//   on a card — keep an extension session from lapsing; a site asking does
//   not (audit, 9 Oct 2026).
// - What is remembered is which sites are connected, and what each was
//   allowed to read, in localStorage. Never a key, never a balance.

import { peekSession, saveSession, touchSession } from './session.js';
import { deriveIdentity, forgetIdentity, openSealedWallet } from './core.js';
import { deriveZecKeys, stopZec, ZecAccount } from './zec/client.js';
import { ERR, METHODS, ProviderError, session } from './connect-ops.js';
import { allowed, connectedTo, SCOPES, scopesOf, withConnection, withScope, without } from './connect-grants.js';
import { endpoint, IN_EXTENSION } from './origin.js';
import './styles.css';
import './connect.css';

const root = document.querySelector('#app');
const KEPT_KEY = 'nap.kept.v1';
const NETWORK_KEY = 'nap.network';
const CONNECTED_KEY = 'nap.connected.v1';

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };
const keptWallet = () => { try { return JSON.parse(read(KEPT_KEY) || 'null'); } catch { return null; } };
const connections = () => { try { return JSON.parse(read(CONNECTED_KEY) || '{}') || {}; } catch { return {}; } };
/// A site is connected on a network, to one wallet: another wallet opened in
/// this browser later is not connected to it until its holder says so.
const isConnected = (origin, net) => connectedTo(connections(), origin, net, identity?.accountHex);
/// Whether the holder allowed `scope` to this site, on this network and wallet.
const isAllowed = (origin, net, scope) => allowed(connections(), origin, net, identity?.accountHex, scope);
function remember(origin, net) { write(CONNECTED_KEY, JSON.stringify(withConnection(connections(), origin, net, identity.accountHex))); }
function allow(origin, net, scope) { write(CONNECTED_KEY, JSON.stringify(withScope(connections(), origin, net, identity.accountHex, scope))); }
/// Disconnecting takes back every scope with the connection.
function forget(origin) { write(CONNECTED_KEY, JSON.stringify(without(connections(), origin))); }

let networks = [];
let config = null;
let identity = null;
let site = null; // web: the opener's origin, fixed by its first message; extension: the origin of the request in hand
const queue = [];
let working = false;
/// Each site's network, fixed by its first request: two sites on two networks
/// can use one extension window, and neither can move the other.
const siteNetwork = new Map();
/// The last result or error, kept on screen until the next card replaces it.
let lastFlash = null;
/// Set while the unlock screen is up: cancels it if its site goes away.
let abortUnlock = null;
let zecAccount = null;
let zecView = null;

// ---------------------------------------------------------------------------

async function loadNetworks() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();
  const list = Array.isArray(value.networks) && value.networks.length ? value.networks : [{ id: 'default', ...value }];
  return list.filter((n) => n.kind === 'object').map((n) => {
    for (const key of ['rpcUrl', 'lightdUrl']) {
      if (!n[key]) continue;
      n[key] = endpoint(n[key], key);
    }
    if (n.bridges?.eth?.vaultRpc) n.bridges = { ...n.bridges, eth: { ...n.bridges.eth, vaultRpc: endpoint(n.bridges.eth.vaultRpc, 'vaultRpc') } };
    return n;
  });
}

function pickNetwork(wanted) {
  const byId = networks.find((n) => n.id === wanted);
  if (wanted && !byId) throw new ProviderError(ERR.PARAMS, `Nap has no network called ${wanted}`);
  return byId || networks.find((n) => n.id === read(NETWORK_KEY)) || networks[0];
}

const zecNet = () => (config.zcashPrefix === 'u1' ? 'mainnet' : 'testnet');

function context() {
  const hasZec = !!(identity?.zec && config.lightdUrl);
  return {
    config,
    identity,
    // The address, from the keys alone.
    zec: hasZec ? async () => {
      if (!zecAccount) zecAccount = new ZecAccount({ sk: identity.zec[zecNet()], network: zecNet(), url: config.lightdUrl, birthday: config.zecBirthday });
      if (!zecView) zecView = await zecAccount.peek();
      return zecView;
    } : null,
    // A wallet ready to pay: seeded and synced, which needs the block server.
    zecReady: hasZec ? async () => {
      if (!zecAccount) zecAccount = new ZecAccount({ sk: identity.zec[zecNet()], network: zecNet(), url: config.lightdUrl, birthday: config.zecBirthday });
      zecView = await zecAccount.open();
      return zecAccount;
    } : null,
  };
}

// ---------------------------------------------------------------------------
// Messages.

/// Something for the site that is not an answer: that the holder approved
/// (so a window closed afterwards is not "nothing happened"), or that this
/// window needs them (so the site may bring it forward).
function tell(job, msg) {
  if (!job) return;
  if (job.port) { try { job.port.postMessage(msg); } catch { /* gone */ } return; }
  if (site && window.opener && !window.opener.closed) window.opener.postMessage(msg, site);
}

/// Whether the site that asked is still there to hear the answer.
function siteGone(job) {
  if (job.port) return !!job.gone;
  return !window.opener || window.opener.closed;
}

function reply(job, result, error) {
  const { id } = job;
  const msg = error
    ? { nap: 'response', id, error: { code: error.code || -32603, message: error.message || String(error) } }
    : { nap: 'response', id, result: result === undefined ? null : result };
  if (job.port) { try { job.port.postMessage(msg); } catch { /* the site's tab went away */ } return; }
  if (!site || !window.opener) return;
  window.opener.postMessage(msg, site);
}

/// The extension's door: one port per site tab, opened by its content script.
/// Its origin comes from the browser (`port.sender`), so a page cannot speak
/// for another; only http(s) pages in a tab are answered.
function listenForSites() {
  chrome.runtime.onConnect.addListener((port) => {
    if (port.name !== 'nap-site' || !port.sender?.tab) return;
    let origin = port.sender.origin;
    try { origin = origin || new URL(port.sender.url).origin; } catch { origin = null; }
    if (!origin || !/^https?:\/\//.test(origin)) { port.disconnect(); return; }
    port.onMessage.addListener((d) => {
      if (!d || d.nap !== 'request' || typeof d.method !== 'string') return;
      queue.push({ id: d.id, method: d.method, params: d.params && typeof d.params === 'object' ? d.params : {}, origin, port });
      pump();
    });
    // A closed tab's requests are nobody's to answer: queued ones go, and the
    // one on screen is cancelled rather than approved for nobody.
    port.onDisconnect.addListener(() => {
      for (let i = queue.length - 1; i > 0; i--) if (queue[i].port === port) queue.splice(i, 1);
      if (queue[0]?.port === port) { queue[0].gone = true; cancelShown(); }
    });
    port.postMessage({ nap: 'ready', version: 1 });
  });
}

window.addEventListener('message', (ev) => {
  if (IN_EXTENSION) return;
  if (!window.opener || ev.source !== window.opener) return;
  const d = ev.data;
  // The site reloaded and found this window again by name: say it is here.
  if (d?.nap === 'hello') {
    if ((site === null || ev.origin === site) && networks.length) window.opener.postMessage({ nap: 'ready', version: 1 }, ev.origin);
    return;
  }
  if (!d || d.nap !== 'request' || typeof d.method !== 'string') return;
  if (site === null) site = ev.origin;
  if (ev.origin !== site) return; // the opener navigated elsewhere; not ours to answer
  queue.push({ id: d.id, method: d.method, params: d.params && typeof d.params === 'object' ? d.params : {} });
  pump();
});

async function pump() {
  if (working) return;
  const job = queue[0];
  if (!job) { render(); return; }
  working = true;
  if (job.origin) site = job.origin;
  current = job;
  try {
    const result = await handle(job);
    reply(job, result);
  } catch (e) {
    reply(job, undefined, e);
    if (e.code !== ERR.REJECTED) flash(e.message, true);
  } finally {
    queue.shift();
    current = null;
    working = false;
    pump();
  }
}

let current = null;

/// The site went away while its request was on screen: answer "no" for it.
function cancelShown() {
  if (answer) { const a = answer; answer = null; a(false); }
  abortUnlock?.();
}

/// The holder's answer to what is on screen, as a promise.
let answer = null;
const decide = () => new Promise((resolve) => { answer = resolve; });

/// Which network this request is on: the site's, once it has one. A site asks
/// for its network when it connects; after that a request that names another
/// is refused rather than answered from the wrong chain.
function useNetwork(method, params) {
  const wanted = typeof params.network === 'string' && params.network ? params.network : null;
  const had = siteNetwork.get(site);
  let id = had;
  if (!had || (method === 'nap_connect' && wanted && wanted !== had)) id = pickNetwork(wanted || undefined).id;
  else if (wanted && wanted !== had) throw new ProviderError(ERR.PARAMS, `This site is connected on ${had}, not ${wanted}; connect again on ${wanted}`);
  siteNetwork.set(site, id);
  if (config?.id !== id) { config = networks.find((n) => n.id === id); zecAccount = null; zecView = null; }
}

async function handle(job) {
  const { method, params } = job;
  const m = METHODS[method];
  if (!m) throw new ProviderError(ERR.UNSUPPORTED, `Nap does not do ${method}`);

  if (method === 'nap_disconnect') { forget(site); return true; }
  useNetwork(method, params);
  // Public: what the chain says to anyone. No wallet, and the session is not
  // read — so a site polling these keeps nothing unlocked.
  if (m.kind === 'public') return m.run({ config, identity: null, zec: null, zecReady: null }, params);

  // In the extension the toolbar can lock Nap; what it locked is locked here.
  // Looked at, not used: a site's request never pushes the idle lock out.
  if (IN_EXTENSION && identity && !(await peekSession())) { forgetIdentity(identity); identity = null; }
  if (method === 'nap_session') return identity && isConnected(site, config.id) ? session(context()) : null;

  if (!identity) { tell(job, { nap: 'attention' }); await unlock(method); }
  if (siteGone(job)) throw new ProviderError(ERR.REJECTED, 'The site went away');
  if (!isConnected(site, config.id)) {
    tell(job, { nap: 'attention' });
    show(connectCard());
    if (!(await decide())) throw new ProviderError(ERR.REJECTED, 'The holder did not connect');
    remember(site, config.id);
  }
  if (method === 'nap_connect') { working_('Connected.'); return session(context()); }
  // A read that says more than the connection does: asked once per site,
  // network and wallet, on its own card (audit, 9 Oct 2026).
  if (m.scope && !isAllowed(site, config.id, m.scope)) {
    tell(job, { nap: 'attention' });
    show(scopeCard(m.scope));
    if (!(await decide())) throw new ProviderError(ERR.REJECTED, 'The holder did not allow this site to read that');
    if (siteGone(job)) throw new ProviderError(ERR.REJECTED, 'The site went away');
    allow(site, config.id, m.scope);
  }
  if (m.kind === 'read') { working_('Answering…'); return m.run(context(), params); }
  if (m.kind === 'auto') { working_('Collecting what settled…'); const r = await m.run(context(), params); flash(r?.collected ? `Collected ${r.collected}.` : 'Nothing to collect yet.'); return r; }

  working_('Checking with the chain…');
  const plan = await m.prepare(context(), params);
  tell(job, { nap: 'attention' });
  show(approvalCard(plan));
  if (!(await decide())) throw new ProviderError(ERR.REJECTED, 'The holder rejected the request');
  if (siteGone(job)) throw new ProviderError(ERR.REJECTED, 'The site went away before this ran; nothing was sent');
  tell(job, { nap: 'progress', id: job.id, stage: 'approved' });
  working_(plan.title + '…');
  const result = await plan.run((s) => {
    if (s?.proving) working_('Proving the transaction — about half a minute…');
    else if (s?.to) working_(`Syncing ${Number(s.at).toLocaleString('en-US')} of ${Number(s.to).toLocaleString('en-US')}…`);
  });
  flash(`Done: ${plan.title}.`);
  return result;
}

// ---------------------------------------------------------------------------
// Unlocking.

async function unlock(method) {
  // Unlocked already in this browser session: the site's request is still
  // shown and approved below, but the password is not asked again. A site
  // asked, not the holder: the idle deadline stays where it was.
  const held = await peekSession();
  if (held) { identity = held.identity; return; }
  return new Promise((resolve, reject) => {
    const why = method === 'nap_connect' ? 'wants to connect to your Nap' : 'is asking your Nap';
    let screen = '';      // 'none' | 'password' | 'phrase': what is on show
    let shownKept = '';   // the saved record the password screen opens
    let checking = false; // a password is being tried
    const finish = () => { window.removeEventListener('storage', onStored); abortUnlock = null; };
    const done = (id) => { finish(); identity = id; resolve(); };
    const deny = () => { finish(); reject(new ProviderError(ERR.REJECTED, 'The holder did not unlock')); };
    abortUnlock = deny;

    // A wallet kept in this browser opens with its password.
    const askPassword = (kept) => {
      screen = 'password'; shownKept = JSON.stringify(kept);
      show(`<p class="kicker">UNLOCK</p><h2>${siteName()} ${why}.</h2>
        <form id="unlock"><label>Password<input id="pw" type="password" autocomplete="current-password" autofocus></label>
        <button class="primary" type="submit">Unlock <span>→</span></button></form>
        <p class="muted"><a href="" id="use-phrase">Use the recovery phrase instead</a> · <a href="" id="new-wallet">Replace it with a new wallet</a></p>
        <p class="muted" id="note" hidden></p>
        <button class="quiet" id="deny">Not now</button><p class="error" id="err" role="alert"></p>`);
      root.querySelector('#deny').onclick = deny;
      root.querySelector('#use-phrase').onclick = (e) => { e.preventDefault(); askPhrase(); };
      root.querySelector('#new-wallet').onclick = (e) => {
        e.preventDefault();
        // Replacing the saved wallet happens in a Nap tab, which warns first;
        // this window picks the new one up when it is saved.
        const note = root.querySelector('#note');
        note.textContent = 'A Nap tab opens to make the new wallet. It asks you to confirm replacing the one saved here — only its recovery phrase brings that one back. This window then asks for the new password.';
        note.hidden = false;
        window.open('/index.html?setup=create', '_blank');
      };
      root.querySelector('#unlock').onsubmit = async (e) => {
        e.preventDefault();
        checking = true;
        try { const opened = await openSealedWallet(kept, root.querySelector('#pw').value); await saveSession(opened.identity, opened.receiving); done(opened.identity); }
        catch (err) { root.querySelector('#err').textContent = err.message; }
        finally { checking = false; }
      };
    };

    // No wallet here yet: set one up in a full tab rather than typing 24
    // words into a window a website opened. The phrase stays possible, once,
    // behind a link.
    const noWallet = () => {
      screen = 'none';
      show(`<p class="kicker">NO WALLET HERE YET</p><h2>${siteName()} ${why}.</h2>
        <p class="muted">This browser has no Nap wallet yet. Set one up in a Nap tab — create a new one, or restore yours from its recovery phrase — and choose a password. This window then asks only for that password.</p>
        <button class="primary" id="setup-create" type="button">Create a Nap wallet <span>→</span></button>
        <button class="primary cn-alt" id="setup-restore" type="button">Restore from my phrase <span>→</span></button>
        <p class="muted" id="setup-wait" hidden>Finish in the Nap tab — this window picks it up by itself.</p>
        <p class="muted"><a href="" id="use-phrase">Type my recovery phrase here, just this once</a></p>
        <button class="quiet" id="deny">Not now</button><p class="error" id="err" role="alert"></p>`);
      root.querySelector('#deny').onclick = deny;
      root.querySelector('#use-phrase').onclick = (e) => { e.preventDefault(); askPhrase(); };
      const setup = (mode) => { window.open(`/index.html?setup=${mode}`, '_blank'); root.querySelector('#setup-wait').hidden = false; };
      root.querySelector('#setup-create').onclick = () => setup('create');
      root.querySelector('#setup-restore').onclick = () => setup('restore');
    };

    const askPhrase = () => {
      screen = 'phrase';
      show(`<p class="kicker">RECOVERY PHRASE</p><h2>${siteName()} ${why}.</h2>${phraseForm()}
        <p class="muted">Used in this window to open the wallet, then dropped; nothing is kept.</p>
        <button class="quiet" id="deny">Not now</button><p class="error" id="err" role="alert"></p>`);
      root.querySelector('#deny').onclick = deny;
      bindPhrase(done);
    };

    // Another Nap tab of this browser set a wallet up, replaced it or forgot
    // it: follow, without wiping a password being typed or tried.
    async function onStored(e) {
      if (e.key !== KEPT_KEY || screen === 'phrase' || checking) return;
      const kept = keptWallet();
      if (!kept) { if (screen === 'password') noWallet(); return; }
      if (screen === 'password' && JSON.stringify(kept) === shownKept) return;
      // The tab that saved it may have opened it for this browser session too.
      const held = await peekSession();
      if (held) { done(held.identity); return; }
      askPassword(kept);
    }
    window.addEventListener('storage', onStored);

    const kept = keptWallet();
    if (kept) askPassword(kept); else noWallet();
  });
}

function phraseForm() {
  return `<form id="unlock"><label>Recovery phrase<textarea id="words" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></label>
    <div class="split"><label>Passphrase<input id="pass" type="password" autocomplete="off" placeholder="if used"></label><label>Account<input id="idx" type="number" min="0" value="0"></label></div>
    <button class="primary" type="submit">Unlock <span>→</span></button></form>`;
}

function bindPhrase(done) {
  root.querySelector('#unlock').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const words = root.querySelector('#words').value;
      const pass = root.querySelector('#pass').value;
      const idx = Number(root.querySelector('#idx').value);
      const id = deriveIdentity(words, pass, idx);
      try { id.zec = await deriveZecKeys(words, pass, idx); } catch { /* Zyn still works */ }
      root.querySelector('#words').value = '';
      done(id);
    } catch (err) { root.querySelector('#err').textContent = err.message; }
  };
}

// ---------------------------------------------------------------------------
// Screens.

const siteName = () => `<b class="site">${esc(site ? new URL(site).host : 'A site')}</b>`;

function connectCard() {
  return `<p class="kicker">CONNECT</p><h2>${siteName()} wants to connect.</h2>
    <dl class="rows"><dt>It will see</dt><dd>Your Zyn account ID${identity.zec ? ' and your Zcash address' : ''}</dd>
    <dt>When it asks</dt><dd>Your ZEC in apps and token balances, your items, what you are owed, your sale tickets and the coins you made</dd>
    <dt>Only if you allow it</dt><dd>${esc(capital(scopeList(Object.keys(SCOPES))))} — each asked on its own card</dd>
    <dt>It will not see</dt><dd>Your keys or your recovery phrase</dd>
    <dt>Network</dt><dd>${esc(config.network)} · ${esc(config.zcash)}</dd></dl>
    <p class="muted">It can ask you to approve payments and trades. Nothing moves unless you approve it here.</p>
    <div class="actions"><button class="quiet" id="no">Reject</button><button class="primary" id="yes">Connect <span>→</span></button></div>`;
}

const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);
/// "your private-channel notes and your lending positions".
const scopeList = (scopes) => scopes.map((s) => SCOPES[s].what).join(' and ');

/// A read beyond the connection: what goes, and what the site can learn from
/// it, before Allow. Kept for this site on this network until it disconnects.
function scopeCard(scope) {
  const s = SCOPES[scope];
  return `<p class="kicker">SHARE</p><h2>${siteName()} asks to see ${esc(s.what)}.</h2>
    <dl class="rows"><dt>It will see</dt><dd>${esc(s.shows)}</dd>
    <dt>Network</dt><dd>${esc(config.network)}</dd></dl>
    <p class="muted">${esc(s.risk)}</p>
    <p class="muted">Allowed once for this site on ${esc(config.network)}. Disconnecting the site takes it back.</p>
    <div class="actions"><button class="quiet" id="no">Reject</button><button class="primary" id="yes">Allow <span>→</span></button></div>`;
}

function approvalCard(plan) {
  return `<p class="kicker">${esc(new URL(site).host)} ASKS</p><h2>${esc(plan.title)}.</h2>
    ${plan.image ? `<img class="cn-picture" src="${esc(plan.image)}" alt="The token's picture">` : ''}
    <dl class="rows">${plan.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
    <p class="muted">${esc(plan.note || '')}</p>
    <div class="actions"><button class="quiet" id="no">Reject</button><button class="primary${plan.danger ? ' danger' : ''}" id="yes">Approve <span>→</span></button></div>`;
}

/// Put a screen up. A card that asks something clears the last result; the
/// waiting and resting screens keep it on show.
function show(inner, { keep = false } = {}) {
  if (!keep) lastFlash = null;
  root.innerHTML = frame(inner);
  const yes = root.querySelector('#yes');
  const no = root.querySelector('#no');
  if (yes) {
    // Armed after a moment: a double click meant for the last screen must not
    // land on this one's Approve.
    yes.disabled = true;
    setTimeout(() => { yes.disabled = false; }, 500);
    yes.onclick = () => { void touchSession(); const a = answer; answer = null; a?.(true); };
  }
  // A click on a card is the holder at the keyboard: the one thing in this
  // window, besides unlocking, that keeps the session from lapsing.
  if (no) no.onclick = () => { void touchSession(); const a = answer; answer = null; a?.(false); };
  root.querySelector('#disconnect')?.addEventListener('click', () => { forget(site); render(); });
}

function frame(inner) {
  return `<div class="grain"></div><header class="cn-head"><span class="brand"><img src="/nap-mark.png" alt=""><span>Nap</span></span>${config ? `<span class="network"><i></i>${esc(config.network)}</span>` : ''}</header>
    <main class="cn">${inner}</main><p class="cn-flash${lastFlash?.bad ? ' bad' : ''}" id="flash" role="status">${esc(lastFlash?.text || '')}</p>`;
}

function working_(text) { show(`<p class="kicker">WORKING</p><h2>${esc(text)}</h2><div class="cn-spin" aria-hidden="true"></div>`, { keep: true }); }

function flash(text, bad = false) {
  lastFlash = { text, bad };
  const el = root.querySelector('#flash');
  if (!el) return;
  el.textContent = text;
  el.classList.toggle('bad', bad);
}

function render() {
  if (working || answer) return;
  if (!site) { show(`<p class="kicker">NAP CONNECT</p><h2>Waiting for the site…</h2><p class="muted">${IN_EXTENSION ? 'This window answers sites that ask for Nap.' : 'This window answers the page that opened it.'}</p>`, { keep: true }); return; }
  const connected = config && isConnected(site, config.id);
  const how = IN_EXTENSION
    ? 'It asks you here before anything moves. While Nap is unlocked, sites you connected can read your holdings; lock Nap from the toolbar to stop that.'
    : 'Keep this window open while you use the site; it asks you here before anything moves. Closing it locks Nap for that site.';
  const shared = connected ? scopesOf(connections(), site, config.id, identity?.accountHex) : [];
  show(`<p class="kicker">NAP CONNECT</p><h2>${connected ? `Connected to ${siteName()}.` : `${siteName()} is not connected.`}</h2>
    <p class="muted">${connected ? how : 'Nothing was shared.'}</p>
    ${shared.length ? `<p class="muted">You allowed it to see ${esc(scopeList(shared))}.</p>` : ''}
    ${connected ? '<button class="quiet" id="disconnect">Disconnect this site</button>' : ''}`, { keep: true });
}

// ---------------------------------------------------------------------------

window.addEventListener('pagehide', () => { forgetIdentity(identity); identity = null; stopZec(); });

(async () => {
  // Inside a frame a site could cover this page with its own and borrow the
  // clicks; without an opener there is nobody to answer. Either way, stop.
  if (window.top !== window.self) { document.body.textContent = 'Nap does not run inside another page.'; return; }
  if (!IN_EXTENSION && !window.opener) {
    root.innerHTML = frame('<p class="kicker">NAP CONNECT</p><h2>Nothing is asking.</h2><p class="muted">This window opens when a site asks to connect to Nap. To use your wallet directly, <a href="/">open Nap</a>.</p>');
    return;
  }
  try {
    networks = await loadNetworks();
    render();
    // Only now can the page answer; saying so earlier would lose requests.
    if (IN_EXTENSION) listenForSites();
    else window.opener.postMessage({ nap: 'ready', version: 1 }, '*');
  } catch (e) {
    root.innerHTML = frame(`<h2>Nap cannot open.</h2><p class="muted">${esc(e.message)}</p>`);
    // Said to the site too, so it is not left waiting on a window that
    // will never answer.
    if (!IN_EXTENSION) window.opener.postMessage({ nap: 'error', message: `Nap cannot open: ${e.message}` }, '*');
    return;
  }
  if (IN_EXTENSION) {
    // Lock in the toolbar (or the idle timeout) ends the session: this window
    // forgets the keys too.
    globalThis.chrome?.storage?.session?.onChanged?.addListener((changes) => {
      if (!changes['nap.session'] || changes['nap.session'].newValue) return;
      forgetIdentity(identity); identity = null; stopZec(); zecAccount = null; zecView = null;
      render();
    });
  } else {
    // The page that opened this window closed or went elsewhere: whatever it
    // asked is cancelled, not approved for nobody.
    setInterval(() => { if (current && siteGone(current)) cancelShown(); }, 500);
  }
})();
