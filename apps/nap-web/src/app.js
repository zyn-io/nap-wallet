import QRCode from 'qrcode';
import { x25519 } from '@noble/curves/ed25519.js';
import { PROGRAM as OBJECT_PROGRAM, scan as scanObjects, objectCall, registerIntent, sealNote, signedFrame as objectFrame, spendIntent, submitSigned, withdrawIntent } from './object.js';
import { decodeMeta, fund as fundFrom, lendAsset } from './market.js';
import { bridgedName, loadBridged } from './ledger.js';
import { bridgePage } from './bridges.js';
import { activity, logActivity } from './pocket.js';
import { checkedEpoch, cancelOfferIntent, deriveCollectionAccount, XZEC, deriveIdentity, forgetIdentity, hex, newMnemonic, openSealedWallet, parseAmount, placeOfferIntent, readableAmount, rpc, sealWallet, signedFrame, signedRead, transferFrame, unhex, WAD } from './core.js';
import { deriveZecKeys, stopZec, ZecAccount } from './zec/client.js';
import { parsePaymentRequest } from './zip321.js';
import { boundedBytes, MAX_IMAGE, MAX_MANIFEST, parseManifest, safeRaster } from './media.js';
import { endpoint, IN_APP, IN_EXTENSION, IN_POPUP, openPage } from './origin.js';
import { endSession, hasSession, loadSession, saveSession } from './session.js';
import { installTips, tip } from './tip.js';
import './styles.css';
import './moved-banner.js';

installTips();

const root = document.querySelector('#app');
let config;
let identity = null;
/// Where bought items land — one per collection the deployment declares.
let receiving = [];
/// Our own resting offers — items escrowed in the order book, not in an account.
let listings = [];
let assets = [];
let holdings = [];
/// The object ledger's notes this wallet holds, with commitments — what a
/// withdrawal spends.
let objectHeld = [];
let generatedWords = '';
/// The Zcash wallet for the chosen network: plain shielded ZEC, held the way
/// any Zcash wallet holds it. Separate from the Zyn account above it on
/// purpose — a Zcash address gets a Zcash transaction, a Zyn account gets Zyn
/// tokens and items, and neither is dressed up as the other.
let zecAccount = null;
let zecTimer = 0;
/// A wallet made in this session has no history to scan back through.
let zecFresh = false;
/// A tap on an event's NFC tag (§150): `/tap?e=<event>&picc=…&cmac=…`, the
/// URL the tag writes on every read. Kept until the wallet is open, then the
/// certificate is collected into it.
let tapLink = (() => {
  if (!/\/tap\/?$/.test(location.pathname)) return null;
  const q = new URLSearchParams(location.search);
  const [e, picc, cmac] = ['e', 'picc', 'cmac'].map((k) => String(q.get(k) || '').toLowerCase());
  return /^[0-9a-f]{64}$/.test(e) && /^[0-9a-f]{32}$/.test(picc) && /^[0-9a-f]{16}$/.test(cmac) ? { event: e, picc, cmac } : null;
})();
if (/\/tap\/?$/.test(location.pathname)) history.replaceState(null, '', '/');
// The toolbar popup sends setting up here (`?setup=create|restore`): 24 words
// want more room than a popup has.
// Kept for this tab (sessionStorage) so a reload mid-setup is still setup —
// the site's Nap window is waiting for the wallet it makes.
const setupMode = (() => {
  const asked = new URLSearchParams(location.search).get('setup');
  try {
    if (['create', 'restore'].includes(asked)) sessionStorage.setItem('nap.setup', asked);
    const kept = sessionStorage.getItem('nap.setup');
    return ['create', 'restore'].includes(kept) ? kept : '';
  } catch { return ['create', 'restore'].includes(asked) ? asked : ''; }
})();
const endSetup = () => { try { sessionStorage.removeItem('nap.setup'); } catch { /* nothing kept */ } };
const giftUrl = new URL(location.href);
giftUrl.searchParams.delete('setup');
const claimCode = new URLSearchParams(giftUrl.hash.slice(1)).get('claim') || giftUrl.searchParams.get('claim') || '';
// Fragment links keep the card secret out of HTTP access logs. Scrub legacy
// query links immediately; deployments must also redact them from access logs.
giftUrl.searchParams.delete('claim'); giftUrl.hash = '';
history.replaceState(null, '', giftUrl.pathname + giftUrl.search);
// In the phone app the compact wallet (popup.html) is home; this page is the
// full view, opened for what only it does — an event tag's tap, a gift card —
// or on request (`?full=1`).
if (IN_APP && !tapLink && !claimCode && !new URLSearchParams(location.search).has('full')) location.replace('/popup.html');
let generation = 0;
let refreshId = 0;
const artUrls = new Set();
function clearSession() {
  generation++; refreshId++;
  napBrowser?.closeBrowser();
  clearTimeout(zecTimer); stopZec(); zecAccount = null;
  forgetIdentity(identity); identity = null;
  for (const r of receiving) forgetIdentity(r);
  receiving = []; holdings = []; assets = []; listings = []; generatedWords = '';
  for (const url of artUrls) URL.revokeObjectURL(url);
  artUrls.clear();
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (s) => `${s.slice(0, 8)}…${s.slice(-6)}`;
// One network: a label, as before. More than one: a control, because a wallet
// that can reach two chains must let the holder see which one they are on and
// say so out loud — the chain id stays visible either way.
// The name only. The chain id still appears where it decides something — on
// the send review, beside the destination — but in the corner it was noise on
// every screen rather than a check anyone was making.
// Both chains, because the wallet spans both: ZEC goes in at a Zcash address
// and arrives as ZEC.zy on Zyn. The chain id is not here — it appears on the
// send review, where it decides something.
const networkNames = (n) => `${n.zcash} · ${n.network}`;
const networkPill = () => (config.networks && config.networks.length > 1)
  ? `<label class="network network-pick"><i></i><span class="visually-hidden">Network</span><select id="network-pick">${config.networks.map((n) => `<option value="${escapeHtml(n.id)}"${n.id === config.id ? ' selected' : ''}>${escapeHtml(networkNames(n))}</option>`).join('')}</select></label>`
  : `<span class="network"><i></i>${escapeHtml(networkNames(config))}</span>`;

/// Validate one network's shape. Every URL must be a same-origin path: the
/// shipped CSP permits nothing else, and a cross-origin endpoint here would be
/// a wallet quietly talking to a host the policy never admitted.
function checkedNetwork(value) {
  if (!Number.isInteger(value.chain) || value.chain < 0 || value.chain > 0xffffffff || typeof value.network !== 'string') throw new Error('Deployment configuration is incomplete');
  // A Zyn chain sits on exactly one Zcash network and the node refuses to mix
  // them. Naming it lets the header say both — and `zcashPrefix` is what keeps
  // that name honest, because a label nothing checks is a label that can lie.
  if (typeof value.zcash !== 'string' || !/^u(test)?1$/.test(String(value.zcashPrefix || ''))) {
    throw new Error('Each network must name its Zcash network and address prefix');
  }
  const out = { ...value, collections: Array.isArray(value.collections) ? value.collections : [] };
  for (const key of ['rpcUrl', 'claimUrl', 'mediaGateway', 'lightdUrl', 'attendUrl']) {
    if ((key === 'lightdUrl' || key === 'attendUrl') && !value[key]) continue; // optional: no Zcash wallet, no certificates on this network
    out[key] = endpoint(value[key], key);
  }
  return out;
}

/// Which network the holder last chose. Not a secret — it is the name of a
/// public chain — so `localStorage` is the right place, unlike anything
/// derived from the phrase.
const NETWORK_KEY = 'nap.network';

/// A wallet kept on this device: the derived key, sealed under a password the
/// holder chose. Never the phrase — see `sealIdentity`.
const KEPT_KEY = 'nap.kept.v1';
const keptWallet = () => { try { return JSON.parse(localStorage.getItem(KEPT_KEY) || 'null'); } catch { return null; } };
const keepWallet = (blob) => { try { localStorage.setItem(KEPT_KEY, JSON.stringify(blob)); return true; } catch { return false; } };
const forgetKept = () => { try { localStorage.removeItem(KEPT_KEY); } catch { /* nothing to forget */ } };
const rememberedNetwork = () => { try { return localStorage.getItem(NETWORK_KEY); } catch { return null; } };
const rememberNetwork = (id) => { try { localStorage.setItem(NETWORK_KEY, id); } catch { /* private window: this session only */ } };

async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();

  // The top level is the default network, so a deployment that never heard of
  // `networks` still validates exactly as it did before.
  const fallback = { id: 'default', ...checkedNetwork(value) };
  const networks = Array.isArray(value.networks) && value.networks.length
    ? value.networks.map((n) => ({ id: String(n.id || n.chain), ...checkedNetwork(n) }))
    : [fallback];

  const wanted = rememberedNetwork();
  const chosen = networks.find((n) => n.id === wanted)
    // An unknown or removed id falls back to the deployment's default rather
    // than failing: a stale preference must not lock someone out of a wallet.
    || networks.find((n) => n.chain === fallback.chain)
    || networks[0];
  return { ...chosen, networks };
}

/// Move to another chain without forgetting the phrase.
///
/// The seed is chain-independent — the same words derive the same account on
/// either — so there is no reason to make switching cost a restore. What must
/// go is every cached answer from the old chain, which `reset` already does;
/// `checkedEpoch` then fails closed if an endpoint ever answers for the wrong
/// one.
function switchNetwork(id) {
  const next = config.networks.find((n) => n.id === id);
  if (!next || next.id === config.id) return;
  rememberNetwork(next.id);
  config = { ...next, networks: config.networks };
  // Deliberately NOT clearSession(): that forgets the phrase, and the phrase is
  // not what changed. Only the chain's answers are stale.
  holdings = []; assets = [];
  clearTimeout(zecTimer); stopZec(); zecAccount = null;
  generation++; refreshId++;
  if (identity) { wallet(); refresh(); } else onboarding();
}

// Asking a gateway for the picture of an item you own tells that host your IP,
// which item you hold, and when — on a shielded chain, the one thing the chain
// itself will not reveal. The desktop wallet has always kept this behind an
// explicit toggle; this one fetched art for every holding on every render, so a
// single page load handed over the complete list. Off until the holder says
// otherwise, and the reason is on the button rather than in a help page.
const ART_KEY = 'nap_web_art';
function artEnabled() {
  try {
    return localStorage.getItem(ART_KEY) === '1';
  } catch {
    // A browser that refuses storage is a browser that cannot remember consent,
    // and unremembered consent is not consent. Stay off.
    return false;
  }
}
function setArtEnabled(on) {
  try {
    localStorage.setItem(ART_KEY, on ? '1' : '0');
  } catch {
    /* refused storage: the setting lasts for this render only */
  }
}

function shell(content) {
  root.innerHTML = `<div class="grain"></div><header><a class="brand" href="/" aria-label="Nap Wallet"><img src="/nap-mark.png" alt=""><span>Nap</span></a>${networkPill()}</header>${content}<footer><span>Keys stay in this tab.</span><span>Nap Wallet · Zyn</span></footer>`;
  const pick = root.querySelector('#network-pick');
  if (pick) pick.addEventListener('change', (e) => switchNetwork(e.target.value));
}

function unlockForm() {
  return `<form id="kept-form"><h2>Unlock</h2><div id="bio-slot"></div><label>Password${tip('Your key is stored on this device, sealed. It opens with the password you set here, not your recovery phrase.')}<input id="kept-password" type="password" autocomplete="current-password" autofocus></label><button class="primary" type="submit">Open <span>→</span></button><p class="error" id="form-error" role="alert"></p><p class="muted"><a href="" id="use-phrase">Use a recovery phrase instead</a> · <a href="" id="new-wallet">Create a new wallet</a> · <a href="" id="forget-kept">Forget this device</a></p></form>`;
}

function bindKept() {
  root.querySelector('#kept-form').onsubmit = async (event) => {
    event.preventDefault();
    const button = root.querySelector('.primary');
    button.disabled = true;
    const password = root.querySelector('#kept-password').value;
    try { await openKept(password); offerBiometrics(password); }
    catch (e) { root.querySelector('#form-error').textContent = e.message; button.disabled = false; }
  };
  showBiometricUnlock();
  root.querySelector('#use-phrase').onclick = (e) => { e.preventDefault(); onboarding('restore'); };
  root.querySelector('#new-wallet').onclick = (e) => { e.preventDefault(); onboarding('create'); };
  root.querySelector('#forget-kept').onclick = (e) => {
    e.preventDefault();
    forgetKept();
    vault?.call('forget').catch(() => {});
    onboarding('restore');
  };
}

// Face ID / fingerprint unlock — the phone app only (§151). The kept wallet's
// password goes to the Keychain / Android Keystore behind this device's
// biometrics (the app's `napvault` plugin) and comes back only for a face or
// finger. The password still opens the wallet; the phrase still restores it.
const vault = IN_APP && window.__TAURI__?.core?.invoke
  ? { call: (cmd, args = {}) => window.__TAURI__.core.invoke(`plugin:napvault|${cmd}`, args) }
  : null;
// The Nap browser (§152): sites beside the wallet, their requests answered
// here. Loaded only in the phone app, so the web and extension never carry it.
let napBrowser = null;
if (IN_APP && window.__TAURI__?.core?.invoke) {
  import('./nap-browser.js').then((m) => {
    napBrowser = m;
    return m.startBrowser(() => (identity && config ? { config, identity, zec: zecAccount } : null));
  }).catch(() => { napBrowser = null; });
}
const bioName = (kind) => ({ faceId: 'Face ID', touchId: 'Touch ID', opticId: 'Optic ID' }[kind] || 'fingerprint');
const vaultStatus = () => (vault ? vault.call('status').catch(() => null) : Promise.resolve(null));

/// On the unlock screen: an "Open with Face ID" button, pressed once for the holder.
async function showBiometricUnlock() {
  const st = await vaultStatus();
  const slot = root.querySelector('#bio-slot');
  if (!st?.available || !st.stored || !slot) return;
  slot.innerHTML = `<button type="button" class="primary bio" id="bio-unlock">Open with ${bioName(st.kind)} <span>→</span></button><p class="muted bio-or">or with your password</p>`;
  const go = async () => {
    const error = root.querySelector('#form-error');
    try {
      const { secret } = await vault.call('unlock', { reason: 'Open your Nap wallet' });
      try { await openKept(secret); }
      catch {
        // The kept wallet was sealed again under another password since.
        await vault.call('forget').catch(() => {});
        if (error) error.textContent = `${bioName(st.kind)} no longer matches this wallet; open it with your password.`;
      }
    } catch (e) {
      if (error && !/cancel/i.test(String(e))) error.textContent = String(e).slice(0, 160);
    }
  };
  root.querySelector('#bio-unlock').onclick = go;
  go();
}

/// After the password opened (or kept) the wallet: offer biometrics, once.
async function offerBiometrics(password) {
  const st = await vaultStatus();
  if (!st?.available || st.stored || !password) return;
  const at = root.querySelector('#notice');
  if (!at) return;
  const name = bioName(st.kind);
  at.insertAdjacentHTML('afterend', `<section class="claim bio-offer"><div><h2>Unlock with ${name}?${tip(`Your password is kept in this phone's secure storage and released only to your ${name === 'fingerprint' ? 'fingerprint' : 'face'}. Nothing leaves the phone.`)}</h2></div><div class="bio-actions"><button id="bio-yes">Use ${name} <span>→</span></button><button class="quiet" id="bio-no">Not now</button></div></section>`);
  const card = root.querySelector('.bio-offer');
  root.querySelector('#bio-no').onclick = () => { card.remove(); password = ''; };
  root.querySelector('#bio-yes').onclick = async () => {
    try { await vault.call('store', { secret: password }); card.remove(); note(`${name} opens Nap from now on.`); }
    catch (e) { if (!/cancel/i.test(String(e))) note(String(e).slice(0, 160), true); }
    finally { password = ''; }
  };
}

// Where this Nap is: the words the welcome uses for it.
const WHERE = IN_APP ? { closing: 'Closing the app' }
  : IN_EXTENSION ? { closing: 'Closing Nap' }
  : { closing: 'Closing this tab' };

function onboarding(mode = keptWallet() ? 'kept' : (claimCode ? 'create' : 'restore')) {
  if (mode !== 'create') generatedWords = '';
  shell(`<main class="onboard">
    <section class="intro">
      <h1>Nap Wallet</h1>
      <p class="lede">Shielded ZEC and Zyn assets. Self-custodial.</p>
      ${tapLink ? '<div class="tap-note"><b>Event tag tapped.</b> Open or create your wallet to receive the certificate.</div>' : ''}
      <div class="promise"><span>01</span><p><b>Keys stay on this device.</b>${tip('Your key is derived from your recovery phrase and used only here. There is no account server.')}</p></div>
      ${IN_EXTENSION || setupMode
    ? `<div class="promise"><span>02</span><p><b>Saved here, sealed with your password.</b>${tip('Only the key is stored, sealed under your password. Never your phrase.')}</p></div>`
    : `<div class="promise"><span>02</span><p><b>Not saved unless you set a password.</b>${tip(`${WHERE.closing} forgets the key. With a password, only the key is stored, sealed under it. Never your phrase.`)}</p></div>`}
    </section>
    <section class="entry panel">
      ${mode === 'kept' ? '' : `<div class="tabs"><button data-mode="restore" class="${mode === 'restore' ? 'active' : ''}">Restore</button><button data-mode="create" class="${mode === 'create' ? 'active' : ''}">Create new</button></div>`}
      ${mode === 'kept' ? unlockForm() : (mode === 'restore' ? restoreForm() : createForm())}
      <div class="scope"><b>Holds</b><span>Shielded ZEC, Zyn tokens and items.${tip('The same recovery phrase opens Nap on the web, in the browser extension and on your phone.')}</span></div>
    </section>
  </main>`);
  root.querySelectorAll('[data-mode]').forEach((b) => b.onclick = () => onboarding(b.dataset.mode));
  if (mode === 'kept') bindKept(); else if (mode === 'create') bindCreate(); else bindRestore();
}

/// The extension keeps its wallet by definition — the toolbar opens it with
/// this password — and so does a setup sent here by a connect window or the
/// popup (`?setup=`): there the field is required, not optional.
function keepField() {
  const why = IN_EXTENSION ? 'the toolbar wallet opens with it' : 'Nap opens with it in this browser';
  const field = IN_EXTENSION || setupMode
    ? `<label>Password${tip(`8+ characters. ${why[0].toUpperCase()}${why.slice(1)}.`)}<input id="keep-password" type="password" autocomplete="new-password" required minlength="8" placeholder="8+ characters"></label>`
    : `<label>Password (optional)${tip('Set one to keep the wallet on this device, sealed. Leave it blank and closing forgets the key.')}<input id="keep-password" type="password" autocomplete="new-password" placeholder="Blank: forget on close"></label>`;
  // Saving over a wallet already kept here loses it on this device: said, and
  // confirmed, before anything is replaced.
  return field + (keptWallet()
    ? '<label class="check"><input id="replace-ack" type="checkbox"><span>This replaces the wallet saved in this browser. I have its recovery phrase — the only way back to it.</span></label>'
    : '');
}

/// The replace confirmation, when a wallet is kept and a password would save
/// over it.
function replaceConfirmed() {
  const box = root.querySelector('#replace-ack');
  const saving = !!root.querySelector('#keep-password')?.value;
  if (box && saving && !box.checked) throw new Error('Tick the box to confirm replacing the wallet saved in this browser');
}

function restoreForm() {
  return `<form id="restore-form"><h2>Restore wallet</h2><label>24-word recovery phrase<textarea id="words" rows="5" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="word 1  word 2  word 3 …"></textarea></label><div class="split"><label>Passphrase${tip('An extra word some wallets add to the phrase. Leave blank if you never set one.')}<input id="passphrase" type="password" autocomplete="off" placeholder="Blank if unused"></label><label>Account${tip('Which account under this phrase. 0 unless you use more than one.')}<input id="account-index" type="number" min="0" max="2147483647" value="0"></label></div>${keepField()}<button class="primary" type="submit">Restore <span>→</span></button><p class="error" id="form-error" role="alert"></p></form>`;
}
function createForm() {
  if (!generatedWords) generatedWords = newMnemonic();
  const numbered = generatedWords.split(' ').map((w, i) => `<span><i>${String(i + 1).padStart(2, '0')}</i>${w}</span>`).join('');
  return `<form id="create-form"><h2>New wallet</h2><p class="muted">Write down these 24 words. They are shown once.${tip('They restore your ZEC and your Zyn tokens and items in any Nap.')}</p><div class="phrase">${numbered}</div><label class="check"><input id="ack" type="checkbox"><span>I saved all 24 words offline. I understand a screenshot or cloud note can expose my wallet.</span></label>${keepField()}<button class="primary" type="submit" disabled>Open my wallet <span>→</span></button><p class="error" id="form-error" role="alert"></p></form>`;
}
function bindRestore() {
  root.querySelector('#restore-form').onsubmit = async (event) => {
    event.preventDefault();
    try {
      replaceConfirmed();
      await unlock(
        root.querySelector('#words').value,
        root.querySelector('#passphrase').value,
        Number(root.querySelector('#account-index').value),
        root.querySelector('#keep-password')?.value || '',
      );
    } catch (e) { root.querySelector('#form-error').textContent = e.message; }
  };
}
function bindCreate() {
  const ack = root.querySelector('#ack');
  const button = root.querySelector('.primary');
  ack.onchange = () => { button.disabled = !ack.checked; };
  root.querySelector('#create-form').onsubmit = async (event) => {
    event.preventDefault();
    if (!ack.checked) return;
    try {
      replaceConfirmed();
      await unlock(generatedWords, '', 0, root.querySelector('#keep-password')?.value || '', true);
      generatedWords = '';
    } catch (e) { root.querySelector('#form-error').textContent = e.message; }
  };
}
/// The collections this deployment knows about, from `config.json`.
const knownCollections = () => (config.collections || [])
  .filter((c) => /^[0-9a-f]{64}$/i.test(String(c.id)))
  .map((c) => ({ name: String(c.name || 'Collection'), id: unhex(c.id, 32) }));

async function unlock(words, passphrase, index, keepPassword = '', fresh = false) {
  if ((IN_EXTENSION || setupMode) && !keepPassword) throw new Error('Choose a password for this browser (8+ characters)');
  const nextIdentity = deriveIdentity(words, passphrase, index);
  // The Zcash keys come from the same words, so this is the moment for them
  // too. If the Zcash code cannot load here, the Zyn wallet still opens and
  // the Zcash section says why it is missing.
  try { nextIdentity.zec = await deriveZecKeys(words, passphrase, index); } catch { nextIdentity.zec = undefined; }
  // Derived here because this is the only moment the phrase exists. A kept
  // wallet stores these too — without them, a reopened wallet cannot see what
  // its owner bought.
  const nextReceiving = knownCollections().map((c) => ({
    ...deriveCollectionAccount(words, passphrase, index, c.id),
    name: c.name,
  }));
  // Sealed before the phrase is wiped from the form, and only if asked. A
  // failure here must not cost the unlock — the wallet still works, it just
  // will not be here next time, and the holder is told which.
  let kept = null;
  if (keepPassword) {
    try {
      kept = await sealWallet(nextIdentity, nextReceiving, keepPassword, index);
      if (!keepWallet(kept)) kept = null;
    } catch (e) { kept = null; throw e; }
  }
  clearSession(); identity = nextIdentity; receiving = nextReceiving; zecFresh = fresh;
  if (kept) void saveSession(identity, receiving);
  root.querySelectorAll('textarea,input').forEach((el) => { if (el.type !== 'checkbox') el.value = ''; });
  const siteWaiting = setupMode ? ' If a site opened a Nap window for this, go back to it — it asks for this password now.' : '';
  if (kept) endSetup();
  wallet(kept ? (IN_EXTENSION ? `Your wallet is ready. Open it any time from the Nap icon in your toolbar (pin it from the puzzle-piece menu).${siteWaiting}` : setupMode ? 'Your wallet is kept in this browser. Go back to the Nap window the site opened — it asks for this password now.' : 'Kept on this device. Your password opens it next time; your phrase still restores it anywhere.') : '');
  // Quietly: a first sync announcing its epoch would replace the message
  // above before anyone reads it.
  refresh(!kept);
  if (kept) offerBiometrics(keepPassword);
}

/// Open a wallet this device already holds.
async function openKept(password) {
  const opened = await openSealedWallet(keptWallet(), password);
  clearSession();
  void saveSession(opened.identity, opened.receiving);
  identity = opened.identity;
  // Names are not sealed — they are deployment labels, not secrets — so they
  // are matched back from the current config.
  const named = knownCollections();
  receiving = opened.receiving.map((r) => ({
    ...r,
    name: (named.find((c) => hex(c.id) === hex(r.collection)) || {}).name || 'Collection',
  }));
  root.querySelectorAll('input').forEach((el) => { if (el.type !== 'checkbox') el.value = ''; });
  wallet();
  refresh();
}

function wallet(message = '') {
  const account = identity.accountHex;
  shell(`<main class="wallet">
    <aside class="rail">
      <div><p class="kicker">ZYN ACCOUNT</p><button class="account-copy" id="copy-account"><b>${short(account)}</b><span>Copy full ID</span></button></div>
      <nav><button class="active">Pocket</button><button id="zec-link">Zcash</button><button id="receive-link">Receive</button><button id="market-link">Market</button><button id="bridge-link">Bridge</button>${napBrowser ? '<button id="browser-link">Browser</button>' : ''}<button id="recovery-link">Recovery</button></nav>
      <button class="quiet" id="forget">${keptWallet() ? 'Lock' : 'Lock &amp; forget key'}</button>
    </aside>
    <section class="content">
      <div class="topline"><div><h1>Pocket</h1></div><button class="refresh" id="refresh" aria-label="Refresh"><span aria-hidden="true">↻</span><span class="refresh-word">Refresh</span></button></div>
      <div class="notice ${message ? 'show' : ''}" id="notice">${escapeHtml(message)}</div>
      ${claimCode ? `<section class="claim"><div><p class="kicker">GIFT CARD</p><h2>Nap Mole to claim${tip('The gift coordinator sees this public account ID, not your phrase or key.')}</h2></div><button id="claim">Claim <span>→</span></button></section>` : ''}
      ${tapLink ? `<section class="claim"><div><p class="kicker">EVENT TAG</p><h2>Certificate to collect${tip('The certificate service learns this account ID and nothing else. Nobody can see who holds it.')}</h2></div><button id="attend">Collect <span>→</span></button></section>` : ''}
      ${zecSection()}
      <section><div class="section-title"><h2>Coins</h2><span id="coin-count">—</span></div><div class="coins" id="coins"><div class="skeleton"></div></div></section>
      <section><div class="section-title"><h2>Items</h2><span id="item-count">—</span></div><label class="art-consent"><input type="checkbox" id="art-toggle"><span>Show artwork${tip("Loads each item's picture from the gateway, which tells that host your IP address, which items you hold, and when. Off by default.")}</span></label><div class="items" id="items"><div class="skeleton"></div><div class="skeleton"></div></div></section>
      <section class="activity"><div class="section-title"><h2>Account</h2></div><div class="account-card"><div><span>Public account</span><code>${account}</code></div><canvas id="qr" width="164" height="164"></canvas></div></section>
      <section class="activity"><div class="section-title"><h2>Deposit ZEC</h2></div><div class="account-card" id="deposit-card"><div><span>Your Zcash deposit address</span><code id="deposit-address">Asking the node…</code><p class="muted" id="deposit-note">Arrives as ZEC.zy.${tip('Send shielded ZEC here. No memo needed; this address is yours alone.')}</p><button class="quiet" id="copy-deposit" hidden>Copy address</button> <button class="quiet" id="deposit-from-zec">Pay it from my ZEC →</button></div><canvas id="deposit-qr" width="164" height="164"></canvas></div></section>
      ${config.kind === 'object' ? `<section class="activity"><div class="section-title"><h2>Withdraw ZEC</h2></div><form class="account-card" id="withdraw-form"><div><span>Send ZEC.zy back to a Zcash address</span><label class="visually-hidden" for="withdraw-to">Zcash address</label><input id="withdraw-to" class="withdraw-input" autocomplete="off" spellcheck="false" placeholder="${escapeHtml(config.zcashPrefix)}… or t…"><label class="visually-hidden" for="withdraw-amount">Amount</label><input id="withdraw-amount" class="withdraw-input" inputmode="decimal" autocomplete="off" placeholder="0.0 ZEC"><p class="muted">Fees${tip('The chain records only a commitment to the address. The vault pays it once two custodians sign. The Zcash network fee comes out of the amount; any bridge fee is added on top.')}</p></div><div><button class="primary" type="submit" id="withdraw-go">Withdraw <span>→</span></button></div></form></section>` : ''}
    </section>
  </main><dialog id="send-dialog"></dialog><dialog id="shield-dialog"></dialog><dialog id="recovery-dialog"><button class="x">×</button><h2>Recovery</h2><p>Restore this phrase, passphrase and account index in any Nap to recover <code>${account}</code>. Nap does not store the phrase.</p><div class="descriptor"><span>Derivation</span><b>nap.zyn.ed25519.v1</b><span>Account index</span><b>${identity.accountIndex}</b><span>Network scoped</span><b>No</b></div></dialog>`);
  QRCode.toCanvas(root.querySelector('#qr'), account, { width: 164, margin: 1, color: { dark: '#1f2428', light: '#f8f2e4' } });
  void loadDepositAddress(identity);
  root.querySelector('#withdraw-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = root.querySelector('#withdraw-go');
    button.disabled = true;
    try {
      const to = root.querySelector('#withdraw-to').value.trim();
      if (!to.startsWith(config.zcashPrefix) && !/^t[a-z0-9]/i.test(to)) throw new Error(`That is not a ${config.zcash} address`);
      await withdrawToZcash(to, root.querySelector('#withdraw-amount').value.trim());
      note('Withdrawal recorded. The vault pays it once two custodians sign — usually within minutes.');
      root.querySelector('#withdraw-amount').value = '';
      refresh(false);
    } catch (err) { note(err.message, true); } finally { button.disabled = false; }
  });
  root.querySelector('#copy-account').onclick = async () => { await navigator.clipboard.writeText(account); note('Account ID copied.'); };
  root.querySelector('#receive-link').onclick = () => root.querySelector('.account-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
  // Same origin, same kept key: the market opens it with the same password.
  root.querySelector('#market-link').onclick = () => openPage('/market.html');
  root.querySelector('#bridge-link').onclick = () => (bridgePage(config) ? window.open(bridgePage(config), '_blank', 'noopener') : openPage('/bridge.html'));
  root.querySelector('#recovery-link').onclick = () => root.querySelector('#recovery-dialog').showModal();
  root.querySelector('#browser-link')?.addEventListener('click', () => napBrowser.openBrowser('').catch((e) => note(String(e).slice(0, 160), true)));
  root.querySelector('#recovery-dialog .x').onclick = () => root.querySelector('#recovery-dialog').close();
  // Locking returns to whatever this device can actually offer: a password if
  // the wallet is kept here, the phrase if it is not.
  root.querySelector('#forget').onclick = () => { clearSession(); void endSession(); onboarding(keptWallet() ? 'kept' : 'restore'); };
  root.querySelector('#refresh').onclick = () => { refresh(); zecSync(); };
  root.querySelector('#zec-link').onclick = () => root.querySelector('#zec').scrollIntoView({ behavior: 'smooth', block: 'start' });
  root.querySelector('#deposit-from-zec').onclick = () => {
    const address = root.querySelector('#deposit-address').textContent.trim();
    if (!address.startsWith(config.zcashPrefix)) { note('The deposit address has not arrived yet.', true); return; }
    const to = root.querySelector('#zec-to');
    if (!to) { note('Open your Zcash wallet first.', true); return; }
    to.value = address;
    root.querySelector('#zec').scrollIntoView({ behavior: 'smooth', block: 'start' });
    root.querySelector('#zec-amount').focus();
  };
  bindZec();
  root.querySelector('#claim')?.addEventListener('click', claimGift);
  root.querySelector('#attend')?.addEventListener('click', collectCertificate);
}
// ---------------------------------------------------------------------------
// Zcash: plain shielded ZEC, synced, received and sent from this tab.
// ---------------------------------------------------------------------------

const zecNetwork = () => (config.zcashPrefix === 'u1' ? 'mainnet' : 'testnet');
const ZAT = 100_000_000n;
/// Zatoshi as ZEC, exactly: never through a float.
function zecText(zat) {
  const v = BigInt(zat);
  const frac = (v % ZAT).toString().padStart(8, '0').replace(/0+$/, '');
  return `${v / ZAT}${frac ? `.${frac}` : ''}`;
}
function zatOf(text) {
  if (!/^\d+(\.\d{1,8})?$/.test(text)) throw new Error('Enter an amount in ZEC, up to eight decimals');
  const [whole, frac = ''] = text.split('.');
  const zat = BigInt(whole) * ZAT + BigInt(frac.padEnd(8, '0'));
  if (zat <= 0n) throw new Error('Enter an amount above zero');
  if (zat > 21_000_000n * ZAT) throw new Error('That is more ZEC than exists');
  return Number(zat);
}

function zecSection() {
  if (!identity.zec) {
    const kept = !!keptWallet();
    return `<section class="zec" id="zec"><div class="section-title"><h2>Zcash</h2><span>not on this device yet</span></div>
      <form class="account-card zec-add" id="zec-add"><div><span>Add your Zcash wallet</span><p class="muted">Enter your recovery phrase once.${tip(`This device was set up before Nap held ZEC in the browser, so it has your Zyn keys but not your Zcash keys${kept ? '. Your device password seals them with the rest' : ''}.`)}</p>
        <label class="visually-hidden" for="zec-add-words">Recovery phrase</label><textarea id="zec-add-words" class="withdraw-input" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="24-word recovery phrase"></textarea>
        <label class="visually-hidden" for="zec-add-pass">Passphrase</label><input id="zec-add-pass" class="withdraw-input" type="password" autocomplete="off" placeholder="Passphrase, if you used one">
        ${kept ? '<label class="visually-hidden" for="zec-add-device">Device password</label><input id="zec-add-device" class="withdraw-input" type="password" autocomplete="current-password" placeholder="This device\'s password">' : ''}
      </div><div><button class="primary" type="submit">Add Zcash <span>→</span></button></div></form></section>`;
  }
  return `<section class="zec" id="zec"><div class="section-title"><h2>Zcash</h2><span id="zec-sync">Opening…</span></div>
    <div class="zec-balance"><div><b id="zec-total">—</b><span>ZEC</span></div><p id="zec-detail" class="zec-detail">Shielded. Only this phrase can see it.</p></div>
    <div class="zec-transparent" id="zec-t" hidden><div><span class="zec-t-label">Transparent · public</span><b id="zec-t-amount">—</b></div><button class="primary" type="button" id="zec-shield">Shield <span>→</span></button></div>
    <div class="zec-seg" role="group" aria-label="Receive"><button type="button" data-addr="shielded" aria-pressed="true">Shielded address</button><button type="button" data-addr="transparent" aria-pressed="false">Transparent address</button></div>
    <div class="account-card" id="zec-receive"><div><span id="zec-address-label">Your Zcash address</span><code id="zec-address">Opening…</code><p class="muted" id="zec-address-note">Shielded${tip('Pay it from any Zcash wallet or exchange that sends shielded. What arrives is visible only to this phrase.')}</p><button class="quiet" id="zec-copy" hidden>Copy address</button></div><canvas id="zec-qr" width="164" height="164"></canvas></div>
    <form class="account-card" id="zec-send"><div><span>Send ZEC</span>
      <label class="visually-hidden" for="zec-to">Zcash address</label><input id="zec-to" class="withdraw-input" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="${escapeHtml(config.zcashPrefix)}… or t…">
      <label class="visually-hidden" for="zec-amount">Amount</label><input id="zec-amount" class="withdraw-input" inputmode="decimal" autocomplete="off" placeholder="0.0 ZEC">
      <label class="visually-hidden" for="zec-memo">Memo</label><input id="zec-memo" class="withdraw-input" maxlength="512" autocomplete="off" placeholder="Memo (optional, shielded addresses only)">
      <p class="muted" id="zec-send-note">Network fee added on top.${tip('Proving takes about half a minute on this device; keep the tab open.')}</p></div>
      <div><button class="primary" type="submit" id="zec-go" disabled>Review <span>→</span></button></div></form>
    <ul class="zec-notes" id="zec-notes"></ul></section>`;
}

function zecStatus(text, bad = false) {
  const el = root.querySelector('#zec-sync');
  if (!el) return;
  el.textContent = text;
  el.classList.toggle('bad', bad);
}

let zecQrFor = '';
function renderZec(v) {
  const el = root.querySelector('#zec');
  if (!el || !v) return;
  const held = v.balance.orchard + v.balance.ironwood;
  root.querySelector('#zec-total').textContent = zecText(held);
  const parts = [];
  if (v.balance.inFlight) parts.push(`${zecText(v.balance.inFlight)} ZEC on its way (change from a send, back after 3 blocks)`);
  if (v.balance.orchard && v.balance.ironwood) parts.push(`Ironwood ${zecText(v.balance.ironwood)} · Orchard ${zecText(v.balance.orchard)}`);
  root.querySelector('#zec-detail').textContent = parts.join(' · ') || 'Shielded. Only this phrase can see it.';
  renderZecAddress(v);
  root.querySelector('#zec-go').disabled = held === 0;
  if (v.syncedTo >= 0) zecStatus(`synced to block ${v.syncedTo.toLocaleString('en-US')}`);
  const notes = root.querySelector('#zec-notes');
  const shieldLog = activity(config, identity).filter((a) => a.kind === 'shield').slice(0, 6);
  const shields = shieldLog.map((a) => `<li><b>${escapeHtml(a.amount)} ZEC</b><span>shielded from transparent</span><code>${escapeHtml(short(a.tx || ''))}</code></li>`);
  // A shield's note is listed once, as the shield.
  const shieldTx = new Set(shieldLog.map((a) => a.tx));
  const received = v.notes.filter((n) => !shieldTx.has(n.txid)).slice(0, 12).map((n) => `<li><b>${escapeHtml(zecText(n.zatoshi))} ZEC</b><span>received at block ${Number(n.height).toLocaleString('en-US')}</span><code>${escapeHtml(short(n.txid))}</code></li>`);
  notes.innerHTML = shields.length || received.length
    ? [...shields, ...received].join('')
    : `<li class="zec-empty">Nothing received since block ${Number(v.birthday).toLocaleString('en-US')}. <button type="button" class="quiet" id="zec-rescan">Scan from an earlier block…</button></li>`;
  root.querySelector('#zec-rescan')?.addEventListener('click', zecRescan);
}

// Receive: the shielded address by default; the transparent one for
// exchanges that pay only transparent, said to be public where it shows.
let zecAddressMode = 'shielded';
function renderZecAddress(v = zecAccount?.view) {
  if (!v || !root.querySelector('#zec-receive')) return;
  const t = zecAddressMode === 'transparent';
  root.querySelectorAll('.zec-seg [data-addr]').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.addr === zecAddressMode)));
  const text = t ? v.transparent : v.address;
  const card = root.querySelector('#zec-receive');
  card.classList.toggle('public', t);
  root.querySelector('#zec-address-label').textContent = t ? 'Your transparent address' : 'Your Zcash address';
  root.querySelector('#zec-address-note').innerHTML = t
    ? `<b class="public-line">Payments to this address are public.</b>${tip('Use it for exchanges that only pay transparent addresses. When the ZEC arrives, press Shield to move it into your shielded balance.')}`
    : `Shielded${tip('Pay it from any Zcash wallet or exchange that sends shielded. What arrives is visible only to this phrase.')}`;
  const address = root.querySelector('#zec-address');
  const qr = root.querySelector('#zec-qr');
  if (t && !text) {
    address.innerHTML = 'Needs your recovery phrase once. <button type="button" class="quiet" id="zec-t-add">Add transparent address…</button>';
    root.querySelector('#zec-t-add').onclick = addTransparent;
    root.querySelector('#zec-copy').hidden = true;
    qr.hidden = true;
    return;
  }
  qr.hidden = false;
  address.textContent = text;
  root.querySelector('#zec-copy').hidden = false;
  if (zecQrFor !== text || !qr.dataset.drawn) {
    zecQrFor = text;
    QRCode.toCanvas(qr, text, { width: 164, margin: 1, color: { dark: '#1f2428', light: '#f8f2e4' } });
    qr.dataset.drawn = '1';
  }
}

// The transparent balance: one UTXOS question to the block server, which
// names this public address (never the shielded one). Asked after each sync.
let zecPlan = null;
async function zecTransparent() {
  const account = zecAccount, current = generation;
  if (!account?.tsk) return;
  try {
    const plan = await account.transparent();
    if (current !== generation || zecAccount !== account) return;
    zecPlan = plan;
    const row = root.querySelector('#zec-t');
    if (!row) return;
    row.hidden = !(plan.total > 0);
    root.querySelector('#zec-t-amount').textContent = `${zecText(plan.total)} ZEC`;
    const go = root.querySelector('#zec-shield');
    go.disabled = !(plan.net > 0);
    go.title = plan.total > 0 && !plan.net ? `Less than the ${zecText(plan.fee)} ZEC fee` : '';
  } catch { /* the next sync asks again */ }
}

function shieldDialog() {
  const plan = zecPlan;
  const dialog = root.querySelector('#shield-dialog');
  if (!plan?.net || !zecAccount) return;
  dialog.innerHTML = `<button class="x">×</button><p class="kicker">SHIELD</p><h2>Shield</h2>
    <div class="review"><span>Transparent</span><b>${escapeHtml(zecText(plan.total))} ZEC</b><span>Network fee</span><b>${escapeHtml(zecText(plan.fee))} ZEC</b><span>You receive</span><b>${escapeHtml(zecText(plan.net))} ZEC</b><span>Arrives as</span><b>shielded ZEC</b></div>
    <p class="muted" id="shield-state" role="status">Moves everything on your transparent address into your shielded balance.${tip('Proving takes about half a minute on this device; keep the tab open. The fee is ZIP-317: one input and two shielded actions.')}</p>
    <button class="primary" id="shield-go">Shield ${escapeHtml(zecText(plan.net))} ZEC <span>→</span></button>`;
  dialog.querySelector('.x').onclick = () => dialog.close();
  dialog.querySelector('#shield-go').onclick = async () => {
    const go = dialog.querySelector('#shield-go'), state = dialog.querySelector('#shield-state');
    const account = zecAccount, current = generation;
    go.disabled = true; dialog.querySelector('.x').disabled = true;
    go.innerHTML = 'Shielding… <span></span>';
    state.classList.remove('bad');
    try {
      const view = await account.shield((s) => {
        if (s.proving) state.textContent = 'Proving… about half a minute. Keep this tab open.';
        else if (s.to) state.textContent = `Catching up: ${Number(s.at).toLocaleString('en-US')} of ${Number(s.to).toLocaleString('en-US')}`;
      });
      if (current !== generation) return;
      // Both views list it: Activity here and in the compact wallet.
      logActivity(config, identity, { kind: 'shield', title: 'Shielded ZEC', symbol: 'ZEC', amount: zecText(view.shielded.net), tx: view.txid });
      dialog.querySelector('.review').innerHTML = `<span>Shielded</span><b>${escapeHtml(zecText(view.shielded.net))} ZEC</b><span>Transaction</span><b><code class="txid">${escapeHtml(view.txid)}</code></b>`;
      state.textContent = 'Sent. It shows in your shielded balance in a few blocks (about 5 minutes).';
      go.innerHTML = 'Done <span>→</span>'; go.disabled = false; dialog.querySelector('.x').disabled = false;
      go.onclick = () => dialog.close();
      renderZec(view);
      zecPlan = null; root.querySelector('#zec-t').hidden = true;
      void zecTransparent();
    } catch (e) {
      state.textContent = e.message; state.classList.add('bad');
      go.innerHTML = 'Try again <span>→</span>'; go.disabled = false; dialog.querySelector('.x').disabled = false;
    }
  };
  dialog.showModal();
}

/// A wallet kept before Nap had transparent keys: the phrase, once, to add them.
function addTransparent() {
  const dialog = root.querySelector('#shield-dialog');
  const kept = !!keptWallet();
  dialog.innerHTML = `<button class="x">×</button><p class="kicker">TRANSPARENT ADDRESS</p><h2>Add it</h2><p class="muted">Enter your recovery phrase once.${tip(`This device was set up before Nap had a transparent address, so it does not hold that key${kept ? '. Your device password seals it with the rest' : ''}.`)}</p>
    <form id="t-add"><label>Recovery phrase<textarea id="t-add-words" rows="3" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></label>
    <label>Passphrase<input id="t-add-pass" type="password" autocomplete="off" placeholder="Blank if unused"></label>
    ${kept ? '<label>This device\'s password<input id="t-add-device" type="password" autocomplete="current-password"></label>' : ''}
    <button class="primary" type="submit">Add <span>→</span></button><p class="error" role="alert"></p></form>`;
  dialog.querySelector('.x').onclick = () => dialog.close();
  dialog.querySelector('form').onsubmit = async (e) => {
    e.preventDefault();
    const button = dialog.querySelector('.primary'), error = dialog.querySelector('.error');
    button.disabled = true; error.textContent = '';
    try {
      const words = dialog.querySelector('#t-add-words').value;
      const passphrase = dialog.querySelector('#t-add-pass').value;
      const check = deriveIdentity(words, passphrase, identity.accountIndex);
      const same = check.accountHex === identity.accountHex;
      forgetIdentity(check);
      if (!same) throw new Error('That phrase opens a different wallet than this one.');
      const keys = await deriveZecKeys(words, passphrase, identity.accountIndex);
      const device = dialog.querySelector('#t-add-device');
      if (device) await openSealedWallet(keptWallet(), device.value);
      identity.zec.transparent = keys.transparent;
      if (device && !keepWallet(await sealWallet(identity, receiving, device.value, identity.accountIndex))) throw new Error('Could not save to this device; the address works until you lock.');
      if (hasSession) await saveSession(identity, receiving);
      dialog.close();
      zecAddressMode = 'transparent';
      wallet('Transparent address added.');
      refresh(false);
    } catch (err) { error.textContent = err.message; button.disabled = false; }
  };
  dialog.showModal();
}

async function zecStart() {
  if (!root.querySelector('#zec') || !identity) return;
  if (!identity.zec) return;
  if (!config.lightdUrl) { zecStatus('no block server for this network', true); return; }
  const net = zecNetwork(), current = generation;
  const account = new ZecAccount({ sk: identity.zec[net], tsk: identity.zec.transparent?.[net] || null, network: net, url: config.lightdUrl, birthday: config.zecBirthday });
  zecAccount = account;
  try {
    zecStatus('opening…');
    const view = await account.open({ fresh: zecFresh });
    zecFresh = false;
    if (current !== generation || zecAccount !== account) return;
    renderZec(view);
    // Before the scan, which can take minutes for a restored phrase: money
    // waiting on the transparent address shows at once.
    await zecTransparent();
    await zecSync();
  } catch (e) {
    if (current === generation) zecStatus(e.message, true);
  }
}

async function zecSync() {
  const account = zecAccount, current = generation;
  if (!account) return;
  clearTimeout(zecTimer);
  try {
    const view = await account.sync((s) => {
      if (current !== generation) return;
      if (s.to) zecStatus(`scanning ${Number(s.at).toLocaleString('en-US')} of ${Number(s.to).toLocaleString('en-US')}`);
      for (const e of s.events || []) {
        if (e.kind === 'received') note(`Received ${zecText(e.zatoshi)} ZEC${e.memo ? ` — “${e.memo}”` : ''}.`);
      }
    });
    if (current === generation && zecAccount === account) { renderZec(view); void zecTransparent(); }
  } catch (e) {
    if (current === generation) zecStatus(e.message, true);
  } finally {
    // Zcash makes a block about every 75 seconds; asking more often finds nothing.
    if (current === generation && zecAccount === account) zecTimer = setTimeout(zecSync, 75_000);
  }
}

async function zecRescan() {
  const answer = prompt('Scan from which block height? Earlier finds older payments and takes longer.', String(config.zecBirthday || ''));
  if (answer === null) return;
  const height = Number(answer.trim());
  if (!Number.isInteger(height) || height < 1) { note('A block height is a whole number.', true); return; }
  try {
    zecStatus('starting over…');
    renderZec(await zecAccount.rescanFrom(height));
    await zecSync();
  } catch (e) { zecStatus(e.message, true); }
}

function bindZec() {
  const add = root.querySelector('#zec-add');
  if (add) {
    add.onsubmit = async (e) => {
      e.preventDefault();
      const button = add.querySelector('.primary');
      button.disabled = true;
      try {
        const words = add.querySelector('#zec-add-words').value;
        const passphrase = add.querySelector('#zec-add-pass').value;
        // The phrase must be this wallet's: the Zyn account it derives has to
        // be the one already open, or these would be someone else's keys.
        const check = deriveIdentity(words, passphrase, identity.accountIndex);
        const same = check.accountHex === identity.accountHex;
        forgetIdentity(check);
        if (!same) throw new Error('That phrase opens a different wallet than this one.');
        const keys = await deriveZecKeys(words, passphrase, identity.accountIndex);
        const device = add.querySelector('#zec-add-device');
        if (device) {
          // Opening the current record proves the password before it seals anything new.
          await openSealedWallet(keptWallet(), device.value);
          identity.zec = keys;
          if (!keepWallet(await sealWallet(identity, receiving, device.value, identity.accountIndex))) throw new Error('Could not save to this device; Zcash works until you lock.');
        } else identity.zec = keys;
        add.querySelectorAll('textarea,input').forEach((el) => { el.value = ''; });
        zecFresh = false;
        wallet('Zcash added. It scans from a recent block; use “Scan from an earlier block” if your ZEC is older.');
        refresh(false);
      } catch (err) { note(err.message, true); button.disabled = false; }
    };
    return;
  }
  const form = root.querySelector('#zec-send');
  if (!form) return;
  root.querySelector('#zec-copy').onclick = async () => {
    await navigator.clipboard.writeText(root.querySelector('#zec-address').textContent);
    note(zecAddressMode === 'transparent' ? 'Transparent address copied.' : 'Zcash address copied.');
  };
  root.querySelectorAll('.zec-seg [data-addr]').forEach((b) => { b.onclick = () => { zecAddressMode = b.dataset.addr; renderZecAddress(); }; });
  root.querySelector('#zec-shield').onclick = shieldDialog;
  const go = root.querySelector('#zec-go');
  const disarm = () => { delete go.dataset.armed; go.innerHTML = 'Review <span>→</span>'; };
  form.querySelectorAll('input').forEach((el) => { el.oninput = disarm; });
  // A transparent recipient takes no memo: the field says so rather than
  // refusing at Review.
  const memoField = root.querySelector('#zec-memo');
  root.querySelector('#zec-to').addEventListener('input', (e) => {
    const t = /^t[a-z0-9]{3,}$/i.test(e.target.value.trim());
    memoField.disabled = t;
    if (t) memoField.value = '';
    memoField.placeholder = t ? 'No memo: transparent address' : 'Memo (optional, shielded addresses only)';
  });
  // A ZIP-321 request (a shop's QR, a "zcash:" link) pasted as the recipient
  // fills in the whole payment, which the holder still reviews.
  root.querySelector('#zec-to').addEventListener('input', (e) => {
    const v = e.target.value.trim();
    if (!/^zcash:/i.test(v)) return;
    try {
      const r = parsePaymentRequest(v);
      e.target.value = r.address;
      if (r.zatoshi != null) root.querySelector('#zec-amount').value = zecText(r.zatoshi);
      root.querySelector('#zec-memo').value = r.memo;
      note(r.message ? `Payment request: “${r.message}”. Check it, then review.` : 'Payment request filled in. Check it, then review.');
    } catch (err) { note(err.message, true); }
  });
  form.onsubmit = async (e) => {
    e.preventDefault();
    try {
      const to = root.querySelector('#zec-to').value.trim();
      const memo = root.querySelector('#zec-memo').value;
      if (/^[0-9a-f]{64}$/i.test(to)) throw new Error('That is a Zyn account. This sends ZEC on Zcash; to pay a Zyn account, send ZEC.zy or an item from Coins and Items below.');
      const transparent = /^t[a-z0-9]{20,}$/i.test(to);
      if (!to.startsWith(config.zcashPrefix) && !transparent) throw new Error(`That is not a ${config.zcash} address.`);
      if (transparent && memo) throw new Error('A memo only reaches a shielded address.');
      const zat = zatOf(root.querySelector('#zec-amount').value.trim());
      if (!go.dataset.armed) {
        go.dataset.armed = '1';
        go.innerHTML = `Confirm: send ${escapeHtml(zecText(zat))} ZEC <span>→</span>`;
        note(`To ${short(to)}. A Zcash transaction cannot be undone.`);
        return;
      }
      go.disabled = true;
      const view = await zecAccount.send(to, zat, memo, (s) => {
        if (s.proving) zecStatus('proving the transaction… about half a minute');
        else if (s.to) zecStatus(`scanning ${Number(s.at).toLocaleString('en-US')} of ${Number(s.to).toLocaleString('en-US')}`);
      });
      renderZec(view);
      form.reset();
      note(`Sent ${zecText(zat)} ZEC. Transaction ${view.txid}.`);
    } catch (err) {
      note(err.message, true);
      zecStatus('ready');
    } finally {
      disarm();
      go.disabled = false;
    }
  };
  void zecStart();
}

function note(text, bad = false) {
  const el = root.querySelector('#notice');
  if (!el) return;
  el.textContent = text; el.classList.add('show'); el.classList.toggle('bad', bad);
}

async function refresh(announce = true) {
  if (!identity) return;
  const owner = identity, current = generation, request = ++refreshId;
  const active = () => generation === current && request === refreshId;
  const button = root.querySelector('#refresh');
  if (button) button.disabled = true;
  try {
    const status = await rpc(config.rpcUrl, 'zyn_status');
    if (!active()) return;
    const epoch = checkedEpoch(status, config.chain);

    // An object ledger answers none of the questions below. It publishes
    // commitments and nullifiers and says nothing about who owns what, so the
    // balance is computed here from the holder's own keys rather than asked
    // for. Everything after this point is the AMM chains' shape.
    if (config.kind === 'object') {
      await refreshObject(epoch, announce, active);
      return;
    }
    // The identity *and* every receiving account. An item bought through a
    // store lands in the latter (§97.5), so reading only the identity shows an
    // empty pocket to somebody who has just paid.
    const owners = [{ key: owner, name: null }, ...receiving.map((r) => ({ key: r, name: r.name }))];
    const [allAssets, allOffers, ...records] = await Promise.all([
      rpc(config.rpcUrl, 'zyn_assets'),
      // A listed item is escrowed, so it is gone from `spendable` — without
      // this the wallet would show it as vanished the moment it was listed.
      rpc(config.rpcUrl, 'zyn_offers').catch(() => []),
      ...owners.map((o) => rpc(config.rpcUrl, 'zyn_account', [hex(signedRead(o.key, config.chain, epoch))])),
    ]);
    if (!active()) return;
    if (!Array.isArray(allAssets)) throw new Error('Malformed holdings response');
    const validAsset = (id) => typeof id === 'string' && /^[a-f0-9]{64}$/.test(id);
    if (!allAssets.every((a) => validAsset(a.id))) throw new Error('Invalid asset identifier');

    const merged = [];
    for (const [i, record] of records.entries()) {
      if (record !== null && !Array.isArray(record?.spendable)) throw new Error('Malformed holdings response');
      for (const h of record?.spendable || []) {
        if (!validAsset(h.asset)) throw new Error('Invalid asset identifier');
        // Tagged with the account it was found in, so a send signs with the
        // key that actually holds the item rather than the identity's.
        merged.push({ ...h, owner: owners[i].key, via: owners[i].name });
      }
    }
    const mine = new Map(owners.map((o) => [hex(o.key.account), o]));
    listings = (Array.isArray(allOffers) ? allOffers : [])
      .filter((o) => mine.has(String(o.maker)))
      .map((o) => ({ ...o, owner: mine.get(String(o.maker)).key, via: mine.get(String(o.maker)).name }));
    assets = allAssets;
    holdings = merged;
    renderCoins();
    renderItems();
    if (announce) note(`Synced at epoch ${status.epoch}.`);
  } catch (e) {
    if (!active()) return;
    holdings = []; assets = []; listings = [];
    const coinCount = root.querySelector('#coin-count');
    if (coinCount) coinCount.textContent = 'Unavailable';
    const coinList = root.querySelector('#coins');
    if (coinList) coinList.innerHTML = '';
    root.querySelector('#item-count').textContent = 'Unavailable';
    root.querySelector('#items').innerHTML = '<div class="empty"><h3>Holdings unavailable.</h3><p>Reconnect and refresh before sending.</p></div>';
    note(e.message === 'Failed to fetch' ? 'RPC unavailable. Your key is safe; try again when the connection returns.' : e.message, true);
  } finally { if (button) button.disabled = false; }
}

// The deposit address is not the account. The account receives Zyn items from
// other Zyn users; this receives *Zcash*, and sending ZEC to the account id
// would be sending it to a string that is not an address at all. They sit in
// separate cards, labelled differently, for that reason.
//
// Asking requires a signature, which the browser wallet can produce and a
// stranger cannot: issuing an address writes it into the node's scan register,
// so the public method is gated rather than open (DECISIONS 87.6).
/// Sign and send an intent through the object ledger's holders' door. A
/// refusal inside the receipts is an error here too.
async function submitObject(intent) {
  const status = await rpc(config.rpcUrl, 'zyn_status');
  const epoch = checkedEpoch(status, config.chain);
  const frame = await objectFrame(identity.secretKey, config.chain, epoch + 100n, intent);
  const result = await submitSigned(config.rpcUrl, frame);
  const refused = /Refused\("([^"]*)"\)/.exec(String(result?.receipts || ''));
  if (refused) throw new Error(`The chain refused: ${refused[1]}`);
  return result;
}

/// Publish where this account is paid: its viewing key. Public by design —
/// a payer who cannot read it cannot pay — and it cannot spend anything.
async function registerObjectAccount(owner) {
  await submitObject(registerIntent(owner.account, x25519.getPublicKey(owner.viewing)));
  // Done on its own when the wallet opens: said only if nothing more useful
  // (what to do next, after setting up) is already on show.
  if (!root.querySelector('#notice')?.classList.contains('show')) note('Registered this account to receive ZEC. Deposits to the address below are credited to it.');
}

const EXITS_KEY = () => `nap.exits.${config.chain}.${identity.accountHex}`;
const pendingExits = () => { try { return JSON.parse(localStorage.getItem(EXITS_KEY()) || '[]'); } catch { return []; } };
const savePendingExits = (list) => { try { localStorage.setItem(EXITS_KEY(), JSON.stringify(list)); } catch { /* this session only */ } };

/// Tell the vault where a withdrawal goes, now or on a later visit. The chain
/// holds only a commitment; until the address and salt are revealed the exit
/// is owed and cannot be paid. Kept on this device until the node files it.
async function revealExits() {
  const left = [];
  for (const x of pendingExits()) {
    try {
      await objectCall(config.rpcUrl, 'zyn_exitReveal', { address: x.address, salt: x.salt });
    } catch (e) {
      if (!/no unpaid exit/.test(e.message)) left.push(x);
    }
  }
  savePendingExits(left);
}

/// ZEC.zy back to Zcash: commit to the address, sign the withdrawal, reveal.
async function withdrawToZcash(address, amountText) {
  const zec = config.zecAsset;
  const raw = parseAmount(amountText);
  // The vault pays whole zatoshi: at most eight decimals.
  if (raw % 10_000_000_000n !== 0n) throw new Error('ZEC has eight decimal places');
  if (raw < 100_000n * 10_000_000_000n) throw new Error('Withdraw at least 0.001 ZEC — the Zcash fee comes out of it');
  const salt = hex(crypto.getRandomValues(new Uint8Array(32)));
  const { destination } = await objectCall(config.rpcUrl, 'zyn_exitCommitment', { address, salt });
  if (!/^[0-9a-f]{64}$/.test(String(destination))) throw new Error('The node did not return a commitment');
  // The bridge fee rides on top of what leaves, and stays in the ZYN pot.
  const market = await objectCall(config.rpcUrl, 'zyn_market');
  const bps = BigInt(Number(market?.fees?.bridge_bps) || 0);
  const fee = (raw * bps) / 10_000n;
  const { inputs, change } = fundFrom(identity, objectHeld, unhex(zec, 32), raw + fee);
  // Kept before submitting: if the page closes between the two steps, the
  // next visit still knows where this exit was meant to go.
  savePendingExits([...pendingExits(), { address, salt }]);
  await submitObject(withdrawIntent({ holder: identity.account, inputs, asset: unhex(zec, 32), amount: raw, destination: unhex(destination, 32), outputs: change }));
  await revealExits();
}

async function loadDepositAddress(owner) {
  const current = generation;
  const field = root.querySelector('#deposit-address');
  const note_ = root.querySelector('#deposit-note');
  const copy = root.querySelector('#copy-deposit');
  if (!field) return;
  try {
    let result;
    if (config.kind === 'object') {
      result = await objectCall(config.rpcUrl, 'zyn_depositAddress', { account: owner.accountHex });
      if (generation !== current) return;
      // An address only credits an account that has published where to be
      // paid. The node now holds such a payment as a debt rather than losing
      // it, but registering first means it is credited the moment it lands.
      if (result && result.registered === false && owner.viewing) {
        await registerObjectAccount(owner);
        if (generation !== current) return;
      }
    } else {
      const status = await rpc(config.rpcUrl, 'zyn_status');
      if (generation !== current) return;
      const payload = signedRead(owner, config.chain, checkedEpoch(status, config.chain));
      result = await rpc(config.rpcUrl, 'zyn_depositAddress', [hex(payload)]);
    }
    if (generation !== current) return;
    const address = result?.address;
    if (typeof address !== 'string' || !address) throw new Error('No address returned');
    // The header says which Zcash network this is. If the node hands back an
    // address from the other one, the header is wrong and the money would go
    // to a chain the buyer did not mean — so nothing is shown at all.
    if (!address.startsWith(config.zcashPrefix)) {
      throw new Error(`This node answered with an address that is not ${config.zcash}`);
    }
    field.textContent = address;
    copy.hidden = false;
    copy.onclick = async () => { await navigator.clipboard.writeText(address); note('Deposit address copied.'); };
    QRCode.toCanvas(root.querySelector('#deposit-qr'), address, { width: 164, margin: 1, color: { dark: '#1f2428', light: '#f8f2e4' } });
  } catch (e) {
    if (generation !== current) return;
    // Failing closed matters here: an address that is wrong, stale or someone
    // else's is worse than no address, so nothing is shown at all.
    field.textContent = 'Unavailable';
    note_.textContent = e.message === 'Failed to fetch'
      ? 'The node is unreachable, so no deposit address can be shown. Do not send ZEC anywhere until it returns.'
      : `No deposit address: ${e.message}`;
    root.querySelector('#deposit-qr')?.replaceChildren();
  }
}

/// Fungible holdings: what the account can spend, as opposed to what it owns
/// one of. ZEC.zy is always listed even at zero — somebody who has just sent a
/// deposit needs to watch it arrive, and an empty list would look like the
/// wallet had not noticed.

/// Hold-and-compute, for a chain that will not tell you what you own.
///
/// `zyn_published` carries every note the chain has ever published and every
/// nullifier it has seen. Opening the ones that belong to this wallet, and
/// dropping the ones already spent, is the balance. Nothing here asks the
/// operator a question whose answer they could tailor.
async function refreshObject(epoch, announce, active) {
  if (!identity?.viewing || !identity?.nullifier) {
    holdings = []; assets = []; listings = [];
    renderCoins(); renderItems();
    note('This wallet was stored before the object ledger existed. Restore it from the recovery phrase to read balances here.', true);
    return;
  }

  const published = await rpc(config.rpcUrl, 'zyn_published');
  if (!active()) return;
  const { held } = scanObjects(published, {
    secret: identity.viewing,
    nkey: identity.nullifier,
    owner: identity.account,
  });

  // An object ledger has no asset registry, so the only name this wallet can
  // put to an id is the one the deployment pinned. Anything else is shown by
  // its id rather than given a name nobody assigned.
  const zec = config.zecAsset;
  const seen = [...new Set(held.map((h) => h.asset))];
  // Items are their own assets; the node says which collection and serial.
  const items = new Map();
  const others = seen.filter((a) => a !== zec);
  if (others.length) {
    try {
      for (const i of await objectCall(config.rpcUrl, 'zyn_items', { assets: others.slice(0, 500).join(',') })) {
        if (/^[0-9a-f]{64}$/.test(i.asset) && /^[0-9a-f]{64}$/.test(i.collection) && Number.isSafeInteger(i.serial)) items.set(i.asset, i);
      }
    } catch { /* names only: an item still shows, by id */ }
    if (!active()) return;
  }
  // Launchpad tokens name themselves: their ticker is in the curve's meta.
  const tickers = new Map();
  if (others.some((a) => !items.has(a))) {
    try {
      const market = await objectCall(config.rpcUrl, 'zyn_market');
      for (const c of market.curves || []) {
        const m = /^[0-9a-f]{64}$/.test(c.token) && typeof c.meta === 'string' ? decodeMeta(c.meta) : null;
        if (m) tickers.set(c.token, m.symbol);
      }
      // Bridged coins name themselves by origin (SOL.zy, ETH.zy, a token's
      // .zy), and pool shares by their pair, the way the market names them.
      for (const b of await loadBridged(config)) tickers.set(b.asset, bridgedName(config, b));
      const nameOf = (id) => (id === zec ? 'ZEC.zy' : tickers.get(id) || `${id.slice(0, 6)}…`);
      for (const p of market.pools || []) {
        if (/^[0-9a-f]{64}$/.test(p.lp) && typeof p.a === 'string' && typeof p.b === 'string') tickers.set(p.lp, `LP ${nameOf(p.a)}/${nameOf(p.b)}`);
      }
      // Lending shares: lZEC.zy, lETH.zy, lSOL.zy, as Zyn Lend names them.
      for (const a of [zec, ...tickers.keys()]) {
        if (/^[0-9a-f]{64}$/.test(a) && !tickers.get(a)?.startsWith('LP ')) tickers.set(hex(lendAsset(unhex(a, 32))), `l${nameOf(a)}`);
      }
    } catch { /* names only */ }
    if (!active()) return;
  }
  // Event certificates (§150) are named by the event they came from.
  if (config.attendUrl && [...items.values()].some((i) => !(config.collections || []).some((c) => String(c.id).toLowerCase() === i.collection))) {
    await loadEventNames();
    if (!active()) return;
  }
  const collectionName = (id) => ((config.collections || []).find((c) => String(c.id).toLowerCase() === id) || {}).name || eventNames.get(id)?.name || `Collection ${id.slice(0, 6)}`;
  assets = seen.map((id) => ({
    id,
    symbol: id === zec ? 'ZEC.zy' : items.has(id) ? `${collectionName(items.get(id).collection)} #${items.get(id).serial}` : tickers.get(id) || `asset ${id.slice(0, 8)}…`,
    item: items.has(id),
    event: items.has(id) ? eventNames.get(items.get(id).collection) || null : null,
  }));
  if (zec && !seen.includes(zec)) assets.unshift({ id: zec, symbol: 'ZEC.zy' });

  objectHeld = held;
  void revealExits();
  // `renderCoins` reads decimal strings, and these are WAD BigInts.
  holdings = held.map((h) => ({ asset: h.asset, amount: h.amount.toString() }));
  listings = [];
  renderCoins();
  renderItems();
  if (announce) note(`Synced at epoch ${epoch}.`);
}

/// A WAD amount as a trimmed decimal with thousands marks, to `places`
/// decimals (cut, never rounded up), for display only.
function wadText(raw, places = 18) {
  const v = BigInt(raw);
  const whole = (v / WAD).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const frac = (v % WAD).toString().padStart(18, '0').slice(0, places).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole;
}

function renderCoins() {
  let coins = holdings
    .map((h) => ({ ...h, meta: assets.find((a) => a.id === h.asset) }))
    .filter((h) => h.meta && !h.meta.content && !h.meta.item && decimalRaw(h.amount) > 0n);
  // On the object ledger a holding is one note, in WAD units: the pocket
  // shows one card per coin, its notes summed, as a decimal. What is sent is
  // funded from the notes themselves, not from this total.
  if (config.kind === 'object') {
    const byAsset = new Map();
    for (const c of coins) {
      const had = byAsset.get(c.asset);
      byAsset.set(c.asset, had ? { ...had, amount: (BigInt(had.amount) + BigInt(c.amount)).toString() } : { ...c });
    }
    // Six places, rounded down so a card never shows more than is held; the
    // exact amount is in the title. Below that, say so rather than show 0.
    coins = [...byAsset.values()].map((c) => {
      const shown = wadText(c.amount, 6);
      return { ...c, shown: shown === '0' && BigInt(c.amount) > 0n ? '< 0.000001' : shown, exact: wadText(c.amount) };
    });
  }

  const deposit = assets.find((a) => a.symbol === 'ZEC.zy');
  if (deposit && !coins.some((c) => c.asset === deposit.id)) {
    coins.unshift({ asset: deposit.id, amount: '0', meta: deposit });
  }
  coins.sort((a, b) => (a.meta.symbol === 'ZEC.zy' ? -1 : b.meta.symbol === 'ZEC.zy' ? 1 : a.meta.symbol.localeCompare(b.meta.symbol)));

  const holder = root.querySelector('#coins');
  const count = root.querySelector('#coin-count');
  if (!holder) return;
  count.textContent = String(coins.length);
  holder.innerHTML = coins.map((c, i) => `<div class="coin"><div><p class="kicker">${escapeHtml(c.meta.symbol)}</p><b${c.exact ? ` title="${escapeHtml(c.exact)}"` : ''}>${escapeHtml(c.shown ?? readableAmount(c.amount))}</b></div>${config.kind === 'object' && decimalRaw(c.amount) > 0n ? `<button class="quiet coin-send" data-coin="${i}">Send →</button>` : (c.meta.symbol === 'ZEC.zy' ? '<span class="muted">deposited ZEC</span>' : '')}</div>`).join('');
  holder.querySelectorAll('[data-coin]').forEach((b) => { b.onclick = () => openObjectSend(coins[Number(b.dataset.coin)]); });
}

function renderItems() {
  for (const url of artUrls) URL.revokeObjectURL(url);
  artUrls.clear();
  // Held items, plus the ones resting in the order book. An escrowed item is
  // still the holder's — it is one cancellation away — so hiding it would be
  // telling them it is gone.
  const held = holdings.map((h) => ({ ...h, meta: assets.find((a) => a.id === h.asset) }))
    .filter((h) => (h.meta?.content || h.meta?.item) && decimalRaw(h.amount) > 0n);
  const resting = listings
    .map((o) => ({ asset: o.offerAsset, amount: o.offerAmount, owner: o.owner, via: o.via,
                   meta: assets.find((a) => a.id === o.offerAsset), listing: o }))
    .filter((h) => h.meta?.content);
  const list = [...held, ...resting];
  // On the object ledger an item is shown and sent here; listing, buying and
  // redeeming are the Cave store's.
  if (config.kind === 'object') {
    root.querySelector('#item-count').textContent = String(held.length);
    root.querySelector('#items').innerHTML = held.length ? held.map((h, i) => `<article class="item" data-index="${i}"><div class="art"><img src="/nap-mark.png" alt=""></div><div><p class="kicker">ITEM</p><h3>${escapeHtml(h.meta.symbol)}</h3><p class="media-status">${h.meta.event ? `${escapeHtml(h.meta.event.date)}${h.meta.event.place ? ` · ${escapeHtml(h.meta.event.place)}` : ''}. Proof you were there; only you can see you hold it.` : 'Trade it in the Cave store.'}</p><button>Send →</button></div></article>`).join('') : '<div class="empty"><img src="/nap-mark.png" alt=""><h3>No items yet.</h3><p>Items you buy in the Cave store appear here.</p></div>';
    root.querySelectorAll('.item').forEach((el) => {
      const h = held[Number(el.dataset.index)];
      el.querySelector('button').onclick = () => openObjectSend({ asset: h.asset, amount: h.amount, meta: h.meta });
    });
    return;
  }
  root.querySelector('#item-count').textContent = String(list.length);
  root.querySelector('#items').innerHTML = list.length ? list.map((h, i) => `<article class="item" data-index="${i}"><div class="art" data-content="${escapeHtml(h.meta.content)}"><img src="/nap-mark.png" alt="Generic placeholder; artwork not verified"></div><div><p class="kicker">ITEM · #${escapeHtml(h.asset)}</p><h3>${escapeHtml(h.meta.symbol || `Item ${h.asset}`)}</h3><p class="media-status">${h.listing ? `Listed · ${escapeHtml(readableAmount(h.listing.wantAmount))} ZEC.zy` : 'Artwork not verified'}</p><button>Review & send →</button> <button data-list>${h.listing ? 'Cancel listing' : 'List for sale'} →</button></div></article>`).join('') : `<div class="empty"><img src="/nap-mark.png" alt=""><h3>No items yet.</h3><p>Claim a gift or receive a Zyn item at the account below.</p></div>`;
  root.querySelectorAll('.item').forEach((el) => {
    const item = list[Number(el.dataset.index)];
    const [send, listBtn] = el.querySelectorAll('button');
    // An escrowed item cannot be sent — it is not in the account to send from.
    if (item.listing) { send.disabled = true; send.textContent = 'In escrow'; }
    else send.onclick = () => openSend(item);
    listBtn.onclick = () => openList(item);
  });
  // The gate. Nothing reaches the gateway until this is on, so the default
  // render makes no request that names an item.
  if (artEnabled()) {
    list.forEach((h, i) => loadVerifiedArt(root.querySelectorAll('.art')[i], h.meta.content));
  } else {
    root.querySelectorAll('.media-status').forEach((el) => {
      el.textContent = 'Artwork not fetched — privacy';
    });
  }
  const artToggle = root.querySelector('#art-toggle');
  if (artToggle) {
    artToggle.checked = artEnabled();
    artToggle.onchange = () => {
      setArtEnabled(artToggle.checked);
      note(
        artToggle.checked
          ? 'Artwork on. The gateway now learns which items you hold.'
          : 'Artwork off. Nothing is requested for your items.',
      );
      renderItems();
    };
  }
}
function decimalRaw(value) {
  if (!/^(0|[1-9]\d{0,38})(\.\d{1,18})?$/.test(String(value))) throw new Error('Invalid holdings amount');
  const [whole, frac = ''] = String(value).split('.');
  return BigInt(whole || 0) * WAD + BigInt(frac.padEnd(18, '0').slice(0, 18) || 0);
}
async function loadVerifiedArt(el, content) {
  try {
    if (!/^[a-f0-9]{64}$/.test(content)) return;
    const manifestBytes = await boundedBytes(`${config.mediaGateway.replace(/\/$/, '')}/${content}`, MAX_MANIFEST);
    const committed = new Uint8Array(manifestBytes.length + 1); committed.set(manifestBytes, 1);
    if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', committed))) !== content) return;
    const manifest = parseManifest(manifestBytes);
    const media = manifest.media.find((m) => m.role === 0);
    if (!media) return;
    if (media.bytes > MAX_IMAGE) return;
    const bytes = await boundedBytes(`${config.mediaGateway.replace(/\/$/, '')}/${media.hash}`, MAX_IMAGE);
    if (bytes.length !== media.bytes || hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== media.hash) return;
    if (!safeRaster(media, bytes) || !el.isConnected) return;
    const url = URL.createObjectURL(new Blob([bytes], { type: media.mime }));
    artUrls.add(url);
    el.innerHTML = `<img src="${url}" alt="${escapeHtml(manifest.name)}">`;
    el.classList.add('verified');
    el.closest('.item').querySelector('.media-status').textContent = 'Artwork hash verified';
  } catch (_) { /* the committed placeholder remains */ }
}

/// List an item, or take it back off the market.
///
/// The frame is signed by `item.owner` — the receiving account for anything
/// bought through a store — because an offer is escrowed from the account that
/// holds the item, and the identity holds nothing (§124.3).
function openList(item) {
  const owner = item.owner || identity, current = generation;
  const dialog = root.querySelector('#send-dialog');
  const listed = item.listing;
  dialog.innerHTML = listed
    ? `<button class="x">×</button><p class="kicker">LISTING</p><h2>${escapeHtml(item.meta.symbol || `Item ${item.asset}`)}</h2><p class="muted">This item is escrowed in the order book until it is taken or you cancel. Cancelling returns it to this account.</p><div class="review"><span>Offer</span><b>#${listed.id}</b><span>Asking</span><b>${escapeHtml(readableAmount(listed.wantAmount))} ZEC.zy</b></div><form><button class="primary" type="submit">Cancel the listing <span>→</span></button><p class="error" role="alert"></p></form>`
    : `<button class="x">×</button><p class="kicker">LIST FOR SALE</p><h2>${escapeHtml(item.meta.symbol || `Item ${item.asset}`)}</h2><p class="muted">The item is escrowed while it rests. Nobody can take it except at your price, and you can cancel until they do.</p><form><label>Price in ZEC.zy<input id="ask" autocomplete="off" inputmode="decimal" placeholder="1.5"></label><div class="review"><span>Item</span><b>#${item.asset.slice(0, 12)}…</b><span>Rests until</span><b>cancelled</b></div><button class="primary" type="submit">Sign &amp; list <span>→</span></button><p class="error" role="alert"></p></form>`;
  dialog.querySelector('.x').onclick = () => dialog.close();

  let submitted = false;
  dialog.querySelector('form').onsubmit = async (event) => {
    event.preventDefault();
    const button = dialog.querySelector('.primary');
    button.disabled = true;
    try {
      const status = await rpc(config.rpcUrl, 'zyn_status');
      const epoch = checkedEpoch(status, config.chain);
      if (generation !== current) return;
      const intent = listed
        ? cancelOfferIntent(owner.account, BigInt(listed.id))
        // Rests until cancelled: a silent lapse would look like a theft to
        // whoever was about to take it.
        : placeOfferIntent(owner.account, item.asset, WAD, XZEC, parseAmount(dialog.querySelector('#ask').value), 0xffffffffffffffffn);
      const frame = signedFrame(owner, config.chain, epoch, intent);
      submitted = true;
      const accepted = await rpc(config.rpcUrl, 'zyn_sendRawIntent', [hex(frame)]);
      if (generation !== current) return;
      dialog.close(); await refresh(false);
      if (generation !== current) return;
      note(listed ? `Listing cancelled at sequence ${accepted.seq}.` : `Listed at sequence ${accepted.seq}; acceptance is not anchored finality.`);
    } catch (e) {
      if (generation !== current) return;
      dialog.querySelector('.error').textContent = submitted ? `${e.message}. Submission outcome unknown: refresh and check before trying again.` : e.message;
      button.disabled = submitted;
    }
  };
  dialog.showModal();
}

function openSend(item) {
  // The key that holds *this* item, which is the identity for a gift and a
  // receiving account for anything bought through a store. Signing with the
  // identity would be a signature from an account that holds nothing.
  const owner = item.owner || identity, current = generation;
  let reviewedTo = null;
  const dialog = root.querySelector('#send-dialog');
  dialog.innerHTML = `<button class="x">×</button><p class="kicker">SEND ONE ITEM</p><h2>${escapeHtml(item.meta.symbol || `Item ${item.asset}`)}</h2><p class="muted">Nap sends exactly one whole NFT unit. Review the destination carefully; transfers cannot be undone.</p><form><label>Recipient Zyn account<input id="send-to" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="64 hex characters"></label><div class="review"><span>Asset</span><b>#${item.asset}</b><span>Amount</span><b>1 item</b><span>Network</span><b>${escapeHtml(config.network)} · ${config.chain}</b></div><button class="primary" type="submit">Sign & relay <span>→</span></button><p class="error" role="alert"></p></form>`;
  dialog.querySelector('.x').onclick = () => dialog.close();
  dialog.querySelector('.primary').textContent = 'Review destination →';
  dialog.querySelector('form').onsubmit = async (event) => {
    event.preventDefault(); const button = dialog.querySelector('.primary'); button.disabled = true;
    let submitted = false;
    try {
      const to = unhex(dialog.querySelector('#send-to').value, 32);
      if (generation !== current) throw new Error('Wallet locked or changed. Restore and review again.');
      if (to.every((b) => b === 0) || hex(to) === owner.accountHex) throw new Error('Choose a different, nonzero recipient account');
      if (!reviewedTo) {
        reviewedTo = hex(to);
        dialog.querySelector('#send-to').value = reviewedTo;
        dialog.querySelector('#send-to').readOnly = true;
        button.textContent = 'Confirm: sign & relay 1 item'; button.disabled = false;
        dialog.querySelector('.error').textContent = 'Check all 64 recipient characters above. Close to edit the destination.';
        return;
      }
      if (hex(to) !== reviewedTo) throw new Error('Destination changed; close and review again');
      const status = await rpc(config.rpcUrl, 'zyn_status');
      const epoch = checkedEpoch(status, config.chain);
      if (generation !== current) return;
      const account = await rpc(config.rpcUrl, 'zyn_account', [hex(signedRead(owner, config.chain, epoch))]);
      if (generation !== current) return;
      if (!account?.spendable?.some((h) => h.asset === item.asset && decimalRaw(h.amount) >= WAD)) throw new Error('This account no longer holds one whole item');
      const frame = transferFrame(owner, config.chain, epoch, to, item.asset, WAD);
      submitted = true;
      const accepted = await rpc(config.rpcUrl, 'zyn_sendRawIntent', [hex(frame)]);
      if (generation !== current) return;
      dialog.close(); await refresh(false);
      if (generation !== current) return;
      note(accepted.queued ? `Transfer queued at sequence ${accepted.seq}; not yet settled.` : `Transfer accepted at sequence ${accepted.seq}; acceptance is not anchored finality.`);
    } catch (e) {
      if (generation !== current) return;
      dialog.querySelector('.error').textContent = submitted ? `${e.message}. Submission outcome unknown: refresh holdings and check the node before trying again.` : e.message;
      button.disabled = submitted;
    }
  };
  dialog.showModal();
}

/// Send a coin to another Zyn account on the object ledger: retire notes this
/// wallet holds and create one for the recipient, sealed to the viewing key
/// they registered, plus change sealed to this wallet. Nothing on chain names
/// either account in the clear.
function openObjectSend(coin) {
  const current = generation;
  let reviewed = null;
  const dialog = root.querySelector('#send-dialog');
  const isItem = !!coin.meta.item;
  const isZec = coin.asset === config.zecAsset;
  dialog.innerHTML = `<button class="x">×</button><p class="kicker">SEND ${escapeHtml(coin.meta.symbol)}</p><h2>${isItem ? 'Send item' : 'Send'}</h2><p class="muted">To a Zyn account ID or a Zcash address. Cannot be undone.${tip(`A Zcash address that belongs to a Zyn account is paid on Zyn, privately and at once${isZec ? '. Any other Zcash address is paid on Zcash, as a withdrawal' : isItem ? '. An item cannot go to any other Zcash address' : ''}.`)}</p><form><label>Recipient<input id="send-to" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Zyn account (64 hex) or ${escapeHtml(config.zcashPrefix)}…"></label>${isItem ? '<input id="send-amount" type="hidden" value="1">' : '<label>Amount<input id="send-amount" inputmode="decimal" autocomplete="off" placeholder="0.0"></label>'}<div class="review"><span>Asset</span><b>${escapeHtml(coin.meta.symbol)}</b><span>You hold</span><b>${escapeHtml(coin.exact ?? readableAmount(coin.amount))}</b><span>Network</span><b>${escapeHtml(config.network)} · ${config.chain}</b></div><button class="primary" type="submit">Review →</button><p class="error" role="alert"></p></form>`;
  dialog.querySelector('.x').onclick = () => dialog.close();
  dialog.querySelector('form').onsubmit = async (event) => {
    event.preventDefault();
    const button = dialog.querySelector('.primary');
    const error = dialog.querySelector('.error');
    button.disabled = true;
    try {
      const raw = dialog.querySelector('#send-to').value.trim();
      const amount = parseAmount(dialog.querySelector('#send-amount').value.trim());
      // Who this is, decided before anything is signed: a Zyn account, a
      // Zcash address that belongs to one, or a Zcash address outside Zyn.
      let to = null, external = null;
      if (/^[0-9a-f]{64}$/i.test(raw)) {
        to = unhex(raw.toLowerCase(), 32);
      } else if (raw.startsWith(config.zcashPrefix) || /^t[a-z0-9]{20,}$/i.test(raw)) {
        const r = await objectCall(config.rpcUrl, 'zyn_resolveAddress', { address: raw });
        if (r && /^[0-9a-f]{64}$/.test(String(r.account))) to = unhex(r.account, 32);
        else external = raw;
      } else {
        throw new Error(`That is neither a Zyn account nor a ${config.zcash} address`);
      }
      if (external && !isZec) throw new Error(isItem ? 'An item cannot leave Zyn. Send it to a Zyn account, or to a Zcash address that belongs to one.' : 'Only ZEC.zy can be paid to an outside Zcash address.');
      if (to && (to.every((b) => b === 0) || hex(to) === identity.accountHex)) throw new Error('Choose a different, nonzero recipient');
      const key = `${to ? hex(to) : external}:${amount}`;
      if (!reviewed) {
        reviewed = key;
        dialog.querySelectorAll('input').forEach((el) => { el.readOnly = true; });
        button.textContent = external
          ? `Confirm: withdraw ${readableAmount(String(amount / WAD))}${amount % WAD ? '…' : ''} ZEC to Zcash`
          : `Confirm: send ${isItem ? 'the item' : `${readableAmount(dialog.querySelector('#send-amount').value.trim())} ${coin.meta.symbol}`} on Zyn`;
        button.disabled = false;
        error.textContent = external
          ? 'An outside Zcash address: this leaves Zyn as a withdrawal. The bridge fee is added and the Zcash network fee comes out of it.'
          : `Paying Zyn account ${hex(to).slice(0, 10)}…${hex(to).slice(-6)} privately. Close to edit.`;
        return;
      }
      if (key !== reviewed) throw new Error('Details changed; close and review again');
      if (external) {
        await withdrawToZcash(external, dialog.querySelector('#send-amount').value.trim());
        if (generation !== current) return;
        dialog.close();
        note('Withdrawal recorded. The vault pays it once two custodians sign.');
        refresh(false);
        return;
      }
      const { viewing } = await objectCall(config.rpcUrl, 'zyn_viewingKey', { account: hex(to) });
      if (generation !== current) return;
      const asset = unhex(coin.asset, 32);
      const { inputs, change } = fundFrom(identity, objectHeld, asset, amount);
      const note = { asset, amount, owner: to, nonce: crypto.getRandomValues(new Uint8Array(32)) };
      const enc = sealNote(unhex(viewing, 32), crypto.getRandomValues(new Uint8Array(32)), note);
      await submitObject(spendIntent(identity.account, OBJECT_PROGRAM.privateTransfer, inputs, [{ note, enc }, ...change]));
      if (generation !== current) return;
      dialog.close();
      note_(`Sent ${readableAmount(dialog.querySelector('#send-amount')?.value || '')} ${coin.meta.symbol}.`);
      refresh(false);
    } catch (e) {
      if (generation !== current) return;
      error.textContent = e.message;
      button.disabled = false;
    }
  };
  dialog.showModal();
}
const note_ = (text) => note(text);

/// Events by collection ({name, date}), from the certificate service's public list.
const eventNames = new Map();
async function loadEventNames() {
  if (!config.attendUrl || eventNames.size) return;
  try {
    const r = await fetch(`${config.attendUrl.replace(/\/$/, '')}/events`, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(10000) });
    for (const e of (await r.json()).events || []) {
      if (/^[0-9a-f]{64}$/.test(e.collection) && typeof e.manifest?.name === 'string') eventNames.set(e.collection, { name: e.manifest.name.slice(0, 64), date: String(e.manifest.date || '').slice(0, 10), place: String(e.manifest.place || '').slice(0, 64) });
    }
  } catch { /* names only */ }
}

/// Collect the certificate for the tag this page was opened from (§150).
async function collectCertificate() {
  const owner = identity, current = generation, tap = tapLink;
  const button = root.querySelector('#attend'); if (button) button.disabled = true;
  try {
    if (!config.attendUrl) throw new Error(`Certificates are not handed out on ${config.network}. Switch networks and tap again if the event is on another.`);
    // The certificate is sealed to the key this account published; publish it
    // first if this wallet has never been opened on this network.
    const published = await objectCall(config.rpcUrl, 'zyn_viewingKey', { account: owner.accountHex }).then((r) => /^[0-9a-f]{64}$/.test(String(r?.viewing || '')), () => false);
    if (generation !== current) return;
    if (!published && owner.viewing) await registerObjectAccount(owner);
    if (generation !== current) return;
    const response = await fetch(`${config.attendUrl.replace(/\/$/, '')}/attend`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ event: tap.event, picc: tap.picc, cmac: tap.cmac, account: owner.accountHex }), cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(30000) });
    const body = await response.json().catch(() => ({}));
    if (generation !== current) return;
    if (!response.ok) throw new Error(String(body.error || 'The certificate service did not answer.').slice(0, 200));
    tapLink = null;
    root.querySelector('#attend')?.closest('section')?.remove();
    note(`${String(body.event || 'Your certificate').slice(0, 64)} — certificate #${Number(body.serial)} is in your wallet.`);
    await refresh(false);
  } catch (e) { if (generation === current) note(e.message === 'Failed to fetch' ? 'The certificate service is not answering. Tap the tag again in a moment.' : e.message, true); }
  finally { const b = root.querySelector('#attend'); if (b) b.disabled = false; }
}

async function claimGift() {
  const owner = identity, current = generation;
  const button = root.querySelector('#claim'); button.disabled = true;
  try {
    checkedEpoch(await rpc(config.rpcUrl, 'zyn_status'), config.chain);
    if (generation !== current) return;
    const claimAttemptId = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(['nap.claim.v1', claimCode, owner.accountHex, config.chain])))));
    if (generation !== current) return;
    const response = await fetch(`${config.claimUrl.replace(/\/$/, '')}/api/claims`, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': claimAttemptId }, body: JSON.stringify({ code: claimCode, account: owner.accountHex, chain: config.chain }), cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) });
    const body = await response.json().catch(() => ({}));
    if (generation !== current) return;
    if (!response.ok) throw new Error(body.message || (response.status === 409 ? 'This gift has already been claimed.' : 'The gift coordinator rejected this claim.'));
    const state = body.state || 'submitted';
    await refresh(false);
    if (generation !== current) return;
    note(`Coordinator reports gift ${state}. Check your holdings; this response is not proof of anchored finality.`);
  } catch (e) { if (generation === current) note(e.message === 'Failed to fetch' ? 'Gift coordinator unavailable. Outcome unknown; retry with this same card and account.' : e.message, true); }
  finally { button.disabled = false; }
}

if (IN_POPUP) document.documentElement.classList.add('in-popup');

try {
  const local = ['localhost', '127.0.0.1', '::1'].includes(location.hostname);
  if (!isSecureContext && !local) throw new Error('Nap Web requires HTTPS before it can create or restore an account');
  if (!crypto?.getRandomValues || !crypto?.randomUUID) throw new Error('This browser does not provide the secure randomness Nap requires');
  if (!crypto.subtle || !AbortSignal.timeout) throw new Error('This browser lacks the cryptography or request timeout support Nap requires');
  config = await loadConfig();
  // Already unlocked in this browser session (the toolbar popup, or another
  // of Nap's tabs): open straight into the wallet.
  const session = hasSession && !setupMode ? await loadSession() : null;
  if (session) {
    identity = session.identity;
    const named = knownCollections();
    receiving = session.receiving.map((r) => ({ ...r, name: (named.find((c) => hex(c.id) === hex(r.collection)) || {}).name || 'Collection' }));
    wallet(); refresh();
  } else onboarding(setupMode || undefined);
}
catch (e) { root.innerHTML = `<main class="fatal"><img src="/nap-mark.png" alt=""><h1>Nap is not configured.</h1><p>${escapeHtml(e.message)}</p></main>`; }

if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(() => {});
