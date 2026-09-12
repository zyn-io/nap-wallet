import QRCode from 'qrcode';
import { deriveIdentity, forgetIdentity, hex, newMnemonic, parseAmount, rpc, signedRead, transferFrame, unhex, WAD } from './core.js';
import './styles.css';

const root = document.querySelector('#app');
let config;
let identity = null;
let assets = [];
let holdings = [];
let generatedWords = '';
const claimCode = new URL(location.href).searchParams.get('claim') || '';
let claimAttemptId = '';

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (s) => `${s.slice(0, 8)}…${s.slice(-6)}`;
const networkPill = () => `<span class="network"><i></i>${escapeHtml(config.network)} · chain ${config.chain}</span>`;

async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();
  if (!Number.isInteger(value.chain) || !value.rpcUrl || !value.claimUrl) throw new Error('Deployment configuration is incomplete');
  return value;
}

function shell(content) {
  root.innerHTML = `<div class="grain"></div><header><a class="brand" href="/" aria-label="Nap Wallet"><img src="/nap-mark.png" alt=""><span>Nap</span></a>${networkPill()}</header>${content}<footer><span>Keys stay in this tab.</span><span>Nap Wallet · Zyn</span></footer>`;
}

function onboarding(mode = claimCode ? 'create' : 'restore') {
  shell(`<main class="onboard">
    <section class="intro">
      <p class="eyebrow">BROWSER WALLET / NO INSTALL</p>
      <h1>Your pocket,<br><em>between blocks.</em></h1>
      <p class="lede">Receive the Nap Mole in person, then carry the same account into desktop Nap with one recovery phrase.</p>
      <div class="promise"><span>01</span><p><b>No account server.</b><br>Your key is derived and used on this device.</p></div>
      <div class="promise"><span>02</span><p><b>No browser storage.</b><br>Closing this tab forgets the key; your phrase restores it.</p></div>
    </section>
    <section class="entry panel">
      <div class="tabs"><button data-mode="restore" class="${mode === 'restore' ? 'active' : ''}">Restore</button><button data-mode="create" class="${mode === 'create' ? 'active' : ''}">Create new</button></div>
      ${mode === 'restore' ? restoreForm() : createForm()}
      <div class="scope"><b>Phase 1</b><span>Zyn NFTs and account transfers. Shielded Zcash stays in desktop Nap.</span></div>
    </section>
  </main>`);
  root.querySelectorAll('[data-mode]').forEach((b) => b.onclick = () => onboarding(b.dataset.mode));
  if (mode === 'create') bindCreate(); else bindRestore();
}

function restoreForm() {
  return `<form id="restore-form"><p class="kicker">WELCOME BACK</p><h2>Wake your wallet.</h2><label>24-word recovery phrase<textarea id="words" rows="5" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="word 1  word 2  word 3 …"></textarea></label><div class="split"><label>Optional passphrase<input id="passphrase" type="password" autocomplete="off" placeholder="Leave blank if unused"></label><label>Account<input id="account-index" type="number" min="0" max="2147483647" value="0"></label></div><button class="primary" type="submit">Restore on this device <span>→</span></button><p class="error" id="form-error" role="alert"></p></form>`;
}
function createForm() {
  if (!generatedWords) generatedWords = newMnemonic();
  const numbered = generatedWords.split(' ').map((w, i) => `<span><i>${String(i + 1).padStart(2, '0')}</i>${w}</span>`).join('');
  return `<form id="create-form"><p class="kicker">NEW POCKET</p><h2>Write this down first.</h2><p class="muted">These words restore both your Nap Zcash wallet and your Zyn items. They are shown once.</p><div class="phrase">${numbered}</div><label class="check"><input id="ack" type="checkbox"><span>I saved all 24 words offline. I understand a screenshot or cloud note can expose my wallet.</span></label><button class="primary" type="submit" disabled>Open my wallet <span>→</span></button><p class="error" id="form-error" role="alert"></p></form>`;
}
function bindRestore() {
  root.querySelector('#restore-form').onsubmit = (event) => {
    event.preventDefault();
    try { unlock(root.querySelector('#words').value, root.querySelector('#passphrase').value, Number(root.querySelector('#account-index').value)); }
    catch (e) { root.querySelector('#form-error').textContent = e.message; }
  };
}
function bindCreate() {
  const ack = root.querySelector('#ack');
  const button = root.querySelector('.primary');
  ack.onchange = () => { button.disabled = !ack.checked; };
  root.querySelector('#create-form').onsubmit = (event) => {
    event.preventDefault();
    if (!ack.checked) return;
    try { unlock(generatedWords, '', 0); generatedWords = ''; }
    catch (e) { root.querySelector('#form-error').textContent = e.message; }
  };
}
function unlock(words, passphrase, index) {
  forgetIdentity(identity);
  identity = deriveIdentity(words, passphrase, index);
  root.querySelectorAll('textarea,input').forEach((el) => { if (el.type !== 'checkbox') el.value = ''; });
  wallet();
  refresh();
}

function wallet(message = '') {
  const account = identity.accountHex;
  shell(`<main class="wallet">
    <aside class="rail">
      <div><p class="kicker">YOUR ZYN ACCOUNT</p><button class="account-copy" id="copy-account"><b>${short(account)}</b><span>Copy full ID</span></button></div>
      <nav><button class="active">Pocket</button><button id="receive-link">Receive</button><button id="recovery-link">Recovery</button></nav>
      <button class="quiet" id="forget">Lock & forget key</button>
    </aside>
    <section class="content">
      <div class="topline"><div><p class="eyebrow">POCKET / ITEMS</p><h1>Small things,<br>held properly.</h1></div><button class="refresh" id="refresh">↻ Refresh</button></div>
      <div class="notice ${message ? 'show' : ''}" id="notice">${escapeHtml(message)}</div>
      ${claimCode ? `<section class="claim"><div><p class="kicker">GIFT CARD DETECTED</p><h2>Your mole is waiting.</h2><p>The coordinator sees this public account ID—not your phrase or key.</p></div><button id="claim">Claim gift <span>→</span></button></section>` : ''}
      <section><div class="section-title"><h2>Items</h2><span id="item-count">—</span></div><div class="items" id="items"><div class="skeleton"></div><div class="skeleton"></div></div></section>
      <section class="activity"><div class="section-title"><h2>Account</h2></div><div class="account-card"><div><span>Public account</span><code>${account}</code></div><canvas id="qr" width="164" height="164"></canvas></div></section>
    </section>
  </main><dialog id="send-dialog"></dialog><dialog id="recovery-dialog"><button class="x">×</button><p class="kicker">RECOVERY</p><h2>The phrase is the wallet.</h2><p>Nap does not store it in this browser. Restore this same phrase, passphrase and account index in browser or desktop Nap to recover <code>${account}</code>.</p><div class="descriptor"><span>Derivation</span><b>nap.zyn.ed25519.v1</b><span>Account index</span><b>${identity.accountIndex}</b><span>Network scoped</span><b>No</b></div></dialog>`);
  QRCode.toCanvas(root.querySelector('#qr'), account, { width: 164, margin: 1, color: { dark: '#1f2428', light: '#f8f2e4' } });
  root.querySelector('#copy-account').onclick = async () => { await navigator.clipboard.writeText(account); note('Account ID copied.'); };
  root.querySelector('#receive-link').onclick = () => root.querySelector('.account-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
  root.querySelector('#recovery-link').onclick = () => root.querySelector('#recovery-dialog').showModal();
  root.querySelector('#recovery-dialog .x').onclick = () => root.querySelector('#recovery-dialog').close();
  root.querySelector('#forget').onclick = () => { forgetIdentity(identity); identity = null; generatedWords = ''; onboarding('restore'); };
  root.querySelector('#refresh').onclick = refresh;
  root.querySelector('#claim')?.addEventListener('click', claimGift);
}
function note(text, bad = false) {
  const el = root.querySelector('#notice');
  if (!el) return;
  el.textContent = text; el.classList.add('show'); el.classList.toggle('bad', bad);
}

async function refresh() {
  const button = root.querySelector('#refresh');
  if (button) button.disabled = true;
  try {
    const status = await rpc(config.rpcUrl, 'zyn_status');
    if (Number(status.chain) !== config.chain) throw new Error(`Wrong chain: endpoint reports ${status.chain}, this wallet is pinned to ${config.chain}`);
    const payload = signedRead(identity, config.chain, BigInt(status.epoch));
    const [account, allAssets] = await Promise.all([
      rpc(config.rpcUrl, 'zyn_account', [hex(payload)]),
      rpc(config.rpcUrl, 'zyn_assets'),
    ]);
    assets = Array.isArray(allAssets) ? allAssets : [];
    holdings = account?.spendable || [];
    renderItems();
    note(`Synced at epoch ${status.epoch}.`);
  } catch (e) {
    renderItems();
    note(e.message === 'Failed to fetch' ? 'RPC unavailable. Your key is safe; try again when the connection returns.' : e.message, true);
  } finally { if (button) button.disabled = false; }
}

function renderItems() {
  const list = holdings.map((h) => ({ ...h, meta: assets.find((a) => Number(a.id) === Number(h.asset)) }))
    .filter((h) => h.meta?.content && decimalRaw(h.amount) > 0n);
  root.querySelector('#item-count').textContent = String(list.length);
  root.querySelector('#items').innerHTML = list.length ? list.map((h, i) => `<article class="item" data-index="${i}"><div class="art" data-content="${escapeHtml(h.meta.content)}"><img src="/nap-mark.png" alt="Nap item placeholder"></div><div><p class="kicker">VERIFIED ITEM · #${h.asset}</p><h3>${escapeHtml(h.meta.symbol || `Item ${h.asset}`)}</h3><button>Review & send →</button></div></article>`).join('') : `<div class="empty"><img src="/nap-mark.png" alt=""><h3>This pocket is quiet.</h3><p>Claim a gift or receive a Zyn item at the account below.</p></div>`;
  root.querySelectorAll('.item').forEach((el) => el.querySelector('button').onclick = () => openSend(list[Number(el.dataset.index)]));
  list.forEach((h, i) => loadVerifiedArt(root.querySelectorAll('.art')[i], h.meta.content));
}
function decimalRaw(value) {
  const [whole, frac = ''] = String(value).split('.');
  return BigInt(whole || 0) * WAD + BigInt(frac.padEnd(18, '0').slice(0, 18) || 0);
}
async function loadVerifiedArt(el, content) {
  try {
    const manifestResponse = await fetch(`${config.mediaGateway.replace(/\/$/, '')}/${content}`, { credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!manifestResponse.ok) return;
    const manifestBytes = new Uint8Array(await manifestResponse.arrayBuffer());
    const committed = new Uint8Array(manifestBytes.length + 1); committed.set(manifestBytes, 1);
    if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', committed))) !== content) return;
    const manifest = parseManifest(manifestBytes);
    const media = manifest.media.find((m) => m.role === 0);
    if (!media) return;
    const imageResponse = await fetch(`${config.mediaGateway.replace(/\/$/, '')}/${media.hash}`, { credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!imageResponse.ok) return;
    const bytes = new Uint8Array(await imageResponse.arrayBuffer());
    if (bytes.length !== media.bytes || hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== media.hash) return;
    const url = URL.createObjectURL(new Blob([bytes], { type: media.mime }));
    el.innerHTML = `<img src="${url}" alt="${escapeHtml(manifest.name)}">`;
    el.classList.add('verified');
  } catch (_) { /* the committed placeholder remains */ }
}
function parseManifest(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength); let at = 0;
  const take = (n) => { if (at + n > bytes.length) throw new Error('Truncated manifest'); const value = bytes.slice(at, at + n); at += n; return value; };
  const readU32 = () => { const n = view.getUint32(at); at += 4; return n; };
  const readU64 = () => { const n = Number(view.getBigUint64(at)); at += 8; return n; };
  const text = () => new TextDecoder().decode(take(readU32()));
  if (new TextDecoder().decode(take(15)) !== 'zyn.manifest.v1') throw new Error('Wrong manifest domain');
  const name = text(); const description = text(); const media = [];
  for (let n = readU32(), i = 0; i < n; i++) media.push({ role: take(1)[0], hash: hex(take(32)), mime: text(), bytes: readU64(), width: readU32(), height: readU32(), duration: readU32() });
  return { name, description, media };
}

function openSend(item) {
  const dialog = root.querySelector('#send-dialog');
  dialog.innerHTML = `<button class="x">×</button><p class="kicker">SEND ONE ITEM</p><h2>${escapeHtml(item.meta.symbol || `Item ${item.asset}`)}</h2><p class="muted">Nap sends exactly one whole NFT unit. Review the destination carefully; transfers cannot be undone.</p><form><label>Recipient Zyn account<input id="send-to" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="64 hex characters"></label><div class="review"><span>Asset</span><b>#${item.asset}</b><span>Amount</span><b>1 item</b><span>Network</span><b>${escapeHtml(config.network)} · ${config.chain}</b></div><button class="primary" type="submit">Sign & relay <span>→</span></button><p class="error" role="alert"></p></form>`;
  dialog.querySelector('.x').onclick = () => dialog.close();
  dialog.querySelector('form').onsubmit = async (event) => {
    event.preventDefault(); const button = dialog.querySelector('.primary'); button.disabled = true;
    try {
      const to = unhex(dialog.querySelector('#send-to').value, 32);
      const status = await rpc(config.rpcUrl, 'zyn_status');
      const frame = transferFrame(identity, config.chain, BigInt(status.epoch), to, Number(item.asset), WAD);
      const accepted = await rpc(config.rpcUrl, 'zyn_sendRawIntent', [hex(frame)]);
      dialog.close(); note(accepted.queued ? `Transfer signed and queued at sequence ${accepted.seq}.` : `Transfer accepted at sequence ${accepted.seq}.`); await refresh();
    } catch (e) { dialog.querySelector('.error').textContent = e.message; button.disabled = false; }
  };
  dialog.showModal();
}

async function claimGift() {
  const button = root.querySelector('#claim'); button.disabled = true;
  try {
    const response = await fetch(`${config.claimUrl.replace(/\/$/, '')}/api/claims`, { method: 'POST', headers: { 'content-type': 'application/json', 'idempotency-key': claimAttemptId }, body: JSON.stringify({ code: claimCode, account: identity.accountHex, chain: config.chain }), cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || (response.status === 409 ? 'This gift has already been claimed.' : 'The gift coordinator rejected this claim.'));
    const state = body.state || 'submitted';
    note(state === 'settled' ? 'Gift received. Welcome to Nap.' : `Gift ${state}. Keep this tab open and refresh to follow it.`);
    await refresh();
  } catch (e) { note(e.message === 'Failed to fetch' ? 'Gift coordinator unavailable. Your claim was not marked complete; retry with this same card.' : e.message, true); }
  finally { button.disabled = false; }
}

try {
  const local = ['localhost', '127.0.0.1', '::1'].includes(location.hostname);
  if (!isSecureContext && !local) throw new Error('Nap Web requires HTTPS before it can create or restore an account');
  if (!crypto?.getRandomValues || !crypto?.randomUUID) throw new Error('This browser does not provide the secure randomness Nap requires');
  claimAttemptId = crypto.randomUUID();
  config = await loadConfig(); onboarding();
}
catch (e) { root.innerHTML = `<main class="fatal"><img src="/nap-mark.png" alt=""><h1>Nap is not configured.</h1><p>${escapeHtml(e.message)}</p></main>`; }

if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(() => {});
