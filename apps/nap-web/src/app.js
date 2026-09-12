import QRCode from 'qrcode';
import { checkedEpoch, deriveIdentity, forgetIdentity, hex, newMnemonic, rpc, signedRead, transferFrame, unhex, WAD } from './core.js';
import { boundedBytes, MAX_IMAGE, MAX_MANIFEST, parseManifest, safeRaster } from './media.js';
import './styles.css';

const root = document.querySelector('#app');
let config;
let identity = null;
let assets = [];
let holdings = [];
let generatedWords = '';
const giftUrl = new URL(location.href);
const claimCode = new URLSearchParams(giftUrl.hash.slice(1)).get('claim') || giftUrl.searchParams.get('claim') || '';
// Fragment links keep the card secret out of HTTP access logs. Scrub legacy
// query links immediately; deployments must also redact them from access logs.
giftUrl.searchParams.delete('claim'); giftUrl.hash = '';
history.replaceState(null, '', giftUrl.pathname + giftUrl.search);
let generation = 0;
let refreshId = 0;
const artUrls = new Set();
function clearSession() {
  generation++; refreshId++;
  forgetIdentity(identity); identity = null; holdings = []; assets = []; generatedWords = '';
  for (const url of artUrls) URL.revokeObjectURL(url);
  artUrls.clear();
}

const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (s) => `${s.slice(0, 8)}…${s.slice(-6)}`;
const networkPill = () => `<span class="network"><i></i>${escapeHtml(config.network)} · chain ${config.chain}</span>`;

async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();
  if (!Number.isInteger(value.chain) || value.chain < 0 || value.chain > 0xffffffff || typeof value.network !== 'string') throw new Error('Deployment configuration is incomplete');
  for (const key of ['rpcUrl', 'claimUrl', 'mediaGateway']) {
    const url = new URL(value[key], location.origin);
    if (!value[key] || url.origin !== location.origin || url.username || url.password || url.search || url.hash) throw new Error(`${key} must be a same-origin path`);
    value[key] = url.pathname;
  }
  return value;
}

function shell(content) {
  root.innerHTML = `<div class="grain"></div><header><a class="brand" href="/" aria-label="Nap Wallet"><img src="/nap-mark.png" alt=""><span>Nap</span></a>${networkPill()}</header>${content}<footer><span>Keys stay in this tab.</span><span>Nap Wallet · Zyn</span></footer>`;
}

function onboarding(mode = claimCode ? 'create' : 'restore') {
  if (mode !== 'create') generatedWords = '';
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
  const nextIdentity = deriveIdentity(words, passphrase, index);
  clearSession(); identity = nextIdentity;
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
  root.querySelector('#forget').onclick = () => { clearSession(); onboarding('restore'); };
  root.querySelector('#refresh').onclick = refresh;
  root.querySelector('#claim')?.addEventListener('click', claimGift);
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
    const payload = signedRead(owner, config.chain, checkedEpoch(status, config.chain));
    const [account, allAssets] = await Promise.all([
      rpc(config.rpcUrl, 'zyn_account', [hex(payload)]),
      rpc(config.rpcUrl, 'zyn_assets'),
    ]);
    if (!active()) return;
    if (!Array.isArray(allAssets) || (account !== null && !Array.isArray(account?.spendable))) throw new Error('Malformed holdings response');
    const validAsset = (id) => Number.isInteger(id) && id >= 0 && id <= 0xffffffff;
    if (!allAssets.every((a) => validAsset(a.id)) || !(account?.spendable || []).every((h) => validAsset(h.asset))) throw new Error('Invalid asset identifier');
    assets = allAssets;
    holdings = account?.spendable || [];
    renderItems();
    if (announce) note(`Synced at epoch ${status.epoch}.`);
  } catch (e) {
    if (!active()) return;
    holdings = []; assets = [];
    root.querySelector('#item-count').textContent = 'Unavailable';
    root.querySelector('#items').innerHTML = '<div class="empty"><h3>Holdings unavailable.</h3><p>Reconnect and refresh before sending.</p></div>';
    note(e.message === 'Failed to fetch' ? 'RPC unavailable. Your key is safe; try again when the connection returns.' : e.message, true);
  } finally { if (button) button.disabled = false; }
}

function renderItems() {
  for (const url of artUrls) URL.revokeObjectURL(url);
  artUrls.clear();
  const list = holdings.map((h) => ({ ...h, meta: assets.find((a) => Number(a.id) === Number(h.asset)) }))
    .filter((h) => h.meta?.content && decimalRaw(h.amount) > 0n);
  root.querySelector('#item-count').textContent = String(list.length);
  root.querySelector('#items').innerHTML = list.length ? list.map((h, i) => `<article class="item" data-index="${i}"><div class="art" data-content="${escapeHtml(h.meta.content)}"><img src="/nap-mark.png" alt="Generic placeholder; artwork not verified"></div><div><p class="kicker">ITEM · #${escapeHtml(h.asset)}</p><h3>${escapeHtml(h.meta.symbol || `Item ${h.asset}`)}</h3><p class="media-status">Artwork not verified</p><button>Review & send →</button></div></article>`).join('') : `<div class="empty"><img src="/nap-mark.png" alt=""><h3>This pocket is quiet.</h3><p>Claim a gift or receive a Zyn item at the account below.</p></div>`;
  root.querySelectorAll('.item').forEach((el) => el.querySelector('button').onclick = () => openSend(list[Number(el.dataset.index)]));
  list.forEach((h, i) => loadVerifiedArt(root.querySelectorAll('.art')[i], h.meta.content));
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

function openSend(item) {
  const owner = identity, current = generation;
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
      if (!account?.spendable?.some((h) => Number(h.asset) === Number(item.asset) && decimalRaw(h.amount) >= WAD)) throw new Error('This account no longer holds one whole item');
      const frame = transferFrame(owner, config.chain, epoch, to, Number(item.asset), WAD);
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

try {
  const local = ['localhost', '127.0.0.1', '::1'].includes(location.hostname);
  if (!isSecureContext && !local) throw new Error('Nap Web requires HTTPS before it can create or restore an account');
  if (!crypto?.getRandomValues || !crypto?.randomUUID) throw new Error('This browser does not provide the secure randomness Nap requires');
  if (!crypto.subtle || !AbortSignal.timeout) throw new Error('This browser lacks the cryptography or request timeout support Nap requires');
  config = await loadConfig(); onboarding();
}
catch (e) { root.innerHTML = `<main class="fatal"><img src="/nap-mark.png" alt=""><h1>Nap is not configured.</h1><p>${escapeHtml(e.message)}</p></main>`; }

if ('serviceWorker' in navigator && location.protocol === 'https:') navigator.serviceWorker.register('/sw.js').catch(() => {});
