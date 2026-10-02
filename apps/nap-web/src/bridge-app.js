// Nap Bridge: SOL, ETH and BTC in and out of Zyn as SOL.zy, ETH.zy and BTC.zy
// (DECISIONS §146).
//
// In: a deposit on the other chain carries a code from this wallet — a
// commitment to this account and one of its nonces, never the account — and
// the bridge records it on Zyn, where it waits until this wallet claims it.
// Claiming happens here, on its own, whenever something is waiting.
//
// Out: a withdrawal commits to `keccak(address ‖ salt)`, so the chain never
// carries where the money went; the address is then shown to the bridge that
// pays it, and only to it.

import { endSession, loadSession, saveSession } from './session.js';
import { checkedEpoch, deriveIdentity, forgetIdentity, openSealedWallet, parseAmount } from './core.js';
import { hex, scan, unhex, withdrawIntent } from './object.js';
import * as ledger from './ledger.js';
import * as mk from './market.js';
import * as sol from './solana.js';
import * as btc from './bitcoin.js';
import QRCode from 'qrcode';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bindNetworkPick, networkPill, rememberNetwork } from './netpick.js';
import { endpoint } from './origin.js';
import { installTips, tip } from './tip.js';
import { bridgePage, handoffUrl } from './bridges.js';
import './styles.css';
import './market.css';
import './bridge.css';
import './moved-banner.js';

const root = document.querySelector('#app');
installTips();
/// A deposit handed over by Nap's compact wallet (the toolbar popup, the
/// phone app), where MetaMask and Phantom cannot reach: `#deposit=eth|sol&
/// code=<commitment>&net=<id>`. The code is that wallet's one-time deposit
/// commitment — not its account — and rides in the fragment, which never
/// reaches the server. This page then needs no wallet of its own: it only
/// asks MetaMask or Phantom to send, with the code attached.
const handoff = (() => {
  const q = new URLSearchParams(location.hash.slice(1));
  const code = String(q.get('code') || '');
  const key = String(q.get('deposit') || '');
  if (!/^[0-9a-f]{64}$/.test(code) || !['eth', 'sol'].includes(key)) return null;
  history.replaceState(null, '', location.pathname);
  return { code, key, net: String(q.get('net') || '') };
})();
const KEPT_KEY = 'nap.kept.v1';
const NETWORK_KEY = 'nap.network';
let config;
let identity = null;
let view = 'in';
/// Where to go back to once the wallet opens.
let returnTo = 'in';
let busy = false;
const emptyState = () => ({ epoch: 0n, bridged: [], balances: new Map(), held: [], bps: 0n, waiting: [] });
let state = emptyState();
/// Bumped on a network switch, so an answer from the old chain is dropped.
let generation = 0;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const $ = (sel) => root.querySelector(sel);
const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };
const short = (h) => `${h.slice(0, 6)}…${h.slice(-4)}`;
const LAMPORT = 1_000_000_000n; // one lamport in WAD
const SAT = 10_000_000_000n; // one satoshi in WAD
const MIN_BTC_OUT = 10_000n * SAT; // the network fee comes out of it

function fmt(raw, places = 9) {
  const v = BigInt(raw);
  const w = v / mk.WAD;
  const f = (v % mk.WAD).toString().padStart(18, '0').slice(0, places).replace(/0+$/, '');
  return `${w}${f ? `.${f}` : ''}`;
}

// ---------------------------------------------------------------------------
// The bridges this network has, from config.json, checked against the chain.

function bridgesOf(net) {
  const b = net.bridges || {};
  const out = [];
  if (b.sol && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(b.sol.vault || '')) {
    out.push({ key: 'sol', symbol: 'SOL', zy: 'SOL.zy', decimals: 9, network: b.sol.network, asset: hex(mk.bridgedAsset(b.sol.network)), ...b.sol });
  }
  if (b.eth && /^0x[0-9a-fA-F]{40}$/.test(b.eth.vault || '') && Number.isSafeInteger(b.eth.chainId)) {
    out.push({ key: 'eth', symbol: 'ETH', zy: 'ETH.zy', decimals: 18, network: `eip155:${b.eth.chainId}`, asset: hex(mk.bridgedAsset(`eip155:${b.eth.chainId}`)), ...b.eth });
  }
  if (b.btc && /^[0-9a-f]{64}$/.test(b.btc.internal || '')) {
    // The Bitcoin network the vault key pays on, and the name Zyn registered
    // the coin under (§154).
    const chain = ['bitcoin', 'testnet4'].includes(b.btc.network) ? b.btc.network : 'signet';
    const network = { bitcoin: 'bitcoin', testnet4: 'bitcoin-test', signet: 'bitcoin-signet' }[chain];
    out.push({ ...b.btc, key: 'btc', symbol: 'BTC', zy: 'BTC.zy', decimals: 8, chain, network, asset: hex(mk.bridgedAsset(network)), vault: btc.vaultAddress(b.btc.internal, chain) });
  }
  return out;
}

async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('Deployment is missing config.json');
  const value = await response.json();
  const networks = Array.isArray(value.networks) && value.networks.length ? value.networks : [{ id: 'default', ...value }];
  const wanted = handoff?.net || read(NETWORK_KEY);
  const chosen = networks.find((n) => n.id === wanted) || networks[0];
  return checkedNetwork(chosen, networks);
}

function checkedNetwork(chosen, networks) {
  return { ...chosen, rpcUrl: endpoint(chosen.rpcUrl, 'rpcUrl'), networks, bridges: bridgesOf(chosen) };
}

/// The first network that bridges anything, for the "not here" screen.
const bridgingNetwork = () => (config.networks || []).find((n) => n.id !== config.id && bridgesOf(n).length);

/// Move to another chain, the wallet's way: the key stays open — the same
/// words are the same account on either chain — and every answer from the old
/// chain goes, including any still in flight.
function switchNetwork(id) {
  const next = config.networks.find((n) => n.id === id);
  if (!next || next.id === config.id) return true;
  if (busy) { notice('One moment — a deposit or exit is still in progress. Switch networks once it settles.'); return false; }
  let checked;
  try { checked = checkedNetwork(next, config.networks); } catch (e) { notice(e.message, true); return false; }
  rememberNetwork(checked.id);
  config = checked;
  generation++;
  state = emptyState();
  frame();
  render();
  notice(`On ${config.network} now. Reading the chain…`);
  refresh();
  return true;
}

const keptWallet = () => { try { return JSON.parse(read(KEPT_KEY) || 'null'); } catch { return null; } };
const call = (method, fields = {}) => ledger.call(config, method, fields);

// ---------------------------------------------------------------------------
// Exits waiting to be revealed: kept on this device until the node files them.

// Each takes the network it is about, so a switch in the middle of a reveal
// cannot file one chain's exits under the other's.
const exitsKey = (cfg = config) => `nap.bridge.exits.${cfg.chain}`;
const pendingExits = (cfg = config) => { try { return JSON.parse(read(exitsKey(cfg)) || '[]'); } catch { return []; } };
const savePendingExits = (v, cfg = config) => write(exitsKey(cfg), JSON.stringify(v));

async function revealExits(cfg = config) {
  const left = [];
  for (const x of pendingExits(cfg)) {
    try {
      await ledger.call(cfg, 'zyn_bridgeReveal', { asset: x.asset, address: x.address, salt: x.salt });
    } catch (e) {
      if (!/no unpaid exit/.test(e.message)) left.push(x);
    }
  }
  savePendingExits(left, cfg);
}

// ---------------------------------------------------------------------------

/// Whether the holder is typing into the view; a timed refresh must not
/// redraw over a half-typed amount or address.
function editing() {
  const view = $('#view');
  if (!view) return false;
  const a = document.activeElement;
  return view.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName);
}

async function refresh(quiet = false, timed = false) {
  const gen = generation;
  // A switch mid-flight leaves this read behind: nothing more is asked of,
  // claimed on or shown from the old chain.
  const stale = () => gen !== generation;
  try {
    const status = await call('zyn_status');
    if (stale()) return;
    const epoch = checkedEpoch(status, config.chain);
    const [bridged, market] = await Promise.all([ledger.loadBridged(config), call('zyn_market').catch(() => ({}))]);
    if (stale()) return;
    const live = new Set(bridged.map((b) => b.asset));
    const next = { ...state, epoch, bridged, bps: BigInt(Number(market?.fees?.bridge_bps) || 0) };
    for (const b of config.bridges) {
      b.live = live.has(b.asset);
      const row = bridged.find((x) => x.asset === b.asset);
      b.issued = /^\d+$/.test(String(row?.issued ?? '')) ? BigInt(row.issued) : null;
    }
    if (identity) {
      const me = identity;
      let waiting = await ledger.loadWaiting(config, me, bridged).catch(() => []);
      if (stale()) return;
      if (waiting.length && identity === me) {
        notice(`Claiming ${waiting.length} deposit${waiting.length > 1 ? 's' : ''} that arrived…`);
        await ledger.claimWaiting(config, me);
        waiting = [];
      }
      if (stale()) return;
      const published = await call('zyn_published');
      if (stale()) return;
      const { held, balances } = scan(published, { secret: me.viewing, nkey: me.nullifier, owner: me.account });
      Object.assign(next, { held, balances, waiting });
      await revealExits();
      if (stale()) return;
    }
    state = next;
    if (timed && editing()) {
      const e = $('#epoch');
      if (e) e.textContent = `epoch ${state.epoch}`;
    } else {
      render();
    }
    if (!quiet) notice(`Up to date at epoch ${epoch}.`);
  } catch (e) {
    if (stale()) return;
    notice(e.message === 'Failed to fetch' ? 'The chain is not answering. Nothing was sent.' : e.message, true);
  }
}

// ---------------------------------------------------------------------------
// In.

async function solanaBlockhash(b) {
  const r = await fetch(b.rpc, {
    method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getLatestBlockhash', params: [{ commitment: 'finalized' }] }),
  });
  const j = await r.json().catch(() => ({}));
  const h = j?.result?.value?.blockhash;
  if (!h) throw new Error('Solana did not answer; try again shortly.');
  return h;
}

async function depositSol(b, amountText, say) {
  const wad = parseAmount(amountText);
  if (wad % LAMPORT !== 0n) throw new Error('SOL has nine decimal places');
  const { memo } = handoff ? { memo: `zyn:${handoff.code}` } : await ledger.bridgeMemo(config, identity);
  const wallets = sol.solanaWallets();
  await new Promise((r) => setTimeout(r, 300));
  if (!wallets.length) throw new Error('No Solana wallet in this browser. Install one (Phantom, Solflare, Backpack), switch it to devnet, and reload.');
  const w = wallets[0];
  say(`Connecting ${w.name}…`);
  const { accounts } = await w.features['standard:connect'].connect();
  const account = accounts?.[0];
  if (!account) throw new Error(`${w.name} shared no account.`);
  const message = sol.depositMessage({ owner: account.address, vault: b.vault, lamports: wad / LAMPORT, memo, blockhash: await solanaBlockhash(b) });
  say(`Approve the deposit of ${fmt(wad)} SOL in ${w.name}.`);
  return sol.signAndSend(w, account, sol.unsigned(message), `solana:${b.cluster || 'devnet'}`);
}

/// What a capped bridge still takes, in its smallest unit; null when uncapped
/// or when the chain's total is not known yet.
function capRoom(b) {
  if (!/^\d+$/.test(String(b.capWei ?? '')) || b.issued === null || b.issued === undefined) return null;
  const room = BigInt(b.capWei) - b.issued;
  return room > 0n ? room : 0n;
}

function pilotNote(b) {
  if (!b.capWei) return '';
  const room = capRoom(b);
  return `<p class="mk-fine br-pilot"><strong>Pilot.</strong> At most ${fmt(BigInt(b.capWei), 18)} ETH in total${room === null ? '' : ` (${fmt(room, 18)} left)`}. The vault is held by a ${esc(b.custody || 'multisig')}${b.safe ? ` (<code>${esc(b.safe.toLowerCase())}</code>)` : ''}: its owners approve every payout, so sending out can take hours, and they could move what the vault holds. The vault contract is not audited.</p>`;
}

const selector = (s) => keccak_256(new TextEncoder().encode(s)).slice(0, 4);

async function depositEth(b, amountText, say) {
  const wei = parseAmount(amountText);
  const eth = window.ethereum;
  if (!eth?.request) throw new Error('No Ethereum wallet in this browser. Install one (MetaMask, Rabby) and reload.');
  // A capped pilot (§155): what fits under the cap is checked here, and the
  // bridge lists anything over it for a refund rather than crediting it.
  const room = capRoom(b);
  if (room !== null && wei > room) throw new Error(room > 0n ? `The pilot takes at most ${fmt(room, 18)} ETH more right now.` : 'The pilot is full for now — nothing more can come in.');
  const { commitment } = handoff ? { commitment: handoff.code } : await ledger.bridgeMemo(config, identity);
  const [from] = await eth.request({ method: 'eth_requestAccounts' });
  const chainHex = `0x${b.chainId.toString(16)}`;
  if ((await eth.request({ method: 'eth_chainId' })) !== chainHex) {
    say(`Switch your wallet to ${b.chainId === 1 ? 'Ethereum' : 'Sepolia'}…`);
    await eth.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: chainHex }] });
  }
  const asset = new Uint8Array(32);
  new DataView(asset.buffer).setUint32(28, Number(b.assetId || 1));
  const data = `0x${hex(selector('depositNative(bytes32,uint32)'))}${commitment}${hex(asset)}`;
  say(`Approve the deposit of ${fmt(wei, 18)} ETH in your wallet.`);
  return eth.request({ method: 'eth_sendTransaction', params: [{ from, to: b.vault, value: `0x${wei.toString(16)}`, data }] });
}

/// Bitcoin wallets cannot attach a memo, so the code is the address: the
/// vault key tweaked by this deposit's commitment. Nap derives it here and
/// asks the bridge to watch it; it never takes the address from the server.
async function depositBtc(b) {
  const { commitment } = await ledger.bridgeMemo(config, identity);
  await call('zyn_depositWatch', { network: b.network, commitment });
  return btc.depositAddress(b.internal, unhex(commitment), b.chain);
}

// ---------------------------------------------------------------------------
// Out.

function destinationBytes(b, text) {
  const t = String(text).trim();
  if (b.key === 'sol') return sol.solanaKey(t);
  if (b.key === 'btc') {
    const script = btc.scriptOf(t, b.chain);
    if (!script) throw new Error(`That is not a ${b.chain === 'bitcoin' ? 'bc1' : 'tb1'}… address. Legacy addresses (1…, 3…, m…, n…, 2…) are not supported.`);
    return script;
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(t)) throw new Error('That is not an Ethereum address');
  return unhex(t.slice(2).toLowerCase());
}

async function withdraw(b, to, amountText) {
  const raw = parseAmount(amountText);
  if (b.key === 'sol' && raw % LAMPORT !== 0n) throw new Error('SOL has nine decimal places');
  if (b.key === 'sol' && raw <= 5_000n * LAMPORT) throw new Error('Withdraw more than the 0.000005 SOL network fee');
  if (b.key === 'btc' && raw % SAT !== 0n) throw new Error('BTC has eight decimal places');
  if (b.key === 'btc' && raw < MIN_BTC_OUT) throw new Error('Send out at least 0.0001 BTC; the Bitcoin network fee comes out of it');
  const address = destinationBytes(b, to);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const destination = mk.exitCommitment(address, salt);
  const fee = (raw * state.bps) / 10_000n;
  const { inputs, change } = mk.fund(identity, state.held, unhex(b.asset), raw + fee);
  // Kept before submitting: if the page closes between the two steps, the
  // next visit still knows where this exit was meant to go.
  savePendingExits([...pendingExits(), { asset: b.asset, address: hex(address), salt: hex(salt) }]);
  await ledger.submitIntent(config, identity, withdrawIntent({ holder: identity.account, inputs, asset: unhex(b.asset), amount: raw, destination, outputs: change }));
  await revealExits();
}

// ---------------------------------------------------------------------------
// Screens.

function shell(content) {
  root.innerHTML = `<div class="grain"></div>
  <header class="mk-header">
    <a class="brand" href="/" aria-label="Nap Wallet"><img src="/nap-mark.png" alt=""><span>Nap</span><em>Bridge</em></a>
    <div class="mk-head-right">
      ${networkPill(config)}
      <a class="mk-link" href="/">Wallet →</a>
    </div>
  </header>${content}
  <footer><span>A deposit carries a code, not your account. An exit's address is shown only to the bridge that pays it.</span><span>Nap Bridge · Zyn</span></footer>`;
  bindNetworkPick(root, config, switchNetwork);
}

function frame() {
  shell(`<main class="wallet mk">
    <aside class="rail">
      <div>${handoff ? `<p class="kicker">ONE-TIME CODE</p><b class="mk-account">${short(handoff.code)}</b>` : identity ? `<p class="kicker">BRIDGING AS</p><b class="mk-account">${short(identity.accountHex)}</b>` : '<p class="kicker">NOT OPEN</p><button class="mk-act mk-open" id="open-wallet">Open wallet</button>'}<p class="mk-epoch" id="epoch">epoch —</p></div>
      <nav id="tabs"${handoff ? ' hidden' : ''}>${[['in', 'Deposit'], ['out', 'Withdraw']].map(([k, t]) => `<button data-view="${k}">${t}</button>`).join('')}</nav>
      ${identity ? '<button class="quiet" id="lock">Lock</button>' : ''}
    </aside>
    <section class="content">
      <div class="notice" id="notice" role="status"></div>
      <div id="view"></div>
    </section>
  </main>`);
  $('#lock')?.addEventListener('click', () => { forgetIdentity(identity); identity = null; void endSession(); frame(); render(); });
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

/// A page's heading: its name, an "i" when something needs explaining, and
/// at most one short line under it.
function heading(title, explain = '', lede = '') {
  return `<div class="topline"><div><h1 class="mk-h1">${esc(title)}${explain ? tip(explain) : ''}</h1></div><button class="refresh" id="refresh" aria-label="Refresh"><span aria-hidden="true">↻</span><span class="refresh-word">Refresh</span></button></div>${lede ? `<p class="br-lede">${esc(lede)}</p>` : ''}`;
}

function bindRefresh() {
  $('#refresh')?.addEventListener('click', () => refresh());
}

function balanceOf(b) {
  return state.balances.get(b.asset) || 0n;
}

/// No bridge on this network: say where there is one, and go there in one tap.
function renderNone() {
  const there = bridgingNetwork();
  $('#view').innerHTML = `${heading('Bridge', there ? 'Testnet coins are for trying it out; they are worth nothing.' : '', there
    ? `Not on this network. ${bridgesOf(there).map((b) => b.symbol).join(', ')} bridge on ${there.network} (${bridgesOf(there).map((b) => ({ sol: 'Solana devnet', eth: 'Ethereum Sepolia', btc: `Bitcoin ${b.chain}` })[b.key]).join(', ')}).`
    : 'No network here bridges another chain yet.')}
    ${there ? `<div class="br-none"><button class="primary mk-act" id="switch-bridge" data-network="${esc(there.id)}">Switch to ${esc(there.network)} <span>→</span></button><p class="mk-fine">The wallet switches too; switch back from the header.</p></div>` : ''}`;
  $('#switch-bridge')?.addEventListener('click', (e) => switchNetwork(e.currentTarget.dataset.network));
}

function renderIn() {
  if (!config.bridges.length) { renderNone(); return; }
  const shown = handoff ? config.bridges.filter((b) => b.key === handoff.key) : config.bridges;
  $('#view').innerHTML = `${handoff
    ? heading(`Deposit ${shown[0]?.symbol || ''}`, 'Your Nap wallet made this one-time code. It arrives in Nap once final, and Nap claims it on its own.', `Send from ${handoff.key === 'eth' ? 'MetaMask, Rabby or another Ethereum wallet' : 'Phantom or another Solana wallet'}.`)
    : heading('Deposit', 'The deposit carries a one-time code from this wallet, not your account, and arrives as a note only you can see. Every deposit gets a new code, so two deposits are not linked by it.', `${config.bridges.map((b) => b.symbol).join(', ').replace(/, ([^,]*)$/, ' and $1')} from your wallet on the other chain.`)}
    <div class="br-cards">${shown.map((b) => `<section class="mk-card br-card" data-bridge="${b.key}">
      <p class="eyebrow">${esc(b.symbol)} · ${esc(b.network)}</p>
      <h3>${esc(b.zy)} <span>${identity ? `you hold ${fmt(balanceOf(b), b.decimals)}` : ''}</span></h3>
      ${b.live === false ? '<p class="br-say error">This network has not registered it yet.</p>' : ''}
      ${b.key === 'btc' ? btcCard(b) : `<label class="mk-field"><span>Amount of ${esc(b.symbol)}</span><input class="amt" inputmode="decimal" autocomplete="off" placeholder="0.05"></label>
      ${identity || handoff
    ? `<button class="primary go" ${b.live ? '' : 'disabled'}>Deposit from a${b.key === 'eth' ? 'n Ethereum' : ' Solana'} wallet <span>→</span></button>`
    : '<button class="primary open-first" type="button">Open your wallet to deposit <span>→</span></button>'}
      <p class="br-say say" role="status"></p>
      <p class="mk-fine">Into the vault <code>${esc(b.key === 'sol' ? b.vault : b.vault.toLowerCase())}</code>. Arrives once ${b.key === 'sol' ? 'Solana' : 'Ethereum'} finalizes it${b.key === 'eth' ? ' (about 15 minutes)' : ' (under a minute)'}, and ${handoff ? 'your Nap wallet' : 'this page'} claims it for you.${state.bps ? ` Bridge fee ${Number(state.bps) / 100}%.` : ''}</p>${b.key === 'eth' ? pilotNote(b) : ''}`}
    </section>`).join('')}</div>`;
  root.querySelectorAll('[data-bridge]').forEach((card) => {
    const b = config.bridges.find((x) => x.key === card.dataset.bridge);
    const say = (t, bad = false) => { const el = card.querySelector('.say'); el.textContent = t; el.classList.toggle('error', bad); };
    card.querySelector('.open-first')?.addEventListener('click', () => { returnTo = 'in'; view = 'wallet'; render(); });
    if (b.key === 'btc') { bindBtcCard(b, card, say); return; }
    if (!card.querySelector('.go')) return;
    card.querySelector('.go').onclick = async () => {
      if (busy || !(identity || handoff)) return;
      busy = true;
      try {
        const id = b.key === 'sol' ? await depositSol(b, card.querySelector('.amt').value, say) : await depositEth(b, card.querySelector('.amt').value, say);
        const link = (b.explorer || '').replace('{tx}', id);
        say(handoff
          ? `Sent — ${String(id).slice(0, 14)}…. You can close this page; it arrives in your Nap wallet once final.`
          : `Sent. It arrives here once final — ${String(id).slice(0, 14)}…`);
        if (link) card.querySelector('.say').insertAdjacentHTML('beforeend', ` <a href="${esc(link)}" target="_blank" rel="noreferrer">view</a>`);
        if (!handoff) for (const wait of [20_000, 45_000, 90_000, 240_000, 600_000, 1_000_000]) setTimeout(() => refresh(true), wait);
      } catch (e) {
        say(e.code === 4001 || /reject|declin|cancel/i.test(e.message) ? 'Not sent. Nothing left your wallet.' : e.message, true);
      } finally { busy = false; }
    };
  });
}

const BTC_NAMES = { signet: 'signet', testnet4: 'testnet4', bitcoin: 'Bitcoin' };
let btcShown = null; // { chain, account, address } — kept across re-renders

function btcCard(b) {
  const shown = btcShown && identity && btcShown.account === identity.accountHex && btcShown.chain === config.chain ? btcShown.address : '';
  return `${identity
    ? `<button class="primary go" ${b.live ? '' : 'disabled'} ${shown ? 'hidden' : ''}>Show my deposit address <span>→</span></button>`
    : '<button class="primary open-first" type="button">Open your wallet to deposit <span>→</span></button>'}
      <div class="br-btc" ${shown ? '' : 'hidden'}>
        <canvas class="br-qr" width="164" height="164" aria-label="QR code of the deposit address"></canvas>
        <div class="br-btc-addr"><code class="addr">${esc(shown)}</code><button class="quiet copy" type="button">Copy</button></div>
        <p class="mk-fine">Send any amount of ${esc(BTC_NAMES[b.chain])} BTC here, from any Bitcoin wallet. This address carries your one-time code; nobody else's deposits land on it.</p>
      </div>
      <p class="br-say say" role="status"></p>
      <p class="mk-fine">Held by a 2-of-3 Taproot key (vault <code>${esc(b.vault)}</code>). Arrives after ${Number(b.confirmations) || 2} confirmations (about ${(Number(b.confirmations) || 2) * 10} minutes), and this page claims it for you.${state.bps ? ` Bridge fee ${Number(state.bps) / 100}%.` : ''}</p>`;
}

function showBtcAddress(card, address) {
  const box = card.querySelector('.br-btc');
  box.hidden = false;
  card.querySelector('.go')?.setAttribute('hidden', '');
  box.querySelector('.addr').textContent = address;
  QRCode.toCanvas(box.querySelector('.br-qr'), `bitcoin:${address}`, { width: 164, margin: 1, color: { dark: '#1f2428', light: '#f8f2e4' } });
}

function bindBtcCard(b, card, say) {
  if (btcShown && identity && btcShown.account === identity.accountHex && btcShown.chain === config.chain) showBtcAddress(card, btcShown.address);
  card.querySelector('.copy')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(card.querySelector('.addr').textContent); say('Copied.'); } catch { say('Select the address and copy it.', true); }
  });
  const go = card.querySelector('.go');
  if (!go) return;
  go.onclick = async () => {
    if (busy || !identity) return;
    busy = true;
    say('Deriving your address…');
    try {
      const address = await depositBtc(b);
      btcShown = { chain: config.chain, account: identity.accountHex, address };
      showBtcAddress(card, address);
      say('');
      for (const wait of [60_000, 300_000, 900_000, 1_500_000, 2_400_000, 3_600_000]) setTimeout(() => refresh(true), wait);
    } catch (e) {
      say(e.message === 'Failed to fetch' ? 'The bridge is not answering; try again shortly.' : e.message, true);
    } finally { busy = false; }
  };
}

function renderOut() {
  const live = config.bridges.filter((b) => b.live);
  if (!config.bridges.length) { renderNone(); return; }
  if (!identity) {
    $('#view').innerHTML = `${heading('Withdraw', `Withdrawing ${config.bridges.map((b) => b.zy).join(' or ')} spends notes only your key can open.`, 'Open your wallet to withdraw.')}<div class="br-none"><button class="primary mk-act" id="out-open" type="button">Open wallet <span>→</span></button></div>`;
    $('#out-open').onclick = () => { returnTo = 'out'; view = 'wallet'; render(); };
    return;
  }
  $('#view').innerHTML = `${heading('Withdraw', 'The chain records only a commitment to the destination. The address is shown to the bridge that pays it, and to nobody else.', `To ${config.bridges.map((b) => ({ sol: 'Solana', eth: 'Ethereum', btc: 'Bitcoin' })[b.key]).join(', ').replace(/, ([^,]*)$/, ' or $1')}.`)}
    <section class="mk-card"><form id="out-form" class="br-out">
      <label class="mk-field"><span>From</span><select id="out-asset">${live.map((b) => `<option value="${b.key}">${esc(b.zy)} — you hold ${fmt(balanceOf(b), b.decimals)}</option>`).join('')}</select></label>
      <label class="mk-field"><span>To address</span><input id="out-to" autocomplete="off" spellcheck="false" placeholder="${esc(live.map((b) => ({ sol: 'a Solana address', eth: '0x… on Ethereum', btc: `${b.chain === 'bitcoin' ? 'bc1' : 'tb1'}… on Bitcoin` })[b.key]).join(', ') || 'an address')}"></label>
      <label class="mk-field"><span>Amount</span><input id="out-amt" inputmode="decimal" autocomplete="off" placeholder="0.02"></label>
      <button class="primary" type="submit" ${live.length ? '' : 'disabled'}>Send out <span>→</span></button>
      <p class="mk-fine">${state.bps ? `A ${Number(state.bps) / 100}% bridge fee rides on top. ` : ''}${live.some((b) => b.key === 'sol') ? 'SOL pays its 0.000005 network fee out of the amount. ' : ''}${live.some((b) => b.key === 'btc') ? 'BTC pays its network fee out of the amount (at least 0.0001 BTC, to a segwit or Taproot address). ' : ''}${live.some((b) => b.key === 'eth' && b.capWei) ? 'ETH goes out once two of the vault Safe’s owners approve it. ' : ''} The bridge pays once the other chain finalizes it.</p>
    </form></section>`;
  $('#out-form').onsubmit = async (e) => {
    e.preventDefault();
    if (busy) return;
    busy = true;
    try {
      const b = config.bridges.find((x) => x.key === $('#out-asset').value);
      await withdraw(b, $('#out-to').value, $('#out-amt').value);
      notice(`Sent out. The bridge pays it once it is final on ${({ sol: 'Solana', eth: 'Ethereum', btc: 'Bitcoin' })[b.key]}.`);
      await refresh(true);
    } catch (err) { notice(err.message, true); } finally { busy = false; }
  };
}

function renderWallet(error = '') {
  // Unlocked already in this browser session (the extension): straight in.
  if (!error && !renderWallet.asked) {
    renderWallet.asked = true;
    loadSession().then((held) => { if (held && !identity) begin(held.identity); });
  }
  const kept = keptWallet();
  $('#view').innerHTML = `<section class="entry panel mk-entry">
    ${kept ? '<form id="kept-form"><h2>Unlock</h2><label>Password<input id="kept-password" type="password" autocomplete="current-password" autofocus></label><button class="primary" type="submit">Open <span>→</span></button></form><p class="muted"><a href="" id="use-phrase">Use a recovery phrase instead</a></p>' : ''}
    <form id="phrase-form" ${kept ? 'hidden' : ''}><h2>Restore wallet</h2><label>24-word recovery phrase<textarea id="words" rows="4" autocomplete="off" autocapitalize="none" spellcheck="false"></textarea></label><div class="split"><label>Passphrase<input id="passphrase" type="password" autocomplete="off" placeholder="Blank if unused"></label><label>Account<input id="account-index" type="number" min="0" value="0"></label></div><button class="primary" type="submit">Open <span>→</span></button></form>
    <p class="error" id="form-error" role="alert">${esc(error)}</p>
  </section>`;
  $('#use-phrase')?.addEventListener('click', (e) => { e.preventDefault(); $('#phrase-form').hidden = false; $('#kept-form').hidden = true; });
  $('#kept-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try { const opened = await openSealedWallet(keptWallet(), $('#kept-password').value); await saveSession(opened.identity, opened.receiving); begin(opened.identity); } catch (err) { $('#form-error').textContent = err.message; }
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
  view = returnTo;
  frame();
  render();
  refresh();
}

function render() {
  if (!$('#view')) return;
  $('#epoch').textContent = state.epoch ? `epoch ${state.epoch}` : 'epoch —';
  root.querySelectorAll('#tabs [data-view]').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  if (view === 'wallet' && identity) view = returnTo;
  ({ in: renderIn, out: renderOut, wallet: renderWallet })[view]();
  bindRefresh();
}

(async () => {
  try {
    config = await loadConfig();
  } catch (e) {
    root.textContent = e.message;
    return;
  }
  // Testnet bridging moved to the lending app's Bridge tab.
  if (bridgePage(config)) {
    location.replace(handoff ? handoffUrl(config, handoff.key, handoff.code) : bridgePage(config));
    return;
  }
  // Unlocked already (the extension, the phone app): open straight in.
  const held = handoff ? null : await loadSession();
  if (held?.identity.viewing) begin(held.identity);
  else { frame(); render(); refresh(true); }
  setInterval(() => { if (identity && !busy) refresh(true, true); }, 30_000);
})();
