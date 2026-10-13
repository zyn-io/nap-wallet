// What the wallet reads and does, without a page around it: the
// deployment's networks, what this wallet holds on the object ledger, what
// each thing is called and what it is worth, where ZEC comes in, and the two
// ways value leaves — to another Zyn account, or out to a Zcash address. The
// compact wallet (popup-app.js) and the full view (app.js) both use it.
import { x25519 } from '@noble/curves/ed25519.js';
import { checkedEpoch, hex, unhex } from './core.js';
import { claimIntent, decodeMeta, fund, lendAsset, redeem, WAD } from './market.js';
import { bridgedName, call, loadBridged, loadOwed, loadWaiting, PER_CLAIM, submitIntent } from './ledger.js';
import { objectCall, PROGRAM, registerIntent, scan, sealNote, spendIntent } from './object.js';
import { endpoint } from './origin.js';
import { CAVE_Z, itemName } from './items.js';

// ---------------------------------------------------------------------------
// Networks.

const NETWORK_KEY = 'nap.network';
const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };

/// One network, checked as app.js checks it: every endpoint a path on Nap's
/// origin, and the Zcash network named by an address prefix something checks.
function checkedNetwork(value) {
  if (!Number.isInteger(value.chain) || typeof value.network !== 'string') throw new Error('Deployment configuration is incomplete');
  if (typeof value.zcash !== 'string' || !/^u(test)?1$/.test(String(value.zcashPrefix || ''))) throw new Error('Each network must name its Zcash network');
  const out = { ...value, collections: Array.isArray(value.collections) ? value.collections : [] };
  for (const key of ['rpcUrl', 'claimUrl', 'mediaGateway', 'lightdUrl', 'attendUrl']) {
    if ((key === 'lightdUrl' || key === 'attendUrl') && !value[key]) continue;
    out[key] = endpoint(value[key], key);
  }
  // The vault registry read (functions/eth) is a path on Nap's origin too.
  if (value.bridges?.eth?.vaultRpc) out.bridges = { ...value.bridges, eth: { ...value.bridges.eth, vaultRpc: endpoint(value.bridges.eth.vaultRpc, 'vaultRpc') } };
  return out;
}

export async function loadConfig() {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) throw new Error('config.json is missing');
  const value = await response.json();
  const networks = (Array.isArray(value.networks) && value.networks.length ? value.networks : [value])
    .map((n) => ({ id: String(n.id || n.chain), ...checkedNetwork(n) }));
  const chosen = networks.find((n) => n.id === read(NETWORK_KEY)) || networks[0];
  return { ...chosen, networks };
}

/// The same choice the full wallet remembers, so both open on one network.
export function chooseNetwork(config, id) {
  const next = config.networks.find((n) => n.id === id);
  if (!next) return config;
  write(NETWORK_KEY, next.id);
  return { ...next, networks: config.networks };
}

// ---------------------------------------------------------------------------
// Holdings.

/// Everything this wallet holds on the ledger, summed per asset and named.
/// The ledger says nothing about who owns what: the notes are opened here,
/// from the wallet's own keys.
export async function loadPocket(config, identity) {
  const epoch = checkedEpoch(await call(config, 'zyn_status'), config.chain);
  if (!identity.viewing || !identity.nullifier) return { epoch, coins: [], items: [], held: [], old: true };
  const published = await call(config, 'zyn_published');
  const { held } = scan(published, { secret: identity.viewing, nkey: identity.nullifier, owner: identity.account });
  const zec = config.zecAsset;
  const others = [...new Set(held.map((h) => h.asset))].filter((a) => a !== zec);

  const items = new Map();
  if (others.length) {
    const found = await objectCall(config.rpcUrl, 'zyn_items', { assets: others.slice(0, 500).join(',') }).catch(() => []);
    for (const i of Array.isArray(found) ? found : []) {
      if (/^[0-9a-f]{64}$/.test(i.asset) && /^[0-9a-f]{64}$/.test(i.collection) && Number.isSafeInteger(i.serial)) items.set(i.asset, i);
    }
  }
  // Names nobody signed are not invented: a launchpad token by its ticker, a
  // bridged coin by its origin, a pool share by its pair, anything else by id.
  const names = new Map([[zec, 'ZEC.zy']]);
  const origin = new Map([[zec, 'Zcash']]);
  try {
    const market = await objectCall(config.rpcUrl, 'zyn_market');
    for (const c of market.curves || []) {
      const m = /^[0-9a-f]{64}$/.test(c.token) && typeof c.meta === 'string' ? decodeMeta(c.meta) : null;
      if (m) { names.set(c.token, m.symbol); origin.set(c.token, 'Launchpad'); }
    }
    for (const b of await loadBridged(config)) {
      names.set(b.asset, bridgedName(config, b));
      origin.set(b.asset, ({ 'eip155:1': 'Ethereum', 'eip155:11155111': 'Sepolia', 'eip155:31611': 'Mezo testnet', 'solana-devnet': 'Solana devnet', 'bitcoin-signet': 'Bitcoin signet', bitcoin: 'Bitcoin' })[b.network] || b.network);
    }
    const nameOf = (id) => names.get(id) || `${id.slice(0, 6)}…`;
    for (const p of market.pools || []) {
      if (/^[0-9a-f]{64}$/.test(p.lp)) { names.set(p.lp, `LP ${nameOf(p.a)}/${nameOf(p.b)}`); origin.set(p.lp, 'Pool share'); }
    }
    // Lending receipts (Zyn Lend): derived from the asset lent, so named
    // from it without asking — lSOL.zy is a share of the SOL.zy pool.
    for (const [a, n] of [...names]) {
      if (/^[0-9a-f]{64}$/.test(a) && !n.startsWith('LP ')) { const r = hex(lendAsset(unhex(a, 32))); names.set(r, `l${n}`); origin.set(r, 'Lending share'); }
    }
  } catch { /* names only */ }

  const sums = new Map();
  for (const h of held) sums.set(h.asset, (sums.get(h.asset) || 0n) + h.amount);
  const collectionName = (id) => (config.collections.find((c) => String(c.id).toLowerCase() === id) || {}).name || (id === CAVE_Z ? 'Cave Collection Z' : `Collection ${id.slice(0, 6)}`);
  const named = (c, serial) => (c === CAVE_Z ? itemName(c, serial) : `${collectionName(c)} #${serial}`);
  const coins = [...sums].filter(([a, v]) => !items.has(a) && v > 0n)
    .map(([asset, amount]) => ({ asset, amount, symbol: names.get(asset) || `${asset.slice(0, 8)}…`, origin: origin.get(asset) || 'Zyn' }));
  if (zec && !coins.some((c) => c.asset === zec)) coins.push({ asset: zec, amount: 0n, symbol: 'ZEC.zy', origin: 'Zcash' });
  coins.sort((a, b) => (a.asset === zec ? -1 : b.asset === zec ? 1 : a.symbol.localeCompare(b.symbol)));
  const owned = [...sums].filter(([a, v]) => items.has(a) && v > 0n)
    .map(([asset]) => ({ asset, collection: items.get(asset).collection, serial: items.get(asset).serial, collectionName: collectionName(items.get(asset).collection), name: named(items.get(asset).collection, items.get(asset).serial) }));
  // What finished swaps and loans owe this wallet: collected on the next pass.
  const owed = await loadOwed(config, identity).catch(() => []);
  const nameOf = (id) => names.get(id) || `${id.slice(0, 6)}…`;
  // Bridge deposits that arrived under this wallet's codes and wait to be
  // collected (§146): not coins yet, but this wallet's to take.
  const arrived = (await loadWaiting(config, identity).catch(() => [])).map((w) => ({ asset: w.asset, amount: w.amount, symbol: nameOf(w.asset) }));
  return { epoch, coins, items: owned, held, owed, arrived, nameOf };
}

// ---------------------------------------------------------------------------
// Worth, in dollars: the prices posted on Zyn for its lending markets
// (`zyn_lendMarkets`), the one price source the chain itself checks. A coin
// with no posted price has no dollar figure; a lending share is worth its
// pool's share price in the coin lent.

export async function loadPrices(config) {
  const m = await objectCall(config.rpcUrl, 'zyn_lendMarkets').catch(() => null);
  const isInt = (v) => typeof v === 'string' && /^\d{1,40}$/.test(v);
  const isHex = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
  const price = new Map(Object.entries(m?.prices || {}).filter(([a, v]) => isHex(a) && isInt(v) && v !== '0').map(([a, v]) => [a, BigInt(v)]));
  const share = new Map((Array.isArray(m?.pools) ? m.pools : []).filter((p) => isHex(p.asset) && isHex(p.receipt) && isInt(p.share_price)).map((p) => [p.receipt, p]));
  /// Dollars (WAD) for `amount` (WAD) of `asset`, or null.
  return (asset, amount) => {
    const s = share.get(asset);
    const [a, v] = s ? [s.asset, (BigInt(amount) * BigInt(s.share_price)) / WAD] : [asset, BigInt(amount)];
    const p = price.get(a);
    return p ? (v * p) / WAD : null;
  };
}

/// Dollars (WAD) as text: `$1,234.56`, `<$0.01`, or '' for none.
export function usdText(v) {
  if (v == null || v === 0n) return '';
  const cents = v / (WAD / 100n);
  if (cents === 0n && v > 0n) return '<$0.01';
  return `$${(cents / 100n).toLocaleString('en-US')}.${String(cents % 100n).padStart(2, '0')}`;
}

/// Collect everything swaps and loans owe this wallet. Returns how many.
export async function collectOwed(config, identity, owed) {
  let done = 0;
  for (let i = 0; i < owed.length; i += PER_CLAIM) {
    const batch = owed.slice(i, i + PER_CLAIM);
    await submitIntent(config, identity, claimIntent(redeem(identity, batch)));
    done += batch.length;
  }
  return done;
}

// ---------------------------------------------------------------------------
// Coming in.

/// This wallet's ZEC.zy deposit address, publishing where it is paid first if
/// it never has. An address from the wrong Zcash network is refused outright.
export async function depositAddress(config, identity) {
  let r = await objectCall(config.rpcUrl, 'zyn_depositAddress', { account: identity.accountHex });
  if (r?.registered === false && identity.viewing) {
    await submitIntent(config, identity, registerIntent(identity.account, x25519.getPublicKey(identity.viewing)));
    r = await objectCall(config.rpcUrl, 'zyn_depositAddress', { account: identity.accountHex });
  }
  const address = String(r?.address || '');
  if (!address.startsWith(config.zcashPrefix)) throw new Error(`The node answered with an address that is not ${config.zcash}`);
  return address;
}

// ---------------------------------------------------------------------------
// Going out.

/// Who a recipient is, decided before anything is signed: a Zyn account, a
/// Zcash address that belongs to one (paid on Zyn), or an outside Zcash
/// address (only ZEC.zy may go there, as a withdrawal).
export async function resolveRecipient(config, identity, raw, { isZec, isItem }) {
  const text = String(raw).trim();
  let to = null, external = null;
  if (/^[0-9a-f]{64}$/i.test(text)) to = text.toLowerCase();
  else if (text.startsWith(config.zcashPrefix) || /^t[a-z0-9]{20,}$/i.test(text)) {
    const r = await objectCall(config.rpcUrl, 'zyn_resolveAddress', { address: text });
    if (r && /^[0-9a-f]{64}$/.test(String(r.account))) to = r.account;
    else external = text;
  } else throw new Error(`That is neither an account ID nor a ${config.zcash} address`);
  if (external && !isZec) throw new Error(isItem ? 'An item cannot leave Zyn. Send it to a Zyn account.' : 'Only ZEC in apps can be paid to an outside Zcash address.');
  if (to && (/^0{64}$/.test(to) || to === identity.accountHex)) throw new Error('Choose a different recipient');
  return { to, external };
}

/// Pay another Zyn account: retire notes this wallet holds and make one
/// sealed to the key the recipient published, with change back to this one.
export async function payOnZyn(config, identity, held, assetHex, amount, toHex) {
  const { viewing } = await objectCall(config.rpcUrl, 'zyn_viewingKey', { account: toHex });
  if (!/^[0-9a-f]{64}$/.test(String(viewing || ''))) throw new Error('That account has not published where it is paid yet');
  const asset = unhex(assetHex, 32);
  const { inputs, change } = fund(identity, held, asset, amount);
  const note = { asset, amount, owner: unhex(toHex, 32), nonce: crypto.getRandomValues(new Uint8Array(32)) };
  const enc = sealNote(unhex(viewing, 32), crypto.getRandomValues(new Uint8Array(32)), note);
  return submitIntent(config, identity, spendIntent(identity.account, PROGRAM.privateTransfer, inputs, [{ note, enc }, ...change]));
}

// Exits waiting to be told where they go — the same record app.js keeps.
// ZEC out, and the exits waiting to be revealed, live in bridges.js.
export { revealExits, withdrawZec } from './bridges.js';

// ---------------------------------------------------------------------------
// What this wallet did, as this device saw it. The ledger publishes no
// history an account can read back, so the popup keeps its own short log.

const logKey = (config, identity) => `nap.activity.${config.chain}.${identity.accountHex}`;
export const activity = (config, identity) => { try { return JSON.parse(read(logKey(config, identity)) || '[]'); } catch { return []; } };
export function logActivity(config, identity, entry) {
  write(logKey(config, identity), JSON.stringify([{ at: Date.now(), ...entry }, ...activity(config, identity)].slice(0, 50)));
}

// ---------------------------------------------------------------------------
// Coins bridged in through a site (Zyn Lend's Bridge) arrive under this
// wallet's one-time codes; the wallet claims them itself. The bridges live in
// bridges.js, shared with Nap Connect.
export { bridgesOf, claimDeposits, revealBridgeExits } from './bridges.js';
