// The object ledger, as the wallet's pages talk to it: one JSON-RPC call,
// the holder's own view of what they hold, and signing an intent.
//
// Shared by the wallet, the connect window and the embedded core. Two copies of the claim-id
// derivation or the nonce counter would drift, and a drift here is money the
// wallet can no longer find — so there is one.

import { checkedEpoch } from './core.js';
import { hex, rpcPost, scan, signedFrame, submitSigned, unhex } from './object.js';
import * as mk from './market.js';
import { b58decode } from './solana.js';

/// Epochs a signature stays valid. Long enough to survive a slow submit,
/// short enough that a frame found later is useless.
export const VALIDITY = 100n;
/// How far past the last nonce this device used to look for claims — another
/// device, or a restore, may have used some.
export const LOOKAHEAD = 24;
/// Claims per redemption: the VM's I/O limit.
export const PER_CLAIM = 16;

const read = (key) => { try { return localStorage.getItem(key); } catch { return null; } };
const write = (key, v) => { try { localStorage.setItem(key, v); } catch { /* this session only */ } };

export async function call(config, method, fields = {}) {
  const id = crypto.randomUUID();
  const response = await rpcPost(config.rpcUrl, { jsonrpc: '2.0', id, method, params: [], ...fields });
  if (!response.ok) throw new Error(`The chain answered HTTP ${response.status}`);
  const body = await response.json();
  if (body.id !== id) throw new Error('The chain answered a different question');
  if (body.error) throw new Error(body.error.message || 'The chain refused');
  return body.result;
}

// Nonces are receipts, so they are counted per chain and account and never
// handed out twice by this device — whichever page hands them out.
const counterKey = (config, identity) => `nap.market.n.${config.chain}.${identity.accountHex}`;
export const nonceCount = (config, identity) => Number(read(counterKey(config, identity)) || 0);
export function nextNonce(config, identity) {
  const n = nonceCount(config, identity);
  write(counterKey(config, identity), String(n + 1));
  return mk.marketNonce(identity.secretKey, n);
}

/// Every claim this wallet could be owed, from every nonce it may have used.
export function claimSources(identity, limit, from = 0) {
  const out = [];
  const me = identity.account;
  for (let n = from; n < limit; n++) {
    const nonce = mk.marketNonce(identity.secretKey, n);
    const lend = mk.lendSource(me, nonce);
    for (const source of [mk.orderId(me, nonce), mk.liquidityId(me, nonce), mk.commitId(me, nonce), mk.launchSource(me, nonce), mk.listingSource(me, nonce), mk.curveOrderId(me, nonce), mk.curveSource(me, nonce), lend, mk.leftoverSource(lend)]) {
      out.push(...mk.claimIds(source).map(hex));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Finding the count after a restore (the 25 Sep audit's H2).
//
// The count of nonces a wallet has used lives on the device that used them.
// A restored wallet starts at zero and looks only LOOKAHEAD past it, so an
// active holder's newest — uncollected — claims, tickets and deposits were out
// of sight. A device that has never counted for this wallet now walks its
// nonces in pages, asking the chain for anything still held under each one
// (claims owed, sale tickets, deposits waiting, coins it created), until
// RECOVERY_GAP nonces in a row show nothing; then it keeps the count. Settled
// and collected trades leave nothing behind, so a longer run of those than
// the gap is the one case this cannot see past — the Owed view can look
// further by hand (`recoverNonces(…, { gap })`).
export const RECOVERY_GAP = 256;
const RECOVERY_PAGE = 64;
const recovering = new Map();

/// Once per device and wallet: recover the count if this device never kept one.
export function ensureNonces(config, identity) {
  if (read(counterKey(config, identity)) != null) return Promise.resolve(nonceCount(config, identity));
  const key = counterKey(config, identity);
  if (!recovering.has(key)) recovering.set(key, recoverNonces(config, identity).finally(() => recovering.delete(key)));
  return recovering.get(key);
}

/// Walk this wallet's nonces for anything the chain still holds under them,
/// and keep the count past the last one found. Returns the count.
export async function recoverNonces(config, identity, { gap = RECOVERY_GAP } = {}) {
  const me = identity.account;
  const market = await call(config, 'zyn_market').catch(() => ({}));
  const made = new Set((market.curves || []).map((c) => c.token));
  const bridged = (await loadBridged(config)).map((b) => b.asset);
  let last = -1;
  for (let from = 0; from <= last + gap; from += RECOVERY_PAGE) {
    const to = from + RECOVERY_PAGE;
    const at = new Map(); // id -> nonce index
    for (let n = from; n < to; n++) {
      const nonce = mk.marketNonce(identity.secretKey, n);
      if (made.has(hex(mk.tokenOf(me, nonce)))) last = Math.max(last, n);
      for (const id of claimSources(identity, n + 1, n)) at.set(id, n);
      at.set(hex(mk.ticketId(me, nonce, 0)), n);
      at.set(hex(mk.voucherTicketId(mk.voucherCommitment(me, nonce), 0)), n);
      const commitment = mk.depositCommitment(me, nonce);
      for (const a of bridged) at.set(hex(mk.depositKey(commitment, unhex(a))), n);
      // A lending position (or the auction it became) is keyed by its source.
      at.set(hex(mk.lendSource(me, nonce)), n);
    }
    const ids = [...at.keys()];
    // One page's questions at once: a restore should take seconds, not a minute.
    const asks = [];
    for (const [method, field, size] of [['zyn_claims', 'id', 240], ['zyn_tickets', 'ticket', 500], ['zyn_waiting', 'key', 500], ['zyn_lendPositions', 'id', 240]]) {
      for (let i = 0; i < ids.length; i += size) {
        asks.push(call(config, method, { ids: ids.slice(i, i + size).join(',') }).then((part) => (Array.isArray(part) ? part.map((row) => row[field]) : []), () => []));
      }
    }
    const found = (await Promise.all(asks)).flat();
    for (const id of found) if (at.has(id)) last = Math.max(last, at.get(id));
  }
  const count = Math.max(last + 1, nonceCount(config, identity));
  write(counterKey(config, identity), String(count));
  return count;
}

/// What each claim id a nonce can produce is, for the Owed view: a swap that
/// filled is not a swap that came back.
const CLAIM_KINDS = [
  ['order', ['Swap filled', 'Swap refunded — the batch price was worse than your floor', 'Swap']],
  ['liquidity', ['Pool shares', 'Liquidity returned', 'Liquidity returned']],
  ['commit', ['Launch commitment', 'Launch refund', 'Launch']],
  ['launch', ['Your launch', 'Your launch', 'Your launch']],
  ['listing', ['Sale proceeds', 'Listing', 'Listing']],
  ['curve-order', ['Curve trade filled', 'Curve trade refunded — the price moved past your floor', 'Curve trade']],
  ['curve', ['Creator payout', 'Creator payout', 'Creator payout']],
  ['lend', ['Lending: shares, coins or collateral', 'Lending refund', 'Lending']],
  ['lend-lot', ['Left over after liquidation', 'Collateral back after liquidation', 'Liquidation']],
];
function claimKinds(identity, limit, from = 0) {
  const kinds = new Map();
  const me = identity.account;
  for (let n = from; n < limit; n++) {
    const nonce = mk.marketNonce(identity.secretKey, n);
    const lend = mk.lendSource(me, nonce);
    const sources = [mk.orderId(me, nonce), mk.liquidityId(me, nonce), mk.commitId(me, nonce), mk.launchSource(me, nonce), mk.listingSource(me, nonce), mk.curveOrderId(me, nonce), mk.curveSource(me, nonce), lend, mk.leftoverSource(lend)];
    sources.forEach((source, i) => mk.claimIds(source).forEach((id, k) => kinds.set(hex(id), CLAIM_KINDS[i][1][k])));
  }
  return kinds;
}

export async function loadOwed(config, identity) {
  await ensureNonces(config, identity);
  const kinds = claimKinds(identity, nonceCount(config, identity) + LOOKAHEAD);
  const ids = [...kinds.keys()];
  const rows = [];
  for (let i = 0; i < ids.length; i += 240) {
    const part = await call(config, 'zyn_claims', { ids: ids.slice(i, i + 240).join(',') });
    if (Array.isArray(part)) rows.push(...part);
  }
  return rows.filter((r) => /^[0-9a-f]{64}$/.test(r.id) && /^[0-9a-f]{64}$/.test(r.asset) && /^\d+$/.test(r.amount))
    .map((r) => ({ ...r, kind: kinds.get(r.id) || 'Owed' }));
}

/// Wait until notes a write spent are gone from this holder's view, so the
/// next write funds from what the chain now publishes (its change) rather
/// than from notes already spent. The node may seal the write before this
/// is even called, so this watches the notes, not the epoch.
export async function waitSpent(config, identity, commitments, timeoutMs = 90_000) {
  const gone = new Set(commitments);
  for (const until = Date.now() + timeoutMs; Date.now() < until;) {
    const { held } = await loadHoldings(config, identity, []);
    if (!held.some((h) => gone.has(h.commitment))) return;
    await new Promise((r) => setTimeout(r, 1500));
  }
  throw new Error('The chain has not taken the last step in yet; try the rest again shortly');
}

// ---------------------------------------------------------------------------
// Deposits from other chains (§146): SOL, ETH. A deposit there carries a
// commitment to this account and one of its nonces — never the account — and
// waits on the ledger until this wallet claims it.

/// The assets bridged here beside ZEC, as the chain describes them.
export async function loadBridged(config) {
  const rows = await call(config, 'zyn_bridged').catch(() => []);
  return (Array.isArray(rows) ? rows : []).filter((r) => isHex(r.asset) && typeof r.network === 'string' && isSmall(r.decimals));
}

/// A bridged asset's name from its origin (§146): the network's own coin is
/// SOL.zy, ETH.zy, BTC.zy or mzBTC.zy; a token bridged from it takes the symbol the deployment
/// gives its mint or contract (BOLD.zy), else its short address.
export function bridgedName(config, b) {
  const short = (h) => `${h.slice(0, 8)}…`;
  if (b.origin) {
    const token = b.network.startsWith('solana') && (config.bridges?.sol?.tokens || []).find((t) => {
      try { return hex(b58decode(String(t.mint))) === b.origin; } catch { return false; }
    });
    // An ERC-20 into the EVM vault (BOLD, §68), by the symbol the deployment gives it.
    const erc20 = b.network === `eip155:${config.bridges?.eth?.chainId}` && (config.bridges?.eth?.tokens || []).find((t) => String(t.address || '').slice(2).toLowerCase() === b.origin);
    return `${token ? String(token.symbol) : erc20 ? String(erc20.symbol) : short(b.origin)}.zy`;
  }
  if (b.network.startsWith('solana')) return 'SOL.zy';
  // BTC through Mezo (testnet 31611, mainnet 31612) is its own asset (§158).
  if (b.network === 'eip155:31611' || b.network === 'eip155:31612') return 'mzBTC.zy';
  if (b.network.startsWith('eip155:')) return 'ETH.zy';
  if (b.network.startsWith('bitcoin')) return 'BTC.zy';
  return short(b.asset);
}

const bridgeKey = (config, identity) => `nap.bridge.${config.chain}.${identity.accountHex}`;
const bridgeUsedKey = (config, identity) => `nap.bridge.used.${config.chain}.${identity.accountHex}`;
const usedNonces = (config, identity) => new Set(JSON.parse(read(bridgeUsedKey(config, identity)) || '[]'));

/// Deposits waiting for this wallet, from every nonce it may have used.
export async function loadWaiting(config, identity, bridged) {
  await ensureNonces(config, identity);
  const assets = (bridged || (await loadBridged(config))).map((b) => b.asset);
  if (!assets.length) return [];
  const me = identity.account;
  const want = new Map();
  const limit = nonceCount(config, identity) + LOOKAHEAD;
  for (let n = 0; n < limit; n++) {
    const secret = mk.marketNonce(identity.secretKey, n);
    const commitment = mk.depositCommitment(me, secret);
    for (const a of assets) want.set(hex(mk.depositKey(commitment, unhex(a))), { n, secret, asset: a });
  }
  const ids = [...want.keys()];
  const rows = [];
  for (let i = 0; i < ids.length; i += 500) {
    const part = await call(config, 'zyn_waiting', { ids: ids.slice(i, i + 500).join(',') });
    if (Array.isArray(part)) rows.push(...part);
  }
  return rows
    .filter((r) => want.has(r.key) && isInt(r.amount) && want.get(r.key).asset === r.asset)
    .map((r) => ({ ...want.get(r.key), amount: BigInt(r.amount) }));
}

/// The code a deposit on another chain carries: `zyn:<commitment>`. The same
/// code comes back until a deposit with it lands, then a fresh one — so two
/// deposits are not linked to each other by their memo.
export async function bridgeMemo(config, identity) {
  const saved = read(bridgeKey(config, identity));
  if (saved != null && !usedNonces(config, identity).has(Number(saved))) {
    const n = Number(saved);
    const waiting = await loadWaiting(config, identity).catch(() => []);
    if (!waiting.some((w) => w.n === n)) {
      const commitment = mk.depositCommitment(identity.account, mk.marketNonce(identity.secretKey, n));
      return { memo: `zyn:${hex(commitment)}`, commitment: hex(commitment) };
    }
    markUsed(config, identity, n);
  }
  const n = nonceCount(config, identity);
  nextNonce(config, identity);
  write(bridgeKey(config, identity), String(n));
  const commitment = mk.depositCommitment(identity.account, mk.marketNonce(identity.secretKey, n));
  return { memo: `zyn:${hex(commitment)}`, commitment: hex(commitment) };
}

function markUsed(config, identity, n) {
  const used = usedNonces(config, identity);
  used.add(n);
  write(bridgeUsedKey(config, identity), JSON.stringify([...used]));
}

/// Claim every waiting deposit into this wallet, one note each.
export async function claimWaiting(config, identity) {
  const waiting = await loadWaiting(config, identity);
  for (const w of waiting) {
    await submitIntent(config, identity, mk.claimDepositIntent({
      owner: identity.account, secret: w.secret, asset: unhex(w.asset), output: mk.selfNote(identity, unhex(w.asset), w.amount),
    }));
    markUsed(config, identity, w.n);
  }
  return waiting.length;
}

/// Tickets this wallet bought in a sale (§144). A ticket id derives from a
/// nonce only this wallet holds, so it asks by id: the first ticket of every
/// nonce it may have used, then the rest of each buy it finds.
export async function loadTickets(config, identity, collection) {
  await ensureNonces(config, identity);
  const me = identity.account;
  const limit = nonceCount(config, identity) + LOOKAHEAD;
  const nonces = Array.from({ length: limit }, (_, n) => mk.marketNonce(identity.secretKey, n));
  const ask = async (ids) => {
    const rows = [];
    for (let i = 0; i < ids.length; i += 500) {
      const part = await call(config, 'zyn_tickets', { ids: ids.slice(i, i + 500).map((x) => x.id).join(',') });
      if (Array.isArray(part)) rows.push(...part);
    }
    const byId = new Map(ids.map((x) => [x.id, x]));
    return rows
      .filter((r) => isHex(r.ticket) && r.collection === collection && isSmall(r.index) && typeof r.claimed === 'boolean' && byId.has(r.ticket))
      .map((r) => ({ ...byId.get(r.ticket), index: r.index, claimed: r.claimed }));
  };
  // Bought tickets derive from (me, nonce, k); burn tickets (§145) from the
  // commitment a burn's memo carried, made from (me, nonce) — so one scan of
  // this wallet's nonces finds both.
  const id = (nonce, k, voucher) => hex(voucher ? mk.voucherTicketId(mk.voucherCommitment(me, nonce), k) : mk.ticketId(me, nonce, k));
  const firsts = await ask(nonces.flatMap((nonce) => [false, true].map((voucher) => ({ id: id(nonce, 0, voucher), nonce, k: 0, voucher }))));
  const rest = await ask(firsts.flatMap((t) => Array.from({ length: 19 }, (_, j) => ({ id: id(t.nonce, j + 1, t.voucher), nonce: t.nonce, k: j + 1, voucher: t.voucher }))));
  return [...firsts, ...rest]
    .map((t) => ({ ticket: t.id, nonce: t.nonce, k: t.k, voucher: t.voucher, index: t.index, claimed: t.claimed }))
    .sort((a, b) => a.index - b.index);
}

/// The memo a burn on Solana carries to become this wallet's tickets (§145):
/// `zyn:<commitment>`, from this account and a nonce only it derives. The
/// same memo comes back until a burn with it lands, so a site asking again
/// does not use up nonces.
/// `fresh`: a new code even if the last one has not landed yet — for a burn
/// about to be signed, so a second burn before the first is posted gets its
/// own tickets instead of reusing a code the chain will refuse.
export async function burnMemo(config, identity, { fresh = false } = {}) {
  const key = `nap.burn.${config.chain}.${identity.accountHex}`;
  const saved = read(key);
  if (saved != null && !fresh) {
    const commitment = mk.voucherCommitment(identity.account, mk.marketNonce(identity.secretKey, Number(saved)));
    const landed = await call(config, 'zyn_tickets', { ids: hex(mk.voucherTicketId(commitment, 0)) });
    if (!(Array.isArray(landed) && landed.length)) return { memo: `zyn:${hex(commitment)}`, commitment: hex(commitment) };
  }
  const n = nonceCount(config, identity);
  nextNonce(config, identity);
  write(key, String(n));
  const commitment = mk.voucherCommitment(identity.account, mk.marketNonce(identity.secretKey, n));
  return { memo: `zyn:${hex(commitment)}`, commitment: hex(commitment) };
}

/// A sale as the chain holds it, and the posted draw and open-mint order —
/// each checked against the root the chain holds, so the node serving them
/// cannot change who won or what sells next.
export async function loadSale(config, collection) {
  const market = await call(config, 'zyn_market');
  const sale = (market.sales || []).find((s) => s.collection === collection);
  if (!sale) return null;
  const terms = (market.collections || []).find((c) => c.asset === collection);
  const out = { sale, quote: terms && isHex(terms.quote) ? terms.quote : config.zecAsset, draw: null, open: null };
  if (sale.phase === 'drawn' || sale.phase === 'openmint') {
    const d = await call(config, 'zyn_saleDraw', { collection, kind: 'draw' });
    if (d && Array.isArray(d.won)) {
      const won = d.won.filter((w) => isHex(w.ticket) && Array.isArray(w.serials) && w.serials.length && w.serials.every(isSmall));
      const leaves = won.map((w) => mk.drawLeaf(unhex(w.ticket), w.serials));
      if (won.length === d.won.length && hex(mk.merkleRoot(leaves)) === sale.draw_root) out.draw = { won, leaves };
    }
  }
  if (sale.phase === 'openmint') {
    const o = await call(config, 'zyn_saleDraw', { collection, kind: 'open' });
    if (o && Array.isArray(o.order) && o.order.every(isSmall) && o.order.length === sale.open_count) {
      const leaves = o.order.map((s, i) => mk.openLeaf(i, s));
      if (hex(mk.merkleRoot(leaves)) === sale.open_root) out.open = { order: o.order, leaves };
    }
  }
  return out;
}

// What the node says goes into markup, ids and arithmetic, so its shape is
// checked first: a row that is not exactly hex ids and integer strings is
// dropped rather than rendered.
export const isHex = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
export const isInt = (v) => typeof v === 'string' && /^\d{1,40}$/.test(v);
export const isSmall = (v) => Number.isSafeInteger(v) && v >= 0;
export const validOffer = (o) => ['item', 'asset', 'price_asset'].every((k) => isHex(o[k]))
  && ['price_raw', 'fee_raw', 'pay_raw'].every((k) => isInt(o[k])) && isSmall(o.expires_at_epoch)
  && (o.collection === '' || isHex(o.collection)) && (o.nullifier === '' || isHex(o.nullifier)) && Number.isSafeInteger(o.serial);

/// The public order book, validated.
export async function loadOffers(config) {
  const book = await call(config, 'zyn_offers').catch(() => ({ offers: [] }));
  return (book?.offers || []).filter(validOffer);
}

/// What this holder holds, opened with their own keys, and which of it are
/// items (asked by asset, which says nothing a listing does not).
export async function loadHoldings(config, identity, offers) {
  const published = await call(config, 'zyn_published');
  const { held, balances } = scan(published, { secret: identity.viewing, nkey: identity.nullifier, owner: identity.account });
  const items = new Map();
  for (const o of offers) if (o.serial >= 0) items.set(o.asset, { collection: o.collection, serial: o.serial });
  const unknown = [...new Set(held.map((h) => h.asset))].filter((a) => a !== config.zecAsset && !items.has(a));
  if (unknown.length) {
    const found = await call(config, 'zyn_items', { assets: unknown.slice(0, 500).join(',') }).catch(() => []);
    for (const i of Array.isArray(found) ? found : []) {
      if (isHex(i.asset) && isHex(i.collection) && isSmall(i.serial)) items.set(i.asset, { collection: i.collection, serial: i.serial });
    }
  }
  return { held, balances, items };
}

/// Submit an intent that carries a nonce, taking the next nonce and trying
/// again whenever the chain says one was already used. A nonce is counted on
/// this device, so a restored phrase, a second device or a cleared browser
/// starts the count where another left off — and the chain, which refuses a
/// reused source, is the only place that knows. Returns the nonce that took.
/// Every way the chain says "this nonce is already taken" — by a claim or
/// order, by a resting listing, or by a coin (whose address is a hash of its
/// creator and nonce). tests/nonce.test.mjs checks these against the VM.
export const NONCE_TAKEN = /that nonce was already used|that nonce is in use|that token exists/;

export async function submitFresh(config, identity, build, tries = 64) {
  for (let i = 0; i < tries; i++) {
    const nonce = nextNonce(config, identity);
    try {
      await submitIntent(config, identity, build(nonce));
      return nonce;
    } catch (e) {
      if (!NONCE_TAKEN.test(String(e.message))) throw e;
    }
  }
  throw new Error('Every nonce tried was already used; this wallet has traded from somewhere else a lot. Try again.');
}

/// Sign an intent and hand it to the holders' door. A refusal inside the
/// receipts is an error too — the frame was accepted, the intent was not.
export async function submitIntent(config, identity, intent) {
  const status = await call(config, 'zyn_status');
  const epoch = checkedEpoch(status, config.chain);
  const frame = await signedFrame(identity.secretKey, config.chain, epoch + VALIDITY, intent);
  const result = await submitSigned(config.rpcUrl, frame);
  const refused = /Refused\("([^"]*)"\)/.exec(String(result?.receipts || ''));
  if (refused) throw new Error(`The chain refused: ${refused[1]}`);
  return result;
}

/// This wallet's lending positions, and any that became auctions: asked by
/// the ids only this wallet can derive, so nobody learns whose they are.
export async function loadPositions(config, identity) {
  const count = (await ensureNonces(config, identity)) + LOOKAHEAD;
  const ids = [];
  for (let n = 0; n < count; n++) ids.push(hex(mk.lendSource(identity.account, mk.marketNonce(identity.secretKey, n))));
  const rows = [];
  for (let i = 0; i < ids.length; i += 240) {
    const part = await call(config, 'zyn_lendPositions', { ids: ids.slice(i, i + 240).join(',') }).catch(() => []);
    if (Array.isArray(part)) rows.push(...part);
  }
  // Only ids this wallet asked for: a site is handed this list, and it must
  // never carry a position that is not this account's.
  const mine = new Set(ids);
  return rows.filter((r) => r && mine.has(r.id));
}
