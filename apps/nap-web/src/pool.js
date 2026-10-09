// The private bridge channel in Nap (DECISIONS §158): SOL through the
// Solana pools, ETH through Sepolia's, BTC through Mezo's as mzBTC.zy.
//
// A note is two secrets derived from this wallet's key and an index — so any
// Nap holding the same phrase can find its notes again — whose commitment
// sits in a pool on the other chain. Spending one proves "one of the pool's
// notes is mine" without saying which, bound to what the spend is for: a Zyn
// deposit code (in), or an address, a relayer and its fee (out). The relayer
// submits spends, so no wallet of the holder's pays for one.
//
// Only commitments and states are stored; secrets are derived when needed.

import { sha512 } from '@noble/hashes/sha2.js';
import { hex, unhex } from './core.js';
import * as ledger from './ledger.js';
import * as bridges from './bridges.js';
import { b58decode } from './solana.js';
import { bridgedAsset } from './market.js';

const DOMAIN = new TextEncoder().encode('zyn-pool.note.v1');
const pow10 = (n) => 10n ** BigInt(n);

/// The private channels: one set of pools per chain, three sizes each, in
/// the chain's smallest unit. `chain` is what the node routes the relayer
/// calls by. ETH shares ETH.zy with the transparent bridge; BTC through Mezo
/// is its own asset, mzBTC.zy.
const ALL = {
  sol: { key: 'sol', chain: 'solana', symbol: 'SOL', zy: 'SOL.zy', decimals: 9, sizes: [100_000_000n, 1_000_000_000n, 10_000_000_000n], address: 'solana' },
  eth: { key: 'eth', chain: 'eip155:11155111', symbol: 'ETH', zy: 'ETH.zy', decimals: 18, sizes: [pow10(16), pow10(17), pow10(18)], address: 'evm', chainName: 'Sepolia', chainId: 11155111 },
  mzbtc: { key: 'mzbtc', chain: 'eip155:31611', symbol: 'BTC', zy: 'mzBTC.zy', decimals: 18, sizes: [pow10(15), pow10(16), pow10(17)], address: 'evm', chainName: 'Mezo testnet', chainId: 31611 },
};

/// The channels this network has: testnet only until the keys come from a
/// ceremony (§158.8).
export function channels(config) {
  const b = config.bridges || {};
  const out = [];
  if (b.sol && /devnet|testnet/.test(b.sol.network || '')) out.push({ ...ALL.sol, chainName: 'Solana devnet' });
  if (b.eth?.chainId === ALL.eth.chainId) out.push(ALL.eth);
  if (b.mezo?.chainId === ALL.mzbtc.chainId) out.push(ALL.mzbtc);
  return out.map((c) => ({ ...c, network: c.key === 'sol' ? b.sol.network : c.chain, asset: hex(bridgedAsset(c.key === 'sol' ? b.sol.network : c.chain)) }));
}

export function channel(config, key = 'sol') {
  const c = channels(config).find((x) => x.key === key);
  if (!c) throw new Error('No such private channel on this network');
  return c;
}

/// A size in the chain's unit, as the text a person reads: "0.1 SOL".
export const sizeText = (c, size) => {
  const v = BigInt(size);
  const whole = v / pow10(c.decimals);
  const frac = (v % pow10(c.decimals)).toString().padStart(c.decimals, '0').replace(/0+$/, '');
  return `${whole}${frac ? `.${frac}` : ''} ${c.symbol}`;
};

/// One size of `c`, or a refusal naming the sizes it takes.
export function sizeOf(c, size) {
  let v;
  try { v = BigInt(String(size)); } catch { v = -1n; }
  if (!c.sizes.includes(v)) throw new Error(`Pools take ${c.sizes.map((x) => sizeText(c, x)).join(', ')}`);
  return v;
}

const read = (k) => { try { return localStorage.getItem(k); } catch { return null; } };
const write = (k, v) => { try { localStorage.setItem(k, v); } catch { /* this session only */ } };
const u32be = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

// ------------------------------------------------------------------ core

let ready = null;
/// The WASM core with the proving key loaded, once.
function core() {
  if (!ready) {
    ready = (async () => {
      const m = await import('./pool-pkg/nap_pool.js');
      const inNode = typeof window === 'undefined';
      if (inNode) {
        const { readFileSync } = await import('node:fs');
        await m.default({ module_or_path: readFileSync(new URL('./pool-pkg/nap_pool_bg.wasm', import.meta.url)) });
        m.load_key(readFileSync(new URL('../public/pool/spend.pk.raw', import.meta.url)));
      } else {
        await m.default();
        const r = await fetch('/pool/spend.pk.raw');
        if (!r.ok) throw new Error('The private channel could not load its proving key');
        m.load_key(new Uint8Array(await r.arrayBuffer()));
      }
      return m;
    })().catch((e) => { ready = null; throw e; });
  }
  return ready;
}

const randomHex = () => hex(crypto.getRandomValues(new Uint8Array(32)));

// ------------------------------------------------------------------ notes

const key = (config, identity) => `nap.pool.v1.${config.chain}.${identity.accountHex}`;

function book(config, identity) {
  try { return JSON.parse(read(key(config, identity)) || '') || { next: 0, notes: [] }; } catch { return { next: 0, notes: [] }; }
}
const save = (config, identity, b) => write(key(config, identity), JSON.stringify(b));

async function secrets(config, identity, i) {
  const seed = sha512(new Uint8Array([...DOMAIN, ...identity.secretKey, ...u32be(config.chain >>> 0), ...u32be(i)]));
  return JSON.parse((await core()).note(hex(seed)));
}

/// A fresh note of `size` (in the chain's unit) for channel `c`: `in` (to
/// deposit into a pool) or `out` (a private exit's destination).
export async function newNote(config, identity, c, size, kind) {
  const v = sizeOf(c, size);
  // An index already used on any chain would make the same note again: one
  // whose nullifier may be spent, so coins deposited to it could never leave.
  // A wallet restored from its phrase starts with an empty book, so the pools
  // are read first, and a pool that cannot be read stops the note.
  const { complete } = await scan(config, identity);
  if (!complete) throw new Error('Nap could not read every pool to pick a fresh note; try again shortly');
  const b = book(config, identity);
  const i = b.next;
  const n = await secrets(config, identity, i);
  b.next = i + 1;
  b.notes.push({ i, ch: c.key, size: String(v), kind, commitment: n.commitment, state: 'new', at: Date.now() });
  save(config, identity, b);
  return { i, ch: c.key, size: String(v), commitment: n.commitment };
}

function mark(config, identity, commitment, state, extra = {}) {
  const b = book(config, identity);
  const n = b.notes.find((x) => x.commitment === commitment);
  if (n) Object.assign(n, { state }, extra);
  save(config, identity, b);
}

/// Notes written before there was more than one channel are SOL notes.
const chOf = (n) => n.ch || 'sol';

export const info = (config, c) => ledger.call(config, 'zyn_poolInfo', { chain: c.chain });
const pools = async (config, c, size) => ledger.call(config, 'zyn_poolLeaves', { chain: c.chain, size: String(size) });
const leaves = async (config, c, size) => (await pools(config, c, size)).leaves;
const SPENT = new Set(['to zyn', 'sent', 'spent']);
/// How far past the last note found a restored wallet keeps looking.
const GAP = 20;

/// This wallet's notes on every channel, each with where it stands: `new` or
/// `burned` (not in its pool yet), `in pool` (unspent: into Zyn or to an
/// address), or spent. Found again from the phrase alone: every index is
/// tried against every pool's notes, and a note whose nullifier hash a spend
/// published is spent.
export async function notes(config, identity) {
  return (await scan(config, identity)).notes;
}

/// A pool's notes, asked up to three times: a public RPC behind a relayer
/// can refuse one call and answer the next.
async function readPool(config, c, size) {
  for (let t = 0; ; t++) {
    try { return await pools(config, c, size); } catch (e) {
      if (t === 2) throw e;
      await new Promise((z) => setTimeout(z, 1500 * (t + 1)));
    }
  }
}

async function scan(config, identity) {
  const b = book(config, identity);
  const seen = [];
  let complete = true;
  for (const c of channels(config)) {
    for (const size of c.sizes) {
      const r = await readPool(config, c, size).catch(() => { complete = false; return { leaves: [], spent: [] }; });
      seen.push({ c, size: String(size), leaves: new Set(r.leaves), spent: new Set(r.spent || []) });
    }
  }
  let last = b.next - 1;
  for (let i = 0; i <= Math.max(b.next, last + 1) + GAP; i++) {
    const n = await secrets(config, identity, i);
    for (const p of seen) {
      if (!p.leaves.has(n.commitment)) continue;
      last = Math.max(last, i);
      let note = b.notes.find((x) => x.commitment === n.commitment);
      if (!note) {
        note = { i, ch: p.c.key, size: p.size, kind: 'note', commitment: n.commitment, state: 'in pool', at: null };
        b.notes.push(note);
      }
      if (p.spent.has(n.nullifier_hash)) {
        if (!SPENT.has(note.state)) note.state = 'spent';
      } else note.state = 'in pool';
    }
  }
  b.next = Math.max(b.next, last + 1);
  b.notes.sort((x, y) => x.i - y.i);
  save(config, identity, b);
  const known = new Set(channels(config).map((c) => c.key));
  const notes = b.notes
    .filter((n) => known.has(chOf(n)))
    .map(({ i, size, kind, commitment, state, at, signature, ...n }) => ({ i, ch: chOf(n), size: String(size), kind, commitment, state, at, signature }));
  return { notes, complete };
}

async function proveFor(config, identity, c, note, binding) {
  const ls = await leaves(config, c, note.size);
  if (!ls.includes(note.commitment)) throw new Error('That note is not in its pool yet; try again once its deposit or exit is confirmed');
  const s = await secrets(config, identity, note.i);
  const m = await core();
  return { m, p: JSON.parse(m.prove(JSON.stringify(ls), s.nullifier, s.secret, binding, randomHex())), count: ls.length };
}

/// A note of this wallet's that can still be spent — whichever way: a note
/// deposited on its chain can go to an address, and an exit note into Zyn.
export function own(config, identity, commitment) {
  const n = book(config, identity).notes.find((x) => x.commitment === commitment);
  if (!n) throw new Error('No such note in this wallet');
  if (SPENT.has(n.state)) throw new Error('That note is already spent');
  return { ...n, ch: chOf(n), size: String(n.size), c: channel(config, chOf(n)) };
}

/// A deposited note, into Zyn: a proof bound to a fresh deposit code of this
/// wallet's, submitted by the relayer. Arrives as the channel's asset, the
/// note's size. Always a code of its own: one shared with a transparent
/// deposit would tie the private exit to that deposit's wallet (audit, 9 Oct 2026).
export async function toZyn(config, identity, commitment) {
  const note = own(config, identity, commitment);
  const code = await bridges.depositCode(config, identity, 'to-zyn');
  const m = await core();
  const { p } = await proveFor(config, identity, note.c, note, m.binding_to_zyn(code));
  const r = await ledger.call(config, 'zyn_poolRelay', { chain: note.c.chain, size: note.size, kind: 'to_zyn', proof: p.proof, root: p.root, nullifier_hash: p.nullifier_hash, code });
  mark(config, identity, commitment, 'to zyn', { signature: r.signature });
  return r;
}

/// A private exit's destination, as the bridges read it
/// (`sol_bridge::as_pool_destination`): "zyn-pool" ‖ size (u64 LE) ‖ commitment.
export function destination(size, commitment) {
  const address = new Uint8Array(48);
  address.set(new TextEncoder().encode('zyn-pool'), 0);
  new DataView(address.buffer).setBigUint64(8, BigInt(size), true);
  address.set(unhex(commitment, 32), 16);
  return address;
}

/// One size in WAD, as Zyn holds every asset.
export const wadOf = (c, size) => BigInt(size) * pow10(18 - c.decimals);

/// Out privately: burn one size on Zyn with a fresh note as the destination;
/// the bridge puts the note into the pool.
export async function withdraw(config, identity, held, c, size, bps) {
  const v = sizeOf(c, size);
  const note = await newNote(config, identity, c, v, 'out');
  await bridges.bridgeOutTo(config, identity, held, { asset: c.asset }, destination(v, note.commitment), wadOf(c, v), bps);
  mark(config, identity, note.commitment, 'burned');
  return note;
}

/// The address bytes of `to` on `c`'s chain, or a refusal.
export function recipientOf(c, to) {
  const t = String(to || '').trim();
  if (c.address === 'evm') {
    if (!/^0x[0-9a-fA-F]{40}$/.test(t)) throw new Error(`That is not a ${c.chainName} address`);
    return unhex(t.slice(2), 20);
  }
  let b;
  try { b = b58decode(t); } catch { b = new Uint8Array(0); }
  if (b.length !== 32) throw new Error('That is not a Solana address');
  return b;
}

/// An exit note, to any address on its chain, through the relayer (which
/// takes its fee from the note).
export async function sendOut(config, identity, commitment, to) {
  const note = own(config, identity, commitment);
  const c = note.c;
  const recipient = recipientOf(c, to);
  const i = await info(config, c);
  const relayer = c.address === 'evm' ? unhex(String(i.relayer).slice(2), 20) : b58decode(i.relayer);
  const m = await core();
  const binding = m.binding_to_address(hex(recipient), hex(relayer), BigInt(i.fee));
  const { p } = await proveFor(config, identity, c, note, binding);
  const r = await ledger.call(config, 'zyn_poolRelay', { chain: c.chain, size: note.size, kind: 'to_address', proof: p.proof, root: p.root, nullifier_hash: p.nullifier_hash, recipient: String(to).trim(), fee: String(i.fee) });
  mark(config, identity, commitment, 'sent', { signature: r.signature });
  return { ...r, fee: String(i.fee) };
}
