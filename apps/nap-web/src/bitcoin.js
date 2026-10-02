// BTC.zy's addresses (DECISIONS §154), derived here so Nap never has to take
// a deposit address on trust.
//
// The vault is a Taproot key held 2-of-3 by the custodians. A deposit under a
// Zyn deposit code goes to that key tweaked by the code (BIP-341, with the
// code's tagged hash standing where a script tree's root would): the address
// is the memo Bitcoin wallets cannot attach. zyn-custody's `deposit_address`
// is the other half of this and the vectors in tests/bitcoin.test.mjs pin both.

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';

const { taggedHash, lift_x } = schnorr.utils;
const Point = secp256k1.ProjectivePoint || secp256k1.Point;
const N = secp256k1.CURVE?.n ?? Point.CURVE().n;
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const bytesToNumber = (b) => BigInt(`0x${toHex(b) || '0'}`);
const numberTo32 = (n) => fromHex(n.toString(16).padStart(64, '0'));

/// The tweak root for a deposit code: tagged hash "Zyn/BtcDeposit".
export const depositRoot = (commitment) => taggedHash('Zyn/BtcDeposit', commitment);

/// BIP-341 output key of `internal` (32-byte x-only) with an optional root.
export function outputKey(internal, root) {
  const P = lift_x(bytesToNumber(internal));
  const t = bytesToNumber(root ? taggedHash('TapTweak', internal, root) : taggedHash('TapTweak', internal));
  if (t >= N) throw new Error('tweak out of range');
  const Q = P.add(Point.BASE.multiply(t));
  return numberTo32(Q.toAffine().x);
}

// ---- bech32 / bech32m (BIP-173, BIP-350) ----
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32M = 0x2bc830a3;
function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp) => [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
function convertBits(data, from, to, pad) {
  let acc = 0; let bits = 0; const out = []; const max = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & max); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & max); } else if (bits >= from || ((acc << (to - bits)) & max)) return null;
  return out;
}
function encode(hrp, version, program) {
  const data = [version, ...convertBits(program, 8, 5, true)];
  const constant = version === 0 ? 1 : BECH32M;
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ constant;
  const check = Array.from({ length: 6 }, (_, i) => (mod >> (5 * (5 - i))) & 31);
  return `${hrp}1${[...data, ...check].map((d) => CHARSET[d]).join('')}`;
}
function decode(address, hrp) {
  const s = address.trim();
  if (s !== s.toLowerCase() && s !== s.toUpperCase()) return null;
  const low = s.toLowerCase();
  const pos = low.lastIndexOf('1');
  if (pos < 1 || pos + 7 > low.length || low.length > 90 || low.slice(0, pos) !== hrp) return null;
  const data = [...low.slice(pos + 1)].map((c) => CHARSET.indexOf(c));
  if (data.includes(-1)) return null;
  const mod = polymod([...hrpExpand(hrp), ...data]);
  const version = data[0];
  if (mod !== (version === 0 ? 1 : BECH32M)) return null;
  const program = convertBits(data.slice(1, -6), 5, 8, false);
  if (!program || program.length < 2 || program.length > 40 || version > 16) return null;
  if (version === 0 && program.length !== 20 && program.length !== 32) return null;
  return { version, program: Uint8Array.from(program) };
}

/// The human-readable prefix for a network: signet and testnet share "tb".
export const hrpOf = (network) => (network === 'bitcoin' ? 'bc' : 'tb');

/// The address a deposit under `commitment` goes to.
export function depositAddress(internalHex, commitment, network = 'signet') {
  return encode(hrpOf(network), 1, outputKey(fromHex(internalHex), depositRoot(commitment)));
}

/// The vault's own key-path address (change and fee buffer).
export function vaultAddress(internalHex, network = 'signet') {
  return encode(hrpOf(network), 1, outputKey(fromHex(internalHex), null));
}

/// The output script a segwit address pays (v0 P2WPKH/P2WSH, v1 Taproot…),
/// or null for anything else — legacy addresses are not accepted here.
export function scriptOf(address, network = 'signet') {
  const d = decode(address, hrpOf(network));
  if (!d) return null;
  const op = d.version === 0 ? 0 : 0x50 + d.version;
  return Uint8Array.from([op, d.program.length, ...d.program]);
}
