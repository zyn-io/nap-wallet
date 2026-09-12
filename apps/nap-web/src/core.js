import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

ed.hashes.sha512 = sha512;

const te = new TextEncoder();
export const WAD = 1_000_000_000_000_000_000n;
export const DERIVATION = Object.freeze({ version: 1, salt: 'nap.zyn.ed25519.v1', info: 'account', networkScoped: false });

export const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};
export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
export const unhex = (value, length) => {
  const s = value.trim().replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(s) || s.length !== length * 2) throw new Error(`Expected ${length * 2} hex characters`);
  return Uint8Array.from(s.match(/../g) || [], (b) => parseInt(b, 16));
};
export const u8 = (n) => Uint8Array.of(Number(n));
export const u16 = (n) => integerBytes(BigInt(n), 2);
export const u32 = (n) => integerBytes(BigInt(n), 4);
export const u64 = (n) => integerBytes(BigInt(n), 8);
export const i128 = (n) => {
  const v = BigInt(n);
  if (v < -(1n << 127n) || v >= (1n << 127n)) throw new Error('Amount is outside signed 128-bit range');
  return integerBytes(v < 0 ? (1n << 128n) + v : v, 16);
};
function integerBytes(n, width) {
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
  if (n !== 0n) throw new Error('Integer is too large');
  return out;
}

export function newMnemonic() { return generateMnemonic(wordlist, 256); }
export function normalizeMnemonic(words) { return words.trim().toLowerCase().split(/\s+/).join(' '); }
export function assertMnemonic(words) {
  const normalized = normalizeMnemonic(words);
  if (!validateMnemonic(normalized, wordlist)) throw new Error('Enter a valid English BIP-39 recovery phrase');
  return normalized;
}

export function deriveIdentity(words, passphrase = '', accountIndex = 0) {
  const mnemonic = assertMnemonic(words);
  const index = Number(accountIndex);
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) throw new Error('Account index must be between 0 and 2³¹−1');
  const bip39Seed = mnemonicToSeedSync(mnemonic, passphrase);
  const secretKey = hkdf(sha256, bip39Seed, te.encode(DERIVATION.salt), concat(te.encode(DERIVATION.info), u32(index)), 32);
  const publicKey = ed.getPublicKey(secretKey);
  const account = sha256(concat(te.encode('zyn.account.v1'), u8(1), u32(publicKey.length), publicKey));
  bip39Seed.fill(0);
  return { secretKey, publicKey, account, accountHex: hex(account), accountIndex: index };
}

export function readChallenge(chain, account, epoch) {
  return concat(te.encode('zyn.read.v1'), u32(chain), account, u64(epoch));
}
export function signedRead(identity, chain, epoch) {
  const signature = ed.sign(readChallenge(chain, identity.account, epoch), identity.secretKey);
  return concat(identity.account, u64(epoch), u8(1), identity.publicKey, signature);
}

export function vmId() {
  return sha256(concat(u8(0), te.encode('zyn.vm.v1'), te.encode('zynzap'), u16(2)));
}
export function parseAmount(value) {
  const s = String(value).trim();
  if (!/^(0|[1-9]\d*)(\.\d{1,18})?$/.test(s)) throw new Error('Use a positive decimal with at most 18 decimal places');
  const [whole, fraction = ''] = s.split('.');
  const raw = BigInt(whole) * WAD + BigInt(fraction.padEnd(18, '0') || '0');
  if (raw <= 0n) throw new Error('Amount must be greater than zero');
  return raw;
}
export function transferIntent(from, to, asset, rawAmount) {
  return concat(u8(2), from, to, u32(asset), i128(rawAmount));
}
export function transferFrame(identity, chain, epoch, to, asset, rawAmount) {
  const program = vmId();
  const validUntil = BigInt(epoch) + 100n;
  const intent = transferIntent(identity.account, to, asset, rawAmount);
  const payload = concat(te.encode('zyn.auth.v1'), u8(1), u32(chain), program, u64(validUntil), u32(intent.length), intent);
  const signature = ed.sign(payload, identity.secretKey);
  return concat(program, u64(validUntil), u8(1), identity.publicKey, signature, intent);
}

export async function rpc(url, method, params = []) {
  const id = crypto.randomUUID();
  const response = await fetch(url, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
    cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw new Error(`RPC returned HTTP ${response.status}`);
  const body = await response.json();
  if (body.jsonrpc !== '2.0' || body.id !== id) throw new Error('Mismatched RPC response');
  if (body.error) throw new Error(body.error.message || 'RPC rejected the request');
  return body.result;
}

export function checkedEpoch(status, chain) {
  if (status.chain !== chain) throw new Error(`Wrong chain: expected ${chain}, received ${status.chain}`);
  if (typeof status.epoch === 'number' && !Number.isSafeInteger(status.epoch)) throw new Error('Unsafe RPC epoch');
  if (!/^(0|[1-9]\d*)$/.test(String(status.epoch))) throw new Error('Invalid RPC epoch');
  const epoch = BigInt(status.epoch);
  u64(epoch + 100n);
  return epoch;
}

export function forgetIdentity(identity) {
  identity?.secretKey?.fill(0);
}
