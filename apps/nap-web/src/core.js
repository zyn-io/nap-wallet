import * as ed from '@noble/ed25519';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import {
  nullifierKey as objectNullifierKey,
  viewingSecret as objectViewingSecret,
} from './object.js';
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
  // The object ledger's two keys, derived here because this is the only place
  // the BIP39 seed exists. It is zeroed on the next line, and `identityFromSecretKey`
  // -- the path a stored wallet takes -- never has it at all, so a wallet that
  // derived these lazily would work from the phrase and silently report an
  // empty balance from a kept device. They travel in the sealed blob instead.
  //
  // Neither can spend. The viewing key finds notes, the nullifier key
  // recognises spends, and the identity key is derived from the same seed by a
  // different salt so holding either of these does not yield it.
  const viewing = objectViewingSecret(bip39Seed, index);
  const nullifier = objectNullifierKey(bip39Seed, index);
  bip39Seed.fill(0);
  return {
    secretKey,
    publicKey,
    account,
    accountHex: hex(account),
    accountIndex: index,
    viewing,
    nullifier,
  };
}

/// Rebuild an identity from the derived key alone.
///
/// Everything an identity does needs only the 32-byte Ed25519 secret — the
/// public key and the account are functions of it. That is what makes it safe
/// to keep a wallet on a device without keeping the *phrase* on it: what is
/// stored controls this one Zyn account, and not the Zcash wallet the same
/// words also control, and not any other account index.
export function identityFromSecretKey(secretKey, accountIndex = 0) {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 32) throw new Error('A stored key must be 32 bytes');
  const publicKey = ed.getPublicKey(secretKey);
  const account = sha256(concat(te.encode('zyn.account.v1'), u8(1), u32(publicKey.length), publicKey));
  return { secretKey, publicKey, account, accountHex: hex(account), accountIndex: Number(accountIndex) || 0 };
}

/// PBKDF2-SHA256 at OWASP's current floor. The whole security of a kept wallet
/// is this number and the password: once ciphertext is on a disk, an attacker
/// who takes it can guess offline for as long as they like.
export const KEEP = Object.freeze({ version: 2, iterations: 600_000, algorithm: 'PBKDF2-SHA256/AES-256-GCM' });

async function keyFrom(password, salt) {
  const material = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: KEEP.iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/// The derived keys as plain hex, the one shape both a sealed record and an
/// unlocked extension session (session.js) hold.
export function exportKeys(identity, receiving) {
  return {
    i: hex(identity.secretKey),
    r: (receiving || []).map((r) => ({ c: hex(r.collection), k: hex(r.secretKey) })),
    // The object-ledger keys, which cannot be recovered from `i`: they come
    // from the BIP39 seed by their own salts, and this blob is the only place
    // a device that does not hold the phrase can find them.
    ov: identity.viewing ? hex(identity.viewing) : undefined,
    on: identity.nullifier ? hex(identity.nullifier) : undefined,
    // The Zcash spending keys, one per network (ZIP-32, the desktop's path).
    // Also underivable without the phrase, and they control real ZEC: a
    // cracked record costs these too, which is why sealing is opt-in.
    zm: identity.zec?.mainnet ? hex(identity.zec.mainnet) : undefined,
    zt: identity.zec?.testnet ? hex(identity.zec.testnet) : undefined,
    // The transparent keys (BIP-44 m/44'/coin'/account'/0/0), for receiving
    // from exchanges and shielding. Absent from records sealed before Nap
    // had them; the wallet then asks for the phrase once to add them.
    tm: identity.zec?.transparent?.mainnet ? hex(identity.zec.transparent.mainnet) : undefined,
    tt: identity.zec?.transparent?.testnet ? hex(identity.zec.transparent.testnet) : undefined,
  };
}

/// Seal the derived keys under a password. The phrase is never an input.
///
/// Both the identity key and one key per collection receiving account, because
/// a bought item lands in the latter and the seed that derives them is not
/// kept. A cracked record therefore costs these accounts — not the phrase, and
/// not the Zcash wallet the same words also control.
export async function sealWallet(identity, receiving, password, accountIndex = 0) {
  if (typeof password !== 'string' || password.length < 8) throw new Error('Use at least 8 characters');
  const bundle = te.encode(JSON.stringify(exportKeys(identity, receiving)));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await keyFrom(password, salt);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bundle));
  return {
    v: KEEP.version,
    kdf: KEEP.algorithm,
    iterations: KEEP.iterations,
    accountIndex: Number(accountIndex) || 0,
    salt: hex(salt),
    iv: hex(iv),
    key: hex(sealed),
  };
}

/// Open a sealed wallet. A wrong password is indistinguishable from a damaged
/// record on purpose — AES-GCM fails authentication either way, and saying
/// which would tell someone holding a stolen file that they are close.
export async function openSealedWallet(blob, password) {
  if (!blob) throw new Error('No wallet is saved in this browser. Restore it from your recovery phrase.');
  if (blob.v !== KEEP.version) throw new Error(`This wallet was saved by ${Number(blob.v) > KEEP.version ? 'a newer' : 'an older'} Nap and cannot be opened here. Restore it from your recovery phrase.`);
  const iterations = Number(blob.iterations);
  if (!Number.isSafeInteger(iterations) || iterations < 100_000) throw new Error('Stored wallet uses too weak a key derivation');
  const salt = unhex(blob.salt, 16);
  const iv = unhex(blob.iv, 12);
  const sealed = unhex(blob.key, (blob.key.length / 2) | 0);
  const key = await keyFrom(password, salt);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, sealed));
  } catch {
    throw new Error('That password does not open this wallet');
  }
  return importKeys(JSON.parse(new TextDecoder().decode(plain)), blob.accountIndex);
}

/// Keys from `exportKeys` back into an identity and its receiving accounts.
export function importKeys(bundle, accountIndex = 0) {
  const identity = identityFromSecretKey(unhex(bundle.i, 32), accountIndex);
  // Carried forward when the blob has them. A wallet sealed before the object
  // ledger existed does not, and reads as holding nothing there rather than
  // failing to open -- which is the right way round: the Zyn account it does
  // control still works.
  if (bundle.ov) identity.viewing = unhex(bundle.ov, 32);
  if (bundle.on) identity.nullifier = unhex(bundle.on, 32);
  // Likewise the Zcash keys: a record sealed before the browser held ZEC
  // opens without them, and the wallet asks for the phrase once to add them.
  if (bundle.zm && bundle.zt) identity.zec = { mainnet: unhex(bundle.zm, 32), testnet: unhex(bundle.zt, 32) };
  if (identity.zec && bundle.tm && bundle.tt) identity.zec.transparent = { mainnet: unhex(bundle.tm, 32), testnet: unhex(bundle.tt, 32) };
  const receiving = (bundle.r || []).map((r) => ({
    ...identityFromSecretKey(unhex(r.k, 32), accountIndex),
    collection: unhex(r.c, 32),
  }));
  return { identity, receiving };
}

/// Receiving accounts: where an item bought through a store actually lands.
///
/// A checkout quotes against the *collection's* receiving account rather than
/// the identity, so the payment and the item end up in an account with no other
/// history and nothing has to be moved afterwards — and a move is exactly what
/// would write the link back in (§97.5). The consequence for a wallet is that
/// looking only at the identity shows an empty pocket to somebody who has just
/// bought something.
///
/// Must match `zynzapd::receive::collection_key` byte for byte. A test on each
/// side pins both against the same phrase; if they drift, this wallet looks in
/// the wrong place and the item appears lost.
export const RECEIVE = Object.freeze({ salt: 'nap.zyn.receive.v1', info: 'collection' });

export function deriveCollectionAccount(words, passphrase = '', accountIndex = 0, collection) {
  const mnemonic = assertMnemonic(words);
  const index = Number(accountIndex);
  if (!Number.isSafeInteger(index) || index < 0 || index >= 0x80000000) throw new Error('Account index must be between 0 and 2³¹−1');
  if (!(collection instanceof Uint8Array) || collection.length !== 32) throw new Error('A collection id is 32 bytes');
  const bip39Seed = mnemonicToSeedSync(mnemonic, passphrase);
  // info = "collection" || u32_be(account) || collection[32] — a distinct
  // prefix from the indexed form, so a collection id can never be mistaken for
  // an index.
  const info = concat(te.encode(RECEIVE.info), u32(index), collection);
  const secretKey = hkdf(sha256, bip39Seed, te.encode(RECEIVE.salt), info, 32);
  const publicKey = ed.getPublicKey(secretKey);
  const account = sha256(concat(te.encode('zyn.account.v1'), u8(1), u32(publicKey.length), publicKey));
  bip39Seed.fill(0);
  return { secretKey, publicKey, account, accountHex: hex(account), accountIndex: index, collection };
}

export function readChallenge(chain, account, epoch) {
  return concat(te.encode('zyn.read.v1'), u32(chain), account, u64(epoch));
}
export function signedRead(identity, chain, epoch) {
  const signature = ed.sign(readChallenge(chain, identity.account, epoch), identity.secretKey);
  return concat(identity.account, u64(epoch), u8(1), identity.publicKey, signature);
}

export function vmId() {
  return sha256(concat(u8(0), te.encode('zyn.vm.v1'), te.encode('zynzap'), u16(4)));
}
/// Trim a chain amount to something a person reads.
///
/// The RPC sends a decimal string like `0.100000000000000000`. This drops
/// trailing zeros and never touches the value — display only, and deliberately
/// not a parser: anything that decides something re-reads the raw string.
export function readableAmount(value) {
  const s = String(value);
  if (!/^\d+(\.\d+)?$/.test(s)) return s;
  if (!s.includes('.')) return s;
  const trimmed = s.replace(/0+$/, '').replace(/\.$/, '');
  return trimmed === '' ? '0' : trimmed;
}

/// The largest amount the ledger can represent (signed 128-bit), exclusive.
export const MAX_AMOUNT = 1n << 127n;

export function parseAmount(value) {
  const s = String(value).trim();
  if (!/^(0|[1-9]\d*)(\.\d{1,18})?$/.test(s)) throw new Error('Use a positive decimal with at most 18 decimal places');
  const [whole, fraction = ''] = s.split('.');
  const raw = BigInt(whole) * WAD + BigInt(fraction.padEnd(18, '0') || '0');
  if (raw <= 0n) throw new Error('Amount must be greater than zero');
  // The ledger's amounts are signed 128-bit; anything larger would be encoded
  // as something else entirely (a price shown as huge, signed as dust).
  if (raw >= MAX_AMOUNT) throw new Error('That amount is larger than any the ledger can hold');
  return raw;
}
/// ZEC.zy, the asset a Zyn price is quoted in.
///
/// A protocol constant rather than a deployment setting: it is the same id on
/// every Zyn chain, so putting it in `config.json` would invite a deployment to
/// declare a different one and quote prices in something else.
export const XZEC = unhex('0e212262cb35bf6e88bc7d0a52b60a5cc70c2859b65966a2557229d2ea469201', 32);

export function transferIntent(from, to, asset, rawAmount) {
  const id = typeof asset === 'string' ? unhex(asset, 32) : asset;
  if (!(id instanceof Uint8Array) || id.length !== 32) throw new Error('Asset ID must be 64 hex characters');
  return concat(u8(2), from, to, id, i128(rawAmount));
}
export function transferFrame(identity, chain, epoch, to, asset, rawAmount) {
  return signedFrame(identity, chain, epoch, transferIntent(identity.account, to, asset, rawAmount));
}

/// The order book intents, encoded exactly as `swapvm::wire` decodes them.
///
/// Tags 35, 36 and 37, with the field order taken from the decoder rather than
/// from the struct definition — a signature commits to these bytes, so a field
/// out of order is a signature over something the chain will read differently.
const OFFER_TAGS = Object.freeze({ place: 35, take: 36, cancel: 37 });

export function placeOfferIntent(maker, offerAsset, offerRaw, wantAsset, wantRaw, expiresAtEpoch) {
  const offerId = typeof offerAsset === 'string' ? unhex(offerAsset, 32) : offerAsset;
  const wantId = typeof wantAsset === 'string' ? unhex(wantAsset, 32) : wantAsset;
  if (!(offerId instanceof Uint8Array) || offerId.length !== 32) throw new Error('Asset ID must be 64 hex characters');
  if (!(wantId instanceof Uint8Array) || wantId.length !== 32) throw new Error('Asset ID must be 64 hex characters');
  return concat(u8(OFFER_TAGS.place), maker, offerId, i128(offerRaw), wantId, i128(wantRaw), u64(expiresAtEpoch));
}

export function takeOfferIntent(taker, offer) {
  return concat(u8(OFFER_TAGS.take), taker, u64(offer));
}

export function cancelOfferIntent(maker, offer) {
  return concat(u8(OFFER_TAGS.cancel), maker, u64(offer));
}

/// Wrap any intent in the authorisation the node expects, signed by `identity`.
///
/// Extracted from `transferFrame` so an offer cannot drift from a transfer in
/// how it is authorised — the envelope is the part a node checks before it
/// looks at what the intent says.
export function signedFrame(identity, chain, epoch, intent) {
  const program = vmId();
  const validUntil = BigInt(epoch) + 100n;
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
  identity?.zec?.mainnet?.fill(0);
  identity?.zec?.testnet?.fill(0);
  identity?.zec?.transparent?.mainnet?.fill(0);
  identity?.zec?.transparent?.testnet?.fill(0);
}
