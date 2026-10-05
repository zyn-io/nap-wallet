// Reading an object ledger.
//
// The AMM chains answer `zyn_account` and hand a wallet its balance. An object
// ledger cannot: it holds commitments and nullifiers, and *nothing on it says
// who owns what*. That is the privacy property, and the cost is that the
// balance is something the holder computes rather than asks for.
//
// So: fetch every published note, try to open each one, keep the ones that
// open, and drop the ones whose nullifier has already appeared. What is left
// is what this account holds.
//
// Every constant here is a wire format shared with the Rust side. Change one
// and a restored wallet looks at the right chain and finds nothing — which is
// indistinguishable from having been robbed.

import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';

const te = new TextEncoder();

/// `hash_leaf` on the Rust side: SHA-256 over a domain-separating 0x00 byte
/// and the encoded body. The prefix is what keeps a leaf from colliding with
/// an interior node of the same bytes.
const LEAF_PREFIX = 0x00;

function leaf(...parts) {
  let n = 1;
  for (const p of parts) n += p.length;
  const buf = new Uint8Array(n);
  buf[0] = LEAF_PREFIX;
  let at = 1;
  for (const p of parts) { buf.set(p, at); at += p.length; }
  return sha256(buf);
}

/// Derivations, pinned to `zynzapd/src/object_keys.rs`.
const VIEWING_SALT = 'nap.zyn.viewing.v1';
const VIEWING_INFO = 'viewing';
const NULLIFIER_SALT = 'nap.zyn.nullifier.v1';
const NULLIFIER_INFO = 'nullifier';

function derive(seed, salt, info, account) {
  const labelled = new Uint8Array(info.length + 4);
  labelled.set(te.encode(info), 0);
  new DataView(labelled.buffer).setUint32(info.length, account, false);
  return hkdf(sha256, seed, te.encode(salt), labelled, 32);
}

/// The key that opens notes sent to this account. Never spends one.
export const viewingSecret = (seed, account = 0) =>
  derive(seed, VIEWING_SALT, VIEWING_INFO, account);

/// What to publish so others can pay this account.
export const viewingKey = (seed, account = 0) =>
  x25519.getPublicKey(viewingSecret(seed, account));

/// The key that recognises this account's own spends. Also never spends.
export const nullifierKey = (seed, account = 0) =>
  derive(seed, NULLIFIER_SALT, NULLIFIER_INFO, account);

/// `zyn.note.kdf.v1` — the symmetric key for one note.
const noteKey = (shared, epk) => leaf(te.encode('zyn.note.kdf.v1'), shared, epk);

/// A single fixed nonce is safe because the key never repeats: it comes from a
/// fresh ECDH against a per-note ephemeral key, so no two notes share one.
const NOTE_NONCE = te.encode('zyn.note.v1\0');

const PLAINTEXT_LEN = 128;

/// Open one published note, or return null.
///
/// Null covers both "not ours" and "damaged" deliberately, exactly as the Rust
/// side does: telling a scanner *why* a trial decryption failed tells an
/// attacker which notes are close.
export function openNote(secret, epk, ciphertext) {
  let padded;
  try {
    const shared = x25519.getSharedSecret(secret, epk);
    padded = chacha20poly1305(noteKey(shared, epk), NOTE_NONCE).decrypt(ciphertext);
  } catch {
    return null;
  }
  if (padded.length !== PLAINTEXT_LEN) return null;
  const len = new DataView(padded.buffer, padded.byteOffset).getUint32(0, false);
  if (len > PLAINTEXT_LEN - 4) return null;
  const body = padded.subarray(4, 4 + len);
  // asset(32) ‖ amount(i128 big-endian) ‖ nonce(32)
  if (body.length !== 80) return null;
  return {
    asset: body.subarray(0, 32),
    amount: readI128(body.subarray(32, 48)),
    nonce: body.subarray(48, 80),
  };
}

/// A signed 128-bit big-endian integer, as `BigInt`.
///
/// `BigInt` and not `Number`: amounts are in WAD units, so a balance of a few
/// ZEC already exceeds what a double represents exactly, and a wallet that
/// rounds someone's balance is a wallet that lies about it.
function readI128(b) {
  let v = 0n;
  for (const byte of b) v = (v << 8n) | BigInt(byte);
  // Two's complement.
  return v >= 1n << 127n ? v - (1n << 128n) : v;
}

/// Two's complement, refusing what does not fit: wrapping silently would sign
/// a different number from the one shown (the 25 Sep audit's H1).
function i128Bytes(v) {
  if (typeof v !== 'bigint' || v >= 1n << 127n || v < -(1n << 127n)) throw new Error('An amount is outside what the ledger can hold');
  let u = v < 0n ? (1n << 128n) + v : v;
  const out = new Uint8Array(16);
  for (let i = 15; i >= 0; i--) { out[i] = Number(u & 0xffn); u >>= 8n; }
  return out;
}

/// `commitment(note)` — what the chain published for this note.
///
/// Recomputed rather than trusted: a mirror could hand back a ciphertext
/// paired with somebody else's commitment, and a wallet that believed the
/// pairing would show a balance it cannot spend.
export function commitment(note, owner) {
  return leaf(
    te.encode('zyn.object.v1'),
    note.asset,
    i128Bytes(note.amount),
    owner,
    note.nonce,
  );
}

/// The nullifier that retires a commitment.
export const nullifierOf = (nkey, commit) =>
  leaf(te.encode('zyn.nullifier.v1'), nkey, commit);

const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/// What this account holds, from a `zyn_published` feed.
///
/// `published.outputs` is `{commitment, epk, ciphertext}` and
/// `published.nullifiers` is every nullifier the chain has seen. A note is
/// held when it opens, when the commitment it recomputes to is the one the
/// chain published, and when its nullifier has not appeared.
export function scan(published, { secret, nkey, owner }) {
  const spent = new Set(published.nullifiers || []);
  const held = [];
  const byAsset = new Map();

  for (const o of published.outputs || []) {
    const note = openNote(secret, unhex(o.epk), unhex(o.ciphertext));
    if (!note) continue;

    // The pairing is checked, not assumed.
    const commit = commitment(note, owner);
    if (hex(commit) !== o.commitment) continue;
    if (spent.has(hex(nullifierOf(nkey, commit)))) continue;

    const asset = hex(note.asset);
    held.push({ commitment: hex(commit), asset, amount: note.amount });
    byAsset.set(asset, (byAsset.get(asset) || 0n) + note.amount);
  }
  return { held, balances: byAsset };
}

export function unhex(s) {
  if (typeof s !== 'string' || s.length % 2) return new Uint8Array(0);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export { hex };

// ---------------------------------------------------------------------------
// Writing to it.
// ---------------------------------------------------------------------------

/// Program ids, pinned to `zyn-vm/src/program.rs`.
///
/// A wire constant: an intent naming a program the VM does not know is an
/// intent it will not run, and one naming the *wrong* known program is worse —
/// it runs a rule the holder did not intend.
export const PROGRAM = {
  registerViewingKey: 'e08ada46a2a9adb8d9cbfc45316173f8a5e0edf6ec035252b19fd8b6600a5386',
};

/// Intent tags, pinned to `ObjectVm::encode_intent`.
const TAG_REGISTER = 8;

function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/// `Op::Register` as the node's `zyn_submit` expects it.
///
/// Publishing where to be paid. Re-registering replaces the key, because a
/// holder who loses one needs a way to be paid again — and the old key could
/// never spend anything, it only ever found notes. What it costs is that
/// anyone able to submit as this account can redirect *future*
/// discoverability, not any note that already exists.
export function registerIntent(account, viewing) {
  return concatBytes(
    new Uint8Array([TAG_REGISTER]),
    account,
    unhex(PROGRAM.registerViewingKey),
    viewing,
  );
}

// ---------------------------------------------------------------------------
// Signing. The node applies a holder's intent only inside a frame their own
// key signed; `zyn_submit` is the operator's door and is closed to everyone
// else. The layouts are pinned to `zyn-vm/src/{auth,verify}.rs` and held to
// Rust-produced bytes by the shared fixture.
// ---------------------------------------------------------------------------

import * as ed from '@noble/ed25519';

const AUTH_DOMAIN = te.encode('zyn.auth.v1');
const ACCOUNT_DOMAIN = te.encode('zyn.account.v1');
const FRAME_MAGIC = te.encode('ZYNAUTH1');
const FRAME_SIGNED = 1;
const SCHEME_ED25519 = 1;

function u64be(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false);
  return b;
}

/// Which program a signature is bound to: `H("zyn.vm.v1" ‖ name ‖ u16 version)`.
/// A signature does not travel between applications, nor across a version
/// bump that changed what an intent means.
export const vmId = (name = 'objectvm', version = 1) => {
  const v = new Uint8Array(2);
  new DataView(v.buffer).setUint16(0, version, false);
  return leaf(te.encode('zyn.vm.v1'), te.encode(name), v);
};

/// The account a key controls: `sha256("zyn.account.v1" ‖ scheme ‖ len ‖ key)`.
export const accountOf = (publicKey) =>
  sha256(concatBytes(ACCOUNT_DOMAIN, new Uint8Array([SCHEME_ED25519]), u32be(publicKey.length), publicKey));

/// Exactly what the key signs: the envelope and the intent together, so a
/// signature cannot be lifted onto another chain, another program, or past
/// its expiry.
export function signingPayload(chain, validUntilEpoch, intentBytes) {
  return concatBytes(
    AUTH_DOMAIN,
    new Uint8Array([SCHEME_ED25519]),
    u32be(chain),
    vmId(),
    u64be(validUntilEpoch),
    u32be(intentBytes.length),
    intentBytes,
  );
}

/// A frame `zyn_submitSigned` accepts: the envelope, one Ed25519 credential,
/// and the intent. Ed25519 is deterministic, so the same key and intent give
/// the same frame — which is also what makes a resubmission recognisable as a
/// replay rather than a second payment.
export async function signedFrame(secretKey, chain, validUntilEpoch, intentBytes) {
  const publicKey = await ed.getPublicKeyAsync(secretKey);
  const signature = await ed.signAsync(signingPayload(chain, validUntilEpoch, intentBytes), secretKey);
  return concatBytes(
    FRAME_MAGIC,
    new Uint8Array([FRAME_SIGNED]),
    u32be(chain),
    vmId(),
    u64be(validUntilEpoch),
    new Uint8Array([1, SCHEME_ED25519]),
    publicKey,
    signature,
    u32be(intentBytes.length),
    intentBytes,
  );
}

/// POST one JSON-RPC payload, waiting out the gateway's rate limit.
///
/// A 429 or 503 is the gateway turning the request away before the chain sees
/// it, so it is sent again after a short, growing, jittered wait — even a
/// submission: what was refused never arrived. Opening a wallet reads some
/// eighty things at once; without this, the first refusal was shown to the
/// holder as "The chain answered HTTP 503" and the page stopped.
///
/// The body is JSON sent as text/plain: a "simple" request, so a page on
/// another origin sends no CORS preflight — one request per call, not two,
/// and no preflight for the rate limit to refuse, which the browser reports
/// only as "Failed to fetch". A read that fails that way is sent again; a
/// write is not, since it may have arrived.
const BUSY = new Set([429, 503]);
const WRITES = /submit|put|delete|mint|relay|reveal/i;
export async function rpcPost(url, payload, { timeout = 15000, attempts = 6 } = {}) {
  for (let attempt = 1; ; attempt++) {
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify(payload),
        cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer',
        signal: AbortSignal.timeout(timeout),
      });
    } catch (e) {
      if (e?.name !== 'TypeError' || WRITES.test(String(payload?.method || '')) || attempt >= attempts) throw e;
      await new Promise((resolve) => setTimeout(resolve, Math.min(4000, 250 * 2 ** (attempt - 1)) * (0.5 + Math.random())));
      continue;
    }
    if (!BUSY.has(response.status) || attempt >= attempts) return response;
    const after = Number(response.headers.get('retry-after'));
    const wait = after > 0 ? after * 1000 : Math.min(4000, 250 * 2 ** (attempt - 1)) * (0.5 + Math.random());
    await new Promise((resolve) => setTimeout(resolve, wait));
  }
}

/// Submit a signed frame through the holders' door.
export async function submitSigned(rpcUrl, frame) {
  const response = await rpcPost(rpcUrl, { jsonrpc: '2.0', id: 1, method: 'zyn_submitSigned', frame: hex(frame) });
  if (!response.ok) throw new Error(`The chain answered HTTP ${response.status}`);
  const body = await response.json();
  if (body.error) throw new Error(body.error.message || 'the chain refused the intent');
  return body.result;
}

/// Seal a note to a recipient's viewing key.
///
/// `ephemeral` must be fresh for every note. Reusing one links the notes and,
/// worse, reuses the key the fixed nonce's safety rests on.
export function sealNote(toViewingKey, ephemeralSecret, note) {
  const body = concatBytes(note.asset, i128Bytes(note.amount), note.nonce);
  if (body.length !== 80) throw new Error('a note is asset, amount and nonce');
  const padded = new Uint8Array(PLAINTEXT_LEN);
  new DataView(padded.buffer).setUint32(0, body.length, false);
  padded.set(body, 4);
  const shared = x25519.getSharedSecret(ephemeralSecret, toViewingKey);
  const epk = x25519.getPublicKey(ephemeralSecret);
  return {
    epk,
    ciphertext: chacha20poly1305(noteKey(shared, epk), NOTE_NONCE).encrypt(padded),
  };
}

const TAG_SPEND = 2;

function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

/// `Op::Spend` — retire these commitments, create these notes.
///
/// `inputs` is `{commitment, nullifier}` and `outputs` is `{note, enc}` as
/// `sealNote` returns. The VM checks that what goes in equals what comes out;
/// this only has to encode it the way the VM reads it.
export function spendIntent(spender, program, inputs, outputs) {
  const parts = [
    new Uint8Array([TAG_SPEND]),
    spender,
    unhex(program),
    u32be(inputs.length),
    u32be(outputs.length),
  ];
  for (const i of inputs) parts.push(i.commitment, i.nullifier);
  for (const o of outputs) {
    parts.push(
      o.note.asset,
      i128Bytes(o.note.amount),
      o.note.owner,
      o.note.nonce,
      o.enc.epk,
      u32be(o.enc.ciphertext.length),
      o.enc.ciphertext,
    );
  }
  return concatBytes(...parts);
}

PROGRAM.privateTransfer = '1bf1117563416d5aea4b85568432f26dd1c13418f440b0095592db5cc449fcae';

/// Shared with `market.js`, which encodes the market's intents in the same
/// wire format.
export { leaf, concatBytes, i128Bytes, u32be, u64be };

// ---------------------------------------------------------------------------
// Leaving: ZEC.zy back to Zcash.
// ---------------------------------------------------------------------------

/// `named("withdraw")`, derived the way `zyn-vm/src/program.rs` names rules.
PROGRAM.withdraw = hex(leaf(te.encode('zyn.program.named.v1'), u32be(8), te.encode('withdraw')));

const TAG_WITHDRAW = 7;

/// `Op::Withdraw` — retire these notes, record a payout the vault owes, and
/// take change back. `destination` is the 32-byte commitment to the Zcash
/// address and a salt only the holder knows, so the chain never carries
/// where anyone's money went.
export function withdrawIntent({ holder, inputs, asset, amount, destination, outputs }) {
  const parts = [
    new Uint8Array([TAG_WITHDRAW]),
    holder,
    unhex(PROGRAM.withdraw),
    asset,
    i128Bytes(amount),
    destination,
    u32be(inputs.length),
    u32be(outputs.length),
  ];
  for (const i of inputs) parts.push(i.commitment, i.nullifier);
  for (const o of outputs) {
    parts.push(o.note.asset, i128Bytes(o.note.amount), o.note.owner, o.note.nonce, o.enc.epk, u32be(o.enc.ciphertext.length), o.enc.ciphertext);
  }
  return concatBytes(...parts);
}

/// A JSON-RPC call with named fields, as the object node reads them, checked
/// to be the answer to this question.
export async function objectCall(rpcUrl, method, fields = {}) {
  const id = crypto.randomUUID();
  const response = await rpcPost(rpcUrl, { jsonrpc: '2.0', id, method, params: [], ...fields });
  if (!response.ok) throw new Error(`The chain answered HTTP ${response.status}`);
  const body = await response.json();
  if (body.id !== id) throw new Error('The chain answered a different question');
  if (body.error) throw new Error(body.error.message || 'The chain refused');
  return body.result;
}

/// A launchpad token's picture and description, as the creator attaches
/// them: canonical JSON (keys in this order), hashed. The content server
/// recomputes exactly this from what it is sent.
export function contentBytes({ description = '', image = '' }) {
  return new TextEncoder().encode(JSON.stringify({ description: String(description), image: String(image), v: 1 }));
}
export const contentHash = (content) => sha256(contentBytes(content));

/// Proof that the holder of `secretKey` created `token` with `nonce`
/// (token = tokenOf(accountOf(publicKey), nonce)) and attaches `hash` to it.
/// Reveals the creator to whoever keeps the content — the journal already
/// names them — and nothing else.
export async function contentProof(secretKey, nonce, token, hash) {
  const publicKey = await ed.getPublicKeyAsync(secretKey);
  const message = concatBytes(new TextEncoder().encode('cave.jade.content.v1'), token, hash);
  const signature = await ed.signAsync(message, secretKey);
  return { publicKey: hex(publicKey), nonce: hex(nonce), signature: hex(signature) };
}

/// The content server's check: `proof.publicKey` made `token` (it is
/// tokenOf(accountOf(key), nonce), the ledger's derivation) and signed
/// `hash` for it. Shared with the server so both sides derive it one way.
export async function verifyContentProof(token, hash, proof) {
  const te = new TextEncoder();
  const publicKey = unhex(proof.publicKey);
  const nonce = unhex(proof.nonce);
  const signature = unhex(proof.signature);
  if (publicKey.length !== 32 || nonce.length !== 32 || signature.length !== 64) return false;
  const made = leaf(te.encode('objectvm.token.v1'), accountOf(publicKey), nonce);
  if (hex(made) !== hex(token)) return false;
  const message = concatBytes(te.encode('cave.jade.content.v1'), token, hash);
  try { return await ed.verifyAsync(signature, message, publicKey); } catch { return false; }
}
