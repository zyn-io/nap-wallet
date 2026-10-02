// The browser's half of the object-ledger note format.
//
// The Rust side opens these notes too, and nothing makes the two agree except
// that they were written from the same spec. The failure if they drift is
// silent: a wallet looks at the right chain, opens nothing, and reports zero —
// which is indistinguishable from having been robbed. So both sides check the
// same committed fixture, and neither can move alone.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  commitment,
  hex,
  nullifierKey,
  nullifierOf,
  openNote,
  scan,
  unhex,
  viewingKey,
  viewingSecret,
} from '../src/object.js';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, 'object-vectors.json'), 'utf8'));
const seed = new TextEncoder().encode(v.seed_utf8);

/// The salts are a wire format. An account registered on chain is bound to the
/// viewing key this produces; change a salt and every restored wallet looks at
/// the wrong ciphertexts and finds nothing.
test('the key derivations match the Rust side', () => {
  assert.equal(hex(viewingKey(seed, v.account)), v.viewing_key);
  assert.equal(hex(nullifierKey(seed, v.account)), v.nullifier_key);
});

/// The whole point: a note sealed by Rust opens in the browser.
test('a note sealed by the Rust side opens here', () => {
  const note = openNote(viewingSecret(seed, v.account), unhex(v.epk), unhex(v.ciphertext));
  assert.ok(note, 'the note must open');
  assert.equal(hex(note.asset), v.note.asset);
  assert.equal(note.amount, BigInt(v.note.amount));
  assert.equal(hex(note.nonce), v.note.nonce);
});

/// Amounts are WAD units, so a few ZEC already exceeds what a double holds
/// exactly. A wallet that rounds a balance is a wallet that lies about it.
test('the amount survives as an exact integer', () => {
  const note = openNote(viewingSecret(seed, v.account), unhex(v.epk), unhex(v.ciphertext));
  assert.equal(typeof note.amount, 'bigint');
  assert.equal(note.amount.toString(), v.note.amount);
  // And this is why it is a BigInt: at this magnitude a double cannot even
  // tell the value from the next one up, so a wallet holding the balance as a
  // Number would be unable to represent the difference a single unit makes.
  assert.equal(
    Number(note.amount),
    Number(note.amount) + 1,
    'a double cannot separate these, which is the reason for BigInt'
  );
});

test('the commitment and nullifier match the Rust side', () => {
  const note = openNote(viewingSecret(seed, v.account), unhex(v.epk), unhex(v.ciphertext));
  const c = commitment(note, unhex(v.owner));
  assert.equal(hex(c), v.commitment);
  assert.equal(hex(nullifierOf(nullifierKey(seed, v.account), c)), v.nullifier);
});

/// Not ours and damaged are one case, exactly as in Rust: telling a scanner
/// *why* a trial decryption failed tells an attacker which notes are close.
test('a note for somebody else does not open, and neither does rubbish', () => {
  const other = viewingSecret(new TextEncoder().encode('a different seed'), 0);
  assert.equal(openNote(other, unhex(v.epk), unhex(v.ciphertext)), null);

  const secret = viewingSecret(seed, v.account);
  const damaged = unhex(v.ciphertext);
  damaged[0] ^= 0xff;
  assert.equal(openNote(secret, unhex(v.epk), damaged), null);
  assert.equal(openNote(secret, new Uint8Array(32), unhex(v.ciphertext)), null);
  assert.equal(openNote(secret, unhex(v.epk), new Uint8Array(0)), null);
});

/// A mirror is not trusted. It could hand back a real ciphertext paired with
/// somebody else's commitment, and a wallet that believed the pairing would
/// show a balance it cannot spend.
test('a note paired with the wrong commitment is not counted', () => {
  const feed = {
    outputs: [{ commitment: 'ff'.repeat(32), epk: v.epk, ciphertext: v.ciphertext }],
    nullifiers: [],
  };
  const held = scan(feed, {
    secret: viewingSecret(seed, v.account),
    nkey: nullifierKey(seed, v.account),
    owner: unhex(v.owner),
  });
  assert.equal(held.held.length, 0, 'the pairing must be checked, not assumed');
});

/// A spent note is gone. Without this the wallet shows money it cannot move.
test('a note whose nullifier has appeared is not held', () => {
  const args = {
    secret: viewingSecret(seed, v.account),
    nkey: nullifierKey(seed, v.account),
    owner: unhex(v.owner),
  };
  const outputs = [{ commitment: v.commitment, epk: v.epk, ciphertext: v.ciphertext }];

  const unspent = scan({ outputs, nullifiers: [] }, args);
  assert.equal(unspent.held.length, 1);
  assert.equal(unspent.balances.get(v.note.asset), BigInt(v.note.amount));

  const spent = scan({ outputs, nullifiers: [v.nullifier] }, args);
  assert.equal(spent.held.length, 0, 'a spent note must not still be held');
});

/// An empty or malformed feed is a balance of nothing, not a crash.
test('a missing or empty feed reads as nothing held', () => {
  const args = {
    secret: viewingSecret(seed, v.account),
    nkey: nullifierKey(seed, v.account),
    owner: unhex(v.owner),
  };
  for (const feed of [{}, { outputs: [] }, { outputs: [], nullifiers: [] }]) {
    assert.equal(scan(feed, args).held.length, 0);
  }
});

// ---------------------------------------------------------------------------
// Recovery: the keys have to survive being stored.
// ---------------------------------------------------------------------------

import { deriveIdentity, openSealedWallet, sealWallet } from '../src/core.js';

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/// The failure this guards is silent: a wallet kept on a device would open,
/// control its Zyn account, and report an empty object-ledger balance --
/// indistinguishable from having been robbed. The keys come from the BIP39
/// seed, which is zeroed after derivation and never present on the stored
/// path, so they must travel in the sealed blob.
test('the object keys survive sealing and unsealing', async () => {
  const id = deriveIdentity(PHRASE, '', 0);
  assert.ok(id.viewing, 'deriving a wallet produces a viewing key');
  assert.ok(id.nullifier, 'and a nullifier key');

  const blob = await sealWallet(id, [], 'a password long enough', 0);
  const { identity } = await openSealedWallet(blob, 'a password long enough');

  assert.equal(hex(identity.viewing), hex(id.viewing), 'the viewing key must come back');
  assert.equal(hex(identity.nullifier), hex(id.nullifier), 'and the nullifier key');
});

/// The same phrase must give the same keys every time, or a restore looks at
/// the wrong ciphertexts and finds nothing.
test('the same phrase derives the same object keys', () => {
  const a = deriveIdentity(PHRASE, '', 0);
  const b = deriveIdentity(PHRASE, '', 0);
  assert.equal(hex(a.viewing), hex(b.viewing));
  assert.equal(hex(a.nullifier), hex(b.nullifier));

  // And a different account index is a different wallet, so a payer
  // encrypting to one must not produce notes the other can open.
  const other = deriveIdentity(PHRASE, '', 1);
  assert.notEqual(hex(a.viewing), hex(other.viewing));
  assert.notEqual(hex(a.nullifier), hex(other.nullifier));
});

/// Holding a viewing key must not yield the key that spends.
test('the object keys are not the identity key', () => {
  const id = deriveIdentity(PHRASE, '', 0);
  assert.notEqual(hex(id.viewing), hex(id.secretKey));
  assert.notEqual(hex(id.nullifier), hex(id.secretKey));
  assert.notEqual(hex(id.viewing), hex(id.nullifier));
});

/// A wallet sealed before the object ledger existed must still open. It reads
/// as holding nothing there, which is right: the Zyn account it does control
/// keeps working.
test('a blob sealed without object keys still opens', async () => {
  const id = deriveIdentity(PHRASE, '', 0);
  const blob = await sealWallet(
    { secretKey: id.secretKey }, // no viewing/nullifier, as an older wallet had
    [],
    'a password long enough',
    0
  );
  const { identity } = await openSealedWallet(blob, 'a password long enough');
  assert.equal(hex(identity.secretKey), hex(id.secretKey));
  assert.equal(identity.viewing, undefined);
});

// ---------------------------------------------------------------------------
// Writing.
// ---------------------------------------------------------------------------

import { PROGRAM, registerIntent } from '../src/object.js';

/// A program id is a wire constant: naming one the VM does not know is an
/// intent it will not run, and naming the wrong *known* one runs a rule the
/// holder did not intend.
test('the program ids match the Rust side', () => {
  assert.equal(PROGRAM.registerViewingKey, v.programs.register_viewing_key);
});

/// The encoding is checked against bytes Rust produced, not against a
/// description of them.
test('a Register intent encodes to exactly the bytes Rust produces', () => {
  const bytes = registerIntent(unhex(v.owner), unhex(v.viewing_key));
  assert.equal(hex(bytes), v.register_intent);
  assert.equal(bytes[0], v.intent_tags.register, 'the tag leads');
  assert.equal(bytes.length, 1 + 32 + 32 + 32);
});

import { sealNote, spendIntent } from '../src/object.js';

/// A note sealed here must open on the Rust side, which is what makes a
/// payment from this wallet findable by its recipient.
test('a note sealed here has the shape Rust opens', () => {
  const recipientSecret = viewingSecret(new TextEncoder().encode('recipient seed'), 0);
  const recipient = viewingKey(new TextEncoder().encode('recipient seed'), 0);
  const note = {
    asset: unhex(v.note.asset),
    amount: 2000000000000000000n,
    owner: unhex(v.spend.out_owner),
    nonce: unhex(v.spend.out_nonce),
  };
  const enc = sealNote(recipient, new Uint8Array(32).fill(0x55), note);
  // It round-trips through our own opener, which is byte-compatible with the
  // Rust one by the vectors above.
  const back = openNote(recipientSecret, enc.epk, enc.ciphertext);
  assert.ok(back, 'the recipient must be able to open it');
  assert.equal(back.amount, note.amount);
  assert.equal(hex(back.nonce), hex(note.nonce));
  assert.equal(hex(back.asset), hex(note.asset));
});

/// The Spend encoding, checked against the bytes Rust produced.
test('a Spend intent encodes to exactly the bytes Rust produces', () => {
  const bytes = spendIntent(
    unhex(v.owner),
    v.programs.private_transfer,
    [{ commitment: unhex(v.commitment), nullifier: unhex(v.nullifier) }],
    [
      {
        note: {
          asset: unhex(v.note.asset),
          amount: BigInt(v.spend.out_amount),
          owner: unhex(v.spend.out_owner),
          nonce: unhex(v.spend.out_nonce),
        },
        enc: { epk: unhex(v.spend.out_epk), ciphertext: unhex(v.spend.out_ciphertext) },
      },
    ],
  );
  assert.equal(hex(bytes), v.spend.intent);
  assert.equal(bytes[0], v.intent_tags.spend, 'the tag leads');
});

// ---------------------------------------------------------------------------
// Signing: the frame the node's holders' door accepts.
// ---------------------------------------------------------------------------

import { accountOf, signedFrame, signingPayload, vmId } from '../src/object.js';
import * as ed25519 from '@noble/ed25519';

test('the program id a signature is bound to matches Rust', () => {
  assert.equal(hex(vmId()), v.signed.vm_id);
});

test('an ed25519 key controls the same account in both implementations', async () => {
  const pub = await ed25519.getPublicKeyAsync(unhex(v.signed.seed));
  assert.equal(hex(accountOf(pub)), v.signed.account);
});

/// What the key signs, byte for byte. A payload that differed by one byte is a
/// valid signature over something the node never checks.
test('the signing payload matches Rust', () => {
  const intent = registerIntent(unhex(v.signed.account), unhex(v.viewing_key));
  assert.equal(hex(signingPayload(v.signed.chain, v.signed.valid_until_epoch, intent)), v.signed.payload);
});

/// Ed25519 is deterministic, so the whole signed frame must come out identical.
test('a signed frame is byte-identical to the one Rust produces', async () => {
  const intent = registerIntent(unhex(v.signed.account), unhex(v.viewing_key));
  const frame = await signedFrame(unhex(v.signed.seed), v.signed.chain, v.signed.valid_until_epoch, intent);
  assert.equal(hex(frame), v.signed.frame);
});
