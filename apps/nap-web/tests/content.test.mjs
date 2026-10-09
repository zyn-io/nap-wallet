// A launchpad token's picture and description are attached by the creator
// alone: the proof ties a key to the token the ledger derives from it.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as ed from '@noble/ed25519';
import { accountOf, contentHash, contentProof, verifyContentProof } from '../src/object.js';
import { tokenOf } from '../src/market.js';

test('only the key that made a token can attach content to it', async () => {
  const sk = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(32).fill(9);
  const token = tokenOf(accountOf(await ed.getPublicKeyAsync(sk)), nonce);
  const hash = contentHash({ description: 'a stone', image: '' });
  const proof = await contentProof(sk, nonce, token, hash);
  assert.equal(await verifyContentProof(token, hash, proof), true);
  assert.equal(await verifyContentProof(tokenOf(accountOf(await ed.getPublicKeyAsync(sk)), new Uint8Array(32).fill(8)), hash, proof), false, 'another token');
  assert.equal(await verifyContentProof(token, contentHash({ description: 'swapped', image: '' }), proof), false, 'other content');
  const stranger = await contentProof(new Uint8Array(32).fill(1), nonce, token, hash);
  assert.equal(await verifyContentProof(token, hash, stranger), false, 'a stranger signing for it');
});

test('content hashes canonically, whatever order the fields arrive in', () => {
  const a = contentHash({ description: 'x', image: 'data:image/png;base64,AA==' });
  const b = contentHash({ image: 'data:image/png;base64,AA==', description: 'x' });
  assert.deepEqual(a, b);
});

test('a v2 proof names its chain and holds only there', async () => {
  const sk = new Uint8Array(32).fill(3);
  const nonce = new Uint8Array(32).fill(4);
  const token = tokenOf(accountOf(await ed.getPublicKeyAsync(sk)), nonce);
  const hash = contentHash({ description: 'a coin', image: '' });
  const proof = await contentProof(sk, nonce, token, hash, 26460);
  assert.equal(proof.v, 2);
  assert.equal(await verifyContentProof(token, hash, proof, 26460), true, 'on its chain');
  assert.equal(await verifyContentProof(token, hash, proof, 212), false, 'not replayed onto the other chain');
  assert.equal(await verifyContentProof(token, hash, { ...proof, chain: 212 }, 212), false, 'nor relabelled');
  const v1 = await contentProof(sk, nonce, token, hash);
  assert.equal(v1.v, undefined);
  assert.equal(await verifyContentProof(token, hash, v1, 212), true, 'a v1 proof names no chain; the server decides where it may hold');
});
