import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as sol from '../src/solana.js';

// A SOL deposit into the bridge vault (§146). This layout was accepted and
// finalized by Solana devnet on 24 Sep 2026 (2UYJc1sE…nG3Fq1Yz1, 0.03 SOL,
// credited to the wallet whose memo it carried), so the bytes are pinned.
const INPUT = {
  owner: 'HBvV7YqSRSPW4YEBsDvpvF2PrUWFubqVbTNYafkddTsy',
  vault: '7KacSYXuVhKSf8dpXcLY3qFZQYiZg2m6vKh4m1HxKZmA',
  lamports: 30_000_000n,
  memo: `zyn:${'3b'.repeat(32)}`,
  blockhash: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
};

test('a SOL deposit: one signer, a transfer to the vault, then the memo', () => {
  const m = sol.depositMessage(INPUT);
  assert.deepEqual([...m.slice(0, 4)], [1, 0, 2, 4], 'one signer, two read-only programs, four keys');
  const keys = Array.from({ length: 4 }, (_, i) => sol.b58encode(m.slice(4 + i * 32, 36 + i * 32)));
  assert.deepEqual(keys, [INPUT.owner, INPUT.vault, sol.SYSTEM_PROGRAM, sol.MEMO_PROGRAM]);
  const ix = m.slice(4 + 4 * 32 + 32);
  assert.equal(ix[0], 2, 'two instructions');
  assert.deepEqual([...ix.slice(1, 5)], [2, 2, 0, 1], 'the system program moves from the owner to the vault');
  assert.deepEqual([...ix.slice(5, 18)], [12, 2, 0, 0, 0, 0x80, 0xc3, 0xc9, 0x01, 0, 0, 0, 0], 'transfer 30,000,000 lamports');
  assert.equal(new TextDecoder().decode(ix.slice(21)), INPUT.memo);
});

test('it deposits only with Nap\'s code, and only something', () => {
  assert.throws(() => sol.depositMessage({ ...INPUT, memo: 'hello' }), /memo/);
  assert.throws(() => sol.depositMessage({ ...INPUT, lamports: 0n }), /something/);
  assert.throws(() => sol.solanaKey('0x1234'), /not base58|Solana address/);
});
