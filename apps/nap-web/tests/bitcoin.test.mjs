// BTC.zy addresses (§154): what Nap derives must be what the custodians can
// spend. The vectors come from the Rust side (bitcoin crate + zyn-custody's
// deposit_root), for the x-only key of the secp256k1 generator.
import test from 'node:test';
import assert from 'node:assert/strict';
import { depositAddress, depositRoot, scriptOf, vaultAddress } from '../src/bitcoin.js';

const G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const hex = (b) => Buffer.from(b).toString('hex');

test('deposit and vault addresses match the custodians\' derivation', () => {
  const code = new Uint8Array(32).fill(1);
  assert.equal(hex(depositRoot(code)), '31db50eec0f5af7ca3675c4aa70742dcd3fdd6ceb96297c2fa15ac7a9fddf5bd');
  assert.equal(depositAddress(G, code, 'signet'), 'tb1pptyy6t2rcnrly2muc8xwyqstyf2sah9789welww3wf9mtpdqen9q9ljjmh');
  assert.equal(vaultAddress(G, 'signet'), 'tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2');
  assert.notEqual(depositAddress(G, new Uint8Array(32).fill(2)), depositAddress(G, code));
});

test('withdrawal addresses become the script they pay, and nothing else is accepted', () => {
  assert.equal(hex(scriptOf('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 'signet')), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
  const tr = scriptOf('tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv2', 'signet');
  assert.equal(tr.length, 34); assert.equal(tr[0], 0x51); assert.equal(tr[1], 32);
  assert.equal(scriptOf('tb1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssk79hv3', 'signet'), null, 'bad checksum');
  assert.equal(scriptOf('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'signet'), null, 'mainnet address on signet');
  assert.equal(scriptOf('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn', 'signet'), null, 'legacy');
  assert.equal(scriptOf('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsX', 'signet'), null, 'mixed case');
});
