// What this deployment tells a wallet to talk to.
//
// `config.json` and the RPC route are the only two things that decide which
// chain a holder reaches. They are edited by hand, on different days, in
// different languages, and nothing else checks that they still agree — which
// is how the testnet spent a week pointed at chain 11 after chain 11 was
// retired, showing "Holdings unavailable" to anyone who switched to it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const config = JSON.parse(readFileSync(join(here, '../public/config.json'), 'utf8'));
const route = readFileSync(join(here, '../functions/rpc/[[path]].js'), 'utf8');

const network = (id) => config.networks.find((n) => n.id === id);

/// Chain 11 was retired on 22 Sep 2026. Nothing may send a holder there.
test('no network points at the retired chain', () => {
  for (const n of config.networks) {
    assert.notEqual(n.chain, 11, `network ${n.id} still points at retired chain 11`);
  }
  assert.notEqual(config.chain, 11, 'the default network still points at chain 11');
  assert.doesNotMatch(route, /testnet\/?'/, 'the rpc route still forwards to /testnet');
});

/// The testnet is the object ledger, chain 212.
test('the testnet is chain 212 on the object ledger', () => {
  const t = network('testnet');
  assert.ok(t, 'the deployment offers a testnet');
  assert.equal(t.chain, 212);
  // Zcash testnet, because a Zyn chain sits on exactly one Zcash network and
  // a testnet chain anchoring into mainnet would be a different mistake.
  assert.equal(t.zcashPrefix, 'utest1');
  assert.equal(t.zcash, 'ZEC testnet');
});

/// Mainnet is untouched by any testnet work.
test('mainnet is still 26460 and is still the default', () => {
  assert.equal(network('mainnet').chain, 26460);
  assert.equal(config.chain, 26460);
  assert.equal(config.rpcUrl, '/rpc');
});

/// Both Zyn chains are object ledgers now: 212 on testnet, and 26460 on
/// mainnet since the AMM chain that held that id was retired on 23 Sep 2026.
/// A network left on the AMM shape asks for `zyn_assets`, which an object
/// ledger does not serve, and shows "Holdings unavailable".
test('every network is read as an object ledger', () => {
  for (const n of config.networks) {
    assert.equal(n.kind, 'object', `${n.id} is still read as an AMM chain`);
    assert.match(n.zecAsset, /^[0-9a-f]{64}$/, `${n.id} names no ZEC asset`);
  }
  assert.equal(config.kind, 'object', 'the default network too');
});

/// Every declared rpcUrl must be a route the worker actually serves, or the
/// wallet asks for a path that 404s with "no such chain".
test('every network rpcUrl resolves to a declared route', () => {
  const declared = [...route.matchAll(/(?:^|[{,]\s*)'?([A-Za-z]*)'?\s*:\s*'([^']*)'/g)]
    .map((m) => m[1]);
  for (const n of config.networks) {
    const rest = n.rpcUrl.replace(/^\/rpc\/?/, '');
    assert.ok(
      declared.includes(rest),
      `${n.id} asks for /rpc/${rest}, which the worker does not declare (declared: ${declared.join(', ')})`
    );
  }
});
