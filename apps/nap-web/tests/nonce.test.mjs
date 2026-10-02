// Nap steps over a nonce another device already used. It recognises that by
// the chain's refusal text, so every refusal that means "taken" must match —
// read here from the VM's own source, so a new wording cannot slip past.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { NONCE_TAKEN } from '../src/ledger.js';

const vm = (f) => readFile(new URL(`../../../objectvm/src/${f}`, import.meta.url), 'utf8');
// The VM's source sits beside Nap in the Zyn workspace, not in Nap's own repo.
const NO_VM = await vm('lib.rs').then(() => false, () => 'objectvm is not checked out beside Nap');

test('every "taken" refusal in the VM is one Nap steps over', { skip: NO_VM }, async () => {
  const src = (await Promise.all(['lib.rs', 'market.rs', 'curve.rs', 'primary.rs'].map((f) => vm(f).catch(() => '')))).join('\n');
  const taken = [...src.matchAll(/(?:Refused|Err)\("([^"]*(?:nonce (?:was already used|is in use)|token exists)[^"]*)"\)/g)].map((m) => m[1]);
  assert.ok(taken.length >= 3, `found ${taken.join(' | ')}`);
  for (const msg of taken) assert.match(msg, NONCE_TAKEN, msg);
});

test('a refusal that is not about the nonce is not stepped over', () => {
  for (const msg of ['an output needs a nonce', 'a mint needs a nonce', 'the price changed', 'not enough to cover that']) {
    assert.doesNotMatch(msg, NONCE_TAKEN, msg);
  }
});

// The 25 Sep audit's H2: a restored wallet looked only 24 nonces past zero, so
// an active holder's newest claims were out of sight on a new device.
test('a restore finds claims far past the old lookahead and keeps the count', async () => {
  const mem = {};
  globalThis.localStorage = { getItem: (k) => mem[k] ?? null, setItem: (k, v) => { mem[k] = String(v); }, removeItem: (k) => { delete mem[k]; } };
  const { deriveIdentity } = await import('../src/core.js');
  const ledger = await import('../src/ledger.js');
  const id = deriveIdentity(`${'abandon '.repeat(23)}art`, '', 0);
  const config = { rpcUrl: 'http://node.test/rpc', chain: 212 };
  // The chain still owes this wallet one claim, from its 151st trade.
  const owed = ledger.claimSources(id, 151, 150)[0];
  const seen = [];
  globalThis.fetch = async (_url, init) => {
    const { method, ids, id: rid } = JSON.parse(init.body);
    seen.push(method);
    const list = String(ids || '').split(',');
    const result = method === 'zyn_claims' ? (list.includes(owed) ? [{ id: owed, asset: 'aa'.repeat(32), amount: '5' }] : [])
      : method === 'zyn_market' ? { curves: [] } : [];
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: rid, result }), { headers: { 'content-type': 'application/json' } });
  };
  assert.equal(ledger.nonceCount(config, id), 0, 'a new device');
  const rows = await ledger.loadOwed(config, id);
  assert.deepEqual(rows.map((r) => r.id), [owed], 'the 151st trade is found');
  assert.equal(ledger.nonceCount(config, id), 151, 'and the count is kept');
  seen.length = 0;
  await ledger.loadOwed(config, id);
  assert.ok(!seen.includes('zyn_market') && !seen.includes('zyn_bridged'), 'recovery runs once per device, not on every look');
});
