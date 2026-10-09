// ZCaveDAO's Nap requests (§172, §173): what a vote is on comes from the
// chain, not the page; a proposal in the wrong state is refused before any
// card is shown.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
const { METHODS } = await import('../src/connect-ops.js');
const { deriveIdentity } = await import('../src/core.js');

const CONFIG = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const testnet = CONFIG.networks.find((n) => n.id === 'testnet');
const ctx = { config: { ...testnet, rpcUrl: 'http://chain.test/' }, identity: deriveIdentity('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art') };
const CAVE_Z = '024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e';

let dao = null;
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  const result = body.method === 'zyn_dao' ? dao : null;
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), { headers: { 'content-type': 'application/json' } });
};

const vote = (proposal, choice) => METHODS.zyn_daoVote.prepare(ctx, { collection: CAVE_Z, proposal, choice });

test('a vote names a proposal the chain has, in the state the choice needs', async () => {
  dao = { set: true, backers: 10, proposals: [{ id: 3, state: 'backing', text: 'ab'.repeat(32), pay: null }, { id: 4, state: 'lapsed', text: 'cd'.repeat(32), pay: null }] };
  await assert.rejects(vote(9, 'yes'), /There is no proposal #9/);
  await assert.rejects(vote(3, 'yes'), /#3 is backing, not open for votes/);
  await assert.rejects(vote(4, 'back'), /#4 is lapsed, not gathering backers/);
  await assert.rejects(vote(3, 'maybe'), /choice must be back, yes or no/);
  await assert.rejects(vote(0, 'yes'), /a proposal number/);
});

test('a proposal needs a DAO and a text of up to 4,000 characters', async () => {
  dao = { set: false };
  await assert.rejects(METHODS.zyn_daoPropose.prepare(ctx, { collection: CAVE_Z, text: '' }), /1 to 4,000/);
  await assert.rejects(METHODS.zyn_daoPropose.prepare(ctx, { collection: CAVE_Z, text: 'x'.repeat(4001) }), /1 to 4,000/);
  await assert.rejects(METHODS.zyn_daoPropose.prepare(ctx, { collection: CAVE_Z, text: 'fund a replica' }), /no DAO/);
  await assert.rejects(METHODS.zyn_daoPropose.prepare(ctx, { collection: CAVE_Z, text: 'x', pay: { asset: 'zz', to: 'ab'.repeat(32), amount: '1' } }), /64 hex/);
});

test('every DAO card says the operator and replicas can see which item acted', () => {
  const src = readFileSync(new URL('../src/connect-ops.js', import.meta.url), 'utf8');
  const block = src.slice(src.indexOf('zyn_daoPass: {'), src.indexOf("// Collection Z's sale (§144)"));
  assert.equal((block.match(/operator and replicas can see/g) || []).length, 3);
  assert.match(block, /i \+= 32/, 'votes go in chunks of 32, so every item counts');
});

test('a Zyn proposal needs the DAO\'s Zyn track and pays nothing (§176)', async () => {
  dao = { set: true, backers: 10, proposals: [] };
  const propose = (o) => METHODS.zyn_daoPropose.prepare(ctx, { collection: CAVE_Z, text: 'bridge BTC next', ...o });
  await assert.rejects(propose({ track: 'zyn' }), /does not vote on Zyn issues yet/);
  await assert.rejects(propose({ track: 'cave' }), /track must be/);
  dao = { ...dao, zyn: { team: 'ab'.repeat(32), rule: 'veto', share_bps: 0, frozen: false } };
  await assert.rejects(propose({ track: 'zyn', pay: { asset: 'ab'.repeat(32), to: 'cd'.repeat(32), amount: '1' } }), /pays nothing/);
});

test('a vote on a Zyn proposal says what the team\'s vote weighs and whether it is cast', () => {
  const src = readFileSync(new URL('../src/connect-ops.js', import.meta.url), 'utf8');
  assert.match(src, /can veto, not pass/);
  assert.match(src, /% of the tally/);
  assert.match(src, /\['Team vote', `\$\{teamRule\(dao\.zyn\)\}; so far/);
});
