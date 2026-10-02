// The relays tell the gateway who is asking, so its rate limit is per visitor
// rather than one budget for every Nap user behind Cloudflare's addresses —
// and only with the key, so nobody else can choose whose budget they spend.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const rpc = await import(new URL('../functions/rpc/[[path]].js', import.meta.url));
const zec = await import(new URL('../functions/zec/[[path]].js', import.meta.url));

async function sent(mod, env, path, body, visitor = '203.0.113.7') {
  let seen;
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => { seen = { url, headers: init.headers }; return new Response('{}'); };
  try {
    const request = new Request('https://nap.example/x', {
      method: 'POST', body, headers: visitor ? { 'cf-connecting-ip': visitor } : {},
    });
    await mod.onRequest({ request, env: { ZYN_RPC_URL: 'https://gw.example', ...env }, params: { path } });
  } finally { globalThis.fetch = real; }
  return seen;
}

for (const [name, mod, path, body] of [['rpc', rpc, ['testnet'], '{}'], ['zec', zec, ['testnet'], new Uint8Array([1])]]) {
  test(`${name}: the visitor's address goes to the gateway with the relay key`, async () => {
    const s = await sent(mod, { ZYN_RELAY_KEY: 'k' }, path, body);
    assert.ok(s, 'the request was relayed');
    assert.equal(s.headers['x-zyn-client'], '203.0.113.7');
    assert.equal(s.headers['x-zyn-relay-key'], 'k');
  });

  test(`${name}: without a key, or without a visitor address, neither header is sent`, async () => {
    const none = await sent(mod, {}, path, body);
    assert.equal(none.headers['x-zyn-client'], undefined);
    assert.equal(none.headers['x-zyn-relay-key'], undefined);
    const anon = await sent(mod, { ZYN_RELAY_KEY: 'k' }, path, body, null);
    assert.equal(anon.headers['x-zyn-relay-key'], undefined, 'the key never travels alone');
  });
}
