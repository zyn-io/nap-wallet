// The gateway's rate limit is waited out, not shown to the holder.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rpcPost, objectCall } from '../src/object.js';

function stub(statuses) {
  const seen = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push(JSON.parse(init.body));
    const status = statuses[Math.min(seen.length - 1, statuses.length - 1)];
    const body = status === 200 ? JSON.stringify({ jsonrpc: '2.0', id: seen.at(-1).id, result: 'ok' }) : '<html>busy</html>';
    return new Response(body, { status });
  };
  return { seen, restore: () => { globalThis.fetch = real; } };
}

test('a 503 or 429 is sent again until the gateway lets it through', async () => {
  const s = stub([503, 429, 200]);
  try {
    assert.equal(await objectCall('https://gw.example', 'zyn_status'), 'ok');
    assert.equal(s.seen.length, 3);
    assert.deepEqual(new Set(s.seen.map((b) => b.id)).size, 1, 'the same request, not a new one');
  } finally { s.restore(); }
});

test('it gives up after its attempts, with what the gateway said', async () => {
  const s = stub([503]);
  try {
    const r = await rpcPost('https://gw.example', { id: 1 }, { attempts: 3 });
    assert.equal(r.status, 503);
    assert.equal(s.seen.length, 3);
  } finally { s.restore(); }
});

test('other failures are not retried', async () => {
  const s = stub([500]);
  try {
    const r = await rpcPost('https://gw.example', { id: 1 });
    assert.equal(r.status, 500);
    assert.equal(s.seen.length, 1);
  } finally { s.restore(); }
});
