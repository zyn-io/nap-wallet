// An item's picture comes from the media gateway by its hash, which tells
// that host which item the holder is looking at. The gate has to hold in the
// two states that actually occur — a fresh browser, and one that refuses
// storage — and in both nothing may be fetched. Once on, only bytes that hash
// to the name are shown.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const { artOn, artHash, CAVE_Z, itemArt, itemName, setArtOn, forgetArt } = await import('../src/items.js');

const store = new Map();
const storage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
const refusing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
const config = { id: 'mainnet', mediaGateway: '/media' };
const index = readFileSync(new URL(`../public/art/${CAVE_Z}.bin`, import.meta.url));
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1foAAAAASUVORK5CYII=', 'base64');

/// A fetch that serves the shipped index and `blob` for any picture, and
/// records every picture asked for.
function serve(blob) {
  const asked = [];
  globalThis.fetch = async (url) => {
    if (String(url).startsWith('/art/')) return new Response(index);
    asked.push(String(url));
    return new Response(blob);
  };
  return asked;
}

test('off by default: nothing is fetched', async () => {
  store.clear();
  globalThis.localStorage = storage;
  const asked = serve(png);
  assert.equal(artOn(), false);
  assert.equal(await itemArt(config, CAVE_Z, 0), null);
  assert.deepEqual(asked, []);
});

test('a browser that refuses storage stays off', async () => {
  globalThis.localStorage = refusing;
  const asked = serve(png);
  assert.equal(artOn(), false);
  setArtOn(true); // cannot be remembered, so it is not on
  assert.equal(artOn(), false);
  assert.equal(await itemArt(config, CAVE_Z, 1), null);
  assert.deepEqual(asked, []);
});

test('the shipped index names each Collection Z picture by its hash', async () => {
  globalThis.localStorage = storage;
  serve(png);
  assert.equal(index.length, 4444 * 32);
  assert.equal(await artHash(CAVE_Z, 0), 'f756dfdc95ad215eab0615e3af9a40a792e5276d36c2f1f4ed03c684d6e26ff4');
  assert.equal(await artHash(CAVE_Z, 4444), null);
  assert.equal(await artHash('ab'.repeat(32), 0), null);
  assert.equal(itemName(CAVE_Z, 0), 'Zyn Mole #0001');
  assert.equal(itemName(CAVE_Z, 2222), 'Zyn Owl #0001');
  assert.equal(itemName(CAVE_Z, 4443), 'Zyn Moth #0889');
});

test('once on, bytes that do not hash to the name are not shown', async () => {
  store.clear();
  globalThis.localStorage = storage;
  setArtOn(true);
  forgetArt();
  const asked = serve(png); // a real PNG, but not the one the index names
  assert.equal(await itemArt(config, CAVE_Z, 2), null);
  assert.deepEqual(asked, [`/media/${await artHash(CAVE_Z, 2)}`]);
});

test('once on, a picture whose bytes match is shown, and fetched once', async () => {
  store.clear();
  globalThis.localStorage = storage;
  setArtOn(true);
  forgetArt();
  const hash = createHash('sha256').update(png).digest('hex');
  // An index naming the 1×1 PNG at serial 0.
  const own = Buffer.from(index); Buffer.from(hash, 'hex').copy(own, 0);
  const asked = [];
  globalThis.fetch = async (url) => (String(url).startsWith('/art/') ? new Response(own) : (asked.push(String(url)), new Response(png)));
  globalThis.URL.createObjectURL = () => 'blob:art';
  // A fresh module, so its index is the one served here.
  const fresh = await import(`../src/items.js?own=${Date.now()}`);
  assert.equal(await fresh.itemArt(config, CAVE_Z, 0), 'blob:art');
  assert.equal(await fresh.itemArt(config, CAVE_Z, 0), 'blob:art');
  assert.deepEqual(asked, [`/media/${hash}`]);
});

test('both wallet views say what turning artwork on gives away, where it is turned on', () => {
  for (const f of ['app.js', 'popup-app.js']) {
    const src = readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
    const at = src.indexOf('Show artwork');
    assert.ok(at > 0, `${f} has the switch`);
    const label = src.slice(at, at + 200);
    for (const words of ['IP address', 'which items you hold']) assert.ok(label.includes(words), `${f}: the label says "${words}"`);
  }
});
