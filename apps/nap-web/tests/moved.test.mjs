// The old-host notice: only on nap.cavebro.win, never in a packaged build or
// on the new host, and it links the same page on nap.zyn-network.com.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { movedLink, NEW_ORIGIN, OLD_HOST } from '../src/moved.js';

const at = (href) => new URL(href);

test('the old host links the same page on the new one', () => {
  assert.equal(movedLink(at('https://nap.cavebro.win/')), 'https://nap.zyn-network.com/');
  assert.equal(movedLink(at('https://nap.cavebro.win/market.html?network=testnet#swap')), 'https://nap.zyn-network.com/market.html?network=testnet#swap');
  assert.equal(OLD_HOST, 'nap.cavebro.win');
  assert.equal(NEW_ORIGIN, 'https://nap.zyn-network.com');
});

test('no notice on the new host, a preview or a packaged build', () => {
  assert.equal(movedLink(at('https://nap.zyn-network.com/')), null);
  assert.equal(movedLink(at('https://nap-web.pages.dev/')), null);
  assert.equal(movedLink(at('http://127.0.0.1:4179/')), null);
  assert.equal(movedLink(at('chrome-extension://abc/index.html')), null);
  assert.equal(movedLink(at('tauri://localhost/popup.html')), null);
  assert.equal(movedLink(at('https://nap.cavebro.win/'), true), null);
});

test('the full pages load the notice; the packaged-only popup does not', () => {
  for (const f of ['app.js', 'market-app.js', 'bridge-app.js']) {
    assert.match(readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8'), /import '\.\/moved-banner\.js';/, f);
  }
  assert.doesNotMatch(readFileSync(new URL('../src/popup-app.js', import.meta.url), 'utf8'), /moved-banner/);
});
