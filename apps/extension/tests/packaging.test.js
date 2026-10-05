import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { test } from 'node:test';

// Run after `npm run build`: these check what ships, not the sources.
const at = (p) => new URL(`../${p}`, import.meta.url);
const read = (p) => readFileSync(at(p), 'utf8');
const json = (p) => JSON.parse(read(p));
const API = 'https://nap.zyn-network.com';

/// Two stores, two background models, one extension. Chrome's MV3 runs the
/// background as a service worker; Firefox runs it as an event page and wants
/// an add-on id and a data declaration. Anything else that diverges is drift.
test('the two builds differ only in how the background runs', () => {
  const chrome = json('dist/manifest.json');
  const firefox = json('dist-firefox/manifest.json');
  assert.deepEqual(chrome.background, { service_worker: 'background.js' });
  assert.deepEqual(firefox.background, { scripts: ['background.js'] });
  assert.equal(firefox.browser_specific_settings.gecko.id, 'nap-wallet@cavebro.win');
  assert.equal(chrome.browser_specific_settings, undefined);
  for (const key of new Set([...Object.keys(chrome), ...Object.keys(firefox)])) {
    if (key === 'background' || key === 'browser_specific_settings') continue;
    assert.deepEqual(firefox[key], chrome[key], `${key} drifted between the two builds`);
  }
});

/// The wallet works by itself: no desktop app on the loopback, one server.
test('it asks for one host and no more than a wallet needs', () => {
  const m = json('dist/manifest.json');
  assert.deepEqual(m.host_permissions, [`${API}/*`]);
  assert.deepEqual(m.permissions, ['storage']);
  assert.ok(!JSON.stringify(m).includes('8977'), 'no desktop app address');
  // The provider is offered to https pages and local development only.
  for (const cs of m.content_scripts) assert.ok(cs.matches.every((p) => p.startsWith('https://') || /^http:\/\/(localhost|127\.0\.0\.1)\//.test(p)), cs.matches.join());
  // WebAssembly (the Zcash wallet) and nothing looser.
  assert.equal(m.content_security_policy.extension_pages, "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'");
});

test('every page it ships is the wallet, talking only to Nap', () => {
  const m = json('dist/manifest.json');
  assert.equal(m.action.default_popup, 'popup.html');
  for (const page of ['popup.html', 'index.html', 'connect.html']) {
    const html = read(`dist/${page}`);
    const csp = html.match(/connect-src ([^;"]*)/)[1].split(/\s+/);
    assert.ok(csp.includes(API), `${page} can reach Nap`);
    assert.ok(csp.every((s) => s === "'self'" || s === API || s === 'https://api.devnet.solana.com'), `${page}: ${csp.join(' ')}`);
    assert.ok(!/<script[^>]+src="https?:/.test(html), `${page} loads no remote script`);
    assert.ok(!/<script>(?!\s*<\/script>)/.test(html), `${page} has no inline script`);
  }
  for (const f of ['sw.js', 'manifest.webmanifest', '_headers']) assert.ok(!existsSync(at(`dist/${f}`)), `${f} is the web deployment's, not the extension's`);
  // The endpoints the pages were built for.
  const js = readdirSync(at('dist/assets')).filter((f) => f.endsWith('.js')).map((f) => read(`dist/assets/${f}`)).join('\n');
  assert.ok(js.includes(API), 'the pages were built for the extension (VITE_NAP_API)');
  assert.ok(!js.includes('127.0.0.1:8977'));
});

test('the background only opens the connect window, and only for a site tab', () => {
  const bg = read('dist/background.js');
  assert.match(bg, /msg\.kind !== 'nap:open' \|\| !sender\.tab/);
  assert.ok(!/fetch\(/.test(bg), 'the background talks to nobody');
});

test('the store packages exist and carry the manifest at their root', () => {
  const v = json('src/manifest.json').version;
  for (const f of [`release/nap-wallet-${v}-chrome.zip`, `release/nap-wallet-${v}-firefox.zip`]) assert.ok(existsSync(at(f)), f);
});
