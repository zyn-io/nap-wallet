// The gate has to hold in the two states that actually occur: a fresh browser,
// and one that has refused storage. Both must fetch nothing.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');

test('art is fetched only behind the consent gate', () => {
  // The one call site that reaches the gateway for a holding must sit inside
  // the guard. A future edit that moves it out should fail here.
  const guard = src.indexOf('if (artEnabled()) {');
  const call = src.indexOf('loadVerifiedArt(root.querySelectorAll');
  assert.ok(guard > 0, 'the gate exists');
  assert.ok(call > guard, 'the fetch loop is inside the gate');
  const close = src.indexOf('} else {', guard);
  assert.ok(call < close, 'and not after it');
});

test('a browser that refuses storage stays off', () => {
  const fn = src.slice(src.indexOf('function artEnabled()'), src.indexOf('function setArtEnabled'));
  assert.match(fn, /catch\s*{[\s\S]*return false/, 'storage failure means off, not on');
});

test('the default is off', () => {
  const fn = src.slice(src.indexOf('function artEnabled()'), src.indexOf('function setArtEnabled'));
  // Only an explicit '1' enables it, so an absent key is off.
  assert.match(fn, /=== '1'/);
});

test('the disclosure names what is given away', () => {
  const label = src.slice(src.indexOf('art-consent'), src.indexOf('art-consent') + 400);
  for (const word of ['IP', 'which items you hold', 'Off by default']) {
    assert.ok(label.includes(word), `the label says "${word}"`);
  }
});
