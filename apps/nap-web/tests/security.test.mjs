import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, hkdfSync, pbkdf2Sync, verify } from 'node:crypto';
import { checkedEpoch, concat, deriveIdentity, hex, readChallenge, signedRead, u32, u64 } from '../src/core.js';
import { MAX_MANIFEST, parseManifest, safeRaster, boundedBytes } from '../src/media.js';

const te = new TextEncoder();
const words = `${'abandon '.repeat(23)}art`;
const str = (s) => concat(u32(te.encode(s).length), te.encode(s));
const manifest = () => concat(te.encode('zyn.manifest.v1'), str('Nap Mole #001'), str('A sleeping mole'), u32(1), Uint8Array.of(0), new Uint8Array(32).fill(1), str('image/png'), u64(42), u32(32), u32(32), u32(0), u32(1), str('Species'), str('Mole'));

test('independent OpenSSL primitives reproduce both derivation vectors and verify reads', () => {
  for (const [passphrase, index] of [['', 0], ['nap passphrase', 7]]) {
    const seed = pbkdf2Sync(words.normalize('NFKD'), `mnemonic${passphrase}`.normalize('NFKD'), 2048, 64, 'sha512');
    const key = Buffer.from(hkdfSync('sha256', seed, 'nap.zyn.ed25519.v1', Buffer.concat([Buffer.from('account'), Buffer.from(u32(index))]), 32));
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), key]), format: 'der', type: 'pkcs8' });
    const publicKey = createPublicKey(privateKey);
    const pub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
    const account = createHash('sha256').update(Buffer.concat([Buffer.from('zyn.account.v1'), Buffer.from([1, 0, 0, 0, 32]), pub])).digest();
    const actual = deriveIdentity(words, passphrase, index);
    assert.equal(hex(actual.secretKey), key.toString('hex'));
    assert.equal(hex(actual.publicKey), pub.toString('hex'));
    assert.equal(actual.accountHex, account.toString('hex'));
    const signature = signedRead(actual, 11, 42).slice(-64);
    assert.ok(verify(null, readChallenge(11, account, 42), publicKey, signature));
    assert.equal(verify(null, readChallenge(12, account, 42), publicKey, signature), false);
    signature[0] ^= 1;
    assert.equal(verify(null, readChallenge(11, account, 42), publicKey, signature), false);
  }
});

test('manifest parses the canonical domain, media and attributes', () => {
  const parsed = parseManifest(manifest());
  assert.equal(parsed.name, 'Nap Mole #001');
  assert.deepEqual(parsed.attributes, [{ trait: 'Species', value: 'Mole' }]);
  assert.equal(parsed.media[0].mime, 'image/png');
  assert.equal(parsed.media[0].bytes, 42);
});

test('manifest rejects every truncation, trailing data, excessive counts and size', () => {
  const bytes = manifest();
  for (let i = 0; i < bytes.length; i++) assert.throws(() => parseManifest(bytes.slice(0, i)));
  assert.throws(() => parseManifest(concat(bytes, Uint8Array.of(0))));
  assert.throws(() => parseManifest(new Uint8Array(MAX_MANIFEST + 1)));
  assert.throws(() => parseManifest(concat(te.encode('zyn.manifest.v1'), str(''), str(''), u32(1025))));
});

test('only bounded raster MIME/signatures can be rendered', () => {
  const png = concat(Uint8Array.from([137, 80, 78, 71, 13, 10, 26, 10]), u32(13), te.encode('IHDR'), u32(32), u32(32));
  const media = { mime: 'image/png', bytes: png.length, width: 32, height: 32 };
  assert.ok(safeRaster(media, png));
  assert.equal(safeRaster({ ...media, mime: 'image/svg+xml' }, png), false);
  assert.equal(safeRaster({ ...media, width: 100000 }, png), false);
  assert.equal(safeRaster({ ...media, width: 31 }, png), false);
  assert.equal(safeRaster(media, te.encode('<script>')), false);
});

test('wrong chains and unsafe epochs fail before signing', () => {
  assert.equal(checkedEpoch({ chain: 11, epoch: 42 }, 11), 42n);
  assert.throws(() => checkedEpoch({ chain: 12, epoch: 42 }, 11));
  assert.throws(() => checkedEpoch({ chain: 11, epoch: 9007199254740992 }, 11));
  assert.throws(() => checkedEpoch({ chain: 11, epoch: '-1' }, 11));
  assert.throws(() => checkedEpoch({ chain: 11, epoch: '18446744073709551615' }, 11));
});

test('streamed responses are capped even without content-length', async () => {
  const original = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(new ReadableStream({ start(c) { c.enqueue(new Uint8Array(10)); c.enqueue(new Uint8Array(10)); c.close(); } }));
    await assert.rejects(boundedBytes('/fixture', 12), /too large/);
  } finally { globalThis.fetch = original; }
});
