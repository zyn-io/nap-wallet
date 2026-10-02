import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePaymentRequest, paymentRequest, zatoshiOf } from '../src/zip321.js';

const UA = 'u1l8xunezsvhq8fgzfl7404m450nwnd76zshscn6nfys7vyz2ywyh4cc5daaq0c7q2su5lqfh23sp7fkf3kt27ve5948mzpfdvckzaect2jtte308mkwlycj2u0eac077wu70vqcetkxf';

test('the examples in ZIP-321 read as written', () => {
  const r = parsePaymentRequest(`zcash:${UA}?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase`);
  assert.equal(r.address, UA);
  assert.equal(r.zatoshi, 100_000_000);
  assert.equal(r.memo, 'This is a simple memo.');
  assert.equal(r.message, 'Thank you for your purchase');
  assert.equal(parsePaymentRequest('zcash:t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4?amount=0.0001').zatoshi, 10_000);
  assert.equal(parsePaymentRequest(`zcash:?address=${UA}&amount=0.5`).address, UA);
});

test('what Nap cannot pay honestly is refused, not half-paid', () => {
  assert.throws(() => parsePaymentRequest(`zcash:?address=${UA}&amount=1&address.1=${UA}&amount.1=2`), /more than one recipient/);
  assert.throws(() => parsePaymentRequest(`zcash:${UA}?req-future=1`), /does not understand/);
  assert.throws(() => parsePaymentRequest(`zcash:${UA}?amount=1.123456789`), /eight decimals/);
  assert.throws(() => parsePaymentRequest(`zcash:${UA}?amount=1&amount=2`), /twice/);
  assert.throws(() => parsePaymentRequest('zcash:t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4?memo=aGk'), /shielded/);
  assert.throws(() => parsePaymentRequest('bitcoin:abc'), /zcash:/);
  assert.throws(() => parsePaymentRequest('zcash:?amount=1'), /no address/);
});

test('a request Nap writes is one it reads back', () => {
  const uri = paymentRequest({ address: UA, zatoshi: 12_345_678, memo: 'order #42 — ok', message: 'Cave' });
  const r = parsePaymentRequest(uri);
  assert.equal(r.zatoshi, 12_345_678);
  assert.equal(r.memo, 'order #42 — ok');
  assert.equal(r.message, 'Cave');
  assert.equal(zatoshiOf('0.00000001'), 1);
});
