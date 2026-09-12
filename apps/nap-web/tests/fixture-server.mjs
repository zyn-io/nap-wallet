// Local-only UI fixture. Never connects to a chain or handles real funds.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { resolve, extname } from 'node:path';
import { concat, u32, u64 } from '../src/core.js';
const te = new TextEncoder();
const str = (s) => concat(u32(te.encode(s).length), te.encode(s));
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+a1foAAAAASUVORK5CYII=', 'base64');
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const mediaHash = hash(png);
const manifest = concat(te.encode('zyn.manifest.v1'), str('Fixture Mole'), str('Local UI test only'), u32(1), Uint8Array.of(0), mediaHash, str('image/png'), u64(png.length), u32(1), u32(1), u32(0), u32(0));
const content = hash(concat(Uint8Array.of(0), manifest)).toString('hex');
const balances = new Map();
let wrongChain = false, seq = 42;
const base = resolve('dist');
const pubKey = (bytes) => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]), format: 'der', type: 'spki' });
const accountOf = (pub) => hash(concat(te.encode('zyn.account.v1'), Uint8Array.of(1), u32(32), pub));
const reply = (res, data, status = 200) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(data)); };
http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://127.0.0.1');
    if (url.pathname === '/fixture/wrong-chain') { wrongChain = url.searchParams.get('on') === '1'; return reply(res, { wrongChain }); }
    if (url.pathname === '/rpc') {
      let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 8192) throw new Error('Oversized fixture request'); }
      const { id, method, params } = JSON.parse(raw); let result;
      try {
        if (method === 'zyn_status') result = { chain: wrongChain ? 12 : 11, epoch: 42, seq, anchored_epoch: 40 };
        else if (method === 'zyn_assets') result = [{ id: 7, symbol: 'FIXTURE-MOLE', content }];
        else if (method === 'zyn_account') {
          const bytes = Buffer.from(params[0], 'hex'), pub = bytes.subarray(41, 73), account = accountOf(pub);
          if (bytes.length !== 137 || !account.equals(bytes.subarray(0, 32)) || !verify(null, concat(te.encode('zyn.read.v1'), u32(11), account, bytes.subarray(32, 40)), pubKey(pub), bytes.subarray(73))) throw new Error('Invalid signed read');
          const key = account.toString('hex');
          if (!balances.has(key)) balances.set(key, 1);
          result = { spendable: balances.get(key) ? [{ asset: 7, amount: '1.000000000000000000' }] : [] };
        } else if (method === 'zyn_sendRawIntent') {
          const bytes = Buffer.from(params[0], 'hex'), pub = bytes.subarray(41, 73), intent = bytes.subarray(137);
          const message = concat(te.encode('zyn.auth.v1'), Uint8Array.of(1), u32(11), bytes.subarray(0, 32), bytes.subarray(32, 40), u32(intent.length), intent);
          if (bytes.length !== 222 || intent[0] !== 2 || !accountOf(pub).equals(intent.subarray(1, 33)) || !verify(null, message, pubKey(pub), bytes.subarray(73, 137))) throw new Error('Invalid signed transfer');
          if (intent.readUInt32BE(65) !== 7 || intent.subarray(69).toString('hex') !== '00000000000000000de0b6b3a7640000') throw new Error('Not one fixture item');
          balances.set(intent.subarray(1, 33).toString('hex'), 0); balances.set(intent.subarray(33, 65).toString('hex'), 1);
          result = { seq: ++seq, epoch: 42, queued: false, receipts: 1 };
        } else throw new Error('Unknown fixture method');
        return reply(res, { jsonrpc: '2.0', id, result });
      } catch (e) { return reply(res, { jsonrpc: '2.0', id, error: { code: -32000, message: e.message } }); }
    }
    if (url.pathname === '/claim/api/claims') return reply(res, { state: 'already_claimed', message: 'This fixture gift has already been claimed.' }, 409);
    if (url.pathname === `/media/${content}` || url.pathname === `/media/${mediaHash.toString('hex')}`) {
      res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end(url.pathname.endsWith(content) ? manifest : png);
    }
    const path = resolve(base, '.' + (url.pathname === '/' ? '/index.html' : url.pathname));
    if (!path.startsWith(base + '/')) throw new Error('Invalid path');
    const bytes = await readFile(path);
    res.writeHead(200, { 'content-type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png' })[extname(path)] || 'application/octet-stream' }); res.end(bytes);
  } catch { reply(res, { error: 'Fixture not found' }, 404); }
}).listen(4174, '127.0.0.1', () => process.stdout.write('Nap fixture: http://127.0.0.1:4174 (no real funds)\n'));
