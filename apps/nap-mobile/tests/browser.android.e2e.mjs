// The Nap browser on Android, end to end (DECISIONS §152): the wallet opens
// its browser, Cave Jade (testnet) finds Nap in the app, connects through a
// native sheet, reads what Nap holds, and buys a test coin approved in the
// sheet and signed in the wallet.
//
// Needs: an emulator running the debug app with a fingerprint-free lock, the
// WebView debug socket forwarded (`adb forward tcp:9333
// localabstract:webview_devtools_remote_<pid>`), PHRASE_FILE (a testnet
// wallet holding a little ZEC.zy) and TOKEN (a ZEC-quoted Jade coin).
import { chromium } from '../../nap-connect/node_modules/playwright-core/index.mjs';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
const HERE = new URL('.', import.meta.url).pathname;
const ADB = `${process.env.HOME}/Library/Android/sdk/platform-tools/adb`;
const ui = (...a) => { try { return execFileSync(`${HERE}ui.sh`, a).toString(); } catch (e) { return String(e.stdout || ''); } };
const unstick = () => { if (/isn't responding/.test(ui('dump'))) ui('tap', 'Wait'); };
const ok = (c, w) => { console.log((c ? 'PASS  ' : 'FAIL  ') + w); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WORDS = readFileSync(process.env.PHRASE_FILE, 'utf8').trim();
const TOKEN = process.env.TOKEN;
async function approveSheet(expect) {
  for (let i = 0; i < 30; i++) { unstick(); const d = ui('dump'); if (/text="Approve"/.test(d)) { ok(expect.test(d), `native sheet: ${(d.match(/text="[^"]*asks[^"]*"/i) || [''])[0]} ${(d.match(/text="(Connect|Buy)[^"]*"/) || [''])[0]}`); await sleep(1000); ui('tap', 'Approve'); return true; } await sleep(1000); }
  ok(false, 'no approval sheet appeared'); return false;
}
const b = await chromium.connectOverCDP('http://127.0.0.1:9333');
const wallet = b.contexts()[0].pages().find((p) => p.url().startsWith('http://tauri.localhost'));
await wallet.evaluate(() => localStorage.setItem('nap.network', 'testnet')); await wallet.reload();
await wallet.waitForSelector('#restore-form');
await wallet.fill('#words', WORDS); await wallet.click('#restore-form button[type=submit]');
await wallet.waitForSelector('#browser-link', { timeout: 60000 });
ok(true, 'the wallet menu has a Browser entry in the app');
await wallet.click('#browser-link'); await sleep(4000); unstick();
const home = ui('dump');
ok(/Sites that know Nap/.test(home) && /Cave Jade/.test(home), 'the Nap browser opens on its start page');
// The site's page is a separate web view: find it.
let site;
for (let i = 0; i < 15 && !site; i++) { await sleep(1000); site = b.contexts().flatMap((c) => c.pages()).find((p) => !p.url().startsWith('http://tauri.localhost')); }
ok(!!site, 'the site runs in its own web view, not the wallet\'s');
await site.goto('https://cave-jade.pages.dev/?network=testnet');
await site.waitForSelector(`[data-coin="${TOKEN}"]`, { timeout: 40000 });
ok(await site.evaluate(() => !!window.zyn?.isNapApp && !window.__TAURI__ && !window.__TAURI_INTERNALS__), 'the site sees Nap\'s provider and no app internals');
await site.click('#wallet-button'); await site.waitForSelector('.jade-wallet-option');
const names = await site.$$eval('.jade-wallet-option', (els) => els.map((e) => e.textContent.replace(/\s+/g, ' ').trim()));
ok(names.some((n) => /Nap Wallet/.test(n) && /Nap app/.test(n)), `Jade finds Nap in the app: ${JSON.stringify(names)}`);
await site.click('.jade-wallet-option:has-text("Nap app")');
await approveSheet(/cave-jade\.pages\.dev asks/i);
await site.waitForFunction(() => !/Connect wallet/.test(document.querySelector('#wallet-button').textContent), null, { timeout: 60000 });
ok(true, `connected: ${(await site.textContent('#wallet-button')).trim()}`);
await site.click(`[data-coin="${TOKEN}"]`);
await site.waitForFunction(() => /You hold/.test(document.querySelector('#trade-balance')?.textContent || ''), null, { timeout: 60000 });
ok(true, `the site reads what Nap holds: ${await site.textContent('#trade-balance')}`);
await site.fill('#trade-input', '0.001'); await sleep(400);
await site.click('.trade-submit');
await approveSheet(/Buy ZTEST with 0\.001 ZEC\.zy/);
await site.waitForFunction(() => /Placed|refused|Not enough|error/i.test(document.querySelector('#trade-status').textContent), null, { timeout: 90000 });
ok(/Placed/.test(await site.textContent('#trade-status')), `signed in the wallet, placed: ${await site.textContent('#trade-status')}`);
await site.waitForFunction(() => /Filled|Settled/.test(document.querySelector('#trade-status').textContent), null, { timeout: 420000 }).catch(() => {});
ok(/Filled/.test(await site.textContent('#trade-status')), `collected: ${await site.textContent('#trade-status')}`);
await b.close();
