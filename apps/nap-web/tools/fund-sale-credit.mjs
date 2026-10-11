// Pay ZEC.zy into a sale as its credit budget (DECISIONS §182), from a Nap
// wallet, through Nap's own code. Not shipped.
//
// The payment is an ordinary sale payment — 90% into the collection's floor
// and 10% to its DAO treasury, at once — and the amount becomes the budget
// burns of ZCAVE and REGI are credited from. It cannot be taken back.
//
//   PHRASE_FILE=<the paying wallet's words> node tools/fund-sale-credit.mjs <mainnet|testnet> status
//   PHRASE_FILE=<…> node tools/fund-sale-credit.mjs <mainnet|testnet> fund <ZEC> [--yes]
//
// Without --yes it says what it would pay and stops. The words never leave
// this process and are never printed.
import { readFileSync } from 'node:fs';

const store = new Map();
globalThis.localStorage ??= { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { deriveIdentity } = await import('../src/core.js');
const ledger = await import('../src/ledger.js');
const mk = await import('../src/market.js');
const { hex, unhex } = await import('../src/object.js');

const CAVE_Z = '024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e';
const NAP = process.env.NAP || 'https://nap.zyn-network.com';
const [, , net, cmd, amountText, ...flags] = process.argv;
const all = JSON.parse(readFileSync(new URL('../public/config.json', import.meta.url), 'utf8'));
const network = all.networks.find((n) => n.id === net);
if (!network || !['status', 'fund'].includes(cmd)) {
  console.error('usage: PHRASE_FILE=… node tools/fund-sale-credit.mjs <mainnet|testnet> status | fund <ZEC> [--yes]');
  process.exit(2);
}
const config = { ...network, rpcUrl: new URL(network.rpcUrl, NAP).href };
const identity = deriveIdentity(readFileSync(process.env.PHRASE_FILE, 'utf8').trim());
const wad = (v) => { const s = String(v).padStart(19, '0'); return `${s.slice(0, -18)}.${s.slice(-18).replace(/0+$/, '') || '0'}`; };

const s = await ledger.loadSale(config, CAVE_Z);
if (!s) throw new Error(`There is no Collection Z sale on ${net} yet.`);
const offers = await ledger.loadOffers(config);
const { held } = await ledger.loadHoldings(config, identity, offers);
const have = held.filter((x) => x.asset === s.quote).reduce((t, x) => t + BigInt(x.amount), 0n);
console.log(`sale        ${s.sale.phase} on ${net}`);
console.log(`budget      ${wad(s.sale.credit_budget || '0')} ZEC of credit left`);
console.log(`wallet      ${identity.accountHex.slice(0, 10)}… holds ${wad(have)} ZEC.zy`);
if (cmd === 'status') process.exit(0);

if (!/^\d*\.?\d+$/.test(amountText || '')) throw new Error('fund <ZEC>, e.g. fund 0.5');
const [i, f = ''] = amountText.split('.');
if (f.length > 8) throw new Error('ZEC has 8 decimal places');
const amount = BigInt(i || '0') * 10n ** 18n + BigInt(f.padEnd(18, '0'));
if (amount <= 0n) throw new Error('fund more than nothing');
if (amount > have) throw new Error(`the wallet holds ${wad(have)} ZEC.zy`);
const treasury = (amount * BigInt(s.sale.treasury_bps)) / 10000n;
console.log(`would pay   ${wad(amount)} ZEC.zy: ${wad(amount - treasury)} to the floor, ${wad(treasury)} to the DAO treasury`);
if (!flags.includes('--yes')) {
  console.log('nothing sent — add --yes to pay it');
  process.exit(0);
}
const { inputs, change } = mk.fund(identity, held, unhex(s.quote), amount);
await ledger.submitFresh(config, identity, (nonce) => mk.fundSaleCreditIntent({ funder: identity.account, collection: unhex(CAVE_Z), amount, nonce, inputs, change }));
const after = await ledger.loadSale(config, CAVE_Z);
console.log(`paid. budget now ${wad(after.sale.credit_budget || '0')} ZEC (${hex(identity.account).slice(0, 10)}…)`);
