# Nap Connect

How a site finds a Nap wallet and talks to it. One file, no dependencies:
`nap-connect.js`. Copy it into the site (a test in each site keeps the copy
identical to this one).

```js
import { discover, connect } from './nap-connect.js';

const wallets = await discover();          // the extension (if any), then Nap in the browser
const { provider, session } = await connect(wallets[0], { network: 'mainnet' });
session.account;                           // Zyn account id
session.zcash?.address;                    // a Zcash address to show or pay back to

// From a click: Nap in the browser may need to open its window.
await provider.request({ method: 'zec_pay', params: { uri: 'zcash:u1…?amount=0.5&memo=…' } });
await provider.request({ method: 'zyn_nftBuy', params: { item, pay: '1.01' } });
```

## Two ways in

| | How it is found | Where approvals happen |
|---|---|---|
| **Extension** (desktop Nap behind it) | `nap:announceProvider` in answer to `nap:requestProvider` — EIP-6963's shape; older builds via `window.zyn` | the extension's own window |
| **Nap in the browser** | always offered; opens `https://nap.zyn-network.com/connect.html` as a popup and talks by `postMessage` | Nap's window, on Nap's origin |

The browser path is how web-only wallets do it: the keys never leave Nap's
origin, the site never draws an approval, and every message is checked both
ways — Nap answers only the window that opened it, at the origin that window
had when it first spoke; the site listens only to Nap's window at Nap's
origin. `connect.html` refuses to run in a frame.

Zcash itself has no common dApp-connection standard (MetaMask's Zcash snap
talks only to its own site; a WalletConnect-for-Zcash grant was declined in
May 2026). What Zcash wallets do share is **ZIP-321** payment requests, so
that is what `zec_pay` takes.

## Methods

Errors carry EIP-1193 codes: `4001` rejected, `4100` not connected, `4200`
unsupported, `-32602` bad parameters.

| Method | Needs | Returns |
|---|---|---|
| `nap_connect {network?}` | the holder's approval, once per site | `{account, network, chain, zcash: {network, address} \| null}` |
| `nap_session` | nothing; never prompts | the same, or `null` |
| `nap_disconnect` | — | `true` |
| `zec_getAddress` | connected | `{network, address}` |
| `zec_pay {uri}` or `{address, amount, memo?}` | connected + approval | `{txid}` (browser) / a job (desktop) |
| `zyn_nftOffers` | nothing (public order book) | `{offers}` |
| `zyn_nftItems`, `zyn_owed` | connected | `{items}`, `{owed}` |
| `zyn_nftBuy {item, pay}`, `zyn_nftList {asset, price}`, `zyn_nftCancel {asset}`, `zyn_nftRedeem {asset}` | connected + approval | what happened |
| `zyn_collect` | connected (no prompt: it only moves what the ledger already owes you) | what arrived |
| `zyn_curves` | nothing (public) | `{curves, terms, curve}` |
| `zyn_curveHoldings` | connected | `{zec, holdings: [{token, symbol, name, amount}], created: [{token, symbol, name}]}` — `created` is shown only to its holder |
| `zyn_curveCreate {symbol, name, description?, image?}` | connected + approval | `{token, content?: {hash, proof}}` — `image` is a PNG/JPEG/WebP/GIF data URL; post `{content, proof}` to your content store, which checks the proof with `verifyContentProof` (nap-web `object.js`) |
| `zyn_curveBuy {token, amount, minTokens?}`, `zyn_curveSell {token, tokens, minZec?}`, `zyn_swap {pool, sellA, amount, slippageBps?}` | connected + approval | `{order}` — settles at the seal; collect with `zyn_collect` |

Connecting shows the site the Zyn account and a Zcash address — never a
balance, a note or a key. An unconnected site that asks for anything about
the holder gets the connect prompt first. Every write is prepared from what
the chain says (the listed price, the item) and a site's claim that differs
is refused.

## Testing it end to end

```sh
# three servers: a relay to testnet's block server, Nap, and the Cave store
node <relay.mjs> <testnet-block-server> 8098 18095
(cd ../nap-web && npm run build && NAP_DEV_ZEC=http://127.0.0.1:18095 \
  NAP_DEV_RPC=https://zyn-rpc.cavebro.win/object npx vite preview --port 4179)
(cd ../cave-market && python3 -m http.server 4178 --bind 127.0.0.1)

npm i && npm run e2e                                # store ⇄ Nap in the browser, 16 checks
CHROMIUM=<Chrome for Testing> npm run e2e:extension # store ⇄ extension, 5 checks
```

The store reads `?nap=` (where Nap lives) only on localhost; on the real
domain a link that swapped the wallet's address would be a phishing kit.
