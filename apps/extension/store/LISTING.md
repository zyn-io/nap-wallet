# Nap Wallet — store listing

Everything a store form asks for, in the order the Chrome Web Store dashboard
asks it. Firefox Add-ons (AMO) asks for a subset; its notes are at the end.

Packages: `apps/extension/release/nap-wallet-<version>-chrome.zip` and
`…-firefox.zip` (built by `npm run build` in `apps/extension`).

## Store listing

**Name:** Nap Wallet

**Summary** (≤132 characters):
A private wallet for Zcash and Zyn: shielded ZEC, Zyn tokens and items, and approvals for sites. Keys stay on your device.

**Description:**

Nap Wallet is a private wallet for Zcash and Zyn that lives in your toolbar.

• Shielded ZEC — receive at your own shielded address and send from it. The Zcash wallet runs inside the extension.
• Zyn tokens and items — ZEC.zy, bridged SOL.zy and ETH.zy, launchpad tokens, pool shares and collectibles, in one pocket.
• Nap Market — swap and provide liquidity in batches: everyone trading in an epoch pays one price, so nobody can jump the queue.
• Sites ask, you decide — sites such as the Cave store and Cave Jade can ask Nap to connect or to trade. Nap's own window shows what the chain says the request would do, and nothing moves until you approve it.

Your keys stay on your device. Nap never stores your recovery phrase; if you choose to keep the wallet on this device, the key is sealed under a password you set. No account, no email, no analytics.

The same recovery phrase opens Nap in the browser at nap.zyn-network.com.

**Category:** Productivity → Tools (Chrome has no finance category for extensions)
**Language:** English

**Graphic assets** (`apps/extension/store/`):
- Icon: 128×128 is inside the package (`icons/128.png`)
- Screenshots (1280×800): `screenshot-0-popup.png` (the toolbar wallet — lead with it), `screenshot-1-keys.png`, `screenshot-2-pocket.png`, `screenshot-3-approve.png`, `screenshot-4-market.png`
- Small promo tile (440×280): `promo-small-440x280.png`

**Official URL / Homepage:** https://nap.zyn-network.com
**Support URL:** https://x.com/cavebrowin

## Privacy practices

**Single purpose:**
A cryptocurrency wallet for Zcash and Zyn: it holds the user's keys on their device, shows their balances, sends transactions they approve, and lets websites request connections and transactions that the user approves in the wallet's own window.

**Permission justifications:**

| Permission | Why |
|---|---|
| `storage` | Remembers which window is Nap's approval window for the current browser session, so a second request focuses it instead of opening another. (The wallet's own settings and its password-sealed key live in the extension's page storage.) |
| Host `https://nap.zyn-network.com/*` | Nap's server: the wallet reads the Zyn and Zcash networks and sends the user's signed transactions through it. It is the only host the extension talks to. |
| Content script on `https://*/*` (and localhost for development) | Adds the Nap provider to web pages so a site can ask Nap to connect or to approve a transaction. The script reads nothing from the page; it only passes the site's requests to Nap's window, where the user decides. |

**Remote code:** No. All code is in the package. (`'wasm-unsafe-eval'` in the extension's policy lets the packaged Zcash wallet, compiled to WebAssembly, run; no code is fetched.)

**Data usage** — tick:
- **Financial and payment information** — the transactions the user signs are sent to the network through Nap's server. That is the only data that leaves the device.
- Nothing else (no personally identifiable information, health, authentication, personal communications, location, web history or user activity, website content).

Certify: not sold to third parties; not used or transferred for purposes unrelated to the single purpose; not used to determine creditworthiness or for lending.

**Privacy policy URL:** https://nap.zyn-network.com/privacy

## Distribution

Public, all regions (or limit regions if you prefer). Free.

## Firefox Add-ons (AMO)

- Upload `nap-wallet-<version>-firefox.zip`. Add-on id: `nap-wallet@cavebro.win`.
- The package's JavaScript is built and minified by Vite, so AMO asks for **source code**: upload `nap-wallet-<version>-source.zip` (made by `npm run source` in `apps/extension`); its `BUILDING.md` is the reviewer's build instructions.
- Data collection is declared in the manifest (`financialAndPaymentInfo`), matching the table above.
- Same summary, description, category (**Other** or **Privacy & Security**), screenshots and privacy policy URL.
- `web-ext lint` on the Firefox build: 0 errors, 0 notices; the warnings are HTML the wallet writes after escaping every value.
