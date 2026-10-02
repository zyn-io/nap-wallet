# Nap Wallet

<p align="center">
  <img src="apps/extension/icons/128.png" width="96" alt="Nap Wallet">
</p>

Nap is a self-custodial wallet for Zcash and Zyn. It holds shielded ZEC
(Orchard and Ironwood), a transparent address with a one-step Shield, and
assets on Zyn, and it lends, borrows and trades on Zyn's markets. Keys are made
and kept on your device; sites reach Nap through Nap Connect and nothing moves
until you approve it in Nap's own window.

- **Web:** https://nap.zyn-network.com
- **Chrome extension:** [latest release](https://github.com/zyn-io/nap-wallet/releases/latest)
- **Mobile:** an iOS and Android shell around the web wallet (`apps/nap-mobile`), not in the stores yet

## Status

Experimental and unaudited. Testnet is the default; testnet coins are worth
nothing. Use mainnet only with amounts you can lose.

## Install the extension

Until Nap is in the Chrome Web Store:

1. Download `nap-wallet-chrome.zip` from the [latest release](https://github.com/zyn-io/nap-wallet/releases/latest) and unzip it.
2. Open `chrome://extensions` and turn on **Developer mode**.
3. Click **Load unpacked** and choose the unzipped folder.

Works in Chrome, Brave, Edge and Arc. To update, replace the folder's contents
and press reload on Nap's card; the wallet stays.

## Keys

A wallet is a 24-word BIP-39 phrase.

- **Zcash:** ZIP-32 Orchard (`m/32'/133'/0'`, testnet `m/32'/1'/0'`) and BIP-44
  transparent (`m/44'/133'/0'/0/0`) from the phrase's seed. The same words
  restore the same Zcash account in any wallet that restores a 24-word Zcash
  seed. Other wallets may not show Ironwood notes until they support Ironwood.
- **Zyn:** an ed25519 key from the same seed through HKDF
  (`nap.zyn.ed25519.v1`), so the Zyn account never shares a key with Zcash.

## What is here

| Path | What |
|---|---|
| `apps/nap-web` | The wallet: web, extension and mobile builds, Nap Connect's wallet side, tests |
| `apps/nap-web/zec-core` | Zcash in WebAssembly: keys, scanning, proving (built output committed in `src/zec-pkg`) |
| `apps/nap-web/pool-core` | The private channel's prover in WebAssembly (built output in `src/pool-pkg`) |
| `apps/extension` | Packages the extension build for Chrome and Firefox |
| `apps/nap-mobile` | Tauri shell for iOS and Android |
| `apps/nap-connect` | The SDK sites use to find and talk to Nap |
| `zyn-vm`, `zyn-bridge`, `zyn-custody`, `zyn-pool` | The Zyn and Zcash libraries the WebAssembly cores build from |

## Build

```sh
cd apps/nap-web && npm ci
npm test                      # unit tests
npm run build                 # the web wallet, into dist/
npm run build:extension       # the extension's pages
cd ../extension && npm run build   # zips into release/
```

Rebuilding the WebAssembly is only needed when its Rust changes: see
`apps/nap-web/zec-core/build.sh` and `apps/nap-web/pool-core/build.sh`
(the wasm32 target, wasm-bindgen-cli 0.2.128, and for zec-core a clang that
targets wasm32).

Nap is developed inside the Zyn workspace and published here from it.

## License

MIT. See [LICENSE](LICENSE). Report security issues as described in
[SECURITY.md](SECURITY.md).
