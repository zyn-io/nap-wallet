# Nap Wallet

<p align="center">
  <img src="apps/nap/icon.png" width="128" alt="Nap Wallet icon">
</p>

Nap is a self-custodial Zcash wallet with native support for Orchard and
Ironwood, transparent deposits that can be swept into the shielded pool, and a
bounded command-line interface for AI agents acting on Zyn.

The wallet keeps recovery material, scanning, transaction construction,
proving, and signing in the local Rust process. The browser page, Tauri desktop
shell, and browser extension are interfaces to that same core.

## Status

Nap is experimental software under active development. The code has not had an
independent security audit. Mainnet must be configured explicitly; the bundled
defaults point at the current Zyn testnet services.

## Features

- Shielded ZEC receive and send with encrypted memos.
- Orchard and Ironwood scanning through `zyn-lightd`.
- Transparent receive with a one-way **Make it private** sweep.
- New wallets backed by 24-word BIP-39 phrases.
- ZIP-32 Orchard accounts and BIP-44 transparent receivers.
- Versioned portable backups with network, birthday, account, and recovery
  material.
- Mainnet and testnet wallets kept separately.
- Desktop, local web, and browser-extension interfaces from one wallet core.
- Swap-only AI mandates enforced by committed Zyn authorization, with a
  restricted `nap-agent` CLI.
- Locally hosted fonts; opening the wallet does not fetch Google Fonts.

Nap currently scans Orchard, Ironwood, and transparent funds. It does not scan
Sapling, so importing a phrase from another Zcash wallet may show only the
supported pools.

## Run the local wallet

Install a current stable Rust toolchain, then run:

```sh
cargo run -p zynzapd --bin nap-wallet
```

Open <http://127.0.0.1:8977>. On first launch, Nap creates separate wallet
records under `~/.zyn/app`. Open **Settings → Backup** and save the recovery
phrase or portable JSON backup offline before funding the wallet.

Useful overrides:

```sh
ZYN_APP_DIR=/path/to/private/data \
ZYN_LIGHTD=host:port \
cargo run -p zynzapd --bin nap-wallet
```

Keep `ZYN_APP_DIR` outside the repository. Wallet records and exported backups
are plaintext secrets and should be readable only by their owner.

## Desktop app

Install Node.js and the [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/), then:

```sh
cd apps/nap
npm install
npm run tauri dev
```

The build command copies the canonical UI and bundled OFL fonts from
`zynzapd/ui` into `apps/nap/dist`.

## Browser extension

The extension is a face for the local wallet process and holds no private keys.
Start `nap-wallet`, then build the unpacked extension:

```sh
cd apps/extension
node build.mjs
```

Load `apps/extension/dist` as an unpacked extension in a Chromium browser.

## Recovery CLI

```sh
# Write a complete portable backup.
zyn-wallet backup ~/.zyn/app/wallet-testnet > nap-testnet-backup.json
chmod 600 nap-testnet-backup.json

# Restore the portable backup into a new path.
zyn-wallet import-backup restored.wallet nap-testnet-backup.json

# Restore BIP-39 words without placing them in shell history.
zyn-wallet import-mnemonic restored.wallet phrase.txt <birthday-height> [account]
cat phrase.txt | zyn-wallet import-mnemonic restored.wallet - <birthday-height> [account]

# Optional BIP-39 passphrase.
ZYN_BIP39_PASSPHRASE='...' zyn-wallet import-mnemonic restored.wallet phrase.txt <birthday-height>

# Legacy raw Orchard keys remain supported.
zyn-wallet import restored.wallet <64-hex-key> <birthday-height>
```

Choose a birthday at or before the wallet's first receipt. An earlier birthday
costs scanning time; a later birthday misses funds. See
[docs/RECOVERY.md](docs/RECOVERY.md) for the backup format and compatibility
rules.

## Verify the source

```sh
cargo test -p zynzapd
cargo check -p zynzapd --all-targets

cd apps/nap && node build-ui.mjs
cd ../extension && node build.mjs && node --check dist/popup.js
```

## Repository layout

| Path | Purpose |
|---|---|
| `zynzapd/src/wallet.rs` | Wallet keys, recovery, scanning, and spending |
| `zynzapd/src/app.rs` | Shared wallet API and policy boundary |
| `zynzapd/ui` | Canonical wallet interface and bundled font licenses |
| `apps/nap` | Tauri desktop shell |
| `apps/extension` | Keyless browser-extension face |
| `zyn-custody` | Zcash note, transaction, and custody primitives |
| `zyn`, `zyn-vm`, `swapvm`, `zyn-bridge` | Zyn execution and verification used by wallet features |

Security reports should follow [SECURITY.md](SECURITY.md). Contributions are
described in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
