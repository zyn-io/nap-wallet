# Contributing

Changes should keep the three wallet faces on one implementation. Edit the
canonical UI in `zynzapd/ui/index.html`; regenerate the desktop and extension
copies instead of editing files under `dist`.

## Development checks

```sh
cargo test -p zynzapd
cargo check -p zynzapd --all-targets

cd apps/nap
node build-ui.mjs
cmp -s ../../zynzapd/ui/index.html dist/index.html

cd ../extension
node build.mjs
node --check dist/popup.js
```

Tests that contact live Zcash, Solana, or price services are ignored by default.
Do not turn them into required CI checks.

For key or backup changes, add a fixed derivation vector and a round-trip test.
Preserve support for legacy 32-byte wallet files unless a migration plan proves
that existing funds remain recoverable.

Never add wallet files, exported backups, `.env` files, credentials, service
tokens, or production endpoints carrying embedded secrets to a commit.
