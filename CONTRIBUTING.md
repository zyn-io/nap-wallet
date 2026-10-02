# Contributing

Nap is developed inside the Zyn workspace and published here, so a pull
request is applied there and comes back in the next sync.

## Checks

```sh
cd apps/nap-web && npm ci && npm test
npm run build:extension && cd ../extension && npm run build && npm test
cargo test --workspace          # from the repository root
```

For any change to keys or backups, add a fixed derivation vector and a
round-trip test. Never commit recovery phrases, keys, wallet files, `.env`
files or service tokens.
