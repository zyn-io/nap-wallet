# Nap Zyn key derivation v1

Status: normative for new mnemonic-backed Nap wallets.

## Contract

Inputs are the 64-byte BIP-39 seed (including the optional BIP-39 passphrase)
and the ZIP-32/BIP-44 account index as an unsigned 32-bit integer below `2^31`.
Derive the 32-byte Ed25519 seed with HKDF-SHA256:

```text
IKM  = BIP39-Seed(mnemonic, passphrase)       # exactly 64 bytes
salt = UTF8("nap.zyn.ed25519.v1")
info = UTF8("account") || U32_BE(account)
OKM  = HKDF-SHA256(IKM, salt, info, 32)
```

Use `OKM` as the RFC 8032 Ed25519 seed. The public key becomes the Zyn account
under the existing rule:

```text
account_id = SHA256(UTF8("zyn.account.v1") || 0x01 || U32_BE(32) || public_key)
```

The derivation is versioned by its salt and is deliberately **not** scoped by
Zcash network or Zyn chain. This matches Nap's historical single `zyn.key`
identity and lets one phrase restore one Zyn identity on browser and desktop.
It also correlates that public account across chains; users who need separation
must choose another account index. Signed reads/intents bind a chain id, so the
shared identity does not permit cross-chain replay.

Derive from BIP-39 seed bytes—not normalized display text, an Orchard child,
or a transparent child. Desktop source of truth is `Wallet::zyn_signing_key`;
browser source is `apps/nap-web/src/core.js`.

## Test vectors

Both vectors use this 24-word mnemonic:

```text
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art
```

| Passphrase | Index | Ed25519 seed | Public key | Zyn account |
|---|---:|---|---|---|
| empty | 0 | `57d47cefdba062bb9669a7a64e9072e49d2b5bc66892952429240e4c91b16183` | `308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a6` | `b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea` |
| `nap passphrase` | 7 | `f4e1b20f8a0cd2e19ae9d85ce3057cbb13863be3630e87972afce0b14c513c2e` | `276237e6804911ecd6d44c3d170ac67ff8dc8abf87cf423489a71dddf68857eb` | `4c976ef0d248340b910e246439c3139911f1752e6ba1d3c198f41071e4503604` |

The fixture suite additionally pins the complete epoch-42 signed-read payload,
ZynZap v2 VM id, transfer intent, Ed25519 signature, and submission frame in
both Rust and JavaScript.

## Backups and compatibility

Nap backup version 2 adds a `zyn` object:

- Derived: `{"source":"bip39-hkdf","version":1,"account":0,…}`. No
  duplicate Zyn secret is needed.
- Legacy: `{"source":"legacy-ed25519","seed":"<64 hex>"}`. The independent
  seed is recovery-critical and is deliberately included in the explicit
  secret backup.

Version-1 backups still parse. A v1 backup never contained the independently
generated Zyn seed, so it cannot promise restoration of that legacy account;
Nap reports whether an imported backup carried complete Zyn material.

New mnemonic wallets write a non-secret derivation descriptor at `zyn.key`.
Existing 32-byte `zyn.key` files are treated as legacy and are never silently
replaced. `/api/zyn-key` inventories movable holdings and non-transferable
creator authorities. `POST /api/zyn-key/migrate` requires explicit
`{"confirm":true}`, cancels open offers, moves spendable balances/items, clears
old agent sessions and account-local binding state, and preserves the old seed
as `zyn.key.legacy`. That file remains necessary for collection creator
authority until the protocol gains authority rotation.
