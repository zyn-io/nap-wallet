# Wallet recovery and backup format

Nap supports two key sources.

New wallets generate 256 bits of entropy and display them as 24 English BIP-39
words. For a selected network and account, the wallet derives the Orchard
spending key at:

```text
m/32'/coin_type'/account'
```

The transparent receiver uses BIP-44:

```text
m/44'/coin_type'/account'/0/0
```

The BIP-39 seed, including its optional passphrase, is the common root of both
derivations. Mainnet uses coin type 133; testnet uses coin type 1.

Legacy Nap wallets are exactly 32 bytes containing an independently generated
Orchard spending key. They keep their original behavior and cannot be converted
into an equivalent mnemonic. Their transparent receiver continues to derive
from those bytes so existing transparent funds stay recoverable.

## Portable backup version 1

Mnemonic-backed wallet:

```json
{
  "format": "nap-wallet-backup",
  "version": 1,
  "network": "mainnet",
  "birthday": 3000000,
  "source": "bip39",
  "mnemonic": "<24 English BIP-39 words>",
  "passphrase": "",
  "account": 0,
  "derivation": "m/32'/133'/0'"
}
```

Legacy raw-key wallet:

```json
{
  "format": "nap-wallet-backup",
  "version": 1,
  "network": "testnet",
  "birthday": 4321000,
  "source": "raw-orchard",
  "spending_key": "<64 lowercase hex characters>"
}
```

`format` and `version` are mandatory. Restore refuses unknown versions, a
network different from the active wallet network, malformed recovery material,
or a birthday above the connected block server's tip.

The JSON is a Nap portability envelope. BIP-39 and ZIP-32 are standard Zcash
recovery inputs; there is no claim that the JSON envelope is a universal Zcash
wallet-file format.

## Pool coverage

A mnemonic restore recovers the selected account's Orchard and Ironwood notes
and its first external transparent receiver. Nap does not currently scan
Sapling. Keep another compatible wallet available when a restored seed has
Sapling history.

## Handling

The recovery phrase, BIP-39 passphrase, raw spending key, internal wallet key
record, and portable backup each control funds. Do not commit them, attach them
to bug reports, paste them into chat, or store them beside the source tree.

Nap creates wallet key records with mode `0600` on Unix. After redirecting a
CLI backup, set its permissions explicitly:

```sh
chmod 600 nap-wallet-*-backup.json
```
