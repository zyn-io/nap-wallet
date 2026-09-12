# NFT custody in Nap Wallet

Nap keeps NFT custody in the **Items** tab. The generic asset form remains for
fungible transfers; an NFT transfer always moves one whole item.

## Receive

Open **Items** and share the 64-character Zyn account ID with **Copy** or its QR
code. The QR contains those exact hexadecimal characters. It does not use an
unregistered wallet URI scheme and it never contains recovery material.

## Review an item

Selecting an item shows its asset ID, content commitment, collection phase and
supply, pool backing, and redeem value. Until Nap has a privacy-reviewed media
resolver that verifies downloaded bytes against the committed content ID, it
uses a deterministic identicon. A content hash is not treated as a remote image
URL.

## Send

1. Select the item and choose **Send this NFT**.
2. Enter the recipient's 64-character hexadecimal Zyn account ID.
3. Review the full account, asset ID, fixed amount of one, settlement path, and
   the fact that the item leaves this wallet.
4. Confirm the transfer.

Leave the Zcash recovery option disabled for an ordinary transfer. Enable it
only when the Zyn node is censoring the signed transfer; it uses the existing
forced-inclusion path and its Zcash fee and delay.

Redeem is not send. Redeeming destroys a live collection item and pays its
share of backing ZEC, so Nap presents a separate two-step confirmation.

## Implementation boundary

`zynzapd::app::zyn_overview` returns the account ID and its QR SVG. The shared
wallet page posts `/api/transfer` with `{to, asset, amount: "1", force}`. The VM
remains authoritative and rejects fractional quantities for indivisible items.
The same `zynzapd/ui/index.html` source is copied into the Tauri application by
`apps/nap/build-ui.mjs`.

## Verification

```sh
cargo test -p zynzapd --bin nap-wallet
cargo test -p swapvm --test chain an_unwrapped_asset_cannot_be_fractionalised -- --exact
cargo test -p swapvm --test chain an_item_cannot_be_ended_by_a_partial_holder -- --exact
npm --prefix apps/nap run ui
cmp -s zynzapd/ui/index.html apps/nap/dist/index.html
```

Also exercise the Receive value, QR code, transfer review, confirmation, and
error states at desktop and compact widths before a release.
