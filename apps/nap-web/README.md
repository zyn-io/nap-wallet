# Nap Web

Browser-first, non-custodial Nap: a wallet. Zyn coins with what each is worth,
items with their verified pictures, sends, ZEC in and out of the object ledger
(deposit address, withdrawal), payouts collected as they come due, approvals
for the sites that use it (Nap Connect: `/connect.html`) — and a shielded
**Zcash wallet**:
the desktop wallet's own core (`zec-core/`, Rust → WebAssembly) syncs, receives
and proves payments in a Web Worker, reaching the block server through the
same-origin `/zec/<network>` function (DECISIONS §139). The same phrase opens
the same ZEC in desktop Nap.

`src/zec-pkg/` is built output, committed so the site builds without Rust;
regenerate it with `zec-core/build.sh` after touching `zyn-custody`.

## Run

```sh
npm ci
npm test
npm run dev
```

`npm run build` writes the deployable static site to `dist/`. This is a
pre-release browser target, not an event-ready deployment. It has no
third-party runtime scripts, analytics, or remote fonts.

By default nothing is persisted: the 24-word phrase and its derived Ed25519
seed exist only in the live page, and locking, closing, or reloading the tab
forgets them.

## A wallet, not a market

Lending, bridging (SOL, ETH, BTC, BOLD), the launchpad and the Collection Z
store and sale are sites — Zyn Lend, Jade, Cave — that ask Nap to approve what
they do, the way a site asks MetaMask or Phantom. Nap lists them under Apps.
`/market.html` and `/bridge.html` are gone; `public/_redirects` sends old
links to Jade and to Zyn Lend's Bridge.

- **Worth** is in dollars at the prices posted on Zyn for its lending markets
  (`zyn_lendMarkets`); a lending share is valued at its pool's share price. A
  coin with no posted price shows none.
- **Pictures.** Collection Z's image hashes ship with Nap in
  `public/art/<collection>.bin` (4,444 × 32 bytes, serial order, from
  cavebro.win/collection-z.json). A picture is fetched from `/media/<hash>`
  only after the holder turns on Show artwork, and shown only if its bytes
  hash to that name and it is a PNG of sane size (`src/items.js`).
- **What is owed is collected, not pushed.** Swaps and loans made on sites pay
  out as claims, and coins bridged in through a site wait under this wallet's
  one-time codes; Nap collects both when it reads the ledger.

## Keeping a wallet on a device

Re-typing 24 words on every reload is not a security property, it is a reason
to write them somewhere worse. A holder may opt in to keeping the wallet here,
under a password:

- **What is stored is the derived Ed25519 key, never the phrase.** The words
  also control the Zcash wallet and may be reused elsewhere; the derived key
  controls one Zyn account at one index and nothing else. A cracked record
  costs that account, not the seed behind it.
- Sealed with **AES-256-GCM** under **PBKDF2-SHA256, 600,000 iterations**
  (OWASP's current floor), salt and IV per record.
- A wrong password and a tampered record fail identically — GCM authenticates,
  and saying which would tell someone holding a stolen file they are close.
- A record naming weaker KDF settings is refused before the password is tried,
  so editing the stored iterations down does not make a later brute force
  cheaper.

**This changes the threat model and should be understood before it is used.**
Without it, an attacker needs the live tab. With it, ciphertext is on the disk:
anyone who takes the file can guess offline for as long as they like, and the
password is then the whole of the security. It is off unless asked for, and
"Forget this device" removes it.

## Deployment boundary

Serve the site over HTTPS and edit `public/config.json` before building:

- `chain` is the pinned Zyn chain id.
- `rpcUrl` is the same-origin reverse proxy to `zyn-rpc` JSON-RPC.
- `claimUrl` is the same-origin reverse proxy to the narrow gift coordinator.
- `mediaGateway` serves content-addressed blobs at `/<64-hex-hash>`.

The shipped CSP permits connections only to the same origin. This is
intentional: deploy `/rpc`, `/claim`, and `/media` as reverse-proxy routes
instead of weakening the policy or publishing the event custody key. The RPC
receives signed reads and signed submission frames only. The claim coordinator
receives a one-time card code, public account id, chain id, and one stable
idempotency key bound to the exact code/account/chain across retries and reloads.
Use `/#claim=<opaque-secret>` links, not query parameters: fragments do not
reach the HTTP server. Legacy query links are scrubbed immediately in the page,
but deployment access logs must also redact them.

Expected claim endpoint:

```text
POST /claim/api/claims
Idempotency-Key: <sha256 of JSON ["nap.claim.v1",code,account,chain]>
{"code":"<opaque secret>","account":"<64 hex>","chain":11}

200 {"state":"reserved|submitted|settled","seq":123,"asset":456}
409 {"state":"already_claimed","message":"…"}
```

## Security checks

- Recovery acknowledgement gates creation.
- Raw seed material is never written to `localStorage` or IndexedDB. A kept
  wallet stores only the sealed key (see above), never the phrase or the seed.
- BIP-39, HKDF-SHA256, Ed25519, and QR dependencies are pinned in
  `package-lock.json` and bundled locally.
- Account reads use the signed-read payload accepted by `zyn_account`.
- Transfers are encoded and signed locally, then relayed byte-for-byte through
  `zyn_sendRawIntent`.
- The chain id is shown where it decides something — on the send review,
  beside the destination — and a mismatched endpoint fails closed regardless.
- Manifest and image bytes are SHA-256 verified before artwork replaces the
  generic, explicitly unverified placeholder. Manifest responses are limited
  to 256 KiB and PNG images to 8 MiB/4096×4096; IHDR dimensions are checked
  before decoding. Other formats, including SVG/HTML, are not rendered yet.
- Rust and browser tests assert the same complete signed-read and transfer
  frames, not merely the same account id.

The gift service itself remains tracked separately because recipient code
must never gain event custody authority.

## Release gates

Claims currently implement a **proposed client contract**, not a deployed #13
coordinator. They report service state without claiming verified finality.
Receipt/lifecycle tracking and current mobile Safari/Chrome acceptance remain
open in #16. Do not distribute funded gift cards against this build yet.

The service worker does not cache pages or requests. Offline signing is not
supported; every transfer requires a fresh chain check and signed holdings read.
Serve `Content-Security-Policy` as an HTTP header with `frame-ancestors 'none'`
(browsers ignore that directive in a meta tag), `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on HTML/config and
RPC/claim responses. Never cache claim URLs or deploy third-party scripts.

Use only the public test mnemonic in the test suite.
See [release status and runbook](../../docs/NAP-RELEASE.md).
