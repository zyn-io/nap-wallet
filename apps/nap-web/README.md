# Nap Web

Browser-first, non-custodial Nap for Zyn accounts, NFT claims, verified media,
and one-item transfers. It deliberately does **not** claim to implement the
shielded Zcash wallet in a browser; use desktop Nap for Zcash operations.

## Run

```sh
npm ci
npm test
npm run dev
```

`npm run build` writes the deployable static site to `dist/`. This is a
pre-release browser target, not an event-ready deployment. It has no
third-party runtime scripts, analytics, remote fonts, or secret persistence.
The 24-word phrase and its derived Ed25519 seed exist only in the live page;
locking, closing, or reloading the tab forgets them.

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
- Raw seed material is never written to `localStorage` or IndexedDB.
- BIP-39, HKDF-SHA256, Ed25519, and QR dependencies are pinned in
  `package-lock.json` and bundled locally.
- Account reads use the signed-read payload accepted by `zyn_account`.
- Transfers are encoded and signed locally, then relayed byte-for-byte through
  `zyn_sendRawIntent`.
- The chain id is shown on every screen and a mismatched endpoint fails closed.
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

Local UI regression fixture, with independent signature verification and no
real funds: `npm run build`, then `node tests/fixture-server.mjs`, then open
`http://127.0.0.1:4174/`. Use only the public test mnemonic in the test suite.
See [release status and runbook](../../docs/NAP-RELEASE.md).
