# Nap recovery and browser release — 2026-09-12

Work for #15 and #16 is published in PR #19, but neither issue is complete.
Do not enable automatic migration or use this build for the funded event yet.

## Decisions

- One BIP-39 seed derives the network-independent Zyn identity with the
  versioned HKDF domain `nap.zyn.ed25519.v1`; old independent keys stay intact.
- Identity replacement uses a durable rollback journal, not delete-then-open.
  Old recovery material is retained locally in a protected backup directory.
- Browser secrets live in memory only. Generation requires offline-backup
  acknowledgement. Restores accept supported English BIP-39 phrase lengths.
- Every send has an immutable recipient review, a fresh chain check and a
  signed ownership read. Accepted or queued is not anchored finality.
- Media is verified before rendering, bounded and restricted to raster types.
  The same-origin gateway still learns which content was requested; no claim
  of private media retrieval is made.
- Automatic legacy migration fails closed until its full recovery/settlement
  design is implemented. Green CI alone does not make migration safe.

## Backlog / remaining acceptance gates

### #15

- Resumable migration journal, immutable inventory review, verified transfer
  completion, and coverage of pending orders, escrows, vesting and authorities.
- Preserve and export non-rotatable legacy authority after any account switch.
- App-boundary verification of the protected file-export flow. Complete
  backups are now written directly by the wallet process; the UI gets a path
  only, and `/api/export` omits legacy Zyn seed material.
- End-to-end create/export/delete/restore with NFT holdings and failure
  injection at the App boundary; helper-level rollback tests already pass.

### #16

- Agree and implement the #13 coordinator contract, retry/status protocol and
  honest rejected/pending/sealed/anchored tracking. Current client submission
  is not an end-to-end claim service.
- Current mobile Safari and Chrome acceptance, clearing-site-data restore,
  and deployed HTTPS/CSP/proxy configuration verification.
- Real verified collection gateway integration (#17/#8), consent/disclosure
  for media requests, and event dry run using disposable testnet assets.
- Atomic versioned offline shell caching if offline launch is later desired.

## Runbook

1. Back up existing wallet files and independently generated `zyn.key` before
   testing. Never place real recovery material in the source tree or fixtures.
2. Run `cargo test -p zynzapd --lib` and `cargo check -p zynzapd --all-targets`.
3. In `apps/nap-web`, run `npm ci`, `npm test`, and `npm run build`.
4. For local UI testing only, run `node tests/fixture-server.mjs` and open port
   4174. Its signed-read/transfer verifier uses Node/OpenSSL and no chain.
5. On restore interruption, preserve `nap-restore-pending.json` and the
   referenced `restore-backup-*` directory. Restart Nap to roll back before
   loading either identity. If rollback fails, repair filesystem access first;
   do not bypass the journal or invent a replacement seed.
6. A leftover `wallet-*.restore` is staged recovery material. Preserve/inspect
   it before retrying; Nap refuses to overwrite a previous staging file.
7. Backups contain secrets even when installation succeeded. `index.json`
   identifies original paths; protect retained copies with the same care as
   the active wallet. No automatic backup deletion is performed.
8. Before deployment, configure same-origin `/rpc`, `/claim`, `/media` and
   required HTTP security headers from the browser README. No mainnet mint,
   transfer, deployment or migration was performed as part of these checks.

## Evidence

- 83 Rust library tests passed, including private file export, two-key replacement,
  failed-install rollback and interrupted-install recovery.
- 9 browser tests passed, including independent OpenSSL derivation/signature
  checks, manifest truncation/size validation and wrong-chain rejection.
- Browser production build and daemon all-targets check passed.
- Controlled in-app browser: public-vector restore, signed holdings read,
  verified raster art, immutable recipient review, independently verified
  one-item relay and explicit accepted-not-final result; wrong-chain refresh
  clears holdings and displays an unavailable warning.
- Mobile device testing, coordinator integration and funded recovery drill
  have not been performed. Keep #15 and #16 open.
