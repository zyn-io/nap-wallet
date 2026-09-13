# NFT ownership privacy: public readers versus trusted operators

Decision date: 13 September 2026. Local source: DECISIONS §70 and BACKLOG P0–P4.
Status: chosen scope; implementation and live deployment verification pending.

## Decision

The near-term target is to hide NFT ownership from public readers while trusting
authorized sequencer and replay-verifier operators. It is not operator-private
execution, formal unlinkability, anonymity, or hidden activity timing. Senders,
recipients, event issuers and opted-in public listings disclose information by
design. An authorized operator can copy or leak plaintext.

The earlier §21 claim that intents are never published is historical. Current
`zynzapd/src/publish.rs` includes raw epoch intent journals in availability
bundles. `swapvm/src/wire.rs` encodes transfer endpoints and asset, mint recipient,
and the Reblind value in those bytes. Hash-only snapshots and signed account
reads do not protect ownership from someone who obtains the journal.

This is evidence about source behavior, not a completed audit of live mirror
exposure. No production access controls, retention or publication are changed
by this planning work.

## Architecture constraints

- Separate allowlisted public commitments/anchors/certificates and reviewed
  aggregate/catalog information from confidential full journals, base states,
  private records and ownership-bearing proofs. Review hash/index/order/timing
  inference too; absence of plaintext is not a proof of unlinkability.
- Choose and test confidential authenticated distribution, reader authorization,
  provisioning, rotation/revocation, cache policy and diagnostic redaction.
  Exact mechanisms remain design work; hiding only NFT opcodes is insufficient
  in a shared replay journal.
- Authorized independent verifiers must continue to replay and reject invalid
  state, preserving backing/quorum checks. Restricting their inputs reduces
  unrestricted public replay. Public roots or operator certificates are not an
  equivalent substitute for permissionless execution verification.
- Preserve authenticated holder access and durable export of anchored records
  and inclusion/exit witnesses. Test recovery, outage and forced-exit behavior;
  state any dependence on previously retained witnesses. Do not change live
  publication until this recovery contract and its tests pass.
- Fresh receiving accounts require recoverable, versioned derivation and tested
  account discovery. Blinding requires confirmed execution and a confidential
  journal path. A disclosed blind is not secret; future rotation cannot undo
  already public ownership history.
- Review offers, public listings, claims, explorers, logs and media requests so
  these surfaces do not publish an alternate owner map. Public listings must
  require informed opt-in where they disclose ownership.
- Set a future chain/epoch privacy cutoff. Do not promise to erase previously
  distributed records. A rollback to plaintext publishing must not silently
  expose transactions submitted under a privacy expectation.

Aliases and operator-private NFT notes/nullifiers/zero-knowledge proofs are
explicitly deferred; neither is implemented by this workstream.

## Backlog and acceptance

| Local ID | GitHub issue | Dependencies | Required evidence |
|---|---|---|---|
| P0 | [#21 — Disclosure audit and threat model](https://github.com/zyn-io/nap-wallet/issues/21) | First | Artifact/reader/metadata matrix, synthetic leakage fixture, separately documented live exposure and corrected claims |
| P1 | [#22 — Restricted replay with verification and recovery](https://github.com/zyn-io/nap-wallet/issues/22) | P0; coordinate #1/#15 | Unauthorized access denial; authorized root reproduction/tamper rejection; holder proof export, restore and outage/exit drills; explicit public-replay tradeoff |
| P2 | [#23 — Recoverable receiving accounts and blinding](https://github.com/zyn-io/nap-wallet/issues/23) | P1; #15/#16 | Exact account/item recovery after clearing browser state; initialization/rotation ordering; no false privacy status; preserved legacy authority |
| P3 | [#24 — Secondary ownership disclosures](https://github.com/zyn-io/nap-wallet/issues/24) | P0; integrates #6/#8/#13/#16/#17 | Public/network/log inspection through receive/view/claim/list/sell; explicit listing disclosures; private claim allocations; existing media-privacy checks |
| P4 | [#25 — Integrated rollout gate](https://github.com/zyn-io/nap-wallet/issues/25) | P0–P3 | Leakage plus replay/backing/quorum/recovery/outage/exit/revocation tests; disposable-testnet rollout and rollback; documented chain/epoch cutoff |

These acceptance tests are requirements to implement, not claims of completed
testing. Existing claim and media issues keep their implementation scope; P3
coordinates them instead of creating another claim service or gateway.

No mainnet action, live mirror restriction, cache purge, history deletion,
automatic wallet migration or funded event launch is authorized by these issues.
