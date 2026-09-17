# Cave randomness engine

`cave-randomness` is the deterministic allocation core behind Cave collection
launches. It has no network, clock, database, wallet, or Zyn authority. Given
the same committed policy, manifest, tickets, and public evidence, it produces
the same allocation batch byte-for-byte.

## What is committed

`AllocationPolicy::canonical_bytes()` uses fixed-width, length-delimited binary
encoding under `cave-allocation/v1`; `digest()` domain-separates and hashes those
bytes with SHA-256. A policy commits the collection id, supply, entry price,
deposit close height, quantity policy, identity policy, manifest root, pinned
drand chain, future-round delay, and any collection reveal targets. Weighted outcomes are sorted by item
count before encoding, so JSON or form order cannot alter the promise.

Manifest leaves commit `(global index, item id, content hash)`, and every item id
must equal Zyn's canonical `item_address(ADDRESS_SCOPE_V1, collection, index)`.
Ticket leaves commit the exact Zcash transaction output, exact entry-price value,
Zyn recipient, announced beacon targets, buyer choice, and resolved quantity.
The ticket id is derived from the policy digest plus every ticket field other
than the id itself: payment, recipient, confirmed position, announced future
rounds and buyer choice. It is not selected by the operator, and none of those
fields can be changed without invalidating it. Receipts carry Merkle inclusion
proofs; the batch commits
the complete ticket ledger and final assignment. Receipts and batches have their
own versioned canonical bytes and domain-separated SHA-256 digests for stable
publication independent of a service's JSON representation.

## Randomness

- The engine pins drand Quicknet's chain hash and RFC9380 public key. Every
  supplied beacon is BLS-verified in-process. Its randomness is
  `SHA-256(signature)`, as specified by drand.
- All local seeds use HKDF-SHA256 with the policy digest as salt and distinct
  quantity, concealed-shuffle, and instant-assignment domains.
- Weighted quantities use a 64-bit rejection sampler over the sum of positive
  creator weights. There is no `0–99` rule and no modulo bias.
- Concealed identity combines the predeclared drand round, predeclared Zcash
  block height/hash, manifest root, and final ticket-ledger root, then performs
  a ChaCha20-backed Fisher–Yates shuffle.
- Instant identity binds each draw to its ticket and the ledger prefix, and
  removes selected indices from the remaining set. Sequential identity consumes
  no randomness.
- Missing, early, wrong-chain, wrong-round, or invalid beacon evidence fails the
  allocation. There is no local-randomness fallback.

## Integration boundary

The caller still has to prove facts the pure engine cannot observe:

1. the policy and manifest digest were published before the first accepted
   deposit;
2. each deposit is canonical, sufficiently confirmed, really occupies the
   supplied `(height, transaction index, output index)`, pays the committed
   entry price, and arrived at the deposit address derived for the bound Zyn
   recipient;
3. the ticket and its future drand target were durably committed before that
   round became knowable;
4. the supplied Zcash block hash is canonical at the policy's reveal height;
5. unresolved tickets reserve `policy.maximum_receipt()` items and the append-only
   ledger is persisted idempotently by ticket id and deposit outpoint.

The engine itself rejects tickets confirmed after the committed close height and
requires a concealed reveal block strictly after that close.

The service should pause when any evidence is unavailable. It must not substitute
its own clock, block hash, seed, ordering, or RNG.

## Verification

```sh
cargo test -p cave-randomness
```

The suite pins an official drand Quicknet round-42 vector plus policy and batch
digest vectors, rejects altered signatures and receipts, exercises all quantity
and identity modes, and allocates all 4,444 Collection Z indices exactly once.
