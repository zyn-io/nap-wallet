//! ZynZap's state commitment.
//!
//! The primitives — the encoder, the tree, the inclusion path — are the
//! microchain spec's, in `zyn_vm::commit`, because a settlement verifier and a
//! light client have to agree with them byte-for-byte across every application.
//! What lives here is the part that is genuinely ZynZap's: which fields go
//! into which leaf, and how the sections are laid out.
//!
//! Four sections, in the order the spec fixes:
//!
//! ```text
//!   0  header    every scalar field of the chain
//!   1  accounts  holder balances and pending exits  <- the exit hatch opens this
//!   2  tokens
//!   3  pools
//! ```
//!
//! Sections 0 and 1 are the spec's; 2 and 3 are ZynZap's. Committing them
//! separately is what lets a client be handed a proof of one balance without
//! being handed every pool in the chain.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub use zyn_vm::commit::{
    fold_intent, hash_leaf, hash_node, merkle_proof, merkle_root, verify_proof, Encoder, Hash,
    ProofIndex, ProofStep,
};

use crate::fixed::Fixed;
use crate::state::SwapState;
use crate::types::{AccountId, Params};
use crate::wire::encode_launch;

pub(crate) fn encode_params(e: &mut Encoder, p: &Params) {
    // **S5.** Every field here changes what a future transition does, so every
    // field has to be committed. `exit_timeout_epochs` and
    // `reference_staleness` were round-tripped by the codec but missing from
    // this function for a while: two nodes configured differently would have
    // agreed on the root and disagreed on whether an exit could be cancelled.
    // A field added to `Params` and not added here is invisible to the only
    // check that would catch it.
    e.u16(p.default_fee_bps)
        .fixed(p.min_liquidity)
        .u8(p.max_hops)
        .u16(p.protocol_fee_share_bps)
        .bytes(&p.treasury)
        .fixed(p.min_pool_xzec)
        .u64(p.exit_timeout_epochs)
        .u64(p.reference_staleness);
}


/// Every account proof for one state root, served without rebuilding the tree.
///
/// The read path an endpoint needs. `SwapState::account_proof` hashes every
/// leaf and scans the account map on each call, which is correct for a proof
/// taken once and hopeless for a node serving them: measured at 50,000
/// accounts it is 26 ms per request, about forty a second on a core.
///
/// Bound to one root, which is the same lifetime a proof is valid for — so
/// there is no cache to invalidate, only an index to rebuild when the epoch
/// turns over.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccountIndex {
    ids: Vec<AccountId>,
    tree: ProofIndex,
    header: Hash,
    tail: Hash,
    root: Hash,
}

impl AccountIndex {
    /// The state root these proofs verify against.
    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// A holder's leaf and its path to the state root.
    pub fn proof(&self, account: &AccountId) -> Option<(Hash, Vec<ProofStep>)> {
        // Binary search rather than a scan: the ids come from a `BTreeMap`, so
        // they are already in order.
        let i = self.ids.binary_search(account).ok()?;
        let mut path = self.tree.proof(i)?;
        path.push(ProofStep { sibling: self.header, node_is_right: true });
        path.push(ProofStep { sibling: self.tail, node_is_right: false });
        Some((self.tree.leaf(i)?, path))
    }
}

impl SwapState {
    /// Leaf committing to every scalar field of the chain.
    pub(crate) fn header_leaf(&self) -> Hash {
        let mut e = Encoder::new();
        e.bytes(b"swapvm.header.v1")
            .u32(self.chain_id)
            .u64(self.epoch)
            .u64(self.seq)
            .bytes(&self.parent_root)
            .bytes(&self.intent_acc)
            .u64(self.finalized_epoch)
            .u64(self.epoch_intents)
            .fixed(self.epoch_gross_volume)
            .u32(self.next_asset_id)
            .u32(self.next_pool_id);
        encode_params(&mut e, &self.params);
        // Appended only when on, so a chain that never turned clearing on
        // keeps the header leaf — and the roots — it always had.
        if self.batch_clearing {
            e.bytes(b"clearing");
        }
        e.leaf()
    }

    /// One leaf per open order, in sequence order.
    pub(crate) fn order_leaves(&self) -> Vec<Hash> {
        self.orders
            .iter()
            .map(|o| {
                let mut e = Encoder::new();
                e.bytes(b"swapvm.order.v1").u64(o.seq).bytes(&o.account).u32(o.pool).u32(o.asset_in).fixed(o.amount_in).fixed(o.min_out);
                e.leaf()
            })
            .collect()
    }

    /// The leaf preimage for one account.
    ///
    /// Balances are count-prefixed and iterate in asset-id order. A zero
    /// balance is never present — `Account::debit` removes it — so the record
    /// commits to what the account holds and not to what it once held.
    ///
    /// Public because a holder exiting without the sequencer has to be able to
    /// rebuild this from what was published and check it hashes to the leaf the
    /// anchored root committed.
    pub fn account_record(&self, id: &AccountId) -> Option<Vec<u8>> {
        let a = self.accounts.get(id)?;
        let mut e = Encoder::new();
        e.bytes(b"swapvm.account.v1").bytes(id).u32(a.balances.len() as u32);
        for (asset, amount) in a.balances.iter() {
            e.u32(*asset).fixed(*amount);
        }
        // Exits in flight are part of what an account holds a claim on, so they
        // are part of what it proves.
        e.u32(a.pending.len() as u32);
        for (asset, exit) in a.pending.iter() {
            e.u32(*asset).fixed(exit.amount).u64(exit.since);
        }
        e.u32(a.incoming.len() as u32);
        for (asset, c) in a.incoming.iter() {
            e.u32(*asset).fixed(c.amount).u64(c.epoch);
        }
        let b = a.binding.unwrap_or(crate::state::Binding {
            destination: [0u8; 32],
            pending: None,
        });
        e.bytes(&b.destination)
            .bool(b.pending.is_some())
            .bytes(&b.pending.map(|(d, _)| d).unwrap_or([0u8; 32]))
            .u64(b.pending.map(|(_, s)| s).unwrap_or(0));
        // Appended only once set, so an account that never shielded itself
        // keeps the leaf — and the chain the root — it always had.
        if a.blind != [0u8; 32] {
            e.bytes(b"blind").bytes(&a.blind);
        }
        Some(e.finish().to_vec())
    }

    /// One leaf per account, in account-id order.
    pub(crate) fn account_leaves(&self) -> Vec<Hash> {
        self.accounts
            .keys()
            .map(|id| {
                hash_leaf(
                    &self
                        .account_record(id)
                        .expect("an account being iterated always has a record"),
                )
            })
            .collect()
    }

    /// One leaf per asset, in asset-id order.
    pub(crate) fn token_leaves(&self) -> Vec<Hash> {
        self.tokens
            .iter()
            .map(|(id, t)| {
                let mut e = Encoder::new();
                e.bytes(b"swapvm.token.v1")
                    .u32(*id)
                    .bytes(&t.symbol)
                    .fixed(t.supply)
                    .opt_u32(t.lp_of)
                    .opt_u32(t.genesis_pool)
                    .fixed(t.unit)
                    .fixed(t.bond);
                if let Some(c) = t.content {
                    e.bytes(b"content").bytes(&c);
                }
                e
                    .u16(t.vault.map(|v| v.origin).unwrap_or(0))
                    .fixed(t.vault.map(|v| v.confirmed).unwrap_or(Fixed::ZERO))
                    .u64(t.vault.map(|v| v.deposits).unwrap_or(0))
                    .fixed(t.vault.map(|v| v.min_exit).unwrap_or(Fixed::ZERO))
                    .fixed(t.vault.map(|v| v.observed).unwrap_or(Fixed::ZERO))
                    .u64(t.vault.map(|v| v.observed_epoch).unwrap_or(0))
                    .fixed(t.vault.map(|v| v.cap).unwrap_or(Fixed::ZERO))
                    .fixed(t.vault.map(|v| v.epoch_cap).unwrap_or(Fixed::ZERO))
                    .fixed(t.vault.map(|v| v.epoch_credited).unwrap_or(Fixed::ZERO))
                    .u64(t.vault.map(|v| v.epoch).unwrap_or(0));
                e.leaf()
            })
            .collect()
    }

    /// One leaf per pool, in pool-id order.
    pub(crate) fn pool_leaves(&self) -> Vec<Hash> {
        self.pools
            .iter()
            .map(|(id, p)| {
                let mut e = Encoder::new();
                e.bytes(b"swapvm.pool.v1")
                    .u32(*id)
                    .u32(p.asset0)
                    .u32(p.asset1)
                    .fixed(p.reserve0)
                    .fixed(p.reserve1)
                    .u16(p.fee_bps)
                    .u32(p.lp_asset)
                    .fixed(p.lp_supply)
                    .fixed(p.locked)
                    .fixed(p.min_in0)
                    .fixed(p.min_in1)
                    .fixed(p.reference.map(|r| r.price).unwrap_or(Fixed::ZERO))
                    .u64(p.reference.map(|r| r.seq).unwrap_or(0));
                e.leaf()
            })
            .collect()
    }

    /// One leaf per collection: what backs its items and how many are left.
    pub fn collection_leaves(&self) -> Vec<Hash> {
        self.collections
            .iter()
            .map(|(id, c)| {
                let mut e = Encoder::new();
                e.bytes(b"swapvm.collection.v1")
                    .u32(*id)
                    .bytes(&c.creator)
                    .bytes(&c.symbol)
                    .u32(c.cap)
                    .u32(c.minted)
                    .u32(c.outstanding)
                    .fixed(c.pool)
                    .u16(c.fee_bps)
                    .u8(c.phase.code());
                e.leaf()
            })
            .collect()
    }

    /// One leaf per resting offer: who committed what, at what price, until
    /// when. An offer holds an asset, and an escrow nobody can check is not one.
    pub fn offer_leaves(&self) -> Vec<Hash> {
        self.offers
            .iter()
            .map(|(id, o)| {
                let mut e = Encoder::new();
                e.bytes(b"swapvm.offer.v1")
                    .u64(*id)
                    .bytes(&o.maker)
                    .u32(o.offer_asset)
                    .fixed(o.offer_amount)
                    .u32(o.want_asset)
                    .fixed(o.want_amount)
                    .u64(o.expires_at_epoch);
                e.leaf()
            })
            .collect()
    }

    /// The chain's state root.
    pub fn state_root(&self) -> Hash {
        merkle_root(&self.sections())
    }

    /// The sections the root is built from, in order.
    ///
    /// One definition, because there are two callers — the checkpoint the
    /// chain commits and the integrity check on a saved state — and a root
    /// with two definitions is a root that will drift between them.
    pub fn sections(&self) -> Vec<Hash> {
        let mut parts = alloc::vec![
            self.header_leaf(),
            merkle_root(&self.account_leaves()),
            merkle_root(&self.token_leaves()),
            merkle_root(&self.pool_leaves()),
        ];
        // Collections are state a replayer must reproduce — the pool is the
        // floor, and a floor nobody can check is not one. They join the root
        // only once a collection exists, so a chain without any keeps its
        // roots unchanged by this feature existing at all.
        if !self.collections.is_empty() {
            parts.push(merkle_root(&self.collection_leaves()));
        }
        // Open orders are state a replayer must reproduce; they join the root
        // only while any exist, so a chain without them keeps its roots.
        if !self.orders.is_empty() {
            parts.push(merkle_root(&self.order_leaves()));
        }
        // Resting offers hold escrowed assets, so a replayer must reproduce
        // them exactly. Same rule: they join the root only while any exist, so
        // a chain that has never had one keeps the roots it already published.
        if !self.offers.is_empty() {
            parts.push(merkle_root(&self.offer_leaves()));
        }
        // The launch's bookkeeping is state a replayer must reproduce, and
        // joins the root only once a launch exists.
        if let Some(l) = &self.launch {
            let mut e = Encoder::new();
            e.bytes(b"swapvm.launch.v1");
            encode_launch(&mut e, &l.params);
            e.u64(l.zcash_height).u64(l.graduated_at).u32(l.zyn).u32(l.genesis_pool).fixed(l.minted).u64(l.last_mint_height);
            for (a, v) in &l.contributions { e.bytes(a).fixed(*v); }
            for (a, v) in &l.epoch_bridge_fees { e.bytes(a).fixed(*v); }
            for (p, v) in &l.epoch_pool_fees { e.u32(*p).fixed(*v); }
            for ((a, from), v) in &l.vesting {
                e.bytes(a);
                // Written only for a grant that came from a bridged market,
                // so a chain that has only ever made the ZYN genesis grant
                // keeps the leaf — and the root — it always had.
                if *from != 0 { e.u32(*from); }
                e.fixed(v.total).fixed(v.released).u64(v.start).u64(v.end);
            }
            if !l.assets.is_empty() {
                e.bytes(b"markets");
                for (id, a) in &l.assets {
                    e.u32(*id).fixed(a.reference.map(|r| r.price).unwrap_or(Fixed::ZERO)).u64(a.reference.map(|r| r.seq).unwrap_or(0))
                        .u64(a.opened_at).u32(a.pool).fixed(a.grant);
                    for (acct, v) in &a.contributions { e.bytes(acct).fixed(*v); }
                }
            }
            parts.push(e.leaf());
        }
        parts
    }

    /// The header leaf, for data-availability consumers rebuilding the root.
    pub fn header_leaf_public(&self) -> Hash {
        self.header_leaf()
    }
    /// The account leaves in commitment order.
    ///
    /// Exposed so a data-availability consumer can rebuild the accounts tree
    /// through this encoding rather than reimplementing it. A second
    /// implementation of a leaf is a second thing that can drift, and drift
    /// here means a holder whose balance is real but unprovable.
    pub fn account_leaves_public(&self) -> Vec<Hash> {
        self.account_leaves()
    }
    pub fn accounts_root(&self) -> Hash {
        merkle_root(&self.account_leaves())
    }
    pub fn tokens_root(&self) -> Hash {
        merkle_root(&self.token_leaves())
    }
    pub fn pools_root(&self) -> Hash {
        merkle_root(&self.pool_leaves())
    }

    /// The committed leaf for one account, or `None` if the chain has never
    /// seen it.
    pub fn account_leaf(&self, account: &AccountId) -> Option<Hash> {
        let index = self.accounts.keys().position(|k| k == account)?;
        self.account_leaves().into_iter().nth(index)
    }

    /// Inclusion path proving `account`'s leaf under the chain's state root.
    ///
    /// The path spans both levels: up through the accounts tree, then the two
    /// steps that bind the accounts root into the chain root. Those last two
    /// are fixed by the four-section layout — the accounts root is the right
    /// child of `node(header, accounts)`, which is the left child of the root.
    ///
    /// Paired with `account_leaf`, this is everything a holder needs to prove a
    /// balance against a checkpointed root without trusting the node that
    /// served it.
    pub fn account_proof(&self, account: &AccountId) -> Option<Vec<ProofStep>> {
        let index = self.accounts.keys().position(|k| k == account)?;
        let mut path = merkle_proof(&self.account_leaves(), index);
        path.push(ProofStep { sibling: self.header_leaf(), node_is_right: true });
        path.push(ProofStep {
            sibling: merkle_root(&[self.tokens_root(), self.pools_root()]),
            node_is_right: false,
        });
        Some(path)
    }

    /// An index over the accounts tree, for serving many proofs from one root.
    ///
    /// Built once when an epoch seals; every withdrawal proof against that root
    /// is then `log(n)` hashes instead of a rebuild. See `AccountIndex`.
    pub fn account_index(&self) -> AccountIndex {
        AccountIndex {
            ids: self.accounts.keys().copied().collect(),
            tree: ProofIndex::build(self.account_leaves()),
            header: self.header_leaf(),
            tail: merkle_root(&[self.tokens_root(), self.pools_root()]),
            root: self.state_root(),
        }
    }

    /// Hex rendering, for logs and the settlement bridge.
    pub fn state_root_hex(&self) -> String {
        self.state_root().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod root_agreement {
    use super::*;
    use zyn_vm::spec::MicrochainVm;

    /// The checkpoint's root and a saved state's root are the same function.
    /// They were not, once: sections() kept its own list and stopped matching
    /// when orders and the launch joined the root, so a node's checkpoints
    /// and its own state file disagreed about what the chain looked like.
    #[test]
    fn the_two_roots_are_one() {
        let mut s = crate::state::SwapState::new(7, crate::types::Params::v1());
        assert_eq!(s.state_root(), <crate::state::SwapState as MicrochainVm>::state_root(&s));
        s.batch_clearing = true;
        s.orders.push(crate::state::Order { seq: 1, account: [1u8; 32], pool: 1, asset_in: 1, amount_in: Fixed::whole(1), min_out: Fixed::ZERO });
        s.launch = Some(crate::launch::LaunchState::new(crate::launch::Launch::v1()));
        assert_eq!(s.state_root(), <crate::state::SwapState as MicrochainVm>::state_root(&s), "every section must reach both");
        assert_eq!(s.sections().len(), 6, "header, accounts, tokens, pools, orders, launch");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::state::{symbol, Pool, TokenInfo};
    use crate::types::XZEC;

    fn state() -> SwapState {
        SwapState::new(7, Params::v1())
    }

    #[test]
    fn empty_tree_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_is_its_own_root() {
        let l = hash_leaf(b"x");
        assert_eq!(merkle_root(&[l]), l);
    }

    #[test]
    fn leaves_and_nodes_are_domain_separated() {
        // A leaf whose content happens to be two concatenated hashes must not
        // collide with the internal node over those hashes.
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let mut concat = Vec::new();
        concat.extend_from_slice(&a);
        concat.extend_from_slice(&b);
        assert_ne!(merkle_root(&[a, b]), hash_leaf(&concat));
    }

    #[test]
    fn odd_leaf_is_promoted_not_duplicated() {
        let a = hash_leaf(b"a");
        let b = hash_leaf(b"b");
        let c = hash_leaf(b"c");
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, c]));
    }

    #[test]
    fn identical_states_hash_identically() {
        assert_eq!(state().state_root(), state().state_root());
    }

    #[test]
    fn every_header_field_is_committed() {
        let base = state();
        let root = base.state_root();

        let mut s = base.clone();
        s.epoch += 1;
        assert_ne!(s.state_root(), root, "epoch must be committed");

        let mut s = base.clone();
        s.seq += 1;
        assert_ne!(s.state_root(), root, "sequence must be committed");

        let mut s = base.clone();
        let mut v = crate::state::Vault::new(1);
        v.attest(Fixed::ONE, 0).unwrap();
        v.credit(Fixed::ONE, 1, 0).unwrap();
        s.tokens.get_mut(&XZEC).unwrap().vault = Some(v);
        assert_ne!(s.state_root(), root, "backing must be committed");

        let mut s = base.clone();
        s.parent_root = [9u8; 32];
        assert_ne!(s.state_root(), root, "checkpoint lineage must be committed");

        let mut s = base.clone();
        s.intent_acc = [9u8; 32];
        assert_ne!(s.state_root(), root, "intent commitment must be committed");

        let mut s = base.clone();
        s.epoch_intents += 1;
        assert_ne!(s.state_root(), root, "epoch intent count must be committed");

        let mut s = base.clone();
        s.chain_id += 1;
        assert_ne!(s.state_root(), root, "chain id must be committed");

        let mut s = base.clone();
        s.params.default_fee_bps += 1;
        assert_ne!(s.state_root(), root, "params must be committed");

        let mut s = base.clone();
        s.next_pool_id += 1;
        assert_ne!(s.state_root(), root, "id counters must be committed");
    }

    #[test]
    fn a_one_raw_unit_balance_change_moves_the_root() {
        let mut s = state();
        s.account_mut(&[3u8; 32]).credit(XZEC, Fixed::whole(100)).unwrap();
        let before = s.state_root();
        s.account_mut(&[3u8; 32]).credit(XZEC, Fixed::raw(1)).unwrap();
        assert_ne!(s.state_root(), before);
    }

    #[test]
    fn pool_reserves_are_committed() {
        let mut s = state();
        s.pools.insert(
            1,
            Pool {
                asset0: 1,
                asset1: 2,
                reserve0: Fixed::whole(10),
                reserve1: Fixed::whole(1_000),
                fee_bps: 30,
                lp_asset: 3,
                lp_supply: Fixed::whole(100),
                locked: Fixed::raw(1_000),
                min_in0: Fixed::raw(1),
                min_in1: Fixed::raw(1),
                reference: None,
            },
        );
        let before = s.state_root();
        s.pools.get_mut(&1).unwrap().reserve0 = Fixed::whole(10).add(Fixed::raw(1)).unwrap();
        assert_ne!(s.state_root(), before, "a reserve change did not move the root");
    }

    #[test]
    fn token_supply_is_committed() {
        let mut s = state();
        s.tokens.insert(
            2,
            TokenInfo::divisible(symbol(b"CAT"), Fixed::whole(1_000)),
        );
        let before = s.state_root();
        s.tokens.get_mut(&2).unwrap().supply = Fixed::whole(1_001);
        assert_ne!(s.state_root(), before);
    }

    /// Two accounts holding the same total across different assets must not
    /// collide — the asset id is part of the leaf, not just the amount.
    #[test]
    fn balances_are_bound_to_their_asset() {
        let mut a = state();
        a.tokens.insert(2, TokenInfo::divisible(symbol(b"CAT"), Fixed::ZERO));
        let mut b = a.clone();
        a.account_mut(&[1u8; 32]).credit(XZEC, Fixed::whole(5)).unwrap();
        b.account_mut(&[1u8; 32]).credit(2, Fixed::whole(5)).unwrap();
        assert_ne!(a.state_root(), b.state_root());
    }

    #[test]
    fn hex_rendering_is_64_chars() {
        assert_eq!(state().state_root_hex().len(), 64);
    }

    #[test]
    fn the_intent_chain_commits_to_order() {
        let z = [0u8; 32];
        let ab = fold_intent(fold_intent(z, 1, b"a"), 2, b"b");
        let ba = fold_intent(fold_intent(z, 1, b"b"), 2, b"a");
        assert_ne!(ab, ba, "reordering intents did not change the commitment");

        // And to the sequence numbers, not only the payloads.
        let shifted = fold_intent(fold_intent(z, 2, b"a"), 3, b"b");
        assert_ne!(ab, shifted);

        // And to where it started, so an epoch's chain is not reusable.
        assert_ne!(ab, fold_intent(fold_intent([1u8; 32], 1, b"a"), 2, b"b"));
    }
}

#[cfg(test)]
mod proof_tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::types::{AccountId, XZEC};

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n).map(|i| hash_leaf(&[i as u8])).collect()
    }

    /// Every index in every tree size up to 33. Odd sizes are the interesting
    /// ones: promotion means some levels contribute no step, so a verifier
    /// deriving sides from index parity would fail exactly there.
    #[test]
    fn every_index_of_every_size_proves() {
        for n in 1..=33 {
            let ls = leaves(n);
            let root = merkle_root(&ls);
            for i in 0..n {
                assert!(
                    verify_proof(ls[i], &merkle_proof(&ls, i), root),
                    "size {} index {} failed to verify",
                    n, i
                );
            }
        }
    }

    #[test]
    fn a_proof_does_not_verify_against_the_wrong_leaf() {
        let ls = leaves(8);
        let root = merkle_root(&ls);
        let path = merkle_proof(&ls, 3);
        assert!(verify_proof(ls[3], &path, root));
        assert!(!verify_proof(ls[4], &path, root), "path accepted a foreign leaf");
        assert!(!verify_proof(hash_leaf(b"forged"), &path, root));
    }

    #[test]
    fn a_tampered_path_does_not_verify() {
        let ls = leaves(8);
        let root = merkle_root(&ls);
        let mut path = merkle_proof(&ls, 3);
        path[0].node_is_right = !path[0].node_is_right;
        assert!(!verify_proof(ls[3], &path, root), "flipped side still verified");

        let mut path = merkle_proof(&ls, 3);
        path[1].sibling = hash_leaf(b"wrong");
        assert!(!verify_proof(ls[3], &path, root), "swapped sibling still verified");
    }

    #[test]
    fn an_out_of_range_index_yields_an_empty_path() {
        assert!(merkle_proof(&leaves(4), 9).is_empty());
    }

    /// The path a withdrawal actually uses: an account leaf all the way to the
    /// chain's state root, across all four sections.
    #[test]
    fn account_proofs_verify_against_the_chain_root() {
        let mut s = SwapState::new(1, Params::v1());
        let accounts: Vec<AccountId> = (1u8..=9).map(|i| [i; 32]).collect();
        for (i, a) in accounts.iter().enumerate() {
            let acct = s.account_mut(a);
            acct.credit(XZEC, Fixed::whole(1_000 * (i as i64 + 1))).unwrap();
            acct.set_pending(XZEC, Fixed::whole(10 * (i as i64 + 1)), 0);
        }
        let root = s.state_root();
        let leaves = s.account_leaves();
        for (i, a) in accounts.iter().enumerate() {
            let path = s.account_proof(a).expect("account should be provable");
            assert!(verify_proof(leaves[i], &path, root), "account {} did not verify", a[0]);
        }
    }

    #[test]
    fn an_unknown_account_has_no_proof() {
        let s = SwapState::new(1, Params::v1());
        assert!(s.account_proof(&[42u8; 32]).is_none());
    }

    /// A path is bound to the state it was taken from: someone else's balance
    /// moving invalidates it, which is what stops a stale proof being replayed
    /// against a newer checkpoint.
    #[test]
    fn a_proof_is_bound_to_the_state_it_was_taken_from() {
        let mut s = SwapState::new(1, Params::v1());
        s.account_mut(&[1u8; 32]).credit(XZEC, Fixed::whole(100)).unwrap();
        s.account_mut(&[2u8; 32]).credit(XZEC, Fixed::whole(200)).unwrap();
        let path = s.account_proof(&[1u8; 32]).unwrap();
        let leaf = s.account_leaves()[0];
        assert!(verify_proof(leaf, &path, s.state_root()));

        s.account_mut(&[2u8; 32]).credit(XZEC, Fixed::raw(1)).unwrap();
        assert!(
            !verify_proof(leaf, &path, s.state_root()),
            "a stale path verified against a newer root"
        );
    }
}

#[cfg(test)]
mod blind_tests {
    use crate::state::SwapState;
    use crate::tx::{Intent, SequencedIntent};
    use crate::types::Params;
    use crate::vm;
    use zyn_vm::spec::MicrochainVm;

    fn go(s: &mut SwapState, i: Intent) {
        let seq = s.seq + 1;
        let r = vm::apply(s, &SequencedIntent { seq, intent: i });
        assert!(!r.iter().any(|x| x.is_rejection()), "rejected: {:?}", r);
    }

    /// The whole point of the blind: someone holding the published leaves
    /// and a guess about a record must not be able to confirm the guess.
    /// Two accounts with identical holdings and different blinds have
    /// different leaves; one with no blind has the leaf it always had.
    #[test]
    fn a_blind_makes_a_leaf_unguessable_and_its_absence_changes_nothing() {
        let mut s = SwapState::new(1, Params::testnet());
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let before = s.account_record(&a);
        go(&mut s, Intent::Reblind { account: a, blind: [7u8; 32] });
        go(&mut s, Intent::Reblind { account: b, blind: [8u8; 32] });
        let ra = s.account_record(&a).unwrap();
        let rb = s.account_record(&b).unwrap();
        // Same holdings (none), different blinds: an observer cannot tell
        // these apart from any other record by hashing a guess.
        assert_ne!(SwapState::leaf_of_record(&ra), SwapState::leaf_of_record(&rb));
        assert!(ra.ends_with(&[7u8; 32]) && rb.ends_with(&[8u8; 32]));
        // The record a guesser would hash — id and empty balances, no blind —
        // is not the record in the tree.
        let mut guess = ra.clone();
        guess.truncate(ra.len() - 5 - 32);
        assert_ne!(SwapState::leaf_of_record(&guess), SwapState::leaf_of_record(&ra));
        // An account that never shielded itself is encoded exactly as before
        // blinds existed, so a chain's existing roots are untouched.
        assert_eq!(before, None);
        let c = [3u8; 32];
        s.account_mut(&c);
        assert!(!s.account_record(&c).unwrap().windows(5).any(|w| w == b"blind"));
    }

    /// A mirrored item is indivisible, backed by a vault, and unique per token.
    #[test]
    fn a_mirrored_item_is_whole_units_with_a_vault_and_unique() {
        let mut s = SwapState::new(1, Params::testnet());
        go(&mut s, Intent::CreateBridgedItem { symbol: crate::state::symbol(b"PUNK.zy"), origin: crate::types::ORIGIN_SOLANA, content: [4u8; 32] });
        let (id, t) = s.tokens.iter().find(|(_, t)| t.content == Some([4u8; 32])).map(|(i, t)| (*i, *t)).unwrap();
        assert_eq!(t.unit, crate::Fixed::ONE);
        assert!(t.vault.is_some() && t.supply.is_zero());
        assert!(!t.admits(crate::Fixed::raw(5)), "a fraction of an item is not a quantity");
        let seq = s.seq + 1;
        let r = vm::apply(&mut s, &SequencedIntent { seq, intent: Intent::CreateBridgedItem { symbol: crate::state::symbol(b"OTHER"), origin: crate::types::ORIGIN_SOLANA, content: [4u8; 32] } });
        assert!(r.iter().any(|x| x.is_rejection()), "the same token mirrored twice");
        let _ = id;
    }

    #[test]
    fn a_zero_blind_is_refused_and_an_item_keeps_its_content() {
        let mut s = SwapState::new(1, Params::testnet());
        let seq = s.seq + 1;
        let r = vm::apply(&mut s, &SequencedIntent { seq, intent: Intent::Reblind { account: [1u8; 32], blind: [0u8; 32] } });
        assert!(r.iter().any(|x| x.is_rejection()), "a zero blind is no blind");

        let creator = [5u8; 32];
        s.account_mut(&creator).balances.insert(crate::types::XZEC, crate::Fixed::whole(1));
        s.tokens.get_mut(&crate::types::XZEC).unwrap().supply = crate::Fixed::whole(1);
        go(&mut s, Intent::MintItem { creator, symbol: crate::state::symbol(b"ART"), supply: crate::Fixed::whole(1), bond: crate::Fixed::raw(1_000_000_000_000_000), content: [9u8; 32] });
        let item = s.tokens.iter().find(|(_, t)| t.symbol == crate::state::symbol(b"ART")).map(|(_, t)| t).unwrap();
        assert_eq!(item.content, Some([9u8; 32]));
    }
}
