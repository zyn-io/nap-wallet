//! Full serialisation of the microchain's state.
//!
//! Needed by anything that has to *carry* a state rather than merely commit to
//! it: a prover feeding a guest its pre-state, a node restarting, an operator
//! moving the chain between machines, a fresh node catching up from a peer.
//!
//! Distinct from `merkle`, which commits to state, and from `wire`, which
//! carries intents. The three share an encoding style on purpose — fixed width,
//! big-endian, no varints — because the same reasoning applies to all of them:
//! a serialiser that can represent one value two ways is a serialiser that can
//! fork a chain.
//!
//! The round-trip property this module owes the rest of the crate is stronger
//! than "decode undoes encode": a decoded state must produce the **same state
//! root**, or a node that restarted would silently diverge from one that did
//! not.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::merkle::{Encoder, Hash};
use crate::fixed::Fixed;
use crate::state::{Order,
    Account, Binding, PendingCredit, PendingExit, Pool, Reference, SwapState, TokenInfo, Vault,
};
use crate::wire::{Decoder, SwapDecode, WireError};

/// Format version, so a state written by one build is never silently misread
/// by another.
/// Version 8 activates authorization-aware intent commitments. The state body
/// is unchanged, so versions 1-7 still decode for migration; continuing from
/// one under VM v2 folds `ZYNAUTH1` records into the next epoch root.
pub const STATE_VERSION: u16 = 8;

impl SwapState {
    /// Serialise the complete state.
    pub fn encode_state(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u16(STATE_VERSION)
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
        crate::wire::encode_params(&mut e, &self.params);

        // Tokens, in asset-id order — the same order the commitment uses, so a
        // decode-encode cycle is byte-identical.
        e.u32(self.tokens.len() as u32);
        for (id, t) in self.tokens.iter() {
            e.u32(*id).bytes(&t.symbol).fixed(t.supply).opt_u32(t.lp_of).opt_u32(t.genesis_pool)
                .fixed(t.unit)
                .fixed(t.bond)
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
            e.bool(t.content.is_some()).bytes(&t.content.unwrap_or([0u8; 32]));
            e.opt_u32(t.collection);
        }

        // Pools, in pool-id order.
        e.u32(self.pools.len() as u32);
        for (id, p) in self.pools.iter() {
            e.u32(*id)
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
        }

        // Accounts, in account-id order, each with its balances in asset order.
        e.u32(self.accounts.len() as u32);
        for (id, a) in self.accounts.iter() {
            e.bytes(id).u32(a.balances.len() as u32);
            for (asset, amount) in a.balances.iter() {
                e.u32(*asset).fixed(*amount);
            }
            e.u32(a.pending.len() as u32);
            for (asset, exit) in a.pending.iter() {
                e.u32(*asset).fixed(exit.amount).u64(exit.since);
            }
            e.u32(a.incoming.len() as u32);
            for (asset, c) in a.incoming.iter() {
                e.u32(*asset).fixed(c.amount).u64(c.epoch);
            }
            let b = a.binding.unwrap_or(Binding { destination: [0u8; 32], pending: None });
            e.bytes(&b.destination)
                .bool(b.pending.is_some())
                .bytes(&b.pending.map(|(d, _)| d).unwrap_or([0u8; 32]))
                .u64(b.pending.map(|(_, s)| s).unwrap_or(0));
            e.bytes(&a.blind);
        }

        // Batch clearing: the switch and the orders waiting for the seal.
        e.bool(self.batch_clearing);
        e.u32(self.orders.len() as u32);
        for o in &self.orders {
            e.u64(o.seq).bytes(&o.account).u32(o.pool).u32(o.asset_in).fixed(o.amount_in).fixed(o.min_out);
        }

        // The launch, if set.
        e.bool(self.launch.is_some());
        if let Some(l) = &self.launch {
            crate::wire::encode_launch(&mut e, &l.params);
            e.u64(l.zcash_height).u64(l.graduated_at).u32(l.zyn).u32(l.genesis_pool).fixed(l.minted).u64(l.last_mint_height);
            e.u32(l.contributions.len() as u32);
            for (a, v) in &l.contributions { e.bytes(a).fixed(*v); }
            e.u32(l.epoch_bridge_fees.len() as u32);
            for (a, v) in &l.epoch_bridge_fees { e.bytes(a).fixed(*v); }
            e.u32(l.epoch_pool_fees.len() as u32);
            for (p, v) in &l.epoch_pool_fees { e.u32(*p).fixed(*v); }
            e.u32(l.vesting.len() as u32);
            for ((a, from), v) in &l.vesting { e.bytes(a).u32(*from).fixed(v.total).fixed(v.released).u64(v.start).u64(v.end); }
            e.u32(l.assets.len() as u32);
            for (id, a) in &l.assets {
                e.u32(*id)
                    .fixed(a.reference.map(|r| r.price).unwrap_or(Fixed::ZERO))
                    .u64(a.reference.map(|r| r.seq).unwrap_or(0))
                    .u64(a.opened_at).u32(a.pool).fixed(a.grant)
                    .u32(a.contributions.len() as u32);
                for (acct, v) in &a.contributions { e.bytes(acct).fixed(*v); }
            }
        }

        // Collections last, so a v5 reader that stops before them still reads
        // everything it knows about.
        e.u32(self.next_collection_id).u32(self.collections.len() as u32);
        for (id, c) in &self.collections {
            e.u32(*id)
                .bytes(&c.creator)
                .bytes(&c.symbol)
                .u32(c.cap)
                .u32(c.minted)
                .u32(c.outstanding)
                .fixed(c.pool)
                .u16(c.fee_bps)
                .u8(c.phase.code());
        }

        // Offers after them, for the same reason: a v6 reader stops here and
        // still has everything it knows about.
        e.u64(self.next_offer_id).u32(self.offers.len() as u32);
        for (id, o) in &self.offers {
            e.u64(*id)
                .bytes(&o.maker)
                .u32(o.offer_asset)
                .fixed(o.offer_amount)
                .u32(o.want_asset)
                .fixed(o.want_amount)
                .u64(o.expires_at_epoch);
        }

        e.finish().to_vec()
    }

    /// Reconstruct a state from bytes.
    pub fn decode_state(buf: &[u8]) -> Result<SwapState, WireError> {
        let mut d = Decoder::new(buf);
        let version = d.u16()?;
        if version == 0 || version > STATE_VERSION {
            return Err(WireError::UnknownDiscriminant(0));
        }
        let chain_id = d.u32()?;
        let epoch = d.u64()?;
        let seq = d.u64()?;
        let parent_root = d.hash()?;
        let intent_acc = d.hash()?;
        let finalized_epoch = d.u64()?;
        let epoch_intents = d.u64()?;
        let epoch_gross_volume = d.fixed()?;
        let next_asset_id = d.u32()?;
        let next_pool_id = d.u32()?;
        let params = d.params()?;

        let mut tokens = BTreeMap::new();
        let n = d.u32()?;
        for _ in 0..n {
            let id = d.u32()?;
            tokens.insert(
                id,
                TokenInfo {
                    symbol: d.symbol()?,
                    supply: d.fixed()?,
                    lp_of: d.opt_u32()?,
                    genesis_pool: d.opt_u32()?,
                    unit: d.fixed()?,
                    bond: d.fixed()?,
                    vault: {
                        let origin = d.u16()?;
                        let confirmed = d.fixed()?;
                        let deposits = d.u64()?;
                        let min_exit = d.fixed()?;
                        let observed = d.fixed()?;
                        let observed_epoch = d.u64()?;
                        let cap = d.fixed()?;
                        let epoch_cap = d.fixed()?;
                        let epoch_credited = d.fixed()?;
                        let epoch = d.u64()?;
                        if origin == 0 {
                            None
                        } else {
                            Some(Vault {
                                origin,
                                confirmed,
                                deposits,
                                min_exit,
                                observed,
                                observed_epoch,
                                cap,
                                epoch_cap,
                                epoch_credited,
                                epoch,
                            })
                        }
                    },
                    // Read in the order written: content, then the link.
                    content: if version >= 2 {
                        let has = d.u8()? != 0;
                        let h = d.hash()?;
                        has.then_some(h)
                    } else {
                        None
                    },
                    collection: if version >= 6 { d.opt_u32()? } else { None },
                },
            );
        }

        let mut pools = BTreeMap::new();
        let n = d.u32()?;
        for _ in 0..n {
            let id = d.u32()?;
            pools.insert(
                id,
                Pool {
                    asset0: d.u32()?,
                    asset1: d.u32()?,
                    reserve0: d.fixed()?,
                    reserve1: d.fixed()?,
                    fee_bps: d.u16()?,
                    lp_asset: d.u32()?,
                    lp_supply: d.fixed()?,
                    locked: d.fixed()?,
                    min_in0: d.fixed()?,
                    min_in1: d.fixed()?,
                    reference: {
                        let price = d.fixed()?;
                        let seq = d.u64()?;
                        if price.is_positive() { Some(Reference { price, seq }) } else { None }
                    },
                },
            );
        }

        let mut accounts = BTreeMap::new();
        let n = d.u32()?;
        for _ in 0..n {
            let id = d.account()?;
            let bn = d.u32()?;
            let mut balances = BTreeMap::new();
            for _ in 0..bn {
                let asset = d.u32()?;
                balances.insert(asset, d.fixed()?);
            }
            let pn = d.u32()?;
            let mut pending = BTreeMap::new();
            for _ in 0..pn {
                let asset = d.u32()?;
                let amount = d.fixed()?;
                pending.insert(asset, PendingExit { amount, since: d.u64()? });
            }
            let cn = d.u32()?;
            let mut incoming = BTreeMap::new();
            for _ in 0..cn {
                let asset = d.u32()?;
                let amount = d.fixed()?;
                incoming.insert(asset, PendingCredit { amount, epoch: d.u64()? });
            }
            let binding = {
                let dest = d.hash()?;
                let has_pending = d.u8()? != 0;
                let pend_dest = d.hash()?;
                let pend_since = d.u64()?;
                if dest == [0u8; 32] {
                    None
                } else {
                    Some(Binding {
                        destination: dest,
                        pending: has_pending.then_some((pend_dest, pend_since)),
                    })
                }
            };
            // Version 1 predates blinds; such an account has none.
            let blind = if version >= 2 { d.hash()? } else { [0u8; 32] };
            accounts.insert(id, Account { balances, pending, incoming, binding, blind });
        }

        let (batch_clearing, orders) = if version >= 3 {
            let on = d.u8()? != 0;
            let n = d.u32()?;
            let mut orders = Vec::with_capacity(n as usize);
            for _ in 0..n {
                orders.push(Order { seq: d.u64()?, account: d.account()?, pool: d.u32()?, asset_in: d.u32()?, amount_in: d.fixed()?, min_out: d.fixed()? });
            }
            (on, orders)
        } else {
            (false, Vec::new())
        };

        let launch = if version >= 4 && d.u8()? != 0 {
            let params = if version >= 5 { crate::wire::decode_launch(&mut d)? } else { crate::wire::decode_launch_legacy(&mut d)? };
            let mut l = crate::launch::LaunchState::new(params);
            l.zcash_height = d.u64()?;
            l.graduated_at = d.u64()?;
            l.zyn = d.u32()?;
            l.genesis_pool = d.u32()?;
            l.minted = d.fixed()?;
            l.last_mint_height = d.u64()?;
            for _ in 0..d.u32()? { let a = d.account()?; l.contributions.insert(a, d.fixed()?); }
            for _ in 0..d.u32()? { let a = d.account()?; l.epoch_bridge_fees.insert(a, d.fixed()?); }
            for _ in 0..d.u32()? { let p = d.u32()?; l.epoch_pool_fees.insert(p, d.fixed()?); }
            for _ in 0..d.u32()? {
                let a = d.account()?;
                let from = if version >= 5 { d.u32()? } else { 0 };
                l.vesting.insert((a, from), crate::launch::Vest { total: d.fixed()?, released: d.fixed()?, start: d.u64()?, end: d.u64()? });
            }
            if version >= 5 {
                for _ in 0..d.u32()? {
                    let id = d.u32()?;
                    let price = d.fixed()?;
                    let seq = d.u64()?;
                    let mut a = crate::launch::AssetLaunch {
                        reference: price.is_positive().then_some(Reference { price, seq }),
                        opened_at: d.u64()?, pool: d.u32()?, grant: d.fixed()?,
                        contributions: Default::default(),
                    };
                    for _ in 0..d.u32()? { let acct = d.account()?; a.contributions.insert(acct, d.fixed()?); }
                    l.assets.insert(id, a);
                }
            }
            Some(l)
        } else {
            None
        };

        // Collections, written last, so a v5 state simply has none.
        let mut collections = BTreeMap::new();
        let mut next_collection_id = 1u32;
        if version >= 6 {
            next_collection_id = d.u32()?;
            let n = d.u32()?;
            for _ in 0..n {
                let id = d.u32()?;
                collections.insert(
                    id,
                    crate::state::Collection {
                        creator: d.account()?,
                        symbol: d.symbol()?,
                        cap: d.u32()?,
                        minted: d.u32()?,
                        outstanding: d.u32()?,
                        pool: d.fixed()?,
                        fee_bps: d.u16()?,
                        phase: crate::state::Phase::from_code(d.u8()?).ok_or(WireError::UnknownDiscriminant(0))?,
                    },
                );
            }
        }

        // Offers, written after collections, so a v6 state simply has none.
        let mut offers = BTreeMap::new();
        let mut next_offer_id = 1u64;
        if version >= 7 {
            next_offer_id = d.u64()?;
            let n = d.u32()?;
            for _ in 0..n {
                let id = d.u64()?;
                offers.insert(
                    id,
                    crate::state::Offer {
                        maker: d.account()?,
                        offer_asset: d.u32()?,
                        offer_amount: d.fixed()?,
                        want_asset: d.u32()?,
                        want_amount: d.fixed()?,
                        expires_at_epoch: d.u64()?,
                    },
                );
            }
        }

        if d.remaining() != 0 {
            return Err(WireError::TrailingBytes);
        }

        let mut state = SwapState::new(chain_id, params);
        state.batch_clearing = batch_clearing;
        state.orders = orders;
        state.launch = launch;
        state.epoch = epoch;
        state.seq = seq;
        state.parent_root = parent_root;
        state.intent_acc = intent_acc;
        state.finalized_epoch = finalized_epoch;
        state.epoch_intents = epoch_intents;
        state.epoch_gross_volume = epoch_gross_volume;
        state.next_asset_id = next_asset_id;
        state.next_pool_id = next_pool_id;
        // Replaces the genesis xZEC entry `new` installed, rather than merging
        // with it: a restored state is the encoded one exactly, not the encoded
        // one laid over a fresh chain.
        state.tokens = tokens;
        state.pools = pools;
        state.accounts = accounts;
        state.collections = collections;
        state.next_collection_id = next_collection_id;
        state.offers = offers;
        state.next_offer_id = next_offer_id;
        Ok(state)
    }

    /// The committed root of a serialised state, without keeping the state.
    pub fn root_of_encoded(buf: &[u8]) -> Result<Hash, WireError> {
        Ok(SwapState::decode_state(buf)?.state_root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::tx::{Intent, SequencedIntent};
    use crate::types::{AccountId, Params, XZEC};
    use crate::vm::apply;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    /// A chain with a token, a pool, balances, a pending exit and a sealed
    /// epoch behind it — every field the encoder has to carry.
    fn busy_chain() -> SwapState {
        let mut s = SwapState::new(9, Params::v1());
        let mut seq = 0u64;
        let mut go = |s: &mut SwapState, intent: Intent| {
            seq += 1;
            let r = apply(s, &SequencedIntent { seq, intent });
            assert!(!r.iter().any(|x| x.is_rejection()), "setup rejected: {:?}", r);
        };
        {
                let observed = s.backing_of(XZEC).add(Fixed::whole(10_000)).unwrap();
                go(&mut s, Intent::AttestVaultBalance { asset: XZEC, observed });
                let i = Intent::next_deposit(&s, acct(1), XZEC, Fixed::whole(10_000), [0u8; 32]);
                go(&mut s, i);
            }
        // Deposits are not spendable until the epoch containing them has been
        // anchored, so a setup that goes on to spend must seal and confirm.
        let at = s.epoch;
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch: at });
        go(&mut s, Intent::CreateToken {
            creator: acct(1),
            symbol: crate::state::symbol(b"CAT"),
            supply: Fixed::whole(1_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(1_000),
            token_liquidity: Fixed::whole(100_000),
            fee_bps: 30,
        });
        go(&mut s, Intent::Transfer {
            from: acct(1),
            to: acct(2),
            asset: XZEC,
            amount: Fixed::whole(500),
        });
        go(&mut s, Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: alloc::vec![1],
            amount_in: Fixed::whole(100),
            min_out: Fixed::ZERO,
        });
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::RequestWithdrawal { account: acct(2), asset: XZEC, amount: Fixed::whole(50), destination: [0u8; 32] });
        s
    }

    #[test]
    fn state_round_trips_byte_identically() {
        let s = busy_chain();
        let bytes = s.encode_state();
        let back = SwapState::decode_state(&bytes).expect("decode");
        assert_eq!(back.encode_state(), bytes, "re-encoding changed the bytes");
    }

    /// The property that actually matters: a restarted node commits to the same
    /// root as one that never stopped.
    #[test]
    fn a_decoded_state_has_the_same_root() {
        let s = busy_chain();
        let back = SwapState::decode_state(&s.encode_state()).expect("decode");
        assert_eq!(back.state_root(), s.state_root());
        assert_eq!(SwapState::root_of_encoded(&s.encode_state()).unwrap(), s.state_root());
    }

    #[test]
    fn a_decoded_state_is_equal_field_for_field() {
        let s = busy_chain();
        let back = SwapState::decode_state(&s.encode_state()).expect("decode");
        assert_eq!(back, s);
        back.check_invariants().expect("a decoded state must still be consistent");
    }

    /// A restored state must be able to keep executing from where it stopped —
    /// the sequence space and the epoch commitment carry across the restart.
    #[test]
    fn execution_resumes_after_a_round_trip() {
        let s = busy_chain();
        let mut restored = SwapState::decode_state(&s.encode_state()).expect("decode");
        let mut live = s.clone();
        let next = SequencedIntent {
            seq: s.seq + 1,
            intent: Intent::next_deposit(&s, acct(3), XZEC, Fixed::whole(7), [0u8; 32]),
        };
        apply(&mut live, &next);
        apply(&mut restored, &next);
        assert_eq!(restored.state_root(), live.state_root());
    }

    #[test]
    fn a_fresh_chain_round_trips() {
        let s = SwapState::new(1, Params::v1());
        let back = SwapState::decode_state(&s.encode_state()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.tokens.len(), 1, "genesis xZEC entry was duplicated or lost");
    }

    #[test]
    fn truncation_errors_rather_than_panicking() {
        let bytes = busy_chain().encode_state();
        for cut in 0..bytes.len() {
            assert!(
                SwapState::decode_state(&bytes[..cut]).is_err(),
                "truncation at {} decoded",
                cut
            );
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = busy_chain().encode_state();
        bytes.push(0);
        assert_eq!(SwapState::decode_state(&bytes), Err(WireError::TrailingBytes));
    }

    #[test]
    fn a_wrong_version_is_refused() {
        let mut bytes = busy_chain().encode_state();
        bytes[0] = 0xFF;
        assert!(SwapState::decode_state(&bytes).is_err());
    }
}
