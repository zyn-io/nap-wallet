//! ZynZap as a Zyn microchain VM.
//!
//! The whole of this file is a translation layer. Everything it exposes already
//! existed — the transition, the sections, the sealing, the codec — because the
//! spec was written from what a working application needed rather than imposed
//! on one afterwards. That is the point: ZynZap does not bend to be
//! conformant, and it will not have to bend again when Zyn opens to other
//! applications.
//!
//! What the spec buys ZynZap in return is everything above it. Sequencing,
//! epoch policy, anchoring to Zcash, the exit hatch, crash recovery — none of
//! that is written here, and none of it will need rewriting when a second
//! application arrives beside this one.

use alloc::vec::Vec;

use zyn_vm::commit::Hash;
use zyn_vm::spec::{AccountId as SpecAccountId, MicrochainVm};
use zyn_vm::Checkpoint;

use crate::fixed::Fixed;
use crate::state::SwapState;
use crate::tx::{Intent, Receipt, Reject, SequencedIntent};
use crate::types::Params;

impl MicrochainVm for SwapState {
    type Intent = Intent;
    type Receipt = Receipt;
    type Params = Params;

    const VM_NAME: &'static str = "zynzap";
    /// V2 commits the complete authorization record for every sequenced
    /// action. This intentionally changes the VM id and invalidates signatures
    /// made for the bare-intent commitment path.
    const VM_VERSION: u16 = 2;

    fn genesis(chain_id: u32, params: Params) -> Self {
        SwapState::new(chain_id, params)
    }

    fn chain_id(&self) -> u32 {
        self.chain_id
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn epoch(&self) -> u64 {
        self.epoch
    }

    fn apply(&mut self, seq: u64, intent: &Intent) -> Vec<Receipt> {
        crate::vm::apply(self, &SequencedIntent { seq, intent: intent.clone() })
    }

    fn apply_committed(
        &mut self,
        seq: u64,
        intent: &Intent,
        committed: &[u8],
    ) -> Vec<Receipt> {
        crate::vm::apply_committed(
            self,
            &SequencedIntent {
                seq,
                intent: intent.clone(),
            },
            committed,
        )
    }

    /// Four sections. The first two are the spec's — a header and the accounts
    /// the exit hatch opens — and the last two are ZynZap's own.
    fn sections(&self) -> Vec<Hash> {
        SwapState::sections(self)
    }

    fn seal_intent() -> Intent {
        Intent::Checkpoint
    }

    fn sealed(receipts: &[Receipt]) -> Option<Checkpoint> {
        receipts.iter().find_map(|r| match r {
            Receipt::Checkpointed(cp) => Some(*cp),
            _ => None,
        })
    }

    fn finality_intent(epoch: u64) -> Option<Intent> {
        Some(Intent::ConfirmAnchor { epoch })
    }

    fn as_sealed(&self, cp: &Checkpoint) -> Option<Self> {
        SwapState::as_sealed(self, cp)
    }

    fn rejected(r: &Receipt) -> bool {
        r.is_rejection()
    }

    /// An arithmetic failure is the one rejection that is not an ordinary
    /// event: it can surface mid-mutation, so the batch carrying it has to be
    /// discarded rather than recorded.
    fn unprovable(r: &Receipt) -> bool {
        r.rejection() == Some(Reject::ArithmeticFailure)
    }

    fn typed_intent(intent: &Intent) -> zyn_vm::eip712::TypedData {
        crate::typed::typed_intent(intent)
    }

    /// Who must have signed, for each intent.
    ///
    /// `AcceptOffer` names both sides deliberately: it is the settlement of a
    /// negotiated trade, and a trade one party can settle unilaterally is not a
    /// trade. Operator intents return nothing and are therefore unreachable by
    /// any user signature.
    fn intent_authorities(intent: &Intent) -> Vec<zyn_vm::spec::AccountId> {
        use alloc::vec;
        match intent {
            Intent::SwapExactIn { account, .. }
            | Intent::SwapExactOut { account, .. }
            | Intent::AddLiquidity { account, .. }
            | Intent::RemoveLiquidity { account, .. }
            | Intent::RequestWithdrawal { account, .. }
            | Intent::CancelWithdrawal { account, .. }
            | Intent::BindWithdrawal { account, .. }
            | Intent::Reblind { account, .. } => vec![*account],

            Intent::Transfer { from, .. } => vec![*from],
            Intent::BurnItem { holder, .. } => vec![*holder],
            // Redeeming needs no counterparty: the holder burns their own item
            // for its share of the pool. Leaving it operator-only would make
            // the floor something we grant rather than something they hold.
            Intent::RedeemCollectionItem { holder, .. } => vec![*holder],
            Intent::FundCollection { from, .. } => vec![*from],
            Intent::CreateCollection { creator, .. }
            | Intent::MintCollectionItem { creator, .. }
            | Intent::AdvanceCollection { creator, .. } => vec![*creator],
            Intent::CreatePool { creator, .. }
            | Intent::CreateToken { creator, .. }
            | Intent::MintItem { creator, .. } => vec![*creator],

            // Both sides, or it is not an agreement.
            Intent::AcceptOffer { maker, taker, .. } => vec![*maker, *taker],

            // A resting offer is the other half of that: the maker agreed when
            // they placed it and gave up the asset to say so, which is what
            // lets the taker settle alone.
            Intent::PlaceOffer { maker, .. } | Intent::CancelOffer { maker, .. } => vec![*maker],
            Intent::TakeOffer { taker, .. } => vec![*taker],

            // Operator intents: no user signature reaches them.
            _ => Vec::new(),
        }
    }

    /// What each intent costs a session key in authority.
    ///
    /// Capabilities follow the economic effect rather than the transport. A
    /// transfer to an attacker's Zyn account is a total loss even though it
    /// never leaves the chain, so it must not share the default swap bit.
    ///
    /// Operator intents demand `CAP_DELEGATE`, which no delegation may hold —
    /// so they are unreachable by any session key, by construction rather than
    /// by a check someone could forget.
    fn intent_capability(intent: &Intent) -> u32 {
        use zyn_vm::session::{
            CAP_COLLECTION, CAP_DELEGATE, CAP_ITEM, CAP_LIQUIDITY, CAP_OFFER,
            CAP_PRIVACY, CAP_SWAP, CAP_TRANSFER, CAP_WITHDRAW,
        };
        match intent {
            Intent::SwapExactIn { .. } | Intent::SwapExactOut { .. } => CAP_SWAP,

            Intent::Transfer { .. } => CAP_TRANSFER,

            Intent::AcceptOffer { .. }
            | Intent::PlaceOffer { .. }
            | Intent::TakeOffer { .. }
            | Intent::CancelOffer { .. } => CAP_OFFER,

            Intent::AddLiquidity { .. }
            | Intent::RemoveLiquidity { .. }
            | Intent::CreatePool { .. } => CAP_LIQUIDITY,

            Intent::CreateToken { .. }
            | Intent::MintItem { .. }
            | Intent::BurnItem { .. } => CAP_ITEM,

            Intent::CreateCollection { .. }
            | Intent::MintCollectionItem { .. }
            | Intent::AdvanceCollection { .. }
            | Intent::FundCollection { .. }
            | Intent::RedeemCollectionItem { .. } => CAP_COLLECTION,

            Intent::Reblind { .. } => CAP_PRIVACY,

            // Value leaving the chain, and cancelling a request to.
            Intent::RequestWithdrawal { .. } | Intent::CancelWithdrawal { .. } => CAP_WITHDRAW,

            // Deciding where a payout lands is the one thing a warm key must
            // never do — it is the whole point of the binding.
            Intent::BindWithdrawal { .. } => CAP_DELEGATE,

            // Every operator-only and future intent fails closed. The default
            // requires CAP_DELEGATE, which Delegation::permits always refuses.
            _ => CAP_DELEGATE,
        }
    }

    fn delegation_policy(
        &self,
        delegation: &zyn_vm::session::Delegation,
        intent: &Intent,
    ) -> Result<(), zyn_vm::session::DelegationPolicyError> {
        use zyn_vm::session::DelegationPolicyError as E;
        if !delegation.constrained() {
            return Ok(());
        }
        let Intent::SwapExactIn { asset_in, path, amount_in, min_out, .. } = intent else {
            return Err(E::UnsupportedIntent);
        };
        if !delegation.allowed_assets.contains(asset_in) {
            return Err(E::WrongAsset);
        }
        if path.iter().any(|pool| !delegation.allowed_pools.contains(pool)) {
            return Err(E::WrongPool);
        }
        let max = delegation
            .max_per_action
            .iter()
            .find(|limit| limit.asset == *asset_in)
            .map(|limit| limit.amount)
            .ok_or(E::OverLimit)?;
        if *amount_in > max {
            return Err(E::OverLimit);
        }
        let mut asset = *asset_in;
        for id in path {
            let pool = self.pool(*id).ok_or(E::WrongPool)?;
            asset = if pool.asset0 == asset {
                pool.asset1
            } else if pool.asset1 == asset {
                pool.asset0
            } else {
                return Err(E::WrongPool);
            };
            if !delegation.allowed_assets.contains(&asset) {
                return Err(E::WrongAsset);
            }
        }
        let quoted = crate::vm::quote(self, *asset_in, path, *amount_in)
            .map_err(|_| E::WrongPool)?
            .amount_out;
        let floor = quoted
            .0
            .checked_mul((10_000u16 - delegation.max_slippage_bps) as i128)
            .and_then(|n| n.checked_div(10_000))
            .ok_or(E::Malformed)?;
        if min_out.0 < floor {
            return Err(E::ExcessiveSlippage);
        }
        Ok(())
    }

    fn encode_intent(intent: &Intent) -> Vec<u8> {
        crate::wire::encode_intent_bytes(intent)
    }

    fn decode_intent(d: &mut zyn_vm::read::Decoder) -> Option<Intent> {
        crate::wire::decode_intent(d).ok()
    }

    fn encode(&self) -> Vec<u8> {
        self.encode_state()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        SwapState::decode_state(bytes).ok()
    }

    fn account_ids(&self) -> Vec<SpecAccountId> {
        self.accounts.keys().copied().collect()
    }

    fn account_leaves(&self) -> Vec<Hash> {
        self.account_leaves_public()
    }

    fn account_record(&self, id: &SpecAccountId) -> Option<Vec<u8>> {
        SwapState::account_record(self, id)
    }

    fn leaf_of_record(record: &[u8]) -> Hash {
        zyn_vm::commit::hash_leaf(record)
    }

    fn gross_volume(&self) -> Fixed {
        self.epoch_gross_volume
    }

    /// ZynZap conserves three things: every token's supply against the units
    /// actually held, every xZEC against its confirmed ZEC backing, and every
    /// pool's reserves against the shares that claim them.
    ///
    /// This check already existed and was already exhaustive — it was simply
    /// never wired to anything but the test suite, which meant nothing stopped
    /// a committed root from asserting that value had been created. `S11` is
    /// what closed that gap.
    fn conserved(&self) -> Result<(), &'static str> {
        self.check_invariants()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zyn_vm::conformance::{assert_conforms, check, Fixture};
    use zyn_vm::spec::Provable;

    use crate::state::symbol;
    use crate::types::XZEC;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }
    use crate::types::AccountId;

    /// A chain with balances, a pool, an LP position and a pending exit — so
    /// the suite exercises sections the spec does not know the shape of.
    fn fixture() -> Fixture<SwapState> {
        let mut s = SwapState::new(7, Params::v1());
        let go = |s: &mut SwapState, i: Intent| {
            let at = s.seq;
            let r = crate::vm::apply(s, &SequencedIntent { seq: at + 1, intent: i });
            assert!(!r.iter().any(|x| x.is_rejection()), "setup rejected: {:?}", r);
        };
        for n in 1..=4u8 {
            {
                let observed = s.backing_of(XZEC).add(Fixed::whole(10_000 * n as i64)).unwrap();
                go(&mut s, Intent::AttestVaultBalance { asset: XZEC, observed });
                let i = Intent::next_deposit(&s, acct(n), XZEC, Fixed::whole(10_000 * n as i64), [0u8; 32]);
                go(&mut s, i);
            }
        }
        // Deposits are not spendable until the epoch containing them has been
        // anchored, so a setup that goes on to spend must seal and confirm.
        let at = s.epoch;
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch: at });
        go(&mut s, Intent::CreateToken {
            creator: acct(1),
            symbol: symbol(b"CAT"),
            supply: Fixed::whole(1_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(1_000),
            token_liquidity: Fixed::whole(500_000),
            fee_bps: 30,
        });
        go(&mut s, Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: alloc::vec![1],
            amount_in: Fixed::whole(50),
            min_out: Fixed::ZERO,
        });
        go(&mut s, Intent::RequestWithdrawal { account: acct(3), asset: XZEC, amount: Fixed::whole(100), destination: [0u8; 32] });

        let accepted = Intent::next_deposit(&s, acct(5), XZEC, Fixed::whole(1), [0u8; 32]);
        Fixture {
            state: s,
            accepted,
            // Nobody holds asset 99.
            rejected: Intent::Transfer {
                from: acct(9),
                to: acct(1),
                asset: XZEC,
                amount: Fixed::whole(1),
            },
            // A run with variety: a swap, liquidity moving, and a transfer, so
            // determinism and conservation are checked against more than one
            // shape of state change.
            sequence: alloc::vec![
                Intent::SwapExactIn {
                    account: acct(1),
                    asset_in: XZEC,
                    path: alloc::vec![1],
                    amount_in: Fixed::whole(5),
                    min_out: Fixed::ZERO,
                },
                Intent::Transfer {
                    from: acct(1),
                    to: acct(2),
                    asset: XZEC,
                    amount: Fixed::whole(1),
                },
                Intent::Checkpoint,
            ],
        }
    }

    /// The headline: ZynZap satisfies the microchain VM specification.
    #[test]
    fn zynzap_conforms_to_the_microchain_spec() {
        assert_conforms(fixture());
    }

    /// The suite must be capable of failing, or passing it means nothing. A VM
    /// whose sections are mislabelled is caught by S6.
    #[test]
    fn the_conformance_suite_catches_a_broken_vm() {
        struct Broken(SwapState);
        // Everything delegates except `sections`, which swaps the accounts
        // section for the pools one — the kind of mistake that would silently
        // break every user's exit proof.
        impl Clone for Broken {
            fn clone(&self) -> Self {
                Broken(self.0.clone())
            }
        }
        impl MicrochainVm for Broken {
            type Intent = Intent;
            type Receipt = Receipt;
            type Params = Params;
            const VM_NAME: &'static str = "broken";
            const VM_VERSION: u16 = 1;
            fn genesis(c: u32, p: Params) -> Self {
                Broken(SwapState::new(c, p))
            }
            fn chain_id(&self) -> u32 {
                self.0.chain_id
            }
            fn seq(&self) -> u64 {
                self.0.seq
            }
            fn epoch(&self) -> u64 {
                self.0.epoch
            }
            fn apply(&mut self, seq: u64, i: &Intent) -> Vec<Receipt> {
                MicrochainVm::apply(&mut self.0, seq, i)
            }
            fn sections(&self) -> Vec<Hash> {
                alloc::vec![
                    self.0.header_leaf_public(),
                    self.0.pools_root(), // wrong: not the accounts root
                    self.0.tokens_root(),
                    self.0.accounts_root(),
                ]
            }
            fn seal_intent() -> Intent {
                Intent::Checkpoint
            }
            fn sealed(r: &[Receipt]) -> Option<Checkpoint> {
                <SwapState as MicrochainVm>::sealed(r)
            }
            fn as_sealed(&self, cp: &Checkpoint) -> Option<Self> {
                self.0.as_sealed(cp).map(Broken)
            }
            fn rejected(r: &Receipt) -> bool {
                r.is_rejection()
            }
            fn unprovable(r: &Receipt) -> bool {
                <SwapState as MicrochainVm>::unprovable(r)
            }
            fn encode_intent(i: &Intent) -> Vec<u8> {
                crate::wire::encode_intent_bytes(i)
            }
            fn decode_intent(d: &mut zyn_vm::read::Decoder) -> Option<Intent> {
                crate::wire::decode_intent(d).ok()
            }
            fn encode(&self) -> Vec<u8> {
                self.0.encode_state()
            }
            fn decode(b: &[u8]) -> Option<Self> {
                SwapState::decode_state(b).ok().map(Broken)
            }
            fn account_ids(&self) -> Vec<SpecAccountId> {
                self.0.accounts.keys().copied().collect()
            }
            fn account_leaves(&self) -> Vec<Hash> {
                self.0.account_leaves_public()
            }
            fn account_record(&self, id: &SpecAccountId) -> Option<Vec<u8>> {
                SwapState::account_record(&self.0, id)
            }
            fn leaf_of_record(r: &[u8]) -> Hash {
                zyn_vm::commit::hash_leaf(r)
            }
            fn gross_volume(&self) -> Fixed {
                self.0.epoch_gross_volume
            }
            fn conserved(&self) -> Result<(), &'static str> {
                self.0.check_invariants()
            }
        }

        let f = fixture();
        let violations = check(Fixture {
            state: Broken(f.state),
            accepted: f.accepted,
            rejected: f.rejected, sequence: Vec::new(),
        });
        assert!(!violations.is_empty(), "the suite passed a VM with mislabelled sections");
        assert!(
            violations.iter().any(|v| v.rule == "S6"),
            "the section violation was not reported as S6: {:?}",
            violations
        );
    }

    /// The spec's derived exit path and ZynZap's own hand-written one must
    /// agree, or a holder proving through the infrastructure would get a
    /// different answer than one proving through the application.
    #[test]
    fn the_derived_exit_path_matches_the_hand_written_one() {
        let s = fixture().state;
        for id in MicrochainVm::account_ids(&s) {
            let spec_path = Provable::account_proof(&s, &id).expect("spec path");
            let own_path = SwapState::account_proof(&s, &id).expect("swapvm path");
            assert_eq!(spec_path, own_path, "the two exit paths disagree for {}", id[0]);
        }
    }

    /// S11 protects the invariant the custody model rests on. A state whose
    /// xZEC has drifted from its ZEC backing cannot be committed, however it
    /// got there.
    #[test]
    fn a_batch_that_breaks_the_backing_invariant_cannot_commit() {
        use zyn_vm::zvm;

        let f = fixture();
        let mut s = f.state;
        let before = MicrochainVm::state_root(&s);
        let at = s.seq;

        // A conserving batch commits.
        let credit = Intent::next_deposit(&s, acct(6), XZEC, Fixed::whole(5), [0u8; 32]);
        zvm::apply_batch(&mut s, &[(at + 1, credit)])
        .expect("a conserving batch must commit");
        assert_ne!(MicrochainVm::state_root(&s), before);

        // Now break the backing behind the VM's back — the shape of a bug that
        // credits xZEC without recording the ZEC behind it — and confirm no
        // batch can commit from there.
        let mut drifted = s.clone();
        let b = drifted.tokens.get_mut(&XZEC).unwrap().vault.as_mut().unwrap();
        b.confirmed = b.confirmed.sub(Fixed::whole(1)).unwrap();
        assert!(drifted.conserved().is_err(), "unbacked xZEC passed conservation");

        let stuck = MicrochainVm::state_root(&drifted);
        let at = drifted.seq;
        let credit = Intent::next_deposit(&drifted, acct(7), XZEC, Fixed::whole(1), [0u8; 32]);
        let batch = [(at + 1, credit)];
        assert!(
            matches!(zvm::apply_batch(&mut drifted, &batch), Err(zvm::ZvmError::NotConserved(_))),
            "an unbacked state kept committing"
        );
        assert_eq!(MicrochainVm::state_root(&drifted), stuck);
    }

    #[test]
    fn the_spec_root_and_the_application_root_are_the_same_value() {
        let s = fixture().state;
        assert_eq!(MicrochainVm::state_root(&s), SwapState::state_root(&s));
        assert_eq!(
            MicrochainVm::sections(&s)[zyn_vm::spec::SECTION_ACCOUNTS],
            s.accounts_root()
        );
    }

    #[test]
    fn an_agent_policy_binds_assets_pools_amount_and_slippage() {
        use zyn_vm::session::{AssetLimit, Delegation, DelegationPolicyError as E};

        let s = fixture().state;
        let amount = Fixed::whole(5);
        let quote = crate::vm::quote(&s, XZEC, &[1], amount).unwrap();
        let floor = Fixed::raw(quote.amount_out.0 * 9_900 / 10_000);
        let intent = Intent::SwapExactIn {
            account: acct(1),
            asset_in: XZEC,
            path: alloc::vec![1],
            amount_in: amount,
            min_out: floor,
        };
        let mut mandate = Delegation::session(acct(1), [9u8; 32], s.epoch, 10);
        mandate.allowed_assets = alloc::vec![XZEC, quote.asset_out];
        mandate.allowed_assets.sort_unstable();
        mandate.allowed_pools = alloc::vec![1];
        mandate.max_per_action = alloc::vec![AssetLimit { asset: XZEC, amount }];
        mandate.max_slippage_bps = 100;
        mandate.salt = [7u8; 32];
        assert_eq!(s.delegation_policy(&mandate, &intent), Ok(()));

        let mut wrong_asset = mandate.clone();
        wrong_asset.allowed_assets.retain(|asset| *asset == XZEC);
        assert_eq!(s.delegation_policy(&wrong_asset, &intent), Err(E::WrongAsset));
        let mut wrong_pool = mandate.clone();
        wrong_pool.allowed_pools = alloc::vec![2];
        assert_eq!(s.delegation_policy(&wrong_pool, &intent), Err(E::WrongPool));
        let mut over = intent.clone();
        if let Intent::SwapExactIn { amount_in, .. } = &mut over { *amount_in = Fixed::whole(6); }
        assert_eq!(s.delegation_policy(&mandate, &over), Err(E::OverLimit));
        let mut loose = intent;
        if let Intent::SwapExactIn { min_out, .. } = &mut loose { *min_out = Fixed::ZERO; }
        assert_eq!(s.delegation_policy(&mandate, &loose), Err(E::ExcessiveSlippage));
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use crate::tx::Intent;
    use zyn_vm::session::{
        CAP_COLLECTION, CAP_DELEGATE, CAP_ITEM, CAP_LIQUIDITY, CAP_OFFER,
        CAP_PRIVACY, CAP_SWAP, CAP_TRANSFER, CAP_WITHDRAW,
    };

    const A: zyn_vm::spec::AccountId = [1u8; 32];

    /// A holder must be able to redeem their own item. Left as an operator
    /// intent, the floor would be something the operator grants rather than
    /// something the holder holds — which is the opposite of the claim.
    #[test]
    fn a_holder_authorises_their_own_redemption() {
        let i = Intent::RedeemCollectionItem { holder: A, asset: 7 };
        assert_eq!(<SwapState as MicrochainVm>::intent_authorities(&i), alloc::vec![A]);
        assert_eq!(<SwapState as MicrochainVm>::intent_capability(&i), CAP_COLLECTION);
    }

    /// Running a collection is the creator's, and each of these names them.
    #[test]
    fn running_a_collection_has_its_own_capability() {
        for i in [
            Intent::CreateCollection { creator: A, symbol: *b"NAP\0\0\0\0\0", cap: 10, fee_bps: 100 },
            Intent::MintCollectionItem { creator: A, collection: 1, to: [2u8; 32], symbol: *b"NAP\0\0\0\0\0", content: [3u8; 32] },
            Intent::AdvanceCollection { creator: A, collection: 1, to: 1 },
        ] {
            assert_eq!(<SwapState as MicrochainVm>::intent_authorities(&i), alloc::vec![A], "{:?}", i);
            assert_eq!(<SwapState as MicrochainVm>::intent_capability(&i), CAP_COLLECTION, "{:?}", i);
        }
    }

    /// Funding hands back no position, so a swap-only session must not be able
    /// to do it even though a separately approved collection session can.
    #[test]
    fn funding_a_pool_needs_a_cold_key() {
        let i = Intent::FundCollection { from: A, collection: 1, amount: crate::Fixed::whole(1) };
        assert_eq!(<SwapState as MicrochainVm>::intent_authorities(&i), alloc::vec![A]);
        assert_eq!(<SwapState as MicrochainVm>::intent_capability(&i), CAP_COLLECTION);
    }

    #[test]
    fn every_user_effect_has_a_distinct_capability_class() {
        let cases = [
            (Intent::SwapExactIn { account: A, asset_in: 0, path: alloc::vec![1], amount_in: crate::Fixed::whole(1), min_out: crate::Fixed::ZERO }, CAP_SWAP),
            (Intent::Transfer { from: A, to: [2u8; 32], asset: 0, amount: crate::Fixed::whole(1) }, CAP_TRANSFER),
            (Intent::PlaceOffer { maker: A, offer_asset: 0, offer_amount: crate::Fixed::whole(1), want_asset: 1, want_amount: crate::Fixed::whole(1), expires_at_epoch: 10 }, CAP_OFFER),
            (Intent::AddLiquidity { account: A, pool: 1, max0: crate::Fixed::whole(1), max1: crate::Fixed::whole(1), min_shares: crate::Fixed::ZERO }, CAP_LIQUIDITY),
            (Intent::MintItem { creator: A, symbol: *b"NAP\0\0\0\0\0", supply: crate::Fixed::whole(1), bond: crate::Fixed::whole(1), content: [3u8; 32] }, CAP_ITEM),
            (Intent::CreateCollection { creator: A, symbol: *b"NAP\0\0\0\0\0", cap: 10, fee_bps: 100 }, CAP_COLLECTION),
            (Intent::Reblind { account: A, blind: [4u8; 32] }, CAP_PRIVACY),
            (Intent::RequestWithdrawal { account: A, asset: 0, amount: crate::Fixed::whole(1), destination: [5u8; 32] }, CAP_WITHDRAW),
            (Intent::BindWithdrawal { account: A, destination: [6u8; 32] }, CAP_DELEGATE),
        ];
        for (intent, expected) in cases {
            assert_eq!(<SwapState as MicrochainVm>::intent_capability(&intent), expected, "{:?}", intent);
        }
    }
}
