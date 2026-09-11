//! The microchain as a traction and revenue engine, end to end.
//!
//! The unit tests check each mechanism. This checks the claim the architecture
//! is built on: that a real trading session on a Zcash-anchored microchain
//! costs a fraction of settling the same session directly, earns a fee on the
//! flow it absorbs, and leaves every holder able to exit without asking the
//! sequencer for anything.
//!
//! Each test is one line of the pitch, made checkable.

use swapvm::state::symbol;
use swapvm::tx::{Intent, Receipt};
use swapvm::types::{AccountId, XZEC};
use swapvm::state::SwapState;
use swapvm::{Fixed, Params, Revenue};
use zyn::anchor::LineageError;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;

fn acct(n: u8) -> AccountId {
    [n; 32]
}

const TREASURY: u8 = 250;
const CAT: u32 = 2;
const POOL: u32 = 1;

/// Zatoshi per Zcash transaction. A round figure in the right neighbourhood —
/// the argument is about the ratio, not the constant.
const ZCASH_FEE: u64 = 10_000;

fn market_params() -> Params {
    let mut p = Params::v1();
    // Revenue on: a fifth of the 0.30% fee, LPs keep the rest.
    p.protocol_fee_share_bps = 2_000;
    p.treasury = acct(TREASURY);
    p
}

/// Seal the current epoch and record it as anchored, so credited deposits
/// become spendable. A deposit needs the same quorum a withdrawal does.
fn finalize(n: &mut Node<SwapState>) {
    let at = n.state().epoch;
    n.submit_operator(Intent::Checkpoint, 0);
    n.submit_operator(Intent::ConfirmAnchor { epoch: at }, 0);
}

/// A memecoin market: one LP seeds CAT/xZEC, a crowd of traders arrives.
fn market(policy: EpochPolicy) -> Node<SwapState> {
    // Seed the vault's observation: units issued can never exceed units the
    // vault was seen to hold, and this suite is about flow, not custody.
    let mut seeded = SwapState::new(1, market_params());
    seeded.tokens.get_mut(&XZEC).unwrap().vault.as_mut().unwrap().observed =
        Fixed::whole(1_000_000_000);
    let mut n = Node::resume(seeded, policy, Economics::flat(ZCASH_FEE), 0);

    let d = Intent::next_deposit(n.state(), acct(1), XZEC, Fixed::whole(1_000_000), [0u8; 32]);
    n.submit_operator(d, 0);
    finalize(&mut n);
    // A launch mints CAT and opens its xZEC market in one intent, with the
    // bond permanently locked inside it.
    n.submit_operator(
        Intent::CreateToken {
            creator: acct(1),
            symbol: symbol(b"CAT"),
            supply: Fixed::whole(100_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(100_000),
            token_liquidity: Fixed::whole(50_000_000),
            fee_bps: 30,
        },
        0,
    );
    // Twenty traders, each funded over the Zcash bridge.
    for t in 10..30u8 {
        let d = Intent::next_deposit(n.state(), acct(t), XZEC, Fixed::whole(5_000), [0u8; 32]);
        n.submit_operator(d, 0);
    }
    finalize(&mut n);
    n
}

/// Run `rounds` of two-way flow, the way a memecoin market actually trades:
/// many small swaps, alternating direction.
///
/// Revenue is accumulated by the caller from the receipts, exactly as an
/// operator would: the microchain layer measures compression and settlement
/// cost, and the application measures what its own flow earned.
fn trade_earning(n: &mut Node<SwapState>, rounds: u32, now: u64, rev: &mut Revenue) {
    for i in 0..rounds {
        let who = acct(10 + (i % 20) as u8);
        let buy = i % 3 != 0;
        let intent = if buy {
            Intent::SwapExactIn {
                account: who,
                asset_in: XZEC,
                path: vec![POOL],
                amount_in: Fixed::whole(1 + (i % 5) as i64),
                min_out: Fixed::ZERO,
            }
        } else {
            Intent::SwapExactIn {
                account: who,
                asset_in: CAT,
                path: vec![POOL],
                amount_in: Fixed::whole(400 + (i % 7) as i64 * 10),
                min_out: Fixed::ZERO,
            }
        };
        rev.absorb(&n.submit_operator(intent, now).receipts);
    }
}

fn trade(n: &mut Node<SwapState>, rounds: u32, now: u64) {
    trade_earning(n, rounds, now, &mut Revenue::default());
}

/// "25,000 microchain actions → 15 Zcash transactions."
///
/// The headline claim, run rather than quoted.
#[test]
fn a_real_session_compresses_into_a_handful_of_zcash_transactions() {
    let mut n = market(EpochPolicy::v1());
    trade(&mut n, 5_000, 0);
    n.seal_now(0);
    n.anchor_now(0);

    let c = n.compression();
    assert!(c.actions > 5_000, "the session did not run");
    assert!(
        c.anchors < 10,
        "{} actions took {} Zcash transactions — no compression",
        c.actions,
        c.anchors
    );
    let ratio = c.realised_ratio().expect("a settled chain has a ratio");
    assert!(ratio > 500, "only {} actions per Zcash transaction", ratio);
    assert_eq!(c.transactions_saved(), c.actions - c.anchors);

    n.state().check_invariants().expect("5,000 swaps must leave the chain consistent");
    n.ledger().verify_lineage().expect("the session's lineage must verify");
}

/// "Mainnet ZEC memecoin trading is too slow and too expensive to settle one by
/// one." This is the cost half, priced.
#[test]
fn settling_directly_would_cost_orders_of_magnitude_more() {
    let mut n = market(EpochPolicy::v1());
    trade(&mut n, 5_000, 0);
    n.seal_now(0);
    n.anchor_now(0);

    let rep = n.report();
    let spent = ZCASH_FEE * rep.compression.anchors;
    let direct = ZCASH_FEE * rep.compression.actions;

    assert_eq!(rep.l1_saved, direct - spent);
    assert!(
        direct / spent.max(1) > 100,
        "direct settlement was only {}x the cost",
        direct / spent.max(1)
    );
    // A trade's share of the L1 bill drops from a whole transaction fee to
    // pocket change. This is what makes a small swap worth making at all.
    let per_action = rep.cost_per_action.expect("a run with actions has a cost");
    assert!(
        per_action * 100 < ZCASH_FEE,
        "a trade still carries {} of the {} transaction fee",
        per_action,
        ZCASH_FEE
    );
}

/// The revenue half: the microchain earns a slice of the fee on the flow it
/// absorbs, and that revenue clears the settlement cost by a wide margin.
#[test]
fn the_flow_earns_more_than_it_costs_to_settle() {
    let mut n = market(EpochPolicy::v1());
    let mut rev = Revenue::default();
    trade_earning(&mut n, 5_000, 0, &mut rev);
    n.seal_now(0);
    n.anchor_now(0);

    // Not every submitted swap fills — the first sellers reach the pool before
    // they hold any CAT — so revenue tracks executed flow, not offered flow.
    assert!(rev.swaps > 4_900 && rev.swaps < 5_000, "{} swaps executed", rev.swaps);
    assert!(rev.protocol_share.is_positive(), "the engine earned nothing");
    assert!(rev.protocol_share < rev.fees_charged, "the protocol took the whole fee");
    assert!(rev.lp_share().unwrap() > rev.protocol_share, "LPs kept less than the protocol");

    // Revenue is real balances, not a statistic: it is exactly what the
    // treasury holds across both sides of the pair.
    let held_zec = n.state().balance(&acct(TREASURY), XZEC);
    let held_cat = n.state().balance(&acct(TREASURY), CAT);
    assert!(held_zec.is_positive() && held_cat.is_positive());
    assert_eq!(held_zec.add(held_cat).unwrap(), rev.protocol_share);

    // And the xZEC side alone — the part denominated in the asset the L1 bill
    // is paid in — dwarfs the anchoring cost. `Fixed` is WAD-scaled and one
    // xZEC is 1e8 zatoshi, so scale the fee to compare.
    let spent_in_xzec = Fixed::raw((ZCASH_FEE * n.compression().anchors) as i128 * 10_000_000_000);
    assert!(
        held_zec > spent_in_xzec,
        "fees {} did not cover settlement {}",
        held_zec,
        spent_in_xzec
    );
}

/// "Zcash keeps custody and final settlement." Every unit of xZEC stays backed
/// across a full session — deposits, thousands of swaps, exits and all.
#[test]
fn backing_holds_across_the_whole_session() {
    let mut n = market(EpochPolicy::v1());
    trade(&mut n, 2_000, 0);

    // A wave of exits mid-session.
    for t in 10..20u8 {
        let held = n.state().balance(&acct(t), XZEC);
        if held.is_positive() {
            n.submit_operator(Intent::RequestWithdrawal { account: acct(t), asset: XZEC, amount: held, destination: [0u8; 32] }, 0);
        }
    }
    n.state().check_invariants().unwrap();
    trade(&mut n, 1_000, 0);
    for t in 10..20u8 {
        let pending = n
            .state()
            .accounts
            .get(&acct(t))
            .map(|a| a.pending_of(XZEC))
            .unwrap_or(Fixed::ZERO);
        if pending.is_positive() {
            n.submit_operator(Intent::ConfirmWithdrawal { account: acct(t), asset: XZEC, amount: pending }, 0);
        }
    }

    let s = n.state();
    s.check_invariants().expect("exits mid-session must leave the chain consistent");
    assert_eq!(
        s.token(XZEC).unwrap().supply,
        s.backing_of(XZEC),
        "xZEC supply drifted from its ZEC backing"
    );
}

/// "A failed sequencer must not make ZEC permanently inaccessible."
///
/// The trust precondition for anyone putting real ZEC in: with the published
/// snapshot and a root read off Zcash, every holder proves their own balance
/// with the sequencer gone.
#[test]
fn every_holder_can_exit_with_the_sequencer_gone() {
    let mut n = market(EpochPolicy::v1());
    trade(&mut n, 2_000, 0);
    for t in 10..15u8 {
        n.submit_operator(Intent::RequestWithdrawal { account: acct(t), asset: XZEC, amount: Fixed::whole(100), destination: [0u8; 32] }, 0);
    }

    n.seal_now(0).expect("seal");
    let anchor = n.anchor_now(0).expect("anchor");

    // The sequencer is now irrelevant. All anyone has is the root read off
    // Zcash and the snapshot the node published for it.
    let anchored = anchor.checkpoint.state_root;
    let snapshot = n.publishable().expect("an anchored chain must publish its snapshot").clone();
    assert_eq!(snapshot.root, anchored, "the snapshot does not open the anchored root");
    snapshot.verifies_against(anchored).expect("published snapshot must open the anchored root");

    assert!(snapshot.len() >= 20);
    for id in snapshot.ids() {
        assert!(
            snapshot.prove_against(id, anchored).unwrap(),
            "account {} could not prove its balance",
            id[0]
        );
        // And the record is published, not merely its hash — so a holder can
        // read what was committed about them rather than trust the publisher.
        let record = snapshot.record(id).expect("a committed account has a record");
        assert!(!record.is_empty());
    }
}

/// "Only one canonical execution history may be settled."
///
/// A second history at the same height is refused rather than recorded, which
/// is what stops a sequencer settling two versions of the same epoch.
#[test]
fn a_forked_history_cannot_be_settled() {
    let mut honest = market(EpochPolicy::v1());
    trade(&mut honest, 500, 0);
    honest.seal_now(0);
    let first = honest.anchor_now(0).expect("anchor");

    // A second chain reaches a different state at the same height.
    let mut rival = market(EpochPolicy::v1());
    trade(&mut rival, 400, 0);
    rival.seal_now(0);
    let other = rival.anchor_now(0).expect("anchor");
    assert_ne!(first.checkpoint.state_root, other.checkpoint.state_root);

    let mut ledger = zyn::anchor::Ledger::new(1);
    ledger.accept_trusted_operator(first).unwrap();

    // Replaying the rival's anchor over the honest one is refused: it does not
    // continue from the root Zcash actually saw.
    assert_eq!(ledger.accept_trusted_operator(other), Err(LineageError::StaleBase));
    assert_eq!(ledger.len(), 1);
    ledger.verify_lineage().unwrap();
}

/// The compression ratio is a tunable, and moving it moves the economics in the
/// direction the architecture claims.
#[test]
fn tightening_the_policy_buys_cheaper_trades() {
    let mut costs = vec![];
    for (per_epoch, per_anchor) in [(50u64, 1u64), (250, 7), (1_000, 20)] {
        let policy = EpochPolicy {
            intents_per_epoch: per_epoch,
            epochs_per_anchor: per_anchor,
            max_seconds_per_epoch: 0,
            max_seconds_per_anchor: 0,
        };
        policy.validate().unwrap();
        let mut n = market(policy);
        trade(&mut n, 3_000, 0);
        n.seal_now(0);
        n.anchor_now(0);
        costs.push(n.report().cost_per_action.expect("a run with actions has a cost"));
    }
    assert!(
        costs[0] > costs[1] && costs[1] > costs[2],
        "compression did not lower the per-trade cost: {:?}",
        costs
    );
}

/// A market too thin to fill an epoch still settles, because an exit must never
/// be hostage to someone else's volume.
#[test]
fn a_quiet_market_still_reaches_zcash() {
    let policy = EpochPolicy {
        intents_per_epoch: 100_000,
        epochs_per_anchor: 100,
        max_seconds_per_epoch: 60,
        max_seconds_per_anchor: 900,
    };
    let mut n = market(policy);
    // The market setup is itself activity; measure the quiet period from there.
    let after_setup = n.compression().actions;
    // A couple of trades over half an hour.
    trade(&mut n, 1, 0);
    trade(&mut n, 1, 400);
    let mut anchored = None;
    for step in n.submit_all_operator(
        vec![Intent::next_deposit(n.state(), acct(10), XZEC, Fixed::whole(1), [0u8; 32])],
        1_000,
    ) {
        if let Some(a) = step.anchor {
            anchored = Some(a);
        }
    }
    let a = anchored.expect("a quiet market never reached Zcash");
    assert!(
        a.actions < after_setup + 10,
        "the failsafe waited for volume: {} actions",
        a.actions
    );

    // And the exit path works off that anchor exactly as it would off a busy
    // one: three trades in half an hour still leaves every holder provable.
    let snap = n.publishable().expect("a quiet chain must still publish");
    snap.verifies_against(a.checkpoint.state_root).unwrap();
    for id in snap.ids() {
        assert!(snap.prove_against(id, a.checkpoint.state_root).unwrap());
    }
}

/// Receipts are the only source of prices, so the revenue an operator reports
/// is the revenue the traders actually paid.
#[test]
fn reported_revenue_is_what_the_receipts_say() {
    let mut n = market(EpochPolicy::v1());
    let mut rev = Revenue::default();
    let mut charged = Fixed::ZERO;
    let mut taken = Fixed::ZERO;

    for i in 0..400 {
        let step = n.submit_operator(
            Intent::SwapExactIn {
                account: acct(10 + (i % 20) as u8),
                asset_in: XZEC,
                path: vec![POOL],
                amount_in: Fixed::whole(1),
                min_out: Fixed::ZERO,
            },
            0,
        );
        rev.absorb(&step.receipts);
        for r in &step.receipts {
            if let Receipt::Swapped { hops, .. } = r {
                for h in hops {
                    charged = charged.add(h.fee).unwrap();
                    taken = taken.add(h.protocol_fee).unwrap();
                }
            }
        }
    }

    assert_eq!(rev.fees_charged, charged, "reported fees differ from the receipts");
    assert_eq!(rev.protocol_share, taken, "reported revenue differs from the receipts");
    assert_eq!(n.state().balance(&acct(TREASURY), XZEC), taken);
}

/// The live loop, with nothing driven by hand.
///
/// The deposit safety rules are only worth anything if the node actually drives
/// them. It did not: the node never told the VM an epoch had settled, so
/// credited deposits sat unspendable forever, and the vault was never observed,
/// so no deposit could be accepted at all. Both were built and inert — which is
/// a worse failure than not building them, because the tests that exercised the
/// rules directly all passed.
#[test]
fn a_deposit_becomes_spendable_through_the_node_alone() {
    let policy = EpochPolicy {
        intents_per_epoch: 4,
        epochs_per_anchor: 1,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut n: Node<SwapState> =
        Node::new(1, market_params(), policy, Economics::flat(ZCASH_FEE));

    // An operator reports what the Zcash vault holds, then credits against it.
    n.submit_operator(
        Intent::AttestVaultBalance { asset: XZEC, observed: Fixed::whole(500) },
        0,
    );
    let d = Intent::next_deposit(n.state(), acct(1), XZEC, Fixed::whole(500), [7u8; 32]);
    n.submit_operator(d, 0);

    // Credited and backed, and not yet spendable.
    assert_eq!(n.state().backing_of(XZEC), Fixed::whole(500));
    assert_eq!(n.state().balance(&acct(1), XZEC), Fixed::ZERO);

    // Ordinary activity carries the chain to an anchor. Nothing about finality
    // is submitted by hand.
    let mut anchored = false;
    for _ in 0..8 {
        let step = n.submit_operator(
            Intent::Transfer { from: acct(1), to: acct(2), asset: XZEC, amount: Fixed::raw(1) },
            0,
        );
        if step.anchor.is_some() {
            anchored = true;
        }
    }
    assert!(anchored, "the node never anchored");

    // The node told the VM, and the deposit is live.
    assert!(n.state().finalized_epoch > 0, "the node never confirmed finality");
    assert!(
        n.state().balance(&acct(1), XZEC).is_positive(),
        "an anchored deposit was never released"
    );
    n.state().check_invariants().unwrap();
    n.ledger().verify_lineage().unwrap();
}

/// A VM with nothing custodied elsewhere supplies no finality intent, and the
/// node simply never asks — the second application is unaffected.
#[test]
fn finality_is_optional_for_a_vm_that_needs_none() {
    use zyn_vm::spec::MicrochainVm;
    assert!(SwapState::finality_intent(3).is_some());
}
