//! End-to-end tests over the whole microchain.
//!
//! The unit tests in each module check one mechanism. These check the property
//! the system actually owes its users: that a realistic stream of intents
//! leaves the chain consistent, reproducible, and backed — after *every* step,
//! not just at the end.
//!
//! The spine is the demo the project plan describes: create CAT and DOG,
//! pool them against xZEC, deposit, swap, route CAT to DOG through xZEC, add
//! and remove liquidity, checkpoint, withdraw.

use swapvm::fixed::{Fixed, WAD};
use swapvm::state::{symbol, SwapState};
use swapvm::tx::{Intent, Receipt, Reject, SequencedIntent};
use swapvm::types::{legacy_id, AccountId, AssetId, Params, PoolId, XZEC};
use swapvm::vm::{apply, apply_batch, transition};

fn acct(n: u8) -> AccountId {
    [n; 32]
}

/// A chain driver that re-checks every invariant after every single intent.
///
/// Running the check per intent rather than per batch is deliberate: a bug that
/// breaks and then restores an invariant inside one batch is exactly the kind
/// that a per-batch check would miss and a prover would later be asked to
/// attest to.
struct Chain {
    state: SwapState,
    seq: u64,
}

impl Chain {
    fn new() -> Self {
        Chain {
            state: SwapState::new(1, Params::v1()),
            seq: 0,
        }
    }

    fn push(&mut self, intent: Intent) -> Vec<Receipt> {
        self.seq += 1;
        let r = apply(
            &mut self.state,
            &SequencedIntent {
                seq: self.seq,
                intent: intent.clone(),
            },
        );
        self.state
            .check_invariants()
            .unwrap_or_else(|e| panic!("invariant broken after {:?}: {}", intent, e));
        r
    }

    /// Apply an intent that is expected to succeed.
    fn ok(&mut self, intent: Intent) -> Vec<Receipt> {
        let r = self.push(intent.clone());
        assert!(
            !r.iter().any(|x| x.is_rejection()),
            "expected success, got {:?} for {:?}",
            r,
            intent
        );
        r
    }

    /// Apply an intent that is expected to be rejected for a specific reason,
    /// and assert it changed nothing.
    fn rejects(&mut self, intent: Intent, reason: Reject) {
        let before = self.state.state_root();
        let seq_before = self.state.seq;
        let r = self.push(intent.clone());
        assert_eq!(
            r.iter().find_map(|x| x.rejection()),
            Some(reason),
            "wrong rejection for {:?}: {:?}",
            intent,
            r
        );
        // The root must move — the sequence and the epoch commitment advanced —
        // but nothing else may have.
        assert_ne!(
            self.state.state_root(),
            before,
            "a rejection did not advance history"
        );
        assert_eq!(self.state.seq, seq_before + 1);
    }

    /// Observe the vault growing, then credit the deposit — the operational
    /// order, and the only one the chain accepts: units issued can never exceed
    /// units last observed.
    fn deposit(&mut self, who: u8, asset: AssetId, amount: Fixed) {
        let observed = self.state.backing_of(asset).add(amount).unwrap();
        self.ok(Intent::AttestVaultBalance { asset, observed });
        let credit = Intent::next_deposit(&self.state, acct(who), asset, amount, [0u8; 32]);
        self.ok(credit);
    }

    /// Seal the current epoch and record it as anchored.
    ///
    /// Deposits are credited unspendable and released when the epoch containing
    /// them is anchored, so any setup that deposits and then spends has to pass
    /// through here — which is the point: it is the same quorum step a
    /// withdrawal needs.
    fn finalize(&mut self) {
        let at = self.state.epoch;
        self.ok(Intent::Checkpoint);
        self.ok(Intent::ConfirmAnchor { epoch: at });
    }

    fn bal(&self, who: u8, asset: AssetId) -> Fixed {
        self.state.balance(&acct(who), asset)
    }
}

/// CAT is asset 2, DOG is asset 3 (LP assets take the ids in between).
/// Returns `(cat, dog, cat_pool, dog_pool)`.
fn seeded() -> (Chain, AssetId, AssetId, PoolId, PoolId) {
    let mut c = Chain::new();

    // Two traders and one LP arrive over the Zcash bridge.
    c.deposit(1, XZEC, Fixed::whole(100_000));
    c.finalize();
    c.deposit(2, XZEC, Fixed::whole(10_000));

    c.finalize();

    // A launch mints the token and opens its xZEC market in one intent: there
    // is no state in which a token exists without one.
    // CAT/xZEC at 1 ZEC = 500 CAT, DOG/xZEC at 1 ZEC = 500 DOG.
    let launch = |c: &mut Chain, sym: &[u8]| {
        let r = c.ok(Intent::CreateToken {
            creator: acct(1),
            symbol: symbol(sym),
            supply: Fixed::whole(10_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(10_000),
            token_liquidity: Fixed::whole(5_000_000),
            fee_bps: 30,
        });
        let asset = match r[0] {
            Receipt::TokenCreated { asset, .. } => asset,
            _ => panic!("expected TokenCreated"),
        };
        let pool = match r[1] {
            Receipt::PoolCreated { pool, .. } => pool,
            _ => panic!("a launch must open a pool"),
        };
        (asset, pool)
    };
    let (cat, cat_pool) = launch(&mut c, b"CAT");
    let (dog, dog_pool) = launch(&mut c, b"DOG");

    (c, cat, dog, cat_pool, dog_pool)
}

// ---------------------------------------------------------------------------
// The demo the plan describes
// ---------------------------------------------------------------------------

/// Deposit, swap, route, provide liquidity, checkpoint, withdraw — the whole
/// cycle the plan's first demo shows, with the invariants held throughout.
#[test]
fn the_full_deposit_trade_withdraw_cycle() {
    let (mut c, cat, dog, cat_pool, dog_pool) = seeded();

    // 3. Swap xZEC -> CAT.
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    let got_cat = match &r[0] {
        Receipt::Swapped { amount_out, .. } => *amount_out,
        _ => panic!("expected Swapped"),
    };
    assert!(got_cat.is_positive());
    assert_eq!(c.bal(2, cat), got_cat);
    assert_eq!(c.bal(2, XZEC), Fixed::whole(9_900));

    // 4. Swap CAT -> DOG through xZEC, atomically, in one intent.
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool, dog_pool],
        amount_in: got_cat,
        min_out: Fixed::ZERO,
    });
    match &r[0] {
        Receipt::Swapped {
            asset_in,
            asset_out,
            hops,
            amount_out,
            ..
        } => {
            assert_eq!(*asset_in, cat);
            assert_eq!(*asset_out, dog);
            assert_eq!(hops.len(), 2, "the route did not go through xZEC");
            assert_eq!(hops[0].asset_out, XZEC);
            assert_eq!(hops[1].asset_in, XZEC);
            assert!(amount_out.is_positive());
        }
        r => panic!("expected Swapped, got {:?}", r),
    }
    assert_eq!(
        c.bal(2, cat),
        Fixed::ZERO,
        "the whole CAT position should be spent"
    );
    assert!(c.bal(2, dog).is_positive());

    // 5. Add liquidity, 6. remove it again.
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(3),
        asset: cat,
        amount: Fixed::whole(100_000),
    });
    c.deposit(3, XZEC, Fixed::whole(1_000));
    c.finalize();
    let lp_asset = c.state.pool(cat_pool).unwrap().lp_asset;
    let r = c.ok(Intent::AddLiquidity {
        account: acct(3),
        pool: cat_pool,
        max0: Fixed::whole(1_000),
        max1: Fixed::whole(100_000),
        min_shares: Fixed::ZERO,
    });
    let shares = match r[0] {
        Receipt::LiquidityAdded { shares, .. } => shares,
        _ => panic!("expected LiquidityAdded"),
    };
    assert_eq!(c.bal(3, lp_asset), shares);
    c.ok(Intent::RemoveLiquidity {
        account: acct(3),
        pool: cat_pool,
        shares,
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });
    assert_eq!(c.bal(3, lp_asset), Fixed::ZERO);

    // 8. Checkpoint one state root.
    //
    // The sealed root is *not* the root from before the intent: the checkpoint
    // intent is itself part of the history it seals, so it advances the
    // sequence and folds into the epoch commitment before the root is taken.
    // What must hold is that the advance carries the sealed root forward as the
    // next epoch's parent.
    let root_before = c.state.state_root();
    let r = c.ok(Intent::Checkpoint);
    let cp = match r[0] {
        Receipt::Checkpointed(cp) => cp,
        _ => panic!("expected Checkpointed"),
    };
    assert_ne!(
        cp.state_root, root_before,
        "the seal did not include its own intent"
    );
    assert_eq!(cp.epoch, c.state.epoch - 1);
    assert_eq!(
        cp.seq, c.state.seq,
        "the seal must name the sequence it covers"
    );
    assert_eq!(
        c.state.parent_root, cp.state_root,
        "the sealed root did not become the parent"
    );

    // 9. Withdraw back to Zcash.
    let held = c.bal(2, XZEC);
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: held,
        destination: [0u8; 32],
    });
    assert_eq!(c.bal(2, XZEC), Fixed::ZERO);
    // Still backed while the exit is in flight: supply has not moved.
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC)
    );
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: held,
    });
    // The account survives with nothing pending, because it still holds the DOG
    // it routed into. Pruning removes accounts that hold *nothing*, not accounts
    // that have merely exited.
    assert_eq!(
        c.state.accounts.get(&acct(2)).map(|a| a.pending_of(XZEC)),
        Some(Fixed::ZERO)
    );
    assert!(c.bal(2, dog).is_positive());
}

/// An account that has been emptied leaves the map entirely, so the state root
/// commits to who holds a balance rather than to who was ever mentioned.
#[test]
fn an_emptied_account_leaves_no_trace_in_the_root() {
    let mut c = Chain::new();
    let genesis = c.state.state_root();

    c.deposit(1, XZEC, Fixed::whole(10));

    c.finalize();
    assert!(c.state.accounts.contains_key(&acct(1)));

    c.ok(Intent::RequestWithdrawal {
        account: acct(1),
        asset: XZEC,
        amount: Fixed::whole(10),
        destination: [0u8; 32],
    });
    assert!(
        c.state.accounts.contains_key(&acct(1)),
        "a pending exit must keep the account"
    );

    c.ok(Intent::ConfirmWithdrawal {
        account: acct(1),
        asset: XZEC,
        amount: Fixed::whole(10),
    });
    assert!(
        !c.state.accounts.contains_key(&acct(1)),
        "an emptied account was not pruned"
    );
    assert_eq!(c.state.backing_of(XZEC), Fixed::ZERO);

    // Only the header has moved on; the accounts section is back to empty.
    assert_eq!(
        c.state.accounts_root(),
        SwapState::new(1, Params::v1()).accounts_root()
    );
    assert_ne!(
        c.state.state_root(),
        genesis,
        "history must still have advanced"
    );
}

/// Naming an account in an intent that then fails must not conjure it into the
/// state root.
#[test]
fn a_rejected_intent_does_not_create_an_account() {
    let mut c = Chain::new();
    c.rejects(
        Intent::Transfer {
            from: acct(8),
            to: acct(9),
            asset: XZEC,
            amount: Fixed::whole(1),
        },
        Reject::InsufficientBalance,
    );
    assert!(
        c.state.accounts.is_empty(),
        "a rejected transfer left accounts behind"
    );
}

/// The plan's headline infrastructure metric: many microchain actions
/// compressed into one Zcash settlement.
#[test]
fn thousands_of_actions_compress_into_one_settlement() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(500_000),
    });

    // Alternate directions so the pool does not walk off to one extreme.
    for i in 0..1_000 {
        let intent = if i % 2 == 0 {
            Intent::SwapExactIn {
                account: acct(2),
                asset_in: XZEC,
                path: vec![cat_pool],
                amount_in: Fixed::whole(1),
                min_out: Fixed::ZERO,
            }
        } else {
            Intent::SwapExactIn {
                account: acct(2),
                asset_in: cat,
                path: vec![cat_pool],
                amount_in: Fixed::whole(400),
                min_out: Fixed::ZERO,
            }
        };
        let r = apply(
            &mut c.state,
            &SequencedIntent {
                seq: c.seq + 1,
                intent,
            },
        );
        c.seq += 1;
        assert!(
            !r.iter().any(|x| x.is_rejection()),
            "swap {} rejected: {:?}",
            i,
            r
        );
    }
    c.state
        .check_invariants()
        .expect("1000 swaps must leave the chain consistent");

    let r = c.ok(Intent::Checkpoint);
    let cp = match r[0] {
        Receipt::Checkpointed(cp) => cp,
        _ => panic!("expected Checkpointed"),
    };
    assert!(
        cp.intents > 1_000,
        "one settlement should cover the whole epoch"
    );
    assert_eq!(cp.seq, c.state.seq);
}

// ---------------------------------------------------------------------------
// AMM properties under a real intent stream
// ---------------------------------------------------------------------------

/// The fee is what stops a round trip from extracting value, so `k` must never
/// fall across a swap. Checked on the live pool rather than on the arithmetic
/// in isolation, because it is the settlement path that could lose a unit.
#[test]
fn k_never_falls_across_a_swap() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(500_000),
    });

    for i in 0..60 {
        let k_before = c.state.pool(cat_pool).unwrap().k().unwrap();
        let intent = if i % 3 == 0 {
            Intent::SwapExactIn {
                account: acct(2),
                asset_in: cat,
                path: vec![cat_pool],
                amount_in: Fixed::whole(100 + i),
                min_out: Fixed::ZERO,
            }
        } else {
            Intent::SwapExactIn {
                account: acct(2),
                asset_in: XZEC,
                path: vec![cat_pool],
                amount_in: Fixed::whole(1 + i % 5),
                min_out: Fixed::ZERO,
            }
        };
        c.ok(intent);
        let k_after = c.state.pool(cat_pool).unwrap().k().unwrap();
        assert!(
            k_after >= k_before,
            "swap {} lowered k: {} -> {}",
            i,
            k_before,
            k_after
        );
    }
}

/// A round trip through a pool must lose money. If it did not, the pool would
/// be a faucet and the first bot to notice would empty it.
#[test]
fn a_round_trip_cannot_profit() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let start = c.bal(2, XZEC);
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(500),
        min_out: Fixed::ZERO,
    });
    let cat_held = c.bal(2, cat);
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool],
        amount_in: cat_held,
        min_out: Fixed::ZERO,
    });
    assert!(c.bal(2, XZEC) < start, "a round trip returned a profit");
}

/// Exact-output must deliver at least what was asked for, at every scale,
/// including the dust boundary where the fee truncation is larger than the
/// output itself.
#[test]
fn exact_output_always_delivers_at_least_what_was_asked() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    for wanted in [
        Fixed::raw(1),
        Fixed::raw(999),
        Fixed::whole(1),
        Fixed::whole(1_000),
        Fixed::whole(100_000),
    ] {
        let before = c.bal(2, cat);
        c.ok(Intent::SwapExactOut {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_out: wanted,
            max_in: Fixed::whole(1_000),
        });
        let delivered = c.bal(2, cat).sub(before).unwrap();
        assert!(delivered >= wanted, "asked {} got {}", wanted, delivered);
    }
}

/// A routed swap prices every hop against the reserves as they were, and moves
/// every hop's reserves. Both pools must reflect the trade.
#[test]
fn a_routed_swap_moves_every_pool_on_the_path() {
    let (mut c, cat, dog, cat_pool, dog_pool) = seeded();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(10_000),
    });
    let cat_k = c.state.pool(cat_pool).unwrap().k().unwrap();
    let dog_k = c.state.pool(dog_pool).unwrap().k().unwrap();

    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool, dog_pool],
        amount_in: Fixed::whole(10_000),
        min_out: Fixed::ZERO,
    });
    let hops = match &r[0] {
        Receipt::Swapped { hops, .. } => hops.clone(),
        _ => panic!("expected Swapped"),
    };
    // The middle leg is the same quantity leaving one pool and entering the next.
    assert_eq!(hops[0].amount_out, hops[1].amount_in);
    assert!(c.state.pool(cat_pool).unwrap().k().unwrap() >= cat_k);
    assert!(c.state.pool(dog_pool).unwrap().k().unwrap() >= dog_k);
    assert!(c.bal(2, dog).is_positive());
}

/// Liquidity out can never exceed liquidity in. Rounding must land in the pool
/// for the LP as well as for the trader.
#[test]
fn an_lp_cannot_withdraw_more_than_they_deposited_without_fees() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.deposit(4, XZEC, Fixed::whole(1_000));
    c.finalize();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(4),
        asset: cat,
        amount: Fixed::whole(500_000),
    });
    let (zec_before, cat_before) = (c.bal(4, XZEC), c.bal(4, cat));

    let lp_asset = c.state.pool(cat_pool).unwrap().lp_asset;
    c.ok(Intent::AddLiquidity {
        account: acct(4),
        pool: cat_pool,
        max0: Fixed::whole(1_000),
        max1: Fixed::whole(500_000),
        min_shares: Fixed::ZERO,
    });
    let shares = c.bal(4, lp_asset);
    c.ok(Intent::RemoveLiquidity {
        account: acct(4),
        pool: cat_pool,
        shares,
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });
    // No trades happened in between, so nothing was earned and rounding must
    // not have created anything either.
    assert!(
        c.bal(4, XZEC) <= zec_before,
        "LP gained xZEC out of nothing"
    );
    assert!(c.bal(4, cat) <= cat_before, "LP gained CAT out of nothing");
}

/// The locked minimum is what stops a pool ever being emptied of shares, so the
/// creator cannot take it back out.
#[test]
fn the_first_lp_cannot_reclaim_the_locked_minimum() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    let p = *c.state.pool(cat_pool).unwrap();
    let held = c.bal(1, p.lp_asset);
    assert_eq!(
        p.lp_supply.sub(p.locked).unwrap(),
        held,
        "creator should hold all but the lock"
    );

    c.ok(Intent::RemoveLiquidity {
        account: acct(1),
        pool: cat_pool,
        shares: held,
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });
    let p = *c.state.pool(cat_pool).unwrap();
    assert_eq!(p.lp_supply, p.locked, "the lock was spent");
    assert!(
        p.reserve0.is_positive() && p.reserve1.is_positive(),
        "pool was fully drained"
    );
    // And there is nothing left to burn against it.
    c.rejects(
        Intent::RemoveLiquidity {
            account: acct(1),
            pool: cat_pool,
            shares: Fixed::raw(1),
            min0: Fixed::ZERO,
            min1: Fixed::ZERO,
        },
        Reject::InsufficientBalance,
    );
}

// ---------------------------------------------------------------------------
// The revenue rail
// ---------------------------------------------------------------------------

const TREASURY: u8 = 200;

fn with_protocol_share(share_bps: u16) -> Params {
    let mut p = Params::v1();
    p.protocol_fee_share_bps = share_bps;
    p.treasury = acct(TREASURY);
    p
}

/// Under V1 parameters the protocol takes nothing and the treasury never even
/// appears in state. Revenue is a switch, not a rewrite.
#[test]
fn the_rail_is_inert_until_it_is_switched_on() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    assert!(!c.state.params.takes_protocol_fee());
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    assert!(
        !c.state.accounts.contains_key(&acct(TREASURY)),
        "a zero share still created a treasury account"
    );
}

/// Turning the share on routes a slice of the fee to the treasury — and takes
/// it out of the pool's fee, never out of the trader's quote.
#[test]
fn revenue_comes_out_of_the_fee_not_out_of_the_trader() {
    let (mut baseline, _cat, _dog, cat_pool, _) = seeded();
    let (mut earning, ..) = seeded();
    earning.ok(Intent::SetParams {
        params: with_protocol_share(1_000),
    }); // 10% of the fee

    let swap = |pool| Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    };
    let r0 = baseline.ok(swap(cat_pool));
    let r1 = earning.ok(swap(cat_pool));

    let (out0, hop0) = match &r0[0] {
        Receipt::Swapped {
            amount_out, hops, ..
        } => (*amount_out, hops[0]),
        _ => panic!("expected Swapped"),
    };
    let (out1, hop1) = match &r1[0] {
        Receipt::Swapped {
            amount_out, hops, ..
        } => (*amount_out, hops[0]),
        _ => panic!("expected Swapped"),
    };

    // The quote is identical. The trader cannot tell the rail is on.
    assert_eq!(
        out0, out1,
        "switching on revenue changed the trader's quote"
    );
    assert_eq!(hop0.fee, hop1.fee, "the fee charged should be unchanged");
    assert_eq!(hop0.protocol_fee, Fixed::ZERO);
    assert!(
        hop1.protocol_fee.is_positive(),
        "the treasury earned nothing"
    );

    // Ten percent of the fee, and the LPs keep the other ninety.
    assert_eq!(
        hop1.protocol_fee,
        hop1.fee
            .mul_div(Fixed::whole(1_000), Fixed::whole(10_000))
            .unwrap()
    );
    assert_eq!(earning.bal(TREASURY, XZEC), hop1.protocol_fee);
    let lp_kept = hop1.fee.sub(hop1.protocol_fee).unwrap();
    assert!(
        lp_kept > hop1.protocol_fee,
        "the protocol took more than the LPs"
    );
}

/// `k` must stay non-decreasing with the rail on. It is the property that stops
/// a pool being drained, and taking revenue out of the fee is only safe because
/// what the pool retains is still at least what the curve requires.
#[test]
fn revenue_does_not_break_the_curve() {
    for share in [0u16, 1, 2_500, 5_000, 9_999] {
        let (mut c, cat, _dog, cat_pool, _) = seeded();
        c.ok(Intent::SetParams {
            params: with_protocol_share(share),
        });
        c.ok(Intent::Transfer {
            from: acct(1),
            to: acct(2),
            asset: cat,
            amount: Fixed::whole(500_000),
        });
        for i in 0..25 {
            let k_before = c.state.pool(cat_pool).unwrap().k().unwrap();
            let intent = if i % 2 == 0 {
                Intent::SwapExactIn {
                    account: acct(2),
                    asset_in: XZEC,
                    path: vec![cat_pool],
                    amount_in: Fixed::whole(3 + i),
                    min_out: Fixed::ZERO,
                }
            } else {
                Intent::SwapExactOut {
                    account: acct(2),
                    asset_in: cat,
                    path: vec![cat_pool],
                    amount_out: Fixed::whole(1 + i),
                    max_in: Fixed::whole(100_000),
                }
            };
            c.ok(intent);
            let k_after = c.state.pool(cat_pool).unwrap().k().unwrap();
            assert!(
                k_after >= k_before,
                "share {} swap {} lowered k: {} -> {}",
                share,
                i,
                k_before,
                k_after
            );
        }
    }
}

/// Revenue accrues as an ordinary balance, so it moves through the ordinary
/// paths: the treasury can trade it and exit it with no special mechanism.
#[test]
fn treasury_revenue_is_an_ordinary_balance() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::SetParams {
        params: with_protocol_share(5_000),
    });
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(200_000),
    });

    // Earn in both assets: one swap each way.
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(500),
        min_out: Fixed::ZERO,
    });
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool],
        amount_in: Fixed::whole(200_000),
        min_out: Fixed::ZERO,
    });
    assert!(c.bal(TREASURY, XZEC).is_positive());
    assert!(c.bal(TREASURY, cat).is_positive());

    // Route the CAT revenue back into xZEC, then exit it to Zcash.
    let cat_revenue = c.bal(TREASURY, cat);
    c.ok(Intent::SwapExactIn {
        account: acct(TREASURY),
        asset_in: cat,
        path: vec![cat_pool],
        amount_in: cat_revenue,
        min_out: Fixed::ZERO,
    });
    let held = c.bal(TREASURY, XZEC);
    c.ok(Intent::RequestWithdrawal {
        account: acct(TREASURY),
        asset: XZEC,
        amount: held,
        destination: [0u8; 32],
    });
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(TREASURY),
        asset: XZEC,
        amount: held,
    });
    assert_eq!(c.bal(TREASURY, XZEC), Fixed::ZERO);
}

/// A share of 100% would leave LPs nothing for carrying inventory risk, so the
/// VM refuses it outright rather than trusting whoever sets parameters.
#[test]
fn the_protocol_cannot_take_the_whole_fee() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.rejects(
        Intent::SetParams {
            params: with_protocol_share(10_000),
        },
        Reject::InvalidParams,
    );
    c.ok(Intent::SetParams {
        params: with_protocol_share(9_999),
    });
}

/// Revenue is a routed slice of a real fee, so it is bounded by volume — it can
/// never mint units that no swap paid for.
#[test]
fn revenue_never_exceeds_the_fees_that_were_charged() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::SetParams {
        params: with_protocol_share(3_000),
    });
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(400_000),
    });

    let mut charged = Fixed::ZERO;
    let mut taken = Fixed::ZERO;
    for i in 0..30 {
        let r = c.ok(Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(1 + i % 7),
            min_out: Fixed::ZERO,
        });
        if let Receipt::Swapped { hops, .. } = &r[0] {
            for h in hops {
                charged = charged.add(h.fee).unwrap();
                taken = taken.add(h.protocol_fee).unwrap();
            }
        }
    }
    assert!(taken.is_positive());
    assert!(taken < charged, "the protocol took more than was charged");
    assert_eq!(
        c.bal(TREASURY, XZEC),
        taken,
        "treasury balance does not match the receipts"
    );
}

/// An LP position is an ordinary balance, so it transfers, survives
/// conservation, and is provable through the same exit hatch as anything else.
///
/// This is the property that makes fungible LP shares the right shape rather
/// than a per-position record: the plan wants LP assets usable as collateral
/// once ZynBorrow exists (§26B), and collateral has to be transferable and
/// divisible. A non-fungible position could not be posted in part, could not be
/// covered by the pool's own supply invariant, and would need a second section
/// in the state root with a second proof path to exit.
#[test]
fn an_lp_position_is_an_ordinary_transferable_asset() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let lp = c.state.pool(cat_pool).unwrap().lp_asset;
    let held = c.bal(1, lp);
    assert!(held.is_positive());

    // Divisible: half a position moves, which an NFT could not do.
    let half = held.mul_div(Fixed::whole(1), Fixed::whole(2)).unwrap();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(7),
        asset: lp,
        amount: half,
    });
    assert_eq!(c.bal(7, lp), half);
    assert_eq!(c.bal(1, lp), held.sub(half).unwrap());

    // The recipient is a full LP: they can redeem their share of the pool
    // without ever having deposited into it.
    c.ok(Intent::RemoveLiquidity {
        account: acct(7),
        pool: cat_pool,
        shares: half,
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });
    assert_eq!(c.bal(7, lp), Fixed::ZERO);
    assert!(c.bal(7, XZEC).is_positive() && c.bal(7, cat).is_positive());

    // And the pool's share supply still reconciles against the token's.
    c.state
        .check_invariants()
        .expect("a transferred LP position broke conservation");
}

/// A holder proves an LP position against an anchored root exactly as they
/// prove xZEC — one leaf, one path, no application-specific machinery.
#[test]
fn an_lp_position_exits_through_the_same_hatch_as_a_balance() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    let lp = c.state.pool(cat_pool).unwrap().lp_asset;
    assert!(c.bal(1, lp).is_positive());

    let root = c.state.state_root();
    let leaf = c.state.account_leaf(&acct(1)).expect("committed");
    let path = c.state.account_proof(&acct(1)).expect("provable");
    assert!(
        swapvm::merkle::verify_proof(leaf, &path, root),
        "an account holding an LP position could not prove it"
    );

    // The position is genuinely inside the committed leaf: moving it moves the
    // root, so a proof cannot be reused across a position transfer.
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(8),
        asset: lp,
        amount: Fixed::raw(1),
    });
    assert!(!swapvm::merkle::verify_proof(
        leaf,
        &path,
        c.state.state_root()
    ));
}

// ---------------------------------------------------------------------------
// Bridges: one shape, many custodying chains
// ---------------------------------------------------------------------------

use swapvm::state::TokenInfo;
use swapvm::types::{ORIGIN_BITCOIN, ORIGIN_ETHEREUM, ORIGIN_SOLANA, ORIGIN_ZCASH};

/// Register a bridged asset the way a governance action would.
fn add_bridge(c: &mut Chain, sym: &[u8], origin: u16) -> AssetId {
    let origin_network: &[u8] = match origin {
        ORIGIN_ZCASH => b"zcash",
        ORIGIN_BITCOIN => b"bitcoin",
        ORIGIN_ETHEREUM => b"ethereum",
        ORIGIN_SOLANA => b"solana",
        _ => b"test-origin",
    };
    let id = zyn_vm::bridged_address(swapvm::types::ADDRESS_SCOPE_V1, origin_network, sym);
    c.state
        .tokens
        .insert(id, TokenInfo::bridged(symbol(sym), origin));
    c.state
        .check_invariants()
        .expect("a fresh bridge must be consistent");
    id
}

/// xZEC is not special. Bitcoin, Ethereum and Solana ride the same three
/// intents, and the backing identity holds per asset.
#[test]
fn every_bridge_is_the_same_shape() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    let xeth = add_bridge(&mut c, b"xETH", ORIGIN_ETHEREUM);
    let xsol = add_bridge(&mut c, b"xSOL", ORIGIN_SOLANA);

    for (asset, amount) in [(xbtc, 3i64), (xeth, 40), (xsol, 500)] {
        c.deposit(2, asset, Fixed::whole(amount));
        // Credited and backed, but not spendable until the epoch is anchored.
        assert_eq!(c.bal(2, asset), Fixed::ZERO);
        c.finalize();
        assert_eq!(c.bal(2, asset), Fixed::whole(amount));
        assert_eq!(
            c.state.token(asset).unwrap().supply,
            c.state.backing_of(asset),
            "asset {:?} drifted from its vault",
            asset
        );
    }

    // Four vaults, four origins, one accounting rule.
    let bridged = c.state.bridged_assets();
    assert_eq!(bridged.len(), 4, "expected xZEC plus three: {:?}", bridged);
    assert!(bridged.contains(&(XZEC, ORIGIN_ZCASH)));
    assert!(bridged.contains(&(xbtc, ORIGIN_BITCOIN)));
}

/// Bridged assets trade against each other through xZEC like anything else —
/// which is the liquidity story: BTC in, CAT out, one intent.
#[test]
fn bridged_assets_route_through_the_xzec_hub() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    // Seed the pool and keep some back to trade with.
    c.deposit(1, xbtc, Fixed::whole(200));
    c.finalize();

    let r = c.ok(Intent::CreatePool {
        creator: acct(1),
        asset_a: XZEC,
        asset_b: xbtc,
        amount_a: Fixed::whole(5_000),
        amount_b: Fixed::whole(100),
        fee_bps: 30,
    });
    let btc_pool = match r[0] {
        Receipt::PoolCreated { pool, .. } => pool,
        _ => panic!("expected PoolCreated"),
    };

    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: xbtc,
        amount: Fixed::whole(10),
    });
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: xbtc,
        path: vec![btc_pool, cat_pool],
        amount_in: Fixed::whole(10),
        min_out: Fixed::ZERO,
    });
    match &r[0] {
        Receipt::Swapped {
            asset_out, hops, ..
        } => {
            assert_eq!(*asset_out, cat);
            assert_eq!(
                hops[0].asset_out, XZEC,
                "the route did not go through the hub"
            );
        }
        r => panic!("expected Swapped, got {:?}", r),
    }
    assert!(c.bal(2, cat).is_positive());
    c.state.check_invariants().unwrap();
}

/// A shortfall in one vault must not be concealable by a surplus in another.
///
/// The reason backing is checked per asset rather than as one pooled figure: a
/// single total would let a Bitcoin custody failure hide behind Ethereum's
/// reserves until both were gone.
#[test]
fn one_bridge_cannot_borrow_anothers_reserves() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    let xeth = add_bridge(&mut c, b"xETH", ORIGIN_ETHEREUM);
    c.deposit(2, xbtc, Fixed::whole(10));
    c.finalize();
    c.deposit(2, xeth, Fixed::whole(10));

    // Bitcoin's vault is short by one; Ethereum's is over by one. A pooled
    // total would net to zero and notice nothing.
    let b = c
        .state
        .tokens
        .get_mut(&xbtc)
        .unwrap()
        .vault
        .as_mut()
        .unwrap();
    b.confirmed = b.confirmed.sub(Fixed::whole(1)).unwrap();
    let e = c
        .state
        .tokens
        .get_mut(&xeth)
        .unwrap()
        .vault
        .as_mut()
        .unwrap();
    e.confirmed = e.confirmed.add(Fixed::whole(1)).unwrap();

    assert!(
        c.state.check_invariants().is_err(),
        "a per-bridge shortfall was hidden by another bridge's surplus"
    );
}

/// The whole ZEC path, start to finish, with every bound in place.
///
/// This is the first piece everything else rests on: if xZEC is not backed,
/// nothing above it means anything. The properties asserted here are the ones
/// that make "1 xZEC is 1 ZEC" a statement about the chain rather than about
/// the operator.
#[test]
fn the_zec_path_holds_end_to_end() {
    let mut c = Chain::new();
    {
        let v = c
            .state
            .tokens
            .get_mut(&XZEC)
            .unwrap()
            .vault
            .as_mut()
            .unwrap();
        v.cap = Fixed::whole(10_000); // staged mainnet: a limited deposit cap
        v.epoch_cap = Fixed::whole(1_000); // bound a compromise to one epoch
        v.min_exit = Fixed::raw(100_000_000_000); // Zcash cannot pay less
    }

    // 1. Deposits mint against confirmed backing, each naming its transaction —
    //    and never beyond what the vault was observed to hold.
    c.ok(Intent::AttestVaultBalance {
        asset: XZEC,
        observed: Fixed::whole(10_000),
    });
    for i in 1..=4u8 {
        c.ok(Intent::CreditDeposit {
            account: acct(i),
            asset: XZEC,
            amount: Fixed::whole(200),
            index: i as u64,
            external_ref: [i; 32],
        });
    }
    assert_eq!(c.state.backing_of(XZEC), Fixed::whole(800));
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC)
    );

    // 2. The per-epoch allowance binds, and the next epoch restores it.
    c.rejects(
        Intent::CreditDeposit {
            account: acct(5),
            asset: XZEC,
            amount: Fixed::whole(201),
            index: 5,
            external_ref: [5; 32],
        },
        Reject::AboveVaultCap,
    );
    c.ok(Intent::Checkpoint);
    c.ok(Intent::CreditDeposit {
        account: acct(5),
        asset: XZEC,
        amount: Fixed::whole(201),
        index: 5,
        external_ref: [5; 32],
    });

    // 3. The total ceiling binds too, whatever the epoch.
    let headroom = Fixed::whole(10_000).sub(c.state.backing_of(XZEC)).unwrap();
    c.ok(Intent::Checkpoint);
    c.rejects(
        Intent::CreditDeposit {
            account: acct(6),
            asset: XZEC,
            amount: headroom.add(Fixed::raw(1)).unwrap(),
            index: 6,
            external_ref: [6; 32],
        },
        Reject::AboveVaultCap,
    );

    // 4. Anchor the epoch so the credited deposits become spendable, then a
    //    dust exit is refused and a real one queues and is still backed.
    c.finalize();
    c.rejects(
        Intent::RequestWithdrawal {
            account: acct(1),
            asset: XZEC,
            amount: Fixed::raw(1),
            destination: [0u8; 32],
        },
        Reject::BelowExitMinimum,
    );
    c.ok(Intent::RequestWithdrawal {
        account: acct(1),
        asset: XZEC,
        amount: Fixed::whole(50),
        destination: [0u8; 32],
    });
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC),
        "a queued exit broke the backing identity"
    );

    // 5. Settlement pays the longest wait first.
    c.ok(Intent::Checkpoint);
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(60),
        destination: [0u8; 32],
    });
    let s = swapvm::bridge::settlement_for(&c.state, swapvm::types::ORIGIN_ZCASH)
        .expect("exits are waiting");
    assert_eq!(s.len(), 2);
    assert_eq!(
        s.payouts[0].account,
        acct(1),
        "the older exit was not paid first"
    );
    assert!(
        swapvm::bridge::is_covered(&c.state, &s),
        "the vault cannot cover its queue"
    );

    // 6. Confirming burns and releases; the identity holds throughout.
    let before = c.state.backing_of(XZEC);
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(1),
        asset: XZEC,
        amount: Fixed::whole(50),
    });
    assert_eq!(
        c.state.backing_of(XZEC),
        before.sub(Fixed::whole(50)).unwrap()
    );
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC)
    );

    // 7. The exit that was never settled comes home after the timeout.
    let timeout = c.state.params.exit_timeout_epochs;
    for _ in 0..timeout {
        c.ok(Intent::Checkpoint);
    }
    c.ok(Intent::CancelWithdrawal {
        account: acct(2),
        asset: XZEC,
    });
    assert_eq!(
        c.state.accounts.get(&acct(2)).unwrap().pending_of(XZEC),
        Fixed::ZERO
    );

    // 8. And a holder can prove their balance against the sealed root with the
    //    sequencer gone.
    let r = c.ok(Intent::Checkpoint);
    let cp = match r[0] {
        Receipt::Checkpointed(cp) => cp,
        _ => panic!("expected Checkpointed"),
    };
    let sealed = c
        .state
        .as_sealed(&cp)
        .expect("the sealed view must be recoverable");
    for id in sealed.accounts.keys() {
        let leaf = sealed.account_leaf(id).unwrap();
        let path = sealed.account_proof(id).unwrap();
        assert!(
            swapvm::merkle::verify_proof(leaf, &path, cp.state_root),
            "holder {} could not prove against the anchored root",
            id[0]
        );
    }
    c.state
        .check_invariants()
        .expect("the ZEC path must leave the chain consistent");
}

/// Units issued can never exceed units the vault was observed to hold.
///
/// The shielded vault as a mint signal. A Zcash vault emits nothing — there are
/// no contracts, and its balance is not public — so someone with the viewing
/// key has to look. Recording what they saw turns that looking into a number
/// the chain enforces against, rather than an assumption behind an operator's
/// word.
///
/// It does not remove the trust; it changes its shape. A fabricated credit now
/// needs a separate, dated lie about a balance that every viewing-key holder
/// can check — which is why the vault's viewing key belongs with the signers,
/// so each can verify before endorsing the epoch that releases the deposits.
#[test]
fn nothing_can_be_minted_beyond_what_the_vault_was_seen_to_hold() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);

    // Nothing observed yet, so nothing may be issued — however well-formed the
    // credit is.
    c.rejects(
        Intent::CreditDeposit {
            account: acct(2),
            asset: xbtc,
            amount: Fixed::whole(1),
            index: 1,
            external_ref: [1u8; 32],
        },
        Reject::AboveObserved,
    );

    // Report what the vault holds, and exactly that much may be issued.
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(10),
    });
    c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(10),
        index: 1,
        external_ref: [1u8; 32],
    });
    c.rejects(
        Intent::CreditDeposit {
            account: acct(2),
            asset: xbtc,
            amount: Fixed::raw(1),
            index: 2,
            external_ref: [2u8; 32],
        },
        Reject::AboveObserved,
    );
    assert_eq!(c.state.backing_of(xbtc), Fixed::whole(10));
    c.state.check_invariants().unwrap();
}

/// A vault reported short of what it has issued is refused, not absorbed.
///
/// The chain neither swallows the loss quietly nor freezes itself on a failed
/// invariant — it names the condition and leaves the decision with whoever can
/// act on it.
#[test]
fn a_vault_reported_short_is_refused_loudly() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(10),
    });
    c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(10),
        index: 1,
        external_ref: [1u8; 32],
    });

    c.rejects(
        Intent::AttestVaultBalance {
            asset: xbtc,
            observed: Fixed::whole(9),
        },
        Reject::AttestedShortfall,
    );
    assert_eq!(
        c.state.token(xbtc).unwrap().vault.unwrap().observed,
        Fixed::whole(10),
        "a refused report moved the record"
    );
    c.state
        .check_invariants()
        .expect("a refused shortfall must not corrupt the chain");

    // A payout legitimately lowers both, and reports fine.
    c.finalize();
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(4),
        destination: [0u8; 32],
    });
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(4),
    });
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(6),
    });
    c.state.check_invariants().unwrap();
}

/// A fabricated deposit cannot be spent before a quorum has seen it.
///
/// This is the gap that mattered most. The VM cannot see Zcash, so it cannot
/// verify that a deposit happened — the credit is an operator's word. Crediting
/// straight to a balance made that word immediately spendable: a compromised
/// sequencer could mint, swap it for a real asset, and take the proceeds before
/// anyone with a node had reason to look.
///
/// Now a credit is minted and backed but **not spendable** until the epoch
/// containing it has been anchored under a threshold certificate — the same
/// quorum a withdrawal already needed. A fabricated deposit sits in plain view,
/// inside the intent set the signers must endorse, before it can move.
#[test]
fn a_fresh_deposit_cannot_be_spent_before_it_is_anchored() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    c.deposit(9, XZEC, Fixed::whole(1_000));

    // Real and backed...
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC)
    );
    assert_eq!(
        c.state.accounts.get(&acct(9)).unwrap().incoming_of(XZEC),
        Fixed::whole(1_000)
    );
    // ...and worth nothing until a quorum has endorsed the epoch.
    assert_eq!(c.bal(9, XZEC), Fixed::ZERO);
    for intent in [
        Intent::SwapExactIn {
            account: acct(9),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(100),
            min_out: Fixed::ZERO,
        },
        Intent::Transfer {
            from: acct(9),
            to: acct(1),
            asset: XZEC,
            amount: Fixed::whole(1),
        },
        Intent::RequestWithdrawal {
            account: acct(9),
            asset: XZEC,
            amount: Fixed::whole(100),
            destination: [0u8; 32],
        },
    ] {
        c.rejects(intent, Reject::InsufficientBalance);
    }
    assert_eq!(
        c.bal(9, cat),
        Fixed::ZERO,
        "an unanchored deposit bought something"
    );

    // The anchor releases it, and only then.
    c.finalize();
    assert_eq!(c.bal(9, XZEC), Fixed::whole(1_000));
    assert_eq!(
        c.state.accounts.get(&acct(9)).unwrap().incoming_of(XZEC),
        Fixed::ZERO
    );
    c.ok(Intent::SwapExactIn {
        account: acct(9),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    c.state.check_invariants().unwrap();
}

/// Finality cannot be forged into releasing something it should not.
#[test]
fn an_epoch_cannot_be_finalised_early_twice_or_backwards() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let finalized = c.state.finalized_epoch;

    // Not the epoch still being written to — otherwise a sequencer could
    // fabricate a credit and release it in the same breath.
    c.rejects(
        Intent::ConfirmAnchor {
            epoch: c.state.epoch,
        },
        Reject::InvalidFinality,
    );
    c.rejects(
        Intent::ConfirmAnchor {
            epoch: c.state.epoch + 5,
        },
        Reject::InvalidFinality,
    );
    // Nor one already settled, nor an earlier one.
    c.rejects(
        Intent::ConfirmAnchor { epoch: finalized },
        Reject::InvalidFinality,
    );
    assert_eq!(
        c.state.finalized_epoch, finalized,
        "a refused confirmation moved finality"
    );

    // A sealed, unfinalised epoch is accepted.
    let at = c.state.epoch;
    c.ok(Intent::Checkpoint);
    c.ok(Intent::ConfirmAnchor { epoch: at });
    assert_eq!(c.state.finalized_epoch, at);
}

/// Deposits credited after an anchor wait for the *next* one — a fresh credit
/// cannot ride out on an older epoch's finality.
#[test]
fn a_later_deposit_does_not_inherit_an_earlier_finality() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.deposit(9, XZEC, Fixed::whole(100));
    c.finalize();
    assert_eq!(c.bal(9, XZEC), Fixed::whole(100));

    // A second deposit lands in a later epoch and is not released by the
    // finality that released the first.
    c.deposit(9, XZEC, Fixed::whole(100));
    assert_eq!(
        c.bal(9, XZEC),
        Fixed::whole(100),
        "a later deposit was released early"
    );
    assert_eq!(
        c.state.accounts.get(&acct(9)).unwrap().incoming_of(XZEC),
        Fixed::whole(100)
    );
    c.finalize();
    assert_eq!(c.bal(9, XZEC), Fixed::whole(200));
}

/// The same external deposit cannot be credited twice.
///
/// The lesson from Internet Computer's ckBTC, which puts deposit *detection*
/// inside consensus — its replicas run Bitcoin adapters and agree on the UTXO
/// set, so no operator is trusted to say a deposit happened. Zyn cannot copy
/// that: a VM that could observe Bitcoin would not be deterministic. What it
/// can do is refuse to be told the same thing twice.
///
/// The index is the chain's, not the operator's. A replay collides with an
/// index already used, and a gap is refused too — otherwise a credit could be
/// slipped in afterwards and accepted out of order.
#[test]
fn the_same_deposit_cannot_be_credited_twice() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    let txid = [0x7Fu8; 32];
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(100),
    });

    let next = c.state.next_deposit_index(xbtc);
    assert_eq!(next, 1, "a fresh vault starts at one");
    c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(5),
        index: next,
        external_ref: txid,
    });

    // The identical credit again — same index, same txid — is refused.
    c.rejects(
        Intent::CreditDeposit {
            account: acct(2),
            asset: xbtc,
            amount: Fixed::whole(5),
            index: next,
            external_ref: txid,
        },
        Reject::DepositOutOfOrder,
    );
    // And so is skipping ahead, which would leave a slot to backfill later.
    c.rejects(
        Intent::CreditDeposit {
            account: acct(2),
            asset: xbtc,
            amount: Fixed::whole(5),
            index: next + 2,
            external_ref: [0x80; 32],
        },
        Reject::DepositOutOfOrder,
    );
    // Backing moved once, not twice — and the units are still unspendable,
    // which is the second line of defence behind the index.
    assert_eq!(
        c.state.backing_of(xbtc),
        Fixed::whole(5),
        "a refused credit minted units"
    );
    assert_eq!(c.bal(2, xbtc), Fixed::ZERO);

    // The next one in sequence is fine, and each vault counts separately.
    c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(2),
        index: next + 1,
        external_ref: [0x81; 32],
    });
    assert_eq!(c.state.next_deposit_index(xbtc), 3);
    assert_eq!(
        c.state.next_deposit_index(XZEC),
        c.state.token(XZEC).unwrap().vault.unwrap().deposits + 1
    );
}

/// Every minted unit is traceable to a named external transaction, without the
/// chain carrying that history in its state.
///
/// The txid is not stored — it rides in the intent, which the epoch's
/// `intent_root` commits. So an auditor with a Bitcoin node can check every
/// credit against the chain that supposedly made it, and the state stays O(1)
/// per asset rather than growing a set of every deposit ever seen.
#[test]
fn a_credit_names_the_transaction_it_mirrors() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    let txid = [0xAB; 32];
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(1),
    });

    let before = c.state.intent_acc;
    let r = c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(1),
        index: 1,
        external_ref: txid,
    });
    match r[0] {
        Receipt::DepositCredited {
            external_ref,
            index,
            ..
        } => {
            assert_eq!(
                external_ref, txid,
                "the receipt lost the transaction it mirrors"
            );
            assert_eq!(index, 1);
        }
        _ => panic!("expected DepositCredited"),
    }
    // The reference is inside the epoch commitment, not the state.
    assert_ne!(c.state.intent_acc, before);
    assert_eq!(
        c.state.token(xbtc).unwrap().vault.unwrap().deposits,
        1,
        "state grew by a counter, not a set"
    );
}

/// Exits are per asset and per vault, so an account can be leaving to two
/// chains at once without the two interfering.
#[test]
fn exits_to_different_chains_are_independent() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    c.deposit(2, xbtc, Fixed::whole(10));
    c.finalize();

    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(100),
        destination: [0u8; 32],
    });
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(4),
        destination: [0u8; 32],
    });
    let a = c.state.accounts.get(&acct(2)).unwrap();
    assert_eq!(a.pending_of(XZEC), Fixed::whole(100));
    assert_eq!(a.pending_of(xbtc), Fixed::whole(4));

    // Confirming the Bitcoin leg releases only Bitcoin's backing.
    let zec_backing = c.state.backing_of(XZEC);
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(4),
    });
    assert_eq!(c.state.backing_of(xbtc), Fixed::whole(6));
    assert_eq!(
        c.state.backing_of(XZEC),
        zec_backing,
        "the wrong vault was debited"
    );
    assert_eq!(
        c.state.accounts.get(&acct(2)).unwrap().pending_of(xbtc),
        Fixed::ZERO
    );

    // And a vault cannot be asked to release more than was committed to it.
    c.rejects(
        Intent::ConfirmWithdrawal {
            account: acct(2),
            asset: xbtc,
            amount: Fixed::raw(1),
        },
        Reject::InsufficientPending,
    );
}

/// Seal `n` epochs, so a timeout can actually elapse.
fn advance_epochs(c: &mut Chain, n: u64) {
    for _ in 0..n {
        c.ok(Intent::Checkpoint);
    }
}

/// A bound account pays out where it is bound, and nowhere else.
///
/// The answer to a warm signing key. A Zyn key signs swaps, so it is online and
/// will sometimes be stolen. Binding the destination means a stolen key can
/// trade a position but cannot send the proceeds anywhere new — the theft
/// becomes a loss of trading control rather than a loss of funds.
#[test]
fn a_bound_account_cannot_be_paid_out_elsewhere() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let mine = [0x11u8; 32];
    let theirs = [0x66u8; 32];

    // Unbound, an account pays wherever the request says — which is exactly
    // the exposure binding removes.
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(10),
        destination: theirs,
    });

    let r = c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: mine,
    });
    match r[0] {
        Receipt::WithdrawalBound { effective, .. } => {
            assert!(effective, "a first binding should take effect at once")
        }
        _ => panic!("expected WithdrawalBound"),
    }

    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(10),
        destination: mine,
    });
    c.rejects(
        Intent::RequestWithdrawal {
            account: acct(2),
            asset: XZEC,
            amount: Fixed::whole(10),
            destination: theirs,
        },
        Reject::WrongDestination,
    );
    c.state.check_invariants().unwrap();
}

/// Redirecting a binding takes as long as an exit timeout, and re-asking
/// restarts the wait — so a stolen key cannot quietly mature a redirect while
/// the owner watches a different address.
#[test]
fn redirecting_a_binding_takes_time_and_re_asking_restarts_it() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let mine = [0x11u8; 32];
    let theirs = [0x66u8; 32];
    let elsewhere = [0x77u8; 32];
    let delay = c.state.params.exit_timeout_epochs;

    c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: mine,
    });
    let r = c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: theirs,
    });
    match r[0] {
        Receipt::WithdrawalBound { effective, .. } => {
            assert!(!effective, "a redirect took effect immediately")
        }
        _ => panic!("expected WithdrawalBound"),
    }
    // Still bound to the original, and exits still refuse the new address.
    c.rejects(
        Intent::RequestWithdrawal {
            account: acct(2),
            asset: XZEC,
            amount: Fixed::whole(1),
            destination: theirs,
        },
        Reject::WrongDestination,
    );

    advance_epochs(&mut c, delay);
    // Asking for somewhere else resets the clock — the matured request is gone.
    c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: elsewhere,
    });
    let r = c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: theirs,
    });
    match r[0] {
        Receipt::WithdrawalBound { effective, .. } => {
            assert!(!effective, "an abandoned redirect matured anyway")
        }
        _ => panic!("expected WithdrawalBound"),
    }

    // Waited out and re-confirmed, it applies.
    advance_epochs(&mut c, delay);
    let r = c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: theirs,
    });
    match r[0] {
        Receipt::WithdrawalBound { effective, .. } => assert!(effective),
        _ => panic!("expected WithdrawalBound"),
    }
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(1),
        destination: theirs,
    });
}

/// A destination is committed, never stored. The plan lists the withdrawal
/// destination among the things that should stay private (§12), and Zyn's state
/// is readable by everyone.
#[test]
fn a_destination_is_a_commitment_not_an_address() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let commitment = [0x11u8; 32];
    c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: commitment,
    });

    // What the chain holds is 32 bytes that reveal nothing about the address
    // behind them, and it moves the state root like anything else committed.
    let before = c.state.state_root();
    let b = c.state.accounts.get(&acct(2)).unwrap().binding.unwrap();
    assert_eq!(b.destination, commitment);
    c.ok(Intent::BindWithdrawal {
        account: acct(2),
        destination: [0x12u8; 32],
    });
    assert_ne!(
        c.state.state_root(),
        before,
        "a binding change did not move the root"
    );

    // And it survives a restart, or a resumed node would forget where an
    // account is allowed to pay out.
    let back = SwapState::decode_state(&c.state.encode_state()).unwrap();
    assert_eq!(back.state_root(), c.state.state_root());
    assert_eq!(
        back.accounts.get(&acct(2)).unwrap().binding,
        Some(b.request([0x12u8; 32], c.state.epoch))
    );
}

/// An exit the vault never settles can be taken back.
///
/// The plan's ninth invariant: a failed sequencer must not make reserves
/// permanently inaccessible. Without this, requesting a withdrawal is a one-way
/// door — the units leave the balance, and if the signers vanish they sit in a
/// queue nobody can drain, forever.
#[test]
fn an_unsettled_exit_can_be_taken_back() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let timeout = c.state.params.exit_timeout_epochs;
    assert!(
        timeout > 0,
        "the default parameters must allow cancellation"
    );

    let held = c.bal(2, XZEC);
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(500),
        destination: [0u8; 32],
    });
    assert_eq!(c.bal(2, XZEC), held.sub(Fixed::whole(500)).unwrap());

    // Not yet. An exit that could be cancelled at will could race a payout
    // already in flight and be paid on both sides.
    c.rejects(
        Intent::CancelWithdrawal {
            account: acct(2),
            asset: XZEC,
        },
        Reject::ExitNotTimedOut,
    );
    advance_epochs(&mut c, timeout - 1);
    c.rejects(
        Intent::CancelWithdrawal {
            account: acct(2),
            asset: XZEC,
        },
        Reject::ExitNotTimedOut,
    );

    // Once the deadline passes, the units come home.
    advance_epochs(&mut c, 1);
    let r = c.ok(Intent::CancelWithdrawal {
        account: acct(2),
        asset: XZEC,
    });
    match r[0] {
        Receipt::WithdrawalCancelled { amount, waited, .. } => {
            assert_eq!(amount, Fixed::whole(500));
            assert!(waited >= timeout);
        }
        _ => panic!("expected WithdrawalCancelled"),
    }
    assert_eq!(c.bal(2, XZEC), held, "the units did not come back");
    assert_eq!(
        c.state.accounts.get(&acct(2)).unwrap().pending_of(XZEC),
        Fixed::ZERO
    );
    c.state
        .check_invariants()
        .expect("a cancelled exit broke conservation");
}

/// A payout confirmed after a cancellation finds nothing pending and is
/// refused, so the chain can never release backing twice.
///
/// The chain's side is safe by construction. What it cannot protect is an
/// operator who broadcasts after the deadline — which is why the timeout is a
/// coordination deadline set far beyond any honest settlement, not a user
/// convenience.
#[test]
fn a_cancelled_exit_cannot_still_be_settled() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let timeout = c.state.params.exit_timeout_epochs;
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(500),
        destination: [0u8; 32],
    });
    advance_epochs(&mut c, timeout);
    c.ok(Intent::CancelWithdrawal {
        account: acct(2),
        asset: XZEC,
    });

    let backing = c.state.backing_of(XZEC);
    c.rejects(
        Intent::ConfirmWithdrawal {
            account: acct(2),
            asset: XZEC,
            amount: Fixed::whole(500),
        },
        Reject::InsufficientPending,
    );
    assert_eq!(
        c.state.backing_of(XZEC),
        backing,
        "backing was released twice"
    );
}

/// Adding to an exit restarts its clock, or a claim could be accumulated over
/// many small requests and the whole thing cancelled once the oldest aged out.
#[test]
fn topping_up_an_exit_restarts_the_clock() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let timeout = c.state.params.exit_timeout_epochs;
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(100),
        destination: [0u8; 32],
    });
    advance_epochs(&mut c, timeout);

    // The first request has aged out — but topping up resets it.
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(100),
        destination: [0u8; 32],
    });
    c.rejects(
        Intent::CancelWithdrawal {
            account: acct(2),
            asset: XZEC,
        },
        Reject::ExitNotTimedOut,
    );
    advance_epochs(&mut c, timeout);
    c.ok(Intent::CancelWithdrawal {
        account: acct(2),
        asset: XZEC,
    });
    assert_eq!(
        c.state.accounts.get(&acct(2)).unwrap().pending_of(XZEC),
        Fixed::ZERO
    );
}

/// An exit below what the custodying chain can broadcast is refused.
///
/// Bitcoin will not relay an output under its dust limit, so such a payout is
/// units burned here and nothing delivered there. Per asset, because every
/// chain's floor is different.
#[test]
fn an_exit_below_the_chains_dust_limit_is_refused() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    // Bitcoin's dust limit, roughly, in whole-BTC terms.
    let dust = Fixed::raw(5_460_000_000_000);
    c.state
        .tokens
        .get_mut(&xbtc)
        .unwrap()
        .vault
        .as_mut()
        .unwrap()
        .min_exit = dust;
    c.deposit(2, xbtc, Fixed::whole(1));
    c.finalize();

    c.rejects(
        Intent::RequestWithdrawal {
            account: acct(2),
            asset: xbtc,
            amount: dust.sub(Fixed::raw(1)).unwrap(),
            destination: [0u8; 32],
        },
        Reject::BelowExitMinimum,
    );
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: xbtc,
        amount: dust,
        destination: [0u8; 32],
    });

    // xZEC is unaffected: its own floor is one raw unit.
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::raw(1),
        destination: [0u8; 32],
    });
}

/// A native token has no vault, so it can neither be deposited nor exited.
#[test]
fn a_native_asset_has_no_bridge() {
    let (mut c, cat, _dog, _, _) = seeded();
    assert!(!c.state.token(cat).unwrap().is_bridged());
    for intent in [
        Intent::next_deposit(&c.state, acct(1), cat, Fixed::whole(1), [0u8; 32]),
        Intent::RequestWithdrawal {
            account: acct(1),
            asset: cat,
            amount: Fixed::whole(1),
            destination: [0u8; 32],
        },
        Intent::ConfirmWithdrawal {
            account: acct(1),
            asset: cat,
            amount: Fixed::whole(1),
        },
    ] {
        c.rejects(intent, Reject::NotBridged);
    }
}

// ---------------------------------------------------------------------------
// Items: indivisible assets against a refundable bond
// ---------------------------------------------------------------------------

/// The full life of an item: mint against a deposit, own it atomically, trade
/// it whole, end it and get the deposit back.
#[test]
fn an_item_can_be_minted_owned_traded_and_ended() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    c.deposit(4, XZEC, Fixed::whole(20));
    c.finalize();
    let before = c.bal(4, XZEC);

    let r = c.ok(Intent::MintItem {
        content: [0u8; 32],
        creator: acct(4),
        symbol: symbol(b"ITEM"),
        supply: Fixed::whole(1),
        bond,
    });
    let item = match r[0] {
        Receipt::ItemMinted { asset, .. } => asset,
        _ => panic!("expected ItemMinted"),
    };
    assert_eq!(
        c.bal(4, XZEC),
        before.sub(bond).unwrap(),
        "the bond was not taken"
    );
    assert_eq!(c.bal(4, item), Fixed::whole(1));
    assert!(!c.state.token(item).unwrap().is_divisible());

    // It cannot be split, and it cannot be wrapped into something divisible.
    c.rejects(
        Intent::Transfer {
            from: acct(4),
            to: acct(5),
            asset: item,
            amount: Fixed::raw(1),
        },
        Reject::Indivisible,
    );
    c.rejects(
        Intent::CreatePool {
            creator: acct(4),
            asset_a: XZEC,
            asset_b: item,
            amount_a: Fixed::whole(5),
            amount_b: Fixed::whole(1),
            fee_bps: 30,
        },
        Reject::Indivisible,
    );

    // It trades whole, atomically, at a negotiated price.
    c.ok(Intent::AcceptOffer {
        maker: acct(4),
        taker: acct(2),
        offer_asset: item,
        offer_amount: Fixed::whole(1),
        want_asset: XZEC,
        want_amount: Fixed::whole(9),
    });
    assert_eq!(c.bal(2, item), Fixed::whole(1));

    // The new owner ends it and the deposit comes back to them.
    let held = c.bal(2, XZEC);
    c.ok(Intent::BurnItem {
        holder: acct(2),
        asset: item,
    });
    assert_eq!(
        c.bal(2, XZEC),
        held.add(bond).unwrap(),
        "the bond was not refunded"
    );
    assert!(c.state.token(item).is_none(), "the state was not reclaimed");
}

/// The bond is a deposit, not a fee: what a chain holds against live items is
/// exactly what it hands back when they end. This is the property that makes it
/// a different economic object from rent.
#[test]
fn every_bond_is_returned_when_its_item_ends() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    c.deposit(4, XZEC, Fixed::whole(100));
    c.finalize();
    let start = c.bal(4, XZEC);

    let mut items = Vec::new();
    for i in 0..5u8 {
        let r = c.ok(Intent::MintItem {
            content: [0u8; 32],
            creator: acct(4),
            symbol: symbol(&[b'I', b'0' + i]),
            supply: Fixed::whole(1),
            bond,
        });
        match r[0] {
            Receipt::ItemMinted { asset, .. } => items.push(asset),
            _ => panic!(),
        }
    }
    assert_eq!(
        c.state.total_bonded().unwrap(),
        bond.mul(Fixed::whole(5)).unwrap(),
        "the chain is not holding what it took"
    );

    for item in items {
        c.ok(Intent::BurnItem {
            holder: acct(4),
            asset: item,
        });
    }
    assert_eq!(
        c.bal(4, XZEC),
        start,
        "minting and ending was not free of charge"
    );
    assert_eq!(c.state.total_bonded().unwrap(), Fixed::ZERO);
}

/// Only the sole holder may end an item, or burning would destroy somebody
/// else's balance and hand their share of the bond to whoever burned it.
#[test]
fn an_item_cannot_be_ended_by_a_partial_holder() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    c.deposit(4, XZEC, Fixed::whole(20));
    c.finalize();
    let r = c.ok(Intent::MintItem {
        content: [0u8; 32],
        creator: acct(4),
        symbol: symbol(b"RUN"),
        supply: Fixed::whole(3),
        bond,
    });
    let item = match r[0] {
        Receipt::ItemMinted { asset, .. } => asset,
        _ => panic!(),
    };
    c.ok(Intent::Transfer {
        from: acct(4),
        to: acct(5),
        asset: item,
        amount: Fixed::whole(1),
    });

    for who in [acct(4), acct(5)] {
        c.rejects(
            Intent::BurnItem {
                holder: who,
                asset: item,
            },
            Reject::NotSoleHolder,
        );
    }
    // Reassembled, it can be ended.
    c.ok(Intent::Transfer {
        from: acct(5),
        to: acct(4),
        asset: item,
        amount: Fixed::whole(1),
    });
    c.ok(Intent::BurnItem {
        holder: acct(4),
        asset: item,
    });
    assert!(c.state.token(item).is_none());
}

#[test]
fn minting_an_item_is_bonded_and_whole() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    c.deposit(4, XZEC, Fixed::whole(20));
    c.finalize();

    c.rejects(
        Intent::MintItem {
            creator: acct(4),
            symbol: symbol(b"X"),
            supply: Fixed::whole(1),
            bond: bond.sub(Fixed::raw(1)).unwrap(),
            content: [0u8; 32],
        },
        Reject::BelowLaunchBond,
    );
    // A fractional supply could never be fully held, so never burned, so its
    // bond would be stranded forever.
    c.rejects(
        Intent::MintItem {
            content: [0u8; 32],
            creator: acct(4),
            symbol: symbol(b"X"),
            supply: Fixed::whole(1).add(Fixed::raw(1)).unwrap(),
            bond,
        },
        Reject::Indivisible,
    );
    // And an ordinary token cannot be burned through this path.
    let (_, cat, _, _, _) = seeded();
    c.rejects(
        Intent::BurnItem {
            holder: acct(1),
            asset: cat,
        },
        Reject::Indivisible,
    );
}

// ---------------------------------------------------------------------------
// Fractionalisation: the pool is the vector
// ---------------------------------------------------------------------------

/// A supply of one does not make ownership atomic.
///
/// The intuition it refutes is a reasonable one: mint exactly one, never mint
/// again, let the owner build the pool themselves, and surely nobody can end up
/// owning part of it. But the LP share is a *different asset* from the thing
/// the pool holds, and it is divisible. The owner can simply send a third of
/// their position to a stranger, and no property of the underlying supply
/// prevents it.
#[test]
fn a_supply_of_one_does_not_prevent_fractional_ownership() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.deposit(7, XZEC, Fixed::whole(50));
    c.finalize();
    let r = c.ok(Intent::CreateToken {
        creator: acct(7),
        symbol: symbol(b"ONE"),
        supply: Fixed::whole(1),
        unit: Fixed::raw(1),
        xzec_liquidity: Fixed::whole(10),
        token_liquidity: Fixed::whole(1),
        fee_bps: 30,
    });
    let pool = match r[1] {
        Receipt::PoolCreated { pool, .. } => pool,
        _ => panic!("expected PoolCreated"),
    };
    let lp = c.state.pool(pool).unwrap().lp_asset;
    let held = c.bal(7, lp);

    let third = held.mul_div(Fixed::whole(1), Fixed::whole(3)).unwrap();
    c.ok(Intent::Transfer {
        from: acct(7),
        to: acct(8),
        asset: lp,
        amount: third,
    });
    assert_eq!(c.bal(8, lp), third, "a stranger holds part of a one-of-one");
    assert!(c.bal(7, lp) < held);
}

/// Held directly, the same asset cannot be split at all.
///
/// So the answer to "make fractionalisation impossible" is not a new rule — it
/// is not putting the asset in a pool. Wrapping is what creates the divisible
/// claim; an indivisible balance held in an account has no claim to divide.
/// The two modes are the design:
///
/// ```text
///   held directly  -> unit = 1 whole  -> atomic ownership, traded by AcceptOffer
///   wrapped in a pool -> divisible LP -> fractional ownership, priced by the curve
/// ```
#[test]
fn an_unwrapped_asset_cannot_be_fractionalised() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let nft = inject_indivisible(&mut c, b"ONE", Fixed::whole(1));

    for fraction in [
        Fixed::whole(1)
            .mul_div(Fixed::whole(1), Fixed::whole(3))
            .unwrap(),
        Fixed::raw(1),
        Fixed::whole(1).sub(Fixed::raw(1)).unwrap(),
    ] {
        c.rejects(
            Intent::Transfer {
                from: acct(1),
                to: acct(2),
                asset: nft,
                amount: fraction,
            },
            Reject::Indivisible,
        );
    }
    // Only the whole thing moves, and it moves atomically against payment.
    c.ok(Intent::AcceptOffer {
        maker: acct(1),
        taker: acct(2),
        offer_asset: nft,
        offer_amount: Fixed::whole(1),
        want_asset: XZEC,
        want_amount: Fixed::whole(5),
    });
    assert_eq!(c.bal(2, nft), Fixed::whole(1));
    assert_eq!(c.bal(1, nft), Fixed::ZERO);
}

// ---------------------------------------------------------------------------
// Bridged pairs: a reference price that sets the fee, never the quote
// ---------------------------------------------------------------------------

/// A pool with a fresh reference charges enough to cover what an arbitrageur
/// would otherwise take when the pair is repriced elsewhere.
#[test]
fn a_diverged_pool_charges_for_the_arbitrage() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let spot = {
        let p = c.state.pool(cat_pool).unwrap();
        swapvm::amm::spot_price(p.reserve0, p.reserve1).unwrap()
    };

    // Reported 20% away from where the pool is.
    let reference = spot.mul_div(Fixed::whole(12), Fixed::whole(10)).unwrap();
    let r = c.ok(Intent::UpdateReference {
        pool: cat_pool,
        price: reference,
    });
    let charged = match r[0] {
        Receipt::ReferenceUpdated { fee_bps, .. } => fee_bps,
        _ => panic!("expected ReferenceUpdated"),
    };
    assert!(
        charged > 900 && charged < 1_000,
        "expected about 9.54%, got {} bps",
        charged
    );

    // And the swap actually pays it: the LP keeps far more than 0.30%.
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    let (paid, fee) = match &r[0] {
        Receipt::Swapped { hops, .. } => (hops[0].amount_in, hops[0].fee),
        _ => panic!("expected Swapped"),
    };
    let ordinary = paid
        .mul_div(Fixed::whole(30), Fixed::whole(10_000))
        .unwrap();
    assert!(
        fee > ordinary.mul(Fixed::whole(20)).unwrap(),
        "the divergence fee was not charged"
    );
    let _ = cat;
    c.state.check_invariants().unwrap();
}

/// A pool whose price is discovered here — every memecoin pair — has no
/// reference and charges its ordinary fee. The mechanism is inert unless a pair
/// actually has an outside market.
#[test]
fn a_pool_without_a_reference_is_unaffected() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    assert!(c.state.pool(cat_pool).unwrap().reference.is_none());
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    let (paid, fee) = match &r[0] {
        Receipt::Swapped { hops, .. } => (hops[0].amount_in, hops[0].fee),
        _ => panic!("expected Swapped"),
    };
    assert_eq!(fee, swapvm::amm::fee_taken(paid, 30).unwrap());
}

/// A stale reference is not a slightly worse reference — it is a snapshot of a
/// market that has moved on. The pool falls back to its ordinary fee rather
/// than charging a trader for the reporter's silence.
#[test]
fn a_stale_reference_falls_back_to_the_ordinary_fee() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    let spot = {
        let p = c.state.pool(cat_pool).unwrap();
        swapvm::amm::spot_price(p.reserve0, p.reserve1).unwrap()
    };
    c.ok(Intent::UpdateReference {
        pool: cat_pool,
        price: spot.mul_div(Fixed::whole(12), Fixed::whole(10)).unwrap(),
    });

    // Age it out with unrelated activity.
    let staleness = c.state.params.reference_staleness;
    for _ in 0..=staleness {
        c.ok(Intent::Transfer {
            from: acct(1),
            to: acct(2),
            asset: XZEC,
            amount: Fixed::raw(1),
        });
    }
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(10),
        min_out: Fixed::ZERO,
    });
    let (paid, fee) = match &r[0] {
        Receipt::Swapped { hops, .. } => (hops[0].amount_in, hops[0].fee),
        _ => panic!("expected Swapped"),
    };
    assert_eq!(
        fee,
        swapvm::amm::fee_taken(paid, 30).unwrap(),
        "a stale reference still priced"
    );
}

/// The safety property, end to end: a forged reference changes what a trader
/// pays and cannot move a unit out of the pool.
///
/// Two layers protect a trader. The reference only ever raises the fee, so a
/// forged one makes them receive *less* — and their own slippage bound then
/// refuses the trade outright rather than letting it execute badly. A reference
/// so absurd that the divergence ratio is not even representable falls back to
/// the ordinary fee, which is the safe direction: an attacker cannot use it to
/// price a pair out of trading.
#[test]
fn a_forged_reference_cannot_drain_a_pool() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let before = *c.state.pool(cat_pool).unwrap();
    let k_before = before.k().unwrap();
    let spot = swapvm::amm::spot_price(before.reserve0, before.reserve1).unwrap();

    // A hundredfold lie — extreme, but representable.
    c.ok(Intent::UpdateReference {
        pool: cat_pool,
        price: spot.mul_div(Fixed::whole(100), Fixed::whole(1)).unwrap(),
    });

    let honest = swapvm::amm::out_given_in(
        Fixed::whole(100),
        before.reserve_of(XZEC).unwrap(),
        before.reserve_of(cat).unwrap(),
        30,
    )
    .unwrap();

    // A trader with a slippage bound is simply refused, not harmed.
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(100),
            min_out: honest.mul_div(Fixed::whole(99), Fixed::whole(100)).unwrap(),
        },
        Reject::SlippageExceeded,
    );

    // And one without gets less, never more — the pool is strictly better off.
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    let out = match &r[0] {
        Receipt::Swapped { amount_out, .. } => *amount_out,
        _ => panic!("expected Swapped"),
    };
    assert!(
        out < honest,
        "a forged reference paid out more than an honest one"
    );
    assert!(out.is_positive());
    assert!(c.state.pool(cat_pool).unwrap().k().unwrap() > k_before);
    c.state.check_invariants().unwrap();
}

/// A reference so absurd the divergence is not representable falls back to the
/// ordinary fee rather than failing the swap — an attacker cannot price a pair
/// out of trading by reporting nonsense.
#[test]
fn an_unrepresentable_reference_falls_back_rather_than_halting_the_pool() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::UpdateReference {
        pool: cat_pool,
        price: Fixed::raw(1),
    });
    let r = c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::whole(100),
        min_out: Fixed::ZERO,
    });
    let (paid, fee) = match &r[0] {
        Receipt::Swapped { hops, .. } => (hops[0].amount_in, hops[0].fee),
        _ => panic!("expected Swapped"),
    };
    assert_eq!(
        fee,
        swapvm::amm::fee_taken(paid, 30).unwrap(),
        "nonsense priced the trade"
    );
}

/// The endpoint read path must hand out exactly the proofs the one-shot path
/// would, or a node serving from an index gives holders paths a verifier
/// rejects.
///
/// The index exists because the one-shot path rebuilds the tree per request —
/// 27 ms at 50,000 accounts, about forty a second on a core. It is worth having
/// only if it is identical.
#[test]
fn the_served_proof_matches_the_one_shot_proof() {
    let (mut c, _cat, _dog, _, _) = seeded();
    for n in 20..40u8 {
        c.deposit(n, XZEC, Fixed::whole(10));
    }
    c.finalize();

    let index = c.state.account_index();
    assert_eq!(index.root(), c.state.state_root());
    assert_eq!(index.len(), c.state.accounts.len());

    for id in c.state.accounts.keys() {
        let (leaf, served) = index.proof(id).expect("served");
        let direct = c.state.account_proof(id).expect("one-shot");
        assert_eq!(served, direct, "the served path differs for {}", id[0]);
        assert_eq!(leaf, c.state.account_leaf(id).unwrap());
        assert!(
            swapvm::merkle::verify_proof(leaf, &served, index.root()),
            "a served proof did not verify"
        );
    }

    // An account the chain has never seen is refused, not fabricated.
    assert!(index.proof(&acct(200)).is_none());
}

/// **S8.** A vault's observation must survive a restart, or a resumed node
/// would forget what it had seen and refuse every deposit — or, worse, accept
/// ones it should not.
///
/// Pinned because the encoder and decoder for it disagreed once, which is the
/// failure mode a round-trip test exists to catch and a reviewer will not.
#[test]
fn a_vaults_observation_survives_a_restart() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let xbtc = add_bridge(&mut c, b"xBTC", ORIGIN_BITCOIN);
    c.ok(Intent::AttestVaultBalance {
        asset: xbtc,
        observed: Fixed::whole(42),
    });
    c.ok(Intent::CreditDeposit {
        account: acct(2),
        asset: xbtc,
        amount: Fixed::whole(10),
        index: 1,
        external_ref: [1u8; 32],
    });

    let back = SwapState::decode_state(&c.state.encode_state()).expect("decode");
    assert_eq!(back.state_root(), c.state.state_root());
    let v = back.token(xbtc).unwrap().vault.unwrap();
    assert_eq!(
        v.observed,
        Fixed::whole(42),
        "the observation was lost on restore"
    );
    assert_eq!(v.observed_headroom(), Fixed::whole(32));
    assert_eq!(back, c.state);
}

/// **S5.** Every parameter that changes a future transition must move the state
/// root. Two of them did not, for a while: a node configured with a different
/// exit timeout would have agreed on the root and disagreed on whether an exit
/// could be cancelled.
#[test]
fn every_parameter_is_committed_to_the_state_root() {
    let base = SwapState::new(1, Params::v1());
    let root = base.state_root();

    let mut variants = Vec::new();
    let mut p = Params::v1();
    p.exit_timeout_epochs += 1;
    variants.push(("exit_timeout_epochs", p));
    let mut p = Params::v1();
    p.reference_staleness += 1;
    variants.push(("reference_staleness", p));
    let mut p = Params::v1();
    p.min_pool_xzec = p.min_pool_xzec.add(Fixed::raw(1)).unwrap();
    variants.push(("min_pool_xzec", p));
    let mut p = Params::v1();
    p.protocol_fee_share_bps += 1;
    variants.push(("protocol_fee_share_bps", p));
    let mut p = Params::v1();
    p.treasury = [9u8; 32];
    variants.push(("treasury", p));
    let mut p = Params::v1();
    p.max_hops += 1;
    variants.push(("max_hops", p));
    let mut p = Params::v1();
    p.default_fee_bps += 1;
    variants.push(("default_fee_bps", p));
    let mut p = Params::v1();
    p.min_liquidity = p.min_liquidity.add(Fixed::raw(1)).unwrap();
    variants.push(("min_liquidity", p));

    for (name, params) in variants {
        assert_ne!(
            SwapState::new(1, params).state_root(),
            root,
            "{} is not committed to the state root",
            name
        );
    }
}

// ---------------------------------------------------------------------------
// Declared pool constraints — what a "hook" is here
// ---------------------------------------------------------------------------

/// A pool declares a minimum it will trade, and the VM enforces it.
///
/// This is the shape a Uniswap-v4-style hook takes on Zyn: a constraint the
/// pool *declares*, checked by the VM, rather than code the pool *calls*. The
/// difference is load-bearing — arbitrary code inside a transition would bring
/// back reentrancy, make the work unbounded, and let value move in ways
/// conservation cannot account for.
#[test]
fn a_pool_can_decline_dust_trades() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();

    // The default is no constraint: a single raw unit still trades.
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: Fixed::raw(1_000_000),
        min_out: Fixed::ZERO,
    });

    // Raise the floor on the xZEC side only.
    let floor = Fixed::whole(1);
    c.state.pools.get_mut(&cat_pool).unwrap().min_in0 = floor;
    let p = *c.state.pool(cat_pool).unwrap();
    assert_eq!(p.asset0, XZEC, "xZEC should be the canonical first side");
    assert_eq!(p.min_in(XZEC), Some(floor));
    assert_eq!(
        p.min_in(cat),
        Some(Fixed::raw(1)),
        "the other side is untouched"
    );

    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: floor.sub(Fixed::raw(1)).unwrap(),
            min_out: Fixed::ZERO,
        },
        Reject::BelowMinimumTrade,
    );
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: XZEC,
        path: vec![cat_pool],
        amount_in: floor,
        min_out: Fixed::ZERO,
    });

    // Selling the other way is unaffected, and the floor binds exact-output
    // too — otherwise it would be trivially sidestepped by asking for a tiny
    // output instead of offering a tiny input.
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool],
        amount_in: Fixed::raw(1_000),
        min_out: Fixed::ZERO,
    });
    c.rejects(
        Intent::SwapExactOut {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_out: Fixed::raw(1),
            max_in: Fixed::whole(1_000),
        },
        Reject::BelowMinimumTrade,
    );
    c.state.check_invariants().unwrap();
}

/// The floor binds every hop of a route, not just the first — a two-hop swap
/// must not be a way through a pool that declined the trade.
#[test]
fn a_declared_minimum_binds_mid_route() {
    let (mut c, cat, dog, cat_pool, dog_pool) = seeded();
    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(10),
    });

    // The DOG pool declines small xZEC inputs; a CAT -> xZEC -> DOG route pays
    // xZEC into it on the second hop.
    c.state.pools.get_mut(&dog_pool).unwrap().min_in0 = Fixed::whole(1_000);
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: cat,
            path: vec![cat_pool, dog_pool],
            amount_in: Fixed::whole(10),
            min_out: Fixed::ZERO,
        },
        Reject::BelowMinimumTrade,
    );
    assert_eq!(c.bal(2, dog), Fixed::ZERO);
}

// ---------------------------------------------------------------------------
// Negotiated trades — the settlement half of an off-curve sale
// ---------------------------------------------------------------------------

/// An NFT changes hands by selling the pool position that owns it.
///
/// No new pool type, no escrow, no unwrap: the asset stays locked where it was,
/// and what moves is the claim on it. One intent, so the buyer's payment and the
/// seller's position cannot be separated by whoever is sequencing.
#[test]
fn a_pool_position_can_be_sold_off_curve() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.deposit(4, XZEC, Fixed::whole(50));
    c.deposit(5, XZEC, Fixed::whole(50));
    c.finalize();

    // A locks a one-of-a-kind asset in a pool and holds the position.
    let r = c.ok(Intent::CreateToken {
        creator: acct(4),
        symbol: symbol(b"ONE"),
        supply: Fixed::whole(1),
        unit: Fixed::raw(1),
        xzec_liquidity: Fixed::whole(10),
        token_liquidity: Fixed::whole(1),
        fee_bps: 30,
    });
    let pool = match r[1] {
        Receipt::PoolCreated { pool, .. } => pool,
        _ => panic!("expected PoolCreated"),
    };
    let lp = c.state.pool(pool).unwrap().lp_asset;
    let position = c.bal(4, lp);
    assert!(position.is_positive());

    // B's bid is accepted: position and payment cross in one step.
    let bid = Fixed::whole(30);
    c.ok(Intent::AcceptOffer {
        maker: acct(4),
        taker: acct(5),
        offer_asset: lp,
        offer_amount: position,
        want_asset: XZEC,
        want_amount: bid,
    });
    assert_eq!(
        c.bal(5, lp),
        position,
        "the buyer did not receive the position"
    );
    assert_eq!(c.bal(4, lp), Fixed::ZERO);
    assert_eq!(c.bal(5, XZEC), Fixed::whole(50).sub(bid).unwrap());

    // The asset never moved: it is still where it was locked.
    let p = *c.state.pool(pool).unwrap();
    assert_eq!(p.reserve_of(XZEC).unwrap(), Fixed::whole(10));
    c.state
        .check_invariants()
        .expect("an off-curve sale broke conservation");
}

/// A trade that cannot be paid for does not half-happen.
#[test]
fn an_unpayable_offer_moves_nothing() {
    let (mut c, cat, _dog, _, _) = seeded();
    let before = c.state.state_root();
    c.rejects(
        Intent::AcceptOffer {
            maker: acct(1),
            taker: acct(2),
            offer_asset: cat,
            offer_amount: Fixed::whole(100),
            want_asset: XZEC,
            want_amount: Fixed::whole(999_999_999),
        },
        Reject::InsufficientBalance,
    );
    assert_eq!(
        c.bal(2, cat),
        Fixed::ZERO,
        "the taker received an asset they did not pay for"
    );

    // And the same when the maker is the one who cannot deliver.
    c.rejects(
        Intent::AcceptOffer {
            maker: acct(2),
            taker: acct(1),
            offer_asset: cat,
            offer_amount: Fixed::whole(1),
            want_asset: XZEC,
            want_amount: Fixed::whole(1),
        },
        Reject::InsufficientBalance,
    );
    assert_ne!(
        c.state.state_root(),
        before,
        "rejections must still advance history"
    );
}

#[test]
fn a_degenerate_offer_is_refused() {
    let (mut c, cat, _dog, _, _) = seeded();
    // Trading with yourself, or an asset for itself, would mint a receipt
    // asserting a price when nothing moved.
    c.rejects(
        Intent::AcceptOffer {
            maker: acct(1),
            taker: acct(1),
            offer_asset: cat,
            offer_amount: Fixed::whole(1),
            want_asset: XZEC,
            want_amount: Fixed::whole(1),
        },
        Reject::DegenerateOffer,
    );
    c.rejects(
        Intent::AcceptOffer {
            maker: acct(1),
            taker: acct(2),
            offer_asset: cat,
            offer_amount: Fixed::whole(1),
            want_asset: cat,
            want_amount: Fixed::whole(2),
        },
        Reject::DegenerateOffer,
    );
}

/// The launch bond makes a locked asset permanently unredeemable in part, so an
/// "unwrap the NFT" step cannot be built on the launch path.
///
/// Pinned as a test because it is the constraint that decides the design: an
/// asset locked in a launch pool is traded *as* a position, never taken out of
/// one.
#[test]
fn a_launched_pool_can_never_be_fully_unwrapped() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.deposit(6, XZEC, Fixed::whole(50));
    c.finalize();
    let r = c.ok(Intent::CreateToken {
        creator: acct(6),
        symbol: symbol(b"ONE"),
        supply: Fixed::whole(1),
        unit: Fixed::raw(1),
        xzec_liquidity: Fixed::whole(10),
        token_liquidity: Fixed::whole(1),
        fee_bps: 30,
    });
    let (asset, pool) = match (&r[0], &r[1]) {
        (Receipt::TokenCreated { asset, .. }, Receipt::PoolCreated { pool, .. }) => (*asset, *pool),
        _ => panic!(),
    };
    let lp = c.state.pool(pool).unwrap().lp_asset;

    c.ok(Intent::RemoveLiquidity {
        account: acct(6),
        pool,
        shares: c.bal(6, lp),
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });
    let got = c.bal(6, asset);
    assert!(got < Fixed::whole(1), "the bond did not withhold anything");
    assert!(
        c.state
            .pool(pool)
            .unwrap()
            .reserve_of(asset)
            .unwrap()
            .is_positive(),
        "the pool should still hold the remainder"
    );
}

// ---------------------------------------------------------------------------
// The launch bond — what this chain has instead of rent
// ---------------------------------------------------------------------------

/// A launch is atomic: the token and its market come into existence together,
/// so there is no state in which a token exists with nowhere to trade it.
#[test]
fn a_token_cannot_exist_without_a_market() {
    let (c, cat, dog, cat_pool, dog_pool) = seeded();
    for (asset, pool) in [(cat, cat_pool), (dog, dog_pool)] {
        assert_eq!(
            c.state.find_pool(XZEC, asset),
            Some(pool),
            "a token has no xZEC market"
        );
    }
    // Every non-LP token on the chain is one side of an xZEC pool, which is
    // what makes the two-hop routing bound a property rather than an
    // assumption: any token reaches any other through xZEC.
    for (&id, info) in c.state.tokens.iter() {
        if id == XZEC || info.lp_of.is_some() {
            continue;
        }
        assert!(
            c.state.find_pool(XZEC, id).is_some(),
            "token {:?} is unroutable",
            id
        );
    }
}

/// The bond is what stops the spam, so it has to actually bind.
#[test]
fn a_launch_below_the_bond_is_refused() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    assert!(
        bond.is_positive(),
        "the default parameters must charge a bond"
    );

    for short in [
        Fixed::ZERO,
        Fixed::raw(1),
        bond.sub(Fixed::raw(1)).unwrap(),
        bond,
    ] {
        c.rejects(
            Intent::CreateToken {
                creator: acct(1),
                symbol: symbol(b"SPAM"),
                supply: Fixed::whole(1_000),
                unit: Fixed::raw(1),
                xzec_liquidity: short,
                token_liquidity: Fixed::whole(1_000),
                fee_bps: 30,
            },
            Reject::BelowLaunchBond,
        );
    }
    // Seeding exactly the bond is refused too: it would lock the whole pool and
    // leave the creator no position at all.
    c.ok(Intent::CreateToken {
        creator: acct(1),
        symbol: symbol(b"REAL"),
        supply: Fixed::whole(1_000),
        unit: Fixed::raw(1),
        xzec_liquidity: bond.add(Fixed::raw(1)).unwrap(),
        token_liquidity: Fixed::whole(1_000),
        fee_bps: 30,
    });
}

/// The hole a one-off deposit would leave: creating, then withdrawing
/// everything, and keeping the state for free.
///
/// It does not open, because the bond is not a deposit — it is liquidity that
/// was never minted to anyone. The creator can pull their own shares and
/// nothing else, and what stays behind is a live market rather than a payment
/// to nobody. That is the whole difference from rent.
#[test]
fn a_creator_cannot_withdraw_the_bond() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let bond = c.state.params.min_pool_xzec;
    c.deposit(3, XZEC, Fixed::whole(50));
    c.finalize();
    let r = c.ok(Intent::CreateToken {
        creator: acct(3),
        symbol: symbol(b"NEW"),
        supply: Fixed::whole(1_000_000),
        unit: Fixed::raw(1),
        xzec_liquidity: Fixed::whole(50),
        token_liquidity: Fixed::whole(500_000),
        fee_bps: 30,
    });
    let pool = match r[1] {
        Receipt::PoolCreated { pool, .. } => pool,
        _ => panic!("a launch must open a pool"),
    };
    let p = *c.state.pool(pool).unwrap();

    // The locked share is exactly the bond's fraction of the pool.
    let bonded = p.lp_supply.mul_div(bond, Fixed::whole(50)).unwrap();
    assert_eq!(p.locked, bonded, "the lock is not the bond");

    // The creator pulls everything they hold...
    let held = c.bal(3, p.lp_asset);
    assert_eq!(held, p.lp_supply.sub(p.locked).unwrap());
    c.ok(Intent::RemoveLiquidity {
        account: acct(3),
        pool,
        shares: held,
        min0: Fixed::ZERO,
        min1: Fixed::ZERO,
    });

    // ...and the market survives, holding roughly the bond.
    let after = *c.state.pool(pool).unwrap();
    assert_eq!(after.lp_supply, after.locked);
    assert!(after.reserve0.is_positive() && after.reserve1.is_positive());
    let xzec_left = after.reserve_of(XZEC).unwrap();
    assert!(
        xzec_left >= bond.mul_div(Fixed::whole(99), Fixed::whole(100)).unwrap(),
        "the bond drained: {} left against a bond of {}",
        xzec_left,
        bond
    );

    // And there is nothing further to take.
    c.rejects(
        Intent::RemoveLiquidity {
            account: acct(3),
            pool,
            shares: Fixed::raw(1),
            min0: Fixed::ZERO,
            min1: Fixed::ZERO,
        },
        Reject::InsufficientBalance,
    );
}

/// A bigger launch does not dilute the bond away: the lock scales with the
/// pool, so it is always the same amount of real xZEC.
#[test]
fn the_bond_is_a_fixed_amount_not_a_fixed_fraction() {
    let bond = Params::v1().min_pool_xzec;
    for seed in [Fixed::whole(10), Fixed::whole(1_000), Fixed::whole(100_000)] {
        let (mut c, _cat, _dog, _, _) = seeded();
        c.deposit(4, XZEC, seed);
        c.finalize();
        let r = c.ok(Intent::CreateToken {
            creator: acct(4),
            symbol: symbol(b"TOK"),
            supply: Fixed::whole(1_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: seed,
            token_liquidity: Fixed::whole(1_000_000),
            fee_bps: 30,
        });
        let pool = match r[1] {
            Receipt::PoolCreated { pool, .. } => pool,
            _ => panic!("expected PoolCreated"),
        };
        let p = *c.state.pool(pool).unwrap();
        // locked/total of the xZEC reserve is the bond, whatever the size.
        let locked_xzec = p
            .reserve_of(XZEC)
            .unwrap()
            .mul_div(p.locked, p.lp_supply)
            .unwrap();
        let drift = locked_xzec.sub(bond).unwrap().abs().unwrap();
        assert!(
            drift < Fixed::raw(1_000_000),
            "seeded {}: locked {} against a bond of {}",
            seed,
            locked_xzec,
            bond
        );
    }
}

/// A second xZEC market for an existing token posts the bond too, or it would
/// be a way to add state without paying. A pool between two user tokens does
/// not: both sides already paid at launch.
#[test]
fn the_bond_applies_to_xzec_pools_and_is_inherited_by_others() {
    let (mut c, cat, dog, _, _) = seeded();

    // CAT/DOG is free — the bond was paid transitively.
    c.ok(Intent::CreatePool {
        creator: acct(1),
        asset_a: cat,
        asset_b: dog,
        amount_a: Fixed::whole(1_000),
        amount_b: Fixed::whole(1_000),
        fee_bps: 30,
    });
    let cross = c
        .state
        .find_pool(cat, dog)
        .expect("a cross pool should open");
    assert_eq!(
        c.state.pool(cross).unwrap().locked,
        c.state.params.min_liquidity,
        "a cross pool should post only the dust minimum"
    );
}

// ---------------------------------------------------------------------------
// Indivisible assets — the rail for non-fungibles
// ---------------------------------------------------------------------------

/// Inject an indivisible asset directly, standing in for one bridged from
/// Zcash. There is deliberately no intent that creates one — see below.
fn inject_indivisible(c: &mut Chain, sym: &[u8], supply: Fixed) -> AssetId {
    let id = zyn_vm::asset_address(swapvm::types::ADDRESS_SCOPE_V1, &acct(1), sym);
    c.state.tokens.insert(
        id,
        swapvm::state::TokenInfo {
            symbol: symbol(sym),
            supply,
            lp_of: None,
            // A bridged asset has no launch pool: it arrives through the vault,
            // and its bond is the L1 asset the vault holds.
            genesis_pool: None,
            unit: Fixed::ONE,
            bond: Fixed::ZERO,
            vault: None,
            content: None,
            collection: None,
        },
    );
    c.state.account_mut(&acct(1)).credit(id, supply).unwrap();
    c.state
        .check_invariants()
        .expect("an injected asset must be consistent");
    id
}

/// The model can represent an asset that moves only in whole units.
///
/// Nothing in ZynZap *issues* one — a launch is a pool, and a pool cannot price
/// an indivisible asset, so there is no creation path. The rail exists because
/// a Zcash Shielded Asset with supply 1 must be representable when the deposit
/// adapter lands (§10, §26C); a bridged asset arrives through the vault, the
/// way xZEC does, and its bond is the L1 asset the vault is holding.
#[test]
fn an_indivisible_asset_moves_only_in_whole_units() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let ticket = inject_indivisible(&mut c, b"TICKET", Fixed::whole(10));
    assert!(!c.state.token(ticket).unwrap().is_divisible());

    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: ticket,
        amount: Fixed::whole(3),
    });
    assert_eq!(c.bal(2, ticket), Fixed::whole(3));

    for bad in [
        Fixed::raw(1),
        Fixed::raw(WAD / 2),
        Fixed::whole(1).add(Fixed::raw(1)).unwrap(),
    ] {
        c.rejects(
            Intent::Transfer {
                from: acct(1),
                to: acct(2),
                asset: ticket,
                amount: bad,
            },
            Reject::Indivisible,
        );
    }
    assert_eq!(
        c.bal(2, ticket),
        Fixed::whole(3),
        "a rejected transfer moved a balance"
    );
}

/// An indivisible asset cannot be launched, because a launch opens a pool and
/// a constant-product curve returns quantities the asset cannot represent.
///
/// The two rules interact rather than sitting side by side: requiring a market
/// at launch is what removes dead state, and it means the only assets ZynZap
/// itself creates are ones it can actually price.
#[test]
fn an_indivisible_asset_cannot_be_launched() {
    let (mut c, _cat, _dog, _, _) = seeded();
    c.rejects(
        Intent::CreateToken {
            creator: acct(1),
            symbol: symbol(b"TICKET"),
            supply: Fixed::whole(1_000),
            unit: Fixed::ONE,
            xzec_liquidity: Fixed::whole(100),
            token_liquidity: Fixed::whole(1_000),
            fee_bps: 30,
        },
        Reject::Indivisible,
    );
}

/// Nor pooled afterwards, however it got into the state.
#[test]
fn an_amm_refuses_to_price_an_indivisible_asset() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let ticket = inject_indivisible(&mut c, b"TICKET", Fixed::whole(1_000));
    c.rejects(
        Intent::CreatePool {
            creator: acct(1),
            asset_a: XZEC,
            asset_b: ticket,
            amount_a: Fixed::whole(100),
            amount_b: Fixed::whole(100),
            fee_bps: 30,
        },
        Reject::Indivisible,
    );
    assert!(c.state.find_pool(XZEC, ticket).is_none());
}

/// Ordinary tokens are unaffected: the rail is inert at its default.
#[test]
fn divisible_assets_behave_exactly_as_before() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    assert!(c.state.token(cat).unwrap().is_divisible());
    assert!(c.state.token(XZEC).unwrap().is_divisible());
    let lp = c.state.pool(cat_pool).unwrap().lp_asset;
    assert!(
        c.state.token(lp).unwrap().is_divisible(),
        "LP shares must stay divisible"
    );

    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::raw(1),
    });
    assert_eq!(c.bal(2, cat), Fixed::raw(1));
}

// ---------------------------------------------------------------------------
// Backing, the invariant the custody model rests on
// ---------------------------------------------------------------------------

/// xZEC can only be created by a credited deposit and only destroyed by a
/// confirmed exit. Nothing in the trading path may move supply.
#[test]
fn only_the_bridge_moves_xzec_supply() {
    let (mut c, cat, _dog, cat_pool, _) = seeded();
    let supply = c.state.token(XZEC).unwrap().supply;

    c.ok(Intent::Transfer {
        from: acct(1),
        to: acct(2),
        asset: cat,
        amount: Fixed::whole(1_000),
    });
    c.ok(Intent::SwapExactIn {
        account: acct(2),
        asset_in: cat,
        path: vec![cat_pool],
        amount_in: Fixed::whole(1_000),
        min_out: Fixed::ZERO,
    });
    c.ok(Intent::AddLiquidity {
        account: acct(1),
        pool: cat_pool,
        max0: Fixed::whole(100),
        max1: Fixed::whole(1_000_000),
        min_shares: Fixed::ZERO,
    });
    c.ok(Intent::Checkpoint);
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        supply,
        "trading moved xZEC supply"
    );
    assert_eq!(c.state.backing_of(XZEC), supply);
}

/// A pending exit is held out of tradeable balance but still counted as a
/// liability, so the backing identity never goes momentarily false.
#[test]
fn a_pending_exit_is_neither_spendable_nor_forgotten() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    c.ok(Intent::RequestWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(9_000),
        destination: [0u8; 32],
    });
    assert_eq!(c.bal(2, XZEC), Fixed::whole(1_000));
    assert_eq!(
        c.state.token(XZEC).unwrap().supply,
        c.state.backing_of(XZEC)
    );

    // The committed units cannot be traded.
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(2_000),
            min_out: Fixed::ZERO,
        },
        Reject::InsufficientBalance,
    );
    // Nor confirmed beyond what was requested.
    c.rejects(
        Intent::ConfirmWithdrawal {
            account: acct(2),
            asset: XZEC,
            amount: Fixed::whole(9_001),
        },
        Reject::InsufficientPending,
    );

    let backing_before = c.state.backing_of(XZEC);
    c.ok(Intent::ConfirmWithdrawal {
        account: acct(2),
        asset: XZEC,
        amount: Fixed::whole(9_000),
    });
    assert_eq!(
        c.state.backing_of(XZEC),
        backing_before.sub(Fixed::whole(9_000)).unwrap(),
        "confirming an exit did not release the backing"
    );
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

#[test]
fn the_rules_that_protect_the_pools_hold() {
    let (mut c, cat, dog, cat_pool, dog_pool) = seeded();

    c.rejects(
        Intent::CreatePool {
            creator: acct(1),
            asset_a: cat,
            asset_b: XZEC,
            amount_a: Fixed::whole(1),
            amount_b: Fixed::whole(1),
            fee_bps: 30,
        },
        Reject::PoolExists,
    );
    c.rejects(
        Intent::CreatePool {
            creator: acct(1),
            asset_a: cat,
            asset_b: cat,
            amount_a: Fixed::whole(1),
            amount_b: Fixed::whole(1),
            fee_bps: 30,
        },
        Reject::DegeneratePair,
    );
    c.rejects(
        Intent::CreatePool {
            creator: acct(1),
            asset_a: cat,
            asset_b: legacy_id(999),
            amount_a: Fixed::whole(1),
            amount_b: Fixed::whole(1),
            fee_bps: 30,
        },
        Reject::UnknownAsset,
    );
    c.rejects(
        Intent::CreatePool {
            creator: acct(1),
            asset_a: cat,
            asset_b: dog,
            amount_a: Fixed::whole(1),
            amount_b: Fixed::whole(1),
            fee_bps: 10_000,
        },
        Reject::InvalidFee,
    );

    // Spending what you do not have, in every shape.
    c.rejects(
        Intent::Transfer {
            from: acct(9),
            to: acct(1),
            asset: XZEC,
            amount: Fixed::raw(1),
        },
        Reject::InsufficientBalance,
    );
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(1_000_000),
            min_out: Fixed::ZERO,
        },
        Reject::InsufficientBalance,
    );

    // Slippage bounds are honoured in both directions.
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::whole(1_000_000),
        },
        Reject::SlippageExceeded,
    );
    c.rejects(
        Intent::SwapExactOut {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_out: Fixed::whole(1_000),
            max_in: Fixed::raw(1),
        },
        Reject::SlippageExceeded,
    );

    // A swap cannot take a whole reserve.
    c.rejects(
        Intent::SwapExactOut {
            account: acct(1),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_out: Fixed::whole(10_000_000),
            max_in: Fixed::whole(1_000_000),
        },
        Reject::InsufficientReserves,
    );

    // Paths: empty, over the hop limit, disconnected, repeated, unknown.
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        },
        Reject::InvalidPath,
    );
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool, dog_pool, cat_pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        },
        Reject::InvalidPath,
    );
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool, cat_pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        },
        Reject::InvalidPath,
    );
    // CAT is not in the DOG pool, so the route does not connect.
    c.rejects(
        Intent::SwapExactIn {
            account: acct(1),
            asset_in: cat,
            path: vec![dog_pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        },
        Reject::InvalidPath,
    );
    c.rejects(
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![legacy_id(999)],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        },
        Reject::UnknownPool,
    );

    // Zero and negative amounts, everywhere they can appear.
    c.rejects(
        Intent::next_deposit(&c.state, acct(1), XZEC, Fixed::ZERO, [0u8; 32]),
        Reject::NonPositiveAmount,
    );
    c.rejects(
        Intent::next_deposit(&c.state, acct(1), XZEC, Fixed::whole(-5), [0u8; 32]),
        Reject::NonPositiveAmount,
    );
    c.rejects(
        Intent::Transfer {
            from: acct(1),
            to: acct(2),
            asset: XZEC,
            amount: Fixed::whole(-1),
        },
        Reject::NonPositiveAmount,
    );
    c.rejects(
        Intent::RequestWithdrawal {
            account: acct(1),
            asset: XZEC,
            amount: Fixed::ZERO,
            destination: [0u8; 32],
        },
        Reject::NonPositiveAmount,
    );

    c.state
        .check_invariants()
        .expect("rejections must leave the chain consistent");
}

/// An out-of-order intent is refused without touching anything at all — not
/// even the sequence, because an intent that was never in the history must not
/// appear in the epoch's commitment either.
#[test]
fn an_out_of_order_intent_changes_nothing() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let before = c.state.clone();
    for seq in [0, c.state.seq, c.state.seq + 2, u64::MAX] {
        let intent = Intent::next_deposit(&c.state, acct(1), XZEC, Fixed::whole(1), [0u8; 32]);
        let r = apply(&mut c.state, &SequencedIntent { seq, intent });
        assert_eq!(
            r[0].rejection(),
            Some(Reject::OutOfOrder),
            "seq {} was accepted",
            seq
        );
    }
    assert_eq!(c.state, before, "an out-of-order intent moved state");
}

/// The parameter set is enforced, not trusted.
#[test]
fn unsafe_parameters_are_refused() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let mut bad = Params::v1();
    bad.max_hops = 0;
    c.rejects(Intent::SetParams { params: bad }, Reject::InvalidParams);

    let mut bad = Params::v1();
    bad.default_fee_bps = 10_000;
    c.rejects(Intent::SetParams { params: bad }, Reject::InvalidParams);

    // A valid change takes effect and binds the next swap.
    let mut tight = Params::v1();
    tight.max_hops = 1;
    c.ok(Intent::SetParams { params: tight });
    assert_eq!(c.state.params.max_hops, 1);
}

// ---------------------------------------------------------------------------
// Determinism, replay and the checkpoint lineage
// ---------------------------------------------------------------------------

/// Two nodes fed the same ordered intents must reach the same root — the
/// property every other guarantee is built on.
#[test]
fn replay_reproduces_the_root_exactly() {
    let (a, cat, _dog, cat_pool, _) = seeded();

    // Rebuild from genesis with the same script, then keep both going.
    let (mut b, _, _, _, _) = seeded();
    assert_eq!(a.state.state_root(), b.state.state_root());

    let mut a = a;
    let extra = [
        Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(37),
            min_out: Fixed::ZERO,
        },
        Intent::Transfer {
            from: acct(1),
            to: acct(5),
            asset: cat,
            amount: Fixed::whole(3),
        },
        Intent::Checkpoint,
        Intent::RequestWithdrawal {
            account: acct(2),
            asset: XZEC,
            amount: Fixed::whole(1),
            destination: [0u8; 32],
        },
    ];
    for i in extra {
        a.ok(i.clone());
        b.ok(i);
        assert_eq!(a.state.state_root(), b.state.state_root());
    }
    assert_eq!(a.state.encode_state(), b.state.encode_state());
}

/// Each checkpoint names the previous one's root, so the lineage can be walked
/// without trusting the sequencer's account of it.
#[test]
fn checkpoints_chain_to_their_parent() {
    let (mut c, _cat, _dog, cat_pool, _) = seeded();
    let mut previous: Option<swapvm::state::Checkpoint> = None;

    for round in 0..4 {
        c.ok(Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(1 + round),
            min_out: Fixed::ZERO,
        });
        let r = c.ok(Intent::Checkpoint);
        let cp = match r[0] {
            Receipt::Checkpointed(cp) => cp,
            _ => panic!("expected Checkpointed"),
        };
        assert_eq!(cp.chain_id, c.state.chain_id);
        assert_eq!(cp.epoch, c.state.epoch - 1);
        if let Some(prev) = previous {
            assert_eq!(
                cp.parent_root, prev.state_root,
                "epoch {} lost its parent",
                round
            );
            assert!(cp.seq > prev.seq);
            assert_ne!(cp.intent_root, prev.intent_root);
        }
        // Every epoch's transaction commitment starts fresh.
        assert_eq!(c.state.intent_acc, [0u8; 32]);
        assert_eq!(c.state.epoch_intents, 0);
        previous = Some(cp);
    }
}

/// The intent commitment covers what was *asked*, so a checkpoint over a
/// different intent stream is a different commitment even when the resulting
/// balances happen to match.
#[test]
fn the_intent_commitment_distinguishes_equivalent_histories() {
    let mut a = Chain::new();
    let mut b = Chain::new();

    a.deposit(1, XZEC, Fixed::whole(100));
    b.deposit(1, XZEC, Fixed::whole(60));
    b.deposit(1, XZEC, Fixed::whole(40));
    // Same balances, different histories.
    assert_eq!(a.bal(1, XZEC), b.bal(1, XZEC));

    let ra = a.ok(Intent::Checkpoint);
    let rb = b.ok(Intent::Checkpoint);
    let (ca, cb) = match (&ra[0], &rb[0]) {
        (Receipt::Checkpointed(x), Receipt::Checkpointed(y)) => (*x, *y),
        _ => panic!("expected Checkpointed"),
    };
    assert_ne!(
        ca.intent_root, cb.intent_root,
        "different histories shared a commitment"
    );
    assert_ne!(
        ca.state_root, cb.state_root,
        "the sequence should differ too"
    );
}

/// `transition` is the statement a proof would carry: it must refuse a base
/// root the state does not actually commit to.
#[test]
fn a_transition_is_bound_to_its_base_root() {
    let (c, _cat, _dog, cat_pool, _) = seeded();
    let batch = vec![SequencedIntent {
        seq: c.state.seq + 1,
        intent: Intent::SwapExactIn {
            account: acct(2),
            asset_in: XZEC,
            path: vec![cat_pool],
            amount_in: Fixed::whole(5),
            min_out: Fixed::ZERO,
        },
    }];

    let (after, root) =
        transition(c.state.clone(), c.state.state_root(), &batch).expect("valid transition");
    assert_eq!(root, after.state_root());
    after.check_invariants().unwrap();

    assert_eq!(
        transition(c.state.clone(), [0xAB; 32], &batch),
        Err(Reject::OutOfOrder),
        "a transition from an uncommitted base was accepted"
    );
}

/// A batch is atomic against arithmetic failure and leaves the caller's state
/// untouched; soft rejections do not abort it.
#[test]
fn a_batch_survives_rejections_but_not_arithmetic_failure() {
    let (c, _cat, _dog, cat_pool, _) = seeded();
    let mut s = c.state.clone();
    let before = s.state_root();
    let at = s.seq;

    let receipts = apply_batch(
        &mut s,
        &[
            SequencedIntent {
                seq: at + 1,
                intent: Intent::SwapExactIn {
                    account: acct(2),
                    asset_in: XZEC,
                    path: vec![cat_pool],
                    // Rejected: nowhere near this much on deposit.
                    amount_in: Fixed::whole(999_999_999),
                    min_out: Fixed::ZERO,
                },
            },
            SequencedIntent {
                seq: at + 2,
                intent: Intent::AttestVaultBalance {
                    asset: XZEC,
                    observed: c.state.backing_of(XZEC).add(Fixed::whole(5)).unwrap(),
                },
            },
        ],
    )
    .expect("a soft rejection must not abort the batch");

    assert_eq!(receipts[0].rejection(), Some(Reject::InsufficientBalance));
    assert!(!receipts[1].is_rejection());
    assert_ne!(s.state_root(), before);
    s.check_invariants().unwrap();

    // An out-of-order intent inside a batch is a soft rejection too, and the
    // sequence it did not consume stays available.
    let mut s2 = c.state.clone();
    let at2 = s2.seq;
    let r = apply_batch(
        &mut s2,
        &[SequencedIntent {
            seq: at2 + 9,
            intent: Intent::next_deposit(&c.state, acct(7), XZEC, Fixed::whole(5), [0u8; 32]),
        }],
    )
    .unwrap();
    assert_eq!(r[0].rejection(), Some(Reject::OutOfOrder));
    assert_eq!(
        s2.state_root(),
        before,
        "an out-of-order intent moved a batch's state"
    );
}

/// A balance proved against a checkpointed root is the withdrawal path that
/// does not depend on the sequencer being available or honest.
#[test]
fn a_balance_can_be_proved_against_a_checkpointed_root() {
    let (mut c, _cat, _dog, _, _) = seeded();
    let r = c.ok(Intent::Checkpoint);
    let cp = match r[0] {
        Receipt::Checkpointed(cp) => cp,
        _ => panic!("expected Checkpointed"),
    };

    // The chain has moved on since the checkpoint, but the sealed root is still
    // the one the signers hold, so the proof must be taken against that state.
    let sealed = SwapState::decode_state(&c.state.encode_state()).unwrap();
    assert_ne!(
        sealed.state_root(),
        cp.state_root,
        "the epoch should have advanced"
    );

    // Re-derive the sealed state by replaying to the checkpointed sequence.
    let (mut replay, _, _, _, _) = seeded();
    replay.push(Intent::Checkpoint);
    // Roll the header back to what was sealed: the same values the checkpoint
    // committed, before the advance.
    let mut at_seal = replay.state.clone();
    at_seal.epoch = cp.epoch;
    at_seal.parent_root = cp.parent_root;
    at_seal.intent_acc = cp.intent_root;
    at_seal.epoch_intents = cp.intents;
    assert_eq!(at_seal.state_root(), cp.state_root);

    let leaf = at_seal
        .account_leaf(&acct(2))
        .expect("account should be committed");
    let path = at_seal
        .account_proof(&acct(2))
        .expect("account should be provable");
    assert!(
        swapvm::merkle::verify_proof(leaf, &path, cp.state_root),
        "a balance did not prove against the checkpointed root"
    );
}
