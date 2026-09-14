use swapvm::cave::{self, CurveStatus, CURVE_SUPPLY, PAIR_SEED, POOL_TOKEN_SUPPLY, TOTAL_SUPPLY};
use swapvm::state::symbol;
use swapvm::{amm, Fixed, Intent, Params, Receipt, SequencedIntent, SwapState, XZEC};

const CREATOR: [u8; 32] = [1u8; 32];
const BUYER: [u8; 32] = [2u8; 32];

fn funded(amount: Fixed) -> SwapState {
    let mut s = SwapState::new(26460, Params::v1());
    let token = s.tokens.get_mut(&XZEC).unwrap();
    token.supply = amount;
    let vault = token.vault.as_mut().unwrap();
    vault.confirmed = amount;
    vault.observed = amount;
    vault.deposits = 1;
    s.account_mut(&CREATOR)
        .credit(XZEC, Fixed::whole(100))
        .unwrap();
    s.account_mut(&BUYER)
        .credit(XZEC, amount.sub(Fixed::whole(100)).unwrap())
        .unwrap();
    s
}

#[test]
fn launch_buy_sell_and_state_roundtrip_conserve_supply() {
    let mut s = funded(Fixed::whole(1_000));
    let receipts = cave::create(
        &mut s,
        CREATOR,
        symbol("玉".as_bytes()),
        "翡翠🪨".as_bytes().to_vec(),
        [9u8; 32],
        100,
        Fixed::whole(10_000_000),
        Fixed::whole(1),
    )
    .unwrap();
    let asset = match receipts[0] {
        Receipt::CurveCreated {
            asset, pair_seed, ..
        } => {
            assert_eq!(pair_seed, PAIR_SEED);
            asset
        }
        ref r => panic!("unexpected receipt: {r:?}"),
    };
    assert_eq!(s.tokens[&asset].supply, TOTAL_SUPPLY);
    assert_eq!(s.curves[&asset].sold, Fixed::whole(10_000_000));

    cave::sell(&mut s, CREATOR, asset, Fixed::whole(1_000_000), Fixed::ZERO).unwrap();
    assert_eq!(s.curves[&asset].sold, Fixed::whole(9_000_000));
    s.check_invariants().unwrap();

    let encoded = s.encode_state();
    let restored = SwapState::decode_state(&encoded).unwrap();
    assert_eq!(restored, s);
    assert_eq!(restored.state_root(), s.state_root());
}

#[test]
fn reaching_660m_graduates_atomically_and_locks_all_lp() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"ROCK"),
        b"DarkJade".to_vec(),
        [7u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let receipts = cave::buy(&mut s, BUYER, asset, CURVE_SUPPLY, Fixed::whole(100)).unwrap();
    let graduated = receipts
        .iter()
        .find_map(|r| match r {
            Receipt::CurveGraduated {
                pool,
                lp_asset,
                token_liquidity,
                zec_liquidity,
                locked_lp,
                ..
            } => Some((
                *pool,
                *lp_asset,
                *token_liquidity,
                *zec_liquidity,
                *locked_lp,
            )),
            _ => None,
        })
        .expect("graduation receipt");
    assert!(graduated.2 <= POOL_TOKEN_SUPPLY);
    assert!(graduated.3 <= Fixed::whole(34));
    assert_eq!(
        graduated.3,
        graduated.2.mul(cave::GRADUATION_PRICE).unwrap(),
        "opening AMM price must equal the terminal curve price exactly"
    );
    assert_eq!(s.pools[&graduated.0].locked, graduated.4);
    assert_eq!(s.pools[&graduated.0].lp_supply, graduated.4);
    assert_eq!(s.tokens[&asset].genesis_pool, Some(graduated.0));
    assert_eq!(
        s.curves[&asset].status,
        CurveStatus::Graduated { pool: graduated.0 }
    );
    s.check_invariants().unwrap();
}

#[test]
fn creator_is_limited_to_two_launches_per_rolling_sixty_epochs() {
    let mut s = funded(Fixed::whole(100));
    for ticker in [b"ONE".as_slice(), b"TWO".as_slice()] {
        cave::create(
            &mut s,
            CREATOR,
            symbol(ticker),
            ticker.to_vec(),
            [0u8; 32],
            100,
            Fixed::ZERO,
            Fixed::ZERO,
        )
        .unwrap();
    }
    assert_eq!(
        cave::create(
            &mut s,
            CREATOR,
            symbol(b"THREE"),
            b"THREE".to_vec(),
            [0u8; 32],
            100,
            Fixed::ZERO,
            Fixed::ZERO
        ),
        Err(swapvm::Reject::LaunchRateLimited),
    );
    s.epoch = 60;
    cave::create(
        &mut s,
        CREATOR,
        symbol(b"THREE"),
        b"THREE".to_vec(),
        [0u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
}

#[test]
fn launch_intent_is_canonical_on_wire_and_executes_through_the_vm() {
    let intent = Intent::LaunchCurve {
        creator: CREATOR,
        symbol: symbol("玉".as_bytes()),
        display_name: b"Dark Jade".to_vec(),
        metadata_hash: [4u8; 32],
        fee_bps: 125,
        dev_buy: Fixed::whole(1_000_000),
        max_zec: Fixed::whole(1),
    };
    let bytes = swapvm::wire::encode_intent_bytes(&intent);
    let mut decoder = zyn_vm::read::Decoder::new(&bytes);
    assert_eq!(swapvm::wire::decode_intent(&mut decoder).unwrap(), intent);
    assert_eq!(decoder.remaining(), 0);

    let mut state = funded(Fixed::whole(1_000));
    let receipts = swapvm::apply(&mut state, &SequencedIntent { seq: 1, intent });
    assert!(receipts
        .iter()
        .any(|r| matches!(r, Receipt::CurveCreated { fee_bps: 125, .. })));
    assert!(receipts
        .iter()
        .any(|r| matches!(r, Receipt::CurveBought { .. })));
    state.check_invariants().unwrap();
}

#[test]
fn graduated_swap_fee_is_45_pool_45_pol_10_creator() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"FEE"),
        b"Fee Rock".to_vec(),
        [8u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let graduation = cave::buy(&mut s, BUYER, asset, CURVE_SUPPLY, Fixed::whole(100)).unwrap();
    let pool = graduation
        .iter()
        .find_map(|r| match r {
            Receipt::CurveGraduated { pool, .. } => Some(*pool),
            _ => None,
        })
        .unwrap();
    let creator_before = s.balance(&CREATOR, XZEC);
    let pol_before = s.balance(&swapvm::types::ZYN_POL, XZEC);
    let receipts = swapvm::apply(
        &mut s,
        &SequencedIntent {
            seq: 1,
            intent: Intent::SwapExactIn {
                account: BUYER,
                asset_in: XZEC,
                path: vec![pool],
                amount_in: Fixed::whole(1),
                min_out: Fixed::ZERO,
            },
        },
    );
    let Receipt::Swapped { hops, .. } = &receipts[0] else {
        panic!("{receipts:?}")
    };
    assert_eq!(hops[0].fee_asset, XZEC);
    assert_eq!(hops[0].fee, Fixed::raw(10_000_000_000_000_000));
    assert_eq!(hops[0].pool_fee, Fixed::raw(4_500_000_000_000_000));
    assert_eq!(hops[0].protocol_fee, Fixed::raw(5_500_000_000_000_000));
    assert_eq!(hops[0].creator_fee, Fixed::raw(1_000_000_000_000_000));
    assert_eq!(hops[0].pol_fee, Fixed::raw(4_500_000_000_000_000));
    assert_eq!(
        s.balance(&CREATOR, XZEC).sub(creator_before),
        Some(Fixed::raw(1_000_000_000_000_000))
    );
    assert_eq!(
        s.balance(&swapvm::types::ZYN_POL, XZEC).sub(pol_before),
        Some(Fixed::raw(4_500_000_000_000_000))
    );
    s.check_invariants().unwrap();
}

#[test]
fn graduated_token_sell_charges_and_routes_only_zec_output() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"SELL"),
        b"Sell stone".to_vec(),
        [31u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let graduation = cave::buy(&mut s, BUYER, asset, CURVE_SUPPLY, Fixed::whole(100)).unwrap();
    let pool = graduation
        .iter()
        .find_map(|r| match r {
            Receipt::CurveGraduated { pool, .. } => Some(*pool),
            _ => None,
        })
        .unwrap();

    let token_in = Fixed::whole(1_000_000);
    let before_pool = s.pools[&pool];
    let (r_in, r_out) = before_pool.oriented(asset).unwrap();
    let gross_zec = amm::out_given_in(token_in, r_in, r_out, 0).unwrap();
    let expected_fee = amm::fee_taken(gross_zec, 100).unwrap();
    let expected_out = gross_zec.sub(expected_fee).unwrap();
    let creator_zec_before = s.balance(&CREATOR, XZEC);
    let creator_token_before = s.balance(&CREATOR, asset);
    let pol_zec_before = s.balance(&swapvm::types::ZYN_POL, XZEC);
    let pol_token_before = s.balance(&swapvm::types::ZYN_POL, asset);

    let receipts = swapvm::apply(
        &mut s,
        &SequencedIntent {
            seq: 1,
            intent: Intent::SwapExactIn {
                account: BUYER,
                asset_in: asset,
                path: vec![pool],
                amount_in: token_in,
                min_out: expected_out,
            },
        },
    );
    let Receipt::Swapped {
        amount_out, hops, ..
    } = &receipts[0]
    else {
        panic!("{receipts:?}")
    };
    let h = hops[0];
    assert_eq!(*amount_out, expected_out);
    assert_eq!(h.fee_asset, XZEC);
    assert_eq!(h.fee, expected_fee);
    assert_eq!(
        h.pool_fee.add(h.creator_fee).and_then(|v| v.add(h.pol_fee)),
        Some(h.fee)
    );
    assert_eq!(h.creator_fee.add(h.pol_fee), Some(h.protocol_fee));
    assert_eq!(
        s.balance(&CREATOR, XZEC).sub(creator_zec_before),
        Some(h.creator_fee)
    );
    assert_eq!(
        s.balance(&swapvm::types::ZYN_POL, XZEC).sub(pol_zec_before),
        Some(h.pol_fee)
    );
    assert_eq!(s.balance(&CREATOR, asset), creator_token_before);
    assert_eq!(s.balance(&swapvm::types::ZYN_POL, asset), pol_token_before);
    let after_pool = s.pools[&pool];
    assert_eq!(
        after_pool.reserve_of(asset),
        Some(
            before_pool
                .reserve_of(asset)
                .unwrap()
                .add(token_in)
                .unwrap()
        )
    );
    assert_eq!(
        after_pool.reserve_of(XZEC),
        Some(
            before_pool
                .reserve_of(XZEC)
                .unwrap()
                .sub(expected_out.add(h.protocol_fee).unwrap())
                .unwrap()
        )
    );
    s.check_invariants().unwrap();
}

#[test]
fn graduated_exact_output_sell_grosses_up_the_zec_fee() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"EXACT"),
        b"Exact stone".to_vec(),
        [33u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let graduation = cave::buy(&mut s, BUYER, asset, CURVE_SUPPLY, Fixed::whole(100)).unwrap();
    let pool = graduation
        .iter()
        .find_map(|r| match r {
            Receipt::CurveGraduated { pool, .. } => Some(*pool),
            _ => None,
        })
        .unwrap();

    let wanted = Fixed::raw(10_000_000_000_000_000); // 0.01 ZEC.zy net
    let keep = Fixed::whole(9_900);
    let gross = wanted.mul_div_ceil(Fixed::whole(10_000), keep).unwrap();
    let expected_fee = gross.sub(wanted).unwrap();
    let p = s.pools[&pool];
    let (r_in, r_out) = p.oriented(asset).unwrap();
    let expected_input = amm::in_given_out(gross, r_in, r_out, 0).unwrap();
    let receipts = swapvm::apply(
        &mut s,
        &SequencedIntent {
            seq: 1,
            intent: Intent::SwapExactOut {
                account: BUYER,
                asset_in: asset,
                path: vec![pool],
                amount_out: wanted,
                max_in: expected_input,
            },
        },
    );
    let Receipt::Swapped {
        amount_in,
        amount_out,
        hops,
        ..
    } = &receipts[0]
    else {
        panic!("{receipts:?}")
    };
    assert_eq!((*amount_in, *amount_out), (expected_input, wanted));
    assert_eq!(hops[0].fee_asset, XZEC);
    assert_eq!(hops[0].fee, expected_fee);
    assert_eq!(
        hops[0].pool_fee.add(hops[0].protocol_fee),
        Some(expected_fee)
    );
    s.check_invariants().unwrap();
}

#[test]
fn graduated_batch_charges_both_sides_in_zec_and_reconciles_every_share() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"BATCH"),
        b"Batch stone".to_vec(),
        [32u8; 32],
        100,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let graduation = cave::buy(&mut s, BUYER, asset, CURVE_SUPPLY, Fixed::whole(100)).unwrap();
    let pool = graduation
        .iter()
        .find_map(|r| match r {
            Receipt::CurveGraduated { pool, .. } => Some(*pool),
            _ => None,
        })
        .unwrap();
    s.batch_clearing = true;
    let creator_token_before = s.balance(&CREATOR, asset);
    let pol_token_before = s.balance(&swapvm::types::ZYN_POL, asset);
    let creator_zec_before = s.balance(&CREATOR, XZEC);
    let pol_zec_before = s.balance(&swapvm::types::ZYN_POL, XZEC);

    assert!(matches!(
        swapvm::apply(
            &mut s,
            &SequencedIntent {
                seq: 1,
                intent: Intent::SwapExactIn {
                    account: CREATOR,
                    asset_in: XZEC,
                    path: vec![pool],
                    amount_in: Fixed::whole(1),
                    min_out: Fixed::ZERO,
                },
            }
        )
        .as_slice(),
        [Receipt::SwapQueued { .. }]
    ));
    assert!(matches!(
        swapvm::apply(
            &mut s,
            &SequencedIntent {
                seq: 2,
                intent: Intent::SwapExactIn {
                    account: BUYER,
                    asset_in: asset,
                    path: vec![pool],
                    amount_in: Fixed::whole(1_000_000),
                    min_out: Fixed::ZERO,
                },
            }
        )
        .as_slice(),
        [Receipt::SwapQueued { .. }]
    ));
    let receipts = swapvm::apply(
        &mut s,
        &SequencedIntent {
            seq: 3,
            intent: Intent::Checkpoint,
        },
    );
    let hops: Vec<_> = receipts
        .iter()
        .filter_map(|r| match r {
            Receipt::Swapped { hops, .. } => Some(hops[0]),
            _ => None,
        })
        .collect();
    assert_eq!(hops.len(), 2, "{receipts:?}");
    assert!(hops.iter().all(|h| h.fee_asset == XZEC));
    assert!(hops
        .iter()
        .all(|h| h.pool_fee.add(h.creator_fee).and_then(|v| v.add(h.pol_fee)) == Some(h.fee)));
    let creator_total = hops
        .iter()
        .fold(Fixed::ZERO, |v, h| v.add(h.creator_fee).unwrap());
    let pol_total = hops
        .iter()
        .fold(Fixed::ZERO, |v, h| v.add(h.pol_fee).unwrap());
    assert_eq!(
        s.balance(&CREATOR, XZEC).sub(creator_zec_before),
        Some(creator_total.sub(Fixed::whole(1)).unwrap())
    );
    assert_eq!(
        s.balance(&swapvm::types::ZYN_POL, XZEC).sub(pol_zec_before),
        Some(pol_total)
    );
    assert_eq!(
        s.balance(&CREATOR, asset),
        creator_token_before
            .add(
                hops.iter()
                    .find(|h| h.asset_out == asset)
                    .unwrap()
                    .amount_out
            )
            .unwrap()
    );
    assert_eq!(s.balance(&swapvm::types::ZYN_POL, asset), pol_token_before);
    s.check_invariants().unwrap();
}

#[test]
fn long_reversible_churn_matches_quotes_and_survives_restart() {
    let mut s = funded(Fixed::whole(2_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol("石".as_bytes()),
        "Churn stone".as_bytes().to_vec(),
        [13u8; 32],
        cave::MAX_FEE_BPS,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };

    let mut seed = 0x6a09_e667_f3bc_c909_u64;
    let mut held = Fixed::ZERO;
    for step in 0..1_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let tokens = Fixed::whole(((seed >> 32) % 2_000_000 + 1) as i64);
        if step % 3 == 2 && held >= tokens {
            let expected = cave::quote_sell(&s.curves[&asset], tokens).unwrap();
            let receipts = cave::sell(&mut s, BUYER, asset, tokens, Fixed::ZERO).unwrap();
            let Receipt::CurveSold {
                principal,
                fee,
                received,
                sold,
                price,
                ..
            } = receipts[0]
            else {
                panic!("unexpected sell receipt: {receipts:?}")
            };
            assert_eq!(
                (principal, fee, received, sold, price),
                (
                    expected.principal,
                    expected.fee,
                    expected.settlement,
                    expected.sold_after,
                    expected.price_after,
                )
            );
            held = held.sub(tokens).unwrap();
        } else {
            let expected = cave::quote_buy(&s.curves[&asset], tokens).unwrap();
            let receipts = cave::buy(&mut s, BUYER, asset, tokens, Fixed::whole(100)).unwrap();
            let Receipt::CurveBought {
                principal,
                fee,
                total,
                sold,
                price,
                ..
            } = receipts[0]
            else {
                panic!("unexpected buy receipt: {receipts:?}")
            };
            assert_eq!(
                (principal, fee, total, sold, price),
                (
                    expected.principal,
                    expected.fee,
                    expected.settlement,
                    expected.sold_after,
                    expected.price_after,
                )
            );
            held = held.add(tokens).unwrap();
        }
        if step % 25 == 0 {
            s.check_invariants().unwrap();
        }
    }
    assert_eq!(s.balance(&BUYER, asset), held);
    s.check_invariants().unwrap();
    let restored = SwapState::decode_state(&s.encode_state()).unwrap();
    assert_eq!(restored, s);
    restored.check_invariants().unwrap();
}

#[test]
fn atomic_rounding_and_fee_dust_favour_protocol_liquidity() {
    let mut s = funded(Fixed::whole(1_000));
    let created = cave::create(
        &mut s,
        CREATOR,
        symbol(b"DUST"),
        b"Dust stone".to_vec(),
        [21u8; 32],
        cave::DEFAULT_FEE_BPS,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .unwrap();
    let Receipt::CurveCreated { asset, .. } = created[0] else {
        panic!()
    };
    let vault = cave::launch_vault(&asset);
    let pol_before = s.balance(&swapvm::types::ZYN_POL, XZEC);
    let receipts = cave::buy(&mut s, BUYER, asset, cave::TOKEN_UNIT, Fixed::raw(2)).unwrap();
    let Receipt::CurveBought {
        principal,
        fee,
        total,
        ..
    } = receipts[0]
    else {
        panic!()
    };
    assert_eq!(
        (principal, fee, total),
        (Fixed::raw(1), Fixed::raw(1), Fixed::raw(2))
    );
    assert_eq!(
        s.balance(&swapvm::types::ZYN_POL, XZEC),
        pol_before.add(Fixed::raw(1)).unwrap()
    );
    assert_eq!(
        s.balance(&vault, XZEC),
        PAIR_SEED.add(Fixed::raw(1)).unwrap()
    );
    assert_eq!(s.curves[&asset].creator_fees, Fixed::ZERO);
    assert_eq!(s.curves[&asset].graduation_fees, Fixed::ZERO);
    s.check_invariants().unwrap();
}
