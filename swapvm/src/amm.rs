//! Constant-product AMM arithmetic. Uniswap-v2 mechanics, per the project
//! plan: deliberately no concentrated liquidity in V1.
//!
//! Every function is pure and returns `Option` on arithmetic failure. All
//! quantities are positive in practice, and `Fixed` truncates toward zero, so
//! every division rounds **down** — which here always favours the pool.
//! Rounding the other way at any point would let a swap withdraw one raw unit
//! more than the curve allows, and a determined trader would loop that unit
//! into a drain.

use crate::fixed::Fixed;

/// Basis points per whole, the unit fees are expressed in.
pub const BPS: u64 = 10_000;

/// Output for an exact input, fee taken from the input.
///
/// ```text
/// in_after_fee = in * (BPS - fee) / BPS
/// out          = r_out * in_after_fee / (r_in + in_after_fee)
/// ```
pub fn out_given_in(
    amount_in: Fixed,
    reserve_in: Fixed,
    reserve_out: Fixed,
    fee_bps: u16,
) -> Option<Fixed> {
    if !amount_in.is_positive() || !reserve_in.is_positive() || !reserve_out.is_positive() {
        return None;
    }
    let fee_keep = Fixed::whole((BPS - fee_bps as u64) as i64);
    // One `mul_div`, not a `mul` by the basis-point figure: `fee_keep` is 9970,
    // not 0.997, so the division by BPS is what puts it back on scale. Doing it
    // in one step also keeps the fee exact rather than truncating twice.
    let in_after_fee = amount_in.mul_div(fee_keep, Fixed::whole(BPS as i64))?;
    reserve_out.mul_div(in_after_fee, reserve_in.add(in_after_fee)?)
}

/// Input required for an exact output, fee grossed up onto the input.
///
/// The exact inverse of `out_given_in`, with rounding flipped: `out_given_in`
/// truncates twice, so this function ceilings twice, at the same two places.
///
/// ```text
/// a = ceil(r_in * out / (r_out - out))   post-fee input the curve demands
/// in = ceil(a * BPS / (BPS - fee))       grossed up for the fee
/// ```
///
/// Both ceilings are load-bearing, and the pair is exactly tight: `in` is the
/// smallest input for which `out_given_in` returns at least `out`, and `in - 1`
/// always returns less. An earlier version truncated and added a single raw
/// unit, which is not the same thing — at dust scale the fee truncation eats
/// more than a unit, so a one-unit bump left the caller short of what they
/// asked for. Rounding the other way would be worse than short: it would hand
/// out the pool's rounding dust one unit at a time, and a determined trader
/// would loop that into a drain.
pub fn in_given_out(
    amount_out: Fixed,
    reserve_in: Fixed,
    reserve_out: Fixed,
    fee_bps: u16,
) -> Option<Fixed> {
    if !amount_out.is_positive() || !reserve_in.is_positive() || !reserve_out.is_positive() {
        return None;
    }
    if amount_out >= reserve_out {
        return None; // cannot take the whole reserve
    }
    let fee_keep = Fixed::whole((BPS - fee_bps as u64) as i64);
    let in_after_fee = reserve_in.mul_div_ceil(amount_out, reserve_out.sub(amount_out)?)?;
    let gross = in_after_fee.mul_div_ceil(Fixed::whole(BPS as i64), fee_keep)?;
    if !gross.is_positive() {
        return None;
    }
    Some(gross)
}

/// The portion of `amount_in` that does not enter the curve — the fee the pool
/// keeps for its LPs.
///
/// Defined as exactly what `out_given_in` withholds, rather than as
/// `amount_in * fee / BPS` computed independently. The two differ by up to a
/// raw unit at the truncation boundary, and a receipt that reported the second
/// while the reserves moved by the first would be a receipt that does not
/// describe the trade.
pub fn fee_taken(amount_in: Fixed, fee_bps: u16) -> Option<Fixed> {
    if !amount_in.is_positive() {
        return None;
    }
    let fee_keep = Fixed::whole((BPS - fee_bps as u64) as i64);
    let in_after_fee = amount_in.mul_div(fee_keep, Fixed::whole(BPS as i64))?;
    amount_in.sub(in_after_fee)
}

/// The fee that leaves an LP no worse off when the pool is repriced.
///
/// # The problem this exists for
///
/// A constant-product curve is a *price-discovery* mechanism. For a memecoin
/// with no market anywhere else, that is exactly the service an LP provides and
/// the fee is fair payment for it. For a bridged pair — SOL against xZEC, both
/// with deep external markets — price is already discovered, and the pool is a
/// slow mirror of it. Every external move hands an arbitrageur the difference,
/// at the LP's expense. That is loss-versus-rebalancing, and at V1's 0.30% it
/// is not close to covered:
///
/// ```text
///   external move   arb takes   0.30% collects   break-even fee
///           +10%     2.38 xZEC       6.1%             4.88%
///           +20%     9.11 xZEC       3.1%             9.54%
///           +50%    50.51 xZEC       1.3%            22.47%
/// ```
///
/// # The closed form
///
/// Pushing a pool from price `p` to `p·r` costs the arbitrageur `x(√r − 1)` and
/// returns exactly `√r − 1` of that as profit. So the fee that recaptures it is
/// **`√r − 1`**, where `r` is the divergence ratio — no approximation, and the
/// figures above are this formula.
///
/// # Why this takes a reference price and not a price
///
/// The reference sets the **fee**, never the quote. That distinction is the
/// whole safety argument. An oracle that sets prices turns oracle manipulation
/// into direct theft — push the reported price, drain the pool — which is the
/// most exploited pattern in DeFi. An oracle that sets fees can only make fees
/// wrong: a manipulated reference costs the pool some edge on one trade and
/// cannot move a single unit out of it. The curve still decides what a trader
/// receives, so the worst case is bounded by construction rather than by how
/// well the reference is defended.
///
/// Returns `None` on a non-positive price. Never returns less than
/// `base_fee_bps`, and never reaches 100%.
pub fn divergence_fee(pool_price: Fixed, reference: Fixed, base_fee_bps: u16) -> Option<u16> {
    if !pool_price.is_positive() || !reference.is_positive() {
        return None;
    }
    // Divergence is symmetric: it costs an LP the same whether the pool is
    // above the market or below it.
    let ratio = if pool_price >= reference {
        pool_price.div(reference)?
    } else {
        reference.div(pool_price)?
    };
    let excess = sqrt(ratio)?.sub(Fixed::ONE)?;
    if !excess.is_positive() {
        return Some(base_fee_bps);
    }
    let bps = excess.mul(Fixed::whole(BPS as i64))?;
    // A fee at or above 100% would price the pool out of trading entirely; cap
    // just below, and let a caller decide whether that is a pool worth quoting.
    let capped = (bps.0 / crate::fixed::WAD).clamp(0, BPS as i128 - 1) as u16;
    Some(capped.max(base_fee_bps))
}

/// LP shares minted for depositing `(amount0, amount1)` into a pool holding
/// `(reserve0, reserve1)` with `supply` shares outstanding.
///
/// First deposit mints `sqrt(amount0 * amount1) - min_liquidity`; the locked
/// minimum is never minted to anyone, so supply can never reach zero and the
/// first LP cannot corner it. Later deposits mint proportional to the cheaper
/// side — donating an unbalanced amount buys no extra shares, exactly v2.
pub fn mint_shares(
    amount0: Fixed,
    amount1: Fixed,
    reserve0: Fixed,
    reserve1: Fixed,
    supply: Fixed,
    min_liquidity: Fixed,
) -> Option<Fixed> {
    if !amount0.is_positive() || !amount1.is_positive() {
        return None;
    }
    if supply.is_zero() {
        if !reserve0.is_zero() || !reserve1.is_zero() {
            return None; // empty pool must have no reserves
        }
        let product = amount0.mul(amount1)?;
        let shares = sqrt(product)?;
        let shares = shares.sub(min_liquidity)?;
        if !shares.is_positive() {
            return None; // deposit too small to clear the locked minimum
        }
        return Some(shares);
    }
    if !reserve0.is_positive() || !reserve1.is_positive() {
        return None;
    }
    let s0 = amount0.mul_div(supply, reserve0)?;
    let s1 = amount1.mul_div(supply, reserve1)?;
    Some(s0.min(s1))
}

/// Assets returned for burning `shares` against one side of a pool.
pub fn burn_shares(shares: Fixed, reserve: Fixed, supply: Fixed) -> Option<Fixed> {
    if !shares.is_positive() || !supply.is_positive() {
        return None;
    }
    if shares > supply {
        return None;
    }
    reserve.mul_div(shares, supply)
}

/// Spot price of asset0 in units of asset1: reserve1 / reserve0.
pub fn spot_price(reserve0: Fixed, reserve1: Fixed) -> Option<Fixed> {
    if !reserve0.is_positive() || !reserve1.is_positive() {
        return None;
    }
    reserve1.div(reserve0)
}

/// Integer square root of a non-negative `Fixed`, computed on the raw
/// representation: sqrt(w * 1e18) == isqrt(w) * 1e9. Bit-by-bit, so it is
/// exactly reproducible — no platform libm anywhere near a state root.
pub fn sqrt(v: Fixed) -> Option<Fixed> {
    if v.is_negative() {
        return None;
    }
    let root = isqrt_u128(v.0 as u128);
    // Scale back to WAD: multiply by 1e9 = sqrt(1e18), checked for overflow.
    let scaled = (root as i128).checked_mul(1_000_000_000)?;
    Some(Fixed::raw(scaled))
}

fn isqrt_u128(n: u128) -> u128 {
    // Classic shift-subtract, MSB first. 128 iterations, no table, no float.
    let mut rem = n;
    let mut root: u128 = 0;
    let mut bit: u128 = 1 << 126;
    while bit > n {
        bit >>= 2;
    }
    while bit != 0 {
        let candidate = root + bit;
        if rem >= candidate {
            rem -= candidate;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::WAD;

    /// The reference example every AMM implementation is judged against:
    /// 10 CAT and 1000 xZEC, sell 1 CAT with a 0.30% fee.
    #[test]
    fn out_given_in_matches_the_hand_computation() {
        let out = out_given_in(Fixed::whole(1), Fixed::whole(10), Fixed::whole(1_000), 30).unwrap();
        // in_after_fee = 0.997; out = 1000 * 0.997 / (10 + 0.997)
        //              = 997000/10997 = 90.661089388014913158...
        let expected = Fixed::raw(90_661_089_388_014_913_158); // truncated toward zero
        assert_eq!(out, expected);
        // Sanity check on the scale itself: selling a tenth of the pool's CAT
        // must return something near a tenth of its xZEC, not the whole pool.
        assert!(
            out < Fixed::whole(100),
            "fee scaling is off by orders of magnitude"
        );
    }

    #[test]
    fn exact_output_round_trips_to_at_least_the_request() {
        let fee = 30;
        let (r_in, r_out) = (Fixed::whole(10), Fixed::whole(1_000));
        for wanted_raw in [1i128, 7, 123_456_789, 5 * WAD, 900 * WAD] {
            let wanted = Fixed::raw(wanted_raw);
            let need = in_given_out(wanted, r_in, r_out, fee).unwrap();
            assert!(need.is_positive());
            let got = out_given_in(need, r_in, r_out, fee).unwrap();
            assert!(
                got >= wanted,
                "got {} wanted {} (need {})",
                got,
                wanted,
                need
            );
            // And the gross-up must be tight: one more raw unit of input
            // cannot still produce the request.
            let less = Fixed::raw(need.0 - 1);
            let got_less = out_given_in(less, r_in, r_out, fee).unwrap();
            assert!(got_less < wanted, "input gross-up not tight: {}", need);
        }
    }

    /// The closed form is exact: the break-even fee for a divergence `r` is
    /// `sqrt(r) - 1`, which is what the measured arbitrage profit comes to.
    #[test]
    fn the_divergence_fee_matches_the_arbitrage_it_recaptures() {
        let p = Fixed::whole(10);
        for (mult, expect_bps) in [(11, 488u16), (12, 954), (15, 2_247)] {
            let reference = p.mul_div(Fixed::whole(mult), Fixed::whole(10)).unwrap();
            let fee = divergence_fee(p, reference, 30).unwrap();
            // Within a basis point of the hand-computed figure.
            assert!(
                fee.abs_diff(expect_bps) <= 1,
                "divergence {}0%: fee {} bps, expected about {}",
                mult,
                fee,
                expect_bps
            );
        }
    }

    #[test]
    fn divergence_is_symmetric_and_floors_at_the_base_fee() {
        let (a, b) = (Fixed::whole(10), Fixed::whole(12));
        assert_eq!(
            divergence_fee(a, b, 30),
            divergence_fee(b, a, 30),
            "direction changed the fee"
        );
        // A pool already at the reference charges the ordinary fee.
        assert_eq!(divergence_fee(a, a, 30), Some(30));
        // And never less, however small the divergence.
        assert_eq!(
            divergence_fee(a, a.add(Fixed::raw(1)).unwrap(), 30),
            Some(30)
        );
    }

    #[test]
    fn an_extreme_divergence_is_capped_below_a_total_fee() {
        let fee = divergence_fee(Fixed::whole(1), Fixed::whole(1_000_000), 30).unwrap();
        assert!(
            fee < BPS as u16,
            "a fee of 100% or more would be uncollectable"
        );
        assert!(
            fee > 5_000,
            "an extreme divergence should still price steeply: {}",
            fee
        );
        assert_eq!(divergence_fee(Fixed::ZERO, Fixed::ONE, 30), None);
        assert_eq!(divergence_fee(Fixed::ONE, Fixed::ZERO, 30), None);
    }

    /// The safety property: a manipulated reference changes the fee and nothing
    /// else. It can never move a unit out of the pool, because the curve still
    /// decides what a trader receives.
    #[test]
    fn a_manipulated_reference_cannot_move_the_quote() {
        let (r_in, r_out) = (Fixed::whole(1_000), Fixed::whole(100));
        let honest = divergence_fee(r_in.div(r_out).unwrap(), Fixed::whole(10), 30).unwrap();
        let forged = divergence_fee(r_in.div(r_out).unwrap(), Fixed::whole(1), 30).unwrap();
        assert!(forged > honest, "the forged reference should raise the fee");

        // Under both, the output is whatever the curve says for the fee charged
        // — a higher fee gives the trader *less*, never the pool's reserves.
        let a = out_given_in(Fixed::whole(10), r_in, r_out, honest).unwrap();
        let b = out_given_in(Fixed::whole(10), r_in, r_out, forged).unwrap();
        assert!(b < a, "a manipulated reference must not pay out more");
        assert!(b.is_positive() && b < r_out);
    }

    #[test]
    fn the_reported_fee_is_what_the_curve_actually_withheld() {
        // The receipt figure and the reserves must describe the same trade, so
        // the fee is derived from the curve rather than recomputed beside it.
        for raw in [2i128, 1_000, 12_345_678, WAD, 987 * WAD] {
            let amt = Fixed::raw(raw);
            let fee = fee_taken(amt, 30).unwrap();
            let after = amt.sub(fee).unwrap();
            assert_eq!(
                after,
                amt.mul_div(Fixed::whole(9_970), Fixed::whole(10_000))
                    .unwrap()
            );
            assert!(!fee.is_negative(), "fee went negative at {}", amt);
            assert!(fee < amt, "fee consumed the whole input at {}", amt);
        }
        // A zero-fee pool withholds nothing.
        assert_eq!(fee_taken(Fixed::whole(100), 0).unwrap(), Fixed::ZERO);
        assert_eq!(fee_taken(Fixed::ZERO, 30), None);
    }

    #[test]
    fn fees_make_k_non_decreasing() {
        // Every swap must leave r0*r1 >= previous k: the fee is what stops a
        // round trip from extracting value.
        let (mut r0, mut r1) = (Fixed::whole(1_000), Fixed::whole(1_000_000));
        let k_before = r0.mul(r1).unwrap();
        // A deterministic wiggle of swaps both directions.
        for i in 0..50 {
            let (in_amt, r_in, r_out) = if i % 2 == 0 {
                (Fixed::whole(3 + i), r0, r1)
            } else {
                (Fixed::whole(4_000 + 10 * i), r1, r0)
            };
            let out = out_given_in(in_amt, r_in, r_out, 30).unwrap();
            if i % 2 == 0 {
                r0 = r0.add(in_amt).unwrap();
                r1 = r1.sub(out).unwrap();
            } else {
                r1 = r1.add(in_amt).unwrap();
                r0 = r0.sub(out).unwrap();
            }
        }
        assert!(r0.mul(r1).unwrap() >= k_before);
        assert!(r0.is_positive() && r1.is_positive());
    }

    #[test]
    fn first_mint_locks_the_minimum() {
        let min = Fixed::raw(1_000);
        let a0 = Fixed::whole(10);
        let a1 = Fixed::whole(1_000);
        let product = a0.mul(a1).unwrap();
        let shares = mint_shares(a0, a1, Fixed::ZERO, Fixed::ZERO, Fixed::ZERO, min).unwrap();
        assert_eq!(shares, sqrt(product).unwrap().sub(min).unwrap());
        // A deposit too small to clear the locked minimum mints nothing.
        let tiny0 = Fixed::raw(2);
        let tiny1 = Fixed::raw(2);
        assert!(mint_shares(tiny0, tiny1, Fixed::ZERO, Fixed::ZERO, Fixed::ZERO, min).is_none());
    }

    #[test]
    fn proportional_deposit_mints_proportionally() {
        // Doubling both reserves doubles the supply due.
        let supply = Fixed::whole(1_000);
        let shares = mint_shares(
            Fixed::whole(10),
            Fixed::whole(1_000),
            Fixed::whole(10),
            Fixed::whole(1_000),
            supply,
            Fixed::raw(1_000),
        )
        .unwrap();
        assert_eq!(shares, Fixed::whole(1_000));
    }

    #[test]
    fn unbalanced_deposit_mints_for_the_cheaper_side() {
        // Twice the asset0, the exact asset1: shares follow the binding side.
        let shares = mint_shares(
            Fixed::whole(20),
            Fixed::whole(1_000),
            Fixed::whole(10),
            Fixed::whole(1_000),
            Fixed::whole(1_000),
            Fixed::raw(1_000),
        )
        .unwrap();
        assert_eq!(shares, Fixed::whole(1_000));
    }

    #[test]
    fn burning_all_shares_returns_all_reserves() {
        let out = burn_shares(Fixed::whole(500), Fixed::whole(10), Fixed::whole(500)).unwrap();
        assert_eq!(out, Fixed::whole(10));
        assert!(burn_shares(Fixed::whole(501), Fixed::whole(10), Fixed::whole(500)).is_none());
    }

    #[test]
    fn sqrt_is_exact_on_perfect_squares() {
        assert_eq!(sqrt(Fixed::whole(4)).unwrap(), Fixed::whole(2));
        assert_eq!(sqrt(Fixed::whole(1)).unwrap(), Fixed::ONE);
        let product = Fixed::whole(10).mul(Fixed::whole(1_000)).unwrap();
        // sqrt(10000) = 100
        assert_eq!(sqrt(product).unwrap(), Fixed::whole(100));
        assert!(sqrt(Fixed::whole(-1)).is_none());
        // Between squares it floors.
        let s = sqrt(Fixed::whole(8)).unwrap();
        assert!(s >= Fixed::whole(2) && s < Fixed::whole(3));
    }

    #[test]
    fn spot_price_is_reserve_ratio() {
        let p = spot_price(Fixed::whole(10), Fixed::whole(1_000)).unwrap();
        assert_eq!(p, Fixed::whole(100));
    }
}
