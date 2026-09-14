//! Permissionless fixed-supply launches for Cave.
//!
//! A launch mints its entire billion-token supply once. 660 million tokens
//! trade against a reversible linear curve; the remaining 340 million and at
//! most 34 ZEC.zy migrate atomically into the canonical ZynZap pool when the
//! marginal price implies a 100 ZEC.zy fully-diluted value.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::amm;
use crate::fixed::Fixed;
use crate::state::{Pool, SwapState, Symbol, TokenInfo};
use crate::tx::{Receipt, Reject};
use crate::types::{AccountId, AssetId, PoolId, ADDRESS_SCOPE_V1, XZEC, ZYN_POL};

pub const TOTAL_SUPPLY: Fixed = Fixed::raw(1_000_000_000_000_000_000_000_000_000);
pub const CURVE_SUPPLY: Fixed = Fixed::raw(660_000_000_000_000_000_000_000_000);
pub const POOL_TOKEN_SUPPLY: Fixed = Fixed::raw(340_000_000_000_000_000_000_000_000);
pub const TOKEN_UNIT: Fixed = Fixed::raw(10_000_000_000); // 10^-8 token
pub const LAUNCH_FEE: Fixed = Fixed::raw(10_000_000_000_000_000); // 0.01 ZEC.zy
pub const PAIR_SEED: Fixed = Fixed::raw(9_000_000_000_000_000); // 0.009
pub const TREASURY_FEE: Fixed = Fixed::raw(1_000_000_000_000_000); // 0.001
pub const START_PRICE: Fixed = Fixed::raw(9_000_000); // 0.009 / 1B
pub const GRADUATION_PRICE: Fixed = Fixed::raw(100_000_000_000); // 100 / 1B
pub const GRADUATION_POOL_CAP: Fixed = Fixed::raw(34_000_000_000_000_000_000);
pub const DEFAULT_FEE_BPS: u16 = 100;
pub const MIN_FEE_BPS: u16 = 50;
pub const MAX_FEE_BPS: u16 = 300;
pub const MAX_DEV_BUY: Fixed = Fixed::raw(50_000_000_000_000_000_000_000_000);
const RATE_WINDOW_EPOCHS: u64 = 60;
const RATE_LIMIT: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CurveStatus {
    Trading,
    Graduated { pool: PoolId },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CurveLaunch {
    pub creator: AccountId,
    pub symbol: Symbol,
    /// Exact UTF-8 bytes. No normalization: identity is the derived address,
    /// never a display string.
    pub display_name: Vec<u8>,
    pub metadata_hash: [u8; 32],
    pub fee_bps: u16,
    pub sold: Fixed,
    pub creator_fees: Fixed,
    pub graduation_fees: Fixed,
    /// Immutable opening AMM values; zero until graduation.
    pub graduated_token_liquidity: Fixed,
    pub graduated_zec_liquidity: Fixed,
    pub graduation_overflow: Fixed,
    pub graduated_locked_lp: Fixed,
    pub status: CurveStatus,
}

pub type CurveBook = BTreeMap<AssetId, CurveLaunch>;
pub type CreatorLaunches = BTreeMap<AccountId, Vec<u64>>;

/// An exact, deterministic curve quote. `settlement` is the ZEC.zy the buyer
/// pays for a buy, or the seller receives for a sell.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CurveQuote {
    pub principal: Fixed,
    pub fee: Fixed,
    pub settlement: Fixed,
    pub sold_after: Fixed,
    pub price_after: Fixed,
    pub graduates: bool,
}

pub fn launch_vault(asset: &AssetId) -> AccountId {
    zyn_vm::vault_address(ADDRESS_SCOPE_V1, asset)
}

/// Integral of the linear marginal-price curve from zero to `q`.
/// This is the floor used for state/reporting vectors. Trade settlement uses
/// [`principal_between`] so the exact interval is rounded once, at the end.
pub fn reserve_for(q: Fixed) -> Option<Fixed> {
    principal_between(Fixed::ZERO, q, false)
}

/// Exact integral over `[low, high]`, with the only division performed last.
///
/// Curve quantities are multiples of `TOKEN_UNIT` (10^-8 display token), so
/// writing them in token atomic units keeps the denominator inside `i128` and
/// the product inside the fixed library's 256-bit intermediate:
///
/// `a * (2Q*p0 + (Pg-p0)*(high+low)) / (2Q*10^8)`.
///
/// Buys round up so even a sub-WAD exact cost pays one raw ZEC.zy unit; sells
/// round down toward the reserve. This prevents free atomic buys at the start
/// of the curve without storing an unrepresentable fixed-point slope.
fn principal_between(low: Fixed, high: Fixed, round_up: bool) -> Option<Fixed> {
    if low.is_negative() || high < low || high > CURVE_SUPPLY {
        return None;
    }
    if low.0 % TOKEN_UNIT.0 != 0 || high.0 % TOKEN_UNIT.0 != 0 {
        return None;
    }
    let q = CURVE_SUPPLY.0 / TOKEN_UNIT.0;
    let lo = low.0 / TOKEN_UNIT.0;
    let hi = high.0 / TOKEN_UNIT.0;
    let amount = hi.checked_sub(lo)?;
    let twice_q = q.checked_mul(2)?;
    let base = twice_q.checked_mul(START_PRICE.0)?;
    let slope = GRADUATION_PRICE
        .0
        .checked_sub(START_PRICE.0)?
        .checked_mul(hi.checked_add(lo)?)?;
    let average_numerator = base.checked_add(slope)?;
    let denominator = twice_q.checked_mul(100_000_000)?;
    let raw = if round_up {
        zyn_vm::fixed::mul_div_ceil(amount, average_numerator, denominator)?
    } else {
        zyn_vm::fixed::mul_div(amount, average_numerator, denominator)?
    };
    Some(Fixed::raw(raw))
}

pub fn marginal_price(q: Fixed) -> Option<Fixed> {
    if q.is_negative() || q > CURVE_SUPPLY {
        return None;
    }
    START_PRICE.add(
        GRADUATION_PRICE
            .sub(START_PRICE)?
            .mul(q.div(CURVE_SUPPLY)?)?,
    )
}

fn fee(amount: Fixed, bps: u16, round_up: bool) -> Option<Fixed> {
    let n = Fixed::whole(bps as i64);
    let d = Fixed::whole(10_000);
    if round_up {
        amount.mul_div_ceil(n, d)
    } else {
        amount.mul_div(n, d)
    }
}

fn validate_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > 96 {
        return false;
    }
    let Ok(s) = core::str::from_utf8(name) else {
        return false;
    };
    if s.starts_with(' ') || s.ends_with(' ') {
        return false;
    }
    !s.chars().any(|c| {
        c.is_control()
            || (c.is_whitespace() && c != ' ')
            || matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F)
    })
}

fn admits_token_amount(v: Fixed) -> bool {
    v.is_positive() && v.0 % TOKEN_UNIT.0 == 0
}

pub fn quote_buy(c: &CurveLaunch, amount: Fixed) -> Result<CurveQuote, Reject> {
    if !admits_token_amount(amount) {
        return Err(Reject::Indivisible);
    }
    if c.status != CurveStatus::Trading {
        return Err(Reject::CurveGraduated);
    }
    let sold_after = c.sold.add(amount).ok_or(Reject::ArithmeticFailure)?;
    if sold_after > CURVE_SUPPLY {
        return Err(Reject::InsufficientCurveInventory);
    }
    let principal = principal_between(c.sold, sold_after, true).ok_or(Reject::ArithmeticFailure)?;
    let fee = fee(principal, c.fee_bps, true).ok_or(Reject::ArithmeticFailure)?;
    Ok(CurveQuote {
        principal,
        fee,
        settlement: principal.add(fee).ok_or(Reject::ArithmeticFailure)?,
        sold_after,
        price_after: marginal_price(sold_after).ok_or(Reject::ArithmeticFailure)?,
        graduates: sold_after == CURVE_SUPPLY,
    })
}

pub fn quote_sell(c: &CurveLaunch, amount: Fixed) -> Result<CurveQuote, Reject> {
    if !admits_token_amount(amount) {
        return Err(Reject::Indivisible);
    }
    if c.status != CurveStatus::Trading {
        return Err(Reject::CurveGraduated);
    }
    if amount > c.sold {
        return Err(Reject::InsufficientCurveInventory);
    }
    let sold_after = c.sold.sub(amount).ok_or(Reject::ArithmeticFailure)?;
    let principal =
        principal_between(sold_after, c.sold, false).ok_or(Reject::ArithmeticFailure)?;
    let fee = fee(principal, c.fee_bps, false).ok_or(Reject::ArithmeticFailure)?;
    Ok(CurveQuote {
        principal,
        fee,
        settlement: principal.sub(fee).ok_or(Reject::ArithmeticFailure)?,
        sold_after,
        price_after: marginal_price(sold_after).ok_or(Reject::ArithmeticFailure)?,
        graduates: false,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn create(
    state: &mut SwapState,
    creator: AccountId,
    symbol: Symbol,
    display_name: Vec<u8>,
    metadata_hash: [u8; 32],
    fee_bps: u16,
    dev_buy: Fixed,
    max_zec: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !validate_name(&display_name) {
        return Err(Reject::InvalidMetadata);
    }
    if !(MIN_FEE_BPS..=MAX_FEE_BPS).contains(&fee_bps) {
        return Err(Reject::InvalidFee);
    }
    if dev_buy.is_negative()
        || dev_buy > MAX_DEV_BUY
        || (!dev_buy.is_zero() && !admits_token_amount(dev_buy))
    {
        return Err(Reject::InvalidDevBuy);
    }
    let recent = state
        .creator_launches
        .get(&creator)
        .map(|xs| {
            xs.iter()
                .filter(|&&e| state.epoch.saturating_sub(e) < RATE_WINDOW_EPOCHS)
                .count()
        })
        .unwrap_or(0);
    if recent >= RATE_LIMIT {
        return Err(Reject::LaunchRateLimited);
    }

    let asset = zyn_vm::asset_address(ADDRESS_SCOPE_V1, &creator, symbol.as_bytes());
    if state.tokens.contains_key(&asset) || state.curves.contains_key(&asset) {
        return Err(Reject::DuplicateSymbol);
    }
    let dev_cost = if dev_buy.is_positive() {
        let principal =
            principal_between(Fixed::ZERO, dev_buy, true).ok_or(Reject::ArithmeticFailure)?;
        principal
            .add(fee(principal, fee_bps, true).ok_or(Reject::ArithmeticFailure)?)
            .ok_or(Reject::ArithmeticFailure)?
    } else {
        Fixed::ZERO
    };
    let needed = LAUNCH_FEE.add(dev_cost).ok_or(Reject::ArithmeticFailure)?;
    if dev_buy.is_positive() && dev_cost > max_zec {
        return Err(Reject::SlippageExceeded);
    }
    if state.balance(&creator, XZEC) < needed {
        return Err(Reject::InsufficientBalance);
    }

    let vault = launch_vault(&asset);
    let treasury = state.params.treasury;
    state
        .account_mut(&creator)
        .debit(XZEC, LAUNCH_FEE)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&treasury)
        .credit(XZEC, TREASURY_FEE)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .credit(XZEC, PAIR_SEED)
        .ok_or(Reject::ArithmeticFailure)?;
    state.tokens.insert(
        asset,
        TokenInfo {
            symbol,
            supply: TOTAL_SUPPLY,
            lp_of: None,
            genesis_pool: None,
            unit: TOKEN_UNIT,
            bond: Fixed::ZERO,
            vault: None,
            content: None,
            collection: None,
        },
    );
    state
        .account_mut(&vault)
        .credit(asset, TOTAL_SUPPLY)
        .ok_or(Reject::ArithmeticFailure)?;
    state.curves.insert(
        asset,
        CurveLaunch {
            creator,
            symbol,
            display_name,
            metadata_hash,
            fee_bps,
            sold: Fixed::ZERO,
            creator_fees: Fixed::ZERO,
            graduation_fees: Fixed::ZERO,
            graduated_token_liquidity: Fixed::ZERO,
            graduated_zec_liquidity: Fixed::ZERO,
            graduation_overflow: Fixed::ZERO,
            graduated_locked_lp: Fixed::ZERO,
            status: CurveStatus::Trading,
        },
    );
    let now = state.epoch;
    let epochs = state.creator_launches.entry(creator).or_default();
    epochs.retain(|&e| now.saturating_sub(e) < RATE_WINDOW_EPOCHS);
    epochs.push(now);

    let mut out = alloc::vec![Receipt::CurveCreated {
        asset,
        creator,
        symbol,
        supply: TOTAL_SUPPLY,
        fee_bps,
        pair_seed: PAIR_SEED,
    }];
    if dev_buy.is_positive() {
        out.extend(buy(state, creator, asset, dev_buy, max_zec)?);
    }
    Ok(out)
}

pub fn buy(
    state: &mut SwapState,
    buyer: AccountId,
    asset: AssetId,
    amount: Fixed,
    max_zec: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !admits_token_amount(amount) {
        return Err(Reject::Indivisible);
    }
    let c = state.curves.get(&asset).ok_or(Reject::NoSuchCurve)?;
    let quote = quote_buy(c, amount)?;
    let (after, principal, trading_fee, total) = (
        quote.sold_after,
        quote.principal,
        quote.fee,
        quote.settlement,
    );
    if total > max_zec {
        return Err(Reject::SlippageExceeded);
    }
    if state.balance(&buyer, XZEC) < total {
        return Err(Reject::InsufficientBalance);
    }
    settle_buy(state, buyer, asset, amount, principal, trading_fee, after)?;
    let mut out = alloc::vec![Receipt::CurveBought {
        asset,
        buyer,
        tokens: amount,
        principal,
        fee: trading_fee,
        total,
        sold: after,
        price: quote.price_after,
    }];
    if after == CURVE_SUPPLY {
        out.push(graduate(state, asset)?);
    }
    Ok(out)
}

fn settle_buy(
    state: &mut SwapState,
    buyer: AccountId,
    asset: AssetId,
    amount: Fixed,
    principal: Fixed,
    trading_fee: Fixed,
    after: Fixed,
) -> Result<(), Reject> {
    let vault = launch_vault(&asset);
    let to_creator = fee(trading_fee, 1_000, false).ok_or(Reject::ArithmeticFailure)?;
    let to_graduation = fee(trading_fee, 4_000, false).ok_or(Reject::ArithmeticFailure)?;
    let to_pol = trading_fee
        .sub(to_creator)
        .and_then(|v| v.sub(to_graduation))
        .ok_or(Reject::ArithmeticFailure)?;
    let total = principal
        .add(trading_fee)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&buyer)
        .debit(XZEC, total)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .credit(XZEC, total)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .debit(asset, amount)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&buyer)
        .credit(asset, amount)
        .ok_or(Reject::ArithmeticFailure)?;
    if to_pol.is_positive() {
        state
            .account_mut(&vault)
            .debit(XZEC, to_pol)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&ZYN_POL)
            .credit(XZEC, to_pol)
            .ok_or(Reject::ArithmeticFailure)?;
    }
    let c = state
        .curves
        .get_mut(&asset)
        .ok_or(Reject::ArithmeticFailure)?;
    c.sold = after;
    c.creator_fees = c
        .creator_fees
        .add(to_creator)
        .ok_or(Reject::ArithmeticFailure)?;
    c.graduation_fees = c
        .graduation_fees
        .add(to_graduation)
        .ok_or(Reject::ArithmeticFailure)?;
    Ok(())
}

pub fn sell(
    state: &mut SwapState,
    seller: AccountId,
    asset: AssetId,
    amount: Fixed,
    min_zec: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !admits_token_amount(amount) {
        return Err(Reject::Indivisible);
    }
    let c = state.curves.get(&asset).ok_or(Reject::NoSuchCurve)?;
    let quote = quote_sell(c, amount)?;
    if state.balance(&seller, asset) < amount {
        return Err(Reject::InsufficientBalance);
    }
    let (after, principal, trading_fee, received) = (
        quote.sold_after,
        quote.principal,
        quote.fee,
        quote.settlement,
    );
    if received < min_zec {
        return Err(Reject::SlippageExceeded);
    }
    let vault = launch_vault(&asset);
    let to_creator = fee(trading_fee, 1_000, false).ok_or(Reject::ArithmeticFailure)?;
    let to_graduation = fee(trading_fee, 4_000, false).ok_or(Reject::ArithmeticFailure)?;
    let to_pol = trading_fee
        .sub(to_creator)
        .and_then(|v| v.sub(to_graduation))
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&seller)
        .debit(asset, amount)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .credit(asset, amount)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .debit(XZEC, received.add(to_pol).ok_or(Reject::ArithmeticFailure)?)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&seller)
        .credit(XZEC, received)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&ZYN_POL)
        .credit(XZEC, to_pol)
        .ok_or(Reject::ArithmeticFailure)?;
    let c = state
        .curves
        .get_mut(&asset)
        .ok_or(Reject::ArithmeticFailure)?;
    c.sold = after;
    c.creator_fees = c
        .creator_fees
        .add(to_creator)
        .ok_or(Reject::ArithmeticFailure)?;
    c.graduation_fees = c
        .graduation_fees
        .add(to_graduation)
        .ok_or(Reject::ArithmeticFailure)?;
    Ok(alloc::vec![Receipt::CurveSold {
        asset,
        seller,
        tokens: amount,
        principal,
        fee: trading_fee,
        received,
        sold: after,
        price: quote.price_after,
    }])
}

fn graduate(state: &mut SwapState, asset: AssetId) -> Result<Receipt, Reject> {
    let (creator, creator_fees, fee_bps) = {
        let c = state.curves.get(&asset).ok_or(Reject::NoSuchCurve)?;
        (c.creator, c.creator_fees, c.fee_bps)
    };
    let vault = launch_vault(&asset);
    if creator_fees.is_positive() {
        state
            .account_mut(&vault)
            .debit(XZEC, creator_fees)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&creator)
            .credit(XZEC, creator_fees)
            .ok_or(Reject::ArithmeticFailure)?;
    }
    let available = state.balance(&vault, XZEC);
    // Size the token side from the ZEC actually available, then round the
    // token quantity down to its 8-decimal unit and recompute ZEC from that
    // quantity. This preserves the exact terminal `ZEC per token` price; the
    // otherwise-unrepresentable ZEC dust joins ordinary cap overflow in POL.
    let zec_cap = available.min(GRADUATION_POOL_CAP);
    let unrounded_tokens = zec_cap
        .div(GRADUATION_PRICE)
        .ok_or(Reject::ArithmeticFailure)?;
    let token_liquidity = Fixed::raw(unrounded_tokens.0 / TOKEN_UNIT.0 * TOKEN_UNIT.0);
    if !token_liquidity.is_positive() || token_liquidity > POOL_TOKEN_SUPPLY {
        return Err(Reject::InsufficientLiquidityMinted);
    }
    let zec = token_liquidity
        .mul(GRADUATION_PRICE)
        .ok_or(Reject::ArithmeticFailure)?;
    let overflow = available.sub(zec).ok_or(Reject::ArithmeticFailure)?;
    if overflow.is_positive() {
        state
            .account_mut(&vault)
            .debit(XZEC, overflow)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&ZYN_POL)
            .credit(XZEC, overflow)
            .ok_or(Reject::ArithmeticFailure)?;
    }
    let pool_id = zyn_vm::pool_address(ADDRESS_SCOPE_V1, &asset, &XZEC);
    let lp_asset = zyn_vm::lp_address(ADDRESS_SCOPE_V1, &pool_id);
    let (asset0, asset1, amount0, amount1) = if asset < XZEC {
        (asset, XZEC, token_liquidity, zec)
    } else {
        (XZEC, asset, zec, token_liquidity)
    };
    let lp_supply = amm::mint_shares(
        amount0,
        amount1,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .ok_or(Reject::InsufficientLiquidityMinted)?;
    state
        .account_mut(&vault)
        .debit(asset, token_liquidity)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&vault)
        .debit(XZEC, zec)
        .ok_or(Reject::ArithmeticFailure)?;
    state.tokens.insert(
        lp_asset,
        TokenInfo {
            symbol: crate::state::symbol(b"LP"),
            supply: lp_supply,
            lp_of: Some(pool_id),
            genesis_pool: None,
            unit: Fixed::raw(1),
            bond: Fixed::ZERO,
            vault: None,
            content: None,
            collection: None,
        },
    );
    state.pools.insert(
        pool_id,
        Pool {
            asset0,
            asset1,
            vault: zyn_vm::vault_address(ADDRESS_SCOPE_V1, &pool_id),
            reserve0: amount0,
            reserve1: amount1,
            fee_bps,
            lp_asset,
            lp_supply,
            locked: lp_supply,
            min_in0: Fixed::raw(1),
            min_in1: Fixed::raw(1),
            reference: None,
        },
    );
    state
        .tokens
        .get_mut(&asset)
        .ok_or(Reject::ArithmeticFailure)?
        .genesis_pool = Some(pool_id);
    let curve = state
        .curves
        .get_mut(&asset)
        .ok_or(Reject::ArithmeticFailure)?;
    curve.graduated_token_liquidity = token_liquidity;
    curve.graduated_zec_liquidity = zec;
    curve.graduation_overflow = overflow;
    curve.graduated_locked_lp = lp_supply;
    curve.status = CurveStatus::Graduated { pool: pool_id };
    Ok(Receipt::CurveGraduated {
        asset,
        pool: pool_id,
        lp_asset,
        token_liquidity,
        zec_liquidity: zec,
        overflow_to_pol: overflow,
        locked_lp: lp_supply,
    })
}

pub fn graduated_creator(state: &SwapState, pool: PoolId) -> Option<AccountId> {
    state.curves.values().find_map(|c| match c.status {
        CurveStatus::Graduated { pool: p } if p == pool => Some(c.creator),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_hits_the_frozen_endpoints_and_reserve() {
        assert_eq!(marginal_price(Fixed::ZERO), Some(START_PRICE));
        assert_eq!(marginal_price(CURVE_SUPPLY), Some(GRADUATION_PRICE));
        assert_eq!(
            reserve_for(CURVE_SUPPLY),
            Some(Fixed::raw(33_002_970_000_000_000_000))
        );
    }

    #[test]
    fn the_first_atomic_buy_is_not_free_and_the_reverse_rounds_to_the_curve() {
        let mut curve = CurveLaunch {
            creator: [1; 32],
            symbol: crate::state::symbol(b"ATOM"),
            display_name: b"Atomic stone".to_vec(),
            metadata_hash: [2; 32],
            fee_bps: DEFAULT_FEE_BPS,
            sold: Fixed::ZERO,
            creator_fees: Fixed::ZERO,
            graduation_fees: Fixed::ZERO,
            graduated_token_liquidity: Fixed::ZERO,
            graduated_zec_liquidity: Fixed::ZERO,
            graduation_overflow: Fixed::ZERO,
            graduated_locked_lp: Fixed::ZERO,
            status: CurveStatus::Trading,
        };
        let buy = quote_buy(&curve, TOKEN_UNIT).unwrap();
        assert_eq!(buy.principal, Fixed::raw(1));
        assert_eq!(buy.fee, Fixed::raw(1));
        assert_eq!(buy.settlement, Fixed::raw(2));

        curve.sold = TOKEN_UNIT;
        let sell = quote_sell(&curve, TOKEN_UNIT).unwrap();
        assert_eq!(sell.principal, Fixed::ZERO);
        assert_eq!(sell.fee, Fixed::ZERO);
        assert_eq!(sell.settlement, Fixed::ZERO);
    }

    #[test]
    fn every_sampled_interval_rounds_once_and_never_against_the_reserve() {
        let samples = [0_i64, 1, 7, 600_654, 1_000_000, 329_999_999, 659_999_999];
        let widths = [1_i64, 2, 101, 1_000_000];
        for start in samples {
            for width in widths {
                let low = Fixed::raw((start as i128) * TOKEN_UNIT.0);
                let high = Fixed::raw(((start + width) as i128) * TOKEN_UNIT.0);
                if high > CURVE_SUPPLY {
                    continue;
                }
                let buy = principal_between(low, high, true).unwrap();
                let sell = principal_between(low, high, false).unwrap();
                assert!(
                    buy >= sell,
                    "buy {buy} below sell {sell} at {start}+{width}"
                );
                assert!(buy.0 - sell.0 <= 1, "interval rounded more than once");
            }
        }
    }

    #[test]
    fn unicode_display_names_are_valid_but_invisible_text_is_not() {
        assert!(validate_name("翡翠🪨".as_bytes()));
        assert!(validate_name("Dark Jade".as_bytes()));
        assert!(!validate_name(" bad".as_bytes()));
        assert!(!validate_name("abc\u{202e}def".as_bytes()));
    }
}
