//! The state transition function.
//!
//! `apply` is pure with respect to the outside world: the same state plus the
//! same intent yields the same state and the same receipts, on any machine,
//! forever. It reads no clock, allocates no randomness, and performs no I/O.
//!
//! ## Failure discipline
//!
//! Rejections are ordinary. An intent that violates a rule produces a
//! `Receipt::Rejected` and leaves balances untouched, because every handler
//! validates fully before it mutates anything. The sequence number still
//! advances and the intent still folds into the epoch's commitment — a rejected
//! intent is a real event in the chain's history and must be reproducible by
//! anyone replaying it.
//!
//! `Reject::ArithmeticFailure` is the one case that can surface mid-mutation.
//! `apply_batch` runs against a clone and discards it whole if any receipt
//! carries one, so a partially-applied intent never reaches a committed root.
//!
//! ## Why routing lives here
//!
//! A multi-hop swap is one intent, priced and settled inside one transition.
//! The alternative — the control plane splitting a route into per-pool
//! intents — would make an atomic route a hope about sequencing rather than a
//! property of execution, and would let anything interleaved between the hops
//! take the difference.

use alloc::vec;
use alloc::vec::Vec;

use alloc::collections::BTreeMap;
use crate::amm;
use crate::fixed::Fixed;
use crate::merkle::{fold_intent, Hash};
use crate::state::{
    symbol as make_symbol, Binding, Checkpoint, PendingCredit, PendingExit, Phase, Pool, Reference,
    SwapState,
    Symbol, TokenInfo, Order};
use crate::tx::{Hop, Intent, Receipt, Reject, SequencedIntent};
use crate::types::{AccountId, AssetId, CollectionId, OfferId, Params, PoolId, XZEC};

const ARITH: Reject = Reject::ArithmeticFailure;

/// Translate a custody refusal into ZynZap's own rejection alphabet.
///
/// The component states *what* went wrong; naming it in the VM's vocabulary is
/// the application's job, because a receipt is part of ZynZap's interface.
fn bridge_reject(e: zyn_bridge::BridgeError) -> Reject {
    use zyn_bridge::BridgeError as B;
    match e {
        B::NonPositive => Reject::NonPositiveAmount,
        B::AboveCap | B::AboveEpochCap => Reject::AboveVaultCap,
        B::AboveObserved => Reject::AboveObserved,
        B::AttestedShortfall => Reject::AttestedShortfall,
        B::StaleObservation => Reject::StaleObservation,
        B::WrongDestination => Reject::WrongDestination,
        B::RedirectTooSoon => Reject::RedirectTooSoon,
        B::DepositOutOfOrder => Reject::DepositOutOfOrder,
        B::BelowExitMinimum => Reject::BelowExitMinimum,
        B::NothingPending => Reject::InsufficientPending,
        B::NotFinalized => Reject::NotFinalized,
        B::NotTimedOut | B::NoTimeout => Reject::ExitNotTimedOut,
        B::Overflow => Reject::ArithmeticFailure,
    }
}

fn return_rejected(r: Reject) -> Result<Vec<Receipt>, Reject> {
    Err(r)
}

/// Apply one sequenced intent, returning the receipts it produced.
pub fn apply(state: &mut SwapState, si: &SequencedIntent) -> Vec<Receipt> {
    let encoded = crate::wire::encode_intent_bytes(&si.intent);
    apply_committed(state, si, &encoded)
}

/// Apply one sequenced intent and fold the chain's complete committed record.
/// The record includes the authorization evidence; replicas verify it before
/// reaching this function and therefore reproduce both the decision and root.
pub fn apply_committed(
    state: &mut SwapState,
    si: &SequencedIntent,
    committed: &[u8],
) -> Vec<Receipt> {
    // The chain owns a contiguous sequence space. A gap means the caller lost a
    // message, and applying out of order would fork the state root. Nothing
    // advances here: an intent that was never in the history must not appear in
    // the epoch's commitment either.
    if si.seq != state.seq + 1 {
        return vec![Receipt::Rejected { reason: Reject::OutOfOrder }];
    }

    // Record the intent in the chain's history *before* executing it, so the
    // epoch commitment covers what was asked as well as what happened —
    // including the checkpoint intent that seals it.
    state.seq = si.seq;
    state.intent_acc = fold_intent(state.intent_acc, si.seq, committed);
    state.epoch_intents = state.epoch_intents.saturating_add(1);

    let result = match &si.intent {
        Intent::CreditDeposit { account, asset, amount, index, external_ref } => {
            credit_deposit(state, *account, *asset, *amount, *index, *external_ref)
        }
        Intent::Transfer { from, to, asset, amount } => {
            transfer(state, *from, *to, *asset, *amount)
        }
        Intent::AcceptOffer {
            maker,
            taker,
            offer_asset,
            offer_amount,
            want_asset,
            want_amount,
        } => accept_offer(
            state,
            *maker,
            *taker,
            *offer_asset,
            *offer_amount,
            *want_asset,
            *want_amount,
        ),
        Intent::MintItem { creator, symbol, supply, bond, content } => {
            mint_item(state, *creator, *symbol, *supply, *bond, *content)
        }
        Intent::BurnItem { holder, asset } => burn_item(state, *holder, *asset),
        Intent::CreateCollection { creator, symbol, cap, fee_bps } => create_collection(state, *creator, *symbol, *cap, *fee_bps),
        Intent::MintCollectionItem { creator, collection, to, symbol, content } => mint_collection_item(state, *creator, *collection, *to, *symbol, *content),
        Intent::AdvanceCollection { creator, collection, to } => advance_collection(state, *creator, *collection, *to),
        Intent::FundCollection { from, collection, amount } => fund_collection(state, *from, *collection, *amount),
        Intent::RedeemCollectionItem { holder, asset } => redeem_collection_item(state, *holder, *asset),
        Intent::PlaceOffer { maker, offer_asset, offer_amount, want_asset, want_amount, expires_at_epoch } => {
            place_offer(state, *maker, *offer_asset, *offer_amount, *want_asset, *want_amount, *expires_at_epoch)
        }
        Intent::TakeOffer { taker, offer } => take_offer(state, *taker, *offer),
        Intent::CancelOffer { maker, offer } => cancel_offer(state, *maker, *offer),
        Intent::CreateBridgedAsset { symbol, origin } => create_bridged_asset(state, *symbol, *origin),
        Intent::CreateBridgedItem { symbol, origin, content } => create_bridged_item(state, *symbol, *origin, *content),
        Intent::Reblind { account, blind } => reblind(state, *account, *blind),
        Intent::CreateToken {
            creator,
            symbol,
            supply,
            unit,
            xzec_liquidity,
            token_liquidity,
            fee_bps,
        } => launch_token(
            state,
            *creator,
            *symbol,
            *supply,
            *unit,
            *xzec_liquidity,
            *token_liquidity,
            *fee_bps,
        ),
        Intent::CreatePool { creator, asset_a, asset_b, amount_a, amount_b, fee_bps } => {
            create_pool(state, *creator, *asset_a, *asset_b, *amount_a, *amount_b, *fee_bps)
        }
        Intent::AddLiquidity { account, pool, max0, max1, min_shares } => {
            add_liquidity(state, *account, *pool, *max0, *max1, *min_shares)
        }
        Intent::RemoveLiquidity { account, pool, shares, min0, min1 } => {
            remove_liquidity(state, *account, *pool, *shares, *min0, *min1)
        }
        Intent::SwapExactIn { account, asset_in, path, amount_in, min_out } => {
            swap_exact_in(state, *account, *asset_in, path, *amount_in, *min_out)
        }
        Intent::SwapExactOut { account, asset_in, path, amount_out, max_in } => {
            swap_exact_out(state, *account, *asset_in, path, *amount_out, *max_in)
        }
        Intent::RequestWithdrawal { account, asset, amount, destination } => {
            request_withdrawal(state, *account, *asset, *amount, *destination)
        }
        Intent::BindWithdrawal { account, destination } => {
            bind_withdrawal(state, *account, *destination)
        }
        Intent::ConfirmWithdrawal { account, asset, amount } => {
            confirm_withdrawal(state, *account, *asset, *amount)
        }
        Intent::CancelWithdrawal { account, asset } => cancel_withdrawal(state, *account, *asset),
        Intent::AttestVaultBalance { asset, observed } => attest_vault(state, *asset, *observed),
        Intent::ConfirmAnchor { epoch } => confirm_anchor(state, *epoch),
        Intent::Checkpoint => seal_epoch(state),
        Intent::SetClearing { on } => {
            state.batch_clearing = *on;
            Ok(vec![Receipt::ClearingSet { on: *on }])
        }
        Intent::SetLaunch { params } => {
            // The numbers may be corrected until graduation, when they have
            // done something irreversible; after that they are history.
            match (params.validate(), state.launch.as_mut()) {
                (Err(e), _) => Err(e),
                // After graduation the ZYN launch's own numbers are history.
                // The two that govern *future* markets are not: they are
                // parameters, and a new asset class may need a different bar.
                (Ok(()), Some(l)) if l.graduated() => {
                    let mut as_is = *params;
                    as_is.asset_threshold = l.params.asset_threshold;
                    as_is.bootstrap_bps = l.params.bootstrap_bps;
                    if as_is != l.params {
                        return_rejected(Reject::InvalidParams)
                    } else {
                        l.params.asset_threshold = params.asset_threshold;
                        l.params.bootstrap_bps = params.bootstrap_bps;
                        Ok(vec![Receipt::LaunchSet])
                    }
                }
                (Ok(()), Some(l)) => {
                    l.params = *params;
                    crate::launch::undo_partial(state).map(|_| vec![Receipt::LaunchSet])
                }
                (Ok(()), None) => { state.launch = Some(crate::launch::LaunchState::new(*params)); Ok(vec![Receipt::LaunchSet]) }
            }
        }
        Intent::ZcashHeight { height } => crate::launch::observe_height(state, *height),
        Intent::UpdateAssetReference { asset, price } => crate::launch::observe_asset_reference(state, *asset, *price),
        Intent::UpdateReference { pool, price } => update_reference(state, *pool, *price),
        Intent::SetParams { params } => set_params(state, *params),
    };

    // Only the accounts this intent could have emptied are considered, so
    // pruning stays O(1) rather than sweeping every account on the chain.
    for id in accounts_named(&si.intent) {
        if state.accounts.get(&id).map(|a| a.is_empty()).unwrap_or(false) {
            state.accounts.remove(&id);
        }
    }

    match result {
        Ok(receipts) => receipts,
        Err(reason) => vec![Receipt::Rejected { reason }],
    }
}

/// Apply a batch atomically: on any arithmetic failure the whole batch is
/// discarded and the caller's state is left exactly as it was.
///
/// Soft rejections do not abort a batch; only `ArithmeticFailure` does, because
/// that is the one path that can leave a half-applied intent behind.
pub fn apply_batch(
    state: &mut SwapState,
    batch: &[SequencedIntent],
) -> Result<Vec<Receipt>, Reject> {
    let mut scratch = state.clone();
    let mut all = Vec::with_capacity(batch.len());
    for si in batch {
        let receipts = apply(&mut scratch, si);
        if receipts
            .iter()
            .any(|r| matches!(r, Receipt::Rejected { reason: Reject::ArithmeticFailure }))
        {
            return Err(Reject::ArithmeticFailure);
        }
        all.extend(receipts);
    }
    *state = scratch;
    Ok(all)
}

/// The program a zkVM proves.
///
/// A validity proof over the chain asserts exactly this: starting from a state
/// whose root is `expected_base`, applying `batch` in order yields a state whose
/// root is the returned value.
///
/// The base-root check is part of the proven statement on purpose. Without it a
/// proof would attest that *some* state transitioned correctly, leaving the
/// binding to the checkpointed root outside the proof, where a sequencer could
/// substitute a different starting state.
pub fn transition(
    mut state: SwapState,
    expected_base: Hash,
    batch: &[SequencedIntent],
) -> Result<(SwapState, Hash), Reject> {
    if state.state_root() != expected_base {
        return Err(Reject::OutOfOrder);
    }
    apply_batch(&mut state, batch)?;
    let root = state.state_root();
    Ok((state, root))
}

// ---------------------------------------------------------------------------
// Batch clearing
// ---------------------------------------------------------------------------

/// Clear every open order, then seal.
///
/// Orders on one pool clear together at one price. Everything one side sells
/// the other side buys before the curve is touched, and only the residual
/// moves the reserves — so a balanced batch pays the marginal rate, and an
/// unbalanced one pays the curve for its imbalance alone. The receipts come
/// out in order of the orders, ahead of the checkpoint.
fn seal_epoch(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let mut receipts = clear_orders(state)?;
    // The launch's step is all-or-nothing: it runs on a copy and lands only
    // if every part of it succeeded. A failure is reported, never half-kept,
    // and never stops the seal.
    let mut scratch = state.clone();
    match crate::launch::tick(&mut scratch) {
        Ok(r) => { *state = scratch; receipts.extend(r); }
        Err(reason) => receipts.push(Receipt::LaunchSkipped { reason }),
    }
    receipts.push(Receipt::Checkpointed(checkpoint(state)));
    Ok(receipts)
}

/// The two totals a pool sees at the seal, per side, after the fee.
struct Side {
    /// Indices into the order list, in sequence order.
    orders: Vec<usize>,
    /// Sum of inputs before the fee.
    gross: Fixed,
    /// Sum of inputs after the fee — what the curve is asked to price.
    net: Fixed,
    /// Sum of fees, of which a share may go to the treasury.
    fee: Fixed,
}

fn clear_orders(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    if state.orders.is_empty() {
        return Ok(Vec::new());
    }
    let orders = core::mem::take(&mut state.orders);
    // Every order's fate, filled in below; None means still live.
    let mut outcome: Vec<Option<Receipt>> = vec![None; orders.len()];

    // Pools in id order, so the result does not depend on arrival order
    // across pools (within a pool, order does not matter at all).
    let mut pool_ids: Vec<PoolId> = orders.iter().map(|o| o.pool).collect();
    pool_ids.sort_unstable();
    pool_ids.dedup();

    let (seq_now, staleness) = (state.seq, state.params.reference_staleness);
    let share = state.params.protocol_fee_share_bps;
    let treasury = state.params.treasury;

    for pid in pool_ids {
        let Some(pool) = state.pools.get(&pid) else {
            for (i, o) in orders.iter().enumerate() {
                if o.pool == pid { outcome[i] = Some(unfilled(o, Reject::UnknownPool)); }
            }
            continue;
        };
        let (asset0, asset1, fee_bps) = (pool.asset0, pool.asset1, effective_fee(pool, seq_now, staleness));
        let mut live: Vec<usize> = (0..orders.len()).filter(|&i| orders[i].pool == pid).collect();

        // Drop what cannot pay, counting each account's orders together.
        {
            let mut reserved: BTreeMap<(AccountId, AssetId), Fixed> = BTreeMap::new();
            live.retain(|&i| {
                let o = &orders[i];
                let key = (o.account, o.asset_in);
                let so_far = reserved.get(&key).copied().unwrap_or(Fixed::ZERO);
                let need = match so_far.add(o.amount_in) { Some(n) => n, None => { outcome[i] = Some(unfilled(o, Reject::ArithmeticFailure)); return false } };
                if state.balance(&o.account, o.asset_in) < need {
                    outcome[i] = Some(unfilled(o, Reject::InsufficientBalance));
                    return false;
                }
                reserved.insert(key, need);
                true
            });
        }

        // Clear, drop any order whose limit is not met, and clear again
        // without it. Each round removes at least one order, so this ends.
        let fill = loop {
            if live.is_empty() {
                break None;
            }
            let side = |asset: AssetId| -> Result<Side, Reject> {
                let mut s = Side { orders: Vec::new(), gross: Fixed::ZERO, net: Fixed::ZERO, fee: Fixed::ZERO };
                for &i in &live {
                    let o = &orders[i];
                    if o.asset_in != asset { continue }
                    let fee = amm::fee_taken(o.amount_in, fee_bps).ok_or(ARITH)?;
                    s.orders.push(i);
                    s.gross = s.gross.add(o.amount_in).ok_or(ARITH)?;
                    s.net = s.net.add(o.amount_in.sub(fee).ok_or(ARITH)?).ok_or(ARITH)?;
                    s.fee = s.fee.add(fee).ok_or(ARITH)?;
                }
                Ok(s)
            };
            let (s0, s1) = (side(asset0)?, side(asset1)?);
            let pool = state.pools.get(&pid).ok_or(ARITH)?;
            let Some((out1, out0)) = clear_pool(pool.reserve0, pool.reserve1, s0.net, s1.net) else {
                // Nothing prices — refuse the batch rather than guess.
                for &i in &live { outcome[i] = Some(unfilled(&orders[i], Reject::InsufficientReserves)); }
                break None;
            };
            // Pro rata by gross input; the remainder from rounding stays in the pool.
            let mut fills: Vec<(usize, Fixed)> = Vec::with_capacity(live.len());
            let mut dropped = false;
            for (s, total_out) in [(&s0, out1), (&s1, out0)] {
                for &i in &s.orders {
                    let o = &orders[i];
                    let out = if s.gross.is_positive() { total_out.mul_div(o.amount_in, s.gross).ok_or(ARITH)? } else { Fixed::ZERO };
                    if out < o.min_out || !out.is_positive() {
                        outcome[i] = Some(unfilled(o, Reject::SlippageExceeded));
                        dropped = true;
                    } else {
                        fills.push((i, out));
                    }
                }
            }
            if dropped {
                live.retain(|i| outcome[*i].is_none());
                continue;
            }
            break Some((s0, s1, out1, out0, fills));
        };

        let Some((s0, s1, out1, out0, fills)) = fill else { continue };

        // Settle: inputs in (less the protocol's share of the fee), outputs out.
        let cut0 = protocol_cut(s0.fee, share).ok_or(ARITH)?;
        let cut1 = protocol_cut(s1.fee, share).ok_or(ARITH)?;
        if s0.fee.is_positive() { crate::launch::note_pool_fee(state, pid, asset0, s0.fee); }
        if s1.fee.is_positive() { crate::launch::note_pool_fee(state, pid, asset1, s1.fee); }
        {
            let pool = state.pools.get_mut(&pid).ok_or(ARITH)?;
            if s0.gross.is_positive() { pool.credit_reserve(asset0, s0.gross.sub(cut0).ok_or(ARITH)?).ok_or(ARITH)?; }
            if s1.gross.is_positive() { pool.credit_reserve(asset1, s1.gross.sub(cut1).ok_or(ARITH)?).ok_or(ARITH)?; }
            if out1.is_positive() { pool.debit_reserve(asset1, out1).ok_or(ARITH)?; }
            if out0.is_positive() { pool.debit_reserve(asset0, out0).ok_or(ARITH)?; }
        }
        if cut0.is_positive() { state.account_mut(&treasury).credit(asset0, cut0).ok_or(ARITH)?; }
        if cut1.is_positive() { state.account_mut(&treasury).credit(asset1, cut1).ok_or(ARITH)?; }
        // Rounding dust: what was debited from the reserves but not paid out
        // is returned to them, so the reserves and the curve stay honest.
        let mut paid0 = Fixed::ZERO;
        let mut paid1 = Fixed::ZERO;
        for &(i, out) in &fills {
            let o = &orders[i];
            let asset_out = if o.asset_in == asset0 { asset1 } else { asset0 };
            state.account_mut(&o.account).debit(o.asset_in, o.amount_in).ok_or(ARITH)?;
            state.account_mut(&o.account).credit(asset_out, out).ok_or(ARITH)?;
            if asset_out == asset1 { paid1 = paid1.add(out).ok_or(ARITH)?; } else { paid0 = paid0.add(out).ok_or(ARITH)?; }
            let fee = amm::fee_taken(o.amount_in, fee_bps).ok_or(ARITH)?;
            let hop = Hop { pool: pid, asset_in: o.asset_in, asset_out, amount_in: o.amount_in, amount_out: out, fee, protocol_fee: protocol_cut(fee, share).ok_or(ARITH)? };
            state.epoch_gross_volume = state.epoch_gross_volume.add(xzec_leg(core::slice::from_ref(&hop))).ok_or(ARITH)?;
            outcome[i] = Some(Receipt::Swapped { account: o.account, asset_in: o.asset_in, asset_out, amount_in: o.amount_in, amount_out: out, hops: vec![hop] });
        }
        let pool = state.pools.get_mut(&pid).ok_or(ARITH)?;
        let dust1 = out1.sub(paid1).ok_or(ARITH)?;
        let dust0 = out0.sub(paid0).ok_or(ARITH)?;
        if dust1.is_positive() { pool.credit_reserve(asset1, dust1).ok_or(ARITH)?; }
        if dust0.is_positive() { pool.credit_reserve(asset0, dust0).ok_or(ARITH)?; }
    }

    Ok(outcome.into_iter().map(|r| r.expect("every order has an outcome")).collect())
}

fn unfilled(o: &Order, reason: Reject) -> Receipt {
    Receipt::SwapUnfilled { account: o.account, pool: o.pool, asset_in: o.asset_in, amount_in: o.amount_in, reason }
}

/// Clear `u` of asset0 sold and `v` of asset1 sold (both after fees) against
/// reserves `(r0, r1)` at one price. Returns `(out1, out0)`: what the sellers
/// of asset0 receive in total, and what the sellers of asset1 receive.
///
/// The batch auction on a curve: only the imbalance between the two sides
/// crosses the curve, and everything the sides match between themselves
/// clears at that crossing's average price. With `u·r1 ≥ v·r0` the residual
/// is `x = (u·r1 − v·r0) / (r1 + v)` of asset0, which buys `r1·x/(r0 + x)`
/// of asset1 at `p = r1/(r0 + x)`; the asset0 side is paid that plus all of
/// `v`, and the asset1 side is paid the matched `u − x` of asset0 — the same
/// `p` for everyone. The reserves move by exactly the residual, so the
/// invariant is the ordinary curve's. One side empty is the ordinary curve;
/// a balanced batch never touches it and pays the marginal rate.
pub fn clear_pool(r0: Fixed, r1: Fixed, u: Fixed, v: Fixed) -> Option<(Fixed, Fixed)> {
    if !r0.is_positive() || !r1.is_positive() || u.is_negative() || v.is_negative() {
        return None;
    }
    if !u.is_positive() && !v.is_positive() {
        return Some((Fixed::ZERO, Fixed::ZERO));
    }
    // Which side is in surplus, compared without overflow: u·r1 ≥ v·r0.
    if u.mul_div(r1, r0)? >= v {
        let denom = r1.add(v)?;
        let x = u.mul_div(r1, denom)?.sub(v.mul_div(r0, denom)?)?.max(Fixed::ZERO);
        let out_res = if x.is_positive() { r1.mul_div(x, r0.add(x)?)? } else { Fixed::ZERO };
        let out1 = out_res.add(v)?;
        let out0 = u.sub(x)?;
        if out_res >= r1 || out0.is_negative() { return None }
        Some((out1, out0))
    } else {
        let denom = r0.add(u)?;
        let y = v.mul_div(r0, denom)?.sub(u.mul_div(r1, denom)?)?.max(Fixed::ZERO);
        let out_res = if y.is_positive() { r0.mul_div(y, r1.add(y)?)? } else { Fixed::ZERO };
        let out0 = out_res.add(u)?;
        let out1 = v.sub(y)?;
        if out_res >= r0 || out1.is_negative() { return None }
        Some((out1, out0))
    }
}

/// Seal the current epoch and open the next.
///
/// The returned commitment is what the settlement signers sign and what goes
/// into the Zcash checkpoint transaction. It carries the five fields the
/// project plan requires — chain id, epoch, previous root, new root, and the
/// transaction commitment — plus the sequence and intent count that say how
/// much history the roots span.
///
/// The committed `state_root` is the root *before* the epoch advances, so a
/// replayer who stops at `seq` computes exactly the value that was signed. The
/// advance then writes that root into `parent_root`, which is what chains one
/// checkpoint to the next: epoch N commits root A, epoch N+1 declares A as its
/// parent, and a verifier can walk the lineage without trusting the sequencer's
/// account of it.
pub fn checkpoint(state: &mut SwapState) -> Checkpoint {
    let state_root = state.state_root();
    let cp = Checkpoint {
        chain_id: state.chain_id,
        epoch: state.epoch,
        parent_root: state.parent_root,
        state_root,
        intent_root: state.intent_acc,
        seq: state.seq,
        intents: state.epoch_intents,
        gross_volume: state.epoch_gross_volume,
    };

    state.parent_root = state_root;
    state.epoch += 1;
    state.intent_acc = [0u8; 32];
    state.epoch_intents = 0;
    state.epoch_gross_volume = Fixed::ZERO;
    cp
}

/// Accounts an intent could leave empty, so pruning need not sweep the map.
fn accounts_named(i: &Intent) -> Vec<AccountId> {
    match i {
        Intent::MintCollectionItem { creator, to, .. } => alloc::vec![*creator, *to],
        // The escrow can be left empty by the last take or cancel, like any
        // other account this moves value out of.
        Intent::TakeOffer { taker, .. } => alloc::vec![*taker, crate::launch::POT_OFFERS],
        Intent::PlaceOffer { maker: account, .. } | Intent::CancelOffer { maker: account, .. } => {
            alloc::vec![*account, crate::launch::POT_OFFERS]
        }
        Intent::AdvanceCollection { creator: account, .. }
        | Intent::CreateCollection { creator: account, .. }
        | Intent::FundCollection { from: account, .. }
        | Intent::RedeemCollectionItem { holder: account, .. }
        | Intent::CreditDeposit { account, .. }
        | Intent::Reblind { account, .. }
        | Intent::CreateToken { creator: account, .. }
        | Intent::MintItem { creator: account, .. }
        | Intent::BurnItem { holder: account, .. }
        | Intent::CreatePool { creator: account, .. }
        | Intent::AddLiquidity { account, .. }
        | Intent::RemoveLiquidity { account, .. }
        | Intent::SwapExactIn { account, .. }
        | Intent::SwapExactOut { account, .. }
        | Intent::RequestWithdrawal { account, .. }
        | Intent::ConfirmWithdrawal { account, .. }
        | Intent::CancelWithdrawal { account, .. }
        | Intent::BindWithdrawal { account, .. } => vec![*account],
        Intent::Transfer { from, to, .. } => vec![*from, *to],
        Intent::AcceptOffer { maker, taker, .. } => vec![*maker, *taker],
        Intent::Checkpoint
        | Intent::SetParams { .. }
        | Intent::UpdateReference { .. }
        | Intent::ConfirmAnchor { .. }
        | Intent::AttestVaultBalance { .. }
        | Intent::CreateBridgedAsset { .. }
        | Intent::CreateBridgedItem { .. }
        | Intent::SetClearing { .. }
        | Intent::SetLaunch { .. }
        | Intent::ZcashHeight { .. }
        | Intent::UpdateAssetReference { .. } => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Deposits, exits and transfers
// ---------------------------------------------------------------------------

/// Mirror a confirmed Zcash deposit.
///
/// Supply and backing move together and only here, which is what makes
/// `supply == backing` an invariant rather than a hope. There is deliberately
/// no intent that raises one without the other.
fn credit_deposit(
    state: &mut SwapState,
    account: AccountId,
    asset: AssetId,
    amount: Fixed,
    index: u64,
    external_ref: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    if !amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    let mut vault = info.vault.ok_or(Reject::NotBridged)?;
    if !info.admits(amount) {
        return Err(Reject::Indivisible);
    }
    // The custody rules are the component's; what is ZynZap's is moving its own
    // supply and balance in the same step.
    vault.credit(amount, index, state.epoch).map_err(bridge_reject)?;

    let epoch = state.epoch;
    state.mint(asset, amount).ok_or(ARITH)?;
    state.tokens.get_mut(&asset).ok_or(ARITH)?.vault = Some(vault);
    // The bridge fee, if a launch is set: minted and backed like the rest,
    // credited to the pot on the same terms as the depositor's share.
    let (net, fee_to) = match crate::launch::bridge_fee(state, asset, amount) {
        Some((fee, pot)) => (amount.sub(fee).ok_or(ARITH)?, Some((fee, pot))),
        None => (amount, None),
    };
    if let Some((fee, pot)) = fee_to {
        let p = state.account_mut(&pot);
        let credit = p.incoming.get(&asset).copied().unwrap_or(PendingCredit::new(Fixed::ZERO, epoch)).extend(fee, epoch).map_err(bridge_reject)?;
        p.incoming.insert(asset, credit);
        crate::launch::note_fee(state, account, asset, fee);
    }
    // Minted and backed, but not spendable: it waits for the epoch containing
    // it to be anchored under a certificate.
    let a = state.account_mut(&account);
    let credit = a
        .incoming
        .get(&asset)
        .copied()
        .unwrap_or(PendingCredit::new(Fixed::ZERO, epoch))
        .extend(net, epoch)
        .map_err(bridge_reject)?;
    a.incoming.insert(asset, credit);
    Ok(vec![Receipt::DepositCredited {
        account,
        asset,
        amount,
        backing: vault.confirmed,
        index,
        external_ref,
    }])
}

fn transfer(
    state: &mut SwapState,
    from: AccountId,
    to: AccountId,
    asset: AssetId,
    amount: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    // An indivisible asset moves in whole units or not at all.
    if !info.admits(amount) {
        return Err(Reject::Indivisible);
    }
    if state.balance(&from, asset) < amount {
        return Err(Reject::InsufficientBalance);
    }
    // A self-transfer must be a no-op on balances, not a debit followed by a
    // credit against a stale read.
    if from == to {
        return Ok(vec![Receipt::Transferred { from, to, asset, amount }]);
    }
    state.account_mut(&from).debit(asset, amount).ok_or(ARITH)?;
    state.account_mut(&to).credit(asset, amount).ok_or(ARITH)?;
    Ok(vec![Receipt::Transferred { from, to, asset, amount }])
}

/// Commit an asset at a price and leave it resting.
///
/// The asset moves to escrow now. An offer whose asset stays spendable by its
/// maker is an advertisement — a taker could satisfy every check and still find
/// nothing there.
fn place_offer(
    state: &mut SwapState,
    maker: AccountId,
    offer_asset: AssetId,
    offer_amount: Fixed,
    want_asset: AssetId,
    want_amount: Fixed,
    expires_at_epoch: u64,
) -> Result<Vec<Receipt>, Reject> {
    if !offer_amount.is_positive() || !want_amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if offer_asset == want_asset {
        return Err(Reject::DegenerateOffer);
    }
    let offer_info = state.token(offer_asset).ok_or(Reject::UnknownAsset)?;
    if !offer_info.admits(offer_amount) {
        return Err(Reject::Indivisible);
    }
    let want_info = state.token(want_asset).ok_or(Reject::UnknownAsset)?;
    if !want_info.admits(want_amount) {
        return Err(Reject::Indivisible);
    }
    // Refuse now what the take would refuse later: an item priced in anything
    // but xZEC has no fee the chain can compute, and an offer that can never
    // be taken should not be placed.
    collection_fee_of(state, offer_asset, offer_amount, want_asset, want_amount, maker, maker)?;
    if state.balance(&maker, offer_asset) < offer_amount {
        return Err(Reject::InsufficientBalance);
    }
    if state.epoch > expires_at_epoch {
        return Err(Reject::OfferExpired);
    }

    state.account_mut(&maker).debit(offer_asset, offer_amount).ok_or(ARITH)?;
    state.account_mut(&crate::launch::POT_OFFERS).credit(offer_asset, offer_amount).ok_or(ARITH)?;

    let offer = state.next_offer_id;
    state.next_offer_id = offer.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    state.offers.insert(
        offer,
        crate::state::Offer { maker, offer_asset, offer_amount, want_asset, want_amount, expires_at_epoch },
    );
    Ok(alloc::vec![Receipt::OfferPlaced {
        offer,
        maker,
        offer_asset,
        offer_amount,
        want_asset,
        want_amount,
        expires_at_epoch,
    }])
}

/// Take a resting offer at its stated price.
///
/// Signed by the taker alone: the maker agreed when they placed it, and the
/// asset has been out of their hands ever since.
fn take_offer(state: &mut SwapState, taker: AccountId, offer: OfferId) -> Result<Vec<Receipt>, Reject> {
    let o = *state.offers.get(&offer).ok_or(Reject::NoSuchOffer)?;
    if state.epoch > o.expires_at_epoch {
        return Err(Reject::OfferExpired);
    }
    if o.maker == taker {
        return Err(Reject::CannotTakeOwnOffer);
    }

    let fee = collection_fee_of(state, o.offer_asset, o.offer_amount, o.want_asset, o.want_amount, o.maker, taker)?;
    // The taker needs the price and their side of the fee.
    let mut owed = o.want_amount;
    if let Some((_, _, each, payer, _)) = fee {
        if payer == taker {
            owed = owed.add(each).ok_or(ARITH)?;
        }
    }
    if o.want_asset == XZEC {
        if state.balance(&taker, XZEC) < owed {
            return Err(Reject::InsufficientBalance);
        }
    } else {
        if state.balance(&taker, o.want_asset) < o.want_amount {
            return Err(Reject::InsufficientBalance);
        }
        // The maker pays their side out of xZEC they hold, not out of the
        // proceeds, when the proceeds are not xZEC.
        if let Some((_, _, each, payer, _)) = fee {
            if payer == taker && state.balance(&taker, XZEC) < each {
                return Err(Reject::InsufficientBalance);
            }
        }
    }
    if let Some((_, _, each, _, payee)) = fee {
        let held = state.balance(&payee, XZEC);
        let credited = if o.want_asset == XZEC && payee == o.maker { o.want_amount } else { Fixed::ZERO };
        if held.add(credited).ok_or(ARITH)? < each {
            return Err(Reject::InsufficientBalance);
        }
    }

    // Validation complete; both legs now land or the batch is abandoned.
    state.account_mut(&crate::launch::POT_OFFERS).debit(o.offer_asset, o.offer_amount).ok_or(ARITH)?;
    state.account_mut(&taker).credit(o.offer_asset, o.offer_amount).ok_or(ARITH)?;
    state.account_mut(&taker).debit(o.want_asset, o.want_amount).ok_or(ARITH)?;
    state.account_mut(&o.maker).credit(o.want_asset, o.want_amount).ok_or(ARITH)?;
    state.offers.remove(&offer);

    let mut out = alloc::vec![Receipt::OfferTaken {
        offer,
        maker: o.maker,
        taker,
        offer_asset: o.offer_asset,
        offer_amount: o.offer_amount,
        want_asset: o.want_asset,
        want_amount: o.want_amount,
    }];
    if let Some(fee) = fee {
        out.push(charge_collection_fee(state, fee)?);
    }
    Ok(out)
}

/// Withdraw a resting offer and take the asset back.
///
/// Allowed after expiry: expiry stops an offer being taken, not reclaimed.
fn cancel_offer(state: &mut SwapState, maker: AccountId, offer: OfferId) -> Result<Vec<Receipt>, Reject> {
    let o = *state.offers.get(&offer).ok_or(Reject::NoSuchOffer)?;
    if o.maker != maker {
        return Err(Reject::NotTheMaker);
    }
    state.account_mut(&crate::launch::POT_OFFERS).debit(o.offer_asset, o.offer_amount).ok_or(ARITH)?;
    state.account_mut(&maker).credit(o.offer_asset, o.offer_amount).ok_or(ARITH)?;
    state.offers.remove(&offer);
    Ok(alloc::vec![Receipt::OfferCancelled { offer, maker, offer_asset: o.offer_asset, offer_amount: o.offer_amount }])
}

/// What a collection charges on one trade: which collection, its creator, what
/// each side owes, and who the two xZEC sides are.
type CollectionFee = (CollectionId, AccountId, Fixed, AccountId, AccountId);

/// The fee a trade owes, if either leg is a collection item.
///
/// Priced in xZEC, so one leg must be xZEC: an item swapped for a token has no
/// price the chain can read, and a fee it cannot compute is a fee it cannot
/// take. Refusing is the honest answer — the alternative is a free channel
/// around the fee that only the well-informed would find.
///
/// Shared by every path that moves an item between two accounts, so a new one
/// cannot quietly become that free channel.
fn collection_fee_of(
    state: &SwapState,
    offer_asset: AssetId,
    offer_amount: Fixed,
    want_asset: AssetId,
    want_amount: Fixed,
    maker: AccountId,
    taker: AccountId,
) -> Result<Option<CollectionFee>, Reject> {
    let collection = [offer_asset, want_asset]
        .into_iter()
        .find_map(|a| state.token(a).and_then(|t| t.collection));
    let Some(id) = collection else { return Ok(None) };
    let c = state.collections.get(&id).ok_or(Reject::NoSuchCollection)?;
    let (bps, creator) = (c.fee_bps, c.creator);
    let (xzec_amount, xzec_payer, xzec_payee) = if want_asset == XZEC {
        (want_amount, taker, maker)
    } else if offer_asset == XZEC {
        (offer_amount, maker, taker)
    } else {
        return Err(Reject::ItemNeedsAPrice);
    };
    // Each side pays `fee_bps`; the buyer pays it on top and the seller out of
    // the proceeds, so the quoted price is the price.
    let each = Fixed::raw(xzec_amount.0.saturating_mul(i128::from(bps)) / i128::from(amm::BPS));
    Ok((each.is_positive()).then_some((id, creator, each, xzec_payer, xzec_payee)))
}

/// Take it. Both sides pay `each`; half of the total goes to the pool and half
/// to the creator.
fn charge_collection_fee(state: &mut SwapState, fee: CollectionFee) -> Result<Receipt, Reject> {
    let (id, creator, each, payer, payee) = fee;
    state.account_mut(&payer).debit(XZEC, each).ok_or(ARITH)?;
    state.account_mut(&payee).debit(XZEC, each).ok_or(ARITH)?;
    let taken = each.add(each).ok_or(ARITH)?;
    // Half to the holders, half to the creator. The holders' half is not paid
    // to anyone: it goes into the pool, which raises the floor for every
    // outstanding item at once and needs no bookkeeping per holder.
    let to_pool = Fixed::raw(taken.0 / 2);
    let to_creator = taken.sub(to_pool).ok_or(ARITH)?;
    let c = state.collections.get_mut(&id).ok_or(Reject::NoSuchCollection)?;
    c.pool = c.pool.add(to_pool).ok_or(ARITH)?;
    let (pool, redeem_price) = (c.pool, c.redeem_price());
    if to_creator.is_positive() {
        state.account_mut(&creator).credit(XZEC, to_creator).ok_or(ARITH)?;
    }
    Ok(Receipt::CollectionFeeTaken { collection: id, taken, to_pool, to_creator, pool, redeem_price })
}

/// Settle a negotiated trade in one step.
///
/// Both legs are validated before either moves, so a trade either happens whole
/// or does not happen — there is no state in which one side has paid and the
/// other has not.
#[allow(clippy::too_many_arguments)]
fn accept_offer(
    state: &mut SwapState,
    maker: AccountId,
    taker: AccountId,
    offer_asset: AssetId,
    offer_amount: Fixed,
    want_asset: AssetId,
    want_amount: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !offer_amount.is_positive() || !want_amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if maker == taker || offer_asset == want_asset {
        return Err(Reject::DegenerateOffer);
    }
    let offer_info = state.token(offer_asset).ok_or(Reject::UnknownAsset)?;
    if !offer_info.admits(offer_amount) {
        return Err(Reject::Indivisible);
    }
    let want_info = state.token(want_asset).ok_or(Reject::UnknownAsset)?;
    if !want_info.admits(want_amount) {
        return Err(Reject::Indivisible);
    }
    // A collection charges on every trade in it, and the charge is what feeds
    // the floor. Priced in xZEC, so one leg must be xZEC: an item swapped for
    // a token has no price the chain can read, and a fee it cannot compute is
    // a fee it cannot take. Refusing is the honest answer — the alternative is
    // a free channel around the fee that only the well-informed would find.
    let fee = collection_fee_of(state, offer_asset, offer_amount, want_asset, want_amount, maker, taker)?;

    // The buyer needs the price and their side of the fee.
    if let Some((_, _, each, payer, _)) = fee {
        let owed = if payer == taker { want_amount } else { offer_amount }.add(each).ok_or(ARITH)?;
        if state.balance(&payer, XZEC) < owed {
            return Err(Reject::InsufficientBalance);
        }
    }
    if state.balance(&maker, offer_asset) < offer_amount
        || state.balance(&taker, want_asset) < want_amount
    {
        return Err(Reject::InsufficientBalance);
    }

    // Validation complete; both legs now land or the batch is abandoned.
    state.account_mut(&maker).debit(offer_asset, offer_amount).ok_or(ARITH)?;
    state.account_mut(&taker).credit(offer_asset, offer_amount).ok_or(ARITH)?;
    state.account_mut(&taker).debit(want_asset, want_amount).ok_or(ARITH)?;
    state.account_mut(&maker).credit(want_asset, want_amount).ok_or(ARITH)?;

    let mut out = vec![Receipt::OfferAccepted {
        maker,
        taker,
        offer_asset,
        offer_amount,
        want_asset,
        want_amount,
    }];

    if let Some(fee) = fee {
        out.push(charge_collection_fee(state, fee)?);
    }

    Ok(out)
}

/// Report what the vault on the custodying chain holds.
///
/// Reported *before* the deposits it covers are credited, which is also the
/// operational order: see the balance rise, report it, credit against it.
fn attest_vault(
    state: &mut SwapState,
    asset: AssetId,
    observed: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    let epoch = state.epoch;
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    let mut vault = info.vault.ok_or(Reject::NotBridged)?;
    vault.attest(observed, epoch).map_err(bridge_reject)?;
    let headroom = vault.observed_headroom();
    state.tokens.get_mut(&asset).ok_or(ARITH)?.vault = Some(vault);
    Ok(vec![Receipt::VaultAttested { asset, observed, headroom }])
}

/// Record that an epoch reached Zcash under a threshold certificate.
fn confirm_anchor(state: &mut SwapState, epoch: u64) -> Result<Vec<Receipt>, Reject> {
    // Never backwards, never twice, and never an epoch that has not been sealed
    // — a sequencer must not be able to release a deposit it has just
    // fabricated by declaring the epoch it is still writing to be final.
    if state.finalized_epoch > 0 && epoch <= state.finalized_epoch {
        return Err(Reject::InvalidFinality);
    }
    if epoch >= state.epoch {
        return Err(Reject::InvalidFinality);
    }
    state.finalized_epoch = epoch;

    // Release every deposit the anchored epoch covers.
    //
    // Sweeping here rather than making each holder claim is the difference
    // between a deposit that lands and one that lands and then waits to be
    // collected. The cost is a pass over the accounts, paid once per anchor
    // rather than once per action — real work in a guest, and on the metering
    // list for that reason.
    let mut receipts = vec![Receipt::AnchorConfirmed { epoch }];
    let ready: Vec<(AccountId, AssetId, Fixed)> = state
        .accounts
        .iter()
        .flat_map(|(id, a)| {
            a.incoming
                .iter()
                .filter(|(_, c)| c.is_final(epoch))
                .map(|(&asset, c)| (*id, asset, c.amount))
                .collect::<Vec<_>>()
        })
        .collect();
    for (account, asset, amount) in ready {
        let a = state.account_mut(&account);
        a.incoming.remove(&asset);
        a.credit(asset, amount).ok_or(ARITH)?;
        receipts.push(Receipt::DepositClaimed { account, asset, amount });
    }
    Ok(receipts)
}

/// Commit units of a bridged asset to an exit.
///
/// The units leave `balances` but stay counted against supply and backing until
/// the custodying chain confirms. Holding them in a third place is what stops
/// the same units backing a swap and an exit at once, without ever letting the
/// backing identity go momentarily false.
fn request_withdrawal(
    state: &mut SwapState,
    account: AccountId,
    asset: AssetId,
    amount: Fixed,
    destination: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    if !amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    let vault = info.vault.ok_or(Reject::NotBridged)?;
    if !info.admits(amount) {
        return Err(Reject::Indivisible);
    }
    vault.admits_exit(amount).map_err(bridge_reject)?;
    // A bound account pays out where it is bound, and nowhere else.
    if let Some(b) = state.accounts.get(&account).and_then(|a| a.binding) {
        if !b.admits(destination) {
            return Err(Reject::WrongDestination);
        }
    }
    if state.balance(&account, asset) < amount {
        return Err(Reject::InsufficientBalance);
    }
    // The bridge fee comes out of what is asked for: the exit that settles
    // is the amount less the fee, and the fee stays on Zyn in the pot.
    let (net, fee_to) = match crate::launch::bridge_fee(state, asset, amount) {
        Some((fee, pot)) => (amount.sub(fee).ok_or(ARITH)?, Some((fee, pot))),
        None => (amount, None),
    };
    if !net.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let epoch = state.epoch;
    let a = state.account_mut(&account);
    a.debit(asset, amount).ok_or(ARITH)?;
    let exit = a
        .pending
        .get(&asset)
        .copied()
        .unwrap_or(PendingExit::new(Fixed::ZERO, epoch))
        .extend(net, epoch)
        .map_err(bridge_reject)?;
    let pending = exit.amount;
    a.pending.insert(asset, exit);
    if let Some((fee, pot)) = fee_to {
        state.account_mut(&pot).credit(asset, fee).ok_or(ARITH)?;
        crate::launch::note_fee(state, account, asset, fee);
    }
    Ok(vec![Receipt::WithdrawalRequested { account, asset, amount: net, pending, destination }])
}

/// Bind where an account's exits may go, or ask to move that binding.
fn bind_withdrawal(
    state: &mut SwapState,
    account: AccountId,
    destination: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    let (epoch, delay) = (state.epoch, state.params.exit_timeout_epochs);
    let a = state.account_mut(&account);
    let (binding, effective) = match a.binding {
        // Nothing bound yet: an unbound account already pays out wherever a
        // request says, so binding one takes nothing away and waiting would
        // only leave the account unprotected for longer.
        None => (Binding::new(destination), true),
        Some(b) if b.admits(destination) => (Binding { pending: None, ..b }, true),
        Some(b) if b.may_apply(destination, epoch, delay) => (b.apply(destination), true),
        Some(b) => (b.request(destination, epoch), false),
    };
    a.binding = Some(binding);
    Ok(vec![Receipt::WithdrawalBound { account, destination, effective }])
}

/// The custodying chain confirmed the exit: burn the units and release the
/// backing.
///
/// Bounded by what was actually requested, so a settlement signer cannot burn
/// units a user never committed to an exit.
fn confirm_withdrawal(
    state: &mut SwapState,
    account: AccountId,
    asset: AssetId,
    amount: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    let mut vault = info.vault.ok_or(Reject::NotBridged)?;
    let exit = state
        .accounts
        .get(&account)
        .and_then(|a| a.pending.get(&asset))
        .copied()
        .ok_or(Reject::InsufficientPending)?;
    let left = exit.settle(amount).map_err(bridge_reject)?;
    vault.release(amount).map_err(bridge_reject)?;

    state.burn(asset, amount).ok_or(ARITH)?;
    state.tokens.get_mut(&asset).ok_or(ARITH)?.vault = Some(vault);
    let a = state.account_mut(&account);
    a.set_pending(asset, left.amount, left.since);
    Ok(vec![Receipt::WithdrawalConfirmed { account, asset, amount, backing: vault.confirmed }])
}

/// Take back an exit the custodying chain never settled.
///
/// The chain's side of this is safe by construction: the units return to a
/// balance, supply and backing never moved, and a payout confirmed afterwards
/// finds nothing pending and is refused. What it cannot protect is an operator
/// who broadcasts after the deadline — they will have paid out on the far chain
/// with nothing here left to burn. That is why the timeout is a coordination
/// deadline set far beyond any honest settlement, not a user convenience.
fn cancel_withdrawal(
    state: &mut SwapState,
    account: AccountId,
    asset: AssetId,
) -> Result<Vec<Receipt>, Reject> {
    let timeout = state.params.exit_timeout_epochs;
    let exit = state
        .accounts
        .get(&account)
        .and_then(|a| a.pending.get(&asset))
        .copied()
        .ok_or(Reject::InsufficientPending)?;
    let waited = exit.may_cancel(state.epoch, timeout).map_err(bridge_reject)?;
    let amount = exit.amount;

    let a = state.account_mut(&account);
    a.set_pending(asset, Fixed::ZERO, exit.since);
    a.credit(asset, amount).ok_or(ARITH)?;
    Ok(vec![Receipt::WithdrawalCancelled { account, asset, amount, waited }])
}

// ---------------------------------------------------------------------------
// Tokens and pools
// ---------------------------------------------------------------------------

/// Mint an indivisible item against a refundable bond.
/// Fold a holder-chosen secret into the account's published leaf.
fn reblind(state: &mut SwapState, account: AccountId, blind: [u8; 32]) -> Result<Vec<Receipt>, Reject> {
    if blind == [0u8; 32] {
        return Err(Reject::NonPositiveAmount);
    }
    state.account_mut(&account).blind = blind;
    Ok(vec![Receipt::Reblinded { account }])
}

/// Open a collection. The pool starts empty; nothing is backed until it is
/// funded, and `redeem_price` is honestly zero until then.
fn create_collection(
    state: &mut SwapState,
    creator: AccountId,
    symbol: Symbol,
    cap: u32,
    fee_bps: u16,
) -> Result<Vec<Receipt>, Reject> {
    if cap == 0 {
        return Err(Reject::NonPositiveAmount);
    }
    // The same ceiling a pool's fee has, so a collection cannot be created
    // that takes more from a trade than any market on this chain may.
    if fee_bps >= amm::BPS as u16 {
        return Err(Reject::InvalidFee);
    }
    let id = state.next_collection_id;
    state.next_collection_id = id.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    state.collections.insert(
        id,
        crate::state::Collection { creator, symbol, cap, minted: 0, outstanding: 0, pool: Fixed::ZERO, fee_bps, phase: Phase::Depositing },
    );
    Ok(alloc::vec![Receipt::CollectionCreated { collection: id, creator, symbol, cap, fee_bps }])
}

/// Mint one item into a collection.
///
/// No bond: the pool backs it. That is also why the cap matters — an item
/// minted after the pool is full would dilute every holder's claim, so the
/// denominator is fixed before anyone pays in.
fn mint_collection_item(
    state: &mut SwapState,
    by: AccountId,
    collection: CollectionId,
    to: AccountId,
    symbol: Symbol,
    content: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    let c = state.collections.get(&collection).ok_or(Reject::NoSuchCollection)?;
    if c.creator != by {
        return Err(Reject::NotTheCreator);
    }
    if c.phase != Phase::Minting {
        return Err(Reject::WrongCollectionPhase);
    }
    if c.minted >= c.cap {
        return Err(Reject::CollectionFull);
    }
    let asset = state.next_asset_id;
    state.next_asset_id = asset.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    state.tokens.insert(
        asset,
        TokenInfo {
            symbol,
            supply: Fixed::ONE,
            lp_of: None,
            genesis_pool: None,
            unit: Fixed::ONE,
            bond: Fixed::ZERO,
            vault: None,
            content: Some(content),
            collection: Some(collection),
        },
    );
    let a = state.account_mut(&to);
    a.credit(asset, Fixed::ONE).ok_or(ARITH)?;
    let c = state.collections.get_mut(&collection).expect("checked above");
    c.minted += 1;
    c.outstanding += 1;
    let (minted, outstanding) = (c.minted, c.outstanding);
    Ok(alloc::vec![Receipt::CollectionItemMinted { collection, asset, to, minted, outstanding }])
}

/// Move a collection on in its life. Forward only, creator only.
fn advance_collection(
    state: &mut SwapState,
    creator: AccountId,
    collection: CollectionId,
    to: u8,
) -> Result<Vec<Receipt>, Reject> {
    let to = Phase::from_code(to).ok_or(Reject::WrongCollectionPhase)?;
    let c = state.collections.get(&collection).ok_or(Reject::NoSuchCollection)?;
    if c.creator != creator {
        return Err(Reject::NotTheCreator);
    }
    // Exactly one step, and only forwards. Naming the destination is what
    // makes a repeated submission a no-op rather than a skipped phase.
    if c.phase.next() != Some(to) {
        return Err(Reject::WrongCollectionPhase);
    }
    let c = state.collections.get_mut(&collection).expect("checked above");
    c.phase = to;
    let (outstanding, pool, redeem_price) = (c.outstanding, c.pool, c.redeem_price());
    Ok(alloc::vec![Receipt::CollectionPhaseChanged { collection, phase: to.code(), outstanding, pool, redeem_price }])
}

/// Pay xZEC into a collection's pool. The floor rises for everyone at once.
fn fund_collection(
    state: &mut SwapState,
    from: AccountId,
    collection: CollectionId,
    amount: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if !state.collections.contains_key(&collection) {
        return Err(Reject::NoSuchCollection);
    }
    if state.balance(&from, XZEC) < amount {
        return Err(Reject::InsufficientBalance);
    }
    state.account_mut(&from).debit(XZEC, amount).ok_or(ARITH)?;
    let c = state.collections.get_mut(&collection).expect("checked above");
    c.pool = c.pool.add(amount).ok_or(ARITH)?;
    let (pool, redeem_price) = (c.pool, c.redeem_price());
    Ok(alloc::vec![Receipt::CollectionFunded { collection, amount, pool, redeem_price }])
}

/// Destroy one collection item and take its share of the pool.
///
/// Both sides move together — one item out, one item's worth of pool out — so
/// the quotient the next holder faces is the one they faced before. The
/// division's remainder stays behind, which is the only rounding direction
/// that cannot take value out of the collection.
fn redeem_collection_item(
    state: &mut SwapState,
    holder: AccountId,
    asset: AssetId,
) -> Result<Vec<Receipt>, Reject> {
    let info = state.token(asset).ok_or(Reject::UnknownAsset)?;
    let collection = info.collection.ok_or(Reject::NotACollectionItem)?;
    let supply = info.supply;
    if state.balance(&holder, asset) != supply || !supply.is_positive() {
        return Err(Reject::NotTheWholeItem);
    }
    let c = state.collections.get(&collection).ok_or(Reject::NoSuchCollection)?;
    if c.phase != Phase::Live {
        return Err(Reject::WrongCollectionPhase);
    }
    if c.outstanding == 0 {
        return Err(Reject::NotACollectionItem);
    }
    let paid = c.redeem_price();

    // The item goes first: nothing is paid out against an item that still
    // exists, so a failure here can never leave the pool short.
    state.account_mut(&holder).debit(asset, supply).ok_or(ARITH)?;
    state.tokens.remove(&asset);
    let c = state.collections.get_mut(&collection).expect("checked above");
    c.outstanding -= 1;
    c.pool = c.pool.sub(paid).ok_or(ARITH)?;
    let outstanding = c.outstanding;
    if paid.is_positive() {
        state.account_mut(&holder).credit(XZEC, paid).ok_or(ARITH)?;
    }
    Ok(alloc::vec![Receipt::CollectionItemRedeemed { collection, asset, holder, paid, outstanding }])
}

fn mint_item(
    state: &mut SwapState,
    creator: AccountId,
    sym: Symbol,
    supply: Fixed,
    bond: Fixed,
    content: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    if !supply.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if bond < state.params.min_pool_xzec || !bond.is_positive() {
        return Err(Reject::BelowLaunchBond);
    }
    // Whole units only: a supply with a fractional part could never be fully
    // held, so it could never be burned and its bond would be stranded.
    if supply.0 % Fixed::ONE.0 != 0 {
        return Err(Reject::Indivisible);
    }
    if state.balance(&creator, XZEC) < bond {
        return Err(Reject::InsufficientBalance);
    }
    let asset = state.next_asset_id;
    let next = asset.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;

    state.next_asset_id = next;
    state.tokens.insert(
        asset,
        TokenInfo {
            symbol: sym,
            supply,
            lp_of: None,
            genesis_pool: None,
            unit: Fixed::ONE,
            bond,
            vault: None, content: Some(content), collection: None
        },
    );
    let a = state.account_mut(&creator);
    a.debit(XZEC, bond).ok_or(ARITH)?;
    a.credit(asset, supply).ok_or(ARITH)?;

    Ok(vec![Receipt::ItemMinted { asset, creator, symbol: sym, supply, bond }])
}

/// Destroy an item and refund its bond, reclaiming the state it held.
fn burn_item(
    state: &mut SwapState,
    holder: AccountId,
    asset: AssetId,
) -> Result<Vec<Receipt>, Reject> {
    let info = *state.token(asset).ok_or(Reject::UnknownAsset)?;
    if info.is_divisible() || info.lp_of.is_some() {
        return Err(Reject::Indivisible);
    }
    // Only the sole holder may end it. Anything less and burning would destroy
    // somebody else's balance.
    if state.balance(&holder, asset) != info.supply {
        return Err(Reject::NotSoleHolder);
    }

    let a = state.account_mut(&holder);
    a.debit(asset, info.supply).ok_or(ARITH)?;
    a.credit(XZEC, info.bond).ok_or(ARITH)?;
    // The token entry goes with it: this is the one operation that shrinks the
    // state, which is what makes the bond a deposit rather than a fee.
    state.tokens.remove(&asset);

    Ok(vec![Receipt::ItemBurned {
        asset,
        holder,
        supply: info.supply,
        refunded: info.bond,
    }])
}

/// Shares permanently locked when a pool opens.
///
/// For a pool holding xZEC, the lock is the fraction of the pool that
/// `min_pool_xzec` represents — so a fixed amount of *real* liquidity becomes
/// unrecoverable, whatever size the pool is opened at. Seeding a huge pool does
/// not dilute the bond away, and seeding a tiny one is refused before it gets
/// here.
///
/// For a pool between two user tokens there is no xZEC side to measure, and
/// both assets already paid a bond when they launched, so the lock falls back
/// to the dust minimum that exists to stop the first-LP inflation attack.
///
/// Never below that dust minimum either way: the two mechanisms are
/// independent, and the bond must not be able to switch the older one off.
fn locked_shares(
    total_shares: Fixed,
    xzec_side: Option<Fixed>,
    params: &Params,
) -> Result<Fixed, Reject> {
    let floor = params.min_liquidity;
    let Some(xzec) = xzec_side else {
        return Ok(floor);
    };
    if !params.min_pool_xzec.is_positive() {
        return Ok(floor);
    }
    let bonded = total_shares
        .mul_div(params.min_pool_xzec, xzec)
        .ok_or(ARITH)?;
    Ok(bonded.max(floor))
}

/// Launch a token: mint it and open its xZEC market in one step.
/// A bridged asset: a token whose units are issued only against deposits to
/// a vault on `origin`. One per (symbol, origin); a second request is refused
/// rather than duplicated, because two vaults for one asset would double it.
fn create_bridged_asset(
    state: &mut SwapState,
    symbol: crate::state::Symbol,
    origin: crate::types::ChainOrigin,
) -> Result<Vec<Receipt>, Reject> {
    if state.tokens.values().any(|t| t.symbol == symbol) {
        return Err(Reject::DuplicateSymbol);
    }
    let asset = state.next_asset_id;
    state.next_asset_id = state.next_asset_id.checked_add(1).ok_or(ARITH)?;
    state.tokens.insert(asset, crate::state::TokenInfo::bridged(symbol, origin));
    Ok(vec![Receipt::BridgedAssetCreated { asset, symbol, origin }])
}

#[allow(clippy::too_many_arguments)]
/// A mirrored item: whole units only, one vault, identified on its origin
/// chain by `content`. One per content — two mirrors of one token would be
/// two claims on one thing.
fn create_bridged_item(
    state: &mut SwapState,
    symbol: crate::state::Symbol,
    origin: crate::types::ChainOrigin,
    content: [u8; 32],
) -> Result<Vec<Receipt>, Reject> {
    if state.tokens.values().any(|t| t.symbol == symbol || t.content == Some(content)) {
        return Err(Reject::DuplicateSymbol);
    }
    let asset = state.next_asset_id;
    state.next_asset_id = state.next_asset_id.checked_add(1).ok_or(ARITH)?;
    let mut info = crate::state::TokenInfo::bridged(symbol, origin);
    info.unit = Fixed::ONE;
    info.content = Some(content);
    state.tokens.insert(asset, info);
    Ok(vec![Receipt::BridgedAssetCreated { asset, symbol, origin }])
}

#[allow(clippy::too_many_arguments)]
fn launch_token(
    state: &mut SwapState,
    creator: AccountId,
    sym: Symbol,
    supply: Fixed,
    unit: Fixed,
    xzec_liquidity: Fixed,
    token_liquidity: Fixed,
    fee_bps: u16,
) -> Result<Vec<Receipt>, Reject> {
    if !supply.is_positive() || !token_liquidity.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if !unit.is_positive() {
        return Err(Reject::Indivisible);
    }
    if fee_bps >= amm::BPS as u16 {
        return Err(Reject::InvalidFee);
    }
    if token_liquidity > supply {
        return Err(Reject::InsufficientBalance);
    }
    // Strictly above the bond: seeding exactly the bond would lock the entire
    // pool and leave the creator no position at all.
    if xzec_liquidity <= state.params.min_pool_xzec {
        return Err(Reject::BelowLaunchBond);
    }
    if state.balance(&creator, XZEC) < xzec_liquidity {
        return Err(Reject::InsufficientBalance);
    }

    let info =
        TokenInfo {
            symbol: sym,
            supply,
            lp_of: None,
            genesis_pool: None,
            unit,
            bond: Fixed::ZERO,
            vault: None,
            content: None, collection: None,
        };
    if !info.admits(supply) || !info.admits(token_liquidity) {
        return Err(Reject::Indivisible);
    }
    // An AMM cannot price an indivisible asset, and a launch is a pool.
    if !info.is_divisible() {
        return Err(Reject::Indivisible);
    }

    // Reserve every id before committing anything, so a rejected launch leaves
    // no counter advanced.
    let asset = state.next_asset_id;
    let pool_id = state.next_pool_id;
    let lp_asset = asset.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    let next_asset_id = lp_asset.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    let next_pool_id = pool_id.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;

    // Canonical orientation: xZEC is asset 1, so it is always side 0 here.
    let (asset0, asset1, amount0, amount1) = if XZEC < asset {
        (XZEC, asset, xzec_liquidity, token_liquidity)
    } else {
        (asset, XZEC, token_liquidity, xzec_liquidity)
    };
    let total_shares = amm::mint_shares(
        amount0,
        amount1,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .ok_or(Reject::InsufficientLiquidityMinted)?;
    let locked = locked_shares(total_shares, Some(xzec_liquidity), &state.params)?;
    let creator_shares = total_shares.sub(locked).ok_or(ARITH)?;
    if !creator_shares.is_positive() {
        return Err(Reject::BelowLaunchBond);
    }

    // Validation complete.
    state.next_asset_id = next_asset_id;
    state.next_pool_id = next_pool_id;
    // The launch pool is the token's canonical market, fixed for its lifetime.
    state.tokens.insert(asset, TokenInfo { genesis_pool: Some(pool_id), ..info });
    state.tokens.insert(
        lp_asset,
        TokenInfo {
            symbol: lp_symbol(pool_id),
            supply: total_shares,
            lp_of: Some(pool_id),
            genesis_pool: None,
            unit: Fixed::raw(1),
            bond: Fixed::ZERO,
            vault: None,
            content: None, collection: None,
        },
    );
    state.pools.insert(
        pool_id,
        Pool {
            asset0,
            asset1,
            reserve0: amount0,
            reserve1: amount1,
            fee_bps,
            lp_asset,
            lp_supply: total_shares,
            locked,
            min_in0: Fixed::raw(1),
            min_in1: Fixed::raw(1),
                reference: None,
        },
    );

    let a = state.account_mut(&creator);
    // The creator keeps whatever supply was not seeded.
    a.credit(asset, supply.sub(token_liquidity).ok_or(ARITH)?).ok_or(ARITH)?;
    a.debit(XZEC, xzec_liquidity).ok_or(ARITH)?;
    a.credit(lp_asset, creator_shares).ok_or(ARITH)?;

    Ok(vec![
        Receipt::TokenCreated { asset, creator, symbol: sym, supply, unit },
        Receipt::PoolCreated { pool: pool_id, asset0, asset1, lp_asset, fee_bps },
        Receipt::LiquidityAdded {
            account: creator,
            pool: pool_id,
            amount0,
            amount1,
            shares: creator_shares,
        },
    ])
}

/// The symbol an LP asset is created with. Purely cosmetic — the binding that
/// matters is `TokenInfo::lp_of`, which the state root commits to.
fn lp_symbol(pool: PoolId) -> Symbol {
    let mut out = make_symbol(b"LP-");
    // Pool id in decimal, right-padded, truncated at 8 bytes like any symbol.
    let mut digits = [0u8; 5];
    let mut n = pool;
    let mut len = 0;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    }
    while n > 0 && len < 5 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in 0..len {
        out[3 + i] = digits[len - 1 - i];
    }
    out
}

/// Create a pool over a pair and seed it in the same step.
///
/// An empty pool is not a tradeable object, so one never exists between two
/// intents: every pool in `state.pools` prices something, and no swap path has
/// to handle the alternative.
#[allow(clippy::too_many_arguments)]
/// Pool creation on behalf of a pot. The same rules as a user's, except the
/// launch bond: the genesis pot *is* the bond, whatever its size.
pub(crate) fn create_pool_for(state: &mut SwapState, creator: AccountId, a: AssetId, b: AssetId, amount_a: Fixed, amount_b: Fixed, fee_bps: u16) -> Result<Vec<Receipt>, Reject> {
    let bond = state.params.min_pool_xzec;
    state.params.min_pool_xzec = Fixed::ZERO;
    // `params` is in the header leaf; it is restored before anything can
    // observe it, so the root is unaffected.
    let r = create_pool(state, creator, a, b, amount_a, amount_b, fee_bps);
    state.params.min_pool_xzec = bond;
    r
}

pub(crate) fn add_liquidity_for(state: &mut SwapState, account: AccountId, pool: PoolId, max0: Fixed, max1: Fixed, min_shares: Fixed) -> Result<Vec<Receipt>, Reject> {
    add_liquidity(state, account, pool, max0, max1, min_shares)
}

fn create_pool(
    state: &mut SwapState,
    creator: AccountId,
    asset_a: AssetId,
    asset_b: AssetId,
    amount_a: Fixed,
    amount_b: Fixed,
    fee_bps: u16,
) -> Result<Vec<Receipt>, Reject> {
    if asset_a == asset_b {
        return Err(Reject::DegeneratePair);
    }
    if fee_bps >= amm::BPS as u16 {
        return Err(Reject::InvalidFee);
    }
    if !amount_a.is_positive() || !amount_b.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let (info_a, info_b) = (
        state.token(asset_a).ok_or(Reject::UnknownAsset)?,
        state.token(asset_b).ok_or(Reject::UnknownAsset)?,
    );
    // A curve produces whatever quantity the reserves imply, which will not
    // land on a whole unit. Refusing the pair here is more honest than pricing
    // an indivisible asset and then rounding the answer into something the
    // asset cannot represent — an NFT market is a different market structure,
    // and on Zyn it belongs in a different VM.
    if !info_a.is_divisible() || !info_b.is_divisible() {
        return Err(Reject::Indivisible);
    }
    if state.find_pool(asset_a, asset_b).is_some() {
        return Err(Reject::PoolExists);
    }

    // Canonical orientation. Amounts follow their asset, not their position in
    // the intent.
    let (asset0, asset1, amount0, amount1) = if asset_a < asset_b {
        (asset_a, asset_b, amount_a, amount_b)
    } else {
        (asset_b, asset_a, amount_b, amount_a)
    };

    if state.balance(&creator, asset0) < amount0 || state.balance(&creator, asset1) < amount1 {
        return Err(Reject::InsufficientBalance);
    }

    // A pool against xZEC posts the same bond a launch does — otherwise a
    // second xZEC market for an existing token would be a way to add state
    // without paying for it. A pool between two user tokens posts none: both
    // sides already paid at launch, so the bond is covered transitively.
    let xzec_side = if asset0 == XZEC {
        Some(amount0)
    } else if asset1 == XZEC {
        Some(amount1)
    } else {
        None
    };
    if let Some(x) = xzec_side {
        if x <= state.params.min_pool_xzec {
            return Err(Reject::BelowLaunchBond);
        }
    }

    let lp_supply = amm::mint_shares(
        amount0,
        amount1,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
        Fixed::ZERO,
    )
    .ok_or(Reject::InsufficientLiquidityMinted)?;
    let locked = locked_shares(lp_supply, xzec_side, &state.params)?;
    let shares = lp_supply.sub(locked).ok_or(ARITH)?;
    if !shares.is_positive() {
        return Err(Reject::BelowLaunchBond);
    }

    // Reserve both ids without committing either. Taking one and then failing
    // to take the other would advance a counter inside a rejected intent, and a
    // rejected intent must leave state exactly as it found it.
    let pool_id = state.next_pool_id;
    let next_pool_id = pool_id.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;
    let lp_asset = state.next_asset_id;
    let next_asset_id = lp_asset.checked_add(1).ok_or(Reject::IdSpaceExhausted)?;

    // Validation is complete; from here every step must succeed or the batch is
    // abandoned wholesale.
    state.next_pool_id = next_pool_id;
    state.next_asset_id = next_asset_id;
    let a = state.account_mut(&creator);
    a.debit(asset0, amount0).ok_or(ARITH)?;
    a.debit(asset1, amount1).ok_or(ARITH)?;
    a.credit(lp_asset, shares).ok_or(ARITH)?;

    state.tokens.insert(
        lp_asset,
        TokenInfo {
            symbol: lp_symbol(pool_id),
            supply: lp_supply,
            lp_of: Some(pool_id),
            genesis_pool: None,
            unit: Fixed::raw(1),
            bond: Fixed::ZERO,
            vault: None,
            content: None, collection: None,
        },
    );
    state.pools.insert(
        pool_id,
        Pool {
            asset0,
            asset1,
            reserve0: amount0,
            reserve1: amount1,
            fee_bps,
            lp_asset,
            lp_supply,
            locked,
            min_in0: Fixed::raw(1),
            min_in1: Fixed::raw(1),
                reference: None,
        },
    );

    Ok(vec![
        Receipt::PoolCreated { pool: pool_id, asset0, asset1, lp_asset, fee_bps },
        Receipt::LiquidityAdded { account: creator, pool: pool_id, amount0, amount1, shares },
    ])
}

/// Deposit at the current ratio.
///
/// The caller supplies ceilings and the VM takes the balanced pair inside them,
/// so a deposit that races a swap tops out instead of reverting. Both the
/// implied counter-amount and the shares minted round **down**, which leaves any
/// rounding dust in the pool rather than in the depositor's shares.
fn add_liquidity(
    state: &mut SwapState,
    account: AccountId,
    pool_id: PoolId,
    max0: Fixed,
    max1: Fixed,
    min_shares: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !max0.is_positive() || !max1.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let p = *state.pools.get(&pool_id).ok_or(Reject::UnknownPool)?;
    if !p.reserve0.is_positive() || !p.reserve1.is_positive() {
        return Err(Reject::InsufficientReserves);
    }

    // Quote max0 against the pool's ratio; if that needs more of asset1 than
    // offered, the other side binds instead.
    let need1 = max0.mul_div(p.reserve1, p.reserve0).ok_or(ARITH)?;
    let (amount0, amount1) = if need1 <= max1 {
        (max0, need1)
    } else {
        (max1.mul_div(p.reserve0, p.reserve1).ok_or(ARITH)?, max1)
    };
    if !amount0.is_positive() || !amount1.is_positive() {
        return Err(Reject::InsufficientLiquidityMinted);
    }

    let shares = amm::mint_shares(
        amount0,
        amount1,
        p.reserve0,
        p.reserve1,
        p.lp_supply,
        state.params.min_liquidity,
    )
    .ok_or(Reject::InsufficientLiquidityMinted)?;
    if !shares.is_positive() {
        return Err(Reject::InsufficientLiquidityMinted);
    }
    if shares < min_shares {
        return Err(Reject::SlippageExceeded);
    }
    if state.balance(&account, p.asset0) < amount0 || state.balance(&account, p.asset1) < amount1 {
        return Err(Reject::InsufficientBalance);
    }

    let a = state.account_mut(&account);
    a.debit(p.asset0, amount0).ok_or(ARITH)?;
    a.debit(p.asset1, amount1).ok_or(ARITH)?;
    a.credit(p.lp_asset, shares).ok_or(ARITH)?;

    let pool = state.pools.get_mut(&pool_id).ok_or(ARITH)?;
    pool.reserve0 = pool.reserve0.add(amount0).ok_or(ARITH)?;
    pool.reserve1 = pool.reserve1.add(amount1).ok_or(ARITH)?;
    pool.lp_supply = pool.lp_supply.add(shares).ok_or(ARITH)?;
    state.mint(p.lp_asset, shares).ok_or(ARITH)?;

    Ok(vec![Receipt::LiquidityAdded { account, pool: pool_id, amount0, amount1, shares }])
}

/// Burn shares back to the underlying pair.
///
/// The locked minimum is held by no account, so it can never be presented here:
/// a pool always keeps shares outstanding and therefore always keeps reserves,
/// which is what stops the first-LP inflation attack on every deposit after the
/// first.
fn remove_liquidity(
    state: &mut SwapState,
    account: AccountId,
    pool_id: PoolId,
    shares: Fixed,
    min0: Fixed,
    min1: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !shares.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let p = *state.pools.get(&pool_id).ok_or(Reject::UnknownPool)?;
    if state.balance(&account, p.lp_asset) < shares {
        return Err(Reject::InsufficientBalance);
    }

    let amount0 = amm::burn_shares(shares, p.reserve0, p.lp_supply)
        .ok_or(Reject::InsufficientLiquidityBurned)?;
    let amount1 = amm::burn_shares(shares, p.reserve1, p.lp_supply)
        .ok_or(Reject::InsufficientLiquidityBurned)?;
    if !amount0.is_positive() || !amount1.is_positive() {
        return Err(Reject::InsufficientLiquidityBurned);
    }
    if amount0 < min0 || amount1 < min1 {
        return Err(Reject::SlippageExceeded);
    }

    let a = state.account_mut(&account);
    a.debit(p.lp_asset, shares).ok_or(ARITH)?;
    a.credit(p.asset0, amount0).ok_or(ARITH)?;
    a.credit(p.asset1, amount1).ok_or(ARITH)?;

    let pool = state.pools.get_mut(&pool_id).ok_or(ARITH)?;
    pool.debit_reserve(p.asset0, amount0).ok_or(ARITH)?;
    pool.debit_reserve(p.asset1, amount1).ok_or(ARITH)?;
    pool.lp_supply = pool.lp_supply.sub(shares).ok_or(ARITH)?;
    if pool.lp_supply < pool.locked {
        // Unreachable while `locked` is held by nobody, but the check is cheap
        // and the alternative is a pool whose locked shares were spent.
        return Err(ARITH);
    }
    state.burn(p.lp_asset, shares).ok_or(ARITH)?;

    Ok(vec![Receipt::LiquidityRemoved { account, pool: pool_id, amount0, amount1, shares }])
}

// ---------------------------------------------------------------------------
// Swaps and routing
// ---------------------------------------------------------------------------

/// Resolve a path of pool ids into the asset it visits at each step.
///
/// Rejects an empty path, one longer than `max_hops`, one that revisits a pool,
/// one naming a pool that does not exist, and one where consecutive pools do
/// not share an asset. Everything about a route is checked before any reserve
/// moves.
///
/// The repeat check matters beyond tidiness: a path visiting the same pool
/// twice would be priced against reserves the earlier hop had already moved,
/// so the quote in the receipt would not be the trade that happened.
fn resolve_path(
    state: &SwapState,
    asset_in: AssetId,
    path: &[PoolId],
) -> Result<Vec<AssetId>, Reject> {
    if path.is_empty() || path.len() > state.params.max_hops as usize {
        return Err(Reject::InvalidPath);
    }
    for (i, p) in path.iter().enumerate() {
        if path[..i].contains(p) {
            return Err(Reject::InvalidPath);
        }
    }
    if state.token(asset_in).is_none() {
        return Err(Reject::UnknownAsset);
    }

    let mut assets = Vec::with_capacity(path.len() + 1);
    assets.push(asset_in);
    let mut current = asset_in;
    for id in path {
        let pool = state.pools.get(id).ok_or(Reject::UnknownPool)?;
        current = pool.other(current).ok_or(Reject::InvalidPath)?;
        assets.push(current);
    }
    Ok(assets)
}

/// The treasury's slice of one hop's fee.
///
/// A share of the fee the pool already withheld, never an extra charge on the
/// trader: the quote is computed before this is known and is unaffected by it.
/// Rounds **down**, so the rounding unit stays with the LPs rather than with
/// the protocol — the protocol is the one party here that can change the rate.
fn protocol_cut(fee: Fixed, share_bps: u16) -> Option<Fixed> {
    if share_bps == 0 || !fee.is_positive() {
        return Some(Fixed::ZERO);
    }
    fee.mul_div(
        Fixed::whole(share_bps as i64),
        Fixed::whole(amm::BPS as i64),
    )
}

/// Commit a priced route to state: move the payer's balances, each pool's
/// reserves, and the treasury's share of the fees. Every hop was priced against
/// reserves this function then updates, which is sound only because
/// `resolve_path` refuses a repeated pool.
///
/// The protocol's cut is deducted from what the pool receives, not from what
/// the trader pays. The pool therefore retains `amount_in - cut`, which is
/// still at least the `in_after_fee` the curve was priced from — so `k` remains
/// non-decreasing for any share below 100%, and the trader's output is
/// identical whether the rail is on or off.
fn settle_route(
    state: &mut SwapState,
    account: AccountId,
    hops: &[Hop],
) -> Result<(), Reject> {
    let first = hops.first().ok_or(ARITH)?;
    let last = hops.last().ok_or(ARITH)?;
    let treasury = state.params.treasury;

    state
        .account_mut(&account)
        .debit(first.asset_in, first.amount_in)
        .ok_or(ARITH)?;
    for h in hops {
        crate::launch::note_pool_fee(state, h.pool, h.asset_in, h.fee);
        let to_pool = h.amount_in.sub(h.protocol_fee).ok_or(ARITH)?;
        let pool = state.pools.get_mut(&h.pool).ok_or(ARITH)?;
        pool.credit_reserve(h.asset_in, to_pool).ok_or(ARITH)?;
        pool.debit_reserve(h.asset_out, h.amount_out).ok_or(ARITH)?;
        if h.protocol_fee.is_positive() {
            state
                .account_mut(&treasury)
                .credit(h.asset_in, h.protocol_fee)
                .ok_or(ARITH)?;
        }
    }
    state
        .account_mut(&account)
        .credit(last.asset_out, last.amount_out)
        .ok_or(ARITH)?;
    Ok(())
}

/// xZEC-denominated volume for a route, or zero if it never touched xZEC.
///
/// Summing raw input amounts across assets would add CAT to DOG and call the
/// result volume. Measuring the xZEC leg gives a figure in one unit that means
/// something — and since V1 routes through xZEC, it covers nearly every trade.
fn xzec_leg(hops: &[Hop]) -> Fixed {
    for h in hops {
        if h.asset_in == XZEC {
            return h.amount_in;
        }
        if h.asset_out == XZEC {
            return h.amount_out;
        }
    }
    Fixed::ZERO
}

/// Price a route hop by hop, moving nothing.
///
/// Extracted so that [`quote`] and `swap_exact_in` cannot compute different
/// numbers for the same route. A quote that disagrees with execution is worse
/// than no quote: it does not fail, it misleads, and the user finds out after
/// signing. There is one implementation and both callers use it.
///
/// Prices the whole route before anything moves, so a hop that cannot be priced
/// rejects the intent whole rather than leaving a partial route behind.
fn price_hops(
    state: &SwapState,
    assets: &[AssetId],
    path: &[PoolId],
    amount_in: Fixed,
) -> Result<Vec<Hop>, Reject> {
    let share = state.params.protocol_fee_share_bps;
    let (seq_now, staleness) = (state.seq, state.params.reference_staleness);

    let mut hops = Vec::with_capacity(path.len());
    let mut carried = amount_in;
    for (i, id) in path.iter().enumerate() {
        let pool = state.pools.get(id).ok_or(Reject::UnknownPool)?;
        if carried < pool.min_in(assets[i]).ok_or(Reject::InvalidPath)? {
            return Err(Reject::BelowMinimumTrade);
        }
        let (r_in, r_out) = pool.oriented(assets[i]).ok_or(Reject::InvalidPath)?;
        let fee_bps = effective_fee(pool, seq_now, staleness);
        let out = amm::out_given_in(carried, r_in, r_out, fee_bps)
            .ok_or(Reject::InsufficientReserves)?;
        if !out.is_positive() || out >= r_out {
            return Err(Reject::InsufficientReserves);
        }
        let fee = amm::fee_taken(carried, fee_bps).ok_or(ARITH)?;
        hops.push(Hop {
            pool: *id,
            asset_in: assets[i],
            asset_out: assets[i + 1],
            amount_in: carried,
            amount_out: out,
            fee,
            protocol_fee: protocol_cut(fee, share).ok_or(ARITH)?,
        });
        carried = out;
    }
    Ok(hops)
}

/// What a route would pay out, without applying it.
///
/// Read-only and non-binding: a quote is not an intent, and the price it
/// reports holds only until the next intent touches one of these pools. It
/// exists so an interface can show a number and a price impact before asking
/// someone to sign, rather than making them submit a swap to find out.
///
/// It deliberately takes no account and checks no balance. Whether the caller
/// can afford the trade is a separate question from what the trade costs, and
/// conflating them would make quoting require an identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Quote {
    /// What this route pays out if it executes alone, against these reserves.
    pub amount_out: Fixed,
    /// The most this route could pay out: the marginal price, with no slippage
    /// at all.
    ///
    /// Unreachable under sequential execution — trading always moves the price
    /// against you — but it is exactly what a **batch** pays when the other
    /// side of the batch absorbs your flow and the pool never sees a residual.
    ///
    /// So the honest quote for a batch-cleared venue is a range, not a number:
    /// somewhere between [`amount_out`] and this, with the caller's `min_out`
    /// as a floor. And the floor is a *hard* one — an unmet limit means no
    /// fill, not a fill at a worse price, which is more than a sequential AMM
    /// can promise when a sandwich can push you to exactly your limit.
    pub best_case: Fixed,
    pub asset_out: AssetId,
    /// Per-hop detail, so an interface can show where a route loses value.
    pub hops: Vec<Hop>,
}

pub fn quote(
    state: &SwapState,
    asset_in: AssetId,
    path: &[PoolId],
    amount_in: Fixed,
) -> Result<Quote, Reject> {
    if !amount_in.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let assets = resolve_path(state, asset_in, path)?;
    let hops = price_hops(state, &assets, path, amount_in)?;
    Ok(Quote {
        amount_out: hops.last().map(|h| h.amount_out).unwrap_or(amount_in),
        best_case: best_case(state, &assets, path, amount_in)?,
        asset_out: *assets.last().ok_or(ARITH)?,
        hops,
    })
}

/// The route priced at the marginal rate, hop by hop, with fees but no
/// slippage.
///
/// Fees are still charged — netting removes price impact, not the cost of using
/// the pool — so this is the ceiling a perfectly balanced batch reaches and not
/// a fantasy number.
fn best_case(
    state: &SwapState,
    assets: &[AssetId],
    path: &[PoolId],
    amount_in: Fixed,
) -> Result<Fixed, Reject> {
    let (seq_now, staleness) = (state.seq, state.params.reference_staleness);
    let mut carried = amount_in;
    for (i, id) in path.iter().enumerate() {
        let pool = state.pools.get(id).ok_or(Reject::UnknownPool)?;
        let (r_in, r_out) = pool.oriented(assets[i]).ok_or(Reject::InvalidPath)?;
        let fee_bps = effective_fee(pool, seq_now, staleness);
        let kept = carried.sub(amm::fee_taken(carried, fee_bps).ok_or(ARITH)?).ok_or(ARITH)?;
        // Marginal rate: what an infinitesimal trade would receive, applied to
        // the whole amount.
        carried = kept.mul(r_out).ok_or(ARITH)?.div(r_in).ok_or(ARITH)?;
    }
    Ok(carried)
}

fn swap_exact_in(
    state: &mut SwapState,
    account: AccountId,
    asset_in: AssetId,
    path: &[PoolId],
    amount_in: Fixed,
    min_out: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount_in.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    resolve_path(state, asset_in, path)?;
    if state.balance(&account, asset_in) < amount_in {
        return Err(Reject::InsufficientBalance);
    }

    // With clearing on, a direct swap is an order for the seal. It is priced
    // there, together with everything else on the pool, and never here.
    if state.batch_clearing && path.len() == 1 {
        let pool = state.pools.get(&path[0]).ok_or(Reject::UnknownPool)?;
        if amount_in < pool.min_in(asset_in).ok_or(Reject::InvalidPath)? {
            return Err(Reject::BelowMinimumTrade);
        }
        let seq = state.seq;
        state.orders.push(Order { seq, account, pool: path[0], asset_in, amount_in, min_out });
        return Ok(vec![Receipt::SwapQueued { account, pool: path[0], asset_in, amount_in, min_out, seq }]);
    }
    swap_now(state, account, asset_in, path, amount_in, min_out)
}

/// A swap against the curve right now, clearing or not. The launch uses it
/// at the seal, where there is no batch left to join.
pub(crate) fn swap_now(
    state: &mut SwapState,
    account: AccountId,
    asset_in: AssetId,
    path: &[PoolId],
    amount_in: Fixed,
    min_out: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount_in.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let assets = resolve_path(state, asset_in, path)?;
    if state.balance(&account, asset_in) < amount_in {
        return Err(Reject::InsufficientBalance);
    }
    let hops = price_hops(state, &assets, path, amount_in)?;
    let carried = hops.last().map(|h| h.amount_out).unwrap_or(amount_in);

    if carried < min_out {
        return Err(Reject::SlippageExceeded);
    }

    settle_route(state, account, &hops)?;
    state.epoch_gross_volume = state
        .epoch_gross_volume
        .add(xzec_leg(&hops))
        .ok_or(ARITH)?;

    Ok(vec![Receipt::Swapped {
        account,
        asset_in,
        asset_out: *assets.last().ok_or(ARITH)?,
        amount_in,
        amount_out: carried,
        hops,
    }])
}

/// Buy an exact output, paying at most `max_in`.
///
/// Priced backwards from the last hop: each hop's required input becomes the
/// previous hop's required output. `in_given_out` rounds the input **up**, so
/// every hop's rounding lands in the pool and the caller can never receive more
/// than the curve allows for what they paid.
fn swap_exact_out(
    state: &mut SwapState,
    account: AccountId,
    asset_in: AssetId,
    path: &[PoolId],
    amount_out: Fixed,
    max_in: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !amount_out.is_positive() || !max_in.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let assets = resolve_path(state, asset_in, path)?;
    let share = state.params.protocol_fee_share_bps;
    let (seq_now, staleness) = (state.seq, state.params.reference_staleness);

    // Walk the route in reverse, accumulating the input each hop demands.
    let mut needed = amount_out;
    let mut rev: Vec<Hop> = Vec::with_capacity(path.len());
    for i in (0..path.len()).rev() {
        let id = path[i];
        let pool = state.pools.get(&id).ok_or(Reject::UnknownPool)?;
        let (r_in, r_out) = pool.oriented(assets[i]).ok_or(Reject::InvalidPath)?;
        if needed >= r_out {
            return Err(Reject::InsufficientReserves);
        }
        let fee_bps = effective_fee(pool, seq_now, staleness);
        let input = amm::in_given_out(needed, r_in, r_out, fee_bps)
            .ok_or(Reject::InsufficientReserves)?;
        if input < pool.min_in(assets[i]).ok_or(Reject::InvalidPath)? {
            return Err(Reject::BelowMinimumTrade);
        }
        let fee = amm::fee_taken(input, fee_bps).ok_or(ARITH)?;
        rev.push(Hop {
            pool: id,
            asset_in: assets[i],
            asset_out: assets[i + 1],
            amount_in: input,
            amount_out: needed,
            fee,
            protocol_fee: protocol_cut(fee, share).ok_or(ARITH)?,
        });
        needed = input;
    }
    rev.reverse();
    let hops = rev;

    let amount_in = needed;
    if amount_in > max_in {
        return Err(Reject::SlippageExceeded);
    }
    if state.balance(&account, asset_in) < amount_in {
        return Err(Reject::InsufficientBalance);
    }

    settle_route(state, account, &hops)?;
    state.epoch_gross_volume = state
        .epoch_gross_volume
        .add(xzec_leg(&hops))
        .ok_or(ARITH)?;

    Ok(vec![Receipt::Swapped {
        account,
        asset_in,
        asset_out: *assets.last().ok_or(ARITH)?,
        amount_in,
        amount_out,
        hops,
    }])
}

/// The fee a hop actually charges.
///
/// A pool with a fresh reference charges enough to cover what an arbitrageur
/// would otherwise take when the pair is repriced elsewhere; one without —
/// which is every pool whose price is discovered here — charges its ordinary
/// fee. A stale reference falls back too, because pricing a fee from a snapshot
/// of a market that has moved on penalises the trader for the reporter's
/// silence.
/// The fee a pool charges now: its own, or the divergence fee when a fresh
/// reference says the pool has drifted from its market.
pub fn effective_fee(pool: &Pool, now: u64, staleness: u64) -> u16 {
    let Some(r) = pool.reference else {
        return pool.fee_bps;
    };
    if !r.is_fresh(now, staleness) {
        return pool.fee_bps;
    }
    let Some(spot) = amm::spot_price(pool.reserve0, pool.reserve1) else {
        return pool.fee_bps;
    };
    amm::divergence_fee(spot, r.price, pool.fee_bps).unwrap_or(pool.fee_bps)
}

/// Report an external price for a pair.
fn update_reference(
    state: &mut SwapState,
    pool_id: PoolId,
    price: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !price.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    let seq = state.seq;
    let staleness = state.params.reference_staleness;
    let pool = state.pools.get_mut(&pool_id).ok_or(Reject::UnknownPool)?;
    pool.reference = Some(Reference { price, seq });
    let fee_bps = effective_fee(pool, seq, staleness);
    Ok(vec![Receipt::ReferenceUpdated { pool: pool_id, price, fee_bps }])
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

fn set_params(state: &mut SwapState, params: Params) -> Result<Vec<Receipt>, Reject> {
    if params.validate().is_err() {
        return Err(Reject::InvalidParams);
    }
    state.params = params;
    Ok(vec![Receipt::ParamsUpdated])
}

#[cfg(test)]
mod quote_tests {
    use super::*;
    use crate::state::SwapState;
    use crate::tx::SequencedIntent;
    use crate::types::XZEC;

    fn market() -> (SwapState, PoolId, AssetId) {
        let mut s = SwapState::new(7, Params::v1());
        let mut at = 0u64;
        let go = |s: &mut SwapState, at: &mut u64, i: Intent| -> Vec<Receipt> {
            *at += 1;
            apply(s, &SequencedIntent { seq: *at, intent: i })
        };

        // Observe, credit, then anchor: a deposit is unspendable until the
        // epoch containing it is anchored.
        let amount = Fixed::whole(100_000);
        let observed = s.backing_of(XZEC).add(amount).unwrap();
        go(&mut s, &mut at, Intent::AttestVaultBalance { asset: XZEC, observed });
        let d = Intent::next_deposit(&s, [1u8; 32], XZEC, amount, [0u8; 32]);
        go(&mut s, &mut at, d);
        let epoch = s.epoch;
        go(&mut s, &mut at, Intent::Checkpoint);
        go(&mut s, &mut at, Intent::ConfirmAnchor { epoch });

        let r = go(
            &mut s,
            &mut at,
            Intent::CreateToken {
                creator: [1u8; 32],
                symbol: *b"CAT\0\0\0\0\0",
                supply: Fixed::whole(10_000_000),
                unit: Fixed::raw(1),
                xzec_liquidity: Fixed::whole(10_000),
                token_liquidity: Fixed::whole(5_000_000),
                fee_bps: 30,
            },
        );
        let token = match r[0] {
            Receipt::TokenCreated { asset, .. } => asset,
            _ => panic!("expected TokenCreated, got {:?}", r),
        };
        let pool = match r[1] {
            Receipt::PoolCreated { pool, .. } => pool,
            _ => panic!("a launch must open a pool"),
        };
        (s, pool, token)
    }

    /// The property the extraction exists for: a quote must be the number the
    /// swap actually produces, not an approximation of it.
    #[test]
    fn a_quote_equals_what_the_swap_pays_out() {
        let (mut s, pool, _) = market();
        let amount = Fixed::whole(10);
        let q = quote(&s, XZEC, &[pool], amount).expect("quote");

        let at = s.seq + 1;
        let receipts = apply(
            &mut s,
            &SequencedIntent {
                seq: at,
                intent: Intent::SwapExactIn {
                    account: [1u8; 32],
                    asset_in: XZEC,
                    path: vec![pool],
                    amount_in: amount,
                    min_out: Fixed::ZERO,
                },
            },
        );
        let paid = receipts
            .iter()
            .find_map(|r| match r {
                Receipt::Swapped { amount_out, .. } => Some(*amount_out),
                _ => None,
            })
            .expect("a swap receipt");
        assert_eq!(q.amount_out, paid, "the quote disagreed with execution");
    }

    /// Quoting must not move anything. A read that mutates is a read nobody
    /// can offer publicly.
    #[test]
    fn quoting_changes_nothing() {
        let (s, pool, _) = market();
        let before = s.state_root();
        for n in [1i64, 10, 100] {
            let _ = quote(&s, XZEC, &[pool], Fixed::whole(n));
        }
        assert_eq!(s.state_root(), before, "a quote moved the state");
    }

    /// A quote needs no account, so an interface can price a route before
    /// anyone has connected a wallet.
    #[test]
    fn a_quote_needs_no_balance() {
        let (s, pool, _) = market();
        // Far more than any account here holds.
        assert!(quote(&s, XZEC, &[pool], Fixed::whole(400)).is_ok());
    }

    #[test]
    fn a_quote_refuses_what_a_swap_would_refuse() {
        let (s, pool, _) = market();
        assert_eq!(quote(&s, XZEC, &[pool], Fixed::ZERO), Err(Reject::NonPositiveAmount));
        assert_eq!(quote(&s, XZEC, &[9_999], Fixed::whole(1)), Err(Reject::UnknownPool));
    }

    /// The range an aggregator would be quoted: a floor it can rely on and a
    /// ceiling it cannot exceed.
    #[test]
    fn a_quote_brackets_what_a_batch_could_pay() {
        let (s, pool, _) = market();
        for n in [1i64, 10, 100, 1_000] {
            let q = quote(&s, XZEC, &[pool], Fixed::whole(n)).unwrap();
            assert!(
                q.best_case > q.amount_out,
                "no room between solo execution and perfect netting at {}",
                n
            );
        }
    }

    /// The gap between the two *is* price impact, so it widens with size — and
    /// that is the number a router actually needs to compare venues.
    #[test]
    fn the_bracket_widens_with_the_trade() {
        let (s, pool, _) = market();
        let spread = |n: i64| {
            let q = quote(&s, XZEC, &[pool], Fixed::whole(n)).unwrap();
            q.best_case.sub(q.amount_out).unwrap().div(q.best_case).unwrap()
        };
        assert!(spread(1_000) > spread(10), "price impact did not grow with size");
    }

    /// Fees are charged either way. Netting removes slippage, not the cost of
    /// using the pool — a ceiling that ignored fees would be a lie.
    #[test]
    fn the_ceiling_still_pays_the_fee() {
        let (s, pool, _) = market();
        let amount = Fixed::whole(10);
        let q = quote(&s, XZEC, &[pool], amount).unwrap();
        let p = &s.pools[&pool];
        let (r_in, r_out) = p.oriented(XZEC).unwrap();
        let feeless = amount.mul(r_out).unwrap().div(r_in).unwrap();
        assert!(q.best_case < feeless, "the ceiling was quoted without the fee");
    }

    /// Price impact is visible: a larger trade gets a worse rate per unit.
    #[test]
    fn a_larger_trade_prices_worse_per_unit() {
        let (s, pool, _) = market();
        let small = quote(&s, XZEC, &[pool], Fixed::whole(1)).unwrap();
        let large = quote(&s, XZEC, &[pool], Fixed::whole(100)).unwrap();
        let small_rate = small.amount_out.div(Fixed::whole(1)).unwrap();
        let large_rate = large.amount_out.div(Fixed::whole(100)).unwrap();
        assert!(large_rate < small_rate, "price impact was not reflected");
    }
}

#[cfg(test)]
mod clearing_tests {
    use super::*;
    use crate::state::SwapState;
    use crate::tx::SequencedIntent;
    use crate::types::XZEC;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];

    fn go(s: &mut SwapState, i: Intent) -> Vec<Receipt> {
        let at = s.seq + 1;
        apply(s, &SequencedIntent { seq: at, intent: i })
    }

    /// A pool of 10,000 xZEC : 5,000,000 CAT; A holds xZEC and the rest of
    /// the CAT supply, B holds xZEC. Clearing is on.
    fn market() -> (SwapState, PoolId, AssetId) {
        let mut s = SwapState::new(7, Params::v1());
        let amount = Fixed::whole(100_000);
        let observed = s.backing_of(XZEC).add(amount).unwrap().add(amount).unwrap();
        go(&mut s, Intent::AttestVaultBalance { asset: XZEC, observed });
        let d = Intent::next_deposit(&s, A, XZEC, amount, [0u8; 32]);
        go(&mut s, d);
        let d = Intent::next_deposit(&s, B, XZEC, amount, [9u8; 32]);
        go(&mut s, d);
        let epoch = s.epoch;
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch });
        let r = go(&mut s, Intent::CreateToken {
            creator: A, symbol: *b"CAT\0\0\0\0\0", supply: Fixed::whole(10_000_000), unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(10_000), token_liquidity: Fixed::whole(5_000_000), fee_bps: 30,
        });
        let token = match r[0] { Receipt::TokenCreated { asset, .. } => asset, _ => panic!("{:?}", r) };
        let pool = match r[1] { Receipt::PoolCreated { pool, .. } => pool, _ => panic!("{:?}", r) };
        let r = go(&mut s, Intent::SetClearing { on: true });
        assert!(matches!(r[0], Receipt::ClearingSet { on: true }));
        (s, pool, token)
    }

    fn swap(account: AccountId, asset_in: AssetId, pool: PoolId, amount_in: Fixed, min_out: Fixed) -> Intent {
        Intent::SwapExactIn { account, asset_in, path: vec![pool], amount_in, min_out }
    }

    fn product(s: &SwapState, pool: PoolId) -> (Fixed, Fixed) {
        let p = &s.pools[&pool];
        (p.reserve0, p.reserve1)
    }

    /// (r0·r1) never falls: compare r0' ≥ r0·r1 / r1' with 256-bit intermediates.
    fn invariant_kept(before: (Fixed, Fixed), after: (Fixed, Fixed)) -> bool {
        after.0 >= before.0.mul_div(before.1, after.1).unwrap()
    }

    #[test]
    fn with_clearing_on_a_swap_is_queued_not_executed() {
        let (mut s, pool, token) = market();
        let before = product(&s, pool);
        let r = go(&mut s, swap(A, XZEC, pool, Fixed::whole(10), Fixed::ZERO));
        assert!(matches!(r[0], Receipt::SwapQueued { .. }), "{:?}", r);
        assert_eq!(product(&s, pool), before, "the pool moved before the seal");
        assert_eq!(s.orders.len(), 1);
        assert_eq!(s.balance(&A, token), Fixed::whole(5_000_000), "nothing paid out yet");
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_lone_order_pays_exactly_the_curve() {
        let (mut s, pool, token) = market();
        let amount = Fixed::whole(10);
        let q = quote(&s, XZEC, &[pool], amount).unwrap();
        go(&mut s, swap(A, XZEC, pool, amount, Fixed::ZERO));
        let before_cat = s.balance(&A, token);
        let r = go(&mut s, Intent::Checkpoint);
        let got = match &r[0] { Receipt::Swapped { amount_out, .. } => *amount_out, other => panic!("{:?}", other) };
        assert!(matches!(r.last(), Some(Receipt::Checkpointed(_))));
        assert_eq!(got, q.amount_out, "alone in the batch, the curve's price is the price");
        assert_eq!(s.balance(&A, token), before_cat.add(got).unwrap());
        assert!(s.orders.is_empty());
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_balanced_batch_clears_at_one_price_and_beats_the_curve() {
        let (mut s, pool, token) = market();
        let x_in = Fixed::whole(10);
        let solo = quote(&s, XZEC, &[pool], x_in).unwrap();
        // B sells 10 xZEC for CAT; A sells CAT worth about 10 xZEC.
        go(&mut s, swap(B, XZEC, pool, x_in, Fixed::ZERO));
        go(&mut s, swap(A, token, pool, Fixed::whole(5_000), Fixed::ZERO));
        let before = product(&s, pool);
        let r = go(&mut s, Intent::Checkpoint);
        let (mut b_out, mut a_out) = (Fixed::ZERO, Fixed::ZERO);
        for x in &r {
            if let Receipt::Swapped { account, amount_out, .. } = x {
                if *account == B { b_out = *amount_out } else { a_out = *amount_out }
            }
        }
        assert!(b_out.is_positive() && a_out.is_positive(), "{:?}", r);
        assert!(b_out > solo.amount_out, "netted, B must do better than the curve alone: {} vs {}", b_out, solo.amount_out);
        assert!(b_out <= solo.best_case, "and no better than the marginal rate: {} vs {}", b_out, solo.best_case);
        // Both sides paid the same price, within rounding, on what entered
        // the curve (the fee comes off the input on both sides): CAT per xZEC.
        let x_net = x_in.sub(amm::fee_taken(x_in, 30).unwrap()).unwrap();
        let c_net = Fixed::whole(5_000).sub(amm::fee_taken(Fixed::whole(5_000), 30).unwrap()).unwrap();
        let p_b = b_out.div(x_net).unwrap();
        let p_a = c_net.div(a_out).unwrap();
        let ratio = p_b.div(p_a).unwrap();
        assert!(ratio > Fixed::raw(999_000_000_000_000_000) && ratio < Fixed::raw(1_001_000_000_000_000_000), "prices differ: {} vs {}", p_b, p_a);
        assert!(invariant_kept(before, product(&s, pool)));
        s.check_invariants().unwrap();
    }

    #[test]
    fn an_unmet_limit_does_not_fill_and_the_rest_still_clear() {
        let (mut s, pool, token) = market();
        go(&mut s, swap(B, XZEC, pool, Fixed::whole(10), Fixed::whole(1_000_000)));
        go(&mut s, swap(A, token, pool, Fixed::whole(5_000), Fixed::ZERO));
        let r = go(&mut s, Intent::Checkpoint);
        assert!(matches!(r[0], Receipt::SwapUnfilled { account: B, reason: Reject::SlippageExceeded, .. }), "{:?}", r[0]);
        assert!(matches!(r[1], Receipt::Swapped { account: A, .. }), "{:?}", r[1]);
        assert_eq!(s.balance(&B, XZEC), Fixed::whole(100_000), "an unfilled order costs nothing");
        s.check_invariants().unwrap();
    }

    #[test]
    fn an_order_the_account_cannot_pay_by_the_seal_is_unfilled() {
        let (mut s, pool, _) = market();
        go(&mut s, swap(B, XZEC, pool, Fixed::whole(10), Fixed::ZERO));
        go(&mut s, Intent::Transfer { from: B, to: A, asset: XZEC, amount: Fixed::whole(99_995) });
        let r = go(&mut s, Intent::Checkpoint);
        assert!(matches!(r[0], Receipt::SwapUnfilled { reason: Reject::InsufficientBalance, .. }), "{:?}", r[0]);
        s.check_invariants().unwrap();
    }

    #[test]
    fn orders_are_committed_and_survive_the_codec() {
        let (mut s, pool, _) = market();
        let root_off = { let mut t = s.clone(); t.batch_clearing = false; t.state_root() };
        assert_ne!(root_off, s.state_root(), "the switch is part of the root");
        let quiet = s.state_root();
        go(&mut s, swap(B, XZEC, pool, Fixed::whole(1), Fixed::ZERO));
        assert_ne!(quiet, s.state_root(), "an open order is part of the root");
        let back = SwapState::decode_state(&s.encode_state()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.orders.len(), 1);
    }

    #[test]
    fn clear_pool_keeps_the_invariant_and_one_price() {
        let cases = [
            (10_000i64, 5_000_000i64, 10i64, 5_000i64),
            (10_000, 5_000_000, 1_000, 10),
            (10_000, 5_000_000, 3, 900_000),
            (1, 1, 1, 1),
            (500, 500, 100, 0),
            (500, 500, 0, 100),
        ];
        for (r0, r1, u, v) in cases {
            let (r0, r1, u, v) = (Fixed::whole(r0), Fixed::whole(r1), Fixed::whole(u), Fixed::whole(v));
            let (out1, out0) = clear_pool(r0, r1, u, v).expect("prices");
            // What a side is paid can exceed a reserve — the other side
            // supplied it — but the reserves themselves must stay positive.
            let after = (r0.add(u).unwrap().sub(out0).unwrap(), r1.add(v).unwrap().sub(out1).unwrap());
            assert!(after.0.is_positive() && after.1.is_positive(), "a reserve was emptied for {:?}", (r0, r1, u, v));
            assert!(invariant_kept((r0, r1), after), "invariant fell for {:?}", (r0, r1, u, v));
            if u.is_positive() && v.is_positive() {
                let p_sell0 = out1.div(u).unwrap();
                let p_sell1 = v.div(out0).unwrap();
                let ratio = p_sell0.div(p_sell1).unwrap();
                assert!(ratio > Fixed::raw(990_000_000_000_000_000) && ratio < Fixed::raw(1_010_000_000_000_000_000), "prices differ for {:?}: {} vs {}", (r0, r1, u, v), p_sell0, p_sell1);
            }
        }
    }
}

#[cfg(test)]
mod collection_tests {
    use super::*;
    use crate::state::SwapState;
    use crate::tx::SequencedIntent;
    use crate::types::XZEC;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];

    pub(super) fn go(s: &mut SwapState, i: Intent) -> Vec<Receipt> {
        let at = s.seq + 1;
        apply(s, &SequencedIntent { seq: at, intent: i })
    }

    /// Two funded accounts on a chain that has anchored, so their xZEC is
    /// spendable.
    pub(super) fn funded() -> SwapState {
        let mut s = SwapState::new(7, Params::v1());
        let amount = Fixed::whole(1_000);
        let observed = s.backing_of(XZEC).add(amount).unwrap().add(amount).unwrap();
        go(&mut s, Intent::AttestVaultBalance { asset: XZEC, observed });
        let d = Intent::next_deposit(&s, A, XZEC, amount, [0u8; 32]);
        go(&mut s, d);
        let d = Intent::next_deposit(&s, B, XZEC, amount, [9u8; 32]);
        go(&mut s, d);
        let epoch = s.epoch;
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch });
        s
    }

    /// A collection with the sale already over, so items can be claimed.
    /// Tests that care about the sale itself advance it themselves.
    pub(super) fn collection(s: &mut SwapState, cap: u32) -> u32 {
        let c = selling(s, cap);
        open_minting(s, c);
        c
    }

    /// A collection still taking deposits.
    fn selling(s: &mut SwapState, cap: u32) -> u32 {
        match go(s, Intent::CreateCollection { creator: A, symbol: *b"NAP\0\0\0\0\0", cap, fee_bps: 100 }).as_slice() {
            [Receipt::CollectionCreated { collection, .. }] => *collection,
            other => panic!("{:?}", other),
        }
    }

    fn advance(s: &mut SwapState, c: u32, to: Phase) -> Vec<Receipt> {
        go(s, Intent::AdvanceCollection { creator: A, collection: c, to: to.code() })
    }

    /// The sale ends and claiming opens.
    fn open_minting(s: &mut SwapState, c: u32) {
        advance(s, c, Phase::Minting);
    }

    /// Claiming closes, then the market opens — the collection's last two
    /// moments.
    pub(super) fn list(s: &mut SwapState, c: u32) {
        advance(s, c, Phase::Closed);
        advance(s, c, Phase::Live);
    }

    pub(super) fn mint(s: &mut SwapState, c: u32, to: AccountId, n: u8) -> AssetId {
        match go(s, Intent::MintCollectionItem { creator: A, collection: c, to, symbol: *b"NAP\0\0\0\0\0", content: [n; 32] }).as_slice() {
            [Receipt::CollectionItemMinted { asset, .. }] => *asset,
            other => panic!("{:?}", other),
        }
    }

    /// The claim the whole design rests on: redeeming does not move the floor.
    /// One item and one item's worth of pool leave together, so the holder who
    /// stays faces the same number as before — all the way to the last item.
    #[test]
    fn the_floor_holds_through_every_redemption_down_to_the_last_item() {
        let mut s = funded();
        let c = collection(&mut s, 4);
        let items: Vec<AssetId> = (0..4).map(|i| mint(&mut s, c, A, i)).collect();
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(40) });
        list(&mut s, c);

        let floor = s.collections[&c].redeem_price();
        assert_eq!(floor, Fixed::whole(10), "40 xZEC over 4 items");

        for (n, asset) in items.iter().enumerate() {
            let before = s.balance(&A, XZEC);
            let r = go(&mut s, Intent::RedeemCollectionItem { holder: A, asset: *asset });
            match r.as_slice() {
                [Receipt::CollectionItemRedeemed { paid, outstanding, .. }] => {
                    assert_eq!(*paid, floor, "item {} paid the floor", n);
                    assert_eq!(*outstanding as usize, 3 - n);
                }
                other => panic!("{:?}", other),
            }
            assert_eq!(s.balance(&A, XZEC), before.add(floor).unwrap());
            // The floor is unchanged for whoever is left.
            let left = &s.collections[&c];
            if left.outstanding > 0 {
                assert_eq!(left.redeem_price(), floor, "the floor moved after {} redemptions", n + 1);
            }
            s.check_invariants().expect("backing identity holds mid-redemption");
        }
        assert_eq!(s.collections[&c].pool, Fixed::ZERO, "the last item took the rest");
        assert_eq!(s.collections[&c].outstanding, 0);
        // Minted never falls: the collection's final size is a fact about it.
        assert_eq!(s.collections[&c].minted, 4);
    }

    /// Paying in without minting is the only thing that moves the floor, and
    /// it moves it for everyone at once with nothing to distribute.
    #[test]
    fn funding_the_pool_raises_the_floor_for_every_holder_at_once() {
        let mut s = funded();
        let c = collection(&mut s, 4);
        let held: Vec<AssetId> = (0..4).map(|i| mint(&mut s, c, if i % 2 == 0 { A } else { B }, i)).collect();
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(40) });
        list(&mut s, c);
        assert_eq!(s.collections[&c].redeem_price(), Fixed::whole(10));

        // A trade fee arrives. Nobody is credited; the floor simply rises.
        go(&mut s, Intent::FundCollection { from: B, collection: c, amount: Fixed::whole(8) });
        assert_eq!(s.collections[&c].redeem_price(), Fixed::whole(12));

        // And B, who holds two, can take the new floor for each.
        let before = s.balance(&B, XZEC);
        go(&mut s, Intent::RedeemCollectionItem { holder: B, asset: held[1] });
        go(&mut s, Intent::RedeemCollectionItem { holder: B, asset: held[3] });
        assert_eq!(s.balance(&B, XZEC), before.add(Fixed::whole(24)).unwrap());
        s.check_invariants().unwrap();
    }

    /// The pool is xZEC that exists and is held by nobody. If the identity did
    /// not count it, the chain would look short by exactly the amount that
    /// makes the floor real.
    #[test]
    fn a_funded_pool_is_counted_in_the_backing_identity() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        mint(&mut s, c, A, 0);
        s.check_invariants().unwrap();
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(25) });
        assert_eq!(s.total_pooled().unwrap(), Fixed::whole(25));
        s.check_invariants().expect("the pool is counted");
    }

    #[test]
    fn a_collection_refuses_what_would_break_its_promises() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        let one = mint(&mut s, c, A, 0);
        mint(&mut s, c, A, 1);
        list(&mut s, c);

        // Minting is over once the market is open — a late item would dilute
        // a claim people are already redeeming against.
        let r = go(&mut s, Intent::MintCollectionItem { creator: A, collection: c, to: A, symbol: *b"NAP\0\0\0\0\0", content: [9; 32] });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);

        // Only the holder may redeem.
        let r = go(&mut s, Intent::RedeemCollectionItem { holder: B, asset: one });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NotTheWholeItem, .. }]), "{:?}", r);

        // An ordinary asset is not redeemable against a pool it never joined.
        let r = go(&mut s, Intent::RedeemCollectionItem { holder: A, asset: XZEC });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NotACollectionItem, .. }]), "{:?}", r);

        // Funding something that does not exist takes nobody's money.
        let before = s.balance(&A, XZEC);
        let r = go(&mut s, Intent::FundCollection { from: A, collection: 999, amount: Fixed::whole(1) });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NoSuchCollection, .. }]), "{:?}", r);
        assert_eq!(s.balance(&A, XZEC), before);
        s.check_invariants().unwrap();
    }

    /// An empty pool is honestly worth nothing, and redeeming from one is
    /// allowed but pays nothing — it must not invent money or panic.
    #[test]
    fn an_unfunded_collection_redeems_for_nothing_rather_than_failing() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let asset = mint(&mut s, c, A, 0);
        list(&mut s, c);
        assert_eq!(s.collections[&c].redeem_price(), Fixed::ZERO);
        let before = s.balance(&A, XZEC);
        go(&mut s, Intent::RedeemCollectionItem { holder: A, asset });
        assert_eq!(s.balance(&A, XZEC), before, "nothing was invented");
        assert_eq!(s.collections[&c].outstanding, 0);
        s.check_invariants().unwrap();
    }

    /// The attack the phase exists to stop.
    ///
    /// Deposits fund the pool as the sale runs, but items appear only as
    /// people claim them. If redemption were open during that, the first
    /// claimant would face `pool / 1` and walk off with everyone's deposits.
    /// Here: 40 xZEC in, one item claimed, and redeeming is refused — the
    /// denominator is not final, so the quotient is not a floor.
    #[test]
    fn nobody_can_redeem_against_a_denominator_that_is_still_moving() {
        let mut s = funded();
        let c = collection(&mut s, 4);
        let first = mint(&mut s, c, B, 0);
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(40) });

        // The naive quotient here would be 40 xZEC for one item.
        assert_eq!(s.collections[&c].outstanding, 1);
        assert_eq!(s.collections[&c].pool, Fixed::whole(40));
        assert_eq!(s.collections[&c].redeem_price(), Fixed::ZERO, "no floor before the market");

        let before = s.balance(&B, XZEC);
        let r = go(&mut s, Intent::RedeemCollectionItem { holder: B, asset: first });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);
        assert_eq!(s.balance(&B, XZEC), before, "not a single zatoshi left the pool");

        // Closing claiming is not enough either: the market has not opened.
        advance(&mut s, c, Phase::Closed);
        let r = go(&mut s, Intent::RedeemCollectionItem { holder: B, asset: first });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);

        // Once it has, the floor is over the final denominator — not over one.
        advance(&mut s, c, Phase::Live);
        assert_eq!(s.collections[&c].redeem_price(), Fixed::whole(40), "one claimant, one claim");
        s.check_invariants().unwrap();
    }

    /// The phase only ever moves forward, and only the creator moves it.
    #[test]
    fn a_collections_life_runs_one_way_and_only_its_creator_advances_it() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        mint(&mut s, c, A, 0);

        let r = go(&mut s, Intent::AdvanceCollection { creator: B, collection: c, to: Phase::Closed.code() });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NotTheCreator, .. }]), "{:?}", r);

        // Cannot skip a step: the market opens after claiming closes.
        let r = advance(&mut s, c, Phase::Live);
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);

        advance(&mut s, c, Phase::Closed);
        // Submitting the same step twice is refused, not silently skipped
        // ahead — which is why the destination is named rather than implied.
        let r = advance(&mut s, c, Phase::Closed);
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);
        advance(&mut s, c, Phase::Live);
        let r = advance(&mut s, c, Phase::Live);
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);
        // And there is nothing after the market.
        assert_eq!(s.collections[&c].phase.next(), None);
    }

    /// The rule the sale's shape depends on: nothing is claimed while money is
    /// still coming in, so how many the sale allocated is known before a
    /// single item is handed out — which is what lets the remainder be priced
    /// and opened to everyone.
    #[test]
    fn nothing_is_claimed_while_the_sale_is_still_running() {
        let mut s = funded();
        let c = selling(&mut s, 4);
        assert_eq!(s.collections[&c].phase, Phase::Depositing);

        // Money may come in — that is what this phase is for.
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(20) });
        assert_eq!(s.collections[&c].pool, Fixed::whole(20));

        // But nothing is handed out.
        let r = go(&mut s, Intent::MintCollectionItem { creator: A, collection: c, to: B, symbol: *b"NAP\0\0\0\0\0", content: [1; 32] });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::WrongCollectionPhase, .. }]), "{:?}", r);
        assert_eq!(s.collections[&c].minted, 0);

        // The sale ends, and only then does claiming open.
        open_minting(&mut s, c);
        let asset = mint(&mut s, c, B, 1);
        assert_eq!(s.collections[&c].minted, 1);
        assert_eq!(s.balance(&B, asset), Fixed::ONE);
        s.check_invariants().unwrap();
    }

    /// Every trade feeds the floor. Half the fee goes into the pool, which is
    /// what makes volume raise the redeem price without paying 4,444 people.
    #[test]
    fn a_trade_pays_the_collection_and_half_of_it_raises_the_floor() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        let item = mint(&mut s, c, A, 0);
        mint(&mut s, c, A, 1);
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::whole(20) });
        list(&mut s, c);
        assert_eq!(s.collections[&c].redeem_price(), Fixed::whole(10));

        // B buys the item from A for 100 xZEC, fee 100 bps each side.
        let (a0, b0) = (s.balance(&A, XZEC), s.balance(&B, XZEC));
        let r = go(&mut s, Intent::AcceptOffer {
            maker: A, taker: B,
            offer_asset: item, offer_amount: Fixed::ONE,
            want_asset: XZEC, want_amount: Fixed::whole(100),
        });
        let fee = match r.as_slice() {
            [Receipt::OfferAccepted { .. }, Receipt::CollectionFeeTaken { taken, to_pool, to_creator, .. }] => {
                assert_eq!(*taken, Fixed::whole(2), "1% from each side of 100");
                assert_eq!(*to_pool, Fixed::whole(1));
                assert_eq!(*to_creator, Fixed::whole(1));
                *taken
            }
            other => panic!("{:?}", other),
        };
        assert_eq!(fee, Fixed::whole(2));

        // The buyer paid the price and their 1%; the seller received the
        // price less theirs. A is also the creator, so A takes the other half.
        assert_eq!(s.balance(&B, XZEC), b0.sub(Fixed::whole(101)).unwrap());
        assert_eq!(s.balance(&A, XZEC), a0.add(Fixed::whole(99)).unwrap().add(Fixed::whole(1)).unwrap());
        assert_eq!(s.balance(&B, item), Fixed::ONE);

        // And the floor moved for both items, without crediting anybody.
        assert_eq!(s.collections[&c].pool, Fixed::whole(21));
        assert_eq!(s.collections[&c].redeem_price(), Fixed::raw(Fixed::whole(21).0 / 2));
        s.check_invariants().unwrap();
    }

    /// An item traded against something the chain cannot price would be a free
    /// channel around the fee. Refused rather than quietly untaxed.
    #[test]
    fn a_collection_item_cannot_be_traded_around_its_fee() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        let one = mint(&mut s, c, A, 0);
        let two = mint(&mut s, c, B, 1);
        list(&mut s, c);
        let r = go(&mut s, Intent::AcceptOffer {
            maker: A, taker: B,
            offer_asset: one, offer_amount: Fixed::ONE,
            want_asset: two, want_amount: Fixed::ONE,
        });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::ItemNeedsAPrice, .. }]), "{:?}", r);
        assert_eq!(s.balance(&A, one), Fixed::ONE, "nothing moved");
        s.check_invariants().unwrap();
    }

    /// A buyer who can cover the price but not the fee is refused before
    /// anything moves — a half-settled trade would leave the pool short.
    #[test]
    fn a_buyer_who_cannot_cover_the_fee_moves_nothing() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let all = s.balance(&B, XZEC);
        let r = go(&mut s, Intent::AcceptOffer {
            maker: A, taker: B,
            offer_asset: item, offer_amount: Fixed::ONE,
            want_asset: XZEC, want_amount: all,
        });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::InsufficientBalance, .. }]), "{:?}", r);
        assert_eq!(s.balance(&B, XZEC), all);
        assert_eq!(s.balance(&A, item), Fixed::ONE);
        s.check_invariants().unwrap();
    }

    /// Rounding leaves the crumb with the holders who remain: the one
    /// direction that cannot leak value out of the collection.
    #[test]
    fn a_remainder_stays_with_the_holders_who_remain() {
        let mut s = funded();
        let c = collection(&mut s, 3);
        let items: Vec<AssetId> = (0..3).map(|i| mint(&mut s, c, A, i)).collect();
        // 10 raw units over 3 items: 3 each, 1 left behind.
        go(&mut s, Intent::FundCollection { from: A, collection: c, amount: Fixed::raw(10) });
        list(&mut s, c);
        go(&mut s, Intent::RedeemCollectionItem { holder: A, asset: items[0] });
        assert_eq!(s.collections[&c].pool, Fixed::raw(7));
        assert_eq!(s.collections[&c].redeem_price(), Fixed::raw(3));
        s.check_invariants().unwrap();
    }
}

#[cfg(test)]
mod offer_tests {
    use super::collection_tests::{collection, funded, go, list, mint};
    use super::*;
    use crate::launch::POT_OFFERS;
    use crate::state::SwapState;
    use crate::types::XZEC;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];
    const C: AccountId = [3u8; 32];

    fn place(s: &mut SwapState, maker: AccountId, asset: AssetId, price: Fixed, until: u64) -> OfferId {
        match go(s, Intent::PlaceOffer {
            maker,
            offer_asset: asset,
            offer_amount: Fixed::ONE,
            want_asset: XZEC,
            want_amount: price,
            expires_at_epoch: until,
        })
        .as_slice()
        {
            [Receipt::OfferPlaced { offer, .. }] => *offer,
            other => panic!("{:?}", other),
        }
    }

    /// The property the whole primitive exists for: the maker never named the
    /// taker, and was not consulted when the trade happened.
    #[test]
    fn anyone_may_take_a_resting_offer() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let price = Fixed::whole(10);
        let o = place(&mut s, A, item, price, u64::MAX);

        let r = go(&mut s, Intent::TakeOffer { taker: B, offer: o });
        assert!(matches!(r.first(), Some(Receipt::OfferTaken { .. })), "{:?}", r);
        assert_eq!(s.balance(&B, item), Fixed::ONE, "the taker has it");
        assert_eq!(s.balance(&POT_OFFERS, item), Fixed::ZERO, "escrow is empty");
        assert!(s.offers.is_empty(), "the offer is gone");
        s.check_invariants().unwrap();
    }

    /// An offer whose asset stayed spendable would be an advertisement: the
    /// maker could sell it elsewhere and leave the taker with nothing.
    #[test]
    fn placing_an_offer_moves_the_asset_out_of_reach() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        place(&mut s, A, item, Fixed::whole(10), u64::MAX);

        assert_eq!(s.balance(&A, item), Fixed::ZERO, "no longer the maker's to spend");
        assert_eq!(s.balance(&POT_OFFERS, item), Fixed::ONE, "held in escrow");
        // And the maker cannot hand it to anyone behind the offer's back.
        let r = go(&mut s, Intent::Transfer { from: A, to: C, asset: item, amount: Fixed::ONE });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::InsufficientBalance, .. }]), "{:?}", r);
        s.check_invariants().unwrap();
    }

    /// Taken once, and only once — the escrow is empty afterwards, so a second
    /// taker has nothing to find.
    #[test]
    fn an_offer_cannot_be_taken_twice() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let o = place(&mut s, A, item, Fixed::whole(10), u64::MAX);
        go(&mut s, Intent::TakeOffer { taker: B, offer: o });

        let r = go(&mut s, Intent::TakeOffer { taker: C, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NoSuchOffer, .. }]), "{:?}", r);
        assert_eq!(s.balance(&C, item), Fixed::ZERO);
        s.check_invariants().unwrap();
    }

    #[test]
    fn only_the_maker_cancels_and_the_asset_comes_home() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let o = place(&mut s, A, item, Fixed::whole(10), u64::MAX);

        let r = go(&mut s, Intent::CancelOffer { maker: B, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::NotTheMaker, .. }]), "{:?}", r);
        assert_eq!(s.balance(&POT_OFFERS, item), Fixed::ONE, "still escrowed");

        let r = go(&mut s, Intent::CancelOffer { maker: A, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::OfferCancelled { .. }]), "{:?}", r);
        assert_eq!(s.balance(&A, item), Fixed::ONE);
        assert!(s.offers.is_empty());
        s.check_invariants().unwrap();
    }

    /// Expiry stops an offer being taken. It does not strand the asset — the
    /// maker can always reclaim, which is why nothing needs to sweep.
    #[test]
    fn an_expired_offer_cannot_be_taken_but_can_be_reclaimed() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let now = s.epoch;
        let o = place(&mut s, A, item, Fixed::whole(10), now);
        go(&mut s, Intent::Checkpoint);

        let r = go(&mut s, Intent::TakeOffer { taker: B, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::OfferExpired, .. }]), "{:?}", r);

        let r = go(&mut s, Intent::CancelOffer { maker: A, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::OfferCancelled { .. }]), "{:?}", r);
        assert_eq!(s.balance(&A, item), Fixed::ONE);
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_maker_cannot_take_their_own_offer() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let o = place(&mut s, A, item, Fixed::whole(10), u64::MAX);

        let r = go(&mut s, Intent::TakeOffer { taker: A, offer: o });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::CannotTakeOwnOffer, .. }]), "{:?}", r);
        s.check_invariants().unwrap();
    }

    /// The reason the fee lives in one function: a resting offer is a second
    /// way to move an item, and it must not be a cheaper one.
    #[test]
    fn a_resting_offer_pays_the_same_collection_fee_as_a_negotiated_one() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let price = Fixed::whole(10);
        let pool_before = s.collections[&c].pool;
        let o = place(&mut s, A, item, price, u64::MAX);
        let r = go(&mut s, Intent::TakeOffer { taker: B, offer: o });

        // 100 bps of 10, from each side: half of the 0.2 total to the pool.
        let each = Fixed::raw(price.0 / 100);
        let taken = each.add(each).unwrap();
        let to_pool = Fixed::raw(taken.0 / 2);
        assert!(
            r.iter().any(|x| matches!(x, Receipt::CollectionFeeTaken { taken: t, .. } if *t == taken)),
            "{:?}",
            r
        );
        assert_eq!(s.collections[&c].pool, pool_before.add(to_pool).unwrap(), "the floor rose");
        s.check_invariants().unwrap();
    }

    /// An item priced in something the chain cannot read is refused when the
    /// offer is placed, not left to fail at every take.
    #[test]
    fn an_item_offered_for_anything_but_xzec_is_refused_up_front() {
        let mut s = funded();
        let c = collection(&mut s, 2);
        let one = mint(&mut s, c, A, 0);
        let two = mint(&mut s, c, B, 1);
        list(&mut s, c);
        let r = go(&mut s, Intent::PlaceOffer {
            maker: A,
            offer_asset: one,
            offer_amount: Fixed::ONE,
            want_asset: two,
            want_amount: Fixed::ONE,
            expires_at_epoch: u64::MAX,
        });
        assert!(matches!(r.as_slice(), [Receipt::Rejected { reason: Reject::ItemNeedsAPrice, .. }]), "{:?}", r);
        assert_eq!(s.balance(&A, one), Fixed::ONE, "nothing escrowed");
        s.check_invariants().unwrap();
    }

    /// A chain that has never had an offer must commit exactly the sections it
    /// committed before this feature existed, or every live chain re-anchors
    /// the moment it upgrades.
    ///
    /// The root itself moves with every intent — `seq` is in the header leaf —
    /// so the guarantee is about the shape of the commitment, not its value.
    #[test]
    fn offers_join_the_commitment_only_while_they_exist() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        let without = s.sections().len();

        let o = place(&mut s, A, item, Fixed::whole(10), u64::MAX);
        assert_eq!(s.sections().len(), without + 1, "a resting offer is committed state");

        go(&mut s, Intent::CancelOffer { maker: A, offer: o });
        assert_eq!(s.sections().len(), without, "and leaves no section behind");
    }

    /// Escrow is an ordinary account, so a saved state has to bring it back
    /// with the offer that explains it.
    #[test]
    fn offers_survive_a_round_trip_through_the_codec() {
        let mut s = funded();
        let c = collection(&mut s, 1);
        let item = mint(&mut s, c, A, 0);
        list(&mut s, c);
        place(&mut s, A, item, Fixed::whole(10), 4242);

        let back = SwapState::decode_state(&s.encode_state()).expect("decode");
        assert_eq!(back.offers, s.offers);
        assert_eq!(back.next_offer_id, s.next_offer_id);
        assert_eq!(back.state_root(), s.state_root());
    }
}
