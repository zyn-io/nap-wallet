//! ZYN: the chain's own asset, and the launch that creates it.
//!
//! Everything here runs at the seal, like batch clearing, and every unit it
//! moves sits in an ordinary account — the *pots* — so conservation needs
//! no special case: a pot is an account nobody holds a key for.
//!
//! Two kinds of launch run on the same machinery. **ZYN's**, where the pot
//! discovers the price because ZYN has no market anywhere else. And a
//! **bridged asset's**, where the price is already discovered elsewhere and
//! the pot only decides the size: those pools open at the reference price
//! (§5.7's feed), because the divergence fee makes any other opening price
//! permanent. Both end with a pool the protocol owns and cannot remove.
//!
//! The life of the ZYN launch, in order:
//!
//! 1. **Pot.** With the launch set, every ZEC.zy deposit and exit pays a
//!    fee into the genesis pot, and each payer's contribution is recorded.
//! 2. **Graduation.** When the pot reaches the threshold (or a Zcash height
//!    deadline passes), ZYN is created. Half the genesis batch is paired with
//!    the whole pot into the genesis pool ZYN:ZEC.zy, whose LP shares the
//!    protocol holds and can never remove. The other half is credited to the
//!    contributors pro rata to fees paid, vesting linearly by Zcash height.
//! 3. **Emission.** Every seal mints per Zcash block elapsed since the last,
//!    at a rate that halves on a fixed block interval, up to the cap, split
//!    between the LP pot, the bridge pot and the protocol-owned-liquidity pot.
//! 4. **Rewards.** At each seal the LP pot is paid to liquidity providers in
//!    proportion to the fees their pools earned that epoch, the bridge pot to
//!    whoever paid bridge fees that epoch, and the fees themselves are half
//!    burned (bought on the genesis pool and destroyed) and half paired with
//!    pot ZYN into the genesis pool.
//!
//! A bridged asset's is shorter:
//!
//! 1. **Pot.** Its bridge fees accumulate in that asset, and each payer's
//!    share is recorded. They earn the ordinary ZYN rebate meanwhile: they
//!    paid a fee like anyone else.
//! 2. **Graduation.** When the pot is worth more than the threshold at a
//!    fresh reference, and the protocol holds that much ZEC.zy, a pool opens
//!    at exactly the reference price with the pot on one side and protocol
//!    ZEC.zy on the other. The protocol keeps the shares.
//! 3. **Grant.** The contributors share `bootstrap_bps` of whatever ZYN is
//!    still unminted, vesting like the ZYN genesis. Each grant shrinks the
//!    base for the next, so the tenth market costs less than the first and
//!    the cap can never be breached.
//!
//! The clock is Zcash height, reported by the operator (`ZcashHeight`) and
//! only ever moving forward; epochs are the operator's to seal, blocks are
//! not, so emission and vesting are keyed to blocks.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::fixed::Fixed;
use crate::state::{symbol, SwapState, TokenInfo};
use crate::tx::{Receipt, Reject};
use crate::types::{AccountId, AssetId, PoolId, XZEC};

/// Accounts nobody has a key for. They are ordinary accounts to the rest of
/// the VM, which is the point.
pub const POT_GENESIS: AccountId = [0xF0; 32];
pub const POT_LP: AccountId = [0xF1; 32];
pub const POT_BRIDGE: AccountId = [0xF2; 32];
pub const POT_POL: AccountId = [0xF3; 32];
pub const POT_FEES: AccountId = [0xF4; 32];
/// Bridge fees of bridged assets that have no market yet: one balance per
/// asset, which is that asset's pot.
pub const POT_ASSETS: AccountId = [0xF5; 32];
/// Holds every asset committed to a resting offer. Keyless like the rest: the
/// escrow is not ours to spend, and `state.offers` is the ledger of whose it is.
pub const POT_OFFERS: AccountId = [0xF6; 32];

/// ZEC per ZYN at which the reserve matches the POL pot: `0.0002`.
///
/// §71.11's Phase-2 trigger and §71.9's 2,100,000 are the same statement seen
/// twice — 420 ZEC.zy divided by this ratio is exactly 2,100,000 ZYN. Holding
/// the ratio here makes the opening price a property of how the pot was filled
/// rather than a number someone has to remember to hit.
pub const POL_ZEC_PER_ZYN: Fixed = Fixed::raw(200_000_000_000_000); // 0.0002 WAD

/// The most ZYN the reserve will ever match into the POL pot (§71.9).
/// Zcash blocks between the ZYN market becoming due and it opening: ~7 days at
/// 75 seconds a block.
///
/// The point is that the date is knowable in advance and by everyone. The chain
/// records the arming height the moment the pot fills, so the opening block is
/// arithmetic from public state — not an announcement anyone has to be trusted
/// to make, or to make on time.
pub const POL_OPEN_GRACE_BLOCKS: u64 = 8_064;

pub const POL_ZYN_CAP: Fixed = Fixed::raw(2_100_000 * 1_000_000_000_000_000_000);

/// Credit ZEC.zy to the POL pot, and match it with ZYN from the reserve.
///
/// Every route that accrues protocol-owned liquidity goes through here, so the
/// matching cannot be forgotten at a call site added later — which is the whole
/// reason this is a function and not five copies of a credit.
///
/// The reserve releases `zec / 0.0002` ZYN, stopping at [`POL_ZYN_CAP`]. That
/// bound is what keeps this from being a tap: past 420 ZEC.zy the pot holds its
/// full 2,100,000 and the reserve is never drawn on again by this path. What
/// happens after is the AMM's job, not the reserve's — further accrual moves
/// the price rather than the supply (§71.5's buyback).
///
/// No signature authorises this. A keyless pot cannot produce one, and that
/// impossibility is exactly what §71.2 rests on: the release is a rule the VM
/// applies, never a withdrawal anyone can request.
pub fn credit_pol(state: &mut SwapState, zec: Fixed) -> Result<Fixed, Reject> {
    if !zec.is_positive() {
        return Ok(Fixed::ZERO);
    }
    state
        .account_mut(&crate::types::ZYN_POL)
        .credit(XZEC, zec)
        .ok_or(Reject::ArithmeticFailure)?;

    let zyn = crate::types::ZYN_MAINNET;
    let held = state.balance(&crate::types::ZYN_POL_ZYN, zyn);
    let room = POL_ZYN_CAP.sub(held).unwrap_or(Fixed::ZERO);
    if !room.is_positive() {
        // Full already: nothing to match, but the opening may still need
        // arming. Returning here before that check once meant a pot that
        // started full could never become due.
        arm_pol_open(state);
        return Ok(Fixed::ZERO);
    }
    let want = zec
        .mul_div(Fixed::ONE, POL_ZEC_PER_ZYN)
        .ok_or(Reject::ArithmeticFailure)?;
    let available = state.balance(&crate::types::ZYN_RESERVE, zyn);
    let release = want.min(room).min(available);
    if !release.is_positive() {
        return Ok(Fixed::ZERO);
    }
    state
        .account_mut(&crate::types::ZYN_RESERVE)
        .debit(zyn, release)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&crate::types::ZYN_POL_ZYN)
        .credit(zyn, release)
        .ok_or(Reject::ArithmeticFailure)?;

    // The moment the pot is full, the opening becomes *due* and the chain
    // records when. Everything after that is arithmetic anyone can do from
    // public state: the market opens at `armed + POL_OPEN_GRACE_BLOCKS`. That
    // is the whole grace mechanism — not a promise to announce something, but a
    // date that exists before anyone has to be told.
    //
    // Set once. Nothing can leave a keyless pot, so the condition cannot become
    // false again and the date cannot move.
    arm_pol_open(state);
    Ok(release)
}

/// Record when the opening became due, once.
fn arm_pol_open(state: &mut SwapState) {
    if state.pol_open_armed_height.is_some() {
        return;
    }
    if state.balance(&crate::types::ZYN_POL_ZYN, crate::types::ZYN_MAINNET) >= POL_ZYN_CAP {
        state.pol_open_armed_height = Some(state.zcash_height);
    }
}

/// The Zcash height at which the ZYN market opens, once it is due.
///
/// `None` until the POL pot fills. Public so a wallet or explorer can show the
/// same countdown the chain is keeping.
pub fn pol_open_height(state: &SwapState) -> Option<u64> {
    state
        .pol_open_armed_height
        .map(|h| h.saturating_add(POL_OPEN_GRACE_BLOCKS))
}

pub fn is_pot(a: &AccountId) -> bool {
    matches!(
        *a,
        POT_GENESIS
            | POT_LP
            | POT_BRIDGE
            | POT_POL
            | POT_FEES
            | POT_ASSETS
            | POT_OFFERS
            // The derived ZYN pots. Keyless like the rest, and excluded from
            // reward distribution for the same reason: a pot that cannot spend
            // should not be paid, or its share is stranded on every epoch.
            | crate::types::ZYN_POL
            | crate::types::ZYN_POL_ZYN
            | crate::types::ZYN_RESERVE
    )
}

/// The numbers. Set once by the operator; part of the state and the root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Launch {
    /// Bridge fee on ZEC.zy deposits and exits, in basis points.
    pub fee_bps: u16,
    /// Pot balance at which the launch graduates.
    pub threshold: Fixed,
    /// Zcash height at which it graduates regardless (0 = none).
    pub deadline_height: u64,
    /// ZYN created at graduation.
    pub genesis: Fixed,
    /// ZYN that can ever exist.
    pub cap: Fixed,
    /// Emission per Zcash block at graduation; halves every `halving_blocks`.
    pub rate0: Fixed,
    pub halving_blocks: u64,
    /// Blocks over which the contributors' genesis share vests.
    pub vesting_blocks: u64,
    /// Of each mint: to the LP pot, to the bridge pot; the rest to POL.
    pub split_lp_bps: u16,
    pub split_bridge_bps: u16,
    /// Of each epoch's bridge fees after graduation: burned; the rest paired.
    pub fee_burn_bps: u16,
    /// Fee of the genesis pool.
    pub pool_fee_bps: u16,
    /// What a bridged asset's pot must be worth, in ZEC.zy, before its
    /// market opens. The protocol must hold that much ZEC.zy too.
    pub asset_threshold: Fixed,
    /// A bridged market's opening grant, in basis points of the ZYN still
    /// unminted, shared among that asset's pot contributors.
    pub bootstrap_bps: u16,
}

impl Launch {
    /// The decided numbers (DECISIONS §30).
    pub fn v1() -> Launch {
        Launch {
            fee_bps: 50,
            threshold: Fixed::whole(100),
            deadline_height: 0,
            genesis: Fixed::whole(2_100_000),
            cap: Fixed::whole(21_000_000),
            rate0: Fixed::whole(9),
            halving_blocks: 1_050_000,
            vesting_blocks: 207_360,
            split_lp_bps: 5_000,
            split_bridge_bps: 2_500,
            fee_burn_bps: 5_000,
            pool_fee_bps: 30,
            asset_threshold: Fixed::whole(100),
            bootstrap_bps: 50,
        }
    }

    pub fn validate(&self) -> Result<(), Reject> {
        if self.fee_bps >= 10_000
            || self.split_lp_bps as u32 + self.split_bridge_bps as u32 > 10_000
            || self.fee_burn_bps > 10_000
            || self.pool_fee_bps >= 10_000
        {
            return Err(Reject::InvalidParams);
        }
        if !self.threshold.is_positive()
            || !self.genesis.is_positive()
            || self.genesis > self.cap
            || self.halving_blocks == 0
            || self.vesting_blocks == 0
        {
            return Err(Reject::InvalidParams);
        }
        if !self.asset_threshold.is_positive() || self.bootstrap_bps >= 10_000 {
            return Err(Reject::InvalidParams);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vest {
    pub total: Fixed,
    pub released: Fixed,
    pub start: u64,
    pub end: u64,
}

/// A bridged asset on its way to a market of its own.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AssetLaunch {
    /// Units of the asset per ZEC.zy, as the feed reports it, and when.
    pub reference: Option<crate::state::Reference>,
    /// Fees paid into this asset's pot, per account.
    pub contributions: BTreeMap<AccountId, Fixed>,
    /// 0 until its market opens, then the Zcash height it opened at.
    pub opened_at: u64,
    pub pool: PoolId,
    /// ZYN granted to its contributors when it opened.
    pub grant: Fixed,
}

/// What the launch has done so far.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LaunchState {
    pub params: Launch,
    /// The chain's clock: the highest Zcash height reported.
    pub zcash_height: u64,
    /// 0 until graduation, then the height it happened at.
    pub graduated_at: u64,
    pub zyn: AssetId,
    pub genesis_pool: PoolId,
    pub minted: Fixed,
    pub last_mint_height: u64,
    /// Fees paid before graduation, per account.
    pub contributions: BTreeMap<AccountId, Fixed>,
    /// Fees paid this epoch after graduation, per account.
    pub epoch_bridge_fees: BTreeMap<AccountId, Fixed>,
    /// Swap fees earned this epoch, per pool, valued in ZEC.zy.
    pub epoch_pool_fees: BTreeMap<PoolId, Fixed>,
    /// Vesting grants, keyed by holder and by which launch made them:
    /// asset 0 is the ZYN genesis, any other is that asset's market opening.
    pub vesting: BTreeMap<(AccountId, AssetId), Vest>,
    /// Bridged assets with a pot, by asset.
    pub assets: BTreeMap<AssetId, AssetLaunch>,
}

impl LaunchState {
    pub fn new(params: Launch) -> LaunchState {
        LaunchState {
            params,
            zcash_height: 0,
            graduated_at: 0,
            zyn: [0u8; 32],
            genesis_pool: [0u8; 32],
            minted: Fixed::ZERO,
            last_mint_height: 0,
            contributions: BTreeMap::new(),
            epoch_bridge_fees: BTreeMap::new(),
            epoch_pool_fees: BTreeMap::new(),
            vesting: BTreeMap::new(),
            assets: BTreeMap::new(),
        }
    }

    pub fn graduated(&self) -> bool {
        self.graduated_at > 0
    }
}

fn bps(amount: Fixed, bps: u16) -> Option<Fixed> {
    amount.mul_div(Fixed::whole(bps as i64), Fixed::whole(10_000))
}

/// The fee on a bridged deposit or exit, and where it goes. ZEC.zy pays into
/// the ZYN genesis pot, then into the fee pot once ZYN has graduated, where
/// it is burned and paired. Every other bridged asset pays into its own pot,
/// which opens its market and afterwards deepens it. `None` without a launch.
pub fn bridge_fee(state: &SwapState, asset: AssetId, amount: Fixed) -> Option<(Fixed, AccountId)> {
    let l = state.launch.as_ref()?;
    if !state
        .token(asset)
        .map(|t| t.is_bridged() && t.is_divisible())
        .unwrap_or(false)
    {
        return None;
    }
    let fee = bps(amount, l.params.fee_bps)?;
    if !fee.is_positive() {
        return None;
    }
    if asset == XZEC {
        return Some((fee, if l.graduated() { POT_FEES } else { POT_GENESIS }));
    }
    // Every other bridged asset's fee lands in its own pot, whether that
    // pot is waiting to open a market or waiting to deepen one.
    Some((fee, POT_ASSETS))
}

/// Remember who paid a bridge fee: for the ZYN genesis share, for a bridged
/// market's opening grant, and for the ordinary rebate. A bootstrapper earns
/// the rebate too — they paid a fee like anyone else.
pub fn note_fee(state: &mut SwapState, account: AccountId, asset: AssetId, fee: Fixed) {
    let has_market = state.find_pool(XZEC, asset).is_some();
    let Some(l) = state.launch.as_mut() else {
        return;
    };
    let add = |book: &mut BTreeMap<AccountId, Fixed>| {
        let e = book.entry(account).or_insert(Fixed::ZERO);
        *e = e.add(fee).unwrap_or(*e);
    };
    if l.graduated() {
        add(&mut l.epoch_bridge_fees);
    } else if asset == XZEC {
        add(&mut l.contributions);
    }
    // A contribution only counts toward a grant while the market is still
    // to be opened. Once it exists, the fee just deepens it.
    if asset != XZEC && !has_market {
        let a = l.assets.entry(asset).or_default();
        let e = a.contributions.entry(account).or_insert(Fixed::ZERO);
        *e = e.add(fee).unwrap_or(*e);
    }
}

/// The operator posts a bridged asset's market price, in units of the asset
/// per ZEC.zy — the orientation a ZEC.zy pool would use. Only meaningful
/// before its market opens; after that the pool carries its own reference.
pub fn observe_asset_reference(
    state: &mut SwapState,
    asset: AssetId,
    price: Fixed,
) -> Result<Vec<Receipt>, Reject> {
    if !price.is_positive() {
        return Err(Reject::NonPositiveAmount);
    }
    if asset == XZEC || !state.token(asset).map(|t| t.is_bridged()).unwrap_or(false) {
        return Err(Reject::UnknownAsset);
    }
    let seq = state.seq;
    let l = state.launch.as_mut().ok_or(Reject::InvalidParams)?;
    l.assets.entry(asset).or_default().reference = Some(crate::state::Reference { price, seq });
    Ok(vec![Receipt::AssetReferenceUpdated { asset, price }])
}

/// Remember a swap fee a pool earned, in ZEC.zy terms, for the LP rewards.
/// A pool without ZEC.zy on either side is valued through nothing and
/// earns no weight; V1 routes through ZEC.zy, so that is nearly none.
pub fn note_pool_fee(state: &mut SwapState, pool: PoolId, asset_in: AssetId, fee: Fixed) {
    let Some(p) = state.pools.get(&pool) else {
        return;
    };
    let value = if asset_in == XZEC {
        fee
    } else if p.asset0 == XZEC || p.asset1 == XZEC {
        let (r_in, r_out) = match p.oriented(asset_in) {
            Some(x) => x,
            None => return,
        };
        match fee.mul_div(r_out, r_in) {
            Some(v) => v,
            None => return,
        }
    } else {
        return;
    };
    if let Some(l) = state.launch.as_mut() {
        if l.graduated() {
            let e = l.epoch_pool_fees.entry(pool).or_insert(Fixed::ZERO);
            *e = e.add(value).unwrap_or(*e);
        }
    }
}

/// Before graduation nothing is irreversible: if an earlier graduation
/// attempt left ZYN minted or pot ZEC moved (a version of this code that
/// did not run on a scratch copy did), put it back. Called when the
/// numbers are (re)set.
pub fn undo_partial(state: &mut SwapState) -> Result<(), Reject> {
    if state.launch.as_ref().map(|l| l.graduated()).unwrap_or(true) {
        return Ok(());
    }
    let zec = state.balance(&POT_POL, XZEC);
    if zec.is_positive() {
        state
            .account_mut(&POT_POL)
            .debit(XZEC, zec)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&POT_GENESIS)
            .credit(XZEC, zec)
            .ok_or(Reject::ArithmeticFailure)?;
    }
    let stray: Vec<AssetId> = state
        .tokens
        .iter()
        .filter(|(_, t)| t.symbol == symbol(b"ZYN") && t.vault.is_none() && t.lp_of.is_none())
        .map(|(id, _)| *id)
        .collect();
    for id in stray {
        for pot in [POT_POL, POT_LP, POT_BRIDGE, POT_FEES] {
            let b = state.balance(&pot, id);
            if b.is_positive() {
                state
                    .account_mut(&pot)
                    .debit(id, b)
                    .ok_or(Reject::ArithmeticFailure)?;
                state.burn(id, b).ok_or(Reject::ArithmeticFailure)?;
            }
        }
        if state
            .tokens
            .get(&id)
            .map(|t| !t.supply.is_positive())
            .unwrap_or(false)
        {
            state.tokens.remove(&id);
        }
    }
    if let Some(l) = state.launch.as_mut() {
        l.minted = Fixed::ZERO;
        l.zyn = [0u8; 32];
        l.genesis_pool = [0u8; 32];
    }
    Ok(())
}

/// The operator reports the Zcash tip. Never backwards.
pub fn observe_height(state: &mut SwapState, height: u64) -> Result<Vec<Receipt>, Reject> {
    // The chain-level height is tracked whether or not a launch exists: the
    // superseded launch machinery owned this once, and the ZYN market's opening
    // schedule now depends on it (§71.29).
    if height < state.zcash_height {
        return Err(Reject::StaleObservation);
    }
    state.zcash_height = height;
    if let Some(l) = state.launch.as_mut() {
        l.zcash_height = height;
    }
    let mut out = vec![Receipt::HeightObserved { height }];
    out.extend(open_pol_market_if_due(state)?);
    Ok(out)
}

/// Open the ZYN market once its grace period has run out.
///
/// Called on every height observation, so the market opens on the first block
/// at or past the published height and not a moment later. Idempotent: once the
/// pool exists this does nothing, and it cannot run before `arm_pol_open` has
/// recorded a height.
pub fn open_pol_market_if_due(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let Some(armed) = state.pol_open_armed_height else {
        return Ok(Vec::new());
    };
    if state.zcash_height < armed.saturating_add(POL_OPEN_GRACE_BLOCKS) {
        return Ok(Vec::new());
    }
    let zyn = crate::types::ZYN_MAINNET;
    if state.find_pool(XZEC, zyn).is_some() {
        return Ok(Vec::new());
    }
    let zyn_side = state.balance(&crate::types::ZYN_POL_ZYN, zyn);
    let zec_side = POL_ZYN_CAP
        .mul_div(POL_ZEC_PER_ZYN, Fixed::ONE)
        .ok_or(Reject::ArithmeticFailure)?;
    if zyn_side < POL_ZYN_CAP || state.balance(&crate::types::ZYN_POL, XZEC) < zec_side {
        return Ok(Vec::new());
    }

    // Exactly 2,100,000 against exactly 420, whatever else has accrued since.
    // The opening price was published with the schedule; pairing everything in
    // the pot would make it depend on how long the grace period happened to be
    // busy, which is not a price anyone can prepare for. The surplus stays in
    // the pot as buyback reserve (§71.5).
    // Both sides move from the keyless pots to the treasury, which then opens
    // the pool and therefore holds the LP shares. §71.27: this liquidity is
    // withdrawable by 2-of-3 — deliberate, and the one part of the protocol's
    // holdings that is.
    let treasury = crate::types::TREASURY_26460;
    state
        .account_mut(&crate::types::ZYN_POL_ZYN)
        .debit(zyn, POL_ZYN_CAP)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&crate::types::ZYN_POL)
        .debit(XZEC, zec_side)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&treasury)
        .credit(zyn, POL_ZYN_CAP)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&treasury)
        .credit(XZEC, zec_side)
        .ok_or(Reject::ArithmeticFailure)?;

    let (a0, a1) = if zyn < XZEC { (zyn, XZEC) } else { (XZEC, zyn) };
    let (m0, m1) = if zyn < XZEC {
        (POL_ZYN_CAP, zec_side)
    } else {
        (zec_side, POL_ZYN_CAP)
    };
    let fee_bps = state.params.default_fee_bps;
    let mut out = crate::vm::create_pool_for(state, treasury, a0, a1, m0, m1, fee_bps)?;
    let pool = zyn_vm::pool_address(crate::types::ADDRESS_SCOPE_V1, &a0, &a1);
    out.push(Receipt::MarketOpened {
        asset: zyn,
        pool,
        zec: zec_side,
        amount: POL_ZYN_CAP,
        price: POL_ZEC_PER_ZYN,
        grant: Fixed::ZERO,
    });
    Ok(out)
}

/// Everything the launch does at a seal, in order.
pub fn tick(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let mut out = Vec::new();
    if state.launch.is_none() {
        return Ok(out);
    }
    if !state.launch.as_ref().unwrap().graduated() {
        if let Some(r) = maybe_graduate(state)? {
            out.push(r);
        }
        return Ok(out);
    }
    out.extend(mint(state)?);
    release_vesting(state)?;
    out.extend(pay_lp_rewards(state)?);
    out.extend(pay_rebates(state)?);
    // A market that does not exist yet has first call on the protocol's
    // ZEC.zy; deepening the ZYN pool comes after.
    out.extend(open_markets(state)?);
    out.extend(use_fees(state)?);
    Ok(out)
}

fn maybe_graduate(state: &mut SwapState) -> Result<Option<Receipt>, Reject> {
    let (threshold, deadline, height) = {
        let l = state.launch.as_ref().unwrap();
        (l.params.threshold, l.params.deadline_height, l.zcash_height)
    };
    let pot = state.balance(&POT_GENESIS, XZEC);
    let due = pot >= threshold || (deadline > 0 && height >= deadline && pot.is_positive());
    if !due || height == 0 {
        return Ok(None);
    }
    let params = state.launch.as_ref().unwrap().params;

    // The asset.
    let zyn = zyn_vm::native_address(crate::types::ADDRESS_SCOPE_V1, state.chain_id, b"ZYN");
    if state.tokens.contains_key(&zyn) {
        return Err(Reject::DuplicateSymbol);
    }
    state
        .tokens
        .insert(zyn, TokenInfo::divisible(symbol(b"ZYN"), Fixed::ZERO));

    // Half the genesis into the pool with the whole pot; the protocol holds
    // the shares and has no key to move them.
    let to_pool = bps(params.genesis, 5_000).ok_or(Reject::ArithmeticFailure)?;
    let to_users = params
        .genesis
        .sub(to_pool)
        .ok_or(Reject::ArithmeticFailure)?;
    state.mint(zyn, to_pool).ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_POL)
        .credit(zyn, to_pool)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_GENESIS)
        .debit(XZEC, pot)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_POL)
        .credit(XZEC, pot)
        .ok_or(Reject::ArithmeticFailure)?;
    let receipts =
        crate::vm::create_pool_for(state, POT_POL, zyn, XZEC, to_pool, pot, params.pool_fee_bps)?;
    let pool = receipts
        .iter()
        .find_map(|r| match r {
            Receipt::PoolCreated { pool, .. } => Some(*pool),
            _ => None,
        })
        .ok_or(Reject::ArithmeticFailure)?;

    // The other half to the contributors, vesting by height.
    let contributions = state.launch.as_ref().unwrap().contributions.clone();
    let total: Fixed = contributions
        .values()
        .try_fold(Fixed::ZERO, |a, v| a.add(*v))
        .ok_or(Reject::ArithmeticFailure)?;
    let mut vesting = BTreeMap::new();
    let mut granted = Fixed::ZERO;
    if total.is_positive() {
        for (account, paid) in &contributions {
            let share = to_users
                .mul_div(*paid, total)
                .ok_or(Reject::ArithmeticFailure)?;
            if share.is_positive() {
                vesting.insert(
                    (*account, [0u8; 32]),
                    Vest {
                        total: share,
                        released: Fixed::ZERO,
                        start: height,
                        end: height + params.vesting_blocks,
                    },
                );
                granted = granted.add(share).ok_or(Reject::ArithmeticFailure)?;
            }
        }
    }
    // Vesting units exist from now: minted into the LP pot's custody and
    // paid out from there as they vest, so supply and holdings agree.
    state.mint(zyn, granted).ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_LP)
        .credit(zyn, granted)
        .ok_or(Reject::ArithmeticFailure)?;

    let l = state.launch.as_mut().unwrap();
    l.graduated_at = height;
    l.zyn = zyn;
    l.genesis_pool = pool;
    l.minted = to_pool.add(granted).ok_or(Reject::ArithmeticFailure)?;
    l.last_mint_height = height;
    l.vesting = vesting;
    l.contributions.clear();
    let price = pot.div(to_pool).unwrap_or(Fixed::ZERO);
    Ok(Some(Receipt::Graduated {
        pool,
        zyn,
        pot,
        price,
        contributors: contributions.len() as u32,
    }))
}

/// Emission for the blocks since the last mint, at the current halving.
fn mint(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let (height, last, grad, params, minted, zyn) = {
        let l = state.launch.as_ref().unwrap();
        (
            l.zcash_height,
            l.last_mint_height,
            l.graduated_at,
            l.params,
            l.minted,
            l.zyn,
        )
    };
    if height <= last {
        return Ok(Vec::new());
    }
    let blocks = height - last;
    let halvings = (height - grad) / params.halving_blocks;
    let rate = if halvings >= 64 {
        Fixed::ZERO
    } else {
        Fixed::raw(params.rate0.0 >> halvings)
    };
    let mut amount = rate
        .mul(Fixed::whole(blocks as i64))
        .ok_or(Reject::ArithmeticFailure)?;
    let room = params.cap.sub(minted).ok_or(Reject::ArithmeticFailure)?;
    if amount > room {
        amount = room;
    }
    let l = state.launch.as_mut().unwrap();
    l.last_mint_height = height;
    if !amount.is_positive() {
        return Ok(Vec::new());
    }
    l.minted = l.minted.add(amount).ok_or(Reject::ArithmeticFailure)?;
    let to_lp = bps(amount, params.split_lp_bps).ok_or(Reject::ArithmeticFailure)?;
    let to_bridge = bps(amount, params.split_bridge_bps).ok_or(Reject::ArithmeticFailure)?;
    let to_pol = amount
        .sub(to_lp)
        .and_then(|a| a.sub(to_bridge))
        .ok_or(Reject::ArithmeticFailure)?;
    state.mint(zyn, amount).ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_LP)
        .credit(zyn, to_lp)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_BRIDGE)
        .credit(zyn, to_bridge)
        .ok_or(Reject::ArithmeticFailure)?;
    state
        .account_mut(&POT_POL)
        .credit(zyn, to_pol)
        .ok_or(Reject::ArithmeticFailure)?;
    Ok(vec![Receipt::Minted {
        amount,
        height,
        to_lp,
        to_bridge,
        to_pol,
    }])
}

/// Contributors' genesis ZYN, released linearly by height from the LP pot.
fn release_vesting(state: &mut SwapState) -> Result<(), Reject> {
    let (height, zyn, vesting) = {
        let l = state.launch.as_ref().unwrap();
        (l.zcash_height, l.zyn, l.vesting.clone())
    };
    let mut updated = vesting.clone();
    for ((account, from), v) in vesting {
        let at = height.min(v.end);
        if at <= v.start {
            continue;
        }
        let due = v
            .total
            .mul_div(
                Fixed::whole((at - v.start) as i64),
                Fixed::whole((v.end - v.start) as i64),
            )
            .ok_or(Reject::ArithmeticFailure)?;
        let now = due.sub(v.released).ok_or(Reject::ArithmeticFailure)?;
        if !now.is_positive() {
            continue;
        }
        if state.account_mut(&POT_LP).debit(zyn, now).is_none() {
            continue;
        }
        state
            .account_mut(&account)
            .credit(zyn, now)
            .ok_or(Reject::ArithmeticFailure)?;
        let nv = Vest { released: due, ..v };
        if nv.released >= nv.total {
            updated.remove(&(account, from));
        } else {
            updated.insert((account, from), nv);
        }
    }
    state.launch.as_mut().unwrap().vesting = updated;
    Ok(())
}

/// The LP pot, less what is still vesting, to LPs by the fees their pools
/// earned this epoch and their share of those pools.
fn pay_lp_rewards(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let (zyn, pool_fees, reserved) = {
        let l = state.launch.as_ref().unwrap();
        let reserved: Fixed = l
            .vesting
            .values()
            .try_fold(Fixed::ZERO, |a, v| a.add(v.total.sub(v.released)?))
            .ok_or(Reject::ArithmeticFailure)?;
        (l.zyn, l.epoch_pool_fees.clone(), reserved)
    };
    state.launch.as_mut().unwrap().epoch_pool_fees.clear();
    let available = state
        .balance(&POT_LP, zyn)
        .sub(reserved)
        .ok_or(Reject::ArithmeticFailure)?;
    let total_fees: Fixed = pool_fees
        .values()
        .try_fold(Fixed::ZERO, |a, v| a.add(*v))
        .ok_or(Reject::ArithmeticFailure)?;
    if !available.is_positive() || !total_fees.is_positive() {
        return Ok(Vec::new());
    }
    let mut paid = Fixed::ZERO;
    for (pool_id, fee) in pool_fees {
        let Some(pool) = state.pools.get(&pool_id) else {
            continue;
        };
        let (lp_asset, supply) = (pool.lp_asset, pool.lp_supply);
        let for_pool = available
            .mul_div(fee, total_fees)
            .ok_or(Reject::ArithmeticFailure)?;
        if !for_pool.is_positive() || !supply.is_positive() {
            continue;
        }
        // Holders of this pool's shares; pots hold shares too and are skipped,
        // so their part stays in the LP pot for the next epoch.
        let holders: Vec<(AccountId, Fixed)> = state
            .accounts
            .iter()
            .filter(|(id, _)| !is_pot(id))
            .filter_map(|(id, a)| {
                let b = a.balance(lp_asset);
                b.is_positive().then_some((*id, b))
            })
            .collect();
        for (id, shares) in holders {
            let reward = for_pool
                .mul_div(shares, supply)
                .ok_or(Reject::ArithmeticFailure)?;
            if !reward.is_positive() {
                continue;
            }
            if state.account_mut(&POT_LP).debit(zyn, reward).is_none() {
                continue;
            }
            state
                .account_mut(&id)
                .credit(zyn, reward)
                .ok_or(Reject::ArithmeticFailure)?;
            paid = paid.add(reward).ok_or(Reject::ArithmeticFailure)?;
        }
    }
    Ok(if paid.is_positive() {
        vec![Receipt::LpRewardsPaid { amount: paid }]
    } else {
        Vec::new()
    })
}

/// The bridge pot to this epoch's fee payers, pro rata.
fn pay_rebates(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let (zyn, fees) = {
        let l = state.launch.as_ref().unwrap();
        (l.zyn, l.epoch_bridge_fees.clone())
    };
    state.launch.as_mut().unwrap().epoch_bridge_fees.clear();
    let available = state.balance(&POT_BRIDGE, zyn);
    let total: Fixed = fees
        .values()
        .try_fold(Fixed::ZERO, |a, v| a.add(*v))
        .ok_or(Reject::ArithmeticFailure)?;
    if !available.is_positive() || !total.is_positive() {
        return Ok(Vec::new());
    }
    let mut paid = Fixed::ZERO;
    for (id, fee) in fees {
        if is_pot(&id) {
            continue;
        }
        let reward = available
            .mul_div(fee, total)
            .ok_or(Reject::ArithmeticFailure)?;
        if !reward.is_positive() {
            continue;
        }
        if state.account_mut(&POT_BRIDGE).debit(zyn, reward).is_none() {
            continue;
        }
        state
            .account_mut(&id)
            .credit(zyn, reward)
            .ok_or(Reject::ArithmeticFailure)?;
        paid = paid.add(reward).ok_or(Reject::ArithmeticFailure)?;
    }
    Ok(if paid.is_positive() {
        vec![Receipt::RebatesPaid { amount: paid }]
    } else {
        Vec::new()
    })
}

/// This epoch's bridge fees: part bought into ZYN on the genesis pool and
/// burned, the rest paired with pot ZYN as liquidity the protocol holds.
fn use_fees(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let (zyn, pool, params) = {
        let l = state.launch.as_ref().unwrap();
        (l.zyn, l.genesis_pool, l.params)
    };
    let fees = state.balance(&POT_FEES, XZEC);
    if !fees.is_positive() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let to_burn = bps(fees, params.fee_burn_bps).ok_or(Reject::ArithmeticFailure)?;
    let to_pair = fees.sub(to_burn).ok_or(Reject::ArithmeticFailure)?;
    if to_burn.is_positive() {
        if let Ok(r) = crate::vm::swap_now(state, POT_FEES, XZEC, &[pool], to_burn, Fixed::ZERO) {
            let got = r
                .iter()
                .find_map(|x| match x {
                    Receipt::Swapped { amount_out, .. } => Some(*amount_out),
                    _ => None,
                })
                .unwrap_or(Fixed::ZERO);
            if got.is_positive() {
                state
                    .account_mut(&POT_FEES)
                    .debit(zyn, got)
                    .ok_or(Reject::ArithmeticFailure)?;
                state.burn(zyn, got).ok_or(Reject::ArithmeticFailure)?;
                out.push(Receipt::Burned {
                    zyn: got,
                    zec: to_burn,
                });
            }
        }
    }
    if to_pair.is_positive() {
        state
            .account_mut(&POT_FEES)
            .debit(XZEC, to_pair)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&POT_POL)
            .credit(XZEC, to_pair)
            .ok_or(Reject::ArithmeticFailure)?;
        // As much pot ZYN as the pool's ratio wants for this ZEC; whatever
        // does not fit stays in the pot for a later epoch. ZEC a pending
        // market is waiting on is held back — opening one beats deepening
        // the one that exists.
        let reserved = reserved_zec(state)?;
        let (have_zyn, have_zec) = (
            state.balance(&POT_POL, zyn),
            state
                .balance(&POT_POL, XZEC)
                .sub(reserved)
                .ok_or(Reject::ArithmeticFailure)?
                .max(Fixed::ZERO),
        );
        if have_zyn.is_positive() && have_zec.is_positive() {
            let (max0, max1) = if zyn < XZEC {
                (have_zyn, have_zec)
            } else {
                (have_zec, have_zyn)
            };
            if let Ok(r) =
                crate::vm::add_liquidity_for(state, POT_POL, pool, max0, max1, Fixed::ZERO)
            {
                if let Some((a0, a1)) = r.iter().find_map(|x| match x {
                    Receipt::LiquidityAdded {
                        amount0, amount1, ..
                    } => Some((*amount0, *amount1)),
                    _ => None,
                }) {
                    out.push(Receipt::LiquidityPaired {
                        amount0: a0,
                        amount1: a1,
                    });
                }
            }
        }
    }
    Ok(out)
}

/// ZEC.zy the protocol is saving for markets that have not opened yet: for
/// each, what its pot is worth at a fresh reference, never more than the
/// threshold it is aiming at.
fn reserved_zec(state: &SwapState) -> Result<Fixed, Reject> {
    let Some(l) = state.launch.as_ref() else {
        return Ok(Fixed::ZERO);
    };
    let (seq, staleness, threshold) = (
        state.seq,
        state.params.reference_staleness,
        l.params.asset_threshold,
    );
    let mut sum = Fixed::ZERO;
    for (asset, a) in &l.assets {
        if a.opened_at > 0 {
            continue;
        }
        let Some(r) = a.reference.filter(|r| r.is_fresh(seq, staleness)) else {
            continue;
        };
        let pot = state.balance(&POT_ASSETS, *asset);
        if !pot.is_positive() {
            continue;
        }
        let want = pot
            .div(r.price)
            .ok_or(Reject::ArithmeticFailure)?
            .min(threshold);
        sum = sum.add(want).ok_or(Reject::ArithmeticFailure)?;
    }
    Ok(sum)
}

/// Open a market for any bridged asset whose pot is big enough, and deepen
/// the ones that are already open.
///
/// A pool opens at the reference price exactly, because the divergence fee
/// (§5.7) makes whatever price it opens at permanent. The protocol keeps the
/// shares, so the market cannot be taken away from the people it was opened
/// for. Its contributors share `bootstrap_bps` of the ZYN still unminted.
fn open_markets(state: &mut SwapState) -> Result<Vec<Receipt>, Reject> {
    let (seq, staleness) = (state.seq, state.params.reference_staleness);
    let (params, zyn, minted) = {
        let l = state.launch.as_ref().unwrap();
        (l.params, l.zyn, l.minted)
    };
    // Every asset with a pot, and every asset with a launch record: a pot
    // can exist for an asset that already had a market and so never opened
    // one here, and that pot still has to reach the pool.
    let mut candidates: Vec<AssetId> = state
        .launch
        .as_ref()
        .unwrap()
        .assets
        .keys()
        .copied()
        .collect();
    if let Some(pot_account) = state.accounts.get(&POT_ASSETS) {
        for asset in pot_account.balances.keys() {
            if *asset != XZEC && !candidates.contains(asset) {
                candidates.push(*asset);
            }
        }
    }
    candidates.sort_unstable();
    let mut out = Vec::new();
    let mut minted = minted;
    for asset in candidates {
        let pot = state.balance(&POT_ASSETS, asset);
        if !pot.is_positive() {
            continue;
        }
        let a = state
            .launch
            .as_ref()
            .unwrap()
            .assets
            .get(&asset)
            .cloned()
            .unwrap_or_default();
        // An asset that already has a market: its fees deepen it, at the
        // pool's own ratio, with whatever protocol ZEC.zy is spare.
        if let Some(pool) = state.find_pool(XZEC, asset) {
            // A market that exists — opened here or before the launch — is
            // recorded as open, so nothing accrues toward a grant for it.
            {
                let l = state.launch.as_mut().unwrap();
                let e = l.assets.entry(asset).or_default();
                if e.opened_at == 0 {
                    e.opened_at = l.zcash_height.max(1);
                    e.pool = pool;
                    e.contributions.clear();
                }
            }
            let have = state.balance(&POT_POL, XZEC);
            if !have.is_positive() {
                continue;
            }
            state
                .account_mut(&POT_ASSETS)
                .debit(asset, pot)
                .ok_or(Reject::ArithmeticFailure)?;
            state
                .account_mut(&POT_POL)
                .credit(asset, pot)
                .ok_or(Reject::ArithmeticFailure)?;
            let held = state.balance(&POT_POL, asset);
            let (max0, max1) = if XZEC < asset {
                (have, held)
            } else {
                (held, have)
            };
            if let Ok(r) =
                crate::vm::add_liquidity_for(state, POT_POL, pool, max0, max1, Fixed::ZERO)
            {
                if let Some((a0, a1)) = r.iter().find_map(|x| match x {
                    Receipt::LiquidityAdded {
                        amount0, amount1, ..
                    } => Some((*amount0, *amount1)),
                    _ => None,
                }) {
                    out.push(Receipt::LiquidityPaired {
                        amount0: a0,
                        amount1: a1,
                    });
                }
            }
            continue;
        }
        // A market that has not opened: it needs a fresh price and enough
        // ZEC.zy on both counts before anything happens.
        if a.opened_at > 0 || zyn == [0u8; 32] {
            continue;
        }
        let Some(r) = a.reference.filter(|r| r.is_fresh(seq, staleness)) else {
            continue;
        };
        let zec_needed = pot.div(r.price).ok_or(Reject::ArithmeticFailure)?;
        if zec_needed < params.asset_threshold || state.balance(&POT_POL, XZEC) < zec_needed {
            continue;
        }
        state
            .account_mut(&POT_ASSETS)
            .debit(asset, pot)
            .ok_or(Reject::ArithmeticFailure)?;
        state
            .account_mut(&POT_POL)
            .credit(asset, pot)
            .ok_or(Reject::ArithmeticFailure)?;
        let receipts = crate::vm::create_pool_for(
            state,
            POT_POL,
            XZEC,
            asset,
            zec_needed,
            pot,
            params.pool_fee_bps,
        )?;
        let pool = receipts
            .iter()
            .find_map(|x| match x {
                Receipt::PoolCreated { pool, .. } => Some(*pool),
                _ => None,
            })
            .ok_or(Reject::ArithmeticFailure)?;
        // The reference goes onto the pool at once, so it opens defended.
        state
            .pools
            .get_mut(&pool)
            .ok_or(Reject::ArithmeticFailure)?
            .reference = Some(r);

        // The opening grant: a slice of what ZYN is still unminted, so each
        // market costs less than the one before and the cap always holds.
        let grant = bps(
            params.cap.sub(minted).ok_or(Reject::ArithmeticFailure)?,
            params.bootstrap_bps,
        )
        .ok_or(Reject::ArithmeticFailure)?;
        let total: Fixed = a
            .contributions
            .values()
            .try_fold(Fixed::ZERO, |acc, v| acc.add(*v))
            .ok_or(Reject::ArithmeticFailure)?;
        let mut granted = Fixed::ZERO;
        let mut vests = Vec::new();
        if grant.is_positive() && total.is_positive() {
            let height = state.launch.as_ref().unwrap().zcash_height;
            for (account, paid) in &a.contributions {
                let share = grant
                    .mul_div(*paid, total)
                    .ok_or(Reject::ArithmeticFailure)?;
                if share.is_positive() {
                    vests.push((
                        (*account, asset),
                        Vest {
                            total: share,
                            released: Fixed::ZERO,
                            start: height,
                            end: height + params.vesting_blocks,
                        },
                    ));
                    granted = granted.add(share).ok_or(Reject::ArithmeticFailure)?;
                }
            }
        }
        if granted.is_positive() {
            state.mint(zyn, granted).ok_or(Reject::ArithmeticFailure)?;
            state
                .account_mut(&POT_LP)
                .credit(zyn, granted)
                .ok_or(Reject::ArithmeticFailure)?;
            minted = minted.add(granted).ok_or(Reject::ArithmeticFailure)?;
        }
        let height = state.launch.as_ref().unwrap().zcash_height;
        let l = state.launch.as_mut().unwrap();
        l.minted = minted;
        for (k, v) in vests {
            l.vesting.insert(k, v);
        }
        let entry = l.assets.entry(asset).or_default();
        entry.opened_at = height.max(1);
        entry.pool = pool;
        entry.grant = granted;
        entry.contributions.clear();
        out.push(Receipt::MarketOpened {
            asset,
            pool,
            zec: zec_needed,
            amount: pot,
            price: r.price,
            grant: granted,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{Intent, SequencedIntent};
    use crate::types::Params;
    use crate::vm::apply;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];

    fn go(s: &mut SwapState, i: Intent) -> Vec<Receipt> {
        let at = s.seq + 1;
        apply(s, &SequencedIntent { seq: at, intent: i })
    }

    fn params() -> Launch {
        Launch {
            threshold: Fixed::whole(5),
            vesting_blocks: 1_000,
            halving_blocks: 1_000,
            asset_threshold: Fixed::raw(10_000_000_000_000_000),
            ..Launch::v1()
        }
    }

    /// A launch set, the clock at 1000, and two depositors of 1,000 ZEC each.
    fn chain() -> SwapState {
        let mut s = SwapState::new(7, Params::v1());
        assert!(matches!(
            go(&mut s, Intent::SetLaunch { params: params() })[0],
            Receipt::LaunchSet
        ));
        go(&mut s, Intent::ZcashHeight { height: 1_000 });
        let amount = Fixed::whole(1_000);
        let observed = s
            .backing_of(XZEC)
            .add(amount)
            .unwrap()
            .add(amount)
            .unwrap()
            .add(amount)
            .unwrap();
        go(
            &mut s,
            Intent::AttestVaultBalance {
                asset: XZEC,
                observed,
            },
        );
        let d = Intent::next_deposit(&s, A, XZEC, amount, [0u8; 32]);
        go(&mut s, d);
        let d = Intent::next_deposit(&s, B, XZEC, amount, [9u8; 32]);
        go(&mut s, d);
        s
    }

    fn seal_and_anchor(s: &mut SwapState) -> Vec<Receipt> {
        let epoch = s.epoch;
        let r = go(s, Intent::Checkpoint);
        go(s, Intent::ConfirmAnchor { epoch });
        r
    }

    #[test]
    fn deposit_and_exit_fees_fill_the_pot_and_are_remembered() {
        let mut s = chain();
        // Nothing graduates yet: the pot is unreleased until anchored, and a
        // fresh seal sees no ZEC in it.
        seal_and_anchor(&mut s);
        assert_eq!(
            s.balance(&A, XZEC),
            Fixed::whole(995),
            "50 bps came off the deposit"
        );
        assert_eq!(
            s.balance(&POT_GENESIS, XZEC),
            Fixed::whole(10),
            "both fees, released with the deposits"
        );
        let l = s.launch.as_ref().unwrap();
        assert_eq!(l.contributions[&A], Fixed::whole(5));
        assert!(
            !l.graduated(),
            "the pot only fills at the anchor; graduation is the next seal's"
        );
        s.check_invariants().unwrap();

        // An exit pays too, out of what is asked for.
        let r = go(
            &mut s,
            Intent::RequestWithdrawal {
                account: A,
                asset: XZEC,
                amount: Fixed::whole(100),
                destination: [0u8; 32],
            },
        );
        assert!(
            matches!(r[0], Receipt::WithdrawalRequested { pending, .. } if pending == Fixed::raw(99_500_000_000_000_000_000)),
            "{:?}",
            r[0]
        );
        assert_eq!(
            s.balance(&POT_GENESIS, XZEC),
            Fixed::raw(10_500_000_000_000_000_000)
        );
        s.check_invariants().unwrap();
    }

    #[test]
    fn graduation_creates_the_pool_and_the_vesting() {
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        let r = go(&mut s, Intent::Checkpoint);
        let g = r
            .iter()
            .find(|x| matches!(x, Receipt::Graduated { .. }))
            .expect("graduated");
        let (pool, zyn) = match g {
            Receipt::Graduated {
                pool,
                zyn,
                pot,
                contributors,
                ..
            } => {
                assert_eq!(*pot, Fixed::whole(10));
                assert_eq!(*contributors, 2);
                (*pool, *zyn)
            }
            _ => unreachable!(),
        };
        let p = &s.pools[&pool];
        assert_eq!((p.asset0, p.asset1), (XZEC.min(zyn), XZEC.max(zyn)));
        let zyn_reserve = if p.asset0 == zyn {
            p.reserve0
        } else {
            p.reserve1
        };
        assert_eq!(
            zyn_reserve,
            Fixed::whole(1_050_000),
            "half the genesis is in the pool"
        );
        assert!(
            s.balance(&POT_POL, p.lp_asset).is_positive(),
            "the protocol holds the shares"
        );
        assert_eq!(
            s.balance(&POT_GENESIS, XZEC),
            Fixed::ZERO,
            "the pot went into the pool"
        );
        let l = s.launch.as_ref().unwrap();
        assert!(l.graduated());
        assert_eq!(
            l.vesting[&(A, crate::types::legacy_id(0))].total,
            Fixed::whole(525_000),
            "equal fees, equal halves of the other half"
        );
        assert_eq!(s.tokens[&zyn].supply, Fixed::whole(2_100_000));
        assert_eq!(l.minted, Fixed::whole(2_100_000));
        s.check_invariants().unwrap();
    }

    #[test]
    fn emission_by_height_halves_and_caps() {
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        go(&mut s, Intent::Checkpoint); // graduates at 1100
        go(&mut s, Intent::ZcashHeight { height: 1_200 });
        let r = go(&mut s, Intent::Checkpoint);
        let m = r
            .iter()
            .find(|x| matches!(x, Receipt::Minted { .. }))
            .expect("minted");
        match m {
            Receipt::Minted {
                amount,
                to_lp,
                to_bridge,
                to_pol,
                ..
            } => {
                assert_eq!(*amount, Fixed::whole(900), "9 per block for 100 blocks");
                assert_eq!(
                    (*to_lp, *to_bridge, *to_pol),
                    (Fixed::whole(450), Fixed::whole(225), Fixed::whole(225))
                );
            }
            _ => unreachable!(),
        }
        // Past the first halving the rate is 4.5.
        go(&mut s, Intent::ZcashHeight { height: 2_200 });
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ZcashHeight { height: 2_300 });
        let r = go(&mut s, Intent::Checkpoint);
        let amount = r
            .iter()
            .find_map(|x| match x {
                Receipt::Minted { amount, .. } => Some(*amount),
                _ => None,
            })
            .unwrap();
        assert_eq!(amount, Fixed::whole(450));
        let l = s.launch.as_ref().unwrap();
        assert!(l.minted <= l.params.cap);
        s.check_invariants().unwrap();
    }

    #[test]
    fn vesting_releases_by_height() {
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        go(&mut s, Intent::Checkpoint);
        assert_eq!(
            s.balance(&A, s.launch.as_ref().unwrap().zyn),
            Fixed::ZERO,
            "nothing yet"
        );
        go(&mut s, Intent::ZcashHeight { height: 1_600 });
        go(&mut s, Intent::Checkpoint);
        let zyn = s.launch.as_ref().unwrap().zyn;
        assert_eq!(
            s.balance(&A, zyn),
            Fixed::whole(262_500),
            "half way through, half released"
        );
        go(&mut s, Intent::ZcashHeight { height: 5_000 });
        go(&mut s, Intent::Checkpoint);
        assert_eq!(
            s.balance(&A, zyn),
            Fixed::whole(525_000),
            "and all of it after the end"
        );
        assert!(s.launch.as_ref().unwrap().vesting.is_empty());
        s.check_invariants().unwrap();
    }

    #[test]
    fn rewards_rebates_burn_and_pairing_happen_at_the_seal() {
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        go(&mut s, Intent::Checkpoint);
        let (zyn, pool) = {
            let l = s.launch.as_ref().unwrap();
            (l.zyn, l.genesis_pool)
        };
        let lp_asset = s.pools[&pool].lp_asset;
        let supply_before = s.tokens[&zyn].supply;

        // A becomes an LP; B swaps (pays fees) and exits (pays a bridge fee).
        go(&mut s, Intent::ZcashHeight { height: 1_600 }); // releases half of A's vesting: ZYN to pair
        go(&mut s, Intent::Checkpoint);
        let r = go(
            &mut s,
            Intent::AddLiquidity {
                account: A,
                pool,
                max0: Fixed::whole(10),
                max1: Fixed::whole(10),
                min_shares: Fixed::ZERO,
            },
        );
        assert!(matches!(r[0], Receipt::LiquidityAdded { .. }), "{:?}", r[0]);
        assert!(s.balance(&A, lp_asset).is_positive());
        go(
            &mut s,
            Intent::SwapExactIn {
                account: B,
                asset_in: XZEC,
                path: vec![pool],
                amount_in: Fixed::whole(50),
                min_out: Fixed::ZERO,
            },
        );
        go(
            &mut s,
            Intent::RequestWithdrawal {
                account: B,
                asset: XZEC,
                amount: Fixed::whole(100),
                destination: [0u8; 32],
            },
        );
        assert_eq!(
            s.balance(&POT_FEES, XZEC),
            Fixed::raw(500_000_000_000_000_000),
            "0.5 ZEC fee waits in the fee pot"
        );

        let b_zyn_before = s.balance(&B, zyn);
        let a_zyn_before = s.balance(&A, zyn);
        let pol_shares_before = s.balance(&POT_POL, lp_asset);
        go(&mut s, Intent::ZcashHeight { height: 1_700 });
        let r = go(&mut s, Intent::Checkpoint);
        assert!(
            r.iter().any(|x| matches!(x, Receipt::LpRewardsPaid { .. })),
            "{:?}",
            r
        );
        assert!(
            r.iter().any(|x| matches!(x, Receipt::RebatesPaid { .. })),
            "{:?}",
            r
        );
        assert!(
            r.iter().any(|x| matches!(x, Receipt::Burned { .. })),
            "{:?}",
            r
        );
        assert!(
            r.iter()
                .any(|x| matches!(x, Receipt::LiquidityPaired { .. })),
            "{:?}",
            r
        );
        assert!(
            s.balance(&B, zyn) > b_zyn_before,
            "B paid a bridge fee and got ZYN back"
        );
        assert!(
            s.balance(&A, zyn) > a_zyn_before,
            "A's pool earned fees and A got ZYN"
        );
        assert!(
            s.balance(&POT_POL, lp_asset) > pol_shares_before,
            "the protocol's position grew"
        );
        let minted = s.launch.as_ref().unwrap().minted;
        assert!(
            s.tokens[&zyn].supply < minted,
            "burned: supply is below what was minted ({} < {})",
            s.tokens[&zyn].supply,
            minted
        );
        assert!(
            s.tokens[&zyn].supply > supply_before,
            "but emission outran the burn"
        );
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_pot_below_the_launch_bond_still_graduates_and_a_partial_attempt_is_undone() {
        let mut s = chain();
        // Threshold under the 1 ZEC user bond: the pot is the bond.
        let mut p = params();
        p.threshold = Fixed::raw(100_000_000_000_000);
        go(&mut s, Intent::SetLaunch { params: p });
        seal_and_anchor(&mut s);
        // Fake the damage an earlier, non-atomic attempt did: pot moved, ZYN minted.
        let pot = s.balance(&POT_GENESIS, XZEC);
        s.account_mut(&POT_GENESIS).debit(XZEC, pot).unwrap();
        s.account_mut(&POT_POL).credit(XZEC, pot).unwrap();
        let zyn = zyn_vm::native_address(crate::types::ADDRESS_SCOPE_V1, s.chain_id, b"ZYN");
        s.tokens
            .insert(zyn, TokenInfo::divisible(symbol(b"ZYN"), Fixed::ZERO));
        s.mint(zyn, Fixed::whole(5)).unwrap();
        s.account_mut(&POT_POL)
            .credit(zyn, Fixed::whole(5))
            .unwrap();
        s.check_invariants().unwrap();
        // Re-setting the numbers cleans it up.
        assert!(matches!(
            go(&mut s, Intent::SetLaunch { params: p })[0],
            Receipt::LaunchSet
        ));
        assert_eq!(s.balance(&POT_GENESIS, XZEC), pot);
        assert!(!s.tokens.contains_key(&zyn), "the stray ZYN token is gone");
        s.check_invariants().unwrap();
        // And graduation goes through despite the pot being under the user bond.
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        let r = go(&mut s, Intent::Checkpoint);
        assert!(
            r.iter().any(|x| matches!(x, Receipt::Graduated { .. })),
            "{:?}",
            r
        );
        assert!(!r.iter().any(|x| matches!(x, Receipt::LaunchSkipped { .. })));
        s.check_invariants().unwrap();
    }

    // ---- bridged-asset markets -------------------------------------------

    /// A chain past ZYN graduation, with a second bridged asset that has a
    /// pot, a reference, and protocol ZEC.zy saved up for it.
    fn with_asset() -> (SwapState, AssetId) {
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        go(&mut s, Intent::Checkpoint); // ZYN graduates
        let r = go(
            &mut s,
            Intent::CreateBridgedAsset {
                symbol: symbol(b"SOL.zy"),
                origin: 2,
                origin_network: b"solana".to_vec(),
                origin_asset: Vec::new(),
            },
        );
        let sol = match r[0] {
            Receipt::BridgedAssetCreated { asset, .. } => asset,
            _ => panic!("{:?}", r),
        };
        assert_eq!(
            sol,
            crate::types::SOL_ZY,
            "bridge creation must reproduce the published SOL.zy address"
        );
        // 200 SOL bridged in: the fee is 1 SOL into the pot.
        go(
            &mut s,
            Intent::AttestVaultBalance {
                asset: sol,
                observed: Fixed::whole(1_000),
            },
        );
        let d = Intent::next_deposit(&s, B, sol, Fixed::whole(200), [7u8; 32]);
        go(&mut s, d);
        // A price for it: 10 SOL to the ZEC.
        go(
            &mut s,
            Intent::UpdateAssetReference {
                asset: sol,
                price: Fixed::whole(10),
            },
        );
        seal_and_anchor(&mut s);
        (s, sol)
    }

    /// An asset whose market already existed still pays into a pot, and that
    /// pot must reach the pool rather than sit there: the first live run of
    /// this missed it, because only assets with a launch record were looked at.
    #[test]
    fn a_pot_for_an_asset_that_already_has_a_market_is_paired_into_it() {
        let (mut s, sol) = with_asset();
        // Give it a market by hand, as a chain that predates the launch has.
        let d = Intent::next_deposit(&s, A, sol, Fixed::whole(100), [31u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(
            &mut s,
            Intent::CreatePool {
                creator: A,
                asset_a: XZEC,
                asset_b: sol,
                amount_a: Fixed::whole(2),
                amount_b: Fixed::whole(20),
                fee_bps: 30,
            },
        );
        let pool = s.find_pool(XZEC, sol).expect("pool");
        let before = s.pools[&pool].reserve1;
        assert!(
            s.balance(&POT_ASSETS, sol).is_positive(),
            "its fees are in the pot"
        );
        // The protocol has ZEC.zy to pair with.
        let d = Intent::next_deposit(&s, POT_POL, XZEC, Fixed::whole(1), [32u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_200 });
        go(&mut s, Intent::Checkpoint);
        assert!(
            s.pools[&pool].reserve1 > before,
            "the pot deepened the market it belongs to"
        );
        assert_eq!(s.balance(&POT_ASSETS, sol), Fixed::ZERO, "and left the pot");
        let a = &s.launch.as_ref().unwrap().assets[&sol];
        assert!(
            a.opened_at > 0 && a.grant == Fixed::ZERO,
            "a market that already existed earns no grant"
        );
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_bridged_asset_pays_into_its_own_pot_and_still_earns_the_rebate() {
        let (mut s, sol) = with_asset();
        assert_eq!(
            s.balance(&POT_ASSETS, sol),
            Fixed::whole(1),
            "50 bps of 200 SOL"
        );
        assert_eq!(s.balance(&B, sol), Fixed::whole(199));
        assert_eq!(
            s.launch.as_ref().unwrap().assets[&sol].contributions[&B],
            Fixed::whole(1)
        );
        // The rebate book is emptied at every seal, so pay another fee and
        // look before the next one: a bootstrapper earns the rebate too.
        let d = Intent::next_deposit(&s, B, sol, Fixed::whole(100), [21u8; 32]);
        go(&mut s, d);
        let l = s.launch.as_ref().unwrap();
        assert_eq!(
            l.epoch_bridge_fees[&B],
            Fixed::raw(500_000_000_000_000_000),
            "0.5 SOL of fee counts for the rebate"
        );
        assert_eq!(
            l.assets[&sol].contributions[&B],
            Fixed::raw(1_500_000_000_000_000_000),
            "and for the market's grant"
        );
        s.check_invariants().unwrap();
    }

    #[test]
    fn a_market_opens_at_the_reference_price_and_the_protocol_owns_it() {
        let (mut s, sol) = with_asset();
        // Enough ZEC in the protocol's hands: it is held back from the ZYN
        // pool while a market is waiting to open.
        let d = Intent::next_deposit(&s, POT_POL, XZEC, Fixed::whole(1), [8u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_200 });
        let r = go(&mut s, Intent::Checkpoint);
        let m = r
            .iter()
            .find(|x| matches!(x, Receipt::MarketOpened { .. }))
            .unwrap_or_else(|| panic!("{:?}", r));
        let (pool, zec, amount, grant) = match m {
            Receipt::MarketOpened {
                pool,
                zec,
                amount,
                grant,
                ..
            } => (*pool, *zec, *amount, *grant),
            _ => unreachable!(),
        };
        assert_eq!(amount, Fixed::whole(1), "the whole pot went in");
        assert_eq!(
            zec,
            Fixed::raw(100_000_000_000_000_000),
            "1 SOL at 10 per ZEC is 0.1 ZEC"
        );
        let p = &s.pools[&pool];
        let (r0, r1) = (p.reserve0, p.reserve1);
        assert_eq!(
            r1.div(r0).unwrap(),
            Fixed::whole(10),
            "it opens at the reference, exactly"
        );
        assert_eq!(
            p.reference.map(|r| r.price),
            Some(Fixed::whole(10)),
            "and opens defended by it"
        );
        assert!(
            s.balance(&POT_POL, p.lp_asset).is_positive(),
            "the protocol holds the shares"
        );
        assert!(
            !s.balance(&B, p.lp_asset).is_positive(),
            "the contributor does not"
        );
        assert!(grant.is_positive());
        assert_eq!(
            s.launch.as_ref().unwrap().vesting[&(B, sol)].total,
            grant,
            "the grant vests for the contributor"
        );
        assert_eq!(s.balance(&POT_ASSETS, sol), Fixed::ZERO);
        s.check_invariants().unwrap();
    }

    #[test]
    fn the_grant_is_a_slice_of_what_is_unminted_and_shrinks() {
        let (mut s, sol) = with_asset();
        let d = Intent::next_deposit(&s, POT_POL, XZEC, Fixed::whole(1), [8u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_200 });
        let before = s.launch.as_ref().unwrap().minted;
        let r = go(&mut s, Intent::Checkpoint);
        let grant = r
            .iter()
            .find_map(|x| match x {
                Receipt::MarketOpened { grant, .. } => Some(*grant),
                _ => None,
            })
            .unwrap();
        let unminted = Fixed::whole(21_000_000).sub(before).unwrap();
        let expect = unminted
            .mul_div(Fixed::whole(50), Fixed::whole(10_000))
            .unwrap();
        // The epoch also mints emission, so allow the grant to be computed
        // against a marginally larger `minted`; it must be within a whisker.
        let ratio = grant.div(expect).unwrap();
        assert!(
            ratio > Fixed::raw(999_000_000_000_000_000)
                && ratio <= Fixed::raw(1_000_000_000_000_000_000),
            "grant {} vs 50 bps of unminted {}",
            grant,
            expect
        );
        assert!(s.launch.as_ref().unwrap().minted <= Fixed::whole(21_000_000));
        // A second market's grant is smaller, because more is minted by then.
        let r2 = go(
            &mut s,
            Intent::CreateBridgedAsset {
                symbol: symbol(b"ETH.zy"),
                origin: 0x0101,
                origin_network: b"eip155:1".to_vec(),
                origin_asset: Vec::new(),
            },
        );
        let eth = match r2[0] {
            Receipt::BridgedAssetCreated { asset, .. } => asset,
            _ => panic!(),
        };
        go(
            &mut s,
            Intent::AttestVaultBalance {
                asset: eth,
                observed: Fixed::whole(1_000),
            },
        );
        let d = Intent::next_deposit(&s, A, eth, Fixed::whole(200), [11u8; 32]);
        go(&mut s, d);
        go(
            &mut s,
            Intent::UpdateAssetReference {
                asset: eth,
                price: Fixed::whole(10),
            },
        );
        let d = Intent::next_deposit(&s, POT_POL, XZEC, Fixed::whole(1), [12u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_300 });
        let r = go(&mut s, Intent::Checkpoint);
        let grant2 = r
            .iter()
            .find_map(|x| match x {
                Receipt::MarketOpened { grant, .. } => Some(*grant),
                _ => None,
            })
            .unwrap();
        assert!(
            grant2 < grant,
            "the second market costs less: {} < {}",
            grant2,
            grant
        );
        let _ = sol;
        s.check_invariants().unwrap();
    }

    #[test]
    fn nothing_opens_below_the_threshold_or_without_a_fresh_price() {
        let (mut s, sol) = with_asset();
        // Raise the bar above the pot's worth: the market waits.
        let mut p = params();
        p.asset_threshold = Fixed::whole(50);
        // (params may still be changed before the ZYN launch graduated; this
        // one has, so set it the only way the state allows: directly.)
        s.launch.as_mut().unwrap().params.asset_threshold = p.asset_threshold;
        let d = Intent::next_deposit(&s, POT_POL, XZEC, Fixed::whole(1), [8u8; 32]);
        go(&mut s, d);
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_200 });
        let r = go(&mut s, Intent::Checkpoint);
        assert!(
            !r.iter().any(|x| matches!(x, Receipt::MarketOpened { .. })),
            "{:?}",
            r
        );
        assert!(s.find_pool(XZEC, sol).is_none());
        assert_eq!(
            s.balance(&POT_ASSETS, sol),
            Fixed::whole(1),
            "the pot waits"
        );

        // A stale price stops it too, even under a low bar.
        s.launch.as_mut().unwrap().params.asset_threshold = Fixed::raw(1);
        s.launch
            .as_mut()
            .unwrap()
            .assets
            .get_mut(&sol)
            .unwrap()
            .reference = Some(crate::state::Reference {
            price: Fixed::whole(10),
            seq: 0,
        });
        s.params.reference_staleness = 1;
        go(&mut s, Intent::ZcashHeight { height: 1_300 });
        let r = go(&mut s, Intent::Checkpoint);
        assert!(
            !r.iter().any(|x| matches!(x, Receipt::MarketOpened { .. })),
            "a stale price must not open a market: {:?}",
            r
        );
        s.check_invariants().unwrap();
    }

    #[test]
    fn the_launch_is_in_the_root_and_the_codec() {
        let mut s = SwapState::new(7, Params::v1());
        let quiet = s.state_root();
        go(&mut s, Intent::SetLaunch { params: params() });
        assert_ne!(quiet, s.state_root());
        let mut s = chain();
        seal_and_anchor(&mut s);
        go(&mut s, Intent::ZcashHeight { height: 1_100 });
        go(&mut s, Intent::Checkpoint);
        let back = SwapState::decode_state(&s.encode_state()).unwrap();
        assert_eq!(back, s);
        assert!(back.launch.as_ref().unwrap().graduated());
        // After graduation the ZYN launch's own numbers are history, but the
        // two that govern future markets stay adjustable.
        let mut later = params();
        later.genesis = Fixed::whole(1);
        assert!(
            matches!(
                go(&mut s, Intent::SetLaunch { params: later })[0],
                Receipt::Rejected { .. }
            ),
            "after graduation the numbers are history"
        );
        let mut forward = s.launch.as_ref().unwrap().params;
        forward.asset_threshold = Fixed::whole(7);
        forward.bootstrap_bps = 25;
        assert!(
            matches!(
                go(&mut s, Intent::SetLaunch { params: forward })[0],
                Receipt::LaunchSet
            ),
            "but the bar for a new market is a parameter"
        );
        assert_eq!(
            s.launch.as_ref().unwrap().params.asset_threshold,
            Fixed::whole(7)
        );
        let mut fresh = SwapState::new(7, Params::v1());
        go(&mut fresh, Intent::SetLaunch { params: params() });
        let mut p2 = params();
        p2.threshold = Fixed::whole(7);
        assert!(
            matches!(
                go(&mut fresh, Intent::SetLaunch { params: p2 })[0],
                Receipt::LaunchSet
            ),
            "before graduation they may be corrected"
        );
        assert_eq!(
            fresh.launch.as_ref().unwrap().params.threshold,
            Fixed::whole(7)
        );
    }
}

#[cfg(test)]
mod pol_release_tests {
    use super::*;
    use crate::types::{ZYN_MAINNET, ZYN_POL, ZYN_POL_ZYN, ZYN_RESERVE};

    /// A chain with ZYN issued the way the node issues it at genesis.
    fn genesis() -> SwapState {
        let mut s = SwapState::new(26_460, crate::types::Params::v1());
        s.account_mut(&ZYN_RESERVE)
            .credit(ZYN_MAINNET, Fixed::whole(18_900_000))
            .unwrap();
        s.account_mut(&ZYN_POL_ZYN)
            .credit(ZYN_MAINNET, Fixed::whole(2_100_000))
            .unwrap();
        s
    }

    /// The pot starts already full at genesis, so the reserve has nothing to
    /// match — the cap is reached before any fee is ever earned.
    #[test]
    fn a_full_pot_draws_nothing_from_the_reserve() {
        let mut s = genesis();
        let released = credit_pol(&mut s, Fixed::whole(100)).unwrap();
        assert_eq!(released, Fixed::ZERO);
        assert_eq!(s.balance(&ZYN_RESERVE, ZYN_MAINNET), Fixed::whole(18_900_000));
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), Fixed::whole(2_100_000));
        assert_eq!(s.balance(&ZYN_POL, XZEC), Fixed::whole(100), "the ZEC still accrues");
    }

    /// The ratio is the point: 420 ZEC.zy fills the pot to exactly 2,100,000,
    /// which is §71.11's trigger and §71.9's number arriving at the same place.
    #[test]
    fn four_hundred_and_twenty_zec_matches_exactly_two_point_one_million() {
        let mut s = SwapState::new(26_460, crate::types::Params::v1());
        s.account_mut(&ZYN_RESERVE)
            .credit(ZYN_MAINNET, Fixed::whole(21_000_000))
            .unwrap();
        let released = credit_pol(&mut s, Fixed::whole(420)).unwrap();
        assert_eq!(released, Fixed::whole(2_100_000));
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), POL_ZYN_CAP);
        assert_eq!(s.balance(&ZYN_POL, XZEC), Fixed::whole(420));
    }

    /// Past the cap the reserve is never drawn on again by this path. What
    /// happens after is the AMM's job: price, not supply.
    #[test]
    fn the_reserve_stops_at_the_cap_however_much_accrues_after() {
        let mut s = SwapState::new(26_460, crate::types::Params::v1());
        s.account_mut(&ZYN_RESERVE)
            .credit(ZYN_MAINNET, Fixed::whole(21_000_000))
            .unwrap();
        credit_pol(&mut s, Fixed::whole(400)).unwrap();
        let before = s.balance(&ZYN_RESERVE, ZYN_MAINNET);
        // Far past the trigger — ten times the accrual that fills the pot.
        let released = credit_pol(&mut s, Fixed::whole(4_200)).unwrap();
        assert_eq!(
            s.balance(&ZYN_POL_ZYN, ZYN_MAINNET),
            POL_ZYN_CAP,
            "the pot never exceeds 2,100,000"
        );
        assert_eq!(released, Fixed::whole(100_000), "only the last 20 ZEC worth");
        assert_eq!(
            before.sub(s.balance(&ZYN_RESERVE, ZYN_MAINNET)).unwrap(),
            Fixed::whole(100_000)
        );
        assert_eq!(s.balance(&ZYN_POL, XZEC), Fixed::whole(4_600), "all of it still accrues");
    }

    /// Supply is conserved: the release moves ZYN between two keyless pots and
    /// creates none, so §71.3's `total` never moves (§71.4).
    #[test]
    fn releasing_moves_zyn_between_pots_and_creates_none() {
        let mut s = genesis();
        s.account_mut(&ZYN_POL_ZYN)
            .debit(ZYN_MAINNET, Fixed::whole(2_100_000))
            .unwrap();
        let total = |s: &SwapState| {
            s.balance(&ZYN_RESERVE, ZYN_MAINNET)
                .add(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET))
                .unwrap()
        };
        let before = total(&s);
        credit_pol(&mut s, Fixed::whole(50)).unwrap();
        assert_eq!(total(&s), before, "conserved across the two pots");
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), Fixed::whole(250_000));
    }

    /// The reserve cannot go negative even if the cap would allow more.
    #[test]
    fn an_empty_reserve_releases_what_it_has_and_no_more() {
        let mut s = SwapState::new(26_460, crate::types::Params::v1());
        s.account_mut(&ZYN_RESERVE)
            .credit(ZYN_MAINNET, Fixed::whole(1_000))
            .unwrap();
        let released = credit_pol(&mut s, Fixed::whole(420)).unwrap();
        assert_eq!(released, Fixed::whole(1_000), "capped by what the reserve holds");
        assert_eq!(s.balance(&ZYN_RESERVE, ZYN_MAINNET), Fixed::ZERO);
    }
}

#[cfg(test)]
mod pot_registry_tests {
    use super::*;

    /// Every keyless account the protocol holds value in must be known to
    /// `is_pot`, or reward distribution pays a pot that can never spend and
    /// strands the share. The derived ZYN pots were missing when they were
    /// added, which is the shape of mistake this test exists to catch.
    #[test]
    fn every_keyless_account_is_registered_as_a_pot() {
        for (name, id) in [
            ("ZYN_POL", crate::types::ZYN_POL),
            ("ZYN_POL_ZYN", crate::types::ZYN_POL_ZYN),
            ("ZYN_RESERVE", crate::types::ZYN_RESERVE),
            ("POT_GENESIS", POT_GENESIS),
            ("POT_LP", POT_LP),
            ("POT_BRIDGE", POT_BRIDGE),
            ("POT_POL", POT_POL),
            ("POT_FEES", POT_FEES),
            ("POT_ASSETS", POT_ASSETS),
            ("POT_OFFERS", POT_OFFERS),
        ] {
            assert!(is_pot(&id), "{} is keyless but is_pot does not know it", name);
        }
    }

    /// And the treasury is not one: it holds a key, earns LP rewards through
    /// the ordinary path, and can move what it holds.
    #[test]
    fn the_treasury_is_not_a_pot() {
        assert!(!is_pot(&crate::types::TREASURY_26460));
    }
}

#[cfg(test)]
mod pol_open_tests {
    use super::*;
    use crate::tx::Intent;
    use crate::types::{ZYN_MAINNET, ZYN_POL, ZYN_POL_ZYN, ZYN_RESERVE, TREASURY_26460};

    /// ZYN issued the way the node issues it at genesis, so the asset exists
    /// and the reserve holds it.
    fn chain_at(height: u64) -> SwapState {
        let mut s = SwapState::new(26_460, crate::types::Params::v1());
        let i = Intent::IssueToken {
            creator: [0u8; 32],
            symbol: crate::state::symbol(b"ZYN"),
            supply: Fixed::whole(21_000_000),
            unit: Fixed::raw(1),
            allocations: vec![(ZYN_RESERVE, Fixed::whole(21_000_000))],
            policy: crate::state::SupplyPolicy::Fixed,
            native: true,
        };
        let rs = crate::vm::apply(&mut s, &crate::tx::SequencedIntent { seq: 1, intent: i });
        assert!(
            !rs.iter().any(|r| matches!(r, Receipt::Rejected { .. })),
            "ZYN must issue: {:?}",
            rs
        );
        s.zcash_height = height;
        s
    }

    fn observe(s: &mut SwapState, height: u64) -> Vec<Receipt> {
        observe_height(s, height).expect("height")
    }

    fn opened(rs: &[Receipt]) -> bool {
        rs.iter().any(|r| matches!(r, Receipt::MarketOpened { .. }))
    }

    /// Filling the pot does not open the market. It publishes a date.
    #[test]
    fn filling_the_pot_arms_a_date_rather_than_opening() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        assert_eq!(s.pol_open_armed_height, Some(3_000_000));
        assert_eq!(pol_open_height(&s), Some(3_000_000 + POL_OPEN_GRACE_BLOCKS));
        assert!(
            s.find_pool(XZEC, ZYN_MAINNET).is_none(),
            "no market on the block the pot filled"
        );
    }

    /// The whole point: nothing happens until the published height, and then
    /// it happens without anyone acting.
    #[test]
    fn the_market_opens_on_the_published_block_and_not_before() {
        let armed = 3_000_000;
        let mut s = chain_at(armed);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let due = pol_open_height(&s).unwrap();

        let rs = observe(&mut s, due - 1);
        assert!(!opened(&rs), "still closed one block early");
        assert!(s.find_pool(XZEC, ZYN_MAINNET).is_none());

        let rs = observe(&mut s, due);
        assert!(opened(&rs), "opens on the published block");
        let pool = s.find_pool(XZEC, ZYN_MAINNET).expect("pool exists");

        // Opened at exactly the announced ratio.
        let p = s.pools.get(&pool).unwrap();
        let (zyn_side, zec_side) = if ZYN_MAINNET < XZEC {
            (p.reserve0, p.reserve1)
        } else {
            (p.reserve1, p.reserve0)
        };
        assert_eq!(zyn_side, POL_ZYN_CAP);
        assert_eq!(zec_side, Fixed::whole(420));

        // And the LP shares are the treasury's (§71.27).
        let lp = zyn_vm::lp_address(crate::types::ADDRESS_SCOPE_V1, &pool);
        assert!(
            s.balance(&TREASURY_26460, lp).is_positive(),
            "the treasury holds the LP shares"
        );
        for pot in [ZYN_POL_ZYN, ZYN_POL, ZYN_RESERVE] {
            assert_eq!(s.balance(&pot, lp), Fixed::ZERO, "no pot holds LP");
        }
    }

    /// Opening twice would mean a second pool against the same pair.
    #[test]
    fn opening_is_idempotent_across_later_blocks() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let due = pol_open_height(&s).unwrap();
        observe(&mut s, due);
        let pool = s.find_pool(XZEC, ZYN_MAINNET).unwrap();
        let before = s.pools.get(&pool).unwrap().reserve0;

        for h in [due + 1, due + 100, due + 10_000] {
            let rs = observe(&mut s, h);
            assert!(!opened(&rs), "opens once, at {}", h);
        }
        assert_eq!(s.pools.get(&pool).unwrap().reserve0, before);
    }

    /// Surplus accrued during the grace period does not change the opening
    /// price. The date and the price were published together.
    #[test]
    fn accrual_during_the_grace_period_does_not_move_the_opening_price() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let due = pol_open_height(&s).unwrap();
        // Twice as much ZEC.zy arrives while everyone waits.
        credit_pol(&mut s, Fixed::whole(420)).unwrap();

        observe(&mut s, due);
        let pool = s.find_pool(XZEC, ZYN_MAINNET).unwrap();
        let p = s.pools.get(&pool).unwrap();
        let (zyn_side, zec_side) = if ZYN_MAINNET < XZEC {
            (p.reserve0, p.reserve1)
        } else {
            (p.reserve1, p.reserve0)
        };
        assert_eq!(zyn_side, POL_ZYN_CAP, "2,100,000 as announced");
        assert_eq!(zec_side, Fixed::whole(420), "420 as announced");
        assert_eq!(
            s.balance(&ZYN_POL, XZEC),
            Fixed::whole(420),
            "the surplus stays in the pot as buyback reserve"
        );
    }

    /// The date cannot be moved once set, and a stale observation is refused.
    #[test]
    fn the_date_never_moves_and_height_only_goes_forward() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let due = pol_open_height(&s).unwrap();

        credit_pol(&mut s, Fixed::whole(1_000)).unwrap();
        observe(&mut s, 3_000_500);
        credit_pol(&mut s, Fixed::whole(1_000)).unwrap();
        assert_eq!(pol_open_height(&s), Some(due), "the published date is fixed");

        assert!(
            matches!(observe_height(&mut s, 3_000_400), Err(Reject::StaleObservation)),
            "height is monotonic"
        );
    }

    /// An operator cannot bring the opening forward by feeding a false height:
    /// it can only be the real one, because the same height governs deposits
    /// and anchoring. But the grace is enforced on the *chain's* height, so a
    /// node that stops observing simply delays the open — it cannot skip it.
    #[test]
    fn a_node_that_stops_observing_delays_the_open_and_cannot_skip_it() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let due = pol_open_height(&s).unwrap();
        // Silence for a long time, then a single jump far past the date.
        let rs = observe(&mut s, due + 50_000);
        assert!(opened(&rs), "the open is owed and happens on the next observation");
    }

    #[test]
    fn zcash_height_survives_an_encode_decode_round_trip() {
        let mut s = chain_at(3_000_000);
        credit_pol(&mut s, Fixed::whole(420)).unwrap();
        let back = SwapState::decode_state(&s.encode_state()).expect("round trip");
        assert_eq!(back.zcash_height, s.zcash_height);
        assert_eq!(back.pol_open_armed_height, s.pol_open_armed_height);
        assert_eq!(pol_open_height(&back), pol_open_height(&s));
    }

    #[test]
    fn height_observation_needs_no_account_signature() {
        use zyn_vm::spec::MicrochainVm;
        let i = Intent::ZcashHeight { height: 1 };
        assert!(
            <SwapState as MicrochainVm>::intent_authorities(&i).is_empty(),
            "the clock is the operator's to report, not an account's"
        );
    }
    /// Caught in rehearsal, not by a test: genesis put 2,100,000 straight into
    /// the POL pot, `credit_pol` returned early because there was no room to
    /// match, and the arming check sat *after* that return. The pot was full,
    /// the market was never due, and nothing could ever open it.
    #[test]
    fn a_pot_that_is_already_full_still_becomes_due() {
        let mut s = chain_at(3_000_000);
        // Put it there directly, the way the old genesis did.
        s.account_mut(&ZYN_RESERVE)
            .debit(ZYN_MAINNET, POL_ZYN_CAP)
            .unwrap();
        s.account_mut(&ZYN_POL_ZYN)
            .credit(ZYN_MAINNET, POL_ZYN_CAP)
            .unwrap();
        assert_eq!(s.pol_open_armed_height, None);

        let released = credit_pol(&mut s, Fixed::whole(420)).unwrap();
        assert_eq!(released, Fixed::ZERO, "nothing left to match");
        assert_eq!(
            s.pol_open_armed_height,
            Some(3_000_000),
            "but the opening is still due"
        );
    }

    /// The reserve holds everything at genesis, so the pot fills only as real
    /// ZEC.zy arrives. That is what makes 0.0002 a fact about backing.
    #[test]
    fn the_pot_starts_empty_and_fills_from_accrual() {
        let mut s = chain_at(3_000_000);
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), Fixed::ZERO);
        assert_eq!(s.balance(&ZYN_RESERVE, ZYN_MAINNET), Fixed::whole(21_000_000));
        assert_eq!(pol_open_height(&s), None, "no date before there is backing");

        credit_pol(&mut s, Fixed::whole(210)).unwrap();
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), Fixed::whole(1_050_000));
        assert_eq!(pol_open_height(&s), None, "half-full is not due");

        credit_pol(&mut s, Fixed::whole(210)).unwrap();
        assert_eq!(s.balance(&ZYN_POL_ZYN, ZYN_MAINNET), POL_ZYN_CAP);
        assert!(pol_open_height(&s).is_some(), "420 ZEC.zy makes it due");
        assert_eq!(
            s.balance(&ZYN_RESERVE, ZYN_MAINNET),
            Fixed::whole(18_900_000),
            "and 18,900,000 stays in the reserve"
        );
    }
}
