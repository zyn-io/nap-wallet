//! Binary wire format shared with the control plane.
//!
//! Hand-rolled rather than generated, because both sides must agree
//! byte-for-byte and the encoding feeds the epoch's transaction commitment: a
//! serialiser that silently reorders a map or varint-encodes a length would
//! fork the chain.
//!
//! Everything is fixed-width big-endian. `Fixed` is its raw i128, 16 bytes;
//! `AccountId` is 32; a `Symbol` is 8. There are no optional fields and no
//! lengths except explicit counts.
//!
//! ```text
//! request  := op:u8 chain_id:u32 body
//!   op 1 ApplyBatch   := count:u32 (seq:u64 intent)*
//!   op 2 Checkpoint   := (empty)
//!   op 3 Status       := (empty)
//!   op 4 Pools        := (empty)
//!   op 5 AccountProof := account:[32]
//!   op 6 Snapshot     := (empty)
//!   op 7 State        := (empty)      -- full state, enough to carry the chain
//!   op 8 Restore      := len:u32 state
//!   op 9 Quote        := asset_in:u32 count:u32 pool:u32* amount_in:i128
//!
//! response := status:u8 body
//!   status 0 Ok    := seq:u64 epoch:u64 root:[32] backing:i128 count:u32 receipt*
//!   status 1 Error := len:u16 utf8
//! ```

use alloc::vec::Vec;

use crate::merkle::Encoder;
use crate::state::Symbol;
use crate::tx::{Hop, Intent, Receipt, Reject, SequencedIntent};
use crate::types::{AssetId, Params, PoolId};

pub const OP_APPLY_BATCH: u8 = 1;
pub const OP_CHECKPOINT: u8 = 2;
pub const OP_STATUS: u8 = 3;
pub const OP_POOLS: u8 = 4;
pub const OP_ACCOUNT_PROOF: u8 = 5;
/// The public data-availability payload: balances, so a holder can prove an
/// exit without the sequencer, and deliberately nothing else.
pub const OP_SNAPSHOT: u8 = 6;
/// Full state — pools, tokens, parameters and lineage too. Enough to *carry*
/// the chain rather than merely commit to it.
pub const OP_STATE: u8 = 7;
/// Install a previously exported state into a pristine chain.
pub const OP_RESTORE: u8 = 8;
/// Price a route without applying it. Read-only: a quote is not an intent, and
/// nothing it returns is binding until a swap is sequenced.
pub const OP_QUOTE: u8 = 9;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERR: u8 = 1;

/// Maximum hops a decoder will accept in one path, regardless of what the
/// chain's `max_hops` says.
///
/// The VM enforces the real bound, but a decoder that will allocate whatever
/// count a frame claims is a denial-of-service surface in front of it. This cap
/// is a decode-time sanity limit, not a policy.
pub const MAX_PATH_WIRE: usize = 8;

pub use zyn_vm::read::{decode_capped, Decoder, WireError};

/// ZynZap's decoding, layered on the spec's bounds-checked cursor.
///
/// An extension trait rather than inherent methods, because `Decoder` belongs
/// to the spec: a swap's parameters and routing paths are not things every Zyn
/// VM reads.
pub trait SwapDecode {
    fn symbol(&mut self) -> Result<Symbol, WireError>;
    fn params(&mut self) -> Result<Params, WireError>;
    fn path(&mut self) -> Result<Vec<PoolId>, WireError>;
}

impl SwapDecode for Decoder<'_> {
    fn symbol(&mut self) -> Result<Symbol, WireError> {
        self.array::<8>()
    }

    fn params(&mut self) -> Result<Params, WireError> {
        Ok(Params {
            default_fee_bps: self.u16()?,
            min_liquidity: self.fixed()?,
            max_hops: self.u8()?,
            exit_timeout_epochs: self.u64()?,
            reference_staleness: self.u64()?,
            protocol_fee_share_bps: self.u16()?,
            treasury: self.account()?,
            min_pool_xzec: self.fixed()?,
        })
    }
    /// A count-prefixed list of pool ids, capped so a malformed frame cannot
    /// ask for an unbounded allocation.
    fn path(&mut self) -> Result<Vec<PoolId>, WireError> {
        let n = self.u32()? as usize;
        if n > MAX_PATH_WIRE {
            return Err(WireError::TooLong);
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.u32()?);
        }
        Ok(out)
    }
}

pub fn encode_launch(e: &mut Encoder, l: &crate::launch::Launch) {
    e.u16(l.fee_bps).fixed(l.threshold).u64(l.deadline_height).fixed(l.genesis).fixed(l.cap).fixed(l.rate0)
        .u64(l.halving_blocks).u64(l.vesting_blocks).u16(l.split_lp_bps).u16(l.split_bridge_bps).u16(l.fee_burn_bps).u16(l.pool_fee_bps)
        .fixed(l.asset_threshold).u16(l.bootstrap_bps);
}

/// The launch's numbers as a state written before bridged-asset markets
/// existed recorded them: the two fields they lack take today's defaults.
pub fn decode_launch_legacy(d: &mut Decoder) -> Result<crate::launch::Launch, WireError> {
    let v1 = crate::launch::Launch::v1();
    Ok(crate::launch::Launch {
        fee_bps: d.u16()?, threshold: d.fixed()?, deadline_height: d.u64()?, genesis: d.fixed()?, cap: d.fixed()?, rate0: d.fixed()?,
        halving_blocks: d.u64()?, vesting_blocks: d.u64()?, split_lp_bps: d.u16()?, split_bridge_bps: d.u16()?, fee_burn_bps: d.u16()?, pool_fee_bps: d.u16()?,
        asset_threshold: v1.asset_threshold, bootstrap_bps: v1.bootstrap_bps,
    })
}

pub fn decode_launch(d: &mut Decoder) -> Result<crate::launch::Launch, WireError> {
    Ok(crate::launch::Launch {
        fee_bps: d.u16()?, threshold: d.fixed()?, deadline_height: d.u64()?, genesis: d.fixed()?, cap: d.fixed()?, rate0: d.fixed()?,
        halving_blocks: d.u64()?, vesting_blocks: d.u64()?, split_lp_bps: d.u16()?, split_bridge_bps: d.u16()?, fee_burn_bps: d.u16()?, pool_fee_bps: d.u16()?,
        asset_threshold: d.fixed()?, bootstrap_bps: d.u16()?,
    })
}

pub fn encode_params(e: &mut Encoder, p: &Params) {
    e.u16(p.default_fee_bps)
        .fixed(p.min_liquidity)
        .u8(p.max_hops)
        .u64(p.exit_timeout_epochs)
        .u64(p.reference_staleness)
        .u16(p.protocol_fee_share_bps)
        .bytes(&p.treasury)
        .fixed(p.min_pool_xzec);
}

fn encode_path(e: &mut Encoder, path: &[PoolId]) {
    e.u32(path.len() as u32);
    for id in path {
        e.u32(*id);
    }
}

// ---------------------------------------------------------------------------
// Intents
// ---------------------------------------------------------------------------

pub fn encode_intent(e: &mut Encoder, i: &Intent) {
    match i {
        Intent::CreditDeposit { account, asset, amount, index, external_ref } => {
            e.u8(1)
                .bytes(account)
                .u32(*asset)
                .fixed(*amount)
                .u64(*index)
                .bytes(external_ref);
        }
        Intent::Transfer { from, to, asset, amount } => {
            e.u8(2).bytes(from).bytes(to).u32(*asset).fixed(*amount);
        }
        Intent::MintItem { creator, symbol, supply, bond, content } => {
            e.u8(14).bytes(creator).bytes(symbol).fixed(*supply).fixed(*bond).bytes(content);
        }
        Intent::Reblind { account, blind } => {
            e.u8(24).bytes(account).bytes(blind);
        }
        Intent::CreateCollection { creator, symbol, cap, fee_bps } => {
            e.u8(30).bytes(creator).bytes(symbol).u32(*cap).u16(*fee_bps);
        }
        Intent::MintCollectionItem { creator, collection, to, symbol, content } => {
            e.u8(31).bytes(creator).u32(*collection).bytes(to).bytes(symbol).bytes(content);
        }
        Intent::FundCollection { from, collection, amount } => {
            e.u8(32).bytes(from).u32(*collection).fixed(*amount);
        }
        Intent::RedeemCollectionItem { holder, asset } => {
            e.u8(33).bytes(holder).u32(*asset);
        }
        Intent::AdvanceCollection { creator, collection, to } => {
            e.u8(34).bytes(creator).u32(*collection).u8(*to);
        }
        Intent::CreateBridgedItem { symbol, origin, content } => {
            e.u8(25).bytes(symbol).u16(*origin).bytes(content);
        }
        Intent::SetClearing { on } => {
            e.u8(26).bool(*on);
        }
        Intent::SetLaunch { params } => {
            e.u8(27);
            encode_launch(e, params);
        }
        Intent::ZcashHeight { height } => {
            e.u8(28).u64(*height);
        }
        Intent::UpdateAssetReference { asset, price } => {
            e.u8(29).u32(*asset).fixed(*price);
        }
        Intent::BurnItem { holder, asset } => {
            e.u8(15).bytes(holder).u32(*asset);
        }
        Intent::AcceptOffer {
            maker, taker, offer_asset, offer_amount, want_asset, want_amount,
        } => {
            e.u8(13)
                .bytes(maker)
                .bytes(taker)
                .u32(*offer_asset)
                .fixed(*offer_amount)
                .u32(*want_asset)
                .fixed(*want_amount);
        }
        Intent::PlaceOffer {
            maker, offer_asset, offer_amount, want_asset, want_amount, expires_at_epoch,
        } => {
            e.u8(35)
                .bytes(maker)
                .u32(*offer_asset)
                .fixed(*offer_amount)
                .u32(*want_asset)
                .fixed(*want_amount)
                .u64(*expires_at_epoch);
        }
        Intent::TakeOffer { taker, offer } => {
            e.u8(36).bytes(taker).u64(*offer);
        }
        Intent::CancelOffer { maker, offer } => {
            e.u8(37).bytes(maker).u64(*offer);
        }
        Intent::CreateToken {
            creator, symbol, supply, unit, xzec_liquidity, token_liquidity, fee_bps,
        } => {
            e.u8(3)
                .bytes(creator)
                .bytes(symbol)
                .fixed(*supply)
                .fixed(*unit)
                .fixed(*xzec_liquidity)
                .fixed(*token_liquidity)
                .u16(*fee_bps);
        }
        Intent::CreatePool { creator, asset_a, asset_b, amount_a, amount_b, fee_bps } => {
            e.u8(4)
                .bytes(creator)
                .u32(*asset_a)
                .u32(*asset_b)
                .fixed(*amount_a)
                .fixed(*amount_b)
                .u16(*fee_bps);
        }
        Intent::AddLiquidity { account, pool, max0, max1, min_shares } => {
            e.u8(5)
                .bytes(account)
                .u32(*pool)
                .fixed(*max0)
                .fixed(*max1)
                .fixed(*min_shares);
        }
        Intent::RemoveLiquidity { account, pool, shares, min0, min1 } => {
            e.u8(6)
                .bytes(account)
                .u32(*pool)
                .fixed(*shares)
                .fixed(*min0)
                .fixed(*min1);
        }
        Intent::SwapExactIn { account, asset_in, path, amount_in, min_out } => {
            e.u8(7).bytes(account).u32(*asset_in);
            encode_path(e, path);
            e.fixed(*amount_in).fixed(*min_out);
        }
        Intent::SwapExactOut { account, asset_in, path, amount_out, max_in } => {
            e.u8(8).bytes(account).u32(*asset_in);
            encode_path(e, path);
            e.fixed(*amount_out).fixed(*max_in);
        }
        Intent::RequestWithdrawal { account, asset, amount, destination } => {
            e.u8(9).bytes(account).u32(*asset).fixed(*amount).bytes(destination);
        }
        Intent::BindWithdrawal { account, destination } => {
            e.u8(21).bytes(account).bytes(destination);
        }
        Intent::ConfirmWithdrawal { account, asset, amount } => {
            e.u8(10).bytes(account).u32(*asset).fixed(*amount);
        }
        Intent::CancelWithdrawal { account, asset } => {
            e.u8(16).bytes(account).u32(*asset);
        }
        Intent::UpdateReference { pool, price } => {
            e.u8(17).u32(*pool).fixed(*price);
        }
        Intent::CreateBridgedAsset { symbol, origin } => {
            e.u8(22).bytes(symbol).u16(*origin);
        }
        Intent::AttestVaultBalance { asset, observed } => {
            e.u8(20).u32(*asset).fixed(*observed);
        }
        Intent::ConfirmAnchor { epoch } => {
            e.u8(18).u64(*epoch);
        }
        Intent::Checkpoint => {
            e.u8(11);
        }
        Intent::SetParams { params } => {
            e.u8(12);
            encode_params(e, params);
        }
    }
}

/// Encode one intent to a fresh buffer.
///
/// Used by the VM to fold an intent into the epoch's commitment, so the bytes
/// a checkpoint commits to are exactly the bytes the control plane sent.
pub fn encode_intent_bytes(i: &Intent) -> Vec<u8> {
    let mut e = Encoder::new();
    encode_intent(&mut e, i);
    e.finish().to_vec()
}

pub fn decode_intent(d: &mut Decoder) -> Result<Intent, WireError> {
    Ok(match d.u8()? {
        1 => Intent::CreditDeposit {
            account: d.account()?,
            asset: d.u32()?,
            amount: d.fixed()?,
            index: d.u64()?,
            external_ref: d.hash()?,
        },
        2 => Intent::Transfer {
            from: d.account()?,
            to: d.account()?,
            asset: d.u32()?,
            amount: d.fixed()?,
        },
        3 => Intent::CreateToken {
            creator: d.account()?,
            symbol: d.symbol()?,
            supply: d.fixed()?,
            unit: d.fixed()?,
            xzec_liquidity: d.fixed()?,
            token_liquidity: d.fixed()?,
            fee_bps: d.u16()?,
        },
        4 => Intent::CreatePool {
            creator: d.account()?,
            asset_a: d.u32()?,
            asset_b: d.u32()?,
            amount_a: d.fixed()?,
            amount_b: d.fixed()?,
            fee_bps: d.u16()?,
        },
        5 => Intent::AddLiquidity {
            account: d.account()?,
            pool: d.u32()?,
            max0: d.fixed()?,
            max1: d.fixed()?,
            min_shares: d.fixed()?,
        },
        6 => Intent::RemoveLiquidity {
            account: d.account()?,
            pool: d.u32()?,
            shares: d.fixed()?,
            min0: d.fixed()?,
            min1: d.fixed()?,
        },
        7 => Intent::SwapExactIn {
            account: d.account()?,
            asset_in: d.u32()?,
            path: d.path()?,
            amount_in: d.fixed()?,
            min_out: d.fixed()?,
        },
        8 => Intent::SwapExactOut {
            account: d.account()?,
            asset_in: d.u32()?,
            path: d.path()?,
            amount_out: d.fixed()?,
            max_in: d.fixed()?,
        },
        9 => Intent::RequestWithdrawal {
            account: d.account()?,
            asset: d.u32()?,
            amount: d.fixed()?,
            destination: d.hash()?,
        },
        21 => Intent::BindWithdrawal { account: d.account()?, destination: d.hash()? },
        10 => Intent::ConfirmWithdrawal {
            account: d.account()?,
            asset: d.u32()?,
            amount: d.fixed()?,
        },
        16 => Intent::CancelWithdrawal { account: d.account()?, asset: d.u32()? },
        17 => Intent::UpdateReference { pool: d.u32()?, price: d.fixed()? },
        20 => Intent::AttestVaultBalance { asset: d.u32()?, observed: d.fixed()? },
        22 => Intent::CreateBridgedAsset { symbol: d.symbol()?, origin: d.u16()? },
        24 => Intent::Reblind { account: d.account()?, blind: d.hash()? },
        25 => Intent::CreateBridgedItem { symbol: d.symbol()?, origin: d.u16()?, content: d.hash()? },
        26 => Intent::SetClearing { on: d.u8()? != 0 },
        27 => Intent::SetLaunch { params: decode_launch(d)? },
        28 => Intent::ZcashHeight { height: d.u64()? },
        29 => Intent::UpdateAssetReference { asset: d.u32()?, price: d.fixed()? },
        18 => Intent::ConfirmAnchor { epoch: d.u64()? },
        11 => Intent::Checkpoint,
        12 => Intent::SetParams { params: d.params()? },
        30 => Intent::CreateCollection {
            creator: d.account()?,
            symbol: d.symbol()?,
            cap: d.u32()?,
            fee_bps: d.u16()?,
        },
        31 => Intent::MintCollectionItem {
            creator: d.account()?,
            collection: d.u32()?,
            to: d.account()?,
            symbol: d.symbol()?,
            content: d.hash()?,
        },
        32 => Intent::FundCollection {
            from: d.account()?,
            collection: d.u32()?,
            amount: d.fixed()?,
        },
        33 => Intent::RedeemCollectionItem {
            holder: d.account()?,
            asset: d.u32()?,
        },
        34 => Intent::AdvanceCollection { creator: d.account()?, collection: d.u32()?, to: d.u8()? },
        14 => Intent::MintItem {
            creator: d.account()?,
            symbol: d.symbol()?,
            supply: d.fixed()?,
            bond: d.fixed()?,
            content: d.hash()?,
        },
        15 => Intent::BurnItem { holder: d.account()?, asset: d.u32()? },
        13 => Intent::AcceptOffer {
            maker: d.account()?,
            taker: d.account()?,
            offer_asset: d.u32()?,
            offer_amount: d.fixed()?,
            want_asset: d.u32()?,
            want_amount: d.fixed()?,
        },
        35 => Intent::PlaceOffer {
            maker: d.account()?,
            offer_asset: d.u32()?,
            offer_amount: d.fixed()?,
            want_asset: d.u32()?,
            want_amount: d.fixed()?,
            expires_at_epoch: d.u64()?,
        },
        36 => Intent::TakeOffer { taker: d.account()?, offer: d.u64()? },
        37 => Intent::CancelOffer { maker: d.account()?, offer: d.u64()? },
        b => return Err(WireError::UnknownDiscriminant(b)),
    })
}

pub fn decode_sequenced(d: &mut Decoder) -> Result<SequencedIntent, WireError> {
    let seq = d.u64()?;
    Ok(SequencedIntent { seq, intent: decode_intent(d)? })
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

pub fn reject_code(r: Reject) -> u8 {
    match r {
        Reject::OutOfOrder => 1,
        Reject::DuplicateSymbol => 35,
        Reject::NoSuchCollection => 36,
        Reject::WrongCollectionPhase => 40,
        Reject::NotTheCreator => 41,
        Reject::ItemNeedsAPrice => 42,
        Reject::NoSuchOffer => 43,
        Reject::OfferExpired => 44,
        Reject::CannotTakeOwnOffer => 45,
        Reject::NotTheMaker => 46,
        Reject::CollectionFull => 37,
        Reject::NotACollectionItem => 38,
        Reject::NotTheWholeItem => 39,
        Reject::NonPositiveAmount => 2,
        Reject::InsufficientBalance => 3,
        Reject::InsufficientPending => 4,
        Reject::UnknownAsset => 5,
        Reject::UnknownPool => 6,
        Reject::PoolExists => 7,
        Reject::DegeneratePair => 8,
        Reject::InsufficientLiquidityMinted => 9,
        Reject::InsufficientLiquidityBurned => 10,
        Reject::SlippageExceeded => 11,
        Reject::InvalidPath => 12,
        Reject::InsufficientReserves => 13,
        Reject::InvalidFee => 14,
        Reject::Indivisible => 18,
        Reject::BelowLaunchBond => 19,
        Reject::DegenerateOffer => 20,
        Reject::BelowMinimumTrade => 21,
        Reject::NotSoleHolder => 22,
        Reject::NotBridged => 23,
        Reject::DepositOutOfOrder => 24,
        Reject::BelowExitMinimum => 25,
        Reject::WrongDestination => 33,
        Reject::RedirectTooSoon => 34,
        Reject::ExitNotTimedOut => 26,
        Reject::AboveVaultCap => 27,
        Reject::NotFinalized => 28,
        Reject::InvalidFinality => 29,
        Reject::AboveObserved => 30,
        Reject::AttestedShortfall => 31,
        Reject::StaleObservation => 32,
        Reject::InvalidParams => 15,
        Reject::IdSpaceExhausted => 16,
        Reject::ArithmeticFailure => 17,
    }
}

pub fn reject_from_code(c: u8) -> Option<Reject> {
    Some(match c {
        1 => Reject::OutOfOrder,
        2 => Reject::NonPositiveAmount,
        3 => Reject::InsufficientBalance,
        4 => Reject::InsufficientPending,
        5 => Reject::UnknownAsset,
        6 => Reject::UnknownPool,
        7 => Reject::PoolExists,
        8 => Reject::DegeneratePair,
        9 => Reject::InsufficientLiquidityMinted,
        10 => Reject::InsufficientLiquidityBurned,
        11 => Reject::SlippageExceeded,
        12 => Reject::InvalidPath,
        13 => Reject::InsufficientReserves,
        14 => Reject::InvalidFee,
        18 => Reject::Indivisible,
        19 => Reject::BelowLaunchBond,
        20 => Reject::DegenerateOffer,
        21 => Reject::BelowMinimumTrade,
        22 => Reject::NotSoleHolder,
        23 => Reject::NotBridged,
        24 => Reject::DepositOutOfOrder,
        25 => Reject::BelowExitMinimum,
        33 => Reject::WrongDestination,
        34 => Reject::RedirectTooSoon,
        26 => Reject::ExitNotTimedOut,
        27 => Reject::AboveVaultCap,
        28 => Reject::NotFinalized,
        29 => Reject::InvalidFinality,
        30 => Reject::AboveObserved,
        31 => Reject::AttestedShortfall,
        32 => Reject::StaleObservation,
        15 => Reject::InvalidParams,
        16 => Reject::IdSpaceExhausted,
        17 => Reject::ArithmeticFailure,
        _ => return None,
    })
}

fn encode_hop(e: &mut Encoder, h: &Hop) {
    e.u32(h.pool)
        .u32(h.asset_in)
        .u32(h.asset_out)
        .fixed(h.amount_in)
        .fixed(h.amount_out)
        .fixed(h.fee)
        .fixed(h.protocol_fee);
}

pub fn encode_receipt(e: &mut Encoder, r: &Receipt) {
    match r {
        Receipt::DepositCredited { account, asset, amount, backing, index, external_ref } => {
            e.u8(1)
                .bytes(account)
                .u32(*asset)
                .fixed(*amount)
                .fixed(*backing)
                .u64(*index)
                .bytes(external_ref);
        }
        Receipt::Transferred { from, to, asset, amount } => {
            e.u8(2).bytes(from).bytes(to).u32(*asset).fixed(*amount);
        }
        Receipt::CollectionCreated { collection, creator, symbol, cap, fee_bps } => {
            e.u8(40).u32(*collection).bytes(creator).bytes(symbol).u32(*cap).u16(*fee_bps);
        }
        Receipt::CollectionItemMinted { collection, asset, to, minted, outstanding } => {
            e.u8(41).u32(*collection).u32(*asset).bytes(to).u32(*minted).u32(*outstanding);
        }
        Receipt::CollectionFunded { collection, amount, pool, redeem_price } => {
            e.u8(42).u32(*collection).fixed(*amount).fixed(*pool).fixed(*redeem_price);
        }
        Receipt::CollectionItemRedeemed { collection, asset, holder, paid, outstanding } => {
            e.u8(43).u32(*collection).u32(*asset).bytes(holder).fixed(*paid).u32(*outstanding);
        }
        Receipt::CollectionFeeTaken { collection, taken, to_pool, to_creator, pool, redeem_price } => {
            e.u8(45).u32(*collection).fixed(*taken).fixed(*to_pool).fixed(*to_creator).fixed(*pool).fixed(*redeem_price);
        }
        Receipt::OfferPlaced { offer, maker, offer_asset, offer_amount, want_asset, want_amount, expires_at_epoch } => {
            e.u8(46).u64(*offer).bytes(maker).u32(*offer_asset).fixed(*offer_amount).u32(*want_asset).fixed(*want_amount).u64(*expires_at_epoch);
        }
        Receipt::OfferTaken { offer, maker, taker, offer_asset, offer_amount, want_asset, want_amount } => {
            e.u8(47).u64(*offer).bytes(maker).bytes(taker).u32(*offer_asset).fixed(*offer_amount).u32(*want_asset).fixed(*want_amount);
        }
        Receipt::OfferCancelled { offer, maker, offer_asset, offer_amount } => {
            e.u8(48).u64(*offer).bytes(maker).u32(*offer_asset).fixed(*offer_amount);
        }
        Receipt::CollectionPhaseChanged { collection, phase, outstanding, pool, redeem_price } => {
            e.u8(44).u32(*collection).u8(*phase).u32(*outstanding).fixed(*pool).fixed(*redeem_price);
        }
        Receipt::ItemMinted { asset, creator, symbol, supply, bond } => {
            e.u8(14).u32(*asset).bytes(creator).bytes(symbol).fixed(*supply).fixed(*bond);
        }
        Receipt::ItemBurned { asset, holder, supply, refunded } => {
            e.u8(15).u32(*asset).bytes(holder).fixed(*supply).fixed(*refunded);
        }
        Receipt::OfferAccepted {
            maker, taker, offer_asset, offer_amount, want_asset, want_amount,
        } => {
            e.u8(13)
                .bytes(maker)
                .bytes(taker)
                .u32(*offer_asset)
                .fixed(*offer_amount)
                .u32(*want_asset)
                .fixed(*want_amount);
        }
        Receipt::TokenCreated { asset, creator, symbol, supply, unit } => {
            e.u8(3).u32(*asset).bytes(creator).bytes(symbol).fixed(*supply).fixed(*unit);
        }
        Receipt::BridgedAssetCreated { asset, symbol, origin } => {
            e.u8(13).u32(*asset).bytes(symbol).u16(*origin);
        }
        Receipt::Reblinded { account } => {
            e.u8(14).bytes(account);
        }
        Receipt::PoolCreated { pool, asset0, asset1, lp_asset, fee_bps } => {
            e.u8(4)
                .u32(*pool)
                .u32(*asset0)
                .u32(*asset1)
                .u32(*lp_asset)
                .u16(*fee_bps);
        }
        Receipt::LiquidityAdded { account, pool, amount0, amount1, shares } => {
            e.u8(5)
                .bytes(account)
                .u32(*pool)
                .fixed(*amount0)
                .fixed(*amount1)
                .fixed(*shares);
        }
        Receipt::LiquidityRemoved { account, pool, amount0, amount1, shares } => {
            e.u8(6)
                .bytes(account)
                .u32(*pool)
                .fixed(*amount0)
                .fixed(*amount1)
                .fixed(*shares);
        }
        Receipt::Swapped { account, asset_in, asset_out, amount_in, amount_out, hops } => {
            e.u8(7)
                .bytes(account)
                .u32(*asset_in)
                .u32(*asset_out)
                .fixed(*amount_in)
                .fixed(*amount_out)
                .u32(hops.len() as u32);
            for h in hops {
                encode_hop(e, h);
            }
        }
        Receipt::WithdrawalRequested { account, asset, amount, pending, destination } => {
            e.u8(8)
                .bytes(account)
                .u32(*asset)
                .fixed(*amount)
                .fixed(*pending)
                .bytes(destination);
        }
        Receipt::WithdrawalBound { account, destination, effective } => {
            e.u8(21).bytes(account).bytes(destination).bool(*effective);
        }
        Receipt::WithdrawalCancelled { account, asset, amount, waited } => {
            e.u8(16).bytes(account).u32(*asset).fixed(*amount).u64(*waited);
        }
        Receipt::WithdrawalConfirmed { account, asset, amount, backing } => {
            e.u8(9).bytes(account).u32(*asset).fixed(*amount).fixed(*backing);
        }
        Receipt::Checkpointed(cp) => {
            e.u8(10)
                .u32(cp.chain_id)
                .u64(cp.epoch)
                .bytes(&cp.parent_root)
                .bytes(&cp.state_root)
                .bytes(&cp.intent_root)
                .u64(cp.seq)
                .u64(cp.intents)
                .fixed(cp.gross_volume);
        }
        Receipt::ReferenceUpdated { pool, price, fee_bps } => {
            e.u8(17).u32(*pool).fixed(*price).u16(*fee_bps);
        }
        Receipt::AnchorConfirmed { epoch } => {
            e.u8(18).u64(*epoch);
        }
        Receipt::VaultAttested { asset, observed, headroom } => {
            e.u8(20).u32(*asset).fixed(*observed).fixed(*headroom);
        }
        Receipt::DepositClaimed { account, asset, amount } => {
            e.u8(19).bytes(account).u32(*asset).fixed(*amount);
        }
        Receipt::ParamsUpdated => {
            e.u8(11);
        }
        Receipt::Rejected { reason } => {
            e.u8(12).u8(reject_code(*reason));
        }
        Receipt::SwapQueued { account, pool, asset_in, amount_in, min_out, seq } => {
            e.u8(19).bytes(account).u32(*pool).u32(*asset_in).fixed(*amount_in).fixed(*min_out).u64(*seq);
        }
        Receipt::SwapUnfilled { account, pool, asset_in, amount_in, reason } => {
            e.u8(20).bytes(account).u32(*pool).u32(*asset_in).fixed(*amount_in).u8(reject_code(*reason));
        }
        Receipt::ClearingSet { on } => {
            e.u8(21).bool(*on);
        }
        Receipt::LaunchSet => { e.u8(22); }
        Receipt::HeightObserved { height } => { e.u8(23).u64(*height); }
        Receipt::Graduated { pool, zyn, pot, price, contributors } => { e.u8(24).u32(*pool).u32(*zyn).fixed(*pot).fixed(*price).u32(*contributors); }
        Receipt::Minted { amount, height, to_lp, to_bridge, to_pol } => { e.u8(25).fixed(*amount).u64(*height).fixed(*to_lp).fixed(*to_bridge).fixed(*to_pol); }
        Receipt::LpRewardsPaid { amount } => { e.u8(26).fixed(*amount); }
        Receipt::RebatesPaid { amount } => { e.u8(27).fixed(*amount); }
        Receipt::Burned { zyn, zec } => { e.u8(28).fixed(*zyn).fixed(*zec); }
        Receipt::LiquidityPaired { amount0, amount1 } => { e.u8(29).fixed(*amount0).fixed(*amount1); }
        Receipt::LaunchSkipped { reason } => { e.u8(30).u8(reject_code(*reason)); }
        Receipt::AssetReferenceUpdated { asset, price } => { e.u8(31).u32(*asset).fixed(*price); }
        Receipt::MarketOpened { asset, pool, zec, amount, price, grant } => { e.u8(32).u32(*asset).u32(*pool).fixed(*zec).fixed(*amount).fixed(*price).fixed(*grant); }
    }
}

pub fn encode_receipts(receipts: &[Receipt]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u32(receipts.len() as u32);
    for r in receipts {
        encode_receipt(&mut e, r);
    }
    e.finish().to_vec()
}

/// Assets a receipt refers to, for a consumer indexing without decoding
/// everything. Present so the server does not have to re-derive it from the
/// intent that produced the receipt.
pub fn receipt_assets(r: &Receipt) -> Vec<AssetId> {
    match r {
        Receipt::Transferred { asset, .. } => alloc::vec![*asset],
        Receipt::TokenCreated { asset, .. } => alloc::vec![*asset],
        Receipt::BridgedAssetCreated { asset, .. } => alloc::vec![*asset],
        Receipt::PoolCreated { asset0, asset1, lp_asset, .. } => {
            alloc::vec![*asset0, *asset1, *lp_asset]
        }
        Receipt::Swapped { asset_in, asset_out, .. } => alloc::vec![*asset_in, *asset_out],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::state::symbol;
    use crate::types::{AccountId, XZEC};

    fn round_trip(i: Intent) {
        let bytes = encode_intent_bytes(&i);
        let mut d = Decoder::new(&bytes);
        let back = decode_intent(&mut d).expect("decode");
        assert_eq!(back, i, "round trip changed the intent");
        assert_eq!(d.remaining(), 0, "decoder left {} bytes unread", d.remaining());
    }

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    #[test]
    fn every_intent_round_trips() {
        round_trip(Intent::CreditDeposit {
            account: acct(7),
            asset: XZEC,
            amount: Fixed::whole(10),
            index: 7,
            external_ref: [0xAB; 32],
        });
        round_trip(Intent::Transfer {
            from: acct(1),
            to: acct(2),
            asset: 5,
            amount: Fixed::raw(12_310_000_000_000),
        });
        round_trip(Intent::CreateBridgedAsset { symbol: symbol(b"SOL.zy"), origin: crate::types::ORIGIN_SOLANA });
        round_trip(Intent::Reblind { account: acct(3), blind: [9u8; 32] });
        round_trip(Intent::CreateBridgedItem { symbol: symbol(b"PUNK.zy"), origin: crate::types::ORIGIN_SOLANA, content: [4u8; 32] });
        round_trip(Intent::CreateToken {
            creator: acct(1),
            symbol: symbol(b"CAT"),
            supply: Fixed::whole(1_000_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(10),
            token_liquidity: Fixed::whole(1_000_000),
            fee_bps: 30,
        });
        round_trip(Intent::CreatePool {
            creator: acct(1),
            asset_a: 2,
            asset_b: 1,
            amount_a: Fixed::whole(1_000),
            amount_b: Fixed::whole(10),
            fee_bps: 30,
        });
        round_trip(Intent::AddLiquidity {
            account: acct(3),
            pool: 1,
            max0: Fixed::whole(5),
            max1: Fixed::whole(500),
            min_shares: Fixed::ZERO,
        });
        round_trip(Intent::RemoveLiquidity {
            account: acct(3),
            pool: 1,
            shares: Fixed::whole(1),
            min0: Fixed::ZERO,
            min1: Fixed::ZERO,
        });
        round_trip(Intent::SwapExactIn {
            account: acct(4),
            asset_in: 1,
            path: alloc::vec![1, 2],
            amount_in: Fixed::whole(10),
            min_out: Fixed::whole(1),
        });
        round_trip(Intent::SwapExactOut {
            account: acct(4),
            asset_in: 1,
            path: alloc::vec![3],
            amount_out: Fixed::whole(10),
            max_in: Fixed::whole(100),
        });
        round_trip(Intent::RequestWithdrawal { account: acct(5), asset: XZEC, amount: Fixed::whole(12), destination: [0u8; 32] });
        round_trip(Intent::ConfirmWithdrawal { account: acct(5), asset: XZEC, amount: Fixed::whole(12) });
        round_trip(Intent::Checkpoint);
        round_trip(Intent::SetParams { params: Params::v1() });
    }

    #[test]
    fn an_empty_path_round_trips() {
        // The VM rejects it, but the codec must represent it faithfully rather
        // than failing at a different layer than the rule lives in.
        round_trip(Intent::SwapExactIn {
            account: acct(1),
            asset_in: 1,
            path: Vec::new(),
            amount_in: Fixed::ONE,
            min_out: Fixed::ZERO,
        });
    }

    #[test]
    fn extreme_fixed_values_survive() {
        round_trip(Intent::CreditDeposit {
            account: acct(1),
            asset: XZEC,
            amount: Fixed::raw(i128::MAX),
            index: 7,
            external_ref: [0xAB; 32],
        });
        round_trip(Intent::CreditDeposit {
            account: acct(1),
            asset: XZEC,
            amount: Fixed::raw(i128::MIN),
            index: 7,
            external_ref: [0xAB; 32],
        });
    }

    #[test]
    fn a_truncated_frame_errors_rather_than_panicking() {
        let full = encode_intent_bytes(&Intent::SwapExactIn {
            account: acct(1),
            asset_in: 1,
            path: alloc::vec![1, 2],
            amount_in: Fixed::ONE,
            min_out: Fixed::ZERO,
        });
        for cut in 0..full.len() {
            let mut d = Decoder::new(&full[..cut]);
            assert!(decode_intent(&mut d).is_err(), "cut at {} should fail", cut);
        }
    }

    #[test]
    fn unknown_discriminants_are_rejected() {
        let bytes = [99u8, 0, 0];
        let mut d = Decoder::new(&bytes);
        assert_eq!(decode_intent(&mut d), Err(WireError::UnknownDiscriminant(99)));
    }

    /// A frame claiming a huge path must be refused at the count, before any
    /// allocation is sized from it.
    #[test]
    fn an_absurd_path_length_is_refused_before_allocating() {
        let mut e = Encoder::new();
        e.u8(7).bytes(&acct(1)).u32(1).u32(u32::MAX);
        let bytes = e.finish().to_vec();
        let mut d = Decoder::new(&bytes);
        assert_eq!(decode_intent(&mut d), Err(WireError::TooLong));
    }

    #[test]
    fn every_reject_code_is_distinct_and_round_trips() {
        use Reject::*;
        let all = [
            OutOfOrder, NonPositiveAmount, InsufficientBalance, InsufficientPending,
            UnknownAsset, UnknownPool, PoolExists, DegeneratePair,
            InsufficientLiquidityMinted, InsufficientLiquidityBurned, SlippageExceeded,
            InvalidPath, InsufficientReserves, InvalidFee, InvalidParams,
            IdSpaceExhausted, ArithmeticFailure,
        ];
        let mut seen = alloc::vec::Vec::new();
        for r in all {
            let c = reject_code(r);
            assert!(!seen.contains(&c), "duplicate reject code {}", c);
            seen.push(c);
            assert_eq!(reject_from_code(c), Some(r));
        }
        assert_eq!(reject_from_code(0), None);
        assert_eq!(reject_from_code(200), None);
    }

    #[test]
    fn sequenced_intents_carry_their_position() {
        let mut e = Encoder::new();
        e.u64(42);
        encode_intent(&mut e, &Intent::Checkpoint);
        let bytes = e.finish().to_vec();
        let mut d = Decoder::new(&bytes);
        assert_eq!(decode_sequenced(&mut d).unwrap().seq, 42);
    }

    /// The encoding is a wire contract. Pinning the exact bytes means a field
    /// reorder breaks this test rather than silently forking the commitment.
    #[test]
    fn swap_encoding_is_pinned() {
        let b = encode_intent_bytes(&Intent::SwapExactIn {
            account: [0xAB; 32],
            asset_in: 1,
            path: alloc::vec![7],
            amount_in: Fixed::whole(10),
            min_out: Fixed::ZERO,
        });
        // op + account + asset + count + one pool + two i128
        assert_eq!(b.len(), 1 + 32 + 4 + 4 + 4 + 16 + 16);
        assert_eq!(b[0], 7, "discriminant");
        assert_eq!(&b[1..33], &[0xAB; 32], "account");
        assert_eq!(&b[33..37], &1u32.to_be_bytes(), "asset_in");
        assert_eq!(&b[37..41], &1u32.to_be_bytes(), "path length");
        assert_eq!(&b[41..45], &7u32.to_be_bytes(), "pool id");
        assert_eq!(&b[45..61], &Fixed::whole(10).0.to_be_bytes(), "amount is big-endian i128");
    }
}
