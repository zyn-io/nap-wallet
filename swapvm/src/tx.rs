//! The VM's input and output alphabet.
//!
//! **Intents are the only input.** There is deliberately no `Fill` or `Quote`
//! intent: the sequencer decides *order*, the VM decides *price*. If a fill
//! could be submitted, a proof over this VM would attest that bookkeeping was
//! applied faithfully while saying nothing about whether the AMM priced
//! honestly — and honest pricing is the entire property the proof exists to
//! establish.
//!
//! The action set is the one the project plan fixes for V1, with the deposit
//! and withdrawal paths split into their confirmed and requested halves so the
//! backing invariant holds continuously rather than only between exits.

use alloc::vec::Vec;

use crate::fixed::Fixed;
use crate::state::Symbol;
use crate::types::ChainOrigin;
use crate::types::{AccountId, AssetId, CollectionId, OfferId, Params, PoolId};

/// A single instruction from the control plane.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Intent {
    /// Mirror a confirmed deposit on a custodying chain: mint the bridged asset
    /// and raise its recorded backing in the same step.
    ///
    /// One intent for every bridge. Zcash, Bitcoin, Ethereum and Solana differ
    /// in how a deposit is *observed* — confirmation depth, finality, whether a
    /// light client or a threshold quorum attests it — and not at all in what it
    /// *means* here. Keeping the difference upstream is what lets a second
    /// bridge be a new vault and a new asset rather than a new code path.
    ///
    /// The two move together and only here, which is what makes
    /// `supply == backing` an invariant rather than an aspiration. The vault
    /// operator emits this once a deposit has the required confirmations; the
    /// VM has no way to observe Zcash itself and does not pretend to.
    CreditDeposit {
        account: AccountId,
        asset: AssetId,
        amount: Fixed,
        /// This asset's deposit index. Must be exactly the next one, so the
        /// same external deposit cannot be credited twice.
        index: u64,
        /// The transaction on the custodying chain that this mirrors — a txid,
        /// an outpoint hash, a signature. Not interpreted by the VM, which
        /// cannot see the other chain, but folded into the epoch's intent
        /// commitment, so every minted unit is permanently traceable to a
        /// specific external transaction that anyone running that chain's node
        /// can check.
        external_ref: [u8; 32],
    },

    /// Move any asset between two accounts on the chain.
    Transfer { from: AccountId, to: AccountId, asset: AssetId, amount: Fixed },

    /// Swap two assets between two accounts, atomically, at an agreed price.
    ///
    /// The settlement half of any negotiated trade: an OTC block, a bid
    /// accepted off the curve, or the sale of an LP position — which is how an
    /// NFT changes hands when its ownership *is* a pool position.
    ///
    /// One intent rather than two transfers, for the same reason a routed swap
    /// is one intent. Two transfers are two sequencing decisions, and a
    /// sequencer that includes the first and drops the second has taken one
    /// side's asset without delivering the other's. Atomicity here is not a
    /// convenience; it is what makes a trade a trade rather than a pair of
    /// hopeful gifts.
    ///
    /// The VM enforces that both sides can pay and that both legs land
    /// together. It does **not** establish that either party agreed — that is
    /// authorisation, which lives upstream and is bound to this chain and a
    /// validity window by the signing envelope (S12).
    AcceptOffer {
        maker: AccountId,
        taker: AccountId,
        /// What the maker gives up.
        offer_asset: AssetId,
        offer_amount: Fixed,
        /// What the taker gives in return.
        want_asset: AssetId,
        want_amount: Fixed,
    },

    /// Commit an asset at a price and leave it resting until someone takes it.
    ///
    /// The counterpart to [`Intent::AcceptOffer`], and the reason both exist.
    /// `AcceptOffer` names its taker, so the maker has to be present when the
    /// buyer appears; that is a negotiated trade and it settles in one intent.
    /// This is the other shape: the maker commits, goes away, and the offer
    /// still binds. Making that non-custodial is what needs the chain — an
    /// application holding the asset in the meantime would be a custodian, and
    /// asking the maker to stay online would make it not a resting offer.
    ///
    /// The asset moves to [`crate::launch::POT_OFFERS`] now rather than at the
    /// take. An offer whose asset could still be spent by its maker is an
    /// advertisement, not an offer.
    PlaceOffer {
        maker: AccountId,
        /// What the maker gives up.
        offer_asset: AssetId,
        offer_amount: Fixed,
        /// What the maker wants for it.
        want_asset: AssetId,
        want_amount: Fixed,
        /// Last epoch in which this may be taken, inclusive. `u64::MAX` rests
        /// forever, which should be deliberate rather than a default.
        expires_at_epoch: u64,
    },

    /// Take a resting offer at its stated price.
    ///
    /// Signed by the taker alone: the maker already agreed, in the intent that
    /// placed it and moved the asset out of their account.
    TakeOffer { taker: AccountId, offer: OfferId },

    /// Withdraw a resting offer and take the asset back.
    ///
    /// Available after expiry too — expiry stops an offer being taken, not
    /// being reclaimed. Nothing sweeps expired offers on its own, because a
    /// transition needs someone who asked for it.
    CancelOffer { maker: AccountId, offer: OfferId },

    /// Mint an indivisible item, against a refundable bond.
    ///
    /// The creation path for things a curve cannot price. An item moves only in
    /// whole units and can never be wrapped in a pool, so there is no divisible
    /// claim on it and no way to end up owning a third of one — the ownership
    /// is the balance.
    ///
    /// The bond is what replaces the launch pool's locked liquidity for an
    /// asset that has no pool. It is returned in full by `BurnItem`, so holding
    /// state costs capital rather than a payment: the same anti-spam pressure
    /// as rent, without rent's incentive of charging builders more as the
    /// economy succeeds.
    MintItem {
        creator: AccountId,
        symbol: Symbol,
        /// Whole units to mint. One for a unique item; more for a run of
        /// identical ones.
        supply: Fixed,
        /// xZEC to lock. Must be at least `Params::min_pool_xzec`.
        bond: Fixed,
        /// What the item is: a hash of its content or metadata, fixed at mint.
        content: [u8; 32],
    },
    /// Set the secret folded into this account's published leaf, so nobody
    /// holding the data-availability payload can confirm a guess about what
    /// it holds. Rotating it is allowed and cheap.
    Reblind { account: AccountId, blind: [u8; 32] },

    /// Open a collection: a set of unique items sharing one redemption pool.
    ///
    /// The pool starts empty and is filled by [`Intent::FundCollection`] — the
    /// mint proceeds, and later a share of every trade. Any holder may redeem
    /// one item for `pool / outstanding`, so that quotient is a floor the
    /// collection cannot trade below, and one that rises whenever the pool is
    /// paid into without new items being minted.
    CreateCollection {
        creator: AccountId,
        symbol: Symbol,
        /// The most items that may ever exist. Fixed here for good: a floor is
        /// a claim on a known denominator, and a cap that can move is not one.
        cap: u32,
        /// Basis points taken from each side of a trade in this collection.
        fee_bps: u16,
    },
    /// Mint one item into a collection, to `to`.
    ///
    /// Each item is its own indivisible asset with its own content hash, so
    /// the art is per-item. It posts no bond: the collection's pool is what
    /// backs it.
    MintCollectionItem {
        /// Who authorises it. Only the collection's creator may mint into it.
        creator: AccountId,
        collection: CollectionId,
        to: AccountId,
        symbol: Symbol,
        content: [u8; 32],
    },
    /// Pay xZEC into a collection's pool, backing every outstanding item.
    ///
    /// The only way the floor rises. Deliberately its own intent rather than a
    /// side effect of minting, because the mint proceeds, a trade fee and a
    /// gift are the same thing to the holders: xZEC that is now behind their
    /// items.
    FundCollection { from: AccountId, collection: CollectionId, amount: Fixed },
    /// Move a collection to the next phase of its life.
    ///
    /// `Depositing → Minting → Closed → Live`: the sale runs, then claiming
    /// opens (including any open mint for what the sale left over), then
    /// claiming closes, and later the market opens and redemption with it.
    /// One intent rather than one per step, because it is one state machine.
    ///
    /// `to` names the destination rather than saying "next", so submitting it
    /// twice cannot skip a phase. Creator only, and forward only.
    AdvanceCollection { creator: AccountId, collection: CollectionId, to: u8 },
    /// Destroy one collection item and take its share of the pool.
    ///
    /// The counterpart of `BurnItem` for something backed collectively.
    /// Removing one item and one item's worth of pool together leaves the
    /// quotient unchanged, so redeeming never moves the floor for anyone else
    /// — which is what makes the floor hold all the way down to the last item.
    RedeemCollectionItem { holder: AccountId, asset: AssetId },
    /// Destroy an item and reclaim its bond.
    ///
    /// The counterpart of `RemoveLiquidity` for something that was never
    /// liquidity. An item cannot be unwrapped — there is nothing inside it — so
    /// the only way to stop paying for its state is to end it, and the only
    /// account that may is the one holding every unit.
    ///
    /// This is what makes the bond a deposit rather than a fee, and it is the
    /// only operation on this chain that makes the state *smaller*.
    BurnItem { holder: AccountId, asset: AssetId },

    /// Create a Zyn-native token **and open its xZEC market**, atomically.
    ///
    /// The two are one intent on purpose. A token with no market is dead state
    /// on a swap venue: it costs every node and every proof forever and serves
    /// nobody. Requiring the pool at launch means the state only ever holds
    /// assets the product exists to trade, and it is what replaces rent —
    /// `Params::min_pool_xzec` of the seeded liquidity is permanently locked,
    /// so creation costs real capital that becomes a market instead of a fee
    /// paid to nobody.
    ///
    /// Fixed supply at creation: no mint authority is retained, because an
    /// asset whose supply can move underneath a pool is an asset whose LPs
    /// cannot price their risk.
    CreateToken {
        creator: AccountId,
        symbol: Symbol,
        supply: Fixed,
        /// Smallest transferable amount. `Fixed::raw(1)` for an ordinary
        /// divisible token; `Fixed::ONE` for one that moves only in whole
        /// units.
        unit: Fixed,
        /// xZEC seeded into the launch pool. Must exceed the bond.
        xzec_liquidity: Fixed,
        /// How much of `supply` is seeded alongside it. The rest goes to the
        /// creator, so a launch also sets the opening price.
        token_liquidity: Fixed,
        fee_bps: u16,
    },

    /// Create a pool over a pair and seed it with the first liquidity.
    ///
    /// Creation and the first deposit are one intent on purpose: an empty pool
    /// is not a tradeable object, and letting one exist between two intents
    /// would mean every swap path has to handle a pool that prices nothing.
    CreatePool {
        creator: AccountId,
        asset_a: AssetId,
        asset_b: AssetId,
        amount_a: Fixed,
        amount_b: Fixed,
        /// Basis points. Committed to the pool for its lifetime.
        fee_bps: u16,
    },

    /// Deposit into an existing pool at the current ratio.
    ///
    /// `max0`/`max1` are ceilings on the pool's `asset0` and `asset1`, not
    /// exact amounts: the VM takes the balanced pair inside them and leaves the
    /// rest, so a deposit racing a swap tops out rather than reverting.
    /// `min_shares` is the caller's slippage bound.
    ///
    /// Naming them by the pool's canonical sides rather than by argument order
    /// removes the one ambiguity a caller could get silently wrong — the pool
    /// sorts its pair, so "the first amount" is not a property the caller
    /// chooses.
    AddLiquidity {
        account: AccountId,
        pool: PoolId,
        max0: Fixed,
        max1: Fixed,
        min_shares: Fixed,
    },

    /// Burn shares back to the underlying pair.
    RemoveLiquidity {
        account: AccountId,
        pool: PoolId,
        shares: Fixed,
        min0: Fixed,
        min1: Fixed,
    },

    /// Sell exactly `amount_in` along `path`, taking whatever comes out.
    ///
    /// `path` is a list of pool ids; `asset_in` fixes the direction of the
    /// first hop and every hop after it follows from the pair. Bounded by
    /// `Params::max_hops` — a path is sequenced input, and unbounded input is
    /// unbounded work in a program that must have a provable cost.
    SwapExactIn {
        account: AccountId,
        asset_in: AssetId,
        path: Vec<PoolId>,
        amount_in: Fixed,
        min_out: Fixed,
    },

    /// Buy exactly `amount_out` along `path`, paying at most `max_in`.
    SwapExactOut {
        account: AccountId,
        asset_in: AssetId,
        path: Vec<PoolId>,
        amount_out: Fixed,
        max_in: Fixed,
    },

    /// Commit units of a bridged asset to an exit. Moves balance into the
    /// account's pending queue, where it still counts against supply but can no
    /// longer be traded.
    RequestWithdrawal {
        account: AccountId,
        asset: AssetId,
        amount: Fixed,
        /// `H(address, salt)` — where the payout must go.
        ///
        /// A commitment rather than the address, because the plan lists the
        /// withdrawal destination among the things that should stay private
        /// (§12) and Zyn's state is readable by everyone. The operator learns
        /// the address out of band; anyone shown the preimage can check the
        /// payout went where the intent said.
        destination: [u8; 32],
    },

    /// Bring a bridged asset into existence: a token with a vault on `origin`
    /// and no supply until deposits arrive. Operator-only — it names no
    /// account, so no signature can authorise it (`intent_authorities`).
    CreateBridgedAsset { symbol: Symbol, origin: ChainOrigin },
    /// A mirrored item: an indivisible asset backed one-for-one by a token the
    /// vault custodies on `origin`. `content` identifies it there — on Solana
    /// the mint itself. Operator-only, like `CreateBridgedAsset`.
    CreateBridgedItem { symbol: Symbol, origin: ChainOrigin, content: [u8; 32] },

    /// The custodying chain confirmed that exit: burn the units and release the
    /// backing.
    ///
    /// Emitted by the settlement signers after the vault transaction has the
    /// required confirmations. Until it arrives the units are still liabilities
    /// of the chain, which is why the request alone does not burn them.
    ConfirmWithdrawal { account: AccountId, asset: AssetId, amount: Fixed },

    /// Report what the vault on the custodying chain holds.
    ///
    /// A shielded Zcash vault emits nothing — there are no contracts, and its
    /// balance is not public. Someone with the viewing key has to look. This
    /// turns that looking into a recorded number the chain enforces against:
    /// **units issued can never exceed units last observed.**
    ///
    /// It does not remove the trust; it changes its shape. Fabricating a credit
    /// now requires a separate, dated lie about a balance that every
    /// viewing-key holder can check independently — so the natural thing to do
    /// with the vault's viewing key is give it to every signer, and let each
    /// verify before endorsing the epoch that releases the deposits.
    AttestVaultBalance { asset: AssetId, observed: Fixed },

    /// Record that an epoch reached Zcash under a threshold certificate.
    ///
    /// Emitted by the node once it has collected and verified a certificate for
    /// that epoch. It releases every deposit credited in it — which is what
    /// makes a deposit require the **same quorum a withdrawal does**, instead of
    /// one operator's word.
    ///
    /// The VM cannot check the certificate itself; what it enforces is the
    /// shape. An epoch cannot be finalised twice, cannot be finalised backwards,
    /// and cannot be finalised before it has been sealed — so a sequencer
    /// cannot release a deposit it has only just fabricated.
    ConfirmAnchor { epoch: u64 },

    /// Bind where this account's exits may go, or ask to move that binding.
    ///
    /// The first call binds immediately. Every later one is a *request* that
    /// takes `Params::exit_timeout_epochs` to mature, and re-asking with a
    /// different address restarts the wait.
    ///
    /// That delay is the whole point. A Zyn signing key is necessarily warm —
    /// it signs swaps — so it will sometimes be stolen. Binding the destination
    /// means a stolen key can trade a position but cannot send the proceeds
    /// anywhere new without giving the owner a window to notice and empty the
    /// account first.
    BindWithdrawal { account: AccountId, destination: [u8; 32] },

    /// Take back an exit the custodying chain never settled.
    ///
    /// Only after `Params::exit_timeout_epochs` have passed since the request.
    /// Until then an exit is irrevocable, because a user who could cancel at
    /// will could race a payout already in flight and be paid on both sides.
    CancelWithdrawal { account: AccountId, asset: AssetId },

    /// Report an external price for a pair.
    ///
    /// Sets the **fee**, never the quote. A pool whose price is discovered here
    /// — a memecoin against xZEC — should never receive one; a bridged pair,
    /// whose price is discovered elsewhere, needs one or its LPs pay for the
    /// difference on every external move.
    ///
    /// The VM cannot verify it, which is exactly why it is confined to fees: a
    /// manipulated report costs the pool some edge on one trade and cannot move
    /// a unit out of it.
    UpdateReference { pool: PoolId, price: Fixed },
    /// Operator: switch single-hop swaps between executing on arrival and
    /// queueing for the seal, where every order on a pool clears at one price.
    SetClearing { on: bool },
    /// Operator: set the ZYN launch (once; the numbers are then state).
    SetLaunch { params: crate::launch::Launch },
    /// Operator: the Zcash tip, the launch's clock.
    ZcashHeight { height: u64 },
    /// Operator: a bridged asset's market price, in units of it per ZEC.zy.
    /// What a pool of it would open at, before one exists.
    UpdateAssetReference { asset: AssetId, price: Fixed },

    /// Seal the epoch: freeze a state root, commit the intents behind it, and
    /// start the next one.
    Checkpoint,

    /// Replace the chain parameters. The VM enforces them and never computes
    /// them; it refuses a set that is unsafe by construction.
    SetParams { params: Params },
}

impl Intent {
    /// A deposit carrying the next index for its asset.
    ///
    /// The index is read from the chain, not chosen by the caller, so a
    /// correctly built credit cannot replay one already applied.
    pub fn next_deposit(
        state: &crate::state::SwapState,
        account: AccountId,
        asset: AssetId,
        amount: Fixed,
        external_ref: [u8; 32],
    ) -> Intent {
        Intent::CreditDeposit {
            account,
            asset,
            amount,
            index: state.next_deposit_index(asset),
            external_ref,
        }
    }
}

/// An intent bound to its position in the chain's canonical order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SequencedIntent {
    pub seq: u64,
    pub intent: Intent,
}

/// Why an intent did not take effect.
///
/// Rejections are ordinary and expected: they are recorded in receipts and the
/// sequence still advances, because a rejected intent is a real event in the
/// chain's history that anyone replaying must reproduce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    /// A token with this symbol already exists.
    DuplicateSymbol,
    /// No collection with that id.
    NoSuchCollection,
    /// The collection is not in a phase where this makes sense: minting after
    /// claiming closed, or redeeming before the market opened.
    WrongCollectionPhase,
    /// Only the collection's creator may do this.
    NotTheCreator,
    /// A collection item was traded against something other than xZEC, so the
    /// chain cannot read a price to charge the collection's fee on.
    ItemNeedsAPrice,
    /// The collection has minted every item its cap allows.
    CollectionFull,
    /// The asset is not an item in the collection it was redeemed against, or
    /// is not a collection item at all.
    NotACollectionItem,
    /// A redeem needs the whole item: one account holding its only unit.
    NotTheWholeItem,
    /// No resting offer with that id: never placed, or already taken or
    /// cancelled.
    NoSuchOffer,
    /// The offer's last epoch has passed. It can still be cancelled by its
    /// maker.
    OfferExpired,
    /// An offer's maker cannot take it: the trade would be with themselves,
    /// and the fee would be the only thing that moved.
    CannotTakeOwnOffer,
    /// Only the account that placed an offer may cancel it.
    NotTheMaker,
    /// Sequence number was not exactly `state.seq + 1`.
    OutOfOrder,
    /// Amount was zero or negative where only a positive one makes sense.
    NonPositiveAmount,
    /// Account does not hold enough of the asset.
    InsufficientBalance,
    /// A deposit or exit against an asset that no vault custodies.
    NotBridged,
    /// Would take the vault past its total ceiling, or past what may be minted
    /// in a single epoch.
    AboveVaultCap,
    /// Would issue more units than the vault was last observed to hold.
    AboveObserved,
    /// The vault was reported short of what has been issued against it.
    AttestedShortfall,
    /// An observation that does not move the record forward.
    StaleObservation,
    /// The epoch containing this deposit has not been anchored yet.
    NotFinalized,
    /// An epoch cannot be finalised twice, backwards, or before it is sealed.
    InvalidFinality,
    /// An exit below what the custodying chain can pay out.
    BelowExitMinimum,
    /// An exit to somewhere other than where the account is bound.
    WrongDestination,
    /// A redirect that has not waited out its delay.
    RedirectTooSoon,
    /// The exit has not been outstanding long enough to be taken back.
    ExitNotTimedOut,
    /// The deposit index was not the next one — a replay, or a gap that would
    /// let one be inserted later.
    DepositOutOfOrder,
    /// Withdrawal exceeds the account's free xZEC, or a confirmation exceeds
    /// what was actually requested.
    InsufficientPending,
    UnknownAsset,
    UnknownPool,
    /// A pool already exists for that pair. Split liquidity is worse than no
    /// second pool.
    PoolExists,
    /// A pool over an asset with itself.
    DegeneratePair,
    /// An offer that trades an asset for itself, or where one side is the same
    /// account. Neither is a trade, and both would let a caller mint a receipt
    /// that says a price was agreed when nothing moved.
    DegenerateOffer,
    /// The pair is priced but the deposit does not clear the locked minimum, or
    /// would mint zero shares.
    InsufficientLiquidityMinted,
    /// A launch seeded less xZEC than `Params::min_pool_xzec`, or exactly the
    /// bond, which would leave the creator no shares at all.
    BelowLaunchBond,
    /// Burning those shares returns nothing.
    InsufficientLiquidityBurned,
    /// Output fell below `min_out`, input rose above `max_in`, or shares came
    /// in under `min_shares`.
    SlippageExceeded,
    /// Path was empty, longer than `max_hops`, revisited a pool, or did not
    /// connect.
    InvalidPath,
    /// A swap tried to take a whole reserve, or price against an empty one.
    InsufficientReserves,
    /// Fee outside the representable range.
    InvalidFee,
    /// A hop paid in less than the pool's declared minimum.
    BelowMinimumTrade,
    /// Burning an item requires holding every unit of it.
    NotSoleHolder,
    /// The amount is not a whole number of the asset's units, or an indivisible
    /// asset was offered to something that cannot price one.
    Indivisible,
    /// Parameter set is internally inconsistent.
    InvalidParams,
    /// Creating an asset would exhaust the id space.
    IdSpaceExhausted,
    /// A checked arithmetic operation failed. The intent is discarded whole and
    /// the batch containing it is abandoned.
    ArithmeticFailure,
}

/// One leg of a routed swap, as executed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hop {
    pub pool: PoolId,
    pub asset_in: AssetId,
    pub asset_out: AssetId,
    pub amount_in: Fixed,
    pub amount_out: Fixed,
    /// The portion of this hop's input that did not enter the curve. Derived
    /// from the curve rather than recomputed from the rate, so it always
    /// describes the reserves that actually moved — this is the figure a UI
    /// shows as "LP fee".
    pub fee: Fixed,
    /// The slice of `fee` routed to the treasury rather than left in the pool.
    /// Zero under V1 parameters. LPs keep `fee - protocol_fee`.
    pub protocol_fee: Fixed,
}

/// What the VM did.
///
/// Receipts are the *only* way prices reach the outside world: the UI's "you
/// receive 42,812 CAT" is read from a `Swapped`, never computed alongside it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Receipt {
    DepositCredited {
        account: AccountId,
        asset: AssetId,
        amount: Fixed,
        backing: Fixed,
        index: u64,
        external_ref: [u8; 32],
    },
    Transferred { from: AccountId, to: AccountId, asset: AssetId, amount: Fixed },
    OfferAccepted {
        maker: AccountId,
        taker: AccountId,
        offer_asset: AssetId,
        offer_amount: Fixed,
        want_asset: AssetId,
        want_amount: Fixed,
    },
    ItemMinted { asset: AssetId, creator: AccountId, symbol: Symbol, supply: Fixed, bond: Fixed },
    CollectionCreated { collection: CollectionId, creator: AccountId, symbol: Symbol, cap: u32, fee_bps: u16 },
    CollectionItemMinted { collection: CollectionId, asset: AssetId, to: AccountId, minted: u32, outstanding: u32 },
    /// The pool grew, so the floor did. `redeem_price` is what one item is
    /// worth after this — the number the whole design exists to publish.
    CollectionFunded { collection: CollectionId, amount: Fixed, pool: Fixed, redeem_price: Fixed },
    CollectionItemRedeemed { collection: CollectionId, asset: AssetId, holder: AccountId, paid: Fixed, outstanding: u32 },
    /// A trade in a collection paid its fee: half into the pool, where it
    /// raises the floor for every holder, half to the creator.
    CollectionFeeTaken { collection: CollectionId, taken: Fixed, to_pool: Fixed, to_creator: Fixed, pool: Fixed, redeem_price: Fixed },
    OfferPlaced { offer: OfferId, maker: AccountId, offer_asset: AssetId, offer_amount: Fixed, want_asset: AssetId, want_amount: Fixed, expires_at_epoch: u64 },
    OfferTaken { offer: OfferId, maker: AccountId, taker: AccountId, offer_asset: AssetId, offer_amount: Fixed, want_asset: AssetId, want_amount: Fixed },
    OfferCancelled { offer: OfferId, maker: AccountId, offer_asset: AssetId, offer_amount: Fixed },
    /// The collection moved on in its life. `redeem_price` is what an item is
    /// worth once redemption is open, and zero before.
    CollectionPhaseChanged { collection: CollectionId, phase: u8, outstanding: u32, pool: Fixed, redeem_price: Fixed },
    ItemBurned { asset: AssetId, holder: AccountId, supply: Fixed, refunded: Fixed },
    BridgedAssetCreated { asset: AssetId, symbol: Symbol, origin: ChainOrigin },
    Reblinded { account: AccountId },
    TokenCreated {
        asset: AssetId,
        creator: AccountId,
        symbol: Symbol,
        supply: Fixed,
        unit: Fixed,
    },
    PoolCreated {
        pool: PoolId,
        asset0: AssetId,
        asset1: AssetId,
        lp_asset: AssetId,
        fee_bps: u16,
    },
    LiquidityAdded {
        account: AccountId,
        pool: PoolId,
        amount0: Fixed,
        amount1: Fixed,
        shares: Fixed,
    },
    LiquidityRemoved {
        account: AccountId,
        pool: PoolId,
        amount0: Fixed,
        amount1: Fixed,
        shares: Fixed,
    },
    Swapped {
        account: AccountId,
        asset_in: AssetId,
        asset_out: AssetId,
        amount_in: Fixed,
        amount_out: Fixed,
        hops: Vec<Hop>,
    },
    WithdrawalRequested {
        account: AccountId,
        asset: AssetId,
        amount: Fixed,
        pending: Fixed,
        destination: [u8; 32],
    },
    WithdrawalBound { account: AccountId, destination: [u8; 32], effective: bool },
    WithdrawalConfirmed { account: AccountId, asset: AssetId, amount: Fixed, backing: Fixed },
    WithdrawalCancelled { account: AccountId, asset: AssetId, amount: Fixed, waited: u64 },
    AnchorConfirmed { epoch: u64 },
    VaultAttested { asset: AssetId, observed: Fixed, headroom: Fixed },
    /// A swap recorded for the next seal rather than executed.
    SwapQueued { account: AccountId, pool: PoolId, asset_in: AssetId, amount_in: Fixed, min_out: Fixed, seq: u64 },
    /// An order that could not fill at the seal: its limit was not met, or
    /// the account could no longer pay. Nothing moved.
    SwapUnfilled { account: AccountId, pool: PoolId, asset_in: AssetId, amount_in: Fixed, reason: Reject },
    ClearingSet { on: bool },
    LaunchSet,
    HeightObserved { height: u64 },
    Graduated { pool: PoolId, zyn: AssetId, pot: Fixed, price: Fixed, contributors: u32 },
    Minted { amount: Fixed, height: u64, to_lp: Fixed, to_bridge: Fixed, to_pol: Fixed },
    LpRewardsPaid { amount: Fixed },
    RebatesPaid { amount: Fixed },
    Burned { zyn: Fixed, zec: Fixed },
    LiquidityPaired { amount0: Fixed, amount1: Fixed },
    /// The launch's seal step could not complete this epoch; nothing of it
    /// was kept. The seal itself went ahead.
    LaunchSkipped { reason: Reject },
    AssetReferenceUpdated { asset: AssetId, price: Fixed },
    /// A bridged asset got a market of its own, owned by the protocol.
    MarketOpened { asset: AssetId, pool: PoolId, zec: Fixed, amount: Fixed, price: Fixed, grant: Fixed },
    DepositClaimed { account: AccountId, asset: AssetId, amount: Fixed },
    /// An epoch was sealed. Carries the full commitment, which is what the
    /// settlement signers sign and what lands in the Zcash checkpoint
    /// transaction.
    Checkpointed(crate::state::Checkpoint),
    ReferenceUpdated { pool: PoolId, price: Fixed, fee_bps: u16 },
    ParamsUpdated,
    Rejected { reason: Reject },
}

impl Receipt {
    pub fn is_rejection(&self) -> bool {
        matches!(self, Receipt::Rejected { .. })
    }

    pub fn rejection(&self) -> Option<Reject> {
        match self {
            Receipt::Rejected { reason } => Some(*reason),
            _ => None,
        }
    }
}
