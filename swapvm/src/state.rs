//! Accounts, tokens, pools, and the microchain state they compose.
//!
//! Every function here returns `Option` on arithmetic failure rather than
//! panicking. A panic inside a zkVM guest is an unprovable execution, so the VM
//! must be able to *reject* an intent it cannot compute and carry on.
//!
//! Two structural decisions are worth stating up front, because everything else
//! follows from them:
//!
//! 1. **Pool reserves live on the pool, not in an account.** Supply
//!    conservation is therefore `supply == sum(account balances) + sum(pool
//!    reserves)`, checked by `check_invariants`. The alternative — giving each
//!    pool a synthetic account — buys nothing and adds a forgeable identity.
//! 2. **LP shares are ordinary assets.** A pool mints its own `AssetId` at
//!    creation, so an LP position is just a balance. The project plan lists
//!    `LP-CAT-xZEC` alongside CAT and DOG for exactly this reason, and it is
//!    what lets ZynBorrow later accept LP positions as collateral without the
//!    VM growing a second ownership mechanism.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::fixed::Fixed;
use crate::merkle::Hash;
use crate::types::{AccountId, AssetId, ChainOrigin, CollectionId, OfferId, Params, PoolId, FIRST_USER_ASSET, ORIGIN_ZCASH, XZEC};

/// A user-visible ticker. Fixed width because a variable-length field in a
/// state commitment is a length field an encoder can disagree about.
/// Right-padded with zero bytes.
pub type Symbol = [u8; 8];

/// A resting offer: an asset committed at a price until taken, cancelled or
/// expired.
///
/// The offered asset is not here — it is in [`crate::launch::POT_OFFERS`], moved
/// there when the offer was placed. This record is the ledger saying whose it is
/// and what it costs, which is what makes a second take impossible: the asset is
/// gone from the maker before any taker arrives, and gone from escrow after the
/// first one does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Offer {
    pub maker: AccountId,
    pub offer_asset: AssetId,
    pub offer_amount: Fixed,
    pub want_asset: AssetId,
    pub want_amount: Fixed,
    /// Last epoch in which this may be taken, inclusive. `u64::MAX` is no
    /// expiry, which should be deliberate — it is the rests-forever case.
    pub expires_at_epoch: u64,
}

/// A set of unique items sharing one redemption pool.
///
/// Each item is its own indivisible asset with its own content hash, so the
/// art is per-item; what they share is the xZEC behind them. Any holder may
/// redeem one item for `pool / outstanding`, which is why that quotient is a
/// **floor**: below it, buying to redeem is free money, so nobody sells lower.
///
/// Redeeming leaves the quotient unchanged — it removes one share and one
/// item's worth of pool together — so the floor survives any amount of
/// redemption, right down to the last item. Paying into the pool without
/// minting (a trade fee, a royalty, a donation) raises it for everyone at
/// once, with nothing to distribute and no per-holder bookkeeping.

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Collection {
    pub creator: AccountId,
    pub symbol: Symbol,
    /// The most items that may ever exist. Fixed at creation: a cap that can
    /// move is not a cap, and the floor is a claim on a known denominator.
    pub cap: u32,
    /// Items minted so far. Never decreases — a redeemed item does not free
    /// its slot, or the collection would have no final size.
    pub minted: u32,
    /// Items not yet redeemed. The denominator of the floor.
    pub outstanding: u32,
    /// xZEC backing the outstanding items, held by no account.
    pub pool: Fixed,
    /// The protocol's cut of a trade in this collection, in basis points,
    /// charged to each side. Half of what is taken goes to the pool.
    pub fee_bps: u16,
    /// Where the collection is in its life. See [`Phase`].
    pub phase: Phase,
}

/// A collection's life, in one direction only.
///
/// The order is a safety property, not bookkeeping. While items are still
/// being claimed the pool is filling and the denominator is still moving, so
/// `pool / outstanding` is not a floor — it is an artefact of how far the sale
/// has got. Redeeming against it would let the first claimant take a share of
/// everyone else's money: with 36 xZEC in and one item claimed, that item
/// would redeem for 36. Redemption therefore cannot open until the
/// denominator is final, and minting can never reopen once it has, because a
/// late mint would dilute a claim people are already redeeming against.
///
/// Modelled as a phase rather than two flags so that "redeemable while still
/// minting" cannot be written down at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// The sale is running. Money comes in; no items exist yet.
    ///
    /// Claiming starts only once this ends, so the number of items the sale
    /// allocated is known before any is handed out — which is what lets the
    /// remainder be priced and opened to whoever wants them.
    Depositing,
    /// Claims are open, and so is any open mint for what the sale left. The
    /// pool is still filling; nothing may be redeemed.
    Minting,
    /// Claiming has closed, so the denominator is final — but the market has
    /// not opened yet, so neither has redemption.
    Closed,
    /// Listed and trading. Redemption is open and the floor is real.
    Live,
}

impl Phase {
    pub fn code(self) -> u8 {
        match self {
            Phase::Depositing => 0,
            Phase::Minting => 1,
            Phase::Closed => 2,
            Phase::Live => 3,
        }
    }
    pub fn from_code(c: u8) -> Option<Phase> {
        match c {
            0 => Some(Phase::Depositing),
            1 => Some(Phase::Minting),
            2 => Some(Phase::Closed),
            3 => Some(Phase::Live),
            _ => None,
        }
    }
    /// The one phase that may follow this one. `None` at the end of the line.
    ///
    /// A collection's life runs one way: a step back would either dilute a
    /// claim people are redeeming against or reopen a denominator that has
    /// already been used as a divisor.
    pub fn next(self) -> Option<Phase> {
        match self {
            Phase::Depositing => Some(Phase::Minting),
            Phase::Minting => Some(Phase::Closed),
            Phase::Closed => Some(Phase::Live),
            Phase::Live => None,
        }
    }
}

impl Collection {
    /// What one item redeems for right now: `pool / outstanding`.
    ///
    /// Integer division, and the remainder deliberately stays in the pool. A
    /// rounding crumb left behind belongs to the holders who remain, which is
    /// the only direction that cannot leak value out of the collection.
    pub fn redeem_price(&self) -> Fixed {
        if self.phase != Phase::Live || self.outstanding == 0 {
            return Fixed::ZERO;
        }
        Fixed::raw(self.pool.0 / i128::from(self.outstanding))
    }
}

/// Build a `Symbol` from a byte string, truncating past 8 bytes.
pub fn symbol(s: &[u8]) -> Symbol {
    let mut out = [0u8; 8];
    let n = if s.len() > 8 { 8 } else { s.len() };
    out[..n].copy_from_slice(&s[..n]);
    out
}

/// Custody state, from the shared component.
///
/// ZynZap holds bridged balances because it has to — an asset custodied by some
/// other VM could not be swapped here — but it does not own the rules for them.
pub use zyn_bridge::{Binding, PendingCredit, PendingExit, Vault};

/// An asset the VM knows about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TokenInfo {
    pub symbol: Symbol,
    /// Total units in existence: account balances plus pool reserves, plus (for
    /// xZEC) pending exits, plus (for an LP asset) the permanently locked
    /// minimum. `check_invariants` proves that identity holds.
    pub supply: Fixed,
    /// The pool whose LP shares this asset represents, if any. `None` for xZEC
    /// and user-created tokens.
    pub lp_of: Option<PoolId>,
    /// The token's canonical market: the xZEC pool it launched with.
    ///
    /// A token has one *reference* market and any number of secondary ones, and
    /// this names the reference. It is set at launch and never moves, so the
    /// price it quotes is the one thing about a token that cannot be
    /// fragmented.
    ///
    /// Not a parent-child link between pools, which is the shape this wants to
    /// be and cannot: a pool is a symmetric pair, so a CAT/zUSD market is
    /// equally a child of CAT and of zUSD, and picking one would give the same
    /// pool two names — the split-liquidity bug canonical ordering exists to
    /// prevent. The asymmetry belongs on the *token*, where it is real: this
    /// token launched against xZEC, and everything else it trades against came
    /// later.
    ///
    /// `None` for xZEC itself and for LP assets, neither of which launches.
    pub genesis_pool: Option<PoolId>,
    /// What custodies this asset's value, if it is bridged rather than native.
    ///
    /// `None` for Zyn-native tokens, LP assets and items — things that exist
    /// because the VM minted them and are backed by nothing outside it.
    pub vault: Option<Vault>,
    /// What an item *is*: a hash of its content or metadata, chosen by the
    /// minter and committed at mint. `None` for fungible tokens.
    pub content: Option<[u8; 32]>,
    /// The collection this item belongs to, if any.
    ///
    /// A collection item posts no bond of its own: the collection's shared
    /// pool is what backs it, and what it is redeemed against. So `bond` is
    /// zero here and the backing lives in [`Collection::pool`] instead —
    /// which is also what lets the floor rise for every holder at once.
    pub collection: Option<CollectionId>,
    /// xZEC locked against this asset's existence, refunded when it is burned.
    ///
    /// The bond for an asset that has no pool to lock liquidity in. Held here
    /// rather than in a vault account on purpose: there is no address to
    /// transfer *from*, so no intent — and no sequencer — can move it. The only
    /// path out is destroying the asset, which is also the only thing that
    /// releases the state it occupies.
    ///
    /// This is a deposit, not rent. It is denominated in xZEC and it rises with
    /// ZEC, but it comes back: the cost of holding state is holding capital,
    /// not paying it away.
    pub bond: Fixed,
    /// Smallest transferable amount. `Fixed::raw(1)` is fully divisible, which
    /// is what xZEC, LP shares and ordinary tokens use.
    ///
    /// This is a **consensus rule, not a display scale** — the distinction that
    /// makes it safe to have here at all. ERC-20's `decimals` is a per-token
    /// scale factor every integrator has to apply and can mix up; this only
    /// answers whether a transfer is valid. All arithmetic stays in WAD.
    ///
    /// `Fixed::ONE` gives an asset that moves only in whole units — the shape a
    /// non-fungible or semi-fungible asset needs. Nothing in ZynZap issues one
    /// yet; the rail exists so that supporting Zcash Shielded Assets later is a
    /// parameter, not a change to what a balance *is*.
    pub unit: Fixed,
}

impl TokenInfo {
    /// An ordinary, fully divisible asset.
    pub fn divisible(symbol: Symbol, supply: Fixed) -> TokenInfo {
        TokenInfo {
            symbol,
            supply,
            lp_of: None,
            genesis_pool: None,
            unit: Fixed::raw(1),
            bond: Fixed::ZERO,
            vault: None, content: None, collection: None,
        }
    }

    /// A bridged asset: issued here, custodied elsewhere.
    pub fn bridged(symbol: Symbol, origin: ChainOrigin) -> TokenInfo {
        TokenInfo { vault: Some(Vault::new(origin)), ..TokenInfo::divisible(symbol, Fixed::ZERO) }
    }

    pub fn is_bridged(&self) -> bool {
        self.vault.is_some()
    }

    /// Whether this asset can be split at all.
    pub fn is_divisible(&self) -> bool {
        self.unit <= Fixed::raw(1)
    }

    /// Whether `amount` is a legal quantity of this asset.
    pub fn admits(&self, amount: Fixed) -> bool {
        if self.unit.0 <= 1 {
            return true;
        }
        amount.0 % self.unit.0 == 0
    }
}

/// A constant-product pool.
///
/// `asset0 < asset1` always. Canonical ordering means one pair has exactly one
/// representation, so `CAT/xZEC` and `xZEC/CAT` cannot become two pools with
/// split liquidity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pool {
    pub asset0: AssetId,
    pub asset1: AssetId,
    pub reserve0: Fixed,
    pub reserve1: Fixed,
    /// Fee in basis points, taken from the swap input and left in the reserves.
    /// Committed at creation: a pool's fee cannot be changed under its LPs.
    pub fee_bps: u16,
    /// The asset id minted to represent shares in this pool.
    pub lp_asset: AssetId,
    /// Shares outstanding, including `locked`.
    pub lp_supply: Fixed,
    /// Shares burned into the void by the first deposit. Never held by anyone,
    /// so supply can never return to zero and the first LP cannot corner it.
    pub locked: Fixed,
    /// A reported price for this pair, used **only** to set the fee.
    ///
    /// `None` for a pool whose price is discovered here — a memecoin against
    /// xZEC needs no reference and must not have one, because there is nothing
    /// outside to reference. Present for bridged pairs, where price is already
    /// discovered elsewhere and the curve is a slow mirror of it.
    ///
    /// It never touches a quote. See `amm::divergence_fee` for why that
    /// distinction is the whole safety argument.
    pub reference: Option<Reference>,
    /// Smallest input a swap may pay in on each side, in that side's own asset.
    ///
    /// The declarative answer to what Uniswap v4 does with hooks. A v4 hook is
    /// *code the pool calls*; this is *a constraint the pool declares*. The
    /// difference is not stylistic — arbitrary code inside a transition would
    /// reintroduce reentrancy, make work unbounded, and let value move in ways
    /// `conserved` cannot account for. A declared bound costs one comparison
    /// and none of that.
    ///
    /// `Fixed::raw(1)` on both sides is no constraint at all, which is the
    /// default. Raising it is a per-pool anti-dust measure: every swap consumes
    /// a sequence number and a share of a Zcash settlement whatever its size,
    /// so a pool that expects large trades can decline to subsidise a stream of
    /// one-unit ones.
    ///
    /// Distinct from `TokenInfo::unit`, which is *granularity* — what a legal
    /// quantity looks like — and is a property of the asset everywhere it goes,
    /// not of one market.
    pub min_in0: Fixed,
    pub min_in1: Fixed,
}

impl Pool {
    pub fn contains(&self, asset: AssetId) -> bool {
        asset == self.asset0 || asset == self.asset1
    }

    /// The other side of the pair, or `None` if `asset` is not in this pool.
    pub fn other(&self, asset: AssetId) -> Option<AssetId> {
        if asset == self.asset0 {
            Some(self.asset1)
        } else if asset == self.asset1 {
            Some(self.asset0)
        } else {
            None
        }
    }

    pub fn reserve_of(&self, asset: AssetId) -> Option<Fixed> {
        if asset == self.asset0 {
            Some(self.reserve0)
        } else if asset == self.asset1 {
            Some(self.reserve1)
        } else {
            None
        }
    }

    /// The smallest input this pool accepts when paying in `asset`.
    pub fn min_in(&self, asset: AssetId) -> Option<Fixed> {
        if asset == self.asset0 {
            Some(self.min_in0)
        } else if asset == self.asset1 {
            Some(self.min_in1)
        } else {
            None
        }
    }

    /// Reserves oriented as `(in, out)` for a swap of `asset_in`.
    pub fn oriented(&self, asset_in: AssetId) -> Option<(Fixed, Fixed)> {
        if asset_in == self.asset0 {
            Some((self.reserve0, self.reserve1))
        } else if asset_in == self.asset1 {
            Some((self.reserve1, self.reserve0))
        } else {
            None
        }
    }

    /// Add to one side's reserve.
    pub fn credit_reserve(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        if asset == self.asset0 {
            self.reserve0 = self.reserve0.add(amount)?;
        } else if asset == self.asset1 {
            self.reserve1 = self.reserve1.add(amount)?;
        } else {
            return None;
        }
        Some(())
    }

    /// Take from one side's reserve. Refuses to go negative: a reserve that can
    /// dip below zero is a pool that can be drained through a rounding path.
    pub fn debit_reserve(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        let r = self.reserve_of(asset)?;
        let next = r.sub(amount)?;
        if next.is_negative() {
            return None;
        }
        if asset == self.asset0 {
            self.reserve0 = next;
        } else {
            self.reserve1 = next;
        }
        Some(())
    }

    /// `k`, for the invariant that a swap never lowers it.
    pub fn k(&self) -> Option<Fixed> {
        self.reserve0.mul(self.reserve1)
    }
}

/// A reported price for a pair, and when it was reported.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reference {
    /// Units of `asset1` per unit of `asset0` — the same orientation as
    /// `amm::spot_price`, so the two are directly comparable.
    pub price: Fixed,
    /// Sequence number at which it was reported.
    ///
    /// Staleness is measured in sequence numbers rather than time because the
    /// VM has no clock and must not acquire one (**S1**). A quiet chain ages a
    /// reference slowly, which is the right behaviour: nothing has traded
    /// against it either.
    pub seq: u64,
}

impl Reference {
    /// Whether this reference is recent enough to price a fee from.
    ///
    /// A stale reference is not a slightly worse reference — it is a snapshot
    /// of a market that has moved on, and charging a divergence fee from it
    /// would penalise traders for the *reporter's* silence. When it ages out
    /// the pool falls back to its ordinary fee.
    pub fn is_fresh(&self, now: u64, staleness: u64) -> bool {
        staleness > 0 && now.saturating_sub(self.seq) <= staleness
    }
}

/// A ZynZap account: balances in every asset it holds, plus exits in flight.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Account {
    /// Sparse by design — an account holding only xZEC has one entry, and an
    /// asset it has never touched has none. `BTreeMap` so iteration order is
    /// the key order and never insertion order.
    pub balances: BTreeMap<AssetId, Fixed>,
    /// Units committed to a withdrawal request but not yet settled on the
    /// custodying chain, per asset.
    ///
    /// Held out of `balances` so the same units cannot back a swap and a
    /// pending exit at once, and still counted against supply so the backing
    /// invariant holds across the whole exit window.
    ///
    /// Per asset rather than a single figure, because an account may be
    /// exiting to Bitcoin and to Zcash at the same time and those are different
    /// vaults with different confirmation depths.
    pub pending: BTreeMap<AssetId, PendingExit>,
    /// Units minted against a deposit whose epoch has not been anchored yet.
    ///
    /// Real, backed, and not yet spendable. Counted against supply exactly like
    /// a pending exit, so the backing identity holds across the whole deposit
    /// window rather than only at its ends.
    pub incoming: BTreeMap<AssetId, PendingCredit>,
    /// Where this account's exits are allowed to go, if it has bound one.
    ///
    /// Optional, and worth setting: an account with no binding pays out
    /// wherever the request says, so a stolen key can name its own address. One
    /// binding covers every asset — a destination is a *user's* choice about
    /// where value leaves to, not a per-chain detail.
    pub binding: Option<Binding>,
    /// A holder-chosen secret folded into this account's published leaf.
    ///
    /// The data-availability payload is a tree of leaf hashes. A record is
    /// low-entropy — an id and a few balances — so without a blind anyone
    /// holding the payload could confirm a guess ("does X hold item N?") by
    /// hashing it. With one, they cannot. Zero means "never set", and the
    /// leaf is then the bare record, as it was before blinds existed — so an
    /// account that never shielded itself keeps the root it always had.
    pub blind: [u8; 32],
}

impl Account {
    pub fn balance(&self, asset: AssetId) -> Fixed {
        self.balances.get(&asset).copied().unwrap_or(Fixed::ZERO)
    }

    pub fn credit(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        if amount.is_negative() {
            return None;
        }
        let next = self.balance(asset).add(amount)?;
        // A zero credit against a zero balance must leave no entry behind, for
        // the same reason `debit` removes one: a zero in the map makes the
        // state root depend on what an account was *offered* rather than on
        // what it holds. Reachable whenever a caller credits a remainder that
        // happens to be nothing — a launch that seeds its entire supply, say.
        if next.is_zero() {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, next);
        }
        Some(())
    }

    /// Take `amount` of `asset`, refusing to overdraw.
    ///
    /// A zero balance is removed from the map rather than stored, so two
    /// accounts that have held the same assets and spent them to zero produce
    /// the same leaf. Leaving a zero entry behind would make the state root
    /// depend on history rather than on the balances it commits to.
    pub fn debit(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        if amount.is_negative() {
            return None;
        }
        let next = self.balance(asset).sub(amount)?;
        if next.is_negative() {
            return None;
        }
        if next.is_zero() {
            self.balances.remove(&asset);
        } else {
            self.balances.insert(asset, next);
        }
        Some(())
    }

    /// Units of `asset` committed to an exit.
    pub fn pending_of(&self, asset: AssetId) -> Fixed {
        self.pending.get(&asset).map(|p| p.amount).unwrap_or(Fixed::ZERO)
    }

    /// Units of `asset` credited but not yet claimable.
    pub fn incoming_of(&self, asset: AssetId) -> Fixed {
        self.incoming.get(&asset).map(|c| c.amount).unwrap_or(Fixed::ZERO)
    }

    /// The epoch this asset's exit was last increased, if one is outstanding.
    pub fn pending_since(&self, asset: AssetId) -> Option<u64> {
        self.pending.get(&asset).map(|p| p.since)
    }

    /// Move `amount` into the exit queue. Zero entries are never left behind,
    /// for the same reason `debit` removes them.
    pub fn set_pending(&mut self, asset: AssetId, amount: Fixed, since: u64) {
        if amount.is_zero() {
            self.pending.remove(&asset);
        } else {
            self.pending.insert(asset, PendingExit { amount, since });
        }
    }

    pub fn is_empty(&self) -> bool {
        // A blind or a binding is holder configuration: an account that set
        // one is not empty even with nothing in it, or the setting would be
        // swept away with the balance it was meant to protect.
        if self.blind != [0u8; 32] || self.binding.is_some() {
            return false;
        }
        self.balances.is_empty() && self.pending.is_empty() && self.incoming.is_empty()
    }
}

/// What one epoch commits to Zcash.
///
/// The spec's type: sealing, anchoring and recovery are shared infrastructure,
/// so the boundary between execution and settlement is the same shape for every
/// Zyn VM rather than re-specified per application.
pub use zyn_vm::checkpoint::Checkpoint;

/// A swap waiting for the epoch to seal.
///
/// With batch clearing on, a single-hop swap does not touch the pool when it
/// arrives. It is recorded here, and at the seal every order on the same
/// pool clears together at one price: what one side sells the other side
/// buys before the curve sees anything, and only the net residual moves the
/// reserves. Nothing is escrowed — the input stays in the account until the
/// clearing debits it — so an order whose account cannot pay by then simply
/// does not fill.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Order {
    pub seq: u64,
    pub account: AccountId,
    pub pool: PoolId,
    pub asset_in: AssetId,
    pub amount_in: Fixed,
    pub min_out: Fixed,
}

/// The whole microchain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SwapState {
    /// Identifies this microchain in a checkpoint, so a commitment from one
    /// chain can never be replayed as another's.
    pub chain_id: u32,
    /// Which execution epoch is running. Incremented by `checkpoint`.
    pub epoch: u64,
    /// Last applied sequence number, monotonic across the whole lineage rather
    /// than per epoch — an epoch boundary transfers the sequence space, it does
    /// not restart it.
    pub seq: u64,
    pub params: Params,
    pub accounts: BTreeMap<AccountId, Account>,
    pub tokens: BTreeMap<AssetId, TokenInfo>,
    pub pools: BTreeMap<PoolId, Pool>,
    /// State root of the last checkpointed epoch. `[0; 32]` at genesis.
    pub parent_root: Hash,
    /// Highest epoch known to have been carried to Zcash under a threshold
    /// certificate.
    ///
    /// Set by `ConfirmAnchor`, which the node emits only after it has collected
    /// and verified a certificate. Deposits credited in an epoch become
    /// spendable when this reaches it — so a fabricated credit is visible,
    /// inside the intent set a quorum must endorse, before it can move.
    pub finalized_epoch: u64,
    /// Hash chain over the intents applied since the last checkpoint.
    pub intent_acc: Hash,
    /// Intents applied since the last checkpoint, rejections included — a
    /// rejected intent is a real event in the chain's history.
    pub epoch_intents: u64,
    /// Gross swap volume this epoch, denominated in the input asset of each
    /// swap. A rough activity figure for the explorer, not an accounting one.
    pub epoch_gross_volume: Fixed,
    pub next_asset_id: AssetId,
    pub next_pool_id: PoolId,
    /// Collections, by id. Empty on a chain that has never had one, which is
    /// what keeps such a chain's roots unchanged by this feature existing.
    pub collections: BTreeMap<CollectionId, Collection>,
    pub next_collection_id: CollectionId,
    /// Whether single-hop swaps queue for the seal (see [`Order`]) or execute
    /// on arrival. Off by default; an operator turns it on with
    /// `Intent::SetClearing`.
    pub batch_clearing: bool,
    /// Orders waiting for the next seal, in sequence order.
    pub orders: Vec<Order>,
    /// ZYN and its launch, once the operator has set it (`launch.rs`).
    pub launch: Option<crate::launch::LaunchState>,
    /// Resting offers, by id. Empty on a chain that has never had one, which
    /// is what keeps such a chain's roots unchanged by this feature existing.
    pub offers: BTreeMap<OfferId, Offer>,
    pub next_offer_id: OfferId,
}

impl SwapState {
    /// A fresh microchain: xZEC exists with zero supply, nothing else does.
    pub fn new(chain_id: u32, params: Params) -> Self {
        let mut tokens = BTreeMap::new();
        // xZEC is simply the first bridged asset: units issued here against ZEC
        // custodied on Zcash. Nothing about it is special-cased any more.
        tokens.insert(XZEC, TokenInfo::bridged(symbol(b"ZEC.zy"), ORIGIN_ZCASH));
        SwapState {
            chain_id,
            epoch: 0,
            seq: 0,
            params,
            accounts: BTreeMap::new(),
            tokens,
            pools: BTreeMap::new(),
            parent_root: [0u8; 32],
            finalized_epoch: 0,
            intent_acc: [0u8; 32],
            epoch_intents: 0,
            epoch_gross_volume: Fixed::ZERO,
            next_asset_id: FIRST_USER_ASSET,
            collections: BTreeMap::new(),
            next_collection_id: 1,
            next_pool_id: 1,
            batch_clearing: false,
            orders: Vec::new(),
            launch: None,
            offers: BTreeMap::new(),
            next_offer_id: 1,
        }
    }

    /// The account for `id`, created empty if it does not exist.
    pub fn account_mut(&mut self, id: &AccountId) -> &mut Account {
        self.accounts.entry(*id).or_default()
    }

    pub fn balance(&self, id: &AccountId, asset: AssetId) -> Fixed {
        self.accounts.get(id).map(|a| a.balance(asset)).unwrap_or(Fixed::ZERO)
    }

    pub fn pool(&self, id: PoolId) -> Option<&Pool> {
        self.pools.get(&id)
    }

    pub fn token(&self, id: AssetId) -> Option<&TokenInfo> {
        self.tokens.get(&id)
    }

    /// The canonical xZEC market for `asset`, in one lookup.
    ///
    /// The common route is `X -> xZEC -> Y`, which is exactly two genesis
    /// markets, so routing the ordinary case no longer walks the pool set.
    pub fn genesis_market(&self, asset: AssetId) -> Option<PoolId> {
        self.tokens.get(&asset)?.genesis_pool
    }

    /// Every market `asset` trades in, canonical first.
    ///
    /// The one-to-many relation a token actually has. Secondary markets are
    /// still found by scanning, because they are not part of any token's
    /// identity — only the reference market is.
    pub fn markets(&self, asset: AssetId) -> Vec<PoolId> {
        let mut out = Vec::new();
        if let Some(g) = self.genesis_market(asset) {
            out.push(g);
        }
        for (&id, p) in self.pools.iter() {
            if p.contains(asset) && Some(id) != self.genesis_market(asset) {
                out.push(id);
            }
        }
        out
    }

    /// Find the pool trading `a` against `b`, in either order.
    ///
    /// Linear over pools rather than a maintained index. V1 holds a handful of
    /// pools, and a derived index is a second thing that can disagree with the
    /// data it was derived from — a class of bug the state root would not catch
    /// unless the index were also committed.
    pub fn find_pool(&self, a: AssetId, b: AssetId) -> Option<PoolId> {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        self.pools
            .iter()
            .find(|(_, p)| p.asset0 == lo && p.asset1 == hi)
            .map(|(id, _)| *id)
    }

    /// Mint `amount` of `asset` into existence, raising recorded supply.
    pub fn mint(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        if amount.is_negative() {
            return None;
        }
        let t = self.tokens.get_mut(&asset)?;
        t.supply = t.supply.add(amount)?;
        Some(())
    }

    /// Burn `amount` of `asset`, lowering recorded supply. Refuses to go
    /// negative.
    pub fn burn(&mut self, asset: AssetId, amount: Fixed) -> Option<()> {
        if amount.is_negative() {
            return None;
        }
        let t = self.tokens.get_mut(&asset)?;
        let next = t.supply.sub(amount)?;
        if next.is_negative() {
            return None;
        }
        t.supply = next;
        Some(())
    }

    /// Drop accounts that hold nothing.
    ///
    /// An account is created by any intent that names it, including one that
    /// then fails a later check, so without this the account map — and with it
    /// the state root — would record who had been *mentioned* rather than who
    /// holds a balance.
    pub fn prune_empty(&mut self) {
        self.accounts.retain(|_, a| !a.is_empty());
    }

    /// Total units of `asset` held across every account balance.
    pub fn total_held(&self, asset: AssetId) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for a in self.accounts.values() {
            sum = sum.add(a.balance(asset))?;
        }
        Some(sum)
    }

    /// Total units of `asset` sitting in pool reserves.
    pub fn total_reserved(&self, asset: AssetId) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for p in self.pools.values() {
            if let Some(r) = p.reserve_of(asset) {
                sum = sum.add(r)?;
            }
        }
        Some(sum)
    }

    /// Units of `asset` confirmed in its custodying vault, or zero if the asset
    /// is native to Zyn.
    pub fn backing_of(&self, asset: AssetId) -> Fixed {
        self.tokens
            .get(&asset)
            .and_then(|t| t.vault)
            .map(|v| v.confirmed)
            .unwrap_or(Fixed::ZERO)
    }

    /// The index the next deposit for `asset` must carry.
    ///
    /// A bridge operator needs this to build a credit at all, so it is public
    /// API rather than an internal detail: the sequence is the chain's, not the
    /// operator's, which is what stops two operators — or one operator twice —
    /// crediting the same external deposit.
    pub fn next_deposit_index(&self, asset: AssetId) -> u64 {
        self.tokens.get(&asset).and_then(|t| t.vault).map(|v| v.next_index()).unwrap_or(1)
    }

    /// Every bridged asset, with the chain that custodies it.
    pub fn bridged_assets(&self) -> Vec<(AssetId, ChainOrigin)> {
        self.tokens
            .iter()
            .filter_map(|(&id, t)| t.vault.map(|v| (id, v.origin)))
            .collect()
    }

    /// Total units of `asset` committed to exits across every account.
    pub fn total_pending(&self, asset: AssetId) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for a in self.accounts.values() {
            sum = sum.add(a.pending_of(asset))?;
        }
        Some(sum)
    }

    /// Total units of `asset` credited but not yet claimable.
    pub fn total_incoming(&self, asset: AssetId) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for a in self.accounts.values() {
            sum = sum.add(a.incoming_of(asset))?;
        }
        Some(sum)
    }

    /// Total xZEC held in collection redemption pools.
    ///
    /// Like a bond: real xZEC, backed, owned by no account and no pool, and so
    /// it has to be counted in the backing identity or the chain would look
    /// short by exactly the amount that makes the floor real.
    pub fn total_pooled(&self) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for c in self.collections.values() {
            sum = sum.add(c.pool)?;
        }
        Some(sum)
    }

    /// Total xZEC locked as bonds against indivisible assets.
    pub fn total_bonded(&self) -> Option<Fixed> {
        let mut sum = Fixed::ZERO;
        for t in self.tokens.values() {
            sum = sum.add(t.bond)?;
        }
        Some(sum)
    }


    /// Every asset id the chain knows about, in order.
    pub fn asset_ids(&self) -> Vec<AssetId> {
        self.tokens.keys().copied().collect()
    }

    /// The state as `cp` sealed it.
    ///
    /// Sealing commits a root and then advances the header — new epoch, cleared
    /// intent chain, reset volume — so the live state stops matching the root
    /// that was anchored the moment the epoch turns over. This rolls those
    /// header fields back to what the checkpoint recorded, leaving accounts,
    /// tokens and pools untouched because the advance never touched them.
    ///
    /// Returns `None` unless the result actually reproduces `cp.state_root`, so
    /// it is self-checking: a state that has moved on in ways the header cannot
    /// account for — a balance changed since the seal — reports that rather
    /// than handing back a view that would fail every proof built on it.
    pub fn as_sealed(&self, cp: &Checkpoint) -> Option<SwapState> {
        if cp.chain_id != self.chain_id {
            return None;
        }
        let mut s = self.clone();
        s.epoch = cp.epoch;
        s.seq = cp.seq;
        s.parent_root = cp.parent_root;
        s.intent_acc = cp.intent_root;
        s.epoch_intents = cp.intents;
        s.epoch_gross_volume = cp.gross_volume;
        if s.state_root() != cp.state_root {
            return None;
        }
        Some(s)
    }

    /// The core invariants, checked exhaustively.
    ///
    /// Cheap enough to run after every intent in tests and after every batch in
    /// a node. Not called by the VM itself: the VM's job is to never break
    /// these, and a runtime check inside the transition function would be a
    /// second implementation of the rules that could disagree with the first.
    pub fn check_invariants(&self) -> Result<(), &'static str> {
        // 1. Every token's supply equals what is actually held somewhere.
        for (&asset, info) in self.tokens.iter() {
            let held = self.total_held(asset).ok_or("overflow summing balances")?;
            let reserved = self.total_reserved(asset).ok_or("overflow summing reserves")?;
            let mut accounted = held.add(reserved).ok_or("overflow")?;

            // Units in flight in either direction still exist and are still
            // backed. Counting both is what keeps the backing identity true for
            // the whole time a deposit or an exit is in the air, rather than
            // only at the moments it is not.
            let pending = self.total_pending(asset).ok_or("overflow summing exits")?;
            accounted = accounted.add(pending).ok_or("overflow")?;
            let incoming = self.total_incoming(asset).ok_or("overflow summing credits")?;
            accounted = accounted.add(incoming).ok_or("overflow")?;
            if asset == XZEC {
                // Bonds are xZEC that exists and is backed but is held by no
                // account and no pool. Counting them here is what keeps the
                // backing identity true while an item is alive.
                accounted = accounted
                    .add(self.total_bonded().ok_or("overflow summing bonds")?)
                    .ok_or("overflow")?;
                accounted = accounted
                    .add(self.total_pooled().ok_or("overflow summing collection pools")?)
                    .ok_or("overflow")?;
            }
            if let Some(pool_id) = info.lp_of {
                // The locked minimum is owned by nobody but is real supply.
                let p = self.pools.get(&pool_id).ok_or("LP asset names no pool")?;
                accounted = accounted.add(p.locked).ok_or("overflow")?;
            }
            if accounted != info.supply {
                return Err("token supply does not match units held");
            }
            if info.supply.is_negative() {
                return Err("negative token supply");
            }
            if info.bond.is_negative() {
                return Err("negative bond");
            }
            if info.bond.is_positive() && info.is_divisible() {
                return Err("only an indivisible asset posts a bond");
            }
            if !info.unit.is_positive() {
                return Err("token unit must be positive");
            }
            if !info.admits(info.supply) {
                return Err("token supply is not a whole number of its own units");
            }
        }

        // 2. Every bridged unit is backed, per asset. The one the custody model
        //    stands on, and the reason pending exits stay counted.
        //
        //    Checked per asset on purpose: a shortfall in one bridge must not be
        //    concealable by a surplus in another, which is exactly what a single
        //    pooled figure would allow.
        if !self.tokens.contains_key(&XZEC) {
            return Err("xZEC token missing");
        }
        for info in self.tokens.values() {
            if let Some(v) = info.vault {
                // The vault's own coherence rules are the component's, not
                // ZynZap's: every VM that bridges checks exactly these.
                v.check(info.supply)?;
            }
        }

        // 3. A named canonical market must exist and must really be this
        //    token against xZEC.
        //
        //    Deliberately not "every token must name one". A bridged asset
        //    arrives through the vault rather than through a launch and has no
        //    pool of its own, and the state cannot tell the two apart without
        //    recording provenance it has no other use for. That every *launched*
        //    token has a market is enforced where it is actually true — at the
        //    creation path, which mints and pools in one intent — rather than
        //    asserted here over tokens that never went through it.
        for (&asset, info) in self.tokens.iter() {
            if let Some(id) = info.genesis_pool {
                let p = self.pools.get(&id).ok_or("genesis market does not exist")?;
                if !p.contains(asset) || !p.contains(XZEC) {
                    return Err("genesis market is not this token against xZEC");
                }
                if info.lp_of.is_some() {
                    return Err("an LP asset cannot have a canonical market");
                }
            }
        }

        // 4. Pools and LP accounting reconcile.
        for (&id, p) in self.pools.iter() {
            if p.asset0 >= p.asset1 {
                return Err("pool assets are not canonically ordered");
            }
            if p.reserve0.is_negative() || p.reserve1.is_negative() {
                return Err("negative pool reserve");
            }
            if p.lp_supply.is_negative() || p.locked.is_negative() {
                return Err("negative LP supply");
            }
            if p.locked > p.lp_supply {
                return Err("locked liquidity exceeds LP supply");
            }
            if p.fee_bps >= 10_000 {
                return Err("pool fee is not below 100%");
            }
            if !p.min_in0.is_positive() || !p.min_in1.is_positive() {
                return Err("a pool's minimum input must be positive");
            }
            let lp = self.tokens.get(&p.lp_asset).ok_or("pool LP asset missing")?;
            if lp.lp_of != Some(id) {
                return Err("LP asset does not point back at its pool");
            }
            if lp.supply != p.lp_supply {
                return Err("LP token supply disagrees with pool share supply");
            }
            // A pool with shares outstanding must hold both reserves, or those
            // shares are a claim on nothing.
            if p.lp_supply.is_positive() && !(p.reserve0.is_positive() && p.reserve1.is_positive())
            {
                return Err("pool has shares outstanding but an empty reserve");
            }
        }

        // 5. No account holds a negative balance or a negative pending exit.
        for a in self.accounts.values() {
            for (asset, c) in a.incoming.iter() {
                if !c.amount.is_positive() {
                    return Err("an unclaimed credit must be positive or absent");
                }
                if !self.tokens.get(asset).map(|t| t.is_bridged()).unwrap_or(false) {
                    return Err("an unclaimed credit against an asset with no vault");
                }
            }
            for (asset, p) in a.pending.iter() {
                let v = &p.amount;
                if !v.is_positive() {
                    return Err("a pending exit must be positive or absent");
                }
                if !self.tokens.get(asset).map(|t| t.is_bridged()).unwrap_or(false) {
                    return Err("a pending exit against an asset with no vault");
                }
            }
            for v in a.balances.values() {
                if v.is_negative() {
                    return Err("negative account balance");
                }
                if v.is_zero() {
                    return Err("zero balance left in the map");
                }
            }
        }

        // 6. Ids are only ever handed out going up.
        if self.next_asset_id < FIRST_USER_ASSET {
            return Err("next asset id is inside the reserved range");
        }
        if self.tokens.keys().any(|&a| a >= self.next_asset_id && a != XZEC) {
            return Err("an asset id was issued at or beyond the next id");
        }
        if self.pools.keys().any(|&p| p >= self.next_pool_id) {
            return Err("a pool id was issued at or beyond the next id");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SwapState {
        SwapState::new(1, Params::v1())
    }

    #[test]
    fn a_fresh_chain_holds_only_xzec_and_is_consistent() {
        let s = state();
        assert_eq!(s.tokens.len(), 1);
        assert_eq!(s.token(XZEC).unwrap().supply, Fixed::ZERO);
        assert!(s.pools.is_empty());
        s.check_invariants().expect("genesis must be consistent");
    }

    /// Crediting nothing must not create an entry, or two accounts that hold
    /// the same assets hash differently depending on what they were offered.
    #[test]
    fn crediting_zero_leaves_no_entry() {
        let mut a = Account::default();
        a.credit(7, Fixed::ZERO).unwrap();
        assert!(a.balances.is_empty(), "a zero credit created an entry");
        a.credit(7, Fixed::whole(5)).unwrap();
        a.credit(7, Fixed::ZERO).unwrap();
        assert_eq!(a.balance(7), Fixed::whole(5), "a zero credit disturbed a live balance");
    }

    #[test]
    fn debiting_to_zero_removes_the_entry() {
        // Otherwise two accounts holding nothing would hash differently
        // depending on what they had once held.
        let mut a = Account::default();
        a.credit(7, Fixed::whole(5)).unwrap();
        a.debit(7, Fixed::whole(5)).unwrap();
        assert!(a.balances.is_empty(), "a spent-to-zero balance stayed in the map");
        assert_eq!(a.balance(7), Fixed::ZERO);
    }

    #[test]
    fn an_account_cannot_overdraw() {
        let mut a = Account::default();
        a.credit(7, Fixed::whole(5)).unwrap();
        assert_eq!(a.debit(7, Fixed::whole(6)), None);
        assert_eq!(a.balance(7), Fixed::whole(5), "a failed debit moved the balance");
        assert_eq!(a.debit(9, Fixed::raw(1)), None, "debited an asset never held");
    }

    #[test]
    fn pool_orientation_follows_the_input_asset() {
        let p = Pool {
            asset0: 1,
            asset1: 5,
            reserve0: Fixed::whole(1_000),
            reserve1: Fixed::whole(10),
            fee_bps: 30,
            lp_asset: 6,
            lp_supply: Fixed::whole(100),
            locked: Fixed::raw(1_000),
                min_in0: Fixed::raw(1),
                min_in1: Fixed::raw(1),
                reference: None,
        };
        assert_eq!(p.oriented(1), Some((Fixed::whole(1_000), Fixed::whole(10))));
        assert_eq!(p.oriented(5), Some((Fixed::whole(10), Fixed::whole(1_000))));
        assert_eq!(p.oriented(9), None);
        assert_eq!(p.other(1), Some(5));
        assert_eq!(p.other(5), Some(1));
        assert_eq!(p.other(9), None);
    }

    #[test]
    fn a_reserve_cannot_be_driven_negative() {
        let mut p = Pool {
            asset0: 1,
            asset1: 5,
            reserve0: Fixed::whole(10),
            reserve1: Fixed::whole(10),
            fee_bps: 30,
            lp_asset: 6,
            lp_supply: Fixed::whole(10),
            locked: Fixed::ZERO,
                min_in0: Fixed::raw(1),
                min_in1: Fixed::raw(1),
                reference: None,
        };
        assert_eq!(p.debit_reserve(1, Fixed::whole(11)), None);
        assert_eq!(p.reserve0, Fixed::whole(10), "a failed debit moved the reserve");
        assert!(p.debit_reserve(1, Fixed::whole(10)).is_some());
        assert_eq!(p.reserve0, Fixed::ZERO);
    }

    #[test]
    fn find_pool_is_order_independent() {
        let mut s = state();
        s.pools.insert(
            1,
            Pool {
                asset0: 1,
                asset1: 5,
                reserve0: Fixed::ZERO,
                reserve1: Fixed::ZERO,
                fee_bps: 30,
                lp_asset: 6,
                lp_supply: Fixed::ZERO,
                locked: Fixed::ZERO,
                min_in0: Fixed::raw(1),
                min_in1: Fixed::raw(1),
                reference: None,
            },
        );
        assert_eq!(s.find_pool(1, 5), Some(1));
        assert_eq!(s.find_pool(5, 1), Some(1));
        assert_eq!(s.find_pool(1, 9), None);
    }

    #[test]
    fn unbacked_xzec_fails_the_invariant() {
        let mut s = state();
        s.mint(XZEC, Fixed::whole(10)).unwrap();
        s.account_mut(&[1u8; 32]).credit(XZEC, Fixed::whole(10)).unwrap();
        // Supply and balances agree, but nothing backs it.
        assert!(s.check_invariants().is_err(), "unbacked xZEC passed");
        let t = s.tokens.get_mut(&XZEC).unwrap();
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(10), 0).unwrap();
        v.credit(Fixed::whole(10), 1, 0).unwrap();
        t.vault = Some(v);
        s.check_invariants().expect("backed xZEC must pass");
    }

    #[test]
    fn a_balance_that_no_supply_accounts_for_fails() {
        let mut s = state();
        s.mint(XZEC, Fixed::whole(10)).unwrap();
        let t = s.tokens.get_mut(&XZEC).unwrap();
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(10), 0).unwrap();
        v.credit(Fixed::whole(10), 1, 0).unwrap();
        t.vault = Some(v);
        s.account_mut(&[1u8; 32]).credit(XZEC, Fixed::whole(11)).unwrap();
        assert!(s.check_invariants().is_err(), "unminted balance passed");
    }

    #[test]
    fn pending_exits_still_count_against_supply() {
        let mut s = state();
        s.mint(XZEC, Fixed::whole(10)).unwrap();
        let t = s.tokens.get_mut(&XZEC).unwrap();
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(10), 0).unwrap();
        v.credit(Fixed::whole(10), 1, 0).unwrap();
        t.vault = Some(v);
        let a = s.account_mut(&[1u8; 32]);
        a.credit(XZEC, Fixed::whole(4)).unwrap();
        a.set_pending(XZEC, Fixed::whole(6), 0);
        s.check_invariants().expect("balance plus pending must reconcile");

        // Losing track of a pending exit breaks the backing identity, which is
        // the whole point of holding it out of `balances` but still counting it.
        s.accounts.get_mut(&[1u8; 32]).unwrap().set_pending(XZEC, Fixed::whole(5), 0);
        assert!(s.check_invariants().is_err());
    }

    #[test]
    fn burning_below_zero_is_refused() {
        let mut s = state();
        s.mint(XZEC, Fixed::whole(1)).unwrap();
        assert_eq!(s.burn(XZEC, Fixed::whole(2)), None);
        assert_eq!(s.token(XZEC).unwrap().supply, Fixed::whole(1));
        assert_eq!(s.burn(999, Fixed::whole(1)), None, "burned an unknown asset");
    }

    #[test]
    fn prune_drops_accounts_that_hold_nothing() {
        let mut s = state();
        s.account_mut(&[1u8; 32]);
        s.account_mut(&[2u8; 32]).set_pending(XZEC, Fixed::whole(1), 0);
        assert_eq!(s.accounts.len(), 2);
        s.prune_empty();
        assert_eq!(s.accounts.len(), 1, "an account holding nothing survived");
        assert!(s.accounts.contains_key(&[2u8; 32]));
    }
}
