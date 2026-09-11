//! Core identifiers and chain parameters.

use crate::fixed::Fixed;

/// ZynZap account. An opaque 32-byte identity: in production this is derived
/// from the user's shielded spending key (a key hash), so the execution layer
/// never learns the Zcash address behind it. The vault maps deposits to this id
/// out-of-band; the VM only ever holds a balance for it.
pub type AccountId = [u8; 32];

/// An execution-layer asset. Assigned monotonically by the VM at creation so
/// ids cannot collide or be forged. Asset 1 is reserved:
pub type AssetId = u32;

/// xZEC — the 1:1 execution-layer representation of deposited ZEC.
///
/// The naming rule from the project plan: internally `xZEC`, displayed to users
/// simply as "ZEC". Every unit must be backed:
///
/// ```text
/// xZEC liabilities == confirmed ZEC backing
/// ```
///
/// enforced as `tokens[XZEC].supply == sum(balances) + sum(pending exits) ==
/// xzec_backing`, tested after every intent in the test suite.
pub const XZEC: AssetId = 1;

/// Which external chain custodies a bridged asset's value.
///
/// The component's, not ZynZap's: custody is not a swap concept.
pub use zyn_bridge::{ChainOrigin, ORIGIN_BITCOIN, ORIGIN_ETHEREUM, ORIGIN_SOLANA, ORIGIN_ZCASH};

/// Identifies one pool. Assigned by the VM, never chosen by clients.
pub type PoolId = u32;

/// A collection: a set of items sharing one redemption pool.
pub type CollectionId = u32;

/// Identifies a resting offer. Monotonic, never reused — a taker names an
/// offer by id, and an id that came back would let them take a different one.
pub type OfferId = u64;

/// Asset ids below this are reserved (xZEC = 1); user tokens start at 2.
pub const FIRST_USER_ASSET: AssetId = 2;

/// Parameters of the chain. Deliberately tiny next to perpvm's RiskParams: a
/// constant-product AMM has no margin engine to configure. Supplied to the VM
/// and enforced, never computed — same principle, less to get wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Params {
    /// Swap fee in basis points, taken from the input amount. 30 == 0.30%,
    /// the Uniswap-v2 figure the plan fixes for V1. Committed per pool at
    /// creation; this field is the default new pools receive.
    pub default_fee_bps: u16,
    /// Shares permanently locked by a pool's first liquidity deposit. Prevents
    /// the first-LP exploit where a microscopic deposit owns 100% of supply and
    /// can then donate to inflate later mints. Uniswap v2's MINIMUM_LIQUIDITY.
    pub min_liquidity: Fixed,
    /// Maximum hops in one routed swap. V1 routing is direct or one
    /// intermediate xZEC hop, so 2 covers the plan; the bound exists because a
    /// path is sequenced input and unbounded input is unbounded work.
    pub max_hops: u8,
    /// The protocol's share **of the swap fee**, in basis points of that fee —
    /// not an additional charge on the trader.
    ///
    /// At 0 the entire fee stays in the pool, which is the plan's V1 rule. The
    /// rail exists at zero rather than being added later because turning on
    /// revenue must be a parameter change, not a change to how value moves: a
    /// protocol cut introduced afterwards would alter the swap path, the state
    /// root, and every proof written against it.
    ///
    /// The cut comes out of the fee the pool would otherwise keep, so the
    /// trader's quote is unchanged and `k` still never falls — the pool retains
    /// `fee - cut`, which is at least what the curve requires.
    pub protocol_fee_share_bps: u16,
    /// xZEC that a pool against xZEC must be opened with, and that is then
    /// **permanently locked** in it.
    ///
    /// The anti-spam bond, and the reason this chain has no rent. Rent is
    /// denominated in the native asset and paid to nobody, so a successful
    /// economy makes the cost of building on it rise while the payment stays
    /// deadweight — the incentive points the wrong way. A locked launch pool
    /// costs the same capital and converts it into the one thing a swap venue
    /// needs: a market. It is not extracted, it is deployed.
    ///
    /// Three consequences worth naming:
    ///
    /// - Spam is bounded by capital rather than by fees, and the bound is real
    ///   because the locked share is unrecoverable.
    /// - Every token in the state is a *tradeable* token. There is no such
    ///   thing here as an asset with no market taking up room.
    /// - xZEC becomes the routing hub by construction, so the `max_hops = 2`
    ///   bound stops being an assumption about connectivity and becomes a
    ///   property of how tokens come into existence.
    ///
    /// Denominated in xZEC and adjusted by governance, because the VM has no
    /// oracle and must not acquire one.
    pub min_pool_xzec: Fixed,
    /// Epochs after which an unconfirmed exit may be cancelled by its owner.
    ///
    /// The answer to the plan's ninth invariant: a failed sequencer must not
    /// make reserves permanently inaccessible. Without this an exit is a
    /// one-way door — units leave the balance, and if the vault never pays they
    /// are stuck in a queue nobody can drain.
    ///
    /// It is a *coordination deadline*, not a convenience: once it passes, the
    /// chain will let the owner take the units back, and an operator who
    /// broadcasts a payout afterwards has paid out on the far chain without
    /// being able to burn anything here. Set it far longer than any settlement
    /// could honestly take. Zero disables cancellation entirely.
    pub exit_timeout_epochs: u64,
    /// How many sequence numbers a reported price stays usable for.
    ///
    /// Zero disables reference pricing entirely, which is the correct setting
    /// for a chain that has no reporter it trusts. Measured in sequence numbers
    /// because the VM has no clock.
    pub reference_staleness: u64,
    /// Where the protocol's share accrues. An ordinary account, so revenue is
    /// an ordinary balance: it can be swapped, routed and withdrawn through the
    /// same paths as anyone else's, and it is covered by supply conservation
    /// without a second accounting mechanism.
    pub treasury: AccountId,
}

impl Params {
    /// V1 defaults from the project plan: 0.30% fee, Uniswap's minimum
    /// liquidity, one intermediate hop, and the whole fee to LPs.
    pub fn v1() -> Self {
        Params {
            default_fee_bps: 30,
            // 1000 raw units == 1e-15 whole units, Uniswap v2's figure.
            min_liquidity: Fixed::raw(1_000),
            max_hops: 2,
            // Bootstrap liquidity before taxing it. The plan is explicit that
            // protocol fees come after real usage exists.
            protocol_fee_share_bps: 0,
            treasury: [0u8; 32],
            // One xZEC to launch a token. Cheap for a real project, expensive
            // in bulk, and recoverable as liquidity rather than burned. The
            // headline tuning knob for how open the chain is.
            min_pool_xzec: Fixed::whole(1),
            // Long enough that a slow chain, a signer rotation and a weekend
            // all fit inside it.
            exit_timeout_epochs: 2_016,
            // A few hundred actions. Long enough that a quiet pair keeps its
            // reference, short enough that a busy one repriced without a fresh
            // report falls back to the ordinary fee rather than a wrong one.
            reference_staleness: 500,
        }
    }

    /// Parameters scaled to what a testnet faucet actually dispenses.
    ///
    /// The Zcash testnet faucet gives **0.1 TAZ** per request behind a
    /// browser proof-of-work. Against `v1`'s one-whole-unit
    /// `min_pool_xzec`, opening a single pool costs ten faucet requests before
    /// any trading liquidity exists — so `v1` is not merely inconvenient on
    /// testnet, it is a wall.
    ///
    /// Only the economic floors move. Fees, hop limits and staleness stay
    /// exactly as production has them, because a testnet whose *behaviour*
    /// differs from mainnet tests the wrong program. And `exit_timeout_epochs`
    /// stays long: shortening the window a user relies on to leave would make
    /// the one property most worth rehearsing the one property never
    /// rehearsed.
    pub fn testnet() -> Self {
        Params {
            // A hundredth of a faucet grant, so one request funds a pool and
            // still leaves change to trade with.
            min_pool_xzec: Fixed::raw(1_000_000_000_000_000), // 0.001
            ..Params::v1()
        }
    }

    /// Whether any swap fee is routed to the treasury.
    pub fn takes_protocol_fee(&self) -> bool {
        self.protocol_fee_share_bps > 0
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.default_fee_bps >= 10_000 {
            return Err("fee must be below 100% (basis points)");
        }
        if self.min_liquidity.is_negative() {
            return Err("minimum liquidity must not be negative");
        }
        if self.max_hops == 0 {
            return Err("max hops must allow at least a direct swap");
        }
        if self.min_pool_xzec.is_negative() {
            return Err("the launch bond must not be negative");
        }
        if self.protocol_fee_share_bps >= 10_000 {
            // A full cut would leave LPs nothing for carrying the inventory
            // risk, and `k` would stop being non-decreasing.
            return Err("protocol share must be below 100% of the fee");
        }
        Ok(())
    }
}

#[cfg(test)]
mod testnet_params_tests {
    use super::*;

    /// A faucet grant has to be enough to actually use the chain, or the test
    /// plan stalls on our own floor rather than on anything real.
    #[test]
    fn one_faucet_grant_can_open_a_pool_and_still_trade() {
        let taz = Fixed::raw(100_000_000_000_000_000); // 0.1 TAZ
        let p = Params::testnet();
        assert!(p.min_pool_xzec < taz, "one faucet grant cannot open a pool");
        // And with room to spare, not merely by a hair.
        assert!(
            p.min_pool_xzec.mul(Fixed::whole(50)).unwrap() < taz,
            "a grant opens a pool but leaves nothing to trade"
        );
    }

    /// Only the floors move. A testnet that behaves differently tests a
    /// different program.
    #[test]
    fn testnet_changes_the_floor_and_nothing_else() {
        let (a, b) = (Params::v1(), Params::testnet());
        assert_ne!(a.min_pool_xzec, b.min_pool_xzec);
        assert_eq!(a.default_fee_bps, b.default_fee_bps);
        assert_eq!(a.max_hops, b.max_hops);
        assert_eq!(a.reference_staleness, b.reference_staleness);
        assert_eq!(a.min_liquidity, b.min_liquidity);
        assert_eq!(
            a.exit_timeout_epochs, b.exit_timeout_epochs,
            "the exit window is the property most worth rehearsing"
        );
    }

    #[test]
    fn testnet_params_are_valid() {
        assert!(Params::testnet().validate().is_ok());
    }
}
