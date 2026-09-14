//! Core identifiers and chain parameters.

use crate::fixed::Fixed;

/// ZynZap account. An opaque 32-byte identity: in production this is derived
/// from the user's shielded spending key (a key hash), so the execution layer
/// never learns the Zcash address behind it. The vault maps deposits to this id
/// out-of-band; the VM only ever holds a balance for it.
pub type AccountId = [u8; 32];

/// A deterministic execution-layer identity.
///
/// Assets, pools and collections share the same 32-byte representation but
/// occupy disjoint derivation namespaces. Keeping aliases makes their role
/// visible in APIs while preserving cheap copy semantics inside the VM.
pub type AssetId = [u8; 32];

/// Frozen address-derivation scope. Changing these bytes would rename every
/// asset, pool, vault, collection and item, so upgrades use a new scope.
///
/// Re-exported rather than redeclared. Two independent literals of the same
/// frozen value are two things that can drift, and §66.10 exists precisely so
/// this one cannot — a second copy would let a careless edit rename every
/// persistent identity in one crate while the other kept the old bytes.
pub use zyn_vm::derive::ADDRESS_SCOPE_V1;

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
pub const XZEC: AssetId = [
    0x0e, 0x21, 0x22, 0x62, 0xcb, 0x35, 0xbf, 0x6e, 0x88, 0xbc, 0x7d, 0x0a, 0x52, 0xb6, 0x0a, 0x5c,
    0xc7, 0x0c, 0x28, 0x59, 0xb6, 0x59, 0x66, 0xa2, 0x55, 0x72, 0x29, 0xd2, 0xea, 0x46, 0x92, 0x01,
];

/// Keyless account that accumulates ZEC.zy for future ZYN protocol-owned
/// liquidity. This is `derive(ADDRESS_SCOPE_V1, "zyn-pol", [ZEC.zy])`, pinned
/// as a constant so every execution and explorer names the same account.
pub const ZYN_POL: AccountId = [
    0xf4, 0x04, 0x35, 0xd1, 0x40, 0x6a, 0xbc, 0x3a, 0xa4, 0xbe, 0xfa, 0xf3, 0x80, 0xac, 0xea, 0x34,
    0xa4, 0xa8, 0x7e, 0xd7, 0x6a, 0x51, 0x53, 0x8f, 0x88, 0xd0, 0x9b, 0xa0, 0xd2, 0x93, 0x7e, 0x61,
];

pub const ZYN_MAINNET: AssetId = [
    0x49, 0xeb, 0x92, 0x41, 0xe2, 0xa0, 0xb1, 0x16, 0x3a, 0x1e, 0xed, 0x09, 0xbb, 0x91, 0xa5, 0x75,
    0xc9, 0x3b, 0xbc, 0x6e, 0x76, 0xcd, 0x7a, 0xfe, 0xb6, 0x52, 0x63, 0x64, 0x0f, 0xd1, 0x69, 0xd5,
];
pub const ZYN_TESTNET: AssetId = [
    0x89, 0x3e, 0x74, 0x5e, 0x33, 0xb4, 0x03, 0x10, 0x00, 0x30, 0x11, 0xa1, 0x46, 0x51, 0xdc, 0x3c,
    0xf1, 0x73, 0xf7, 0x1b, 0x92, 0xee, 0x6e, 0x77, 0xef, 0x62, 0xb7, 0xba, 0x5a, 0x84, 0xe5, 0x6e,
];
pub const TAZ_ZY: AssetId = [
    0xbf, 0x24, 0x4a, 0x27, 0xad, 0x73, 0xfe, 0xa5, 0x12, 0x8f, 0xea, 0xd6, 0x91, 0xc6, 0x47, 0xfe,
    0x1c, 0x5a, 0x5c, 0xdd, 0xe0, 0xa8, 0x47, 0xb2, 0x4c, 0xa2, 0x00, 0x41, 0x25, 0x0d, 0xa4, 0x8e,
];
pub const SOL_ZY: AssetId = [
    0x0f, 0x61, 0xf4, 0x34, 0x0c, 0xd6, 0xa9, 0x10, 0xec, 0x8d, 0x7e, 0x73, 0xef, 0x23, 0x95, 0x69,
    0xb8, 0x3f, 0x16, 0x09, 0x9e, 0x62, 0x07, 0x86, 0xe7, 0x1e, 0x7e, 0x73, 0x95, 0xc9, 0xf6, 0xdf,
];
pub const BTC_ZY: AssetId = [
    0x0e, 0x7f, 0xaa, 0x55, 0xf3, 0xbd, 0xb1, 0x2e, 0x80, 0x78, 0x1d, 0xa8, 0x8f, 0xb5, 0xac, 0x4e,
    0xb7, 0xe2, 0x4d, 0x19, 0x35, 0x49, 0x4b, 0x9a, 0xab, 0xd8, 0x4c, 0x45, 0x65, 0xbb, 0xff, 0xca,
];
pub const USDC_ZY_SOLANA: AssetId = [
    0x83, 0xe6, 0x6d, 0x69, 0x4a, 0xf6, 0x8a, 0x84, 0x4f, 0x4e, 0xa9, 0xa6, 0x1d, 0x73, 0xbc, 0xe7,
    0xff, 0xa8, 0xe5, 0x3f, 0xc7, 0x80, 0x02, 0x38, 0x68, 0xf8, 0x25, 0xc2, 0xe7, 0x53, 0xc7, 0x9a,
];
pub const BOLD_ZY_ETHEREUM: AssetId = [
    0xdd, 0xf2, 0xb7, 0xec, 0xc2, 0x63, 0x4e, 0x39, 0xa8, 0x91, 0xa1, 0x90, 0x20, 0x20, 0x5a, 0xe2,
    0x6a, 0x87, 0xe9, 0xf7, 0x53, 0xe4, 0x92, 0xe0, 0x3b, 0x84, 0xe7, 0xdc, 0x62, 0x7f, 0x25, 0x0f,
];

/// Official status is address-based. A user may reuse any display name or
/// ticker, but cannot derive one of these addresses because user assets live
/// in the separate `asset` namespace.
pub fn is_official_asset(chain_id: u32, asset: &AssetId) -> bool {
    *asset == XZEC
        || *asset == TAZ_ZY
        || *asset == SOL_ZY
        || *asset == BTC_ZY
        || *asset == USDC_ZY_SOLANA
        || *asset == BOLD_ZY_ETHEREUM
        || (chain_id == 26_460 && *asset == ZYN_MAINNET)
        || (chain_id == 11 && *asset == ZYN_TESTNET)
}

/// Which external chain custodies a bridged asset's value.
///
/// The component's, not ZynZap's: custody is not a swap concept.
pub use zyn_bridge::{ChainOrigin, ORIGIN_BITCOIN, ORIGIN_ETHEREUM, ORIGIN_SOLANA, ORIGIN_ZCASH};

/// Identifies one canonical unordered asset pair.
pub type PoolId = [u8; 32];

/// A collection: a set of items sharing one redemption pool.
pub type CollectionId = [u8; 32];

/// Identifies a resting offer. Monotonic, never reused — a taker names an
/// offer by id, and an id that came back would let them take a different one.
pub type OfferId = u64;

/// A deterministic fixture id for tests and legacy-state migration.
/// Production creation paths use the address derivation functions instead.
pub const fn legacy_id(n: u32) -> [u8; 32] {
    let bytes = n.to_be_bytes();
    let mut out = [0u8; 32];
    out[28] = bytes[0];
    out[29] = bytes[1];
    out[30] = bytes[2];
    out[31] = bytes[3];
    out
}

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

    #[test]
    fn future_zyn_pol_has_the_pinned_derived_address() {
        assert_eq!(
            ZYN_POL,
            zyn_vm::derive(ADDRESS_SCOPE_V1, b"zyn-pol", &[&XZEC])
        );
    }

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
