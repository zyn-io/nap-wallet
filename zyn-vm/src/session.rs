//! Session keys: signing once to authorise many intents.
//!
//! # The problem this actually solves
//!
//! Not Ledger. Ledger is the symptom.
//!
//! ZynZap's entire claim is that trading is fast — settlement batched into
//! epochs, hundreds of thousands of swaps a second in the engine. A wallet
//! popup per swap throws all of it away at the last step. The user's
//! experience is not the sequencer's throughput; it is how long it takes to
//! make a trade, and a MetaMask confirmation is several seconds of reading a
//! dialog. A fast AMM that asks permission for every fill is a slow AMM with a
//! fast engine inside it.
//!
//! So the mainstream wallet should be asked **once**, and what it authorises is
//! a key that can trade — not a trade.
//!
//! # What it buys elsewhere
//!
//! - **Hardware wallets.** A Ledger holding a Solana account needs "allow blind
//!   sign" for UTF-8 offchain messages. One blind sign to open a session is a
//!   very different ask from one per trade.
//! - **Mobile.** Every signature is an app switch. Sessions make that once.
//!
//! # Why this is not just a smaller key with the same powers
//!
//! A session key lives in a browser. It *will* leak. What makes that
//! survivable is that it is issued with strictly less authority than the key
//! that issued it:
//!
//! - it **expires**, in epochs, like every other authorisation here (**S12**);
//! - it carries **capabilities**, and the dangerous ones are withheld by
//!   default. A default session can swap but cannot transfer to another Zyn
//!   account, withdraw, or change account authority;
//! - it **cannot delegate**, so a leaked session cannot mint a quieter,
//!   longer-lived successor.
//!
//! Stacked on the withdrawal binding — a payout destination is bound in state
//! and redirecting it waits out `exit_timeout_epochs` — the worst a stolen
//! session key achieves is bad swaps until it expires. That is a real loss and
//! not a pretended one; it cannot become a direct payment to the attacker.
//!
//! # Why a certificate and not a registry
//!
//! Delegation could be an intent that writes to state. It is not, for the
//! reason [`crate::auth::Scheme`] gives: state is a second thing to authorise
//! and a second thing to steal, and here it would also cost a round trip
//! before the first trade.
//!
//! A [`Delegation`] is a certificate. The sequencer checks a signature chain —
//! owner signed the delegation, session signed the intent — and needs to look
//! nothing up. The cost is that revocation is expiry rather than an instant
//! switch, which is why sessions are short.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::commit::{Encoder, Hash};
use crate::spec::{AccountId, MicrochainVm};

/// Trading against a deterministic market. This is the only authority a
/// default session receives: a leaked session may choose a bad price, but it
/// cannot name a recipient or change the account's long-lived configuration.
pub const CAP_SWAP: u32 = 1 << 0;

/// Moving value off this chain. The irreversible one, and the one a session
/// key should almost never have.
pub const CAP_WITHDRAW: u32 = 1 << 1;

/// Changing who may act for an account — delegating, or binding a withdrawal
/// destination. Withheld from sessions always, so a leaked key cannot widen
/// its own authority or issue a successor.
pub const CAP_DELEGATE: u32 = 1 << 2;

/// Commit, take, cancel, or co-sign an offer.
pub const CAP_OFFER: u32 = 1 << 3;
/// Create or change a liquidity position.
pub const CAP_LIQUIDITY: u32 = 1 << 4;
/// Move value to another account on Zyn.
pub const CAP_TRANSFER: u32 = 1 << 5;
/// Create or destroy a standalone item or token.
pub const CAP_ITEM: u32 = 1 << 6;
/// Create, fund, advance, mint into, or redeem from a collection.
pub const CAP_COLLECTION: u32 = 1 << 7;
/// Rotate the privacy blind committed in an account record.
pub const CAP_PRIVACY: u32 = 1 << 8;

/// Every non-withdrawal, non-delegation application capability.
///
/// Kept as an explicit aggregate for callers that deliberately want the old
/// warm-key authority. It is no longer a bit and is never the session default.
pub const CAP_OPERATE: u32 =
    CAP_SWAP | CAP_OFFER | CAP_LIQUIDITY | CAP_TRANSFER | CAP_ITEM | CAP_COLLECTION | CAP_PRIVACY;

/// What a session may do unless told otherwise.
///
/// Trade, and nothing else. Any wider default would eventually be taken by
/// someone who did not choose it, and the point of the mechanism is that the
/// dangerous powers are the ones you have to ask for.
pub const SESSION_DEFAULT: u32 = CAP_SWAP;

/// Domain tag for delegation payloads. Distinct from `zyn.auth.v1`, so a
/// signature over an intent can never be read as a signature over a
/// delegation — which would be a signature granting authority instead of
/// exercising it.
const DELEGATION_DOMAIN: &[u8] = b"zyn.delegate.v2";
pub const MAX_POLICY_ITEMS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssetLimit {
    pub asset: [u8; 32],
    pub amount: crate::fixed::Fixed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DelegationPolicyError {
    Malformed,
    NotStarted,
    WrongAsset,
    WrongPool,
    OverLimit,
    ExcessiveSlippage,
    UnsupportedIntent,
}

/// One key's authority to act for an account, for a while, within limits.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Delegation {
    /// The account being acted for. Not the session's own account — a session
    /// key has no balance and never appears in state.
    pub account: AccountId,
    /// The ed25519 public key that may sign on its behalf.
    pub session_key: [u8; 32],
    /// Bitmask of the `CAP_*` constants in this module.
    pub capabilities: u32,
    /// Empty lists describe an ordinary capability-only session. Agent
    /// mandates populate all three and SwapVM enforces them at execution.
    pub allowed_assets: Vec<[u8; 32]>,
    pub allowed_pools: Vec<[u8; 32]>,
    pub max_per_action: Vec<AssetLimit>,
    pub max_slippage_bps: u16,
    pub valid_from_epoch: u64,
    /// Owner-chosen uniqueness, so two otherwise identical grants remain
    /// distinct and session signatures do not cross between them.
    pub salt: [u8; 32],
    /// Inclusive last epoch. There is no "never expires" here on purpose:
    /// [`crate::auth::Authorization`] allows `u64::MAX` for an intent because a
    /// specific intent is its own limit, but an unbounded delegation is a
    /// second account key with none.
    pub valid_until_epoch: u64,
}

impl Delegation {
    /// A trade-only session for `epochs` from now.
    pub fn session(
        account: AccountId,
        session_key: [u8; 32],
        now_epoch: u64,
        epochs: u64,
    ) -> Delegation {
        Delegation {
            account,
            session_key,
            capabilities: SESSION_DEFAULT,
            allowed_assets: Vec::new(),
            allowed_pools: Vec::new(),
            max_per_action: Vec::new(),
            max_slippage_bps: 0,
            valid_from_epoch: now_epoch,
            salt: [0u8; 32],
            valid_until_epoch: now_epoch.saturating_add(epochs),
        }
    }

    /// Whether this delegation covers everything `needs` requires.
    ///
    /// [`CAP_DELEGATE`] is refused unconditionally, whatever the mask says. A
    /// delegation that could grant delegation is an account key with extra
    /// steps, and the mistake is one intersection away — so it is not
    /// expressible rather than merely discouraged.
    pub fn permits(&self, needs: u32) -> bool {
        if needs & CAP_DELEGATE != 0 || self.capabilities & CAP_DELEGATE != 0 {
            return false;
        }
        needs != 0 && needs & !self.capabilities == 0
    }

    pub fn constrained(&self) -> bool {
        !self.allowed_assets.is_empty()
            || !self.allowed_pools.is_empty()
            || !self.max_per_action.is_empty()
    }

    pub fn policy_is_well_formed(&self) -> bool {
        if self.valid_from_epoch > self.valid_until_epoch
            || self.max_slippage_bps > 2_000
            || self.allowed_assets.len() > MAX_POLICY_ITEMS
            || self.allowed_pools.len() > MAX_POLICY_ITEMS
            || self.max_per_action.len() > MAX_POLICY_ITEMS
        {
            return false;
        }
        let sorted_unique = |values: &[[u8; 32]]| values.windows(2).all(|w| w[0] < w[1]);
        sorted_unique(&self.allowed_assets)
            && sorted_unique(&self.allowed_pools)
            && self
                .max_per_action
                .iter()
                .all(|limit| limit.amount.is_positive())
            && self
                .max_per_action
                .windows(2)
                .all(|w| w[0].asset < w[1].asset)
            && (!self.constrained()
                || (!self.allowed_assets.is_empty()
                    && !self.allowed_pools.is_empty()
                    && !self.max_per_action.is_empty()))
    }

    fn encode_policy(&self, e: &mut Encoder) {
        e.u8(self.allowed_assets.len() as u8);
        for asset in &self.allowed_assets {
            e.bytes(asset);
        }
        e.u8(self.allowed_pools.len() as u8);
        for pool in &self.allowed_pools {
            e.bytes(pool);
        }
        e.u8(self.max_per_action.len() as u8);
        for limit in &self.max_per_action {
            e.bytes(&limit.asset).fixed(limit.amount);
        }
        e.u16(self.max_slippage_bps)
            .u64(self.valid_from_epoch)
            .bytes(&self.salt);
    }

    pub fn policy_hash(&self) -> Hash {
        let mut e = Encoder::new();
        e.bytes(b"zyn.delegate.policy.v1");
        self.encode_policy(&mut e);
        e.leaf()
    }

    /// The bytes the owner's wallet signs to issue this.
    pub fn payload(&self, chain_id: u32, vm_id: &Hash) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(DELEGATION_DOMAIN)
            .u32(chain_id)
            .bytes(vm_id)
            .bytes(&self.account)
            .bytes(&self.session_key)
            .u32(self.capabilities)
            .bytes(&self.policy_hash())
            .u64(self.valid_until_epoch);
        e.finish().to_vec()
    }

    /// A stable identity for this delegation, bound into every intent the
    /// session signs.
    ///
    /// Without it, a key delegated by two accounts could have one of its
    /// signatures replayed under the other's delegation — the session's
    /// signature says nothing about whose authority it is exercising.
    pub fn id(&self, chain_id: u32, vm_id: &Hash) -> Hash {
        let mut h = Sha256::new();
        h.update(self.payload(chain_id, vm_id));
        h.finalize().into()
    }

    /// What a wallet shows when asked to open a session.
    ///
    /// This is the most consequential prompt in the system — it is where a
    /// user hands over the ability to trade — so it names the powers granted
    /// in words rather than as a number nobody reads.
    pub fn typed(&self) -> crate::eip712::TypedData {
        use crate::eip712::{TypedData, Value};
        use alloc::string::String;

        let mut granted = String::new();
        for (bit, name) in [
            (CAP_SWAP, "swap"),
            (CAP_OFFER, "manage offers"),
            (CAP_LIQUIDITY, "manage liquidity"),
            (CAP_TRANSFER, "transfer on Zyn"),
            (CAP_ITEM, "manage items and tokens"),
            (CAP_COLLECTION, "manage collections"),
            (CAP_PRIVACY, "rotate privacy blinds"),
            (CAP_WITHDRAW, "withdraw"),
            (CAP_DELEGATE, "delegate"),
        ] {
            if self.capabilities & bit != 0 {
                if !granted.is_empty() {
                    granted.push_str(", ");
                }
                granted.push_str(name);
            }
        }
        if granted.is_empty() {
            granted.push_str("nothing");
        }
        TypedData::new("AuthorizeSession")
            .field("account", Value::Bytes32(self.account))
            .field("sessionKey", Value::Bytes32(self.session_key))
            .field("mayOnly", Value::String(granted))
            .field("policyHash", Value::Bytes32(self.policy_hash()))
            .field("validFromEpoch", Value::uint(self.valid_from_epoch))
            .field("validUntilEpoch", Value::uint(self.valid_until_epoch))
    }
}

/// The bytes a session key signs for one intent.
///
/// The delegation's id is inside, so this signature is worthless under any
/// other delegation, and the domain differs from both an intent signature and
/// a delegation signature.
pub fn session_payload<V: MicrochainVm>(
    delegation_id: &Hash,
    auth: &crate::auth::Authorization,
    intent: &V::Intent,
) -> Vec<u8> {
    let encoded = V::encode_intent(intent);
    let mut e = Encoder::new();
    e.bytes(b"zyn.session.v1")
        .bytes(delegation_id)
        .u32(auth.chain_id)
        .bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u32(encoded.len() as u32)
        .bytes(&encoded);
    e.finish().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(caps: u32) -> Delegation {
        let mut d = Delegation::session([1u8; 32], [2u8; 32], 0, 10);
        d.capabilities = caps;
        d
    }

    #[test]
    fn a_default_session_may_trade_and_nothing_else() {
        let s = d(SESSION_DEFAULT);
        assert!(s.permits(CAP_SWAP));
        for denied in [
            CAP_OFFER,
            CAP_LIQUIDITY,
            CAP_TRANSFER,
            CAP_ITEM,
            CAP_COLLECTION,
            CAP_PRIVACY,
            CAP_WITHDRAW,
            CAP_DELEGATE,
        ] {
            assert!(
                !s.permits(denied),
                "default session permits capability {denied:#x}"
            );
        }
        assert!(
            !s.permits(CAP_SWAP | CAP_WITHDRAW),
            "a mixed intent slipped through"
        );
    }

    /// The rule that keeps a leaked session from becoming a permanent one.
    #[test]
    fn delegation_can_never_be_delegated() {
        // Not grantable...
        assert!(!d(CAP_DELEGATE).permits(CAP_DELEGATE));
        // ...and a delegation that names it is void rather than merely
        // narrowed, so an over-broad grant fails closed.
        assert!(!d(CAP_OPERATE | CAP_DELEGATE).permits(CAP_OPERATE));
    }

    #[test]
    fn an_intent_requiring_nothing_is_not_thereby_permitted() {
        assert!(
            !d(SESSION_DEFAULT).permits(0),
            "an unclassified intent was allowed"
        );
    }

    /// Every field is bound, so a delegation cannot be widened in flight.
    #[test]
    fn every_field_changes_the_payload() {
        let base = d(SESSION_DEFAULT);
        let vm = [9u8; 32];
        let p = base.payload(1, &vm);
        let mut caps = base.clone();
        caps.capabilities = CAP_OPERATE | CAP_WITHDRAW;
        let mut longer = base.clone();
        longer.valid_until_epoch = 11;
        let mut other_key = base.clone();
        other_key.session_key = [3u8; 32];
        let mut policy = base.clone();
        policy.allowed_assets = alloc::vec![asset(0), asset(1)];
        policy.allowed_pools = alloc::vec![asset(4)];
        policy.max_per_action = alloc::vec![AssetLimit {
            asset: asset(0),
            amount: crate::fixed::Fixed::whole(5)
        }];
        policy.max_slippage_bps = 50;
        policy.salt = [8u8; 32];
        for changed in [caps, longer, other_key, policy] {
            assert_ne!(p, changed.payload(1, &vm));
        }
        assert_ne!(p, base.payload(2, &vm), "a delegation crossed chains");
        assert_ne!(
            p,
            base.payload(1, &[8u8; 32]),
            "a delegation crossed programs"
        );
    }

    #[test]
    fn malformed_agent_policies_fail_closed() {
        let mut policy = d(SESSION_DEFAULT);
        policy.allowed_assets = alloc::vec![asset(0), asset(1)];
        policy.allowed_pools = alloc::vec![asset(4)];
        policy.max_per_action = alloc::vec![AssetLimit {
            asset: asset(0),
            amount: crate::fixed::Fixed::whole(5)
        }];
        assert!(policy.policy_is_well_formed());
        policy.allowed_assets = alloc::vec![asset(1), asset(0)];
        assert!(
            !policy.policy_is_well_formed(),
            "non-canonical lists were accepted"
        );
        policy.allowed_assets = alloc::vec![asset(0), asset(1)];
        policy.max_slippage_bps = 2_001;
        assert!(
            !policy.policy_is_well_formed(),
            "an unbounded slippage grant was accepted"
        );
    }

    /// A delegation payload must not be readable as an intent payload: one
    /// grants authority, the other spends it.
    #[test]
    fn a_delegation_is_not_an_intent() {
        assert!(d(SESSION_DEFAULT)
            .payload(1, &[9u8; 32])
            .starts_with(DELEGATION_DOMAIN));
        assert_ne!(DELEGATION_DOMAIN, b"zyn.auth.v1");
    }
}
#[cfg(test)]
fn asset(n: u8) -> [u8; 32] {
    [n; 32]
}
