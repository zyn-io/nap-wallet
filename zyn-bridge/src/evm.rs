//! EVM settlement: which chain, where to, and what the signers sign.
//!
//! The EVM half of the bridge differs from Zcash's in one structural way, and
//! everything here follows from it: **the vault is a contract, not a key.**
//!
//! A deposit has to say who it is for. Zcash carries that in a shielded memo;
//! an ERC-20 `transfer` to an address carries nothing at all, so the only thing
//! a watcher could key on is the sender. That would publish a link from every
//! depositor's public EVM identity to their Zyn account — the whole privacy
//! claim, given away at the front door. A contract has calldata, so the
//! destination is an argument. See `DECISIONS.md` §14d.
//!
//! # What is signed
//!
//! Withdrawals are grouped by [`crate::settle::group`], which already produces
//! a canonical ordering — "two nodes building a settlement from the same state
//! produce identical bytes". This module turns one such group into an EIP-712
//! digest. Signers therefore do not *choose* a withdrawal; they attest to one
//! the state already determined (§14e, level 1).
//!
//! # Replay is the default failure here, not an edge case
//!
//! The vault is deployed through CREATE2 at the **same address on every EVM
//! chain**, which is what makes adding a chain a config row instead of an
//! audit. The direct consequence is that a digest which does not bind the
//! chain authorises the identical withdrawal on all of them. So the domain
//! binds both `chainId` and `verifyingContract`, and [`ORIGINS`] is tested for
//! injectivity — two origins sharing a chain id would be exactly this hole.
//!
//! Note the contrast with §6b: there `chainId` is *omitted*, because MetaMask
//! hangs on an id it does not know. The verifier here is a contract, not a
//! wallet, so the field is both safe and required.

use alloc::vec::Vec;
use zyn_vm::eip712::{self, Domain, TypedData, Value, Word};
use zyn_vm::spec::AccountId;
use zyn_vm::Fixed;

use crate::settle::Payout;
use crate::vault::{Binding, ChainOrigin};

/// An EIP-155 chain id.
pub type ChainId = u64;

/// EVM origins live in `0x0100..=0x01FF`, so `is_evm` is a range check and a
/// new EVM chain never collides with the hand-numbered originals.
pub const EVM_ORIGIN_FIRST: ChainOrigin = 0x0100;
pub const EVM_ORIGIN_LAST: ChainOrigin = 0x01FF;

pub const ORIGIN_ETHEREUM_MAINNET: ChainOrigin = 0x0101;
pub const ORIGIN_BASE: ChainOrigin = 0x0102;
pub const ORIGIN_ARBITRUM: ChainOrigin = 0x0103;
pub const ORIGIN_OPTIMISM: ChainOrigin = 0x0104;
pub const ORIGIN_POLYGON: ChainOrigin = 0x0105;
pub const ORIGIN_BSC: ChainOrigin = 0x0106;
/// Robinhood Chain, chain id 4663 — an Arbitrum L2 carrying Robinhood's
/// tokenised stocks and ETFs (each with a Chainlink feed on-chain).
pub const ORIGIN_ROBINHOOD_CHAIN: ChainOrigin = 0x0107;

pub const ORIGIN_SEPOLIA: ChainOrigin = 0x0180;
pub const ORIGIN_BASE_SEPOLIA: ChainOrigin = 0x0181;
pub const ORIGIN_ARBITRUM_SEPOLIA: ChainOrigin = 0x0182;

/// The whole mapping, as data rather than a `match`, so a test can walk it and
/// prove no two origins share a chain id.
pub const ORIGINS: &[(ChainOrigin, ChainId, bool)] = &[
    // origin, EIP-155 chain id, is_testnet
    (ORIGIN_ETHEREUM_MAINNET, 1, false),
    (ORIGIN_BASE, 8453, false),
    (ORIGIN_ARBITRUM, 42161, false),
    (ORIGIN_OPTIMISM, 10, false),
    (ORIGIN_POLYGON, 137, false),
    (ORIGIN_BSC, 56, false),
    (ORIGIN_SEPOLIA, 11_155_111, true),
    (ORIGIN_BASE_SEPOLIA, 84_532, true),
    (ORIGIN_ARBITRUM_SEPOLIA, 421_614, true),
];

pub fn is_evm(origin: ChainOrigin) -> bool {
    (EVM_ORIGIN_FIRST..=EVM_ORIGIN_LAST).contains(&origin)
}

/// The chain id an origin settles on. `None` for a non-EVM or unregistered one.
pub fn chain_id_of(origin: ChainOrigin) -> Option<ChainId> {
    ORIGINS
        .iter()
        .find(|(o, _, _)| *o == origin)
        .map(|(_, id, _)| *id)
}

pub fn origin_of_chain_id(id: ChainId) -> Option<ChainOrigin> {
    ORIGINS
        .iter()
        .find(|(_, c, _)| *c == id)
        .map(|(o, _, _)| *o)
}

pub fn is_testnet(origin: ChainOrigin) -> Option<bool> {
    ORIGINS
        .iter()
        .find(|(o, _, _)| *o == origin)
        .map(|(_, _, t)| *t)
}

/// `keccak(address ‖ salt)` — the destination commitment for an EVM payout.
///
/// [`Binding`] holds an opaque 32 bytes and the VM never computes it, because
/// a withdrawal address written into readable state is a withdrawal address
/// published to everyone (§12). The preimage lives with the user and the
/// operator; anyone shown it can check a settlement afterwards. Fixing the
/// scheme here is what makes "anyone" include people who are not us.
pub fn commitment(address: &[u8; 20], salt: &[u8; 32]) -> Word {
    eip712::keccak(&[&address[..], &salt[..]])
}

/// A user's disclosure of where their exit should land.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reveal {
    pub account: AccountId,
    pub address: [u8; 20],
    pub salt: [u8; 32],
}

/// One payout with its destination resolved and checked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmPayout {
    pub to: [u8; 20],
    /// The application's asset id. The **contract** maps it to an ERC-20
    /// address and to that token's decimals.
    ///
    /// Carrying the id rather than the token address is deliberate: it deletes
    /// the failure where two signers hold different asset tables, and moves the
    /// one copy that matters on-chain where it can be audited.
    pub asset: crate::settle::AssetId,
    /// WAD-scaled, exactly as the VM holds it.
    ///
    /// [`Fixed`] is scaled by 1e18 to match Solidity's convention, so an
    /// 18-decimal token needs no rescaling at all. Anything else is scaled by
    /// the contract, which reverts rather than round — losing dust silently is
    /// how a bridge stops balancing.
    pub amount: Fixed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EvmError {
    /// The settlement is not bound for an EVM chain, or that chain is not
    /// registered in [`ORIGINS`].
    NotEvm,
    /// No reveal was supplied for an account being paid.
    Undisclosed,
    /// The revealed address does not hash to the account's binding.
    WrongDestination,
    /// The account has no withdrawal binding at all.
    Unbound,
    /// Negative, or past what a `uint256` can carry.
    AmountOutOfRange,
}

/// Resolve a settlement's payouts to EVM addresses, checking each against its
/// account's binding.
///
/// The check is the point. An operator assembling a payout list is exactly the
/// position from which a destination would be substituted, and this refuses a
/// list whose addresses do not match what the chain already committed to.
pub fn resolve(
    payouts: &[Payout],
    binding_of: impl Fn(AccountId) -> Option<Binding>,
    reveals: &[Reveal],
) -> Result<Vec<EvmPayout>, EvmError> {
    let mut out = Vec::with_capacity(payouts.len());
    for p in payouts {
        let r = reveals
            .iter()
            .find(|r| r.account == p.account)
            .ok_or(EvmError::Undisclosed)?;
        let b = binding_of(p.account).ok_or(EvmError::Unbound)?;
        if !b.admits(commitment(&r.address, &r.salt)) {
            return Err(EvmError::WrongDestination);
        }
        if !p.amount.is_positive() {
            return Err(EvmError::AmountOutOfRange);
        }
        out.push(EvmPayout {
            to: r.address,
            asset: p.asset,
            amount: p.amount,
        });
    }
    Ok(out)
}

/// A positive `i128` as a `uint256` word.
fn uint_i128(v: i128) -> Option<Value> {
    if v < 0 {
        return None;
    }
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    Some(Value::Uint256(w))
}

/// The EIP-712 domain a vault verifies under.
pub fn domain(vault: [u8; 20], chain_id: ChainId) -> Domain {
    Domain {
        name: "ZynVault".into(),
        version: "1".into(),
        chain_id: Some(chain_id),
        verifying_contract: Some(vault),
        salt: None,
    }
}

/// The digest the signers sign and the contract checks.
///
/// ```text
/// Withdrawal(uint256 nonce,uint256 epoch,Payout[] payouts)
/// Payout(address to,bytes32 asset,uint256 amount)
/// ```
///
/// `nonce` is the vault's own withdrawal counter, held on the EVM side and
/// consumed on use, so a settlement cannot be paid twice on its own chain;
/// the domain stops it being paid on any other. `epoch` is carried so a
/// settlement can be tied back to the state it came from.
pub fn withdrawal_digest(
    vault: [u8; 20],
    chain_id: ChainId,
    nonce: u64,
    epoch: u64,
    payouts: &[EvmPayout],
) -> Result<Word, EvmError> {
    let mut items = Vec::with_capacity(payouts.len());
    for p in payouts {
        items.push(Value::Struct(
            TypedData::new("Payout")
                .field("to", Value::Address(p.to))
                .field("asset", Value::Bytes32(p.asset))
                .field(
                    "amount",
                    uint_i128(p.amount.0).ok_or(EvmError::AmountOutOfRange)?,
                ),
        ));
    }
    let msg = TypedData::new("Withdrawal")
        .field("nonce", Value::uint(nonce))
        .field("epoch", Value::uint(epoch))
        .field(
            "payouts",
            Value::Array {
                elem_type: "Payout".into(),
                items,
            },
        );
    Ok(eip712::digest(&domain(vault, chain_id), &msg))
}

/// Digest a whole settlement, taking its chain from the settlement's origin.
pub fn settlement_digest(
    settlement: &crate::settle::Settlement,
    vault: [u8; 20],
    nonce: u64,
    epoch: u64,
    binding_of: impl Fn(AccountId) -> Option<Binding>,
    reveals: &[Reveal],
) -> Result<Word, EvmError> {
    let chain = chain_id_of(settlement.origin).ok_or(EvmError::NotEvm)?;
    let payouts = resolve(&settlement.payouts, binding_of, reveals)?;
    withdrawal_digest(vault, chain, nonce, epoch, &payouts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::group;
    use alloc::vec;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }
    fn addr(n: u8) -> [u8; 20] {
        [n; 20]
    }
    fn asset(n: u8) -> crate::settle::AssetId {
        [n; 32]
    }
    const SALT: [u8; 32] = [7u8; 32];
    const VAULT: [u8; 20] = [0xABu8; 20];

    fn bound(a: AccountId) -> Option<Binding> {
        Some(Binding::new(commitment(&addr(a[0]), &SALT)))
    }
    fn reveal(n: u8) -> Reveal {
        Reveal {
            account: acct(n),
            address: addr(n),
            salt: SALT,
        }
    }

    /// The hole that the same-address-on-every-chain deployment would open.
    /// Two origins sharing a chain id means a digest built for one settles the
    /// other, and no signature check anywhere would notice.
    #[test]
    fn no_two_origins_share_a_chain_id() {
        for (i, (o1, c1, _)) in ORIGINS.iter().enumerate() {
            for (o2, c2, _) in ORIGINS.iter().skip(i + 1) {
                assert_ne!(
                    c1, c2,
                    "origins {:#x} and {:#x} share chain id {}",
                    o1, o2, c1
                );
                assert_ne!(o1, o2);
            }
        }
    }

    #[test]
    fn every_registered_origin_is_an_evm_origin() {
        for (o, _, _) in ORIGINS {
            assert!(is_evm(*o), "{:#x} is outside the EVM block", o);
            assert_eq!(origin_of_chain_id(chain_id_of(*o).unwrap()), Some(*o));
        }
    }

    /// The originals must not be mistaken for EVM chains.
    #[test]
    fn the_hand_numbered_origins_are_not_evm() {
        use crate::vault::{ORIGIN_BITCOIN, ORIGIN_SOLANA, ORIGIN_ZCASH};
        for o in [ORIGIN_ZCASH, ORIGIN_BITCOIN, ORIGIN_SOLANA] {
            assert!(!is_evm(o));
            assert_eq!(chain_id_of(o), None);
        }
    }

    fn one_payout() -> Vec<EvmPayout> {
        vec![EvmPayout {
            to: addr(1),
            asset: asset(3),
            amount: Fixed::whole(5),
        }]
    }

    /// The CREATE2 consequence, tested directly: identical withdrawal, two
    /// chains, and the signature must not travel.
    #[test]
    fn a_digest_does_not_carry_across_chains() {
        let p = one_payout();
        let base = withdrawal_digest(VAULT, 8453, 1, 10, &p).unwrap();
        let arb = withdrawal_digest(VAULT, 42161, 1, 10, &p).unwrap();
        assert_ne!(base, arb, "a Base withdrawal also authorised Arbitrum");
    }

    #[test]
    fn a_digest_does_not_carry_across_vaults() {
        let p = one_payout();
        let a = withdrawal_digest(VAULT, 8453, 1, 10, &p).unwrap();
        let b = withdrawal_digest([0xCDu8; 20], 8453, 1, 10, &p).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_nonce_and_epoch_are_bound() {
        let p = one_payout();
        let base = withdrawal_digest(VAULT, 8453, 1, 10, &p).unwrap();
        assert_ne!(base, withdrawal_digest(VAULT, 8453, 2, 10, &p).unwrap());
        assert_ne!(base, withdrawal_digest(VAULT, 8453, 1, 11, &p).unwrap());
    }

    #[test]
    fn the_payouts_are_bound() {
        let base = withdrawal_digest(VAULT, 8453, 1, 10, &one_payout()).unwrap();
        let moved = vec![EvmPayout {
            to: addr(2),
            asset: asset(3),
            amount: Fixed::whole(5),
        }];
        let bigger = vec![EvmPayout {
            to: addr(1),
            asset: asset(3),
            amount: Fixed::whole(6),
        }];
        let other = vec![EvmPayout {
            to: addr(1),
            asset: asset(4),
            amount: Fixed::whole(5),
        }];
        for v in [moved, bigger, other] {
            assert_ne!(base, withdrawal_digest(VAULT, 8453, 1, 10, &v).unwrap());
        }
    }

    /// A WAD amount passes `u64` at eighteen-and-a-bit tokens, so encoding one
    /// through a `u64` would silently truncate every ordinary withdrawal.
    #[test]
    fn an_amount_past_u64_survives_encoding() {
        let big = Fixed::whole(100);
        assert!(
            big.0 > u64::MAX as i128,
            "the test is not testing what it says"
        );
        match uint_i128(big.0).unwrap() {
            Value::Uint256(w) => {
                assert_eq!(&w[16..], &big.0.to_be_bytes()[..]);
                assert_eq!(&w[..16], &[0u8; 16]);
            }
            _ => panic!("wrong type"),
        }
        let a = withdrawal_digest(VAULT, 8453, 1, 10, &one_payout()).unwrap();
        let b = withdrawal_digest(
            VAULT,
            8453,
            1,
            10,
            &[EvmPayout {
                to: addr(1),
                asset: asset(3),
                amount: big,
            }],
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_revealed_address_must_match_the_binding() {
        let payouts = vec![Payout {
            account: acct(1),
            asset: asset(3),
            amount: Fixed::whole(5),
            since: 1,
        }];
        assert!(resolve(&payouts, bound, &[reveal(1)]).is_ok());

        // The operator substitutes its own address, keeping the salt.
        let substituted = Reveal {
            account: acct(1),
            address: addr(9),
            salt: SALT,
        };
        assert_eq!(
            resolve(&payouts, bound, &[substituted]),
            Err(EvmError::WrongDestination),
            "an operator redirected a payout and it was accepted"
        );
    }

    #[test]
    fn an_undisclosed_or_unbound_account_is_refused() {
        let payouts = vec![Payout {
            account: acct(1),
            asset: asset(3),
            amount: Fixed::whole(5),
            since: 1,
        }];
        assert_eq!(resolve(&payouts, bound, &[]), Err(EvmError::Undisclosed));
        assert_eq!(
            resolve(&payouts, |_| None, &[reveal(1)]),
            Err(EvmError::Unbound)
        );
    }

    /// `group` sorts oldest-first; the digest must inherit that rather than
    /// depend on the order the caller happened to hold the exits in.
    #[test]
    fn the_digest_follows_the_canonical_order() {
        let a = (acct(1), asset(3), ORIGIN_BASE, Fixed::whole(5), 2u64);
        let b = (acct(2), asset(3), ORIGIN_BASE, Fixed::whole(7), 1u64);
        let one = group(vec![a, b]);
        let two = group(vec![b, a]);
        assert_eq!(one, two);

        let d = |s: &crate::settle::Settlement| {
            settlement_digest(s, VAULT, 1, 10, bound, &[reveal(1), reveal(2)]).unwrap()
        };
        assert_eq!(d(&one[0]), d(&two[0]));
        // Oldest first: account 2 waited longer.
        assert_eq!(one[0].payouts[0].account, acct(2));
    }

    /// The cross-language contract. The Solidity verifier hard-codes these
    /// same type strings, and nothing at runtime would notice them drifting
    /// apart — a mismatched typehash makes every signature simply fail to
    /// verify, on a chain holding funds, with no test in between. So they are
    /// pinned here, on the side that generates them.
    #[test]
    fn the_type_strings_are_what_the_contract_expects() {
        let msg = TypedData::new("Withdrawal")
            .field("nonce", Value::uint(0))
            .field("epoch", Value::uint(0))
            .field(
                "payouts",
                Value::Array {
                    elem_type: "Payout".into(),
                    items: vec![Value::Struct(
                        TypedData::new("Payout")
                            .field("to", Value::Address([0u8; 20]))
                            .field("asset", Value::Bytes32([0u8; 32]))
                            .field("amount", Value::Uint256([0u8; 32])),
                    )],
                },
            );
        assert_eq!(
            msg.encode_type(),
            "Withdrawal(uint256 nonce,uint256 epoch,Payout[] payouts)\
Payout(address to,bytes32 asset,uint256 amount)"
        );
        assert_eq!(
            domain([0u8; 20], 1).as_struct().encode_type(),
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

        let hex = |w: Word| {
            let mut s = alloc::string::String::from("0x");
            for b in w {
                s.push_str(&alloc::format!("{:02x}", b));
            }
            s
        };
        // Printed so the Solidity constants can be copied rather than derived
        // twice. Run with --nocapture.
        std::println!(
            "WITHDRAWAL_TYPEHASH = {}",
            hex(eip712::keccak(&[msg.encode_type().as_bytes()]))
        );
        std::println!(
            "PAYOUT_TYPEHASH      = {}",
            hex(eip712::keccak(&[
                b"Payout(address to,bytes32 asset,uint256 amount)"
            ]))
        );
        // A concrete vector, reproduced by the Solidity test. This is the only
        // check that the two implementations actually agree.
        std::println!(
            "VECTOR_DIGEST        = {}",
            hex(withdrawal_digest(VAULT, 8453, 1, 10, &one_payout()).unwrap())
        );
        std::println!(
            "VECTOR_DOMAIN        = {}",
            hex(domain(VAULT, 8453).separator())
        );
    }

    #[test]
    fn a_settlement_for_a_non_evm_chain_is_refused() {
        let s = group(vec![(
            acct(1),
            asset(3),
            crate::vault::ORIGIN_ZCASH,
            Fixed::whole(5),
            1u64,
        )]);
        assert_eq!(
            settlement_digest(&s[0], VAULT, 1, 10, bound, &[reveal(1)]),
            Err(EvmError::NotEvm)
        );
    }
}
