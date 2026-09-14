//! Solana settlement: the transaction a settlement becomes, byte for byte.
//!
//! The Solana counterpart of [`crate::evm`], and simpler in one important way:
//! **there is no contract.** The vault is an account whose owner is the
//! threshold key, so a withdrawal is an ordinary transaction that Solana
//! verifies natively. What the signers sign is the transaction's *message*, and
//! this module is what makes that message a deterministic function of state —
//! two nodes holding the same settlement must produce identical bytes, or the
//! shares they contribute will not combine.
//!
//! # Why the bytes are assembled here and not by a Solana SDK
//!
//! The SDK's dependency tree is very large and pins curve crates that conflict
//! with the Zcash stack. But the better reason is the property itself: the
//! legacy message format is a few hundred bytes of layout that this file can
//! own and a test can pin, and "the signers agree on what they sign" is not a
//! property to delegate.
//!
//! # A durable nonce, not a recent blockhash
//!
//! An ordinary transaction expires ~90 seconds after the blockhash it names,
//! which is hostile to a signing ceremony across machines. A **durable nonce**
//! account replaces it: the transaction names the nonce's current value, stays
//! valid until used, and using it advances the nonce — so the same settlement
//! cannot be paid twice. That is the "consumed before payout" property the EVM
//! contract had to implement, given by the chain.
//!
//! The vault is its own nonce authority, so the transaction has exactly one
//! signer.
//!
//! # Size
//!
//! A transaction is at most [`MAX_TRANSACTION_BYTES`]. Each payout costs a key
//! and an instruction, so a settlement of any size becomes one or more
//! transactions, filled in order — and [`crate::settle`] orders exits
//! oldest-first precisely so that a cut falls on whoever has waited least.

use alloc::vec::Vec;
use zyn_vm::eip712::keccak;
use zyn_vm::spec::AccountId;
use zyn_vm::Fixed;

use crate::settle::{Payout, Settlement};
use crate::vault::{Binding, ORIGIN_SOLANA};

/// A Solana account address.
pub type Pubkey = [u8; 32];

pub const SYSTEM_PROGRAM: Pubkey = [0u8; 32];
/// `SysvarRecentB1ockHashes11111111111111111111`, which `AdvanceNonceAccount`
/// must be handed.
pub const RECENT_BLOCKHASHES_SYSVAR: Pubkey = [
    6, 167, 213, 23, 25, 44, 86, 142, 224, 138, 132, 95, 115, 210, 151, 136, 207, 3, 92, 49, 69,
    178, 26, 179, 68, 216, 6, 46, 169, 64, 0, 0,
];
/// The network's packet limit for a serialised transaction.
pub const MAX_TRANSACTION_BYTES: usize = 1232;
/// `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` — the SPL Token program.
pub const TOKEN_PROGRAM: Pubkey = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
/// `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` — the Associated Token Account program.
pub const ATA_PROGRAM: Pubkey = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131, 11, 90, 19, 153, 218,
    255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];

/// The associated token account of `owner` for `mint`.
///
/// A program-derived address: SHA-256 over `owner ‖ token program ‖ mint ‖
/// bump ‖ ATA program ‖ "ProgramDerivedAddress"`, with the bump counted down
/// from 255 until the hash is **not** a valid ed25519 point — so no key can
/// ever sign for it. This is where a wallet sends an SPL token to `owner`,
/// and where the vault's tokens live.
pub fn associated_token_address(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    use sha2::Digest;
    for bump in (0u8..=255).rev() {
        let mut h = sha2::Sha256::new();
        h.update(owner);
        h.update(TOKEN_PROGRAM);
        h.update(mint);
        h.update([bump]);
        h.update(ATA_PROGRAM);
        h.update(b"ProgramDerivedAddress");
        let out: [u8; 32] = h.finalize().into();
        let on_curve = curve25519_dalek::edwards::CompressedEdwardsY(out)
            .decompress()
            .is_some();
        if !on_curve {
            return out;
        }
    }
    unreachable!("some bump is always off the curve")
}
/// `Fixed` is scaled by 1e18 and a lamport is 1e-9 SOL.
pub const WAD_PER_LAMPORT: i128 = 1_000_000_000;

const SYSTEM_TRANSFER: u32 = 2;
const SYSTEM_ADVANCE_NONCE: u32 = 4;
const SIGNATURE_BYTES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SolanaError {
    NotSolana,
    Undisclosed,
    Unbound,
    WrongDestination,
    /// Not a whole number of lamports. Refused rather than rounded: dust
    /// dropped silently is how a bridge's books stop balancing.
    Dust,
    AmountOutOfRange,
    /// A payout to the vault or its nonce account. Meaningless at best; at
    /// worst it burns the nonce account's rent-exemption.
    PayoutToVault,
    /// Even a single payout does not fit. Cannot happen with a sane vault; kept
    /// so `chunk` is total.
    TooLarge,
    Empty,
}

/// `keccak(address ‖ salt)` — the destination commitment, 32-byte form.
pub fn commitment(address: &Pubkey, salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[&address[..], &salt[..]])
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reveal {
    pub account: AccountId,
    pub address: Pubkey,
    pub salt: [u8; 32],
}

/// One payout, resolved and in the chain's own unit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SolPayout {
    pub to: Pubkey,
    /// Native SOL, in lamports. Zero for a token payout.
    pub lamports: u64,
    /// An SPL token instead: the mint and the amount in the mint's base
    /// units (1 for a mirrored NFT). Paid to `to`'s associated token account,
    /// created in the same transaction if it does not exist.
    pub token: Option<(Pubkey, u64)>,
}

impl SolPayout {
    pub fn native(to: Pubkey, lamports: u64) -> SolPayout {
        SolPayout {
            to,
            lamports,
            token: None,
        }
    }
    pub fn token(to: Pubkey, mint: Pubkey, amount: u64) -> SolPayout {
        SolPayout {
            to,
            lamports: 0,
            token: Some((mint, amount)),
        }
    }
}

/// A WAD amount as lamports, exactly or not at all.
pub fn lamports(amount: Fixed) -> Result<u64, SolanaError> {
    if !amount.is_positive() {
        return Err(SolanaError::AmountOutOfRange);
    }
    if amount.0 % WAD_PER_LAMPORT != 0 {
        return Err(SolanaError::Dust);
    }
    u64::try_from(amount.0 / WAD_PER_LAMPORT).map_err(|_| SolanaError::AmountOutOfRange)
}

/// Resolve payouts to addresses, checking each against its binding — the same
/// refusal as [`crate::evm::resolve`], for the same reason: assembling the
/// list is exactly where a destination would be substituted.
pub fn resolve(
    payouts: &[Payout],
    binding_of: impl Fn(AccountId) -> Option<Binding>,
    reveals: &[Reveal],
) -> Result<Vec<SolPayout>, SolanaError> {
    let mut out = Vec::with_capacity(payouts.len());
    for p in payouts {
        let r = reveals
            .iter()
            .find(|r| r.account == p.account)
            .ok_or(SolanaError::Undisclosed)?;
        let b = binding_of(p.account).ok_or(SolanaError::Unbound)?;
        if !b.admits(commitment(&r.address, &r.salt)) {
            return Err(SolanaError::WrongDestination);
        }
        out.push(SolPayout::native(r.address, lamports(p.amount)?));
    }
    Ok(out)
}

/// The accounts a settlement transaction is built around.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VaultAccounts {
    pub vault: Pubkey,
    pub nonce_account: Pubkey,
}

/// Solana's "shortvec": little-endian, seven bits per byte, high bit continues.
fn put_compact_u16(out: &mut Vec<u8>, mut v: u16) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// The message the signers sign: one nonce advance, then one transfer per
/// payout, in the order given.
///
/// Account keys are laid out as the runtime requires — the signer first, then
/// writable non-signers, then read-only — and **deduplicated**: two payouts to
/// one address share a key and get two instructions, because a message with a
/// repeated key is rejected outright.
pub fn message(
    accounts: VaultAccounts,
    nonce_value: [u8; 32],
    payouts: &[SolPayout],
) -> Result<Vec<u8>, SolanaError> {
    if payouts.is_empty() {
        return Err(SolanaError::Empty);
    }
    // Writable, non-signing: nonce account, then each distinct destination —
    // for a token payout, the recipient's and the vault's token accounts.
    let mut writable: Vec<Pubkey> = Vec::with_capacity(1 + payouts.len());
    writable.push(accounts.nonce_account);
    let mut readonly: Vec<Pubkey> = Vec::new(); // mints, then the programs
    let has_tokens = payouts.iter().any(|p| p.token.is_some());
    for p in payouts {
        if p.to == accounts.vault || p.to == accounts.nonce_account {
            return Err(SolanaError::PayoutToVault);
        }
        match p.token {
            None => {
                if p.lamports == 0 {
                    return Err(SolanaError::AmountOutOfRange);
                }
                if !writable.contains(&p.to) {
                    writable.push(p.to);
                }
            }
            Some((mint, amount)) => {
                if amount == 0 {
                    return Err(SolanaError::AmountOutOfRange);
                }
                for k in [
                    p.to,
                    associated_token_address(&p.to, &mint),
                    associated_token_address(&accounts.vault, &mint),
                ] {
                    if !writable.contains(&k) {
                        writable.push(k);
                    }
                }
                if !readonly.contains(&mint) {
                    readonly.push(mint);
                }
            }
        }
    }
    readonly.push(RECENT_BLOCKHASHES_SYSVAR);
    readonly.push(SYSTEM_PROGRAM);
    if has_tokens {
        readonly.push(TOKEN_PROGRAM);
        readonly.push(ATA_PROGRAM);
    }
    // Key table: vault (signer) | writable | read-only.
    let mut keys: Vec<Pubkey> = Vec::with_capacity(1 + writable.len() + readonly.len());
    keys.push(accounts.vault);
    keys.extend_from_slice(&writable);
    keys.extend_from_slice(&readonly);
    let index = |k: &Pubkey| keys.iter().position(|x| x == k).map(|i| i as u8);
    let (vault_i, nonce_i) = (0u8, 1u8);
    let sysvar_i = index(&RECENT_BLOCKHASHES_SYSVAR).ok_or(SolanaError::TooLarge)?;
    let system_i = index(&SYSTEM_PROGRAM).ok_or(SolanaError::TooLarge)?;

    let mut out = Vec::with_capacity(MAX_TRANSACTION_BYTES);
    // Header: signatures required, read-only signed, read-only unsigned.
    out.extend_from_slice(&[1, 0, readonly.len() as u8]);
    put_compact_u16(&mut out, keys.len() as u16);
    for k in &keys {
        out.extend_from_slice(k);
    }
    out.extend_from_slice(&nonce_value);

    let n_ix = 1 + payouts
        .iter()
        .map(|p| if p.token.is_some() { 2 } else { 1 })
        .sum::<usize>();
    put_compact_u16(&mut out, n_ix as u16);
    // AdvanceNonceAccount must come first, or the nonce is not honoured.
    out.push(system_i);
    put_compact_u16(&mut out, 3);
    out.extend_from_slice(&[nonce_i, sysvar_i, vault_i]);
    put_compact_u16(&mut out, 4);
    out.extend_from_slice(&SYSTEM_ADVANCE_NONCE.to_le_bytes());
    for p in payouts {
        match p.token {
            None => {
                out.push(system_i);
                put_compact_u16(&mut out, 2);
                out.extend_from_slice(&[vault_i, index(&p.to).ok_or(SolanaError::TooLarge)?]);
                put_compact_u16(&mut out, 12);
                out.extend_from_slice(&SYSTEM_TRANSFER.to_le_bytes());
                out.extend_from_slice(&p.lamports.to_le_bytes());
            }
            Some((mint, amount)) => {
                let (to_i, mint_i) = (
                    index(&p.to).ok_or(SolanaError::TooLarge)?,
                    index(&mint).ok_or(SolanaError::TooLarge)?,
                );
                let dest_ata_i =
                    index(&associated_token_address(&p.to, &mint)).ok_or(SolanaError::TooLarge)?;
                let src_ata_i = index(&associated_token_address(&accounts.vault, &mint))
                    .ok_or(SolanaError::TooLarge)?;
                let (token_i, ata_i) = (
                    index(&TOKEN_PROGRAM).ok_or(SolanaError::TooLarge)?,
                    index(&ATA_PROGRAM).ok_or(SolanaError::TooLarge)?,
                );
                // CreateIdempotent: the recipient's token account, made if
                // missing, paid by the vault. Accounts: payer, ata, owner,
                // mint, system, token program.
                out.push(ata_i);
                put_compact_u16(&mut out, 6);
                out.extend_from_slice(&[vault_i, dest_ata_i, to_i, mint_i, system_i, token_i]);
                put_compact_u16(&mut out, 1);
                out.push(1);
                // Transfer (3): source ata, destination ata, authority.
                out.push(token_i);
                put_compact_u16(&mut out, 3);
                out.extend_from_slice(&[src_ata_i, dest_ata_i, vault_i]);
                put_compact_u16(&mut out, 9);
                out.push(3);
                out.extend_from_slice(&amount.to_le_bytes());
            }
        }
    }
    if out.len() + 1 + SIGNATURE_BYTES > MAX_TRANSACTION_BYTES {
        return Err(SolanaError::TooLarge);
    }
    Ok(out)
}

/// The wire transaction: the signature count, the signature, the message.
pub fn transaction(message: &[u8], signature: &[u8; SIGNATURE_BYTES]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + SIGNATURE_BYTES + message.len());
    put_compact_u16(&mut out, 1);
    out.extend_from_slice(signature);
    out.extend_from_slice(message);
    out
}

/// Split payouts into transaction-sized groups, **in order**.
///
/// Greedy and deterministic. Every payout appears exactly once, and a group
/// is closed only when the next payout would not fit — so the cut falls on
/// whoever is last, which `settle::group` made whoever has waited least.
pub fn chunk(
    accounts: VaultAccounts,
    payouts: &[SolPayout],
) -> Result<Vec<Vec<SolPayout>>, SolanaError> {
    let mut groups: Vec<Vec<SolPayout>> = Vec::new();
    let mut current: Vec<SolPayout> = Vec::new();
    for p in payouts {
        current.push(*p);
        match message(accounts, [0u8; 32], &current) {
            Ok(_) => {}
            Err(SolanaError::TooLarge) => {
                current.pop();
                if current.is_empty() {
                    return Err(SolanaError::TooLarge);
                }
                groups.push(core::mem::take(&mut current));
                current.push(*p);
                message(accounts, [0u8; 32], &current)?;
            }
            Err(e) => return Err(e),
        }
    }
    if !current.is_empty() {
        groups.push(current);
    }
    Ok(groups)
}

/// A whole settlement, resolved and split — the operator's entry point.
pub fn settlement_payouts(
    settlement: &Settlement,
    accounts: VaultAccounts,
    binding_of: impl Fn(AccountId) -> Option<Binding>,
    reveals: &[Reveal],
) -> Result<Vec<Vec<SolPayout>>, SolanaError> {
    if settlement.origin != ORIGIN_SOLANA {
        return Err(SolanaError::NotSolana);
    }
    chunk(
        accounts,
        &resolve(&settlement.payouts, binding_of, reveals)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settle::group;
    use alloc::vec;

    fn pk(n: u8) -> Pubkey {
        [n; 32]
    }
    const ACCTS: VaultAccounts = VaultAccounts {
        vault: [0xAA; 32],
        nonce_account: [0xBB; 32],
    };
    const NONCE: [u8; 32] = [0xCC; 32];

    /// Known shortvec encodings from the Solana test suite.
    #[test]
    fn compact_u16_matches_the_runtime() {
        for (v, bytes) in [
            (0u16, vec![0u8]),
            (127, vec![0x7f]),
            (128, vec![0x80, 0x01]),
            (16383, vec![0xff, 0x7f]),
            (16384, vec![0x80, 0x80, 0x01]),
        ] {
            let mut out = Vec::new();
            put_compact_u16(&mut out, v);
            assert_eq!(out, bytes, "{}", v);
        }
    }

    /// The layout, decoded field by field against the legacy format. This is
    /// the pin: any change to it changes what every signer signs.
    #[test]
    fn the_message_has_the_legacy_layout() {
        let m = message(ACCTS, NONCE, &[SolPayout::native(pk(1), 5_000)]).unwrap();
        let mut i = 0;
        let mut take = |n: usize| {
            let s = &m[i..i + n];
            i += n;
            s
        };
        assert_eq!(
            take(3),
            &[1, 0, 2],
            "header: one signer, two read-only unsigned"
        );
        assert_eq!(take(1), &[5], "vault, nonce, destination, sysvar, system");
        assert_eq!(take(32), &ACCTS.vault);
        assert_eq!(take(32), &ACCTS.nonce_account);
        assert_eq!(take(32), &pk(1));
        assert_eq!(take(32), &RECENT_BLOCKHASHES_SYSVAR);
        assert_eq!(take(32), &SYSTEM_PROGRAM);
        assert_eq!(take(32), &NONCE, "the nonce stands where a blockhash would");
        assert_eq!(take(1), &[2], "advance, then one transfer");
        // AdvanceNonceAccount { nonce, sysvar, authority=vault }
        assert_eq!(take(1), &[4], "system program index");
        assert_eq!(take(1), &[3]);
        assert_eq!(take(3), &[1, 3, 0]);
        assert_eq!(take(1), &[4]);
        assert_eq!(take(4), &4u32.to_le_bytes());
        // Transfer { from=vault, to }
        assert_eq!(take(1), &[4]);
        assert_eq!(take(1), &[2]);
        assert_eq!(take(2), &[0, 2]);
        assert_eq!(take(1), &[12]);
        assert_eq!(take(4), &2u32.to_le_bytes());
        assert_eq!(take(8), &5_000u64.to_le_bytes());
        assert_eq!(i, m.len(), "trailing bytes");
    }

    #[test]
    fn a_repeated_destination_shares_one_key() {
        let p = [SolPayout::native(pk(1), 1), SolPayout::native(pk(1), 2)];
        let m = message(ACCTS, NONCE, &p).unwrap();
        assert_eq!(m[3], 5, "the key table must not repeat an address");
        assert_eq!(m[3 + 1 + 5 * 32 + 32], 3, "but both transfers are present");
    }

    #[test]
    fn a_payout_to_the_vault_or_nonce_is_refused() {
        for to in [ACCTS.vault, ACCTS.nonce_account] {
            assert_eq!(
                message(ACCTS, NONCE, &[SolPayout::native(to, 1)]),
                Err(SolanaError::PayoutToVault)
            );
        }
        assert_eq!(message(ACCTS, NONCE, &[]), Err(SolanaError::Empty));
    }

    #[test]
    fn lamports_are_exact_or_refused() {
        assert_eq!(lamports(Fixed::whole(1)), Ok(1_000_000_000));
        assert_eq!(lamports(Fixed::raw(WAD_PER_LAMPORT)), Ok(1));
        assert_eq!(
            lamports(Fixed::raw(WAD_PER_LAMPORT + 1)),
            Err(SolanaError::Dust)
        );
        assert_eq!(lamports(Fixed::ZERO), Err(SolanaError::AmountOutOfRange));
    }

    /// The signed transaction must fit the packet, and the split must keep
    /// every payout exactly once and in order.
    #[test]
    fn a_large_settlement_splits_in_order_within_the_limit() {
        let payouts: Vec<SolPayout> = (1..=60u8)
            .map(|n| SolPayout::native(pk(n), n as u64))
            .collect();
        let groups = chunk(ACCTS, &payouts).unwrap();
        assert!(groups.len() >= 2, "sixty payouts cannot be one transaction");
        let flat: Vec<SolPayout> = groups.iter().flatten().copied().collect();
        assert_eq!(flat, payouts, "order or membership changed");
        for g in &groups {
            let m = message(ACCTS, NONCE, g).unwrap();
            assert!(transaction(&m, &[0u8; 64]).len() <= MAX_TRANSACTION_BYTES);
        }
        // Greedy: the first group is as full as it can be.
        let mut fuller = groups[0].clone();
        fuller.push(groups[1][0]);
        assert_eq!(message(ACCTS, NONCE, &fuller), Err(SolanaError::TooLarge));
    }

    #[test]
    fn a_substituted_destination_is_refused() {
        let salt = [7u8; 32];
        let bound = |a: AccountId| Some(Binding::new(commitment(&pk(a[0]), &salt)));
        let payouts = vec![Payout {
            account: [1u8; 32],
            asset: asset(2),
            amount: Fixed::whole(1),
            since: 1,
        }];
        assert!(resolve(
            &payouts,
            bound,
            &[Reveal {
                account: [1u8; 32],
                address: pk(1),
                salt
            }]
        )
        .is_ok());
        assert_eq!(
            resolve(
                &payouts,
                bound,
                &[Reveal {
                    account: [1u8; 32],
                    address: pk(9),
                    salt
                }]
            ),
            Err(SolanaError::WrongDestination)
        );
        assert_eq!(resolve(&payouts, bound, &[]), Err(SolanaError::Undisclosed));
    }

    #[test]
    fn a_settlement_for_another_chain_is_refused() {
        let s = group(vec![(
            [1u8; 32],
            asset(2),
            crate::vault::ORIGIN_ZCASH,
            Fixed::whole(1),
            1u64,
        )]);
        assert_eq!(
            settlement_payouts(&s[0], ACCTS, |_| None, &[]),
            Err(SolanaError::NotSolana)
        );
    }

    /// A token payout carries two instructions — create the recipient's
    /// token account if missing, then transfer — and the programs and mint as
    /// read-only keys. Decoded against the layout, like the native case.
    #[test]
    fn a_token_payout_creates_the_account_and_transfers() {
        let mint = pk(0x33);
        let m = message(ACCTS, NONCE, &[SolPayout::token(pk(1), mint, 1)]).unwrap();
        let dest_ata = associated_token_address(&pk(1), &mint);
        let src_ata = associated_token_address(&ACCTS.vault, &mint);
        let mut i = 0;
        let mut take = |n: usize| {
            let s = &m[i..i + n];
            i += n;
            s
        };
        assert_eq!(
            take(3),
            &[1, 0, 5],
            "five read-only: mint, sysvar, system, token, ata programs"
        );
        assert_eq!(take(1), &[10]);
        let mut keys = Vec::new();
        for _ in 0..10 {
            keys.push(<[u8; 32]>::try_from(take(32)).unwrap());
        }
        assert_eq!(keys[0], ACCTS.vault);
        assert!(keys.contains(&dest_ata) && keys.contains(&src_ata) && keys.contains(&mint));
        assert_eq!(
            &keys[5..],
            &[
                mint,
                RECENT_BLOCKHASHES_SYSVAR,
                SYSTEM_PROGRAM,
                TOKEN_PROGRAM,
                ATA_PROGRAM
            ]
        );
        take(32); // nonce
        assert_eq!(take(1), &[3], "advance, create, transfer");
        // skip the advance instruction
        take(1);
        take(1);
        take(3);
        take(1);
        take(4);
        assert_eq!(take(1), &[9], "ata program index");
        assert_eq!(take(1), &[6]);
        let accs = take(6).to_vec();
        assert_eq!(
            keys[accs[0] as usize], ACCTS.vault,
            "the vault pays the rent"
        );
        assert_eq!(keys[accs[1] as usize], dest_ata);
        assert_eq!(keys[accs[2] as usize], pk(1));
        assert_eq!(keys[accs[3] as usize], mint);
        assert_eq!(take(1), &[1]);
        assert_eq!(take(1), &[1], "CreateIdempotent");
        assert_eq!(take(1), &[8], "token program index");
        assert_eq!(take(1), &[3]);
        let accs = take(3).to_vec();
        assert_eq!(keys[accs[0] as usize], src_ata);
        assert_eq!(keys[accs[1] as usize], dest_ata);
        assert_eq!(keys[accs[2] as usize], ACCTS.vault, "the vault authorises");
        assert_eq!(take(1), &[9]);
        assert_eq!(take(1), &[3]);
        assert_eq!(take(8), &1u64.to_le_bytes());
        assert_eq!(i, m.len());
    }

    /// The derivation is checked against `spl-token address` in the live
    /// test; here, only that it is deterministic and off the curve.
    #[test]
    fn an_associated_token_address_is_a_pda() {
        let a = associated_token_address(&pk(1), &pk(2));
        assert_eq!(a, associated_token_address(&pk(1), &pk(2)));
        assert_ne!(a, associated_token_address(&pk(2), &pk(1)));
        assert!(curve25519_dalek::edwards::CompressedEdwardsY(a)
            .decompress()
            .is_none());
    }

    /// Against `spl-token address --owner … --token …` on a validator: the
    /// derivation must produce the account a wallet would actually pay.
    #[test]
    fn the_associated_token_address_matches_the_reference_tooling() {
        let owner: Pubkey = [
            93, 232, 148, 139, 21, 198, 146, 50, 150, 53, 205, 125, 80, 156, 234, 224, 193, 3, 133,
            12, 210, 56, 225, 109, 41, 184, 179, 152, 52, 41, 110, 193,
        ];
        let mint: Pubkey = [
            47, 23, 234, 83, 3, 16, 22, 51, 46, 180, 115, 206, 240, 240, 126, 211, 184, 199, 103,
            65, 99, 66, 73, 66, 170, 124, 252, 247, 205, 68, 45, 212,
        ];
        let ata: Pubkey = [
            113, 121, 145, 41, 173, 126, 221, 138, 106, 78, 223, 65, 119, 137, 93, 121, 111, 1, 19,
            176, 126, 176, 192, 127, 6, 112, 193, 166, 57, 100, 130, 146,
        ];
        assert_eq!(associated_token_address(&owner, &mint), ata);
    }
}
#[cfg(test)]
fn asset(n: u8) -> crate::settle::AssetId {
    [n; 32]
}
