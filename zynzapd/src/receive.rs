//! Fresh receiving accounts, and finding them again afterwards.
//!
//! Sealing the journal (§93) hides ownership from anyone holding a mirror. It
//! does nothing about the operator, or about the key leaking later: a reader
//! who can decrypt sees `MintCollectionItem { recipient }` and builds the owner
//! map exactly as before. Minting to a **fresh account per item** is what
//! survives that — the journal then names an account that was never used before
//! and is never used again, and linking it to a person needs something the
//! chain does not carry.
//!
//! # Derived, never random
//!
//! The obvious implementation — generate a key per item — is unrecoverable, and
//! §70.6 makes recoverability a release gate rather than a nicety. An item held
//! by a key that existed only in a browser that has since been cleared is an
//! item nobody owns. So receiving accounts are derived from the same BIP-39
//! seed as the wallet, and a phrase restores every one of them.
//!
//! # Its own branch, not another account index
//!
//! `KeyMaterial::zyn_signing_key` refuses an account index that differs from
//! the wallet's, on purpose: there, the index means *which wallet*, and two
//! personas must not silently share an identity. Receiving accounts are a
//! different axis — many per wallet — so they take their own salt. The two can
//! never collide, and an item account can never be mistaken for a wallet
//! identity or the reverse.
//!
//! ```text
//!   wallet identity   HKDF(seed, "nap.zyn.ed25519.v1", "account" || account)
//!   receiving account HKDF(seed, "nap.zyn.receive.v1", "receive" || account || index)
//! ```
//!
//! # The gap limit is a promise the wallet has to keep
//!
//! Discovery cannot enumerate an infinite space, so it stops after
//! [`GAP`] consecutive empty indices — the same shape as BIP-44's gap limit and
//! the same obligation: **indices are handed out in order and never skipped.**
//! A wallet that jumps to index 50 while 0..29 sit empty has created an item
//! its own restore will not find. That is a property of the issuing side, so
//! the counter lives with the wallet and this module only ever asks "is this
//! one occupied".

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use swapvm::types::AccountId;
use zyn_vm::auth::{account_of, Scheme};

/// Domain for receiving accounts. Versioned in the salt, like the wallet's own
/// derivation, so a future scheme is a different salt rather than a flag.
const RECEIVE_SALT: &[u8] = b"nap.zyn.receive.v1";
const RECEIVE_INFO: &[u8] = b"receive";

/// How many consecutive empty indices end a scan.
///
/// Twenty, matching BIP-44, for the same reason: large enough that ordinary
/// use never reaches it, small enough that a restore is twenty signed reads
/// rather than a sweep. Raising it later is safe; lowering it is not, because
/// it can orphan an item a previous version could still find.
pub const GAP: u32 = 20;

/// The signing key for one receiving account.
///
/// `wallet_account` scopes the branch to a persona, so two wallets from one
/// phrase do not hand each other's items back.
pub fn receiving_key(seed: &[u8], wallet_account: u32, index: u32) -> Result<SigningKey, String> {
    if index >= 1 << 31 {
        return Err("receiving index must be below 2^31".into());
    }
    let hk = Hkdf::<Sha256>::new(Some(RECEIVE_SALT), seed);
    let mut info = RECEIVE_INFO.to_vec();
    info.extend_from_slice(&wallet_account.to_be_bytes());
    info.extend_from_slice(&index.to_be_bytes());
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| "cannot derive a receiving key".to_string())?;
    Ok(SigningKey::from_bytes(&out))
}

/// The account a holder receives **a whole collection** at.
///
/// This is the granularity to prefer, and the reason is UX rather than
/// cryptography. One account per *item* costs a signed read per item on the
/// most-viewed screen in the wallet, and twenty more before a restore can show
/// anything — an O(N) tax on the hot path, paid to hide which of your three
/// moles is which from a reader who already knows you bought three moles.
///
/// Deriving from the collection instead of a counter also deletes the gap
/// limit and everything that hangs off it: there is no sequence to issue in
/// order, no index to skip, and nothing to orphan. Discovery is one derivation
/// per collection the holder cares about, and collections are public.
pub fn collection_account(
    seed: &[u8],
    wallet_account: u32,
    collection: &[u8; 32],
) -> Result<AccountId, String> {
    let k = collection_key(seed, wallet_account, collection)?;
    Ok(account_of(Scheme::Ed25519, k.verifying_key().as_bytes()))
}

/// The signing key for a collection's receiving account.
pub fn collection_key(
    seed: &[u8],
    wallet_account: u32,
    collection: &[u8; 32],
) -> Result<SigningKey, String> {
    let hk = Hkdf::<Sha256>::new(Some(RECEIVE_SALT), seed);
    // A distinct info prefix, so a collection account and an indexed one can
    // never collide even if a collection id were ever mistaken for an index.
    let mut info = b"collection".to_vec();
    info.extend_from_slice(&wallet_account.to_be_bytes());
    info.extend_from_slice(collection);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .map_err(|_| "cannot derive a collection key".to_string())?;
    Ok(SigningKey::from_bytes(&out))
}

/// The account id an item should be minted to, at a sequential index.
///
/// Kept for the case that genuinely wants per-item unlinkability and will pay
/// for it. [`collection_account`] is the default.
pub fn receiving_account(seed: &[u8], wallet_account: u32, index: u32) -> Result<AccountId, String> {
    let k = receiving_key(seed, wallet_account, index)?;
    Ok(account_of(Scheme::Ed25519, k.verifying_key().as_bytes()))
}

/// What a scan found: the indices that hold something, and how far it looked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// Occupied indices with their accounts, ascending.
    pub occupied: Vec<(u32, AccountId)>,
    /// One past the highest index examined. A wallet resumes issuing here, so
    /// it never reuses an index and never leaves a hole wider than the gap.
    pub scanned_to: u32,
}

impl Found {
    /// The index to hand out next. Always above everything seen, so an item in
    /// flight — paid for but not yet minted — cannot be overwritten by the
    /// next one.
    pub fn next_index(&self) -> u32 {
        self.occupied
            .last()
            .map(|(i, _)| i + 1)
            .unwrap_or(0)
            .max(0)
    }
}

/// Walk a receiving branch until `gap` consecutive indices come back empty.
///
/// `account_at` supplies the account for an index and `occupied` says whether
/// it holds anything. They are separate because the holder of the seed is not
/// always the caller of this function: the wallet owns the derivation, and a
/// probe that needs to *sign* needs the key rather than the id. Taking the
/// derivation as a closure keeps one branch in one place — deriving from two
/// places is precisely how a restore ends up looking in the wrong one.
pub fn discover(
    account_at: &dyn Fn(u32) -> Result<AccountId, String>,
    occupied: &dyn Fn(u32, AccountId) -> Result<bool, String>,
    gap: u32,
) -> Result<Found, String> {
    let mut found = Vec::new();
    let mut empties = 0u32;
    let mut index = 0u32;
    while empties < gap {
        let account = account_at(index)?;
        if occupied(index, account)? {
            found.push((index, account));
            empties = 0;
        } else {
            empties += 1;
        }
        index = index.checked_add(1).ok_or("receiving index overflowed")?;
    }
    Ok(Found {
        occupied: found,
        scanned_to: index,
    })
}

/// [`discover`] over the branch a seed derives, for a caller that holds it.
pub fn discover_from_seed(
    seed: &[u8],
    wallet_account: u32,
    occupied: &dyn Fn(u32, AccountId) -> Result<bool, String>,
    gap: u32,
) -> Result<Found, String> {
    discover(
        &|index| receiving_account(seed, wallet_account, index),
        occupied,
        gap,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    const SEED: &[u8] = b"a 64-byte bip39 seed would sit here, and its length is not fixed by us";

    fn held(indices: &[u32]) -> impl Fn(u32, AccountId) -> Result<bool, String> + '_ {
        let set: BTreeSet<AccountId> = indices
            .iter()
            .map(|i| receiving_account(SEED, 0, *i).unwrap())
            .collect();
        // Checks the *account*, not the index, so the test would catch a
        // discover that walked the branch with the wrong derivation.
        move |_, a| Ok(set.contains(&a))
    }

    #[test]
    fn the_same_phrase_derives_the_same_accounts_forever() {
        let a = receiving_account(SEED, 0, 7).unwrap();
        let b = receiving_account(SEED, 0, 7).unwrap();
        assert_eq!(a, b, "a restore must land on the same account");
        assert_ne!(a, receiving_account(SEED, 0, 8).unwrap(), "per index");
        assert_ne!(a, receiving_account(SEED, 1, 7).unwrap(), "per persona");
        assert_ne!(a, receiving_account(b"another seed", 0, 7).unwrap());
    }

    /// A receiving account must never coincide with the wallet identity that
    /// derives from the same seed, or the separation is cosmetic.
    #[test]
    fn a_receiving_account_is_not_the_wallet_identity() {
        // The wallet's own branch, reproduced here from its documented rule.
        let hk = Hkdf::<Sha256>::new(Some(b"nap.zyn.ed25519.v1"), SEED);
        let mut info = b"account".to_vec();
        info.extend_from_slice(&0u32.to_be_bytes());
        let mut out = [0u8; 32];
        hk.expand(&info, &mut out).unwrap();
        let wallet = account_of(
            Scheme::Ed25519,
            SigningKey::from_bytes(&out).verifying_key().as_bytes(),
        );
        for i in 0..64 {
            assert_ne!(receiving_account(SEED, 0, i).unwrap(), wallet);
        }
    }

    #[test]
    fn discovery_finds_scattered_holdings_and_stops_at_the_gap() {
        let f = discover_from_seed(SEED, 0, &held(&[0, 3, 4, 19]), GAP).unwrap();
        assert_eq!(
            f.occupied.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 3, 4, 19]
        );
        // It stopped GAP indices past the last hit, not at some fixed ceiling.
        assert_eq!(f.scanned_to, 19 + 1 + GAP);
        assert_eq!(f.next_index(), 20);
    }

    /// A hole narrower than the gap must not end the scan — this is the case
    /// that decides whether an item goes missing after a restore.
    #[test]
    fn a_hole_shorter_than_the_gap_is_crossed() {
        let f = discover_from_seed(SEED, 0, &held(&[0, GAP - 1]), GAP).unwrap();
        assert_eq!(f.occupied.len(), 2, "the far side of a 19-wide hole is found");
    }

    /// And one wider than the gap is not. The test exists to make the promise
    /// explicit rather than to celebrate it: this is exactly why indices must
    /// be issued in order.
    #[test]
    fn a_hole_wider_than_the_gap_orphans_what_is_past_it() {
        let f = discover_from_seed(SEED, 0, &held(&[0, GAP + 1]), GAP).unwrap();
        assert_eq!(
            f.occupied.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0],
            "a skipped range is unrecoverable, which is the reason for the rule"
        );
    }

    #[test]
    fn an_empty_wallet_scans_the_gap_and_starts_at_zero() {
        let f = discover_from_seed(SEED, 0, &held(&[]), GAP).unwrap();
        assert!(f.occupied.is_empty());
        assert_eq!(f.scanned_to, GAP);
        assert_eq!(f.next_index(), 0);
    }

    /// The next index is above everything seen, so an item that has been paid
    /// for but not yet minted cannot have its account handed to someone else.
    #[test]
    fn the_next_index_never_reuses_one_that_is_occupied() {
        let f = discover_from_seed(SEED, 0, &held(&[0, 1, 2]), GAP).unwrap();
        assert_eq!(f.next_index(), 3);
    }

    #[test]
    fn a_failing_probe_stops_the_scan_rather_than_reporting_an_empty_wallet() {
        let calls = RefCell::new(0);
        let e = discover_from_seed(
            SEED,
            0,
            &|_, _| {
                *calls.borrow_mut() += 1;
                Err("node unreachable".into())
            },
            GAP,
        );
        assert!(e.is_err(), "an unreachable node must not look like no holdings");
        assert_eq!(*calls.borrow(), 1, "and it stops at the first failure");
    }

    /// The default granularity: one account per collection, derived from the
    /// collection rather than a counter — so there is no sequence to keep, no
    /// gap, and one read instead of N.
    #[test]
    fn a_collection_account_is_stable_and_needs_no_counter() {
        let cavez = [0x02u8; 32];
        let moles = [0x03u8; 32];
        let a = collection_account(SEED, 0, &cavez).unwrap();
        assert_eq!(a, collection_account(SEED, 0, &cavez).unwrap(), "restorable");
        assert_ne!(a, collection_account(SEED, 0, &moles).unwrap(), "per collection");
        assert_ne!(a, collection_account(SEED, 1, &cavez).unwrap(), "per persona");
        assert_ne!(a, collection_account(b"other seed", 0, &cavez).unwrap());
    }

    /// The two branches must not collide, or a collection id that happened to
    /// look like an index would hand over the wrong account.
    #[test]
    fn collection_and_indexed_accounts_never_collide() {
        let mut collection = [0u8; 32];
        collection[28..].copy_from_slice(&7u32.to_be_bytes());
        let by_collection = collection_account(SEED, 0, &collection).unwrap();
        for i in 0..64 {
            assert_ne!(by_collection, receiving_account(SEED, 0, i).unwrap());
        }
    }

    #[test]
    fn keys_are_usable_and_bound_to_their_account() {
        use ed25519_dalek::{Signer, Verifier};
        let k = receiving_key(SEED, 0, 5).unwrap();
        let sig = k.sign(b"move this item");
        assert!(k.verifying_key().verify(b"move this item", &sig).is_ok());
        assert_eq!(
            account_of(Scheme::Ed25519, k.verifying_key().as_bytes()),
            receiving_account(SEED, 0, 5).unwrap()
        );
    }
}
