//! Redeeming a claim code for one of the 333.
//!
//! # What this is, and what it is not
//!
//! A claim code is an **operator promise**, redeemable once (§74.5). The
//! creator key can move any item to any account regardless of what this service
//! does, so the service is trusted by construction and must never be described
//! as trustless. A code is not a bearer asset: it proves nothing on chain, it
//! is not an item, and losing one is a support question rather than a loss.
//!
//! # Why a transfer rather than a mint
//!
//! §74.2 planned to mint at claim time, which would have made the chain's
//! `minted` count a live measure of how many had been given out. Genesis
//! pre-minted all 333 to the treasury and closed the collection instead, so
//! that door is shut: `MintCollectionItem` requires `Minting`, and the cap is
//! full. Claiming is therefore a transfer.
//!
//! The trade is not all loss. Every serial's `content` is already committed on
//! chain, so which mole is #200 was fixed before anyone asked for one — the
//! property §74.3 wanted, arriving by a different route.
//!
//! # Idempotency
//!
//! §74.6: the code carries the serial, the claimant supplies the account.
//! Re-submitting the same code with the same account returns the same result;
//! with a different account it is refused. Both are answered from **chain
//! state** rather than from this service's own records, because the chain is
//! the thing that is true if the two ever disagree — a crash between submitting
//! a transfer and recording it must not cost anyone their mole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use swapvm::types::AccountId;

/// A code's fingerprint. Codes are stored hashed so that reading this file
/// yields nothing redeemable: an operator who needs to reissue a code must
/// generate a new one, which is the correct shape for a promise anyway.
pub type CodeHash = [u8; 32];

pub fn hash_code(code: &str) -> CodeHash {
    // Trimmed and lowercased so a code read off paper survives a phone
    // keyboard's capitalisation.
    let norm = code.trim().to_ascii_lowercase();
    // Domain-separated so a code's fingerprint cannot collide with any other
    // hash the system computes over the same bytes.
    zyn_vm::derive::derive(b"zyn.claim.code.v1", b"code", &[norm.as_bytes()])
}

/// One promise: this code is good for this serial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub serial: u32,
    pub code_hash: CodeHash,
    /// Who redeemed it, if anyone has. Advisory — the chain decides.
    pub claimed_by: Option<AccountId>,
}

/// The issued codes, by fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Book {
    pub entries: BTreeMap<CodeHash, Entry>,
    path: Option<PathBuf>,
}

/// What a claim attempt resolved to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The item moved, or had already moved to this account.
    Granted { serial: u32, asset: [u8; 32] },
    /// The code is good but belongs to a different account now. §74.6: a code
    /// binds the first account that redeems it and never rebinds.
    AlreadyBound { serial: u32 },
    /// No such code.
    Unknown,
}

impl Book {
    pub fn new() -> Book {
        Book::default()
    }

    pub fn issue(&mut self, serial: u32, code: &str) -> CodeHash {
        let code_hash = hash_code(code);
        self.entries.insert(
            code_hash,
            Entry {
                serial,
                code_hash,
                claimed_by: None,
            },
        );
        code_hash
    }

    pub fn lookup(&self, code: &str) -> Option<&Entry> {
        self.entries.get(&hash_code(code))
    }

    pub fn mark_claimed(&mut self, code_hash: CodeHash, by: AccountId) {
        if let Some(e) = self.entries.get_mut(&code_hash) {
            e.claimed_by = Some(by);
        }
    }

    /// `serial\tcode_hash\tclaimed_by` per line. Plain text on purpose: an
    /// operator has to be able to read this during an event, on a laptop, with
    /// no tooling.
    pub fn encode(&self) -> String {
        let mut s = String::from("# zyn claim book v1\n# serial\tcode_hash\tclaimed_by\n");
        for e in self.entries.values() {
            s.push_str(&format!(
                "{}\t{}\t{}\n",
                e.serial,
                hex(&e.code_hash),
                e.claimed_by.map(|a| hex(&a)).unwrap_or_else(|| "-".into())
            ));
        }
        s
    }

    pub fn decode(text: &str) -> Result<Book, String> {
        let mut b = Book::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split('\t');
            let serial: u32 = f
                .next()
                .ok_or_else(|| format!("line {}: no serial", n + 1))?
                .parse()
                .map_err(|_| format!("line {}: serial is not a number", n + 1))?;
            let code_hash = unhex32(f.next().ok_or_else(|| format!("line {}: no hash", n + 1))?)
                .ok_or_else(|| format!("line {}: hash is not 32 bytes", n + 1))?;
            let claimed_by = match f.next() {
                None | Some("-") | Some("") => None,
                Some(a) => Some(unhex32(a).ok_or_else(|| format!("line {}: bad account", n + 1))?),
            };
            b.entries.insert(
                code_hash,
                Entry {
                    serial,
                    code_hash,
                    claimed_by,
                },
            );
        }
        Ok(b)
    }

    pub fn load(path: &Path) -> Result<Book, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut b = Book::decode(&text)?;
        b.path = Some(path.to_path_buf());
        Ok(b)
    }

    /// Written through a temporary file and renamed, so an interrupted save
    /// leaves the previous book rather than half of this one.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.encode()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn persist(&self) -> Result<(), String> {
        match &self.path {
            Some(p) => self.save(p),
            None => Ok(()),
        }
    }

    pub fn set_path(&mut self, p: PathBuf) {
        self.path = Some(p);
    }
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}


/// What submitting a transfer did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Granted {
    /// The item moved now.
    Moved,
    /// The treasury no longer had it — it moved on an earlier attempt whose
    /// response was lost. Indistinguishable from success, and it is success.
    AlreadyGone,
}

/// Resolve one claim.
///
/// # Why there is no read of the chain here
///
/// Balances on Zyn are private: `OP_ACCOUNT` derives the account from a
/// signature, so nobody can look up who holds an item — and the treasury cannot
/// even look up its own, because a threshold account has no single key to sign
/// a read with. So this cannot ask the chain "is it still here?".
///
/// It does not need to. An item is one indivisible unit, so a second transfer
/// of the same item fails with `InsufficientBalance`. Submitting again is
/// therefore safe: either it moves, or the chain says it already had. That
/// makes the chain itself the thing that prevents a double grant, rather than
/// this service's bookkeeping.
///
/// # The binding is written before the transfer
///
/// §74.6 binds a code to the first account that redeems it. The binding is
/// recorded *before* anything is signed, so a crash between submitting and
/// recording cannot lose who the item was for — the retry finds the binding and
/// completes it. The cost is the opposite failure: a crash after binding but
/// before submitting leaves a code bound to someone who has nothing yet, which
/// the same retry fixes by submitting. Losing the record is worse than
/// repeating the attempt, so the order is the safe one.
pub fn resolve(
    book: &mut Book,
    code: &str,
    account: AccountId,
    collection: [u8; 32],
    grant: &dyn Fn(u32, [u8; 32], AccountId) -> Result<Granted, String>,
) -> Result<Outcome, String> {
    let Some(entry) = book.lookup(code).cloned() else {
        return Ok(Outcome::Unknown);
    };
    if let Some(bound) = entry.claimed_by {
        if bound != account {
            return Ok(Outcome::AlreadyBound {
                serial: entry.serial,
            });
        }
    }
    let asset = zyn_vm::item_address(
        zyn_vm::derive::ADDRESS_SCOPE_V1,
        &collection,
        serial_on_chain(entry.serial),
    );

    // Bind first. A lost response after this point costs a repeated submission,
    // which the chain absorbs; a lost binding would cost someone their mole.
    book.mark_claimed(entry.code_hash, account);
    book.persist()?;

    grant(entry.serial, asset, account)?;
    Ok(Outcome::Granted {
        serial: entry.serial,
        asset,
    })
}

/// Collectors count from one; the VM requires `serial < cap` (§C28).
pub fn serial_on_chain(number: u32) -> u32 {
    number.saturating_sub(1)
}

/// Whether a rejection means "that item has already left the treasury".
///
/// `InsufficientBalance` is code 3. For a unique item held by one account it
/// can only mean the item is no longer there, which for a claim is success.
pub fn is_already_gone(err: &str) -> bool {
    err.contains("(code 3)")
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];

    #[test]
    fn a_code_is_stored_only_as_a_fingerprint() {
        let mut b = Book::new();
        b.issue(7, "mole-seven-abcdef");
        let text = b.encode();
        assert!(
            !text.contains("mole-seven-abcdef"),
            "the book must not contain a redeemable code"
        );
        assert!(b.lookup("mole-seven-abcdef").is_some());
    }

    /// A code read off paper into a phone keyboard.
    #[test]
    fn codes_survive_case_and_surrounding_space() {
        let mut b = Book::new();
        b.issue(7, "Mole-Seven-ABCDEF");
        assert_eq!(b.lookup("  mole-seven-abcdef  ").map(|e| e.serial), Some(7));
    }

    #[test]
    fn an_unknown_code_matches_nothing() {
        let mut b = Book::new();
        b.issue(7, "good");
        assert!(b.lookup("bad").is_none());
    }

    #[test]
    fn the_book_round_trips_including_who_claimed_what() {
        let mut b = Book::new();
        let h1 = b.issue(1, "one");
        b.issue(2, "two");
        b.mark_claimed(h1, A);
        let back = Book::decode(&b.encode()).expect("decode");
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.lookup("one").unwrap().claimed_by, Some(A));
        assert_eq!(back.lookup("two").unwrap().claimed_by, None);
        assert_eq!(back.lookup("one").unwrap().serial, 1);
    }

    #[test]
    fn a_claimed_code_names_the_account_that_took_it() {
        let mut b = Book::new();
        let h = b.issue(5, "five");
        b.mark_claimed(h, A);
        assert_eq!(b.lookup("five").unwrap().claimed_by, Some(A));
        assert_ne!(b.lookup("five").unwrap().claimed_by, Some(B));
    }

    #[test]
    fn a_malformed_book_is_refused_rather_than_half_read() {
        assert!(Book::decode("1\tnothex\t-").is_err());
        assert!(Book::decode("notanumber\t00\t-").is_err());
    }
    const COLL: [u8; 32] = [9u8; 32];

    /// A treasury holding one of each item, and a count of what was signed.
    struct Chain {
        held: std::cell::RefCell<std::collections::BTreeSet<[u8; 32]>>,
        submits: std::cell::RefCell<u32>,
    }
    impl Chain {
        fn holding(assets: &[[u8; 32]]) -> Chain {
            Chain {
                held: std::cell::RefCell::new(assets.iter().copied().collect()),
                submits: std::cell::RefCell::new(0),
            }
        }
        fn grant(&self) -> impl Fn(u32, [u8; 32], AccountId) -> Result<Granted, String> + '_ {
            move |_, asset, _| {
                *self.submits.borrow_mut() += 1;
                // A unique item: the second transfer finds nothing to move.
                if self.held.borrow_mut().remove(&asset) {
                    Ok(Granted::Moved)
                } else {
                    Ok(Granted::AlreadyGone)
                }
            }
        }
    }

    fn asset_for(n: u32) -> [u8; 32] {
        zyn_vm::item_address(zyn_vm::derive::ADDRESS_SCOPE_V1, &COLL, serial_on_chain(n))
    }

    #[test]
    fn a_good_code_grants_the_item() {
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        let out = resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        assert_eq!(
            out,
            Outcome::Granted {
                serial: 1,
                asset: asset_for(1)
            }
        );
        assert_eq!(b.lookup("one").unwrap().claimed_by, Some(A));
    }

    /// §74.6: the same code and the same account returns the same result. It
    /// may submit again — the chain absorbs that — but the answer is identical
    /// and the item does not move twice.
    #[test]
    fn retrying_with_the_same_account_answers_identically() {
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        let first = resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        let again = resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        assert_eq!(first, again);
        assert_eq!(c.held.borrow().len(), 0, "the item moved exactly once");
    }

    /// §74.6: a different account is refused, and nothing is signed for it.
    #[test]
    fn a_spent_code_will_not_rebind_to_another_account() {
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        let before = *c.submits.borrow();
        let out = resolve(&mut b, "one", B, COLL, &c.grant()).unwrap();
        assert_eq!(out, Outcome::AlreadyBound { serial: 1 });
        assert_eq!(*c.submits.borrow(), before, "nothing was signed for the second account");
    }

    /// The crash this ordering exists for: the transfer went through and the
    /// response was lost. The binding was written first, so the retry finds it
    /// and completes rather than handing the mole to whoever asks next.
    #[test]
    fn a_lost_response_still_belongs_to_the_account_it_was_bound_to() {
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();

        // B turns up with the same code after A's response was lost.
        assert_eq!(
            resolve(&mut b, "one", B, COLL, &c.grant()).unwrap(),
            Outcome::AlreadyBound { serial: 1 }
        );
        // A retries and is served.
        assert_eq!(
            resolve(&mut b, "one", A, COLL, &c.grant()).unwrap(),
            Outcome::Granted { serial: 1, asset: asset_for(1) }
        );
    }

    /// A crash *before* the transfer: bound but never sent. The retry sends it.
    #[test]
    fn a_binding_with_no_transfer_is_completed_on_retry() {
        let mut b = Book::new();
        let h = b.issue(1, "one");
        b.mark_claimed(h, A);
        let c = Chain::holding(&[asset_for(1)]);
        let out = resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        assert_eq!(out, Outcome::Granted { serial: 1, asset: asset_for(1) });
        assert_eq!(c.held.borrow().len(), 0, "the item was sent this time");
    }

    #[test]
    fn an_unknown_code_grants_nothing() {
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        assert_eq!(
            resolve(&mut b, "nope", A, COLL, &c.grant()).unwrap(),
            Outcome::Unknown
        );
        assert_eq!(*c.submits.borrow(), 0);
    }

    /// Collectors count from one, the VM counts from zero (§C28).
    #[test]
    fn the_code_for_mole001_grants_serial_zero() {
        assert_eq!(serial_on_chain(1), 0);
        assert_eq!(serial_on_chain(333), 332);
        let mut b = Book::new();
        b.issue(1, "one");
        let c = Chain::holding(&[asset_for(1)]);
        let out = resolve(&mut b, "one", A, COLL, &c.grant()).unwrap();
        let want = zyn_vm::item_address(zyn_vm::derive::ADDRESS_SCOPE_V1, &COLL, 0);
        assert_eq!(out, Outcome::Granted { serial: 1, asset: want });
    }

    #[test]
    fn insufficient_balance_reads_as_already_gone() {
        assert!(is_already_gone("rejected: insufficient balance (code 3)"));
        assert!(!is_already_gone("rejected: not the issuer (code 53)"));
        assert!(!is_already_gone("node refused: wrong chain"));
    }
}