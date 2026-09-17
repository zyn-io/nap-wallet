//! Who may mint from a Cave collection, and how many.
//!
//! # What a whitelist entry is
//!
//! An allocation entitlement, not an item and not a payment. It says "this
//! invitation is good for up to N mints"; it does not say which N, because
//! which is decided by [`cave_randomness::allocate`] from evidence nobody
//! controls, and it does not cover the price, which the buyer pays from their
//! own balance at mint time.
//!
//! Like a claim code (§74.5) it is an **operator promise**. The creator key can
//! mint to anyone regardless, so this is trusted by construction and must not
//! be presented otherwise. What it does guarantee is that an invitation binds
//! to one account and cannot be spent past its allocation.
//!
//! # Why the account is not known in advance
//!
//! Whitelisting normally means collecting addresses up front. That cannot work
//! here and should not: Zyn accounts are private, most invitees will not have
//! one when they are invited, and asking for one early leaks who is interested
//! in a collection before they have decided to buy. So an invitation is a code,
//! and the holder binds their own account the first time they use it — the same
//! shape as [`crate::claim`], for the same reason.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use swapvm::types::AccountId;

pub use crate::claim::{hash_code, CodeHash};

/// One invitation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub code_hash: CodeHash,
    /// The most this invitation may ever mint.
    pub allocation: u32,
    /// A commitment to the account it belongs to, once someone has used it —
    /// `H("zyn.whitelist.bound.v1" || salt || account)`, never the account.
    ///
    /// The registry only ever needs to answer "is this the same account as
    /// last time", and a commitment answers that exactly as well as the
    /// account does. Storing the account instead would make this file an owner
    /// map: invitation to account, sitting beside a KV store that already maps
    /// handle to invitation.
    ///
    /// It is honest about what it does not stop. An operator holding *both*
    /// this file and the journal can still test every account the journal
    /// names against every entry and rebuild the map. What it stops is this
    /// file alone being the map — and this file is the one that gets copied,
    /// backed up and passed around (§98.2).
    pub bound_to: Option<Bound>,
    /// How much of the allocation has been taken.
    pub minted: u32,
}

/// A commitment to the account an invitation is bound to.
pub type Bound = [u8; 32];

/// Commit to an account under this registry's salt.
pub fn bind(salt: &[u8; 32], account: &AccountId) -> Bound {
    zyn_vm::derive::derive(b"zyn.whitelist.bound.v1", b"bound", &[salt, account])
}

impl Entry {
    /// What is left. Saturating, so a registry edited by hand into an
    /// inconsistent state reports zero rather than underflowing into plenty.
    pub fn remaining(&self) -> u32 {
        self.allocation.saturating_sub(self.minted)
    }
}

/// Why a mint was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// No such invitation.
    Unknown,
    /// The invitation belongs to a different account.
    BoundElsewhere,
    /// The allocation is spent, or the request is larger than what is left.
    Exhausted { remaining: u32 },
    /// The whitelist phase is not open.
    Closed,
}

/// The invitations, by fingerprint.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub entries: BTreeMap<CodeHash, Entry>,
    /// Whether the whitelist phase is accepting mints.
    ///
    /// Held here rather than in the service so that closing the phase survives
    /// a restart: a window that reopens because a process was bounced is not a
    /// window.
    pub open: bool,
    /// Salt for the account commitments. Generated once with the registry and
    /// persisted with it: a commitment nobody can recompute is a commitment
    /// that cannot be checked either, so the salt travels with the file it
    /// protects. Its job is to stop a *stolen* registry from being tested
    /// against a list of accounts obtained elsewhere.
    pub salt: [u8; 32],
    path: Option<PathBuf>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            entries: BTreeMap::new(),
            open: false,
            salt: rand::random(),
            path: None,
        }
    }

    pub fn issue(&mut self, code: &str, allocation: u32) -> CodeHash {
        let code_hash = hash_code(code);
        self.entries.insert(
            code_hash,
            Entry {
                code_hash,
                allocation,
                bound_to: None,
                minted: 0,
            },
        );
        code_hash
    }

    pub fn lookup(&self, code: &str) -> Option<&Entry> {
        self.entries.get(&hash_code(code))
    }

    /// Total allocation issued, and how much of it has been taken. The two
    /// numbers an operator actually needs during a sale.
    pub fn totals(&self) -> (u32, u32) {
        self.entries.values().fold((0, 0), |(a, m), e| {
            (a.saturating_add(e.allocation), m.saturating_add(e.minted))
        })
    }

    /// Claim `want` mints against an invitation.
    ///
    /// The binding is recorded before the caller does anything irreversible,
    /// the same order [`crate::claim`] uses and for the same reason: losing who
    /// an allocation belonged to is worse than repeating an attempt.
    ///
    /// Returns the entry as it now stands. The caller is expected to persist
    /// before minting and to call [`Registry::release`] if the mint fails, so
    /// that a failed attempt does not silently consume someone's allocation.
    pub fn reserve(
        &mut self,
        code: &str,
        account: AccountId,
        want: u32,
    ) -> Result<Entry, Refused> {
        if !self.open {
            return Err(Refused::Closed);
        }
        let code_hash = hash_code(code);
        let Some(entry) = self.entries.get_mut(&code_hash) else {
            return Err(Refused::Unknown);
        };
        let commitment = bind(&self.salt, &account);
        match entry.bound_to {
            Some(bound) if bound != commitment => return Err(Refused::BoundElsewhere),
            _ => {}
        }
        if want == 0 || want > entry.remaining() {
            return Err(Refused::Exhausted {
                remaining: entry.remaining(),
            });
        }
        entry.bound_to = Some(commitment);
        entry.minted = entry.minted.saturating_add(want);
        Ok(entry.clone())
    }

    /// Give back a reservation whose mint did not happen.
    ///
    /// The binding stays. An invitation that touched an account belongs to it
    /// from then on, whether or not the first attempt succeeded — otherwise a
    /// failed mint would hand the invitation back to whoever asks next.
    pub fn release(&mut self, code: &str, n: u32) {
        if let Some(e) = self.entries.get_mut(&hash_code(code)) {
            e.minted = e.minted.saturating_sub(n);
        }
    }

    /// `code_hash\tallocation\tminted\tbound_to` per line, with the phase on
    /// its own header line. Plain text, for the same reason the claim book is.
    pub fn encode(&self) -> String {
        let mut s = String::from("# zyn whitelist v1\n");
        s.push_str(&format!("# open\t{}\n", if self.open { 1 } else { 0 }));
        // The salt is not a secret from whoever holds this file — it cannot
        // be, or the commitments could not be checked. It is what stops the
        // file being testable against a list of accounts from somewhere else.
        s.push_str(&format!("# salt\t{}\n", hex(&self.salt)));
        s.push_str("# code_hash\tallocation\tminted\tbound\n");
        for e in self.entries.values() {
            s.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                hex(&e.code_hash),
                e.allocation,
                e.minted,
                e.bound_to.map(|a| hex(&a)).unwrap_or_else(|| "-".into())
            ));
        }
        s
    }

    pub fn decode(text: &str) -> Result<Registry, String> {
        let mut r = Registry::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_end();
            if let Some(v) = line.strip_prefix("# open\t") {
                r.open = v.trim() == "1";
                continue;
            }
            if let Some(v) = line.strip_prefix("# salt\t") {
                r.salt = unhex32(v.trim())
                    .ok_or_else(|| format!("line {}: salt is not 32 bytes", n + 1))?;
                continue;
            }
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let mut f = line.split('\t');
            let code_hash = unhex32(f.next().unwrap_or(""))
                .ok_or_else(|| format!("line {}: hash is not 32 bytes", n + 1))?;
            let allocation: u32 = f
                .next()
                .ok_or_else(|| format!("line {}: no allocation", n + 1))?
                .parse()
                .map_err(|_| format!("line {}: allocation is not a number", n + 1))?;
            let minted: u32 = f
                .next()
                .ok_or_else(|| format!("line {}: no minted count", n + 1))?
                .parse()
                .map_err(|_| format!("line {}: minted is not a number", n + 1))?;
            let bound_to = match f.next() {
                None | Some("-") | Some("") => None,
                Some(a) => Some(
                    unhex32(a).ok_or_else(|| format!("line {}: bad binding", n + 1))?,
                ),
            };
            r.entries.insert(
                code_hash,
                Entry {
                    code_hash,
                    allocation,
                    bound_to,
                    minted,
                },
            );
        }
        Ok(r)
    }

    pub fn load(path: &Path) -> Result<Registry, String> {
        let text =
            std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut r = Registry::decode(&text)?;
        r.path = Some(path.to_path_buf());
        Ok(r)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    const A: AccountId = [1u8; 32];
    const B: AccountId = [2u8; 32];

    fn open_registry() -> Registry {
        let mut r = Registry::new();
        r.open = true;
        r
    }

    /// A closed phase refuses everything, including a perfectly good code.
    /// This is the default, so a registry that is loaded but never opened
    /// cannot sell anything by accident.
    #[test]
    fn a_registry_is_closed_until_it_is_opened() {
        let mut r = Registry::new();
        r.issue("invite", 2);
        assert!(!r.open, "closed by default");
        assert_eq!(r.reserve("invite", A, 1), Err(Refused::Closed));
        r.open = true;
        assert!(r.reserve("invite", A, 1).is_ok());
    }

    #[test]
    fn an_invitation_binds_to_the_first_account_and_never_rebinds() {
        let mut r = open_registry();
        r.issue("invite", 3);
        assert_eq!(r.reserve("invite", A, 1).unwrap().bound_to, Some(bind(&r.salt, &A)));
        assert_eq!(r.reserve("invite", B, 1), Err(Refused::BoundElsewhere));
        // And the refusal took nothing from the allocation.
        assert_eq!(r.lookup("invite").unwrap().remaining(), 2);
    }

    /// The allocation is the whole promise, so it must hold at the boundary.
    #[test]
    fn an_allocation_can_be_spent_in_parts_and_never_past_its_total() {
        let mut r = open_registry();
        r.issue("invite", 3);
        r.reserve("invite", A, 2).unwrap();
        assert_eq!(r.lookup("invite").unwrap().remaining(), 1);
        assert_eq!(
            r.reserve("invite", A, 2),
            Err(Refused::Exhausted { remaining: 1 }),
            "asking for more than is left takes nothing"
        );
        r.reserve("invite", A, 1).unwrap();
        assert_eq!(r.lookup("invite").unwrap().remaining(), 0);
        assert_eq!(
            r.reserve("invite", A, 1),
            Err(Refused::Exhausted { remaining: 0 })
        );
    }

    #[test]
    fn asking_for_nothing_is_refused_rather_than_silently_succeeding() {
        let mut r = open_registry();
        r.issue("invite", 1);
        assert_eq!(
            r.reserve("invite", A, 0),
            Err(Refused::Exhausted { remaining: 1 })
        );
    }

    #[test]
    fn an_unknown_invitation_reserves_nothing() {
        let mut r = open_registry();
        r.issue("invite", 1);
        assert_eq!(r.reserve("nope", A, 1), Err(Refused::Unknown));
    }

    /// A mint that failed must not cost the buyer their allocation — but the
    /// invitation still belongs to them.
    #[test]
    fn releasing_a_failed_mint_returns_the_allocation_but_keeps_the_binding() {
        let mut r = open_registry();
        r.issue("invite", 2);
        r.reserve("invite", A, 2).unwrap();
        r.release("invite", 2);
        let e = r.lookup("invite").unwrap();
        assert_eq!(e.remaining(), 2, "the allocation came back");
        assert_eq!(e.bound_to, Some(bind(&r.salt, &A)), "and it is still theirs");
        assert_eq!(
            r.reserve("invite", B, 1),
            Err(Refused::BoundElsewhere),
            "so nobody else can take it"
        );
    }

    #[test]
    fn the_registry_round_trips_including_the_phase_and_the_bindings() {
        let mut r = open_registry();
        r.issue("one", 1);
        r.issue("two", 5);
        r.reserve("two", A, 3).unwrap();
        let back = Registry::decode(&r.encode()).expect("decode");
        assert!(back.open);
        assert_eq!(back.entries.len(), 2);
        // The salt must survive, or every existing binding becomes
        // uncheckable and every invitation silently rebinds.
        assert_eq!(back.salt, r.salt, "the salt round-trips with the file");
        let two = back.lookup("two").unwrap();
        assert_eq!(
            (two.allocation, two.minted, two.bound_to),
            (5, 3, Some(bind(&back.salt, &A)))
        );
        assert_eq!(back.lookup("one").unwrap().bound_to, None);
    }

    /// The property the commitment exists for: this file, on its own, is not
    /// an owner map. It answers "same account as before?" without carrying the
    /// account (§98.2).
    #[test]
    fn the_registry_file_never_contains_the_account() {
        let mut r = open_registry();
        r.issue("two", 5);
        r.reserve("two", A, 1).unwrap();
        let text = r.encode();
        assert!(
            !text.contains(&hex(&A)),
            "the account itself must not appear in the file"
        );
        // And the binding still works across a reload, which is the whole job.
        let back = Registry::decode(&text).unwrap();
        assert!(matches!(back.lookup("two").unwrap().bound_to, Some(_)));
        let mut back = back;
        back.open = true;
        assert!(back.reserve("two", A, 1).is_ok(), "the same account is recognised");
        assert_eq!(
            back.reserve("two", B, 1),
            Err(Refused::BoundElsewhere),
            "and a different one is still refused"
        );
    }

    /// Two registries must not produce the same commitment for one account, or
    /// a binding copied between them would be accepted.
    #[test]
    fn a_binding_does_not_transfer_between_registries() {
        let one = Registry::new();
        let two = Registry::new();
        assert_ne!(one.salt, two.salt, "each registry salts its own bindings");
        assert_ne!(bind(&one.salt, &A), bind(&two.salt, &A));
    }

    /// A closed phase must survive a restart, or bouncing the process reopens
    /// a window that was deliberately shut.
    #[test]
    fn a_closed_phase_survives_a_round_trip() {
        let mut r = open_registry();
        r.issue("one", 1);
        r.open = false;
        assert!(!Registry::decode(&r.encode()).unwrap().open);
    }

    #[test]
    fn totals_report_what_was_issued_and_what_has_gone() {
        let mut r = open_registry();
        r.issue("one", 2);
        r.issue("two", 3);
        assert_eq!(r.totals(), (5, 0));
        r.reserve("one", A, 2).unwrap();
        r.reserve("two", B, 1).unwrap();
        assert_eq!(r.totals(), (5, 3));
    }

    #[test]
    fn the_registry_stores_no_redeemable_code() {
        let mut r = open_registry();
        r.issue("secret-invitation-abcdef", 1);
        assert!(!r.encode().contains("secret-invitation-abcdef"));
        assert!(r.lookup("secret-invitation-abcdef").is_some());
    }

    #[test]
    fn a_malformed_registry_is_refused_rather_than_half_read() {
        assert!(Registry::decode("nothex\t1\t0\t-").is_err());
        assert!(Registry::decode(&format!("{}\tmany\t0\t-", "ab".repeat(32))).is_err());
    }
}
