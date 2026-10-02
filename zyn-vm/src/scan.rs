//! The wallet's half: finding what you own, and knowing what you spent.
//!
//! On an account ledger a wallet asks the node "what does this account hold"
//! and believes the answer. Against an object ledger **that query does not
//! exist** — the chain holds commitments, and a commitment says nothing about
//! who it is for. So a wallet reconstructs its own balance:
//!
//! ```text
//!   for every output ever published
//!       try to open its ciphertext with my viewing key
//!       if it opens, that note is mine
//!   for every nullifier ever published
//!       if it is one of mine, that note is spent
//!   what is left is what I hold
//! ```
//!
//! This is the Zcash sync problem arriving inside Zyn, and it is the price of
//! the ledger being private (DECISIONS §133.5). The cost is linear in
//! *outputs*, not in holders, and every wallet pays it independently.
//!
//! # Why the nullifier half is not optional
//!
//! A wallet that only scans outputs sees everything it ever received and
//! nothing it ever spent, so it shows a balance that only grows. Worse, it
//! would offer to spend notes that are already gone, and every such spend is
//! refused by the chain after the user has been told it would work.
//!
//! Recognising your own spends needs the nullifier key, which is why
//! [`Scanner`] takes one and why it is a different key from the viewing key:
//! a watch-only scanner can be given the second and not the first, and will
//! see receipts it cannot recognise as spent. That is a real posture — an
//! auditor, an accountant — and it should fail visibly rather than quietly
//! report a wrong balance, so [`Scanner::watch_only`] says so in its name.

use alloc::vec::Vec;

use crate::commit::Hash;
use crate::note_enc::{open, EncryptedNote, StaticSecret};
use crate::object::{commitment, nullifier, Note, NullifierKey};

/// One output as published: the commitment the chain stores, and the
/// ciphertext that tells its owner it is theirs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublishedOutput {
    pub commitment: Hash,
    pub enc: EncryptedNote,
}

/// A note this wallet owns and has not spent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Owned {
    pub note: Note,
    pub commitment: Hash,
    /// Where it sits in the commitment tree. Permanent, because the tree
    /// appends and never sorts — which is what makes a witness keep working.
    pub position: u64,
}

/// What a wallet knows after scanning.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Wallet {
    pub live: Vec<Owned>,
    /// Notes we found and later saw spent. Kept rather than dropped: a wallet
    /// that forgets its own history cannot explain a balance to its holder.
    pub spent: Vec<Owned>,
}

impl Wallet {
    /// What this wallet holds of one asset.
    ///
    /// Summed from the notes rather than read from anywhere, because there is
    /// nowhere to read it from. Saturating: a wallet reporting a wrong total
    /// is bad, one that panics mid-scan is worse.
    pub fn balance(&self, asset: &Hash) -> i128 {
        self.live
            .iter()
            .filter(|o| &o.note.asset == asset)
            .fold(0i128, |acc, o| acc.saturating_add(o.note.amount.0))
    }
}

/// Reconstructs a wallet from what the chain published.
pub struct Scanner {
    viewing: StaticSecret,
    nullifier_key: Option<NullifierKey>,
}

impl Scanner {
    /// A wallet that can see its receipts and recognise its spends.
    pub fn new(viewing: StaticSecret, nullifier_key: NullifierKey) -> Self {
        Scanner {
            viewing,
            nullifier_key: Some(nullifier_key),
        }
    }

    /// A scanner that can read receipts but cannot tell which are spent.
    ///
    /// Named so at the call site because the balance it reports is an upper
    /// bound, not a balance, and anything that displays it as one is wrong.
    pub fn watch_only(viewing: StaticSecret) -> Self {
        Scanner {
            viewing,
            nullifier_key: None,
        }
    }

    pub fn can_detect_spends(&self) -> bool {
        self.nullifier_key.is_some()
    }

    /// Decode the plaintext a note was sealed as.
    ///
    /// The format is the sender's, not the chain's, so this is deliberately
    /// strict: a note that opens but does not parse is not ours in any useful
    /// sense, and treating it as ours would put a balance in the wallet that
    /// cannot be spent.
    fn parse(plain: &[u8], owner: &crate::spec::AccountId) -> Option<Note> {
        if plain.len() != 80 {
            return None;
        }
        let asset: Hash = plain[0..32].try_into().ok()?;
        let amount = i128::from_be_bytes(plain[32..48].try_into().ok()?);
        let nonce: Hash = plain[48..80].try_into().ok()?;
        Some(Note {
            asset,
            amount: crate::fixed::Fixed(amount),
            owner: *owner,
            nonce,
        })
    }

    /// Scan a run of published outputs and nullifiers.
    ///
    /// `outputs` must be in tree order and `from_position` the tree position
    /// of the first, because a note's position is how its witness is built and
    /// there is no way to recover it afterwards.
    pub fn scan(
        &self,
        owner: &crate::spec::AccountId,
        outputs: &[PublishedOutput],
        from_position: u64,
        spent_nullifiers: &[Hash],
    ) -> Wallet {
        let mut found: Vec<Owned> = Vec::new();

        for (i, out) in outputs.iter().enumerate() {
            let Ok(plain) = open(&self.viewing, &out.enc) else {
                continue; // not ours, or not a note
            };
            let Some(note) = Self::parse(&plain, owner) else {
                continue;
            };
            // The ciphertext claims a note; the commitment is what the chain
            // committed to. If they disagree the sender sealed one thing and
            // published another, and the note is unspendable — so it is not a
            // receipt, whatever the ciphertext says.
            match commitment(&note) {
                Ok(c) if c == out.commitment => found.push(Owned {
                    note,
                    commitment: c,
                    position: from_position + i as u64,
                }),
                _ => continue,
            }
        }

        let Some(key) = self.nullifier_key else {
            return Wallet {
                live: found,
                spent: Vec::new(),
            };
        };

        let (spent, live) = found
            .into_iter()
            .partition(|o| spent_nullifiers.contains(&nullifier(&key, &o.commitment)));
        Wallet { live, spent }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::note_enc::{seal, viewing_public};

    const ME: crate::spec::AccountId = [0xAA; 32];
    const ZEC: Hash = [0x7a; 32];

    fn published(to: &StaticSecret, amount: i64, nonce: u8, eph: u8) -> (PublishedOutput, Note) {
        let note = Note {
            asset: ZEC,
            amount: Fixed::whole(amount),
            owner: ME,
            nonce: [nonce; 32],
        };
        let mut plain = Vec::new();
        plain.extend_from_slice(&note.asset);
        plain.extend_from_slice(&note.amount.0.to_be_bytes());
        plain.extend_from_slice(&note.nonce);
        let enc = seal(&viewing_public(to), StaticSecret::from([eph; 32]), &plain).unwrap();
        (
            PublishedOutput {
                commitment: commitment(&note).unwrap(),
                enc,
            },
            note,
        )
    }

    /// The whole mechanism: a wallet with no query available rebuilds its own
    /// balance from what anyone could have downloaded.
    #[test]
    fn a_wallet_reconstructs_its_balance_from_published_outputs() {
        let me = StaticSecret::from([0x11; 32]);
        let them = StaticSecret::from([0x22; 32]);
        let (mine_a, _) = published(&me, 5, 1, 41);
        let (theirs, _) = published(&them, 99, 2, 42);
        let (mine_b, _) = published(&me, 12, 3, 43);

        let w = Scanner::new(me, [0x31; 32]).scan(&ME, &[mine_a, theirs, mine_b], 0, &[]);

        assert_eq!(w.live.len(), 2, "two of the three were ours");
        assert_eq!(w.balance(&ZEC), Fixed::whole(17).0);
        assert_eq!(w.live[0].position, 0);
        assert_eq!(w.live[1].position, 2, "position is tree order, not our order");
    }

    /// Without the nullifier half a wallet shows a balance that only grows and
    /// offers to spend notes that are already gone.
    #[test]
    fn a_spent_note_stops_counting() {
        let me = StaticSecret::from([0x11; 32]);
        let key: NullifierKey = [0x31; 32];
        let (out_a, note_a) = published(&me, 5, 1, 41);
        let (out_b, _) = published(&me, 12, 3, 43);

        let spent = nullifier(&key, &commitment(&note_a).unwrap());
        let w = Scanner::new(me, key).scan(&ME, &[out_a, out_b], 0, &[spent]);

        assert_eq!(w.live.len(), 1);
        assert_eq!(w.spent.len(), 1, "and it is remembered, not dropped");
        assert_eq!(w.balance(&ZEC), Fixed::whole(12).0);
    }

    /// A watch-only scanner reports an upper bound, and says as much rather
    /// than quietly reporting it as a balance.
    #[test]
    fn a_watch_only_scanner_cannot_see_spends_and_admits_it() {
        let me = StaticSecret::from([0x11; 32]);
        let key: NullifierKey = [0x31; 32];
        let (out_a, note_a) = published(&me, 5, 1, 41);
        let spent = nullifier(&key, &commitment(&note_a).unwrap());

        let s = Scanner::watch_only(me);
        assert!(!s.can_detect_spends());
        let w = s.scan(&ME, &[out_a], 0, &[spent]);
        assert_eq!(w.live.len(), 1, "it still counts a note that is gone");
    }

    /// A sender who seals one note and publishes another has created a
    /// commitment the recipient cannot spend. Counting it would put money in
    /// the wallet that is not there.
    #[test]
    fn a_ciphertext_that_disagrees_with_its_commitment_is_not_a_receipt() {
        let me = StaticSecret::from([0x11; 32]);
        let (mut out, _) = published(&me, 5, 1, 41);
        out.commitment = [0xEE; 32]; // committed to something else

        let w = Scanner::new(me, [0x31; 32]).scan(&ME, &[out], 0, &[]);
        assert!(w.live.is_empty(), "it opens, and it is still not ours");
    }

    /// Scanning nothing is not an error, and an empty chain is not a lost
    /// wallet.
    #[test]
    fn scanning_an_empty_range_yields_an_empty_wallet() {
        let w = Scanner::new(StaticSecret::from([0x11; 32]), [0x31; 32]).scan(&ME, &[], 0, &[]);
        assert!(w.live.is_empty() && w.spent.is_empty());
        assert_eq!(w.balance(&ZEC), 0);
    }
}
