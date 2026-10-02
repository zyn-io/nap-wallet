//! How a holder finds an object that is theirs.
//!
//! The chain publishes a commitment, which is a hash. Nothing about it says
//! who it is for — that is the point — and so nothing about it tells its owner
//! that it exists. A note nobody can find is a note nobody can spend.
//!
//! Zcash answers this by attaching a ciphertext to every output and having
//! wallets *trial-decrypt* every one: if it opens, it was yours. This is the
//! same construction, and it is deliberately the same because the failure
//! modes are known.
//!
//! ```text
//!   sender    ephemeral keypair, ECDH with the recipient's viewing key
//!             → shared secret → ChaCha20-Poly1305 over the note
//!   chain     commitment · epk · ciphertext
//!   holder    for each new output: try to open it with my viewing key
//! ```
//!
//! # Why this is the keystone and not a later nicety
//!
//! Two things depend on it and neither can ship without it (DECISIONS §133.5,
//! §133.6). A wallet needs it to show a holder what they own, because the
//! query "what does this account hold" does not exist against an object
//! ledger. And a **deposit** needs it: the sequencer creates the note when ZEC
//! arrives, and the depositor has to be able to find it.
//!
//! The tempting shortcut for deposits is to derive the nonce publicly — from
//! the txid, say — so the recipient can recompute the commitment. That leaks:
//! an observer who knows the txid can guess a recipient, recompute the
//! commitment, and *confirm the guess*. Encryption avoids handing anyone a
//! test they can run offline.
//!
//! # What this does not hide
//!
//! The ciphertext's existence, its length, and when it appeared. An observer
//! learns that an output was created and roughly how big its note is. Every
//! note is padded to a fixed length here so the second of those says nothing.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
pub use x25519_dalek::StaticSecret;
use x25519_dalek::PublicKey;

use crate::commit::{Encoder, Hash};

/// What a holder publishes so others can pay them, and keeps so they can find
/// what arrived. Viewing only: it opens notes, it does not spend them.
pub type ViewingKey = [u8; 32];

/// Why a note could not be opened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoteEncError {
    /// Not ours, or damaged. Deliberately one case: telling a scanner *why* a
    /// trial decryption failed would tell an attacker which notes are close.
    NotForUs,
    /// The plaintext did not have the shape a note has.
    Malformed,
}

/// A note as it travels: who can open it is not written anywhere on it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncryptedNote {
    /// The sender's ephemeral public key. Fresh per note, so two notes to the
    /// same recipient share nothing an observer can link.
    pub epk: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Every plaintext is padded to this before sealing, so a long note and a
/// short one are the same size on the wire.
pub const PLAINTEXT_LEN: usize = 128;

/// A single fixed nonce is safe here because the key is never reused: it comes
/// from a fresh ECDH with a per-note ephemeral secret, so no two notes share
/// one. The same argument `dacrypt` makes for per-artifact keys.
const NONCE: [u8; 12] = *b"zyn.note.v1\0";

fn kdf(shared: &[u8; 32], epk: &[u8; 32]) -> Key {
    let mut e = Encoder::new();
    e.bytes(b"zyn.note.kdf.v1").bytes(shared).bytes(epk);
    let k: Hash = e.leaf();
    *Key::from_slice(&k)
}

/// Seal `plaintext` to a recipient's viewing key.
///
/// `ephemeral` must be fresh for every note. Reusing one links the notes and,
/// worse, reuses the key the nonce's safety depends on.
pub fn seal(
    to: &ViewingKey,
    ephemeral: StaticSecret,
    plaintext: &[u8],
) -> Result<EncryptedNote, NoteEncError> {
    if plaintext.len() > PLAINTEXT_LEN {
        return Err(NoteEncError::Malformed);
    }
    let epk = PublicKey::from(&ephemeral).to_bytes();
    let dh = ephemeral.diffie_hellman(&PublicKey::from(*to));
    // A low-order viewing key drives the exchange to an all-zero shared
    // secret, which anybody can recompute — the note would be sealed in
    // public. The sender is the one who would suffer no loss and the
    // recipient the one who would, so it is refused here rather than left
    // to whoever chose the key.
    if !dh.was_contributory() {
        return Err(NoteEncError::Malformed);
    }
    let shared = dh.to_bytes();

    let mut padded = Vec::with_capacity(PLAINTEXT_LEN);
    padded.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(PLAINTEXT_LEN, 0);

    let ciphertext = ChaCha20Poly1305::new(&kdf(&shared, &epk))
        .encrypt(Nonce::from_slice(&NONCE), padded.as_slice())
        .map_err(|_| NoteEncError::Malformed)?;
    Ok(EncryptedNote { epk, ciphertext })
}

/// Try to open a note. This is the scan: call it on every new output and keep
/// the ones that open.
///
/// Constant in what it reveals — a failure is [`NoteEncError::NotForUs`]
/// whether the note was for someone else or was corrupt.
pub fn open(viewing: &StaticSecret, note: &EncryptedNote) -> Result<Vec<u8>, NoteEncError> {
    let shared = viewing.diffie_hellman(&PublicKey::from(note.epk)).to_bytes();
    let padded = ChaCha20Poly1305::new(&kdf(&shared, &note.epk))
        .decrypt(Nonce::from_slice(&NONCE), note.ciphertext.as_slice())
        .map_err(|_| NoteEncError::NotForUs)?;

    if padded.len() != PLAINTEXT_LEN {
        return Err(NoteEncError::Malformed);
    }
    let len = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if len > PLAINTEXT_LEN - 4 {
        return Err(NoteEncError::Malformed);
    }
    Ok(padded[4..4 + len].to_vec())
}

/// The public half of a viewing key, to publish as a payment address.
pub fn viewing_public(secret: &StaticSecret) -> ViewingKey {
    PublicKey::from(secret).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(b: u8) -> StaticSecret {
        StaticSecret::from([b; 32])
    }

    #[test]
    fn a_note_opens_for_its_recipient_and_nobody_else() {
        let alice = secret(1);
        let bob = secret(2);
        let note = seal(&viewing_public(&alice), secret(9), b"17 ZEC").unwrap();

        assert_eq!(open(&alice, &note).unwrap(), b"17 ZEC");
        assert_eq!(open(&bob, &note), Err(NoteEncError::NotForUs));
    }

    /// The scan, in miniature: a holder tries every output and keeps what
    /// opens. This is the whole discovery mechanism, and the cost model —
    /// linear in outputs, not in holders.
    #[test]
    fn scanning_finds_only_our_own() {
        let me = secret(3);
        let them = secret(4);
        let outputs: Vec<EncryptedNote> = (0..8u8)
            .map(|i| {
                let to = if i % 3 == 0 { &me } else { &them };
                seal(&viewing_public(to), secret(100 + i), &[i; 4]).unwrap()
            })
            .collect();

        let mine: Vec<Vec<u8>> = outputs.iter().filter_map(|n| open(&me, n).ok()).collect();
        assert_eq!(mine, vec![vec![0u8; 4], vec![3u8; 4], vec![6u8; 4]]);
    }

    /// Two notes to the same recipient must share nothing an observer can
    /// link, or the ciphertexts become a way to cluster a holder's receipts
    /// even though neither can be opened.
    #[test]
    fn two_notes_to_the_same_holder_look_unrelated() {
        let alice = viewing_public(&secret(5));
        let a = seal(&alice, secret(10), b"same").unwrap();
        let b = seal(&alice, secret(11), b"same").unwrap();

        assert_ne!(a.epk, b.epk);
        assert_ne!(a.ciphertext, b.ciphertext, "identical plaintexts, unlinkable notes");
    }

    /// Length must not leak. A one-byte note and a hundred-byte note are the
    /// same size on the wire, or the size becomes a classifier.
    #[test]
    fn every_note_is_the_same_size_on_the_wire() {
        let to = viewing_public(&secret(6));
        let small = seal(&to, secret(12), b"1").unwrap();
        let large = seal(&to, secret(13), &[7u8; 100]).unwrap();
        assert_eq!(small.ciphertext.len(), large.ciphertext.len());
    }

    /// A failure says "not ours" and never why. A scanner that distinguished
    /// "wrong key" from "corrupt" would be an oracle for how close a guess was.
    #[test]
    fn a_tampered_note_fails_the_same_way_a_foreign_one_does() {
        let alice = secret(7);
        let mut note = seal(&viewing_public(&alice), secret(14), b"x").unwrap();
        note.ciphertext[0] ^= 0xFF;
        assert_eq!(open(&alice, &note), Err(NoteEncError::NotForUs));
    }

    #[test]
    fn a_note_larger_than_the_frame_is_refused() {
        let to = viewing_public(&secret(8));
        assert_eq!(
            seal(&to, secret(15), &[0u8; PLAINTEXT_LEN + 1]),
            Err(NoteEncError::Malformed)
        );
    }
}

#[cfg(test)]
mod low_order {
    use super::*;

    /// A low-order public key drives X25519 to an all-zero shared secret,
    /// which anyone can recompute. Sealing to one would publish the note.
    #[test]
    fn sealing_to_a_degenerate_key_is_refused() {
        // The small-order points of Curve25519. Each forces a zero output.
        let degenerate: [[u8; 32]; 3] = [
            [0u8; 32],
            {
                let mut k = [0u8; 32];
                k[0] = 1;
                k
            },
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
        ];
        for k in degenerate {
            assert_eq!(
                seal(&k, StaticSecret::from([7u8; 32]), b"note"),
                Err(NoteEncError::Malformed),
                "sealing to a low-order key must be refused"
            );
        }
    }

    /// And an ordinary key still works, so the check is not simply refusing.
    #[test]
    fn sealing_to_a_real_key_still_works() {
        let recipient = StaticSecret::from([0x11u8; 32]);
        let note = seal(
            &viewing_public(&recipient),
            StaticSecret::from([7u8; 32]),
            b"note",
        )
        .expect("an ordinary key seals");
        assert_eq!(open(&recipient, &note).unwrap(), b"note");
    }
}
