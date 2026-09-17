//! Confidential data availability: the two files that carry ownership.
//!
//! Everything else in a bundle is already blind. `published.bin` is roots and
//! leaves, and a leaf is `H(record)` over a record carrying the holder's own
//! blind, so it "reveals nothing to anyone but its holder — not a balance, not
//! an item, not whether the account is empty" (`zyn::da`). The anchor and the
//! certificate are commitments and signatures over them.
//!
//! Two files are not blind, and cannot be, because they are what a verifier
//! *replays*:
//!
//!   * `intents/epoch-N.intents` — the journal. `swapvm::wire` encodes a
//!     transfer's sender, recipient and asset, and a mint's recipient.
//!   * `base.state` — the whole VM state a replica starts from.
//!
//! Anyone holding those can build the owner map (DECISIONS §92.1). That is the
//! whole of the leak, and it is inherent: publishing them is what makes
//! verification permissionless.
//!
//! # Encrypted rather than withheld
//!
//! The obvious fix is to serve them only to authorised verifiers. This does
//! something better: it encrypts them and keeps serving them to everyone. A
//! mirror stays dumb, anybody may host the ciphertext, and the durability
//! argument for DA is untouched — "the cheapest hosting that answers `GET` will
//! do" still holds, because a host that cannot read a file can still keep it.
//! What changes is who can *replay*, which is the trade §70.4 asks to be stated
//! rather than hidden: a stranger can still check the anchor chain on Zcash and
//! that the published leaves rebuild the anchored root; they can no longer
//! re-execute the history themselves.
//!
//! # One key per artifact
//!
//! A root key is shared out of band with the verifier set (`ZYN_DA_KEY`). Every
//! artifact gets its **own** key, derived from the root and the artifact's
//! label: HKDF-SHA256, salt `zyn.da.v1`, info `chain || label`. Two properties
//! follow, and both matter more than they look:
//!
//! 1. A fixed nonce is safe. Nonce reuse is catastrophic only when a *key* is
//!    reused, and no two artifacts share one. The one way to break this is to
//!    seal the same label twice with different plaintext — which for an
//!    anchored epoch's journal would already be a bug, since that file is
//!    immutable once published.
//! 2. The sealing is deterministic, so republishing a bundle produces identical
//!    bytes and a mirror push stays idempotent.
//!
//! Per-artifact keys are also the shape selective disclosure needs later: one
//! epoch can be handed to an auditor without handing over the chain.
//!
//! # Compatible in both directions
//!
//! Sealed files carry a magic prefix. A reader opens what is sealed and passes
//! through what is not, so a keyed publisher and an unkeyed one can be rolled
//! out in either order — unlike a `STATE_VERSION` bump (§71.34), this does not
//! have to be a coordinated replacement.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Marks a sealed artifact. Chosen to be something no plaintext artifact
/// begins with: `Saved`, `Published` and the journal all start with their own
/// magic, and none of them is this.
pub const SEALED_MAGIC: &[u8; 8] = b"ZYNSEAL\x01";

const SALT: &[u8] = b"zyn.da.v1";

/// Whether these bytes were produced by [`seal`].
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= SEALED_MAGIC.len() && &bytes[..SEALED_MAGIC.len()] == SEALED_MAGIC
}

/// The label an artifact is sealed under, from its bundle-relative path.
///
/// Derived from the path rather than passed alongside it, so a file cannot be
/// opened under a label other than the one it was written for — moving
/// `chain-11/40/intents/epoch-7.intents` to another epoch's directory makes it
/// undecryptable instead of silently valid.
pub fn label_for(rel: &str) -> String {
    rel.to_string()
}

fn key_for(root: &[u8; 32], chain: u32, label: &str) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(SALT), root);
    let mut info = Vec::with_capacity(4 + label.len());
    info.extend_from_slice(&chain.to_be_bytes());
    info.extend_from_slice(label.as_bytes());
    let mut out = [0u8; 32];
    // Only fails for an absurd output length, which 32 is not.
    hk.expand(&info, &mut out).expect("hkdf output length");
    *Key::from_slice(&out)
}

/// The all-zero nonce, which is safe here precisely because the key is never
/// reused across artifacts. See the module note.
fn nonce() -> Nonce {
    *Nonce::from_slice(&[0u8; 12])
}

/// Encrypt one artifact under its own derived key.
pub fn seal(root: &[u8; 32], chain: u32, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(&key_for(root, chain, label));
    let ct = cipher
        .encrypt(&nonce(), plaintext)
        .map_err(|_| "cannot seal this artifact".to_string())?;
    let mut out = Vec::with_capacity(SEALED_MAGIC.len() + ct.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt one artifact. Bytes that are not sealed are returned unchanged, so
/// a reader with a key can still read a bundle published without one.
pub fn open(root: &[u8; 32], chain: u32, label: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if !is_sealed(bytes) {
        return Ok(bytes.to_vec());
    }
    let cipher = ChaCha20Poly1305::new(&key_for(root, chain, label));
    cipher
        .decrypt(&nonce(), &bytes[SEALED_MAGIC.len()..])
        .map_err(|_| {
            format!("cannot open {label}: wrong data-availability key, or the file was altered")
        })
}

/// Whether a bundle-relative path names an artifact that carries ownership.
///
/// The allowlist is inverted on purpose: anything not recognised as a public
/// commitment is treated as confidential. A new artifact added later is then
/// sealed by default rather than published by default, which is the direction
/// a mistake should fall in.
pub fn is_confidential(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    !matches!(name, "anchor.bin" | "certificate.bin" | "published.bin" | "index")
}

/// Read a root key from its hex form.
pub fn key_from_hex(text: &str) -> Result<[u8; 32], String> {
    let t = text.trim();
    if t.len() != 64 {
        return Err("a data-availability key is 32 bytes (64 hex characters)".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)
            .map_err(|_| "a data-availability key must be hex".to_string())?;
    }
    if out == [0u8; 32] {
        return Err("the all-zero data-availability key is not a key".into());
    }
    Ok(out)
}

/// A [`crate::replica::Fetch`] that opens sealed artifacts on the way out.
///
/// The seam is deliberate: the replica asks for a path and receives plaintext,
/// so nothing downstream of here knows whether the bundle it verified was
/// encrypted at rest.
pub struct Opening<F: crate::replica::Fetch> {
    pub inner: F,
    /// `None` is a reader with no key, which is not the same as a reader with
    /// a zero key: it passes plaintext through and says plainly that it cannot
    /// read a sealed file, rather than failing as though the key were wrong.
    pub key: Option<[u8; 32]>,
    pub chain: u32,
}

impl<F: crate::replica::Fetch> crate::replica::Fetch for Opening<F> {
    fn get(&self, rel: &str) -> Result<Vec<u8>, String> {
        let bytes = self.inner.get(rel)?;
        match (&self.key, is_sealed(&bytes)) {
            (Some(k), _) => open(k, self.chain, &label_for(rel), &bytes),
            (None, false) => Ok(bytes),
            (None, true) => Err(format!(
                "{rel} is sealed and this verifier has no ZYN_DA_KEY — ask the operator for one, or verify roots only"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 32] = [7u8; 32];

    #[test]
    fn a_sealed_artifact_opens_to_exactly_what_went_in() {
        let plain = b"epoch 42 journal bytes".to_vec();
        let sealed = seal(&ROOT, 11, "chain-11/40/intents/epoch-42.intents", &plain).unwrap();
        assert!(is_sealed(&sealed));
        assert!(!sealed.windows(6).any(|w| w == b"journa"), "no plaintext survives");
        let out = open(&ROOT, 11, "chain-11/40/intents/epoch-42.intents", &sealed).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn sealing_is_deterministic_so_a_republish_is_idempotent() {
        let a = seal(&ROOT, 11, "x", b"same").unwrap();
        let b = seal(&ROOT, 11, "x", b"same").unwrap();
        assert_eq!(a, b);
    }

    /// The label is derived from the path, so a file moved to another epoch's
    /// directory fails to open rather than opening as though it belonged there.
    #[test]
    fn an_artifact_cannot_be_opened_under_another_label() {
        let sealed = seal(&ROOT, 11, "chain-11/40/intents/epoch-42.intents", b"x").unwrap();
        assert!(open(&ROOT, 11, "chain-11/41/intents/epoch-43.intents", &sealed).is_err());
    }

    #[test]
    fn another_chain_or_another_key_cannot_open_it() {
        let sealed = seal(&ROOT, 11, "a", b"x").unwrap();
        assert!(open(&ROOT, 26460, "a", &sealed).is_err());
        assert!(open(&[8u8; 32], 11, "a", &sealed).is_err());
    }

    #[test]
    fn a_tampered_artifact_is_refused_rather_than_returned() {
        let mut sealed = seal(&ROOT, 11, "a", b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(&ROOT, 11, "a", &sealed).is_err());
    }

    /// Both directions of a rollout: an unkeyed bundle stays readable by a
    /// keyed reader, so publisher and replicas need not move together.
    #[test]
    fn plaintext_passes_through_a_reader_that_has_a_key() {
        let plain = b"published without a key".to_vec();
        assert_eq!(open(&ROOT, 11, "a", &plain).unwrap(), plain);
    }

    /// Anything not recognised as a public commitment is confidential, so an
    /// artifact added later is sealed by default rather than exposed.
    #[test]
    fn only_the_named_public_commitments_are_public() {
        for public in [
            "chain-11/40/anchor.bin",
            "chain-11/40/certificate.bin",
            "chain-11/40/published.bin",
            "chain-11/index",
        ] {
            assert!(!is_confidential(public), "{public}");
        }
        for secret in [
            "chain-11/40/intents/epoch-42.intents",
            "chain-11/base.state",
            "chain-11/40/something-invented-next-year.bin",
        ] {
            assert!(is_confidential(secret), "{secret}");
        }
    }

    /// A reader with no key is not a reader with a wrong key. It must pass
    /// plaintext through and name the missing key when it meets ciphertext,
    /// because those two failures have completely different fixes.
    #[test]
    fn a_reader_without_a_key_says_so_rather_than_failing_obscurely() {
        use crate::replica::Fetch;
        struct Fixed(Vec<u8>);
        impl Fetch for Fixed {
            fn get(&self, _: &str) -> Result<Vec<u8>, String> {
                Ok(self.0.clone())
            }
        }
        let sealed = seal(&ROOT, 11, "chain-11/base.state", b"holdings").unwrap();

        let blind = Opening { inner: Fixed(sealed.clone()), key: None, chain: 11 };
        let e = blind.get("chain-11/base.state").unwrap_err();
        assert!(e.contains("ZYN_DA_KEY"), "{e}");

        let keyed = Opening { inner: Fixed(sealed), key: Some(ROOT), chain: 11 };
        assert_eq!(keyed.get("chain-11/base.state").unwrap(), b"holdings");

        let plain = Opening { inner: Fixed(b"clear".to_vec()), key: None, chain: 11 };
        assert_eq!(plain.get("chain-11/anchor.bin").unwrap(), b"clear");
    }

    #[test]
    fn a_key_must_be_thirty_two_nonzero_bytes_of_hex() {
        assert!(key_from_hex(&"ab".repeat(32)).is_ok());
        assert!(key_from_hex("00").is_err());
        assert!(key_from_hex(&"00".repeat(32)).is_err());
        assert!(key_from_hex(&"zz".repeat(32)).is_err());
    }
}
