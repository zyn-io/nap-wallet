//! What an item *is*, as committed bytes.
//!
//! [`crate::collection::Item::content`] is `H(manifest)` — 32 bytes on chain,
//! standing for a description of arbitrary size. This module defines what is
//! hashed, so that two builders given the same facts produce the same 32 bytes
//! and a wallet can check that what it was handed is what was committed.
//!
//! # There is no URL in here, and that is the point
//!
//! ERC-721 puts a `tokenURI` on chain: a mutable pointer to a resource that can
//! change or vanish underneath the token. Putting a URL inside a *hashed*
//! manifest is worse, not better — it makes the location immutable, so the
//! collection dies with the domain and nothing can ever be re-hosted.
//!
//! So a manifest names media by **hash and nothing else**. Where the bytes live
//! is a hint held outside consensus, per collection, replaceable at any time.
//! A gateway serves objects keyed by their own hash:
//!
//! ```text
//!   GET {gateway}/{sha256}
//! ```
//!
//! which makes the gateway a dumb blob store: identical bytes deduplicate,
//! anyone may mirror it, and moving providers touches no token. A wrong or
//! hostile gateway is *detected* rather than trusted, because the hash is
//! checked before the bytes are used — see [`verify_media`].
//!
//! # Size
//!
//! Consensus carries 32 bytes whether the media is a 40 KB PNG or a 4 GB film.
//! There is no size cap to be limited by, because size never enters the chain.
//!
//! # Preview and full, and what ownership actually means
//!
//! A manifest may commit both a public `Preview` and the `Full` media. That
//! supports browsing a collection without fetching the real thing, and lets a
//! wallet render something before the full file has arrived.
//!
//! It does **not** make the full media secret. The bytes are public and any
//! holder may republish them; the first owner always can. Ownership is the
//! chain record, never possession of bytes — which is the honest position, and
//! the same one the content hash already takes: it is a commitment, not a
//! secret. A watermark on a public copy is a courtesy, not a control.

use alloc::string::String;
use alloc::vec::Vec;

use crate::commit::{Encoder, Hash};

/// What a piece of media is for.
///
/// A byte on the wire, so the ordering the canonical form depends on cannot
/// drift with a refactor.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum MediaRole {
    /// The item itself.
    Full = 0,
    /// A public, cheap stand-in: a thumbnail, a low-rate clip, a watermarked
    /// copy. Committed so that it, too, can be checked rather than trusted.
    Preview = 1,
}

/// One piece of media, named by hash.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Media {
    pub role: MediaRole,
    /// SHA-256 of the exact bytes. The only name this file has.
    pub sha256: Hash,
    /// IANA media type, so a wallet knows what it is holding before it decodes
    /// it — `image/png`, `image/gif`, `video/mp4`.
    pub mime: String,
    pub bytes: u64,
    /// Zero where the concept does not apply (audio has no width).
    pub width: u32,
    pub height: u32,
    /// Zero for a still.
    pub duration_ms: u32,
}

/// One trait.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Attribute {
    pub trait_type: String,
    pub value: String,
}

/// Everything an item claims about itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    pub name: String,
    pub description: String,
    pub media: Vec<Media>,
    pub attributes: Vec<Attribute>,
}

/// The domain tag, so a manifest hash can never collide with an item leaf, a
/// derived address, or an internal node.
const MANIFEST_DOMAIN: &[u8] = b"zyn.manifest.v1";

impl Manifest {
    /// The committed 32 bytes — what goes in `Item::content`.
    ///
    /// Media and attributes are **sorted** before hashing rather than taken in
    /// the order they were supplied. Ordering comes from the data, so two
    /// builders that know the same facts agree without having to agree on a
    /// convention as well. Every variable-length field is length-prefixed, so
    /// no regrouping of the same bytes produces the same preimage.
    pub fn content(&self) -> Hash {
        let mut media = self.media.clone();
        media.sort_by(|a, b| (a.role, a.sha256).cmp(&(b.role, b.sha256)));
        let mut attrs = self.attributes.clone();
        attrs.sort();

        let mut e = Encoder::new();
        e.bytes(MANIFEST_DOMAIN);
        put_str(&mut e, &self.name);
        put_str(&mut e, &self.description);
        e.u32(media.len() as u32);
        for m in &media {
            e.u8(m.role as u8);
            e.bytes(&m.sha256);
            put_str(&mut e, &m.mime);
            e.u64(m.bytes);
            e.u32(m.width);
            e.u32(m.height);
            e.u32(m.duration_ms);
        }
        e.u32(attrs.len() as u32);
        for a in &attrs {
            put_str(&mut e, &a.trait_type);
            put_str(&mut e, &a.value);
        }
        e.leaf()
    }

    /// The media for a role, if the manifest commits one.
    pub fn media_for(&self, role: MediaRole) -> Option<&Media> {
        self.media.iter().find(|m| m.role == role)
    }
}

fn put_str(e: &mut Encoder, s: &str) {
    e.u32(s.len() as u32);
    e.bytes(s.as_bytes());
}

/// Check bytes against what the manifest committed, **before** they are used.
///
/// This is what makes it safe to accept media from any gateway, a peer, a USB
/// stick, or a stranger: the source is never trusted, only the hash is. A
/// wallet that renders before calling this has no idea what it is showing.
pub fn verify_media(bytes: &[u8], media: &Media) -> bool {
    use sha2::{Digest, Sha256};
    if bytes.len() as u64 != media.bytes {
        return false;
    }
    let got: Hash = Sha256::digest(bytes).into();
    got == media.sha256
}

/// Check a manifest's own bytes against the content hash an item committed.
pub fn verify_manifest(manifest: &Manifest, content: &Hash) -> bool {
    manifest.content() == *content
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    fn media(role: MediaRole, seed: u8, len: u64) -> Media {
        Media {
            role,
            sha256: [seed; 32],
            mime: "image/png".to_string(),
            bytes: len,
            width: 128,
            height: 192,
            duration_ms: 0,
        }
    }

    fn manifest() -> Manifest {
        Manifest {
            name: "Nap Mole #001".to_string(),
            description: "A sleeping Mole.".to_string(),
            media: vec![media(MediaRole::Full, 1, 40075)],
            attributes: vec![
                Attribute { trait_type: "Species".to_string(), value: "Mole".to_string() },
                Attribute { trait_type: "Pose".to_string(), value: "Sleeping".to_string() },
            ],
        }
    }

    #[test]
    fn the_same_facts_give_the_same_commitment() {
        assert_eq!(manifest().content(), manifest().content());
    }

    /// Two builders that disagree only about order must still agree about the
    /// hash, or minting and verifying need a shared convention beyond the data.
    #[test]
    fn order_of_attributes_and_media_does_not_change_the_commitment() {
        let mut a = manifest();
        a.media.push(media(MediaRole::Preview, 9, 900));
        let mut b = a.clone();
        b.attributes.reverse();
        b.media.reverse();
        assert_eq!(a.content(), b.content());
    }

    #[test]
    fn any_changed_fact_changes_the_commitment() {
        let base = manifest().content();
        let mut m = manifest();
        m.name = "Nap Mole #002".to_string();
        assert_ne!(m.content(), base, "name");
        let mut m = manifest();
        m.media[0].sha256 = [2u8; 32];
        assert_ne!(m.content(), base, "media hash");
        let mut m = manifest();
        m.media[0].bytes = 40076;
        assert_ne!(m.content(), base, "length");
        let mut m = manifest();
        m.media[0].mime = "image/gif".to_string();
        assert_ne!(m.content(), base, "mime");
        let mut m = manifest();
        m.attributes[0].value = "Vole".to_string();
        assert_ne!(m.content(), base, "trait value");
    }

    /// Length-prefixing: moving a boundary between two adjacent strings must
    /// not produce the same preimage.
    #[test]
    fn a_boundary_between_fields_cannot_be_slid() {
        let mut a = manifest();
        a.name = "ab".to_string();
        a.description = "c".to_string();
        let mut b = manifest();
        b.name = "a".to_string();
        b.description = "bc".to_string();
        assert_ne!(a.content(), b.content());
    }

    /// The same bytes committed as a preview and as the full item are different
    /// claims, so they must commit differently.
    #[test]
    fn a_preview_is_not_the_full_item() {
        let mut a = manifest();
        a.media = vec![media(MediaRole::Full, 5, 10)];
        let mut b = manifest();
        b.media = vec![media(MediaRole::Preview, 5, 10)];
        assert_ne!(a.content(), b.content());
    }

    #[test]
    fn media_verifies_against_its_bytes_and_rejects_everything_else() {
        use sha2::{Digest, Sha256};
        let bytes = b"the actual file".to_vec();
        let m = Media {
            role: MediaRole::Full,
            sha256: Sha256::digest(&bytes).into(),
            mime: "image/png".to_string(),
            bytes: bytes.len() as u64,
            width: 1,
            height: 1,
            duration_ms: 0,
        };
        assert!(verify_media(&bytes, &m));
        assert!(!verify_media(b"the actual filf", &m), "a changed byte");
        assert!(!verify_media(b"the actual file ", &m), "a changed length");
        assert!(!verify_media(b"", &m), "nothing at all");
    }

    #[test]
    fn a_manifest_verifies_against_the_content_an_item_committed() {
        let m = manifest();
        let content = m.content();
        assert!(verify_manifest(&m, &content));
        let mut other = m.clone();
        other.description = "Something else.".to_string();
        assert!(!verify_manifest(&other, &content), "a substituted manifest is caught");
    }

    /// Cross-check against the collection builder.
    ///
    /// `apps/nap/branding/nap-mole-collection-333/build_manifests.py` prepares
    /// the 333 without needing a Rust build, so two implementations of the same
    /// encoding now exist and can drift. This pins Nap Mole #001 to the hash
    /// that builder produced. If it fails, one of the two moved and the minted
    /// `content` would no longer match the manifest anyone verifies against.
    #[test]
    fn the_nap_333_builder_agrees_with_this_encoding() {
        let m = Manifest {
            name: "Nap Mole #001".to_string(),
            description: "A sleeping Mole from the Nap early-user collection.".to_string(),
            media: vec![Media {
                role: MediaRole::Full,
                sha256: [
                    0x6d, 0x43, 0x8c, 0x2e, 0xe8, 0x69, 0x96, 0xc1, 0x34, 0x5b, 0x36, 0x4a, 0xcd,
                    0xf5, 0x3b, 0x4b, 0xd8, 0x0c, 0x00, 0xa7, 0xa8, 0xf0, 0xe9, 0xb9, 0xfc, 0x6a,
                    0x40, 0x2d, 0x71, 0x92, 0x6e, 0x8e,
                ],
                mime: "image/png".to_string(),
                bytes: 40075,
                width: 128,
                height: 192,
                duration_ms: 0,
            }],
            attributes: [
                ("Species", "Mole"),
                ("Collection", "Nap Early Users"),
                ("Pose", "Sleeping 35-degree"),
                ("Expression", "Sleeping"),
                ("Headwear", "None"),
                ("Mouth", "Friendly Smile"),
                ("Setting", "Cave"),
                ("Sleep Glyphs", "z z Z"),
            ]
            .iter()
            .map(|(t, v)| Attribute { trait_type: t.to_string(), value: v.to_string() })
            .collect(),
        };
        let hex: alloc::string::String = m.content().iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert_eq!(hex, "14ecc2918d1e4a6d0ebc129c2acfcd4b3c8fd0018c5babf838565b7fdd7080c6");
    }

    /// A 4 GB film and a 40 KB thumbnail commit to the same 32 bytes of state.
    #[test]
    fn size_never_enters_the_commitment() {
        let mut big = manifest();
        big.media = vec![Media {
            role: MediaRole::Full,
            sha256: [7u8; 32],
            mime: "video/mp4".to_string(),
            bytes: 4_000_000_000,
            width: 3840,
            height: 2160,
            duration_ms: 5_400_000,
        }];
        assert_eq!(big.content().len(), 32);
    }
}
