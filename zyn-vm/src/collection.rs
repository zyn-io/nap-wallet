//! Item collections — non-fungibles that do not cost state per item.
//!
//! # Why there is no "NFT" in this crate
//!
//! Two of the three VMs worth learning from decline to make NFTs special.
//! Solana's SPL token is a mint with supply 1 and zero decimals; "NFT-ness"
//! lives in Metaplex, a *convention* addressed by PDA, not in the token
//! program. Sui has no NFT type at all — an NFT is any owned object with `key`,
//! and fungibility is emergent from whether a type can merge and split.
//! Ethereum went the other way with ERC-721, and got a dedicated interface plus
//! an approval surface plus `tokenURI` link rot.
//!
//! Zyn follows the majority, and for a stronger reason than precedent: an ERC
//! is an interface *between contracts*, and Zyn has no contracts calling each
//! other. There is nothing to standardise in that sense. What genuinely needs
//! standardising is the **state shape**, because the settlement verifier and
//! the exit hatch have to understand it — and that is what this module is.
//!
//! # The scaling problem this exists to solve
//!
//! A distinct asset costs a token entry, committed in the state root and
//! therefore paid for in every proof and every guest execution, forever. A
//! 10,000-item collection issued that way is 10,000 entries. A million-item
//! collection is not survivable.
//!
//! Solana hit this exact wall and answered with state compression: put the
//! items in a Merkle tree, keep only the root on chain, publish the leaves
//! where anyone can rebuild them. That is how a million NFTs cost cents.
//!
//! Zyn already has both halves. The state root is Merkle sections, and
//! [`crate::spec::Provable`] plus the microchain's data-availability layer
//! already publish leaves so a holder can prove one without the sequencer. A
//! compressed collection is the same construction pointed at items instead of
//! accounts:
//!
//! ```text
//!   1 collection  ==  32 bytes of state,  whether it holds 10 items or 10^7
//!   1 item proof  ==  log2(n) hashes,     verified against an anchored root
//! ```
//!
//! # The honest cost
//!
//! Item ownership lives in the collection tree, not in an account's balances.
//! So "I own item X" and "I hold N xZEC" are **two different proof paths**, and
//! a wallet needs the published leaves to build the first. That is the same
//! trade Solana made — it is why compressed NFTs need an indexer — and it is
//! worth paying only because the alternative does not scale. For a small
//! collection, indivisible fungible assets (`TokenInfo::unit == ONE`) stay
//! simpler and keep everything in one leaf.
//!
//! # Metadata
//!
//! A leaf commits `H(content)`, never the content. ERC-721 stores a `tokenURI`
//! string on chain: a mutable pointer to a resource that can change or vanish
//! underneath the token. A content hash is immutable and checkable, and the
//! bytes live wherever they are cheapest.

use alloc::vec::Vec;

use crate::commit::{hash_node, merkle_proof, merkle_root, Encoder, Hash, ProofStep};
use crate::derive::Address;
use crate::spec::AccountId;

/// An item's identity within its collection. 32 bytes, so it can be derived
/// (see [`crate::derive`]) rather than allocated from a counter.
pub type ItemId = [u8; 32];

/// One item, as committed.
///
/// Three fields and no more: identity, owner, and a commitment to whatever the
/// item *is*. Anything else an application wants belongs behind `content`,
/// where it costs no consensus.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Item {
    pub id: ItemId,
    pub owner: AccountId,
    /// `H(metadata)`. The bytes live in data availability or off-chain; only
    /// the commitment is consensus.
    pub content: Hash,
}

/// The committed leaf for one item.
///
/// The collection address is inside the leaf, so an item proved against one
/// collection's root cannot be replayed against another's — the analogue of
/// binding a signature to a chain id.
pub fn item_leaf(collection: &Address, item: &Item) -> Hash {
    let mut e = Encoder::new();
    e.bytes(b"zyn.item.v1")
        .bytes(collection)
        .bytes(&item.id)
        .bytes(&item.owner)
        .bytes(&item.content);
    e.leaf()
}

/// The root over a collection.
///
/// Items MUST be sorted by id. Ordering comes from the data, not from the
/// order things were minted, so two nodes that hold the same collection agree —
/// the same rule the account tree follows.
pub fn collection_root(collection: &Address, items: &[Item]) -> Option<Hash> {
    if items.windows(2).any(|w| w[0].id >= w[1].id) {
        return None;
    }
    let leaves: Vec<Hash> = items.iter().map(|i| item_leaf(collection, i)).collect();
    Some(merkle_root(&leaves))
}

/// An inclusion path for one item.
pub fn item_proof(
    collection: &Address,
    items: &[Item],
    id: &ItemId,
) -> Option<(Hash, Vec<ProofStep>)> {
    let index = items.iter().position(|i| &i.id == id)?;
    let leaves: Vec<Hash> = items.iter().map(|i| item_leaf(collection, i)).collect();
    Some((leaves[index], merkle_proof(&leaves, index)))
}

/// Whether `item` is committed by `root`.
pub fn verify_item(collection: &Address, item: &Item, path: &[ProofStep], root: Hash) -> bool {
    root_from(item_leaf(collection, item), path) == root
}

/// Recompute a root from a leaf and its path.
///
/// The operation that makes a compressed collection affordable to *update*, not
/// merely to commit. Rebuilding the whole tree on every transfer would be
/// O(n log n) per intent, which defeats the point; with the path already in
/// hand, a new root is log(n) hashes.
///
/// A VM holding a large collection keeps the paths it needs (or has the caller
/// supply them, as Solana does) rather than the whole tree.
pub fn root_from(leaf: Hash, path: &[ProofStep]) -> Hash {
    let mut node = leaf;
    for step in path {
        node = if step.node_is_right {
            hash_node(&step.sibling, &node)
        } else {
            hash_node(&node, &step.sibling)
        };
    }
    node
}

/// The root after `item` changes hands, given the old item's path.
///
/// Returns `None` if the supplied path does not actually open `old` under
/// `root` — a transfer must never be applied against a path for some other
/// item, which is the one way a compressed collection can be corrupted.
pub fn transfer_item(
    collection: &Address,
    old: &Item,
    new_owner: AccountId,
    path: &[ProofStep],
    root: Hash,
) -> Option<(Item, Hash)> {
    if !verify_item(collection, old, path, root) {
        return None;
    }
    let moved = Item {
        owner: new_owner,
        ..*old
    };
    Some((moved, root_from(item_leaf(collection, &moved), path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::derive;

    fn collection() -> Address {
        derive(b"zynmarket", b"collection", &[b"cats"])
    }

    fn items(n: u32) -> Vec<Item> {
        let mut v: Vec<Item> = (0..n)
            .map(|i| {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&i.to_be_bytes());
                let mut owner = [0u8; 32];
                owner[0] = (i % 251) as u8;
                let mut content = [0u8; 32];
                content[..4].copy_from_slice(&(i * 7).to_be_bytes());
                Item { id, owner, content }
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn a_collection_of_any_size_costs_one_hash_of_state() {
        // The whole argument for compression, stated as a test.
        let c = collection();
        let small = collection_root(&c, &items(4)).unwrap();
        let large = collection_root(&c, &items(10_000)).unwrap();
        assert_eq!(small.len(), 32);
        assert_eq!(large.len(), 32);
        assert_ne!(small, large);
    }

    #[test]
    fn an_item_proof_is_logarithmic_not_linear() {
        let c = collection();
        let set = items(4_096);
        let (_, path) = item_proof(&c, &set, &set[1_234].id).unwrap();
        // 2^12 leaves, so twelve siblings — not four thousand.
        assert_eq!(path.len(), 12, "proof was not log2(n)");
    }

    #[test]
    fn every_item_proves_against_the_collection_root() {
        let c = collection();
        for n in [1usize, 2, 3, 7, 8, 33, 64] {
            let set = items(n as u32);
            let root = collection_root(&c, &set).unwrap();
            for it in &set {
                let (_, path) = item_proof(&c, &set, &it.id).expect("provable");
                assert!(verify_item(&c, it, &path, root), "size {} item failed", n);
            }
        }
    }

    /// An item is bound to its collection, so a proof cannot be carried across
    /// one — the same binding a signature needs to a chain id.
    #[test]
    fn an_item_cannot_be_replayed_into_another_collection() {
        let a = collection();
        let b = derive(b"zynmarket", b"collection", &[b"dogs"]);
        let set = items(8);
        let root_a = collection_root(&a, &set).unwrap();
        let (_, path) = item_proof(&a, &set, &set[3].id).unwrap();

        assert!(verify_item(&a, &set[3], &path, root_a));
        assert!(
            !verify_item(&b, &set[3], &path, root_a),
            "an item crossed collections"
        );
        assert_ne!(collection_root(&b, &set).unwrap(), root_a);
    }

    #[test]
    fn ownership_and_content_are_both_committed() {
        let c = collection();
        let set = items(8);
        let root = collection_root(&c, &set).unwrap();
        let (_, path) = item_proof(&c, &set, &set[2].id).unwrap();

        let mut relabelled = set[2];
        relabelled.owner = [0xEE; 32];
        assert!(
            !verify_item(&c, &relabelled, &path, root),
            "owner was not committed"
        );

        let mut rewritten = set[2];
        rewritten.content = [0xEE; 32];
        assert!(
            !verify_item(&c, &rewritten, &path, root),
            "content was not committed"
        );
    }

    /// A transfer is one leaf change, so the new root costs log(n) hashes —
    /// not a rebuild. This is what makes a large collection affordable to use
    /// rather than merely to commit.
    #[test]
    fn a_transfer_updates_the_root_without_rebuilding_the_tree() {
        let c = collection();
        let mut set = items(1_024);
        let root = collection_root(&c, &set).unwrap();
        let (_, path) = item_proof(&c, &set, &set[500].id).unwrap();

        let (moved, new_root) =
            transfer_item(&c, &set[500], [0x77; 32], &path, root).expect("valid transfer");
        assert_eq!(moved.owner, [0x77; 32]);
        assert_eq!(
            moved.id, set[500].id,
            "a transfer changed the item's identity"
        );
        assert_ne!(new_root, root);

        // The incrementally computed root is exactly the rebuilt one.
        set[500] = moved;
        assert_eq!(collection_root(&c, &set).unwrap(), new_root);
        // And the new owner can prove it.
        let (_, fresh) = item_proof(&c, &set, &moved.id).unwrap();
        assert!(verify_item(&c, &moved, &fresh, new_root));
    }

    /// The one way a compressed collection can be corrupted: applying a
    /// transfer against a path that does not open the item being moved.
    #[test]
    fn a_transfer_against_a_foreign_path_is_refused() {
        let c = collection();
        let set = items(64);
        let root = collection_root(&c, &set).unwrap();
        let (_, wrong_path) = item_proof(&c, &set, &set[9].id).unwrap();

        assert!(
            transfer_item(&c, &set[10], [0x77; 32], &wrong_path, root).is_none(),
            "an item was moved using another item's path"
        );
        // And a stale root is refused too.
        let (_, path) = item_proof(&c, &set, &set[10].id).unwrap();
        assert!(transfer_item(&c, &set[10], [0x77; 32], &path, [0xAB; 32]).is_none());
    }

    /// Ordering comes from the ids, not from mint order, so two nodes holding
    /// the same collection agree — the rule the account tree already follows.
    #[test]
    fn the_root_does_not_depend_on_mint_order() {
        let c = collection();
        let set = items(16);
        let mut shuffled = set.clone();
        shuffled.swap(2, 11);
        // Out of order is refused rather than silently re-sorted, so a
        // publisher cannot hand over a different tree and call it the same one.
        assert!(collection_root(&c, &shuffled).is_none());
        shuffled.sort();
        assert_eq!(
            collection_root(&c, &shuffled).unwrap(),
            collection_root(&c, &set).unwrap()
        );
    }

    #[test]
    fn an_empty_collection_has_a_root_and_no_items() {
        let c = collection();
        assert_eq!(collection_root(&c, &[]).unwrap(), [0u8; 32]);
        assert!(item_proof(&c, &[], &[1u8; 32]).is_none());
    }
}
