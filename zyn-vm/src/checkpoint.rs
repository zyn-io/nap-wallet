//! What one epoch commits.
//!
//! The unit of settlement. A microchain runs continuously and settles rarely;
//! a checkpoint is the boundary between the two, and it is the same shape for
//! every Zyn VM — a swap, an auction, a game — because the settlement path,
//! the anchoring rules and the exit hatch are shared infrastructure and must
//! not be re-specified per application.
//!
//! The five fields the project plan requires of a Zcash checkpoint are here:
//! microchain id, epoch number, previous state root, new state root, and the
//! transaction/data commitment. The rest say how much history the roots span
//! and what the epoch carried, so a reader can check a compression claim rather
//! than take it.

use crate::commit::Hash;
use crate::fixed::Fixed;

/// One sealed epoch.
///
/// `state_root` is the root **before** the epoch advances, so a replayer who
/// stops at `seq` computes exactly the value that was signed. The advance then
/// writes that root into the next epoch's `parent_root`, which is what chains
/// one checkpoint to the next: epoch N commits root A, epoch N+1 declares A as
/// its parent, and a verifier walks the lineage without trusting the
/// sequencer's account of it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Checkpoint {
    pub chain_id: u32,
    pub epoch: u64,
    pub parent_root: Hash,
    pub state_root: Hash,
    /// Commitment to the ordered intents this epoch applied — a hash chain, so
    /// a checkpoint fixes not only where execution ended but which inputs took
    /// it there.
    pub intent_root: Hash,
    /// Last sequence number included.
    pub seq: u64,
    /// Intents this epoch applied, rejections included. The numerator of the
    /// compression ratio: microchain actions per Zcash settlement.
    pub intents: u64,
    /// Value the epoch moved, in the chain's settlement asset.
    ///
    /// Application-defined in meaning but not in placement: every VM reports
    /// one figure here, so the infrastructure can total activity across
    /// microchains it does not otherwise understand. A VM with no natural
    /// notion of volume reports zero.
    pub gross_volume: Fixed,
}

impl Checkpoint {
    /// Whether `self` legitimately follows `prev` in the same chain.
    ///
    /// The epoch-level counterpart to the anchor lineage rules: a successor
    /// must be the same chain, advance the epoch, advance the sequence, and
    /// name its predecessor's root.
    pub fn follows(&self, prev: &Checkpoint) -> bool {
        self.chain_id == prev.chain_id
            && self.epoch == prev.epoch + 1
            && self.seq > prev.seq
            && self.parent_root == prev.state_root
    }

    /// Whether this is the first checkpoint of a chain.
    pub fn is_genesis(&self) -> bool {
        self.epoch == 0 && self.parent_root == [0u8; 32]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(epoch: u64, seq: u64, parent: u8, state: u8) -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            epoch,
            parent_root: [parent; 32],
            state_root: [state; 32],
            intent_root: [9u8; 32],
            seq,
            intents: 10,
            gross_volume: Fixed::ZERO,
        }
    }

    #[test]
    fn a_successor_must_name_its_parent_root() {
        let a = cp(0, 100, 0, 5);
        assert!(a.is_genesis());
        assert!(cp(1, 200, 5, 7).follows(&a));
        // A successor that names a root its parent never reached is not a
        // successor, it is a second history.
        assert!(!cp(1, 200, 6, 7).follows(&a));
    }

    #[test]
    fn epochs_and_sequences_must_both_advance() {
        let a = cp(3, 100, 0, 5);
        assert!(!cp(3, 200, 5, 7).follows(&a), "the epoch did not advance");
        assert!(!cp(5, 200, 5, 7).follows(&a), "an epoch was skipped");
        assert!(!cp(4, 100, 5, 7).follows(&a), "the sequence covered no new history");
        assert!(cp(4, 101, 5, 7).follows(&a));
    }

    #[test]
    fn a_checkpoint_from_another_chain_never_follows() {
        let a = cp(0, 100, 0, 5);
        let mut b = cp(1, 200, 5, 7);
        b.chain_id = 2;
        assert!(!b.follows(&a));
    }
}
