//! A holder's exit proof, kept where the holder can reach it.
//!
//! `da.rs` designs for this: a holder who kept their own record and path
//! needs no snapshot at the moment of exit. This is that file — the record,
//! its leaf index, the sibling hashes up to the anchored root, and which
//! anchor the root belongs to. Kilobytes, refreshed at every anchor, and
//! enough to leave with the sequencer gone and every mirror dark.

use serde_json::{json, Value};
use swapvm::state::SwapState;
use zyn_vm::commit::ProofStep;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExitProof {
    pub chain_id: u32,
    /// The epoch the anchor sealed.
    pub epoch: u64,
    /// The anchored state root the path opens.
    pub root: [u8; 32],
    /// The record in the VM's own encoding — what the leaf hashes.
    pub record: Vec<u8>,
    pub index: u32,
    pub path: Vec<ProofStep>,
    /// When it was fetched, seconds since the epoch, for the human.
    pub fetched_at: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

impl ExitProof {
    /// Whether the record and path really open the root — the check anyone
    /// can run, including the holder before they rely on it.
    pub fn verify(&self) -> bool {
        zyn::verify_record::<SwapState>(&self.record, &self.path, self.root)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "format": "zyn.exit-proof.v1",
            "chain_id": self.chain_id,
            "epoch": self.epoch,
            "root": hex(&self.root),
            "record": hex(&self.record),
            "index": self.index,
            "path": self.path.iter().map(|s| json!({ "sibling": hex(&s.sibling), "right": s.node_is_right })).collect::<Vec<_>>(),
            "fetched_at": self.fetched_at,
        })
    }

    pub fn from_json(v: &Value) -> Option<ExitProof> {
        if v.get("format")?.as_str()? != "zyn.exit-proof.v1" {
            return None;
        }
        let mut path = Vec::new();
        for s in v.get("path")?.as_array()? {
            path.push(ProofStep {
                sibling: unhex(s.get("sibling")?.as_str()?)?.try_into().ok()?,
                node_is_right: s.get("right")?.as_bool()?,
            });
        }
        Some(ExitProof {
            chain_id: v.get("chain_id")?.as_u64()? as u32,
            epoch: v.get("epoch")?.as_u64()?,
            root: unhex(v.get("root")?.as_str()?)?.try_into().ok()?,
            record: unhex(v.get("record")?.as_str()?)?,
            index: v.get("index")?.as_u64()? as u32,
            path,
            fetched_at: v.get("fetched_at").and_then(Value::as_u64).unwrap_or(0),
        })
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), String> {
        std::fs::write(
            path,
            serde_json::to_string_pretty(&self.to_json()).unwrap_or_default(),
        )
        .map_err(|e| e.to_string())
    }

    pub fn load(path: &std::path::Path) -> Option<ExitProof> {
        let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        ExitProof::from_json(&v)
    }
}

/// Fetch again when the chain has anchored past what is kept.
pub fn should_refresh(kept: Option<u64>, anchored_epoch: u64, has_anchor: bool) -> bool {
    has_anchor && kept.map(|k| anchored_epoch > k).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::tx::Intent;
    use swapvm::types::XZEC;
    use swapvm::{Fixed, Params};
    use zyn::da::Snapshot;
    use zyn_vm::spec::MicrochainVm;

    #[test]
    fn a_proof_round_trips_through_json_and_still_verifies() {
        let mut s = SwapState::new(6, Params::v1());
        let observed = s.backing_of(XZEC).add(Fixed::whole(10)).unwrap();
        s.apply(
            1,
            &Intent::AttestVaultBalance {
                asset: XZEC,
                observed,
            },
        );
        for i in 0..5u8 {
            let d = Intent::next_deposit(&s, [i + 1; 32], XZEC, Fixed::whole(1), [0u8; 32]);
            s.apply(2 + i as u64, &d);
        }
        let snap = Snapshot::of(&s);
        let (record, index, path) = snap.record_proof(&[3u8; 32]).unwrap();
        let p = ExitProof {
            chain_id: 6,
            epoch: 0,
            root: snap.root,
            record,
            index,
            path,
            fetched_at: 7,
        };
        assert!(p.verify());
        let back = ExitProof::from_json(&p.to_json()).unwrap();
        assert_eq!(back, p);
        let mut bad = back.clone();
        bad.record[0] ^= 1;
        assert!(!bad.verify());
        let mut wrong_root = back;
        wrong_root.root[0] ^= 1;
        assert!(!wrong_root.verify());
        assert!(ExitProof::from_json(&json!({ "format": "other" })).is_none());
    }

    #[test]
    fn refresh_only_when_the_chain_anchored_past_what_is_kept() {
        assert!(
            !should_refresh(None, 0, false),
            "nothing anchored yet: nothing to fetch"
        );
        assert!(should_refresh(None, 0, true));
        assert!(!should_refresh(Some(4), 4, true));
        assert!(should_refresh(Some(4), 5, true));
    }
}
