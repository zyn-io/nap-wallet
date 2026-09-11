//! The replay index: a signature is applied once.
//!
//! An intent's authorisation bounds *when* it may be applied (an epoch
//! window, `zyn_vm::auth`), not *how many times*. Inside the window nothing
//! stopped a captured signed intent from being submitted again — and a
//! forced intent, which legitimately arrives by two routes, made that
//! ordinary rather than adversarial. This index closes it: the hash of the
//! signature is remembered until the authorisation expires, and a second
//! sight of it is refused.
//!
//! Kept beside the state, saved with it. Losing it is not a safety hole for
//! the chain's *history* — replay verification does not need it — but it is
//! for the holder whose intent could be applied twice, so it is persisted.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"ZYNRPLY1";

#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct ReplayIndex {
    /// `key -> last epoch in which the intent may be applied`.
    seen: BTreeMap<[u8; 32], u64>,
}

/// What a signature is remembered as: domain-separated, scheme-bound.
pub fn key(scheme: u8, signature: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zyn.replay.v1");
    h.update([scheme]);
    h.update(signature);
    h.finalize().into()
}

impl ReplayIndex {
    /// Record a signature. `true` the first time; `false` if it was already
    /// seen and has not expired — the caller refuses the intent.
    pub fn fresh(&mut self, k: [u8; 32], valid_until_epoch: u64) -> bool {
        if self.seen.contains_key(&k) {
            return false;
        }
        self.seen.insert(k, valid_until_epoch);
        true
    }

    /// Forget what can no longer be replayed: an authorisation past its epoch
    /// is refused by the VM's own envelope check.
    pub fn prune(&mut self, current_epoch: u64) {
        self.seen.retain(|_, until| *until >= current_epoch);
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.seen.len() * 40);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.seen.len() as u32).to_be_bytes());
        for (k, u) in &self.seen {
            out.extend_from_slice(k);
            out.extend_from_slice(&u.to_be_bytes());
        }
        out
    }

    pub fn decode(b: &[u8]) -> Option<ReplayIndex> {
        if b.len() < 12 || &b[..8] != MAGIC {
            return None;
        }
        let n = u32::from_be_bytes(b[8..12].try_into().ok()?) as usize;
        if b.len() != 12 + n * 40 {
            return None;
        }
        let mut seen = BTreeMap::new();
        for i in 0..n {
            let p = 12 + i * 40;
            let k: [u8; 32] = b[p..p + 32].try_into().ok()?;
            let u = u64::from_be_bytes(b[p + 32..p + 40].try_into().ok()?);
            seen.insert(k, u);
        }
        Some(ReplayIndex { seen })
    }

    fn path(dir: &Path, chain_id: u32) -> PathBuf {
        dir.join(format!("replay-{}.idx", chain_id))
    }

    pub fn load(dir: &Path, chain_id: u32) -> Result<ReplayIndex, String> {
        match std::fs::read(Self::path(dir, chain_id)) {
            Ok(b) => ReplayIndex::decode(&b).ok_or_else(|| "replay index is corrupt; refusing to guess".to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ReplayIndex::default()),
            Err(e) => Err(format!("cannot read the replay index: {}", e)),
        }
    }

    pub fn save(&self, dir: &Path, chain_id: u32) -> Result<(), String> {
        let tmp = dir.join(format!(".replay-{}.tmp", chain_id));
        std::fs::write(&tmp, self.encode()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, Self::path(dir, chain_id)).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_is_fresh_once_until_it_expires() {
        let mut r = ReplayIndex::default();
        let k = key(1, &[7u8; 64]);
        assert!(r.fresh(k, 10));
        assert!(!r.fresh(k, 10), "the same signature again is a replay");
        assert_ne!(key(1, &[7u8; 64]), key(2, &[7u8; 64]), "scheme-bound");
        r.prune(10);
        assert_eq!(r.len(), 1, "still valid in epoch 10");
        r.prune(11);
        assert!(r.is_empty(), "expired authorisations are forgotten");
        assert!(r.fresh(k, 20), "and the VM's envelope would refuse it anyway");
    }

    #[test]
    fn the_index_round_trips_and_refuses_junk() {
        let mut r = ReplayIndex::default();
        r.fresh(key(1, b"a"), 3);
        r.fresh(key(1, b"b"), 9);
        assert_eq!(ReplayIndex::decode(&r.encode()), Some(r.clone()));
        assert!(ReplayIndex::decode(b"junk").is_none());
        let mut short = r.encode();
        short.pop();
        assert!(ReplayIndex::decode(&short).is_none());
        let dir = std::env::temp_dir().join(format!("zyn-replay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        r.save(&dir, 4).unwrap();
        assert_eq!(ReplayIndex::load(&dir, 4).unwrap(), r);
        assert_eq!(ReplayIndex::load(&dir, 5).unwrap(), ReplayIndex::default());
    }
}
