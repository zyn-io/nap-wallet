//! The deposit addresses this vault has handed out.
//!
//! One shielded address per account, derived from the account id
//! ([`zyn_custody::shielded::deposit_index`]). The address *is* the
//! attribution: a depositor needs no memo and no wallet feature, and a
//! verifier holding the viewing key can recompute the index from the account a
//! credit names and check the note arrived there.
//!
//! # Why this is written down at all
//!
//! The index is derived from the account, but the account cannot be derived
//! back from the index — that is the point, since otherwise anyone who saw an
//! address would learn whose it is. So the sequencer keeps the accounts it has
//! issued addresses to, and looks up the account when a note arrives.
//!
//! This register is a **convenience, not a trust root**. It decides which
//! account gets credited; it does not decide whether that credit is honest.
//! A verifier never reads it: it rederives the index from the credit and
//! compares. Losing the file costs nothing that re-issuing cannot restore.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use zcash_protocol::consensus::NetworkType;
use zyn_custody::shielded::{deposit_index, VaultKeys};
use zyn_vm::spec::AccountId;

const MAGIC: &[u8; 8] = b"ZYNADDR1";

/// The accounts that have been given a deposit address.
pub struct Book {
    path: PathBuf,
    /// Which Zcash the addresses it hands out are for. Held here so it cannot
    /// be forgotten at a call site: an address encoded for the wrong chain is
    /// one no depositor can pay.
    network: NetworkType,
    accounts: Vec<AccountId>,
    /// `index -> account`, shared with the scanner, which reads it on every
    /// pass while the RPC may be adding to it.
    index: Arc<Mutex<BTreeMap<[u8; 11], AccountId>>>,
}

impl Book {
    /// Open the register at `dir`, or start an empty one.
    pub fn open(dir: &Path, chain_id: u32, network: NetworkType) -> Result<Book, String> {
        let path = dir.join(format!("deposit-addresses-{}.bin", chain_id));
        let mut accounts = Vec::new();
        if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
                return Err(format!("{} is not a deposit address register", path.display()));
            }
            let body = &bytes[MAGIC.len()..];
            if body.len() % 32 != 0 {
                return Err(format!("{} is truncated", path.display()));
            }
            for chunk in body.chunks_exact(32) {
                let mut a = [0u8; 32];
                a.copy_from_slice(chunk);
                accounts.push(a);
            }
        }
        let mut index = BTreeMap::new();
        for a in &accounts {
            index.insert(*deposit_index(a).as_bytes(), *a);
        }
        Ok(Book { path, network, accounts, index: Arc::new(Mutex::new(index)) })
    }

    /// The register the scanner reads.
    pub fn shared(&self) -> Arc<Mutex<BTreeMap<[u8; 11], AccountId>>> {
        Arc::clone(&self.index)
    }

    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// This account's deposit address, issuing it if this is the first time.
    ///
    /// Idempotent: the address is a function of the account, so asking twice
    /// returns the same one and writes nothing the second time.
    pub fn address_for(&mut self, keys: &VaultKeys, account: &AccountId) -> Result<String, String> {
        let idx = *deposit_index(account).as_bytes();
        let known = self.index.lock().map_err(|_| "address register poisoned".to_string())?.contains_key(&idx);
        if !known {
            // Recorded before it is handed out. A crash between the two would
            // otherwise leave a depositor paying an address the scanner does
            // not know to look for, and that money would look unattributable.
            self.accounts.push(*account);
            self.append(account)?;
            self.index.lock().map_err(|_| "address register poisoned".to_string())?.insert(idx, *account);
        }
        Ok(keys.deposit_address(account, self.network))
    }

    fn append(&self, account: &AccountId) -> Result<(), String> {
        let exists = self.path.exists();
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot open {}: {}", self.path.display(), e))?;
        if !exists {
            f.write_all(MAGIC).map_err(|e| e.to_string())?;
        }
        f.write_all(account).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};

    fn keys() -> VaultKeys {
        VaultKeys::from_full_viewing_key(FullViewingKey::from(&SpendingKey::from_bytes([3u8; 32]).unwrap()))
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-addrbook-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_address_is_stable_and_the_register_survives_a_restart() {
        let dir = tmp("stable");
        let k = keys();
        let alice = [1u8; 32];
        let bob = [2u8; 32];

        let mut b = Book::open(&dir, 7, NetworkType::Test).unwrap();
        assert!(b.is_empty());
        let a1 = b.address_for(&k, &alice).unwrap();
        let a2 = b.address_for(&k, &alice).unwrap();
        assert_eq!(a1, a2, "asking twice gives the same address");
        assert_eq!(b.len(), 1, "and records the account once");
        let b1 = b.address_for(&k, &bob).unwrap();
        assert_ne!(a1, b1);

        // Reopened, it knows both — the scanner will attribute their notes.
        let again = Book::open(&dir, 7, NetworkType::Test).unwrap();
        assert_eq!(again.len(), 2);
        let idx = again.shared();
        let m = idx.lock().unwrap();
        assert_eq!(m.get(deposit_index(&alice).as_bytes()), Some(&alice));
        assert_eq!(m.get(deposit_index(&bob).as_bytes()), Some(&bob));
        assert_eq!(m.len(), 2);
    }

    /// A different chain's register is a different file: two chains sharing a
    /// data directory must not credit each other's accounts.
    #[test]
    fn registers_are_per_chain() {
        let dir = tmp("perchain");
        let k = keys();
        let mut a = Book::open(&dir, 1, NetworkType::Test).unwrap();
        a.address_for(&k, &[5u8; 32]).unwrap();
        let b = Book::open(&dir, 2, NetworkType::Test).unwrap();
        assert!(b.is_empty());
    }
}
