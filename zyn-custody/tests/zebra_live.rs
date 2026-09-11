//! The note tree against the real testnet, through Zebra.
//!
//! Opt-in: `ZYN_ZEBRA_LIVE=1 cargo test -p zyn-custody --test zebra_live`
//! with a Zebra testnet RPC on `127.0.0.1:18232` (an SSH tunnel to the node
//! in `RUNBOOK` §4a).
//!
//! This is the check `DECISIONS` §13 said would decide whether the vault can
//! ever spend: a tree seeded from the node's frontier and fed by our own scan
//! must produce the **same root the node reports**, or every witness it
//! yields is a proof against a tree the chain does not have.

use zyn_custody::notes::NoteStore;
use orchard::ValuePool;
use zyn_custody::shielded::{PoolStores, Scanner, VaultKeys};
use zyn_custody::zebra::{Network, Zebra};

#[test]
fn the_vaults_tree_matches_the_chains_root() {
    if std::env::var("ZYN_ZEBRA_LIVE").is_err() {
        eprintln!("skipped: set ZYN_ZEBRA_LIVE=1 with a Zebra testnet RPC on 127.0.0.1:18232");
        return;
    }
    let zebra = Zebra::connect("127.0.0.1", 18232, None, Network::Testnet).unwrap();
    let tip = zebra.block_count().unwrap();
    let start = tip - 40;

    // Both pools since NU6.3: each seeded from the node's frontier, each
    // checked against the node's root.
    let seed = |pool: ValuePool| {
        let ts = zebra.tree_state_of(start, pool).unwrap();
        let store = NoteStore::from_frontier(&ts.final_state, start).unwrap();
        assert_eq!(store.root_bytes().unwrap(), ts.final_root, "{:?}: a tree seeded from the node's frontier has a different root", pool);
        std::sync::Arc::new(std::sync::Mutex::new(store))
    };
    let stores = PoolStores { orchard: seed(ValuePool::Orchard), ironwood: seed(ValuePool::Ironwood) };

    // Feed twelve real blocks and compare again: this is the scan path the
    // daemon uses, appending every shielded commitment on the chain to the
    // tree of the pool it belongs to.
    let keys = VaultKeys::from_spending_key([7u8; 32]).unwrap();
    let scanner = Scanner::new(keys, start + 1, 100).with_notes(stores.clone());
    let end = start + 12;
    let synced = scanner.sync_notes(&zebra, end).unwrap();
    assert_eq!(synced, end);

    for pool in [ValuePool::Orchard, ValuePool::Ironwood] {
        let after = zebra.tree_state_of(end, pool).unwrap();
        let s = stores.of(pool).lock().unwrap();
        assert_eq!(s.synced_to(), Some(end));
        assert_eq!(s.root_bytes().unwrap(), after.final_root, "{:?}: after {} appended commitments our root diverged from the chain's", pool, s.appended());
        eprintln!("{:?} tree in step with testnet at {}: {} commitments total", pool, end, s.appended());
    }
}
