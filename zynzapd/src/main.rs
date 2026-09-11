//! `zynzapd` — the ZynZap node as a process.
//!
//! ```text
//!   zyn-vm     the specification
//!   swapvm     ZynZap's VM
//!   zyn        sequencing, sealing, anchoring
//!   zynzapd    a port, a clock, a directory, a signal   <- you are here
//! ```
//!
//! # What this node is, and is not
//!
//! It sequences, executes, seals epochs and persists. It does **not** talk to
//! Zcash. Nothing here watches a chain, holds a key, or signs a payout — that
//! is `zyn-custody`, and it needs a Zcash node this process does not have.
//!
//! So the honest name for what it runs is a **devnet**: every unit of `ZEC.zy`
//! it issues comes from an operator intent rather than an observed deposit, and
//! is backed by nothing. Everything above custody is real — accounts, pools,
//! routing, sealing, data availability, and the whole authorisation path from
//! an EIP-712 signature to a sequenced intent. That is most of the machine, and
//! it is the part a wallet and an interface need in order to exist.
//!
//! Do not put value in it.
//!
//! # Durability
//!
//! State is written on every seal and on a timer, and the process seals before
//! it exits on `SIGINT`/`SIGTERM`. A kill that skips all three loses the
//! intents applied since the last seal, which is what `intents_per_epoch`
//! bounds. `FileStore` refuses a blob that does not commit to its recorded
//! root, so a node cannot resume into a state it would have to lie about.

use zynzapd::feeds;
use zynzapd::{alert, bridge, config, rpc, settle};

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use config::Config;
use zyn::epoch::Economics;
use zyn_custody::zebra::Zebra;
use zyn_vm::spec::MicrochainVm;

static STOPPING: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    // Async-signal-safe: set a flag and return. Anything else here — logging,
    // allocating, taking the node's lock — risks deadlocking against the very
    // thread being interrupted.
    STOPPING.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // Cast through a function pointer first: casting the function *item*
    // straight to an integer is a lint, and the two are not the same thing.
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

fn parse_seed(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err("ZYN_VAULT_SEED must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "ZYN_VAULT_SEED must be hex".to_string())?;
    }
    Ok(out)
}

/// `<txid-hex> <account-hex>` per line; `#` comments. A txid is written the
/// way a node displays it (byte-reversed), and stored the way the chain
/// commits to it.
/// The consensus-parameter network for the chain we are configured for.
fn zcash_network(n: zyn_custody::zebra::Network) -> zcash_protocol::consensus::Network {
    match n {
        zyn_custody::zebra::Network::Mainnet => zcash_protocol::consensus::Network::MainNetwork,
        // Regtest shares testnet's parameters for everything the vault reads.
        _ => zcash_protocol::consensus::Network::TestNetwork,
    }
}

/// The address encoding for that network.
fn address_network(n: zyn_custody::zebra::Network) -> zcash_protocol::consensus::NetworkType {
    use zcash_protocol::consensus::Parameters;
    zcash_network(n).network_type()
}

fn load_attributions(path: &std::path::Path) -> Result<std::collections::BTreeMap<[u8; 32], [u8; 32]>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut out = std::collections::BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 2 {
            return Err(format!("{} line {}: expected `<txid> <account-hex>`", path.display(), n + 1));
        }
        let mut txid: [u8; 32] = parse_hex(f[0], 32, "txid")?.try_into().expect("32 bytes");
        txid.reverse();
        let account: [u8; 32] = parse_hex(f[1], 32, "account")?.try_into().expect("32 bytes");
        out.insert(txid, account);
    }
    Ok(out)
}

fn note_tree_path(dir: &std::path::Path, chain_id: u32, pool: orchard::ValuePool) -> std::path::PathBuf {
    dir.join(format!("notes-{}-{}.tree", chain_id, match pool { orchard::ValuePool::Orchard => "orchard", orchard::ValuePool::Ironwood => "ironwood" }))
}

/// Write both trees, atomically each. A tree that fails to write is a
/// longer catch-up on the next start, not a fault.
fn save_trees(cfg: &Config, trees: Option<&zyn_custody::shielded::PoolStores>) {
    let Some(t) = trees else { return };
    for pool in [orchard::ValuePool::Orchard, orchard::ValuePool::Ironwood] {
        let Ok(store) = t.of(pool).lock() else { continue };
        let path = note_tree_path(&cfg.data_dir, cfg.chain_id, pool);
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, store.encode()).and_then(|_| std::fs::rename(&tmp, &path)).is_err() {
            eprintln!("zynzapd: could not save the {:?} note tree", pool);
        }
    }
}

fn parse_hex(hex: &str, len: usize, name: &str) -> Result<Vec<u8>, String> {
    if hex.len() != len * 2 {
        return Err(format!("{} must be {} hex characters", name, len * 2));
    }
    (0..len)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| format!("{} must be hex", name)))
        .collect()
}

fn shares_len(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|d| d.filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().starts_with("share-")).count()).unwrap_or(0)
}

fn a_settler_txid(settler: &Option<zynzapd::anchor::AnchorSettler<zyn_custody::zebra::Zebra, zynzapd::anchor::ZcashBuilder>>, anchor_id: [u8; 32]) -> String {
    settler
        .as_ref()
        .and_then(|s| s.ledger().entries.iter().find(|e| e.nonce == anchor_id))
        .map(|e| e.id.clone())
        .unwrap_or_default()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zynzapd: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cfg = Config::from_env().map_err(|e| e.to_string())?;
    // Anchors travel to Zcash when the vault can sign: the same shares that
    // pay exits carry the roots. Without them anchoring is the V0 in-memory
    // posture, and the log says so.
    let manual = cfg.zebra.as_ref().and_then(|z| z.settle.as_ref()).is_some();
    let booted = zynzapd::boot::open_at(
        &cfg.data_dir,
        cfg.chain_id,
        cfg.profile.params(),
        cfg.policy(),
        Economics::flat(10_000),
        now_secs(),
        manual,
        &cfg.da_dir,
    )?;
    let zynzapd::boot::Booted { mut node, store, journal, resumed, base_root, replay } = booted;
    if let Some((keys, threshold)) = &cfg.signer_set {
        match zyn::anchor::SignerSet::new(keys.clone(), *threshold) {
            Ok(set) => {
                eprintln!("zynzapd: SIGNER SET configured — {} of {} endorsements release each root; a root nobody reproduces never settles", threshold, keys.len());
                node = node.with_signers(set);
            }
            Err(e) => return Err(format!("ZYN_SIGNER_SET: {}", e)),
        }
    }
    if resumed {
        eprintln!(
            "zynzapd: resumed chain {} at seq {} epoch {} with {} anchor(s) in the lineage",
            cfg.chain_id,
            node.state().seq(),
            node.state().epoch(),
            node.ledger().len()
        );
    } else {
        eprintln!("zynzapd: new chain {} with {:?} parameters", cfg.chain_id, cfg.profile);
    }

    let shared: rpc::Shared = Arc::new(Mutex::new(node));

    if cfg.launch {
        let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
        let mut params = swapvm::launch::Launch::v1();
        if let Some(t) = &cfg.launch_threshold {
            params.threshold = zynzapd::client::fixed_of(t).map_err(|e| format!("ZYN_LAUNCH_THRESHOLD: {}", e))?;
        }
        let current = n.state().launch.as_ref().map(|l| (l.params, l.graduated()));
        match current {
            Some((_, true)) => eprintln!("zynzapd: ZYN launch graduated; its numbers are history"),
            _ => {
                let step = n.submit_operator(swapvm::tx::Intent::SetLaunch { params }, now_secs());
                if step.rejected() {
                    return Err(format!("ZYN_LAUNCH refused: {:?}", step.receipts));
                }
                eprintln!("zynzapd: ZYN launch set: {} bps bridge fee to the genesis pot, graduation at {} ZEC.zy, {} ZYN genesis, cap {}", params.fee_bps, params.threshold, params.genesis, params.cap);
            }
        }
    }

    if let Some(on) = cfg.batch_clearing {
        let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
        if n.state().batch_clearing != on {
            let step = n.submit_operator(swapvm::tx::Intent::SetClearing { on }, now_secs());
            if step.rejected() {
                return Err(format!("ZYN_BATCH_CLEARING={} refused: {:?}", on, step.receipts));
            }
            eprintln!("zynzapd: batch clearing {}: single-hop swaps {} at the seal", if on { "on" } else { "off" }, if on { "clear together" } else { "no longer queue; they execute on arrival" });
        }
    }

    if let Some(epochs) = cfg.exit_timeout_epochs {
        let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
        if n.state().params.exit_timeout_epochs != epochs {
            let mut params = n.state().params;
            params.exit_timeout_epochs = epochs;
            let step = n.submit_operator(swapvm::tx::Intent::SetParams { params }, now_secs());
            if step.rejected() {
                return Err(format!("ZYN_EXIT_TIMEOUT_EPOCHS={} refused: {:?}", epochs, step.receipts));
            }
            eprintln!("zynzapd: exit timeout / redirect delay set to {} epochs (TESTNET posture)", epochs);
        }
    }
    let listener = TcpListener::bind(cfg.listen)
        .map_err(|e| format!("cannot bind {}: {}", cfg.listen, e))?;

    eprintln!(
        "zynzapd: chain {} listening on {} — DEVNET, units are unbacked",
        cfg.chain_id, cfg.listen
    );

    // Bridges are opted into, one per watched chain. Without one there is
    // nothing to observe and a devnet is what runs.
    //
    // A `Vec` rather than an `Option` because the EVM vault is the *second*
    // bridge, and running two at once is the whole point of it: each has its
    // own asset, its own vault ceiling and its own progress file, so a fault in
    // one credits nothing in the other (`DECISIONS` §14b, §14e).
    let mut deposits: Vec<bridge::Bridge> = Vec::new();
    // The deposit-address register, once a Zcash vault is configured.
    let mut deposit_book: Option<Arc<Mutex<(zynzapd::deposits::Book, zyn_custody::shielded::VaultKeys)>>> = None;

    let mut zcash_settler: Option<settle::ZcashSettler> = None;
    let mut anchor_settler: Option<zynzapd::anchor::AnchorSettler<Zebra, zynzapd::anchor::ZcashBuilder>> = None;
    let mut note_trees: Option<zyn_custody::shielded::PoolStores> = None;
    if let Some(z) = &cfg.zebra {
        let auth = match (&z.user, &z.password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        };
        let zebra = Zebra::connect(&z.host, z.port, auth, cfg.network)
            .map_err(|e| e.to_string())?;
        // Ask the node which chain it is on, and refuse to run if it disagrees
        // with what we were configured for. Every other safeguard assumes the
        // chain underneath is the configured one; get that wrong and a
        // mainnet-configured vault credits testnet deposits, or hands out
        // addresses nobody can pay — and nothing downstream can tell, because
        // everything downstream is consistent with itself.
        zebra.verify_network().map_err(|e| e.to_string())?;
        eprintln!(
            "zynzapd: Zcash {:?} confirmed by the node at {}:{}",
            cfg.network, z.host, z.port
        );
        let shielded_keys = match (&z.vault_seed, &z.vault_fvk) {
            (Some(seed), _) => Some(
                zyn_custody::shielded::VaultKeys::from_spending_key(parse_seed(seed)?)
                    .ok_or("ZYN_VAULT_SEED is not a valid Orchard spending key")?,
            ),
            (None, Some(fvk_hex)) => {
                let bytes = parse_hex(fvk_hex, 96, "ZYN_VAULT_FVK")?;
                let fvk = orchard::keys::FullViewingKey::from_bytes(&bytes.try_into().expect("96 bytes"))
                    .ok_or("ZYN_VAULT_FVK is not a valid Orchard full viewing key")?;
                Some(zyn_custody::shielded::VaultKeys::from_full_viewing_key(fvk))
            }
            (None, None) => None,
        };
        let source = match (shielded_keys, &z.addresses) {
            (Some(keys), _) => {
                eprintln!("zynzapd: shielded vault own address (change, anchors, top-ups): {}", keys.address(0, address_network(cfg.network)));
                // One deposit address per account, so a depositor needs no
                // memo and a verifier can rederive whose the money is. The
                // register only says which account to credit; whether that
                // credit is honest is settled against the chain.
                let book = zynzapd::deposits::Book::open(&cfg.data_dir, cfg.chain_id, address_network(cfg.network))?;
                eprintln!("zynzapd: {} account deposit address(es) issued so far", book.len());
                let addresses = book.shared();
                deposit_book = Some(Arc::new(Mutex::new((book, keys.clone()))));
                let mut scanner = zyn_custody::shielded::Scanner::new(keys, z.from_height, z.max_blocks)
                    .with_tree_lag(cfg.confirmations)
                    .with_addresses(addresses);
                if let Some(path) = &z.attributions {
                    let a = load_attributions(path)?;
                    if !a.is_empty() {
                        eprintln!("zynzapd: {} memo-less deposit(s) attributed by hand from {}", a.len(), path.display());
                    }
                    scanner = scanner.with_attributions(a);
                }
                if let Some(st) = &z.settle {
                    // Exits need the note trees — one per pool since NU6.3.
                    // Seed each from the node's own frontier at the vault's
                    // creation height, check the root, then walk the blocks
                    // the deposit watcher may already be past: a tree needs
                    // every commitment, credited or not.
                    let seed_height = z.from_height.saturating_sub(1);
                    // A tree written at the last save resumes where it
                    // stopped — checked against the node's root at that
                    // height before it is trusted. Anything else is
                    // re-seeded from the node's frontier.
                    //
                    // Both pools, or neither. `feed_block` appends every
                    // block to **both** trees, so re-seeding one pool from
                    // the vault's birth while the other resumes at the tip
                    // would walk five thousand blocks into the resumed tree
                    // a second time — which is exactly the divergence this
                    // check exists to catch, manufactured at boot.
                    let resume = |pool: orchard::ValuePool| -> Option<zyn_custody::notes::NoteStore> {
                        let path = note_tree_path(&cfg.data_dir, cfg.chain_id, pool);
                        let bytes = std::fs::read(&path).ok()?;
                        let store = match zyn_custody::notes::NoteStore::decode(&bytes) {
                            Some(s) => s,
                            None => {
                                eprintln!("zynzapd: {:?} note tree on disk did not decode; re-seeding", pool);
                                return None;
                            }
                        };
                        let at = store.synced_to().unwrap_or(seed_height);
                        let ts = zebra.tree_state_of(at, pool).ok()?;
                        if store.root_bytes() == Some(ts.final_root) {
                            eprintln!("zynzapd: {:?} note tree resumed from disk at {}, root matches the node ({} notes held)", pool, at, store.held().count());
                            Some(store)
                        } else {
                            eprintln!("zynzapd: {:?} note tree on disk does not match the node at {}; re-seeding", pool, at);
                            None
                        }
                    };
                    let fresh = |pool: orchard::ValuePool| -> Result<zyn_custody::notes::NoteStore, String> {
                        let ts = zebra.tree_state_of(seed_height, pool).map_err(|e| format!("z_gettreestate {}: {}", seed_height, e))?;
                        let store = zyn_custody::notes::NoteStore::from_frontier(&ts.final_state, seed_height)
                            .map_err(|e| format!("cannot seed the {:?} note tree: {:?}", pool, e))?;
                        if store.root_bytes() != Some(ts.final_root) {
                            return Err(format!("the {:?} tree seeded from the node does not reproduce the node's root", pool));
                        }
                        eprintln!("zynzapd: {:?} note tree seeded at {}, root matches the node", pool, seed_height);
                        Ok(store)
                    };
                    let (o, i) = match (resume(orchard::ValuePool::Orchard), resume(orchard::ValuePool::Ironwood)) {
                        (Some(o), Some(i)) if o.synced_to() == i.synced_to() => (o, i),
                        (Some(_), Some(_)) => {
                            eprintln!("zynzapd: the two note trees stopped at different heights; re-seeding both");
                            (fresh(orchard::ValuePool::Orchard)?, fresh(orchard::ValuePool::Ironwood)?)
                        }
                        _ => {
                            eprintln!("zynzapd: re-seeding both note trees together — they are fed together");
                            (fresh(orchard::ValuePool::Orchard)?, fresh(orchard::ValuePool::Ironwood)?)
                        }
                    };
                    let stores = zyn_custody::shielded::PoolStores {
                        orchard: Arc::new(Mutex::new(o)),
                        ironwood: Arc::new(Mutex::new(i)),
                    };
                    let notes = stores.clone();
                    note_trees = Some(stores.clone());
                    scanner = scanner.with_notes(stores);
                    let fvk_hex = z.vault_fvk.as_ref().expect("config requires a viewing key with shares");
                    let bytes = parse_hex(fvk_hex, 96, "ZYN_VAULT_FVK")?;
                    let fvk = orchard::keys::FullViewingKey::from_bytes(&bytes.try_into().expect("96 bytes")).expect("checked above");
                    let shares = zyn_custody::shares::load::<zyn_custody::ceremony::Zcash>(&st.shares)
                        .map_err(|e| format!("cannot load shares from {}: {}", st.shares.display(), e))?;
                    let reveals = settle::load_zcash_reveals(&st.reveals, zcash_network(cfg.network))?;
                    let exit_public = zyn_custody::shares::load_public::<zyn_custody::ceremony::Zcash>(&st.shares)
                        .map_err(|e| format!("cannot load the public package from {}: {}", st.shares.display(), e))?;
                    let exit_shares = if st.custodians.is_some() { Vec::new() } else { shares };
                    let settler = settle::ZcashSettler::new(
                        Zebra::connect(&z.host, z.port, auth, cfg.network).map_err(|e| e.to_string())?,
                        zcash_network(cfg.network),
                        exit_shares, st.threshold, fvk.clone(), notes.clone(), reveals,
                        swapvm::types::XZEC, cfg.confirmations, cfg.data_dir.clone(), cfg.chain_id,
                        exit_public, st.custodians.clone(),
                    )?;
                    eprintln!(
                        "zynzapd: settling Zcash exits from {} — {} of {} shares ON THIS MACHINE, which is a devnet key; Ironwood exits pay shielded addresses, Orchard exits transparent (NU6.3)",
                        settler.deposit_address(), st.threshold, shares_len(&st.shares)
                    );
                    zcash_settler = Some(settler);
                    // The anchor path: same key, same node, its own ledger. With
                    // custodians configured the box loads only the public
                    // package and signs remotely; otherwise it loads the shares.
                    let anchor_public = zyn_custody::shares::load_public::<zyn_custody::ceremony::Zcash>(&st.shares)
                        .map_err(|e| format!("cannot load the public package from {}: {}", st.shares.display(), e))?;
                    let anchor_shares = if st.custodians.is_some() {
                        Vec::new()
                    } else {
                        zyn_custody::shares::load::<zyn_custody::ceremony::Zcash>(&st.shares)
                            .map_err(|e| format!("cannot load shares from {}: {}", st.shares.display(), e))?
                    };
                    let builder = zynzapd::anchor::ZcashBuilder::new(
                        zcash_network(cfg.network),
                        anchor_shares,
                        st.threshold,
                        fvk,
                        notes,
                        Zebra::connect(&z.host, z.port, auth, cfg.network).map_err(|e| e.to_string())?,
                        z.from_height,
                        cfg.confirmations,
                        z.attributions.as_ref().map(|p| load_attributions(p)).transpose()?.unwrap_or_default(),
                        anchor_public,
                        st.custodians.clone(),
                    )?;
                    let chain = Zebra::connect(&z.host, z.port, auth, cfg.network).map_err(|e| e.to_string())?;
                    let mut settler = zynzapd::anchor::AnchorSettler::new(chain, builder, cfg.confirmations, &cfg.data_dir, cfg.chain_id)?;
                    if cfg.signer_set.is_some() {
                        settler = settler.requiring_signatures();
                    }
                    // Repair, and deliberately awkward to reach: operator
                    // authority is not obtainable over the network (see
                    // `rpc.rs`), so re-anchoring an already-settled epoch asks
                    // for the filesystem and a restart. Used when a reorg took
                    // a confirmed anchor off Zcash and the lineage no longer
                    // connects for anyone verifying from the chain (§50.6).
                    if let Ok(list) = std::env::var("ZYN_REANCHOR_EPOCHS") {
                        for epoch in list.split(',').filter_map(|e| e.trim().parse::<u64>().ok()) {
                            match zynzapd::publish::read_local(&cfg.da_dir, cfg.chain_id, epoch) {
                                Err(e) => eprintln!("zynzapd: re-anchor {}: cannot read the published bundle: {}", epoch, e),
                                Ok(b) => {
                                    // Queued, not sent: the note store is not
                                    // current until the scanner has caught up.
                                    settler.queue_reanchor(b.anchor);
                                    eprintln!("zynzapd: re-anchor of epoch {} queued; it will go out when the vault has a spendable note", epoch);
                                }
                            }
                        }
                    }
                    anchor_settler = Some(settler);
                    eprintln!(
                        "zynzapd: anchors ON ZCASH — self-sends from the vault, accepted at {} confirmation(s); the exit hatch verifies against roots the chain has",
                        cfg.confirmations
                    );
                }
                bridge::Source::Shielded(Box::new(scanner))
            }
            (None, Some(path)) => {
                let addresses = bridge::load_addresses(path)?;
                if addresses.is_empty() {
                    return Err(format!("{} lists no addresses", path.display()));
                }
                eprintln!(
                    "zynzapd: TRANSPARENT scaffold, {} address(es) — not the design",
                    addresses.len()
                );
                bridge::Source::Transparent(addresses)
            }
            (None, None) => unreachable!("config rejects a bridge with neither"),
        };
        // Catch the tree up to wherever the deposit watcher already is, so
        // the first live pass appends rather than skips.
        if let bridge::Source::Shielded(scanner) = &source {
            if scanner.notes().is_some() {
                let mut target = bridge::scanned_height(&cfg.data_dir, cfg.chain_id, swapvm::types::XZEC);
                if let Some(r) = z.rescan_from {
                    target = target.min(r.saturating_sub(1));
                }
                let mut synced = scanner.notes().and_then(|n| n.synced_to()).unwrap_or(0);
                while synced < target {
                    match scanner.sync_notes(&zebra, target) {
                        Ok(h) => synced = h,
                        // A memo-less deposit stops the tree here, and the live
                        // scan will say so every pass until it is attributed.
                        // Not a reason to refuse to start.
                        Err(zyn_custody::shielded::ScanRangeError::Unattributable { height, amount }) => {
                            eprintln!("zynzapd: note tree catch-up stopped at {}: shielded funds ({:?}) carry no Zyn memo — attribute them (ZYN_ZEBRA_ATTRIBUTIONS) and restart", height, amount);
                            break;
                        }
                        Err(e) => return Err(format!("note tree catch-up: {:?}", e)),
                    }
                    eprintln!("zynzapd: note trees synced to {} of {}", synced, target);
                }
            }
        }
        let mut b = bridge::Bridge::new(
            bridge::Custody::Zcash { zebra, source },
            cfg.confirmations,
            swapvm::types::XZEC,
            cfg.data_dir.clone(),
            cfg.chain_id,
            {
                let n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
                n.state().next_deposit_index(swapvm::types::XZEC)
            },
        )?;
        if let Some(r) = z.rescan_from {
            b.rescan_from(r)?;
        }
        eprintln!(
            "zynzapd: watching {}:{} for deposits, {} confirmations, scanned to {}",
            z.host,
            z.port,
            cfg.confirmations,
            b.scanned_to()
        );
        {
            let mut b = b.with_replay(Arc::clone(&replay));
            if let Some(from) = cfg.forced_rescan_from {
                match b.rescan_forced(from) {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: forced-intent rescan from {}: {} queued for application", from, n),
                    Err(e) => eprintln!("zynzapd: forced-intent rescan failed: {}", e),
                }
            }
            deposits.push(b);
        }
    }

    if let Some(e) = &cfg.evm {
        // `connect` refuses mainnet and checks the endpoint really is the chain
        // configured — the vault has the same address everywhere, so a wrong
        // URL finds a real contract with real logs.
        let rpc = zyn_custody::evm::Rpc::connect(
            &e.url,
            zyn_custody::evm::Network { chain_id: e.chain_id },
        )
        .map_err(|err| err.to_string())?;
        let observed =
            zyn_custody::evm::Observed::new(rpc, e.vault, e.asset, e.token, e.decimals)
                .map_err(|err| err.to_string())?;
        // Finality, not depth: a finalized block cannot be reorged, so there is
        // nothing left for a confirmation count to protect against.
        let mut b = bridge::Bridge::new(
            bridge::Custody::Evm(Box::new(observed)),
            0,
            e.asset,
            cfg.data_dir.clone(),
            cfg.chain_id,
            {
                let n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
                n.state().next_deposit_index(e.asset)
            },
        )?;
        b.start_no_earlier_than(e.from_height)?;
        eprintln!(
            "zynzapd: watching EVM chain {} vault 0x{} for asset {}, finalized tip, scanned to {}",
            e.chain_id,
            e.vault.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            e.asset,
            b.scanned_to()
        );
        {
            let mut b = b.with_replay(Arc::clone(&replay));
            if let Some(from) = cfg.forced_rescan_from {
                match b.rescan_forced(from) {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: forced-intent rescan from {}: {} queued for application", from, n),
                    Err(e) => eprintln!("zynzapd: forced-intent rescan failed: {}", e),
                }
            }
            deposits.push(b);
        }
    }

    let mut solana_asset: Option<swapvm::types::AssetId> = None;
    let mut solana_mirrored: Vec<zyn_custody::solana::Mirrored> = Vec::new();
    if let Some(sol) = &cfg.solana {
        // The asset is looked up by origin, and created if the chain has
        // none: `SOL.zy` with a Solana vault and no supply until deposits
        // arrive. Operator-only, sequenced like anything else.
        let sol_asset = {
            let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
            match n.state().bridged_assets().into_iter().find(|(_, o)| *o == swapvm::types::ORIGIN_SOLANA) {
                Some((id, _)) => id,
                None => {
                    let step = n.submit_operator(
                        swapvm::tx::Intent::CreateBridgedAsset { symbol: swapvm::state::symbol(b"SOL.zy"), origin: swapvm::types::ORIGIN_SOLANA },
                        now_secs(),
                    );
                    if step.rejected() {
                        return Err(format!("could not create SOL.zy: {:?}", step.receipts));
                    }
                    let id = n.state().bridged_assets().into_iter().find(|(_, o)| *o == swapvm::types::ORIGIN_SOLANA).map(|(id, _)| id).ok_or("SOL.zy not created")?;
                    eprintln!("zynzapd: created SOL.zy as asset {}", id);
                    id
                }
            }
        };
        if sol.asset != 0 && sol.asset != sol_asset {
            return Err(format!("ZYN_SOLANA_ASSET={} but the chain's Solana asset is {}", sol.asset, sol_asset));
        }
        solana_asset = Some(sol_asset);
        let cluster = match sol.cluster.as_str() {
            "devnet" => zyn_custody::solana::Cluster::Devnet,
            "testnet" => zyn_custody::solana::Cluster::Testnet,
            other => {
                return Err(format!(
                    "ZYN_SOLANA_CLUSTER is {:?}; expected devnet or testnet",
                    other
                ))
            }
        };
        // Refuses mainnet, and checks the endpoint's genesis hash is the
        // cluster configured.
        let rpc = zyn_custody::solana::Rpc::connect(&sol.url, cluster)
            .map_err(|e| e.to_string())?;
        // Mirrored tokens: each configured mint exists on the chain as an
        // indivisible bridged item whose `content` is the mint, and the
        // vault's token account for it is watched alongside the vault.
        let mirrored = {
            let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
            for (mint_b58, symbol) in &sol.mints {
                let mint = zyn_custody::solana::pubkey(mint_b58).ok_or_else(|| format!("ZYN_SOLANA_MINTS: {} is not a Solana address", mint_b58))?;
                let exists = n.state().tokens.values().any(|t| t.content == Some(mint));
                if !exists {
                    let mut sym = [0u8; 8];
                    let b = symbol.as_bytes();
                    sym[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
                    let step = n.submit_operator(swapvm::tx::Intent::CreateBridgedItem { symbol: sym, origin: swapvm::types::ORIGIN_SOLANA, content: mint }, now_secs());
                    if step.rejected() {
                        return Err(format!("could not mirror {}: {:?}", mint_b58, step.receipts));
                    }
                    eprintln!("zynzapd: mirroring mint {} as {}", mint_b58, symbol);
                }
            }
            let vault_pk = zyn_custody::solana::pubkey(&sol.vault).ok_or("ZYN_SOLANA_VAULT is not a Solana address")?;
            n.state()
                .tokens
                .iter()
                .filter(|(_, t)| t.vault.map(|v| v.origin) == Some(swapvm::types::ORIGIN_SOLANA) && t.unit == swapvm::Fixed::ONE)
                .filter_map(|(id, t)| t.content.map(|mint| (id, mint)))
                .map(|(id, mint)| zyn_custody::solana::Mirrored {
                    mint: zyn_custody::solana::base58_encode(&mint),
                    asset: *id,
                    ata: zyn_custody::solana::base58_encode(&zyn_bridge::solana::associated_token_address(&vault_pk, &mint)),
                    per_unit: 1,
                })
                .collect::<Vec<_>>()
        };
        for mr in &mirrored {
            eprintln!("zynzapd: watching token account {} for mint {} (asset {})", mr.ata, mr.mint, mr.asset);
        }
        solana_mirrored = mirrored.clone();
        let observed = zyn_custody::solana::Observed::new(rpc, &sol.vault)
            .map_err(|e| e.to_string())?
            .with_mirrored(mirrored.clone());
        let mut b = bridge::Bridge::new(
            bridge::Custody::Solana(Box::new(observed)),
            0, // finalized slots do not need a depth
            sol_asset,
            cfg.data_dir.clone(),
            cfg.chain_id,
            {
                let n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
                n.state().next_deposit_index(sol_asset)
            },
        )?;
        b.start_no_earlier_than(sol.from_slot)?;
        if let Some(r) = sol.rescan_from {
            b.rescan_from(r)?;
        }
        eprintln!(
            "zynzapd: watching Solana {} vault {} for asset {}, finalized tip, scanned to {}",
            sol.cluster,
            sol.vault,
            sol_asset,
            b.scanned_to()
        );
        eprintln!(
            "zynzapd: depositors must attach the memo ZYN1:<their 32-byte account, hex>"
        );
        {
            let mut b = b.with_replay(Arc::clone(&replay));
            if let Some(from) = cfg.forced_rescan_from {
                match b.rescan_forced(from) {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: forced-intent rescan from {}: {} queued for application", from, n),
                    Err(e) => eprintln!("zynzapd: forced-intent rescan failed: {}", e),
                }
            }
            deposits.push(b);
        }
    }

    // Exits, Solana only so far. Deposits and exits are separate opt-ins: a
    // vault that fills and never pays out is a legitimate devnet posture, and
    // a settler that starts because a watcher did is one nobody decided on.
    let mut settler = match cfg.solana.as_ref().and_then(|s| s.settle.as_ref().map(|x| (s, x))) {
        None => None,
        Some((sol, st)) => {
            let cluster = if sol.cluster == "testnet" { zyn_custody::solana::Cluster::Testnet } else { zyn_custody::solana::Cluster::Devnet };
            let rpc = zyn_custody::solana::Rpc::connect(&sol.url, cluster).map_err(|e| e.to_string())?;
            // With custodians configured this box loads only the public
            // package: there is no secret share here to load.
            let shares = if st.custodians.is_some() {
                Vec::new()
            } else {
                zyn_custody::solana::shares::load(&st.shares).map_err(|e| format!("cannot load shares from {}: {}", st.shares.display(), e))?
            };
            let public = zyn_custody::shares::load_public::<zyn_custody::ceremony::Solana>(&st.shares)
                .map_err(|e| format!("cannot load the public package from {}: {}", st.shares.display(), e))?;
            let reveals = settle::load_reveals(&st.reveals)?;
            let s = settle::SolanaSettler::new(
                rpc, shares, public, st.custodians.clone(), st.threshold, &st.nonce_account, reveals,
                solana_asset.unwrap_or(sol.asset), cfg.data_dir.clone(), cfg.chain_id,
            )?
            .with_mirrored(solana_mirrored.clone());
            match &st.custodians {
                Some(addrs) => eprintln!(
                    "zynzapd: settling Solana exits from vault {} — {} of {} custodians sign; this box holds no share",
                    s.vault_address(), st.threshold, addrs.len()
                ),
                None => eprintln!(
                    "zynzapd: settling Solana exits from vault {} — {} of {} shares ON THIS MACHINE, which is a devnet key",
                    s.vault_address(), st.threshold, shares_len(&st.shares)
                ),
            }
            Some(s)
        }
    };

    if deposits.is_empty() {
        eprintln!("zynzapd: no bridge configured — devnet only, units are unbacked");
    }

    install_signal_handlers();

    // The launch's clock: the Zcash tip, reported when it moves.
    if cfg.launch {
        if let Some(z) = cfg.zebra.as_ref() {
            let auth = match (&z.user, &z.password) { (Some(u), Some(p)) => Some((u.as_str(), p.as_str())), _ => None };
            match zyn_custody::zebra::Zebra::connect_reader(&z.host, z.port, auth, zyn_custody::zebra::Network::Testnet) {
                Ok(zebra) => {
                    let shared2 = Arc::clone(&shared);
                    std::thread::spawn(move || {
                        let mut last = 0u64;
                        loop {
                            if let Ok(h) = zebra.block_count() {
                                if h > last {
                                    if let Ok(mut n) = shared2.lock() {
                                        let step = n.submit_operator(swapvm::tx::Intent::ZcashHeight { height: h }, now_secs());
                                        if !step.rejected() { last = h; }
                                    }
                                }
                            }
                            std::thread::sleep(std::time::Duration::from_secs(30));
                        }
                    });
                }
                Err(e) => eprintln!("zynzapd: launch clock: cannot reach Zebra: {}", e),
            }
        } else {
            eprintln!("zynzapd: launch set but no Zebra configured; the clock will not advance");
        }
    }

    let health: Arc<Mutex<Vec<alert::Health>>> = Arc::new(Mutex::new(Vec::new()));
    // The reference-price feed, on its own thread: it reads public markets
    // and posts `UpdateReference` for every pool whose two sides it can
    // price. Its health joins the watchers' in `OP_STATUS`.
    let feed_health: Arc<Mutex<feeds::FeedHealth>> = Arc::new(Mutex::new(feeds::FeedHealth::default()));
    if cfg.feeds {
        let mut map = feeds::default_map();
        if let Some(spec) = &cfg.feed_map {
            feeds::apply_overrides(&mut map, spec).map_err(|e| format!("ZYN_FEED_MAP: {}", e))?;
        }
        let fc = feeds::FeedConfig { interval_secs: cfg.feed_interval.max(15), ..feeds::FeedConfig::default() };
        let mut f = feeds::Feeds::new(fc.clone(), map, feeds::Http::default());
        let shared2 = Arc::clone(&shared);
        let fh = Arc::clone(&feed_health);
        eprintln!("zynzapd: price feeds on: every {} s, {} symbols known", fc.interval_secs, f.map.len());
        std::thread::spawn(move || loop {
            match feeds::cycle(&mut f, &shared2, now_secs(), &fh) {
                Ok(0) => {}
                Ok(n) => eprintln!("zynzapd: feed: posted {} reference(s)", n),
                Err(e) => eprintln!("zynzapd: feed cycle failed: {}", e),
            }
            std::thread::sleep(std::time::Duration::from_secs(fc.interval_secs));
        });
    }
    let mut alerter = alert::Alerter::new(cfg.alert_url.as_deref().map(alert::Webhook::new), cfg.chain_id);
    alerter.after_failures = cfg.alert_after_failures;
    alerter.stall_secs = cfg.stall_secs;
    match &cfg.alert_url {
        Some(u) => eprintln!("zynzapd: alerts to {} after {} failed passes or {}s stalled", u, cfg.alert_after_failures, cfg.stall_secs),
        None => eprintln!("zynzapd: alerts to the journal only (set ZYN_ALERT_URL for a webhook)"),
    }
    let inbox: Arc<Mutex<rpc::Inbox>> = Arc::new(Mutex::new(rpc::Inbox::default()));
    let server = Arc::new(rpc::Server {
        node: Arc::clone(&shared),
        chain_id: cfg.chain_id,
        now: now_secs,
        health: Arc::clone(&health),
        inbox: Arc::clone(&inbox),
        replica: None,
        replay: Arc::clone(&replay),
        deposits: deposit_book.clone(),
        da_dir: Some(cfg.da_dir.clone()),
    });
    std::thread::spawn(move || rpc::serve(server, listener));

    // The main thread is the clock. Sealing on a timer is what makes an expiry
    // measured in epochs mean anything in wall-clock terms (S12): without it, a
    // chain with no traffic never advances and a signed intent never expires.
    if !manual {
        eprintln!("zynzapd: anchors IN MEMORY ONLY (no ZYN_ZEBRA_SHARES): roots never reach Zcash — a devnet posture, not a mainnet one");
    }
    let mut publisher = zynzapd::publish::Publisher::new(zynzapd::publish::parse_mirrors(&cfg.da_mirrors));
    if let Some(root) = base_root {
        // The base is mirrored like any bundle file, every start, so a mirror
        // added later still gets it.
        let base_rel = format!("chain-{}/base.state", cfg.chain_id);
        if let Ok(bytes) = std::fs::read(cfg.da_dir.join(&base_rel)) {
            publisher.queue(vec![(base_rel, bytes)]);
        }
        eprintln!("zynzapd: replicas start from base root {}", root.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    }
    match publisher.mirrors().len() {
        0 => eprintln!("zynzapd: DA bundles written to {} only — set ZYN_DA_MIRRORS so they outlive this box", cfg.da_dir.display()),
        n => eprintln!("zynzapd: DA bundles written to {} and pushed to {} mirror(s)", cfg.da_dir.display(), n),
    }
    let mut last_save = now_secs();
    let mut last_scan = 0u64;
    while !STOPPING.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let now = now_secs();

        let sealed = match shared.lock() {
            Err(_) => {
                eprintln!("zynzapd: node lock poisoned, shutting down");
                break;
            }
            Ok(mut n) => {
                // By policy, not by tick: with batch clearing on, the time
                // between seals is the auction window.
                let sealed = n.seal_if_due(now).is_some();
                if sealed {
                    if manual {
                        // Proposed now, confirmed when Zcash has it.
                        n.propose_anchor(now);
                    } else {
                        n.anchor_now(now);
                    }
                }
                sealed
            }
        };

        if sealed || now.saturating_sub(last_save) >= cfg.save_every_secs {
            { zynzapd::boot::save(&store, &journal, &shared); if let Ok(n) = shared.lock() { zynzapd::boot::save_replay(&cfg.data_dir, cfg.chain_id, &replay, n.state().epoch()); } }
            save_trees(&cfg, note_trees.as_ref());
            last_save = now;
        }

        // Reveals that arrived over the wire: handed to the settlers and
        // appended to the files, so a restart still knows them.
        if let Ok(mut ib) = inbox.lock() {
            if !ib.lines.is_empty() {
                for r in ib.zcash.drain(..) {
                    if let Some(s) = zcash_settler.as_mut() { s.add_reveal(r); }
                }
                for r in ib.solana.drain(..) {
                    if let Some(s) = settler.as_mut() { s.add_reveal(r); }
                }
                for (kind, line) in ib.lines.drain(..) {
                    let path = match kind {
                        "zcash" => cfg.zebra.as_ref().and_then(|z| z.settle.as_ref()).map(|st| st.reveals.clone()),
                        _ => cfg.solana.as_ref().and_then(|s| s.settle.as_ref()).map(|st| st.reveals.clone()),
                    };
                    if let Some(p) = path {
                        use std::io::Write;
                        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(&p) {
                            let _ = writeln!(f, "{}", line);
                        }
                    }
                    eprintln!("zynzapd: reveal received for a {} exit", kind);
                }
            }
        }
        let due = now.saturating_sub(last_scan) >= cfg.bridge_poll_secs;
        if let Some(s) = zcash_settler.as_mut() {
            if due {
                let r = s.poll_once(&shared, now);
                match &r {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: confirmed {} Zcash exit(s) on Zyn", n),
                    Err(e) => eprintln!("zynzapd: Zcash settlement pass failed: {}", e),
                }
                alerter.report("zcash exits", now, r.map(|_| 0));
            }
        }
        if let Some(a) = anchor_settler.as_mut() {
            if due {
                let r = a.poll_once(&shared, now);
                match &r {
                    Ok(Some(c)) => {
                        eprintln!(
                            "zynzapd: anchor for epoch {} CONFIRMED on Zcash in {} at height {} — root {} is now something anyone can check",
                            c.anchor.checkpoint.epoch,
                            c.txid,
                            c.height,
                            c.anchor.checkpoint.state_root.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                        );
                        { zynzapd::boot::save(&store, &journal, &shared); if let Ok(n) = shared.lock() { zynzapd::boot::save_replay(&cfg.data_dir, cfg.chain_id, &replay, n.state().epoch()); } }
                        // The bundle: what lets anyone else check that root.
                        let built = shared
                            .lock()
                            .map_err(|_| "node lock poisoned".to_string())
                            .and_then(|n| zynzapd::publish::bundle_for(&n, &cfg.data_dir, cfg.chain_id, &c.anchor, &c.txid, c.height))
                            .and_then(|b| zynzapd::publish::write_local(&cfg.da_dir, cfg.chain_id, &b));
                        match built {
                            Ok(files) => {
                                eprintln!("zynzapd: DA bundle for epoch {} written ({} files)", c.anchor.checkpoint.epoch, files.len());
                                publisher.queue(files);
                            }
                            Err(e) => eprintln!("zynzapd: DA BUNDLE NOT WRITTEN for epoch {}: {}", c.anchor.checkpoint.epoch, e),
                        }
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("zynzapd: anchor pass failed: {}", e),
                }
                // A pass that succeeded while an anchor sits unendorsed is
                // not health: it is the state in which no deposit becomes
                // spendable. Fold that in so it alerts rather than logging
                // every tenth pass into a journal nobody is reading.
                // A lineage resting on an anchor that has left the chain is
                // the most serious of the three: the pass may well succeed and
                // the endorsements be fine while nothing built since can be
                // verified by anyone (§50.1).
                let health = match a.lineage_health() {
                    Err(e) => Err(e),
                    Ok(()) => match a.endorsement_health(cfg.endorse_stall_passes) {
                        Err(e) => Err(e),
                        Ok(()) => r.map(|_| 0),
                    },
                };
                alerter.report("anchors", now, health);
                // Publish the proposal's bundle as soon as it is broadcast, so
                // signers can verify and endorse before it settles. Idempotent:
                // the index takes each epoch once, the files are rewritten (the
                // certificate fills in once endorsements arrive / it settles).
                if manual {
                    let parts = shared.lock().ok().and_then(|n| {
                        let a = *n.proposed()?;
                        let snap = n.proposal_snapshot()?;
                        let txid = a_settler_txid(&anchor_settler, a.id());
                        Some((a, snap, txid))
                    });
                    if let Some((a, snap, txid)) = parts {
                        let epoch = a.checkpoint.epoch;
                        let on_disk = cfg.da_dir.join(zynzapd::publish::rel_dir(cfg.chain_id, epoch)).join("anchor.bin").exists();
                        if !on_disk {
                            let built = shared
                                .lock()
                                .map_err(|_| "node lock poisoned".to_string())
                                // Flush the journal first: the bundle is read
                                // back off disk, and an epoch still buffered
                                // would publish without its seal.
                                .inspect(|_| { if let Ok(mut j) = journal.lock() { let _ = j.sync(); } })
                                .and_then(|n| zynzapd::publish::proposed_bundle(&n, &cfg.data_dir, cfg.chain_id, &a, &snap, &txid))
                                .and_then(|b| zynzapd::publish::write_local(&cfg.da_dir, cfg.chain_id, &b));
                            match built {
                                Ok(files) => { eprintln!("zynzapd: proposed bundle for epoch {} published for endorsement ({} files)", epoch, files.len()); publisher.queue(files); }
                                Err(e) => eprintln!("zynzapd: could not publish the proposed bundle for epoch {}: {}", epoch, e),
                            }
                        }
                    }
                }
                if !publisher.mirrors().is_empty() && publisher.pending_len() > 0 {
                    let r = publisher.poll_once();
                    match &r {
                        Ok(0) => {}
                        Ok(n) => eprintln!("zynzapd: {} DA file(s) mirrored", n),
                        Err(e) => eprintln!("zynzapd: DA mirroring incomplete: {}", e),
                    }
                    alerter.report("da mirrors", now, r.map(|n| n as u64));
                }
            }
        }
        if let Some(s) = settler.as_mut() {
            if due {
                let r = s.poll_once(&shared, now);
                match &r {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: confirmed {} exit(s) on Zyn", n),
                    // Same posture as a failed deposit scan: nothing was
                    // burned, nothing was sent twice, try again next pass.
                    Err(e) => eprintln!("zynzapd: settlement pass failed: {}", e),
                }
                alerter.report("solana exits", now, r.map(|_| 0));
            }
        }
        if !deposits.is_empty() && now.saturating_sub(last_scan) >= cfg.bridge_poll_secs {
            last_scan = now;
            for b in deposits.iter_mut() {
                let r = b.poll_once(&shared, now);
                match &r {
                    Ok(0) => {}
                    Ok(n) => eprintln!("zynzapd: credited {} deposit(s)", n),
                    // A node that is down or slow is the ordinary case, not a
                    // reason to stop sequencing — and not a reason to skip the
                    // *other* chains either. The watcher makes no progress on
                    // failure, so the next scan repeats the same range.
                    Err(e) => eprintln!("zynzapd: deposit scan failed: {}", e),
                }
                alerter.report(b.name(), now, r.map(|_| b.scanned_to()));
            }
            if let Ok(mut h) = health.lock() {
                let mut all = alerter.health();
                if cfg.feeds {
                    if let Ok(fh) = feed_health.lock() {
                        all.push(alert::Health {
                            name: "price feeds".to_string(),
                            scanned_to: fh.posted,
                            last_ok: fh.last_ok,
                            failures: fh.failures,
                            last_error: fh.last_error.clone(),
                            down: fh.failures >= 3,
                        });
                    }
                }
                *h = all;
            }
        }
    }

    // Seal what is in flight before going, so a restart resumes on an epoch
    // boundary rather than mid-epoch.
    eprintln!("zynzapd: stopping");
    if let Ok(mut n) = shared.lock() {
        let now = now_secs();
        n.seal_now(now);
        if !manual {
            n.anchor_now(now);
        }
    }
    { zynzapd::boot::save(&store, &journal, &shared); if let Ok(n) = shared.lock() { zynzapd::boot::save_replay(&cfg.data_dir, cfg.chain_id, &replay, n.state().epoch()); } }
    save_trees(&cfg, note_trees.as_ref());
    eprintln!("zynzapd: state saved, exiting");
    Ok(())
}
