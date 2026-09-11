//! `zyn-replica` — verifies the chain from Zcash and mirrors alone, and
//! serves what it verified.
//!
//! Holds the vault's *viewing* key and nothing that can spend. Every pass:
//! scan Zcash for the vault's anchor self-sends, fetch each anchor's bundle
//! from a mirror, replay the intents from the last verified state, check the
//! root, publish. On any contradiction it stops advancing and keeps serving
//! the last root it proved.
//!
//! ```text
//!   ZYN_CHAIN_ID            the chain                        (1)
//!   ZYN_LISTEN              RPC, read-only                   (127.0.0.1:8100)
//!   ZYN_DATA_DIR            verified state, ledger, bundles  (./zyn-replica)
//!   ZYN_DA_MIRRORS          comma-separated base URLs to GET bundles from
//!   ZYN_DA_LISTEN           optional: re-serve verified bundles over HTTP GET
//!   ZYN_VAULT_FVK           the vault's Orchard full viewing key, hex
//!   ZYN_ZEBRA_HOST/PORT/USER/PASS   a Zcash node to read (testnet)
//!   ZYN_CONFIRMATIONS       depth before an anchor counts   (10)
//!   ZYN_BRIDGE_FROM_HEIGHT  first height that can hold an anchor
//!   ZYN_SEQUENCER           where writes should go; quoted in refusals
//!   ZYN_PARAMS              v1 | testnet                     (testnet)
//!   ZYN_POLL_SECS           seconds between passes          (30)
//!   ZYN_BASE_ROOT           for a chain older than its journal: the root of
//!                           chain-<id>/base.state on the mirror, as announced
//!   ZYN_SIGNER_KEY          ed25519 seed (hex): endorse each verified anchor
//!   ZYN_ENDORSE_TO          the sequencer's address to send endorsements to
//!   ZYN_SIGNER_SET          hex pubkeys (comma): only believe endorsed roots
//!   ZYN_SIGNER_THRESHOLD    how many of the set must endorse (default majority)
//!   ZYN_ALERT_URL           optional webhook for halts
//! ```

use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use swapvm::Params;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_custody::shielded::{Scanner, VaultKeys};
use zyn_custody::zebra::{Network, Zebra};
use zynzapd::replica::{sighting_from, Http, Replica};
use zynzapd::{alert, publish, rpc};

fn var(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_string())
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zyn-replica: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let chain_id: u32 = var("ZYN_CHAIN_ID", "1").parse().map_err(|_| "ZYN_CHAIN_ID")?;
    let listen = var("ZYN_LISTEN", "127.0.0.1:8100");
    let data_dir = std::path::PathBuf::from(var("ZYN_DATA_DIR", "./zyn-replica"));
    let mirrors: Vec<String> = var("ZYN_DA_MIRRORS", "").split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect();
    if mirrors.is_empty() {
        return Err("ZYN_DA_MIRRORS is required: at least one base URL to fetch bundles from".into());
    }
    let fvk_hex = std::env::var("ZYN_VAULT_FVK").map_err(|_| "ZYN_VAULT_FVK is required (the vault's full viewing key, 96 bytes hex)")?;
    let fvk_bytes = unhex(&fvk_hex).filter(|b| b.len() == 96).ok_or("ZYN_VAULT_FVK must be 96 bytes of hex")?;
    let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes.try_into().expect("96 bytes")).ok_or("ZYN_VAULT_FVK is not a valid Orchard full viewing key")?;
    let host = var("ZYN_ZEBRA_HOST", "127.0.0.1");
    let port: u16 = var("ZYN_ZEBRA_PORT", "18232").parse().map_err(|_| "ZYN_ZEBRA_PORT")?;
    let user = std::env::var("ZYN_ZEBRA_USER").ok();
    let pass = std::env::var("ZYN_ZEBRA_PASS").ok();
    let auth = match (&user, &pass) {
        (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
        _ => None,
    };
    let zebra = Zebra::connect_reader(&host, port, auth, Network::Testnet).map_err(|e| e.to_string())?;
    let confirmations: u64 = var("ZYN_CONFIRMATIONS", "10").parse().map_err(|_| "ZYN_CONFIRMATIONS")?;
    let from_height: u64 = var("ZYN_BRIDGE_FROM_HEIGHT", "0").parse().map_err(|_| "ZYN_BRIDGE_FROM_HEIGHT")?;
    let sequencer = var("ZYN_SEQUENCER", "the sequencer");
    let params = match var("ZYN_PARAMS", "testnet").as_str() {
        "v1" => Params::v1(),
        _ => Params::testnet(),
    };
    let poll_secs: u64 = var("ZYN_POLL_SECS", "30").parse().map_err(|_| "ZYN_POLL_SECS")?;
    let signer_key: Option<ed25519_dalek::SigningKey> = match std::env::var("ZYN_SIGNER_KEY").ok().filter(|s| !s.is_empty()) {
        None => None,
        Some(h) => {
            let seed: [u8; 32] = unhex(&h).and_then(|b| b.try_into().ok()).ok_or("ZYN_SIGNER_KEY must be 32 bytes of hex")?;
            Some(ed25519_dalek::SigningKey::from_bytes(&seed))
        }
    };
    let endorse_to = std::env::var("ZYN_ENDORSE_TO").ok().filter(|s| !s.is_empty());
    let require_set: Option<zyn::anchor::SignerSet> = match std::env::var("ZYN_SIGNER_SET").ok().filter(|s| !s.is_empty()) {
        None => None,
        Some(list) => {
            let mut keys = Vec::new();
            for hh in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                keys.push(unhex(hh).and_then(|b| b.try_into().ok()).ok_or("ZYN_SIGNER_SET keys must be 32 bytes of hex")?);
            }
            let t: usize = var("ZYN_SIGNER_THRESHOLD", "0").parse().map_err(|_| "ZYN_SIGNER_THRESHOLD")?;
            let t = if t == 0 { keys.len() / 2 + 1 } else { t };
            Some(zyn::anchor::SignerSet::new(keys, t).map_err(|e| format!("ZYN_SIGNER_SET: {}", e))?)
        }
    };

    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    let fetch = Http::new(mirrors.clone());
    let base = match std::env::var("ZYN_BASE_ROOT").ok().filter(|s| !s.is_empty()) {
        Some(hex_root) => {
            let root: [u8; 32] = unhex(&hex_root).and_then(|b| b.try_into().ok()).ok_or("ZYN_BASE_ROOT must be 32 bytes of hex")?;
            let bytes = zynzapd::replica::Fetch::get(&fetch, &format!("chain-{}/base.state", chain_id)).map_err(|e| format!("cannot fetch the base state: {}", e))?;
            Some((bytes, root))
        }
        None => None,
    };
    let mut replica = Replica::open_from(&data_dir, chain_id, params, base.as_ref().map(|(b, r)| (b.as_slice(), *r)))?;
    if let Some(set) = require_set {
        replica = replica.requiring(set);
        eprintln!("zyn-replica: only roots this replica reproduces AND the signer set endorses will be believed");
    }
    // Reproducing a root proves the sequencer computed honestly over what it
    // published. Whether the deposits behind it exist is a different question,
    // and only a node this process trusts can answer it. Off by default: a
    // replica pointed at somebody else's node would be asking the party it is
    // checking, which is worse than not asking.
    let verify = std::env::var("ZYN_VERIFY_DEPOSITS").unwrap_or_default();
    if verify == "1" || verify == "strict" {
        // `strict` also refuses a memo-less credit at the vault's own address
        // — change dressed as a deposit. Only correct once every deposit
        // arrives at its account's own address, so it is opt-in separately.
        let strict = verify == "strict";
        let backing = zynzapd::backing::ZcashBacking::new(
            Zebra::connect_reader(&host, port, auth.clone(), Network::Testnet).map_err(|e| e.to_string())?,
            VaultKeys::from_full_viewing_key(fvk.clone()),
            confirmations,
            swapvm::types::XZEC,
        )
        .strict(strict);
        replica = replica.backed_by(Box::new(backing));
        eprintln!(
            "zyn-replica: deposits are checked against THIS node — a credit it cannot see is refused, not endorsed{}",
            if strict { "; STRICT: a credit whose owner only the operator can vouch for is refused too" } else { "" }
        );
    }
    if let Some(k) = &signer_key {
        let pk = k.verifying_key().to_bytes();
        eprintln!("zyn-replica: SIGNER — endorsing verified anchors as {} to {}", pk.iter().map(|b| format!("{:02x}", b)).collect::<String>(), endorse_to.as_deref().unwrap_or("(no ZYN_ENDORSE_TO set!)"));
    }
    eprintln!(
        "zyn-replica: chain {} — verified through epoch {} at height {}; {} mirror(s); Zebra at {}:{}",
        chain_id,
        replica.verified_epoch.map(|e| e.to_string()).unwrap_or_else(|| "none".into()),
        replica.verified_height,
        mirrors.len(),
        host,
        port
    );

    // The read side: a node holding the verified state, never sealing.
    let never = EpochPolicy { intents_per_epoch: u64::MAX, epochs_per_anchor: u64::MAX, max_seconds_per_epoch: 0, max_seconds_per_anchor: 0 };
    let mut node = Node::resume(replica.state().clone(), never, Economics::flat(0), now_secs());
    if let Some(s) = replica.snapshot() {
        node.set_published(s.clone());
    }
    let shared: rpc::Shared = Arc::new(Mutex::new(node));
    let verified = Arc::new(Mutex::new((replica.verified_epoch, replica.verified_height)));
    let forced_counts = Arc::new(Mutex::new((replica.forced_pending().len() as u32, replica.censored().len() as u32)));
    let health: Arc<Mutex<Vec<alert::Health>>> = Arc::new(Mutex::new(Vec::new()));
    let server = Arc::new(rpc::Server {
        node: Arc::clone(&shared),
        chain_id,
        now: now_secs,
        health: Arc::clone(&health),
        inbox: Arc::new(Mutex::new(rpc::Inbox::default())),
        replica: Some(rpc::ReplicaInfo { sequencer: sequencer.clone(), verified: Arc::clone(&verified), forced: Arc::clone(&forced_counts) }),
        replay: Arc::new(Mutex::new(zyn::replay::ReplayIndex::default())),
        // A replica issues nothing: it verifies what the sequencer credited.
        deposits: None,
        // Its own DA copy, so the epoch-to-Zcash mapping can be read from
        // something that never sequenced anything.
        da_dir: Some(replica.da_dir()),
    });
    let listener = TcpListener::bind(&listen).map_err(|e| format!("cannot bind {}: {}", listen, e))?;
    eprintln!("zyn-replica: read-only RPC on {} (writes are refused and pointed at {})", listen, sequencer);
    std::thread::spawn(move || rpc::serve(server, listener));
    if let Ok(da_listen) = std::env::var("ZYN_DA_LISTEN") {
        let l = TcpListener::bind(&da_listen).map_err(|e| format!("cannot bind {}: {}", da_listen, e))?;
        let dir = replica.da_dir();
        eprintln!("zyn-replica: re-serving verified bundles on {}", da_listen);
        std::thread::spawn(move || publish::http::serve(dir, l, None));
    }

    let mut alerter = alert::Alerter::new(std::env::var("ZYN_ALERT_URL").ok().as_deref().map(alert::Webhook::new), chain_id);
    let scanner = Scanner::new(VaultKeys::from_full_viewing_key(fvk), from_height, 200);
    let mut scanned_to = replica.verified_height.max(from_height.saturating_sub(1));

    loop {
        let now = now_secs();
        let pass: Result<u64, String> = (|| {
            if let Some(h) = &replica.halted {
                return Err(format!("HALTED: {}", h));
            }
            let tip = zebra.block_count().map_err(|e| e.to_string())?;
            let safe = tip.saturating_sub(confirmations);
            if safe <= scanned_to {
                return Ok(scanned_to);
            }
            // Forced intents first, so an anchor verified in the same pass is
            // held to them.
            let (_, forced) = scanner.forced(&zebra, scanned_to + 1, safe).map_err(|e| format!("scan: {:?}", e))?;
            let noted = replica.note_forced(&forced);
            if noted > 0 {
                eprintln!("zyn-replica: {} forced intent(s) seen on Zcash; the sequencer has {} blocks to apply each", noted, zynzapd::replica::FORCED_GRACE);
            }
            let (to, sightings) = scanner.anchors(&zebra, scanned_to + 1, safe).map_err(|e| format!("scan: {:?}", e))?;
            let parsed: Vec<_> = sightings.iter().filter_map(sighting_from).collect();
            if !parsed.is_empty() {
                let p = replica.apply_sightings(&parsed, &fetch).map_err(|h| format!("HALTED: {}", h))?;
                if p.verified > 0 {
                    let mut n = shared.lock().map_err(|_| "node lock poisoned".to_string())?;
                    *n = Node::resume(replica.state().clone(), never, Economics::flat(0), now);
                    if let Some(s) = replica.snapshot() {
                        n.set_published(s.clone());
                    }
                    if let Ok(mut v) = verified.lock() {
                        *v = (replica.verified_epoch, replica.verified_height);
                    }
                    eprintln!(
                        "zyn-replica: verified {} anchor(s); through epoch {} at height {} — root {}",
                        p.verified,
                        replica.verified_epoch.unwrap_or(0),
                        replica.verified_height,
                        replica.ledger().head_root().iter().map(|b| format!("{:02x}", b)).collect::<String>()
                    );
                }
            }
            // Endorse what was just verified: sign the anchor id this replica
            // reproduced, and send it to the sequencer. A signature is only
            // ever over a root this process replayed to.
            if let (Some(k), Some(to_addr)) = (&signer_key, &endorse_to) {
                use ed25519_dalek::Signer as _;
                let node = zynzapd::client::Node::new(to_addr, chain_id);
                for (anchor_id, _root) in replica.take_newly_verified() {
                    let sig = k.sign(&anchor_id).to_bytes();
                    match node.endorse(anchor_id, k.verifying_key().to_bytes(), sig) {
                        Ok((counted, clears)) => eprintln!(
                            "zyn-replica: endorsed anchor {} — {}{}",
                            anchor_id.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
                            if counted { "counted" } else { "not in the sequencer's set" },
                            if clears { ", certificate now clears" } else { "" }
                        ),
                        Err(e) => eprintln!("zyn-replica: could not send endorsement to {}: {}", to_addr, e),
                    }
                }
            } else {
                replica.take_newly_verified();
            }
            scanned_to = to;
            if let Ok(mut f) = forced_counts.lock() {
                *f = (replica.forced_pending().len() as u32, replica.censored().len() as u32);
            }
            Ok(to)
        })();
        if let Err(e) = &pass {
            eprintln!("zyn-replica: {}", e);
        }
        alerter.report("verification", now, pass);
        // Censorship is reported on what is happening *now*. The historical
        // record stays in `censored()` — an incident is not undone by age —
        // but an alarm that can never clear teaches its reader to ignore it,
        // and the next real one goes unread with it.
        let all = replica.censored();
        let current = all
            .iter()
            .filter(|c| scanned_to.saturating_sub(c.due_at) <= zynzapd::replica::CENSORSHIP_CURRENT)
            .count();
        alerter.report(
            "censorship",
            now,
            if current == 0 {
                // `scanned_to` carries the lifetime count, so a past incident
                // stays visible in `/signers` without paging anyone.
                Ok(all.len() as u64)
            } else {
                Err(format!("{} forced intent(s) the sequencer refused to apply", current))
            },
        );
        if let Ok(mut h) = health.lock() {
            *h = alerter.health();
        }
        std::thread::sleep(std::time::Duration::from_secs(poll_secs));
    }
}
