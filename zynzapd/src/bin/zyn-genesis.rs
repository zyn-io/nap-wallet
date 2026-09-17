//! Put a chain's genesis objects on chain, signed by a threshold treasury.
//!
//! Genesis is a one-off, but it is not a script's worth of work: 338 intents
//! each need a 2-of-3 signature gathered over the network, and a run that dies
//! at intent 200 must not redo the first 200. So this is a program with a
//! resume point rather than a shell loop.
//!
//! It never holds a share. Each intent's payload goes to the custodians, which
//! return signature shares; this process assembles them and submits. That is
//! the same trust position the sequencer has — it can choose *what* to ask for,
//! and it cannot sign anything the custodians did not agree to.
//!
//! Environment:
//!   ZYN_GENESIS_NODE        node RPC `host:port`          (127.0.0.1:8099)
//!   ZYN_GENESIS_CHAIN       chain id                      (26460)
//!   ZYN_GENESIS_CUSTODIANS  comma-separated `host:port`, at least `threshold`
//!   ZYN_GENESIS_THRESHOLD   signatures required           (2)
//!   ZYN_GENESIS_TREASURY    directory holding public.bin
//!   ZYN_GENESIS_MANIFEST    content.json for the 333
//!
//! Usage:
//!   zyn-genesis plan     print every intent, contact nothing, sign nothing
//!   zyn-genesis run      submit, resuming from what is already on chain

use std::collections::BTreeMap;

use swapvm::tx::Intent;
use zynzapd::client::Node;

const NAPMOLE_SYMBOL: &str = "NAPMOLE";
const NAPMOLE_CAP: u32 = 333;
const CAVE_SYMBOL: &str = "CAVEZ";
const CAVE_CAP: u32 = 4444;
const FEE_BPS: u16 = 100;


/// Phase codes, from `swapvm::state::Phase::code`.
const PHASE_MINTING: u8 = 1;
const PHASE_CLOSED: u8 = 2;

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

/// One manifest entry.
///
/// `serial` and the display number differ by one on purpose: the VM requires
/// `serial < cap`, so a 333-item collection occupies serials 0..=332, while
/// collectors count from one. `MOLE001` is therefore serial 0. Binding the two
/// here, once, is what keeps the off-by-one out of everything downstream.
struct Item {
    serial: u32,
    /// What a collector calls it: 1..=333.
    number: u32,
    symbol: String,
    content: [u8; 32],
}

fn load_manifest(path: &str) -> Result<Vec<Item>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    // content.json is `{"0001": {"content": "<64 hex>", ...}, ...}`. Only the
    // content commitment is consensus-visible; names and media live in the
    // manifest the commitment covers.
    let mut out = Vec::new();
    for serial in 1..=NAPMOLE_CAP {
        let key = format!("\"{:04}\"", serial);
        let at = raw
            .find(&key)
            .ok_or_else(|| format!("manifest has no entry {:04}", serial))?;
        let rest = &raw[at..];
        let ct = rest
            .find("\"content\"")
            .ok_or_else(|| format!("entry {:04} has no content", serial))?;
        let after = &rest[ct + "\"content\"".len()..];
        let q1 = after.find('"').ok_or("malformed content")? + 1;
        let q2 = after[q1..].find('"').ok_or("malformed content")? + q1;
        let hex = &after[q1..q2];
        if hex.len() != 64 {
            return Err(format!("entry {:04}: content is not 32 bytes", serial));
        }
        let mut content = [0u8; 32];
        for (i, b) in content.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("entry {:04}: content is not hex", serial))?;
        }
        out.push(Item {
            serial: serial - 1,
            number: serial,
            symbol: format!("MOLE{:03}", serial),
            content,
        });
    }
    Ok(out)
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode != "plan" && mode != "run" {
        eprintln!("usage: zyn-genesis plan|run");
        std::process::exit(2);
    }

    let chain: u32 = env("ZYN_GENESIS_CHAIN", "26460").parse().expect("chain id");
    let treasury_dir = env("ZYN_GENESIS_TREASURY", "");
    let manifest = env("ZYN_GENESIS_MANIFEST", "");
    if treasury_dir.is_empty() || manifest.is_empty() {
        eprintln!("zyn-genesis: set ZYN_GENESIS_TREASURY and ZYN_GENESIS_MANIFEST");
        std::process::exit(2);
    }

    let public = match zyn_custody::shares::load_public::<zyn_custody::treasury::ZynAccount>(
        std::path::Path::new(&treasury_dir),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("zyn-genesis: cannot read {}/public.bin: {}", treasury_dir, e);
            std::process::exit(1);
        }
    };
    let treasury = zyn_custody::treasury::account_of_group(&public).expect("treasury account");

    let scope = zyn_vm::derive::ADDRESS_SCOPE_V1;
    let napmole = zyn_vm::collection_address(scope, &treasury, NAPMOLE_SYMBOL.as_bytes());
    let cave = zyn_vm::collection_address(scope, &treasury, CAVE_SYMBOL.as_bytes());

    let items = match load_manifest(&manifest) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("zyn-genesis: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("zyn-genesis: chain {}", chain);
    eprintln!("zyn-genesis: treasury   {}", hex32(&treasury));
    eprintln!(
        "zyn-genesis: {} {}  cap {}  fee {} bps",
        NAPMOLE_SYMBOL,
        hex32(&napmole),
        NAPMOLE_CAP,
        FEE_BPS
    );
    eprintln!(
        "zyn-genesis: {}   {}  cap {}  fee {} bps",
        CAVE_SYMBOL,
        hex32(&cave),
        CAVE_CAP,
        FEE_BPS
    );

    if mode == "plan" {
        eprintln!("zyn-genesis: --- plan, nothing contacted, nothing signed ---");
        eprintln!("  1. CreateCollection  {} cap {}", NAPMOLE_SYMBOL, NAPMOLE_CAP);
        eprintln!("  2. CreateCollection  {} cap {}", CAVE_SYMBOL, CAVE_CAP);
        eprintln!("  3. AdvanceCollection {} -> Minting", NAPMOLE_SYMBOL);
        eprintln!("  4. AdvanceCollection {} -> Minting", CAVE_SYMBOL);
        eprintln!(
            "  5..{}. MintCollectionItem {} serials 0..{} (MOLE001..MOLE{:03}) to the treasury",
            4 + NAPMOLE_CAP,
            NAPMOLE_SYMBOL,
            NAPMOLE_CAP - 1,
            NAPMOLE_CAP
        );
        eprintln!("  {}. AdvanceCollection {} -> Closed", 5 + NAPMOLE_CAP, NAPMOLE_SYMBOL);
        eprintln!("zyn-genesis: first  item {} content {}", items[0].symbol, hex32(&items[0].content));
        eprintln!(
            "zyn-genesis: last   item {} content {}",
            items[NAPMOLE_CAP as usize - 1].symbol,
            hex32(&items[NAPMOLE_CAP as usize - 1].content)
        );
        eprintln!("zyn-genesis: {} stays in Minting — its items are minted on demand", CAVE_SYMBOL);
        eprintln!(
            "zyn-genesis: ZYN is issued by the node at its genesis, not here \
             (native assets are operator-only)"
        );
        eprintln!("zyn-genesis: {} intents total", 5 + NAPMOLE_CAP);
        return;
    }

    let node = env("ZYN_GENESIS_NODE", "127.0.0.1:8099");
    let threshold: usize = env("ZYN_GENESIS_THRESHOLD", "2").parse().expect("threshold");
    let custodians: Vec<String> = env("ZYN_GENESIS_CUSTODIANS", "")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    if custodians.len() < threshold {
        eprintln!(
            "zyn-genesis: {} custodian(s) named but threshold is {}",
            custodians.len(),
            threshold
        );
        std::process::exit(2);
    }

    let client = Node::new(&node, chain);
    eprintln!("zyn-genesis: node {}  custodians {:?}", node, custodians);

    // What is already on chain decides where this run starts. A resumed run
    // must not re-submit: a duplicate serial is rejected, but a duplicate
    // CreateCollection would be too, and a run that treats rejection as fatal
    // could never resume at all.
    let seen: BTreeMap<[u8; 32], (u8, u32)> = match client.collections() {
        Ok(cs) => cs
            .iter()
            .map(|c: &zynzapd::client::CollectionView| (c.id, (c.phase, c.minted)))
            .collect(),
        Err(e) => {
            eprintln!("zyn-genesis: cannot read collections: {}", e);
            std::process::exit(1);
        }
    };

    let mut request_id: u64 = 1;
    let mut submitted = 0usize;
    let mut skipped = 0usize;

    let send = |intent: Intent, what: &str, rid: &mut u64| {
        let epoch = match client.status() {
            Ok(s) => s.epoch,
            Err(e) => {
                eprintln!("zyn-genesis: cannot read epoch: {}", e);
                std::process::exit(1);
            }
        };
        let frame = match zynzapd::treasury::frame_submission_across(
            &custodians,
            &public,
            threshold,
            chain,
            epoch,
            &intent,
            *rid,
        ) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("zyn-genesis: {} — signing failed: {}", what, e);
                std::process::exit(1);
            }
        };
        *rid += 1;
        match client.submit_raw(&frame) {
            Ok(_) => eprintln!("zyn-genesis: {} ok", what),
            Err(e) => {
                eprintln!("zyn-genesis: {} REJECTED: {}", what, e);
                std::process::exit(1);
            }
        }
    };

    // ZYN is not issued here. It is the chain's *native* asset, and native
    // addresses are operator-only by design — `is_official_asset` decides
    // officialdom by address, and that guarantee holds only because no account
    // can derive one. So the node issues ZYN at its own genesis, and this
    // driver, which speaks for an account, cannot and should not.

    // 1-2. Create both collections.
    for (sym, cap, id) in [
        (NAPMOLE_SYMBOL, NAPMOLE_CAP, napmole),
        (CAVE_SYMBOL, CAVE_CAP, cave),
    ] {
        if seen.contains_key(&id) {
            eprintln!("zyn-genesis: {} already exists — skipping create", sym);
            skipped += 1;
            continue;
        }
        send(
            Intent::CreateCollection {
                creator: treasury,
                symbol: swapvm::state::symbol(sym.as_bytes()),
                cap,
                fee_bps: FEE_BPS,
            },
            &format!("create {}", sym),
            &mut request_id,
        );
        submitted += 1;
    }

    // 3-4. Both to Minting. Minting is what MintCollectionItem requires, and
    // it is also where Cave stays: its items are minted as they are bought.
    for (sym, id) in [(NAPMOLE_SYMBOL, napmole), (CAVE_SYMBOL, cave)] {
        if seen.get(&id).map(|(p, _)| *p >= PHASE_MINTING) == Some(true) {
            eprintln!("zyn-genesis: {} already past Depositing — skipping advance", sym);
            skipped += 1;
            continue;
        }
        send(
            Intent::AdvanceCollection {
                creator: treasury,
                collection: id,
                to: PHASE_MINTING,
            },
            &format!("advance {} -> Minting", sym),
            &mut request_id,
        );
        submitted += 1;
    }

    // 5..337. The 333, in serial order. Minting in order is what makes the
    // `minted` count a valid resume point: it says serials 1..minted are done.
    let already = seen.get(&napmole).map(|(_, m)| *m).unwrap_or(0);
    if already > 0 {
        eprintln!("zyn-genesis: resuming — {} of {} already minted", already, NAPMOLE_CAP);
    }
    for item in items.iter().filter(|i| i.number > already) {
        send(
            Intent::MintCollectionItem {
                creator: treasury,
                collection: napmole,
                serial: item.serial,
                to: treasury,
                symbol: swapvm::state::symbol(item.symbol.as_bytes()),
                content: item.content,
            },
            &format!("mint {} (serial {}, {}/{})", item.symbol, item.serial, item.number, NAPMOLE_CAP),
            &mut request_id,
        );
        submitted += 1;
    }
    skipped += already as usize;

    // 338. Close the 333. The cap is reached, so the denominator is final.
    if seen.get(&napmole).map(|(p, _)| *p >= PHASE_CLOSED) == Some(true) {
        eprintln!("zyn-genesis: {} already closed — skipping", NAPMOLE_SYMBOL);
        skipped += 1;
    } else {
        send(
            Intent::AdvanceCollection {
                creator: treasury,
                collection: napmole,
                to: PHASE_CLOSED,
            },
            &format!("advance {} -> Closed", NAPMOLE_SYMBOL),
            &mut request_id,
        );
        submitted += 1;
    }

    eprintln!("zyn-genesis: {} submitted, {} already on chain", submitted, skipped);

    // Say what is actually there now, rather than what was intended.
    match client.collections() {
        Ok(cs) => {
            for c in cs {
                eprintln!(
                    "zyn-genesis: on chain — {} {} phase {} minted {}/{}",
                    c.symbol,
                    hex32(&c.id),
                    c.phase,
                    c.minted,
                    c.cap
                );
            }
        }
        Err(e) => eprintln!("zyn-genesis: could not read back state: {}", e),
    }
}
