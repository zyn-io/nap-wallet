//! `zyn-dkg` — a distributed key-generation ceremony, so the vault key is
//! never whole in one place, not even at creation.
//!
//! One relay and N participants. The relay forwards round-one broadcasts
//! (public) and round-two packages (ciphertext it cannot open); each
//! participant runs the three FROST rounds locally and writes its one share.
//!
//! ```text
//!   zyn-dkg relay <participants>                    ZYN_DKG_LISTEN (0.0.0.0:8120)
//!   zyn-dkg join  <relay host:port> <my-index> <threshold> <participants> <out-dir>
//! ```
//!
//! Each participant ends with a share dir (`share-*.bin` + `public.bin`) — the
//! input to `zyn-custodian`. No dir ever holds more than one share, and the
//! relay holds none.

use std::sync::{Arc, Mutex};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("relay") => {
            let n: usize = a.get(2).and_then(|s| s.parse().ok()).unwrap_or_else(|| die("relay <participants>"));
            let listen = std::env::var("ZYN_DKG_LISTEN").unwrap_or_else(|_| "0.0.0.0:8120".into());
            let listener = std::net::TcpListener::bind(&listen).unwrap_or_else(|e| die(&format!("bind {}: {}", listen, e)));
            eprintln!("zyn-dkg: relay on {} for {} participants — it forwards public broadcasts and sealed round-two packages, and holds no share", listen, n);
            zyn_custody::dkg_net::net::serve(Arc::new(Mutex::new(zyn_custody::dkg_net::net::Relay::new(n))), listener);
        }
        Some("join") if a.len() == 7 => {
            let relay = &a[2];
            let idx: u16 = a[3].parse().unwrap_or_else(|_| die("index"));
            let threshold: u16 = a[4].parse().unwrap_or_else(|_| die("threshold"));
            let participants: u16 = a[5].parse().unwrap_or_else(|_| die("participants"));
            let out = std::path::PathBuf::from(&a[6]);
            eprintln!("zyn-dkg: joining as participant {} of {} (threshold {}) via {}", idx, participants, threshold, relay);
            let keys = zyn_custody::dkg_net::net::participate(relay, idx, threshold, participants).unwrap_or_else(|e| die(&e));
            std::fs::create_dir_all(&out).unwrap_or_else(|e| die(&e.to_string()));
            zyn_custody::shares::save::<zyn_custody::ceremony::Zcash>(&out, &[(*keys.key_package.identifier(), keys.clone())]).unwrap_or_else(|e| die(&e.to_string()));
            // The viewing key the settler/scanner needs, derived from the group.
            let group = keys.public_package.verifying_key();
            if let Some(fvk) = zyn_custody::ceremony::orchard_viewing_key(group, [0u8; 32], [0u8; 32]) {
                let _ = std::fs::write(out.join("viewing.hex"), fvk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>());
            }
            eprintln!("zyn-dkg: share written to {} — vault address is the group's; this box holds one share of {}", out.display(), participants);
        }
        // Reads a share dir's group viewing key and prints the vault's address.
        // Worth its own subcommand: the address has to be known and checked
        // *before* anyone funds it, and deriving it by hand from a hex blob at
        // the moment of funding is how a vault gets born on the wrong network.
        Some("address") if a.len() == 4 => {
            let dir = std::path::PathBuf::from(&a[2]);
            let network = match a[3].as_str() {
                "mainnet" | "main" => zcash_protocol::consensus::NetworkType::Main,
                "testnet" | "test" => zcash_protocol::consensus::NetworkType::Test,
                other => die(&format!("network must be mainnet or testnet, not {}", other)),
            };
            let hex = std::fs::read_to_string(dir.join("viewing.hex")).unwrap_or_else(|e| die(&format!("viewing.hex: {}", e)));
            let raw: Vec<u8> = hex
                .trim()
                .as_bytes()
                .chunks(2)
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("zz"), 16).unwrap_or_else(|_| die("viewing.hex is not hex")))
                .collect();
            let bytes: [u8; 96] = raw.as_slice().try_into().unwrap_or_else(|_| die("viewing key is not 96 bytes"));
            let fvk = orchard::keys::FullViewingKey::from_bytes(&bytes).unwrap_or_else(|| die("viewing key does not decode"));
            let keys = zyn_custody::shielded::VaultKeys::from_full_viewing_key(fvk);
            println!("{}", keys.address(0, network));
        }
        _ => {
            eprintln!("usage:\n  zyn-dkg relay <participants>\n  zyn-dkg join <relay host:port> <my-index> <threshold> <participants> <out-dir>\n  zyn-dkg address <share-dir> <mainnet|testnet>");
            std::process::exit(2);
        }
    }
}

fn die(m: &str) -> ! {
    eprintln!("zyn-dkg: {}", m);
    std::process::exit(1);
}
