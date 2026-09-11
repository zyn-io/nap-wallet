//! Scan a block range and report what was actually readable.
//!
//! A scanner that silently skips every transaction and a scanner that finds
//! nothing look identical from the outside. This tells them apart.
//!
//! ```text
//! cargo run -p zyn-custody --example scan-report -- <from> <count> [port]
//! ```

use zyn_custody::shielded::{ScanError, VaultKeys};
use zyn_custody::zebra::{Network, Zebra};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let from: u64 = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(500_000);
    let count: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
    let port: u16 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(18232);

    let zebra = Zebra::connect("127.0.0.1", port, None, Network::Testnet).expect("client");
    let keys = VaultKeys::from_spending_key([1u8; 32]).expect("key");

    let (mut blocks, mut txs, mut parsed, mut undecodable, mut ours) = (0, 0, 0, 0, 0);
    for h in from..from + count {
        let ids = match zebra.block_txids(h) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("height {}: {}", h, e);
                break;
            }
        };
        blocks += 1;
        for id in ids {
            txs += 1;
            let Ok(raw) = zebra.raw_transaction_bytes(&id) else { continue };
            match keys.scan_transaction(&raw, [0u8; 32], h) {
                Ok(d) => {
                    parsed += 1;
                    ours += d.len();
                }
                Err(ScanError::Undecodable) => undecodable += 1,
                Err(ScanError::UnaddressedDeposit(_)) => parsed += 1,
            }
        }
    }

    println!("blocks {}..{}", from, from + blocks);
    println!("  transactions seen   {}", txs);
    println!("  parsed              {}", parsed);
    println!("  undecodable         {}", undecodable);
    println!("  deposits to us      {}", ours);
    if txs > 0 && parsed == 0 {
        println!("\nEVERY transaction was unreadable — the scanner is not working.");
    }
}
