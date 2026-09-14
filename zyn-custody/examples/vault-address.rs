//! Print a vault's deposit address, for pointing a faucet at.
//!
//! ```text
//! cargo run -p zyn-custody --example vault-address -- <32-byte-hex-seed> [index]
//! ```
//!
//! The seed is a **testnet** spending key. In production the spending
//! authority is split by FROST and never exists in one place; this exists so a
//! testnet vault can be funded from a faucet without a ceremony first.

use zyn_custody::shielded::VaultKeys;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seed = args.get(1).map(String::as_str).unwrap_or(
        // A fixed, obviously-not-secret default, so the command works with no
        // arguments and nobody is tempted to reuse it for anything real.
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let index: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut bytes = [0u8; 32];
    if seed.len() != 64 {
        eprintln!("seed must be 64 hex characters");
        std::process::exit(1);
    }
    for i in 0..32 {
        match u8::from_str_radix(&seed[i * 2..i * 2 + 2], 16) {
            Ok(b) => bytes[i] = b,
            Err(_) => {
                eprintln!("seed must be hex");
                std::process::exit(1);
            }
        }
    }

    match VaultKeys::from_spending_key(bytes) {
        None => {
            eprintln!("those bytes are not a valid Orchard spending key; try another seed");
            std::process::exit(1);
        }
        Some(k) => {
            // Testnet unless asked otherwise, like everything else here.
            let mainnet = matches!(
                std::env::var("ZYN_NETWORK").as_deref(),
                Ok("mainnet") | Ok("main")
            );
            let network = if mainnet {
                zcash_protocol::consensus::NetworkType::Main
            } else {
                zcash_protocol::consensus::NetworkType::Test
            };
            println!("index   {}", index);
            println!("network {}", if mainnet { "MAINNET" } else { "testnet" });
            println!("address {}", k.address(index, network));
            println!();
            println!("Orchard-only unified address. Send shielded TAZ to it with a");
            println!("memo of  \"ZYN\" | version | account[32]  — see zyn_custody::memo.");
        }
    }
}
