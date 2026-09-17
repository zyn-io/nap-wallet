//! Issue and manage Cave whitelist invitations.
//!
//! An invitation is an operator promise, good for up to N mints (§74.5 applies
//! here as it does to claim codes: the creator key can mint regardless, so this
//! is trusted by construction). The holder binds their own account the first
//! time they use it, so no addresses are collected in advance — which is both
//! what Zyn's privacy allows and what it requires.
//!
//! Environment:
//!   ZYN_WHITELIST  path to the registry file
//!
//! Usage:
//!   zyn-whitelist issue <count> <allocation>   print invitations, once
//!   zyn-whitelist open                         start accepting mints
//!   zyn-whitelist close                        stop accepting mints
//!   zyn-whitelist status                       what has been issued and taken

use std::path::PathBuf;

use zynzapd::whitelist::Registry;

/// Same alphabet as a claim code: no look-alike characters, so an invitation
/// survives being read aloud and typed on a phone.
fn fresh_code(rng: &mut impl rand::RngCore) -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    format!(
        "{}-{}-{}-{}",
        &body[0..5],
        &body[5..10],
        &body[10..15],
        &body[15..20]
    )
}

fn main() {
    let path = PathBuf::from(std::env::var("ZYN_WHITELIST").unwrap_or_default());
    if path.as_os_str().is_empty() {
        eprintln!("zyn-whitelist: set ZYN_WHITELIST to the registry's path");
        std::process::exit(2);
    }
    let mut reg = if path.exists() {
        Registry::load(&path).unwrap_or_else(|e| {
            eprintln!("zyn-whitelist: {}", e);
            std::process::exit(1);
        })
    } else {
        Registry::new()
    };
    reg.set_path(path.clone());

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("issue") => {
            let count: u32 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let allocation: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            if count == 0 || allocation == 0 {
                eprintln!("usage: zyn-whitelist issue <count> <allocation>");
                std::process::exit(2);
            }
            let mut rng = rand::rngs::OsRng;
            // Printed once. The registry keeps a fingerprint, so an invitation
            // lost here cannot be recovered and must be reissued as a new one.
            println!("# invitation\tallocation");
            for _ in 0..count {
                let code = fresh_code(&mut rng);
                reg.issue(&code, allocation);
                println!("{}\t{}", code, allocation);
            }
            save(&reg);
            let (issued, taken) = reg.totals();
            eprintln!(
                "zyn-whitelist: {} invitation(s) of {} — {} allocated in total, {} taken; \
                 the codes above are not stored",
                count, allocation, issued, taken
            );
        }
        Some(cmd @ ("open" | "close")) => {
            reg.open = cmd == "open";
            save(&reg);
            eprintln!(
                "zyn-whitelist: the whitelist phase is now {}",
                if reg.open { "OPEN" } else { "CLOSED" }
            );
        }
        Some("status") => {
            let (issued, taken) = reg.totals();
            let bound = reg.entries.values().filter(|e| e.bound_to.is_some()).count();
            println!("phase       {}", if reg.open { "open" } else { "closed" });
            println!("invitations {}", reg.entries.len());
            println!("bound       {}", bound);
            println!("allocated   {}", issued);
            println!("taken       {}", taken);
            println!("remaining   {}", issued.saturating_sub(taken));
        }
        _ => {
            eprintln!(
                "usage: zyn-whitelist issue <count> <allocation> | open | close | status"
            );
            std::process::exit(2);
        }
    }
}

fn save(reg: &Registry) {
    if let Err(e) = reg.persist() {
        eprintln!("zyn-whitelist: could not save: {}", e);
        std::process::exit(1);
    }
}
