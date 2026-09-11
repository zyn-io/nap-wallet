//! `zyn-ceremony solana <threshold> <participants> <dir>`
//! `zyn-ceremony zcash  <threshold> <participants> <dir>`
//!
//! Runs a distributed key generation in-process and writes one share file per
//! participant plus the public package. Prints the vault's address.
//!
//! For Zcash it also generates the viewing components the ceremony cannot
//! (`nk`, `rivk` — see `ceremony::orchard_viewing_key`) and writes the full
//! viewing key to `viewing.hex`: that is `ZYN_VAULT_FVK`, the key the scanner
//! watches with and the settler spends under. Without it the shares can sign
//! and never find anything to sign for.
//!
//! In-process means every share is born on this machine. For a real vault each
//! participant runs their own round on their own machine and the files are
//! never together; what this produces is a devnet key in several pieces, and
//! it is labelled that way so a testnet demo cannot be mistaken for custody.

use rand::rngs::OsRng;
use rand::RngCore;
use zyn_custody::ceremony::{orchard_viewing_key, Ceremony, Zcash};
use zyn_custody::solana::custody::{ceremony, vault_address, Id, Keys};
use zyn_custody::solana::base58_encode;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || !matches!(args[1].as_str(), "solana" | "zcash") {
        eprintln!("usage: zyn-ceremony <solana|zcash> <threshold> <participants> <dir>");
        std::process::exit(2);
    }
    let threshold: u16 = args[2].parse().expect("threshold");
    let participants: u16 = args[3].parse().expect("participants");
    let dir = std::path::PathBuf::from(&args[4]);

    match args[1].as_str() {
        "solana" => {
            let keys: Vec<(Id, Keys)> = match ceremony(threshold, participants, &mut OsRng) {
                Ok(k) => k.into_iter().collect(),
                Err(e) => {
                    eprintln!("ceremony refused: {:?}", e);
                    std::process::exit(1);
                }
            };
            zyn_custody::shares::save::<zyn_custody::ceremony::Solana>(&dir, &keys).expect("write shares");
            println!("{}", base58_encode(&vault_address(&keys[0].1)));
            eprintln!("next: fund the vault, then create its nonce account:");
            eprintln!("  solana create-nonce-account <nonce.json> 0.01 --nonce-authority <vault>");
        }
        _ => {
            let keys: Vec<_> = match Ceremony::new(threshold, participants).and_then(|c| c.run_for::<Zcash, _>(&mut OsRng)) {
                Ok(k) => k.into_iter().collect(),
                Err(e) => {
                    eprintln!("ceremony refused: {:?}", e);
                    std::process::exit(1);
                }
            };
            zyn_custody::shares::save::<Zcash>(&dir, &keys).expect("write shares");
            let group = keys[0].1.group_key();
            // nk and rivk grant viewing, never spending; any valid pair will do
            // and they must be kept with the shares.
            let fvk = loop {
                let (mut nk, mut rivk) = ([0u8; 32], [0u8; 32]);
                OsRng.fill_bytes(&mut nk);
                OsRng.fill_bytes(&mut rivk);
                if let Some(k) = orchard_viewing_key(&group, nk, rivk) {
                    break k;
                }
            };
            let hex: String = fvk.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
            std::fs::write(dir.join("viewing.hex"), &hex).expect("write viewing key");
            // The address is encoded for whichever chain this ceremony is
            // for. A vault born for mainnet that printed a testnet address
            // would be funded on the wrong chain, or not at all — and the
            // operator would find out from a depositor.
            let mainnet = matches!(std::env::var("ZYN_NETWORK").as_deref(), Ok("mainnet") | Ok("main"));
            let network = if mainnet {
                zcash_protocol::consensus::NetworkType::Main
            } else {
                zcash_protocol::consensus::NetworkType::Test
            };
            let address = zyn_custody::shielded::VaultKeys::from_full_viewing_key(fvk).address(0, network);
            println!("{}", address);
            eprintln!("ZYN_VAULT_FVK={}", hex);
            eprintln!(
                "this vault is for {} — set ZYN_NETWORK to change it, and check the address above starts with {}",
                if mainnet { "MAINNET" } else { "testnet" },
                if mainnet { "u1" } else { "utest1" }
            );
            eprintln!("next: send {} to the address above", if mainnet { "ZEC" } else { "testnet TAZ" });
        }
    }
    eprintln!(
        "wrote {} share(s) and public.bin to {} — a DEVNET key: every share is on this machine",
        participants,
        dir.display()
    );
}
