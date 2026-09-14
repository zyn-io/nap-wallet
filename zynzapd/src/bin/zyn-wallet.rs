//! `zyn-wallet` — a Zcash wallet on either network, from the vault's own
//! code, thin over `zynzapd::wallet`. It scans compact blocks from a
//! `zyn-lightd`, keeps its own note trees on disk, and spends in v6
//! transactions from Ironwood when the recipient is shielded.
//!
//! ```text
//!   zyn-wallet new     <wallet>              -> address; birthday = today's tip
//!   zyn-wallet import  <wallet> <hex> <birth> -> address, from a 32-byte key
//!   zyn-wallet import-mnemonic <wallet> <phrase-file|-> <birth> [account]
//!   zyn-wallet import-backup <wallet> <backup-file|->
//!   zyn-wallet backup  <wallet>              -> portable JSON on stdout
//!   zyn-wallet address <wallet>
//!   zyn-wallet sync    <wallet>              -> notes and balance
//!   zyn-wallet send    <wallet> <to> <zec> [memo-text]
//!   zyn-wallet reset   <wallet> [birthday]   -> forget scan state, keep key
//! ```
//!
//! `ZYN_LIGHTD=host:port` names the block server (default
//! `168.119.53.39:8098`, the Zyn testnet box). The server says which network
//! it is; the wallet remembers and refuses to sync one wallet against the
//! other network.

use std::io::Read;
use zyn_custody::lightd::Client;

use zynzapd::wallet::{
    network_name, unit, Event, Wallet, WalletBackup, CONFIRMATIONS, ZAT_PER_ZEC,
};

const DEFAULT_LIGHTD: &str = zynzapd::app::DEFAULT_LIGHTD_TESTNET;

fn die(msg: &str) -> ! {
    eprintln!("zyn-wallet: {}", msg);
    std::process::exit(1)
}

fn client() -> Client {
    Client::new(&std::env::var("ZYN_LIGHTD").unwrap_or_else(|_| DEFAULT_LIGHTD.to_string()))
}

fn read_secret(path: &str) -> Result<String, String> {
    let mut out = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut out)
            .map_err(|e| e.to_string())?;
    } else {
        out = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    }
    Ok(out.trim().to_string())
}

fn log(e: Event) {
    match e {
        Event::Progress { at, to } => {
            if at.is_multiple_of(1000) || at == to {
                eprintln!("  … {} of {}", at, to)
            }
        }
        Event::Received {
            pool,
            zatoshi,
            height,
            memo,
            ..
        } => eprintln!(
            "  received {:>10} zat  in {:?} at height {}{}",
            zatoshi,
            pool,
            height,
            if memo.is_empty() {
                String::new()
            } else {
                format!("  memo: {}", memo)
            }
        ),
        Event::Spent {
            pool,
            zatoshi,
            from_height,
            ..
        } => eprintln!(
            "  spent  {:>12} zat  ({:?} note from height {})",
            zatoshi, pool, from_height
        ),
    }
}

fn report(w: &Wallet, synced: u64) {
    let (o, i) = w.balance();
    println!("{}  synced to {}", network_name(w.network()), synced);
    println!(
        "balance: {:.8} {}  (Ironwood {} zat, Orchard {} zat)",
        (o + i) as f64 / ZAT_PER_ZEC,
        unit(w.network()),
        i,
        o
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let r: Result<(), String> = (|| {
        match (a.get(1).map(String::as_str).unwrap_or(""), a.len()) {
            ("new", 3) => {
                let w = Wallet::create(&a[2], client())?;
                eprintln!(
                    "{} wallet, birthday {}",
                    network_name(w.network()),
                    w.state.birthday
                );
                println!("{}", w.address());
            }
            ("import", 5) => {
                let seed: [u8; 32] = (0..32)
                    .map(|i| {
                        u8::from_str_radix(a[3].get(i * 2..i * 2 + 2).unwrap_or("zz"), 16).ok()
                    })
                    .collect::<Option<Vec<u8>>>()
                    .and_then(|v| v.try_into().ok())
                    .ok_or("key is 64 hex characters")?;
                let birthday: u64 = a[4].parse().map_err(|_| "birthday is a block height")?;
                let w = Wallet::import(&a[2], seed, Some(birthday), client())?;
                eprintln!(
                    "{} wallet, birthday {}",
                    network_name(w.network()),
                    w.state.birthday
                );
                println!("{}", w.address());
            }
            ("import-mnemonic", 5) | ("import-mnemonic", 6) => {
                let words = read_secret(&a[3])?;
                let birthday: u64 = a[4].parse().map_err(|_| "birthday is a block height")?;
                let account: u32 = a
                    .get(5)
                    .map(String::as_str)
                    .unwrap_or("0")
                    .parse()
                    .map_err(|_| "account is a number below 2^31")?;
                let passphrase = std::env::var("ZYN_BIP39_PASSPHRASE").unwrap_or_default();
                let w = Wallet::import_mnemonic(
                    &a[2],
                    &words,
                    &passphrase,
                    account,
                    birthday,
                    client(),
                )?;
                eprintln!(
                    "{} wallet, birthday {}, ZIP-32 account {}",
                    network_name(w.network()),
                    w.state.birthday,
                    account
                );
                if w.mnemonic_word_count().is_some_and(|n| n < 24) {
                    eprintln!("warning: imported phrases shorter than 24 words have less than the 256 bits recommended for Zcash; move recovered funds to a new wallet");
                }
                println!("{}", w.address());
            }
            ("import-backup", 4) => {
                let backup = WalletBackup::parse(&read_secret(&a[3])?)?;
                let w = Wallet::import_backup(&a[2], backup, client())?;
                eprintln!(
                    "{} wallet, birthday {}",
                    network_name(w.network()),
                    w.state.birthday
                );
                println!("{}", w.address());
            }
            ("backup", 3) => println!("{}", Wallet::open(&a[2], client())?.export_backup()),
            ("address", 3) => println!("{}", Wallet::open(&a[2], client())?.address()),
            ("reset", 3) | ("reset", 4) => {
                let mut w = Wallet::open(&a[2], client())?;
                let birthday = match a.get(3) {
                    Some(h) => h.parse().map_err(|_| "birthday is a block height")?,
                    None => w.state.birthday,
                };
                w.reset(birthday)?;
                eprintln!(
                    "{} state reset to birthday {}; the next sync rescans from there",
                    network_name(w.network()),
                    w.state.birthday
                );
            }
            ("sync", 3) => {
                let mut w = Wallet::open(&a[2], client())?;
                let synced = w.sync(log)?;
                report(&w, synced);
            }
            ("send", 5) | ("send", 6) => {
                let mut w = Wallet::open(&a[2], client())?;
                let zec: f64 = a[4].parse().map_err(|_| "amount in ZEC")?;
                let zatoshi = (zec * ZAT_PER_ZEC).round() as u64;
                eprintln!("syncing, then proving (the key takes a moment to build)…");
                let txid = w.send(&a[3], zatoshi, a.get(5).map(String::as_str), log)?;
                eprintln!(
                    "sent; the change shows up after {} confirmations",
                    CONFIRMATIONS
                );
                println!("{}", txid);
            }
            _ => {
                eprintln!("usage:\n  zyn-wallet new <wallet>\n  zyn-wallet import <wallet> <key-hex> <birthday-height>\n  zyn-wallet import-mnemonic <wallet> <phrase-file|-> <birthday-height> [account]\n  zyn-wallet import-backup <wallet> <backup-file|->\n  zyn-wallet backup <wallet>\n  zyn-wallet address <wallet>\n  zyn-wallet sync <wallet>\n  zyn-wallet send <wallet> <to-address> <zec> [memo-text]\n  zyn-wallet reset <wallet> [birthday-height]\n\nZYN_BIP39_PASSPHRASE supplies the optional mnemonic passphrase.\nZYN_LIGHTD=host:port picks the block server (default {}).", DEFAULT_LIGHTD);
                std::process::exit(2);
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        die(&e)
    }
}
