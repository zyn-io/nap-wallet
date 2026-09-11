//! The Solana leg, end to end, against a local validator.
//!
//! Opt-in: `ZYN_SOLANA_LIVE=1 cargo test -p zyn-custody --test solana_live`
//! with `solana-test-validator` running on localhost. Everything the unit
//! tests cannot prove is proved here: that the hand-assembled message is one
//! the runtime accepts, that a durable nonce is honoured and consumed, and that
//! a FROST signature from a key nobody holds moves real lamports.
//!
//! The payer and the nonce account are set up through the `solana` CLI, which
//! is the operator's tool for that job anyway.

use std::process::Command;

use rand::rngs::OsRng;
use zyn_bridge::solana::{chunk, SolPayout, VaultAccounts};
use zyn_custody::solana::custody::{broadcast, ceremony, prepare, vault_address, Id, Keys};
use zyn_custody::solana::{base58_encode, pubkey, Cluster, Rpc};

const URL: &str = "http://127.0.0.1:8899";

fn cli(args: &[&str]) -> String {
    let out = Command::new("solana").args(args).args(["-u", URL]).output().expect("solana cli");
    assert!(out.status.success(), "solana {:?}: {}", args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn a_threshold_vault_pays_out_on_a_local_validator() {
    if std::env::var("ZYN_SOLANA_LIVE").is_err() {
        eprintln!("skipped: set ZYN_SOLANA_LIVE=1 with solana-test-validator running");
        return;
    }
    let dir = std::env::temp_dir().join(format!("zyn-sol-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payer = dir.join("payer.json");
    let nonce_kp = dir.join("nonce.json");
    for f in [&payer, &nonce_kp] {
        let out = Command::new("solana-keygen")
            .args(["new", "--no-bip39-passphrase", "-f", "-s", "-o"])
            .arg(f)
            .output()
            .unwrap();
        assert!(out.status.success());
    }
    let payer_s = payer.to_str().unwrap();
    cli(&["airdrop", "5", "-k", payer_s]);

    // The vault is the ceremony's group key. No file holds it.
    let keys: Vec<(Id, Keys)> = ceremony(2, 3, &mut OsRng).unwrap().into_iter().collect();
    let vault = vault_address(&keys[0].1);
    let vault_b58 = base58_encode(&vault);
    cli(&["airdrop", "2", &vault_b58]);

    // A durable nonce account whose authority is the vault.
    cli(&[
        "create-nonce-account", nonce_kp.to_str().unwrap(), "0.01",
        "--nonce-authority", &vault_b58, "-k", payer_s,
    ]);
    let nonce_b58 = cli(&["address", "-k", nonce_kp.to_str().unwrap()]);

    let rpc = match Rpc::connect(URL, Cluster::Devnet) {
        Ok(r) => r,
        // A test validator has its own genesis; connect without the check.
        Err(_) => Rpc::connect_unchecked(URL, Cluster::Devnet),
    };
    // The library reads the nonce at *finalized* commitment, which is what the
    // vault signs against. A just-created account takes ~13 s to get there on
    // a test validator; an operator's nonce account is years old.
    let nonce_before = {
        let mut last = Err(zyn_custody::solana::SolanaError::Malformed("unread"));
        for _ in 0..40 {
            last = rpc.nonce_value(&nonce_b58);
            if last.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        last.expect("nonce account never finalized")
    };

    let dest = pubkey(&cli(&["address", "-k", payer_s])).unwrap();
    let payouts = vec![SolPayout::native(dest, 500_000_000)];
    let groups = chunk(VaultAccounts { vault, nonce_account: pubkey(&nonce_b58).unwrap() }, &payouts).unwrap();
    assert_eq!(groups.len(), 1);

    let quorum: Vec<(Id, &Keys)> = keys.iter().take(2).map(|(i, k)| (*i, k)).collect();
    let payment = prepare(&rpc, &quorum, 2, &nonce_b58, &groups[0], &mut OsRng).unwrap();
    let before: u64 = cli(&["balance", "--lamports", &base58_encode(&dest)]).split(' ').next().unwrap().parse().unwrap();
    let lamports_of = |who: &str| -> u64 {
        cli(&["balance", "--lamports", who]).split(' ').next().unwrap().parse().unwrap()
    };
    let vault_before = lamports_of(&vault_b58);
    let sig = broadcast(&rpc, &payment).unwrap();
    assert_eq!(sig, payment.id(), "the chain's id for the transaction is its signature");

    // Wait for the chain, not for the clock: first confirmation, then the
    // nonce's new value reaching finality (~13 s on a test validator).
    let mut status = String::new();
    for _ in 0..60 {
        status = cli(&["confirm", &sig]);
        if status.contains("Confirmed") || status.contains("Finalized") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(status.contains("Confirmed") || status.contains("Finalized"), "status: {}", status);

    assert_eq!(lamports_of(&base58_encode(&dest)) - before, 500_000_000, "the payout did not arrive");
    assert_eq!(vault_before - lamports_of(&vault_b58), 500_000_000 + 5_000, "vault paid other than payout plus one fee");

    let mut nonce_after = nonce_before;
    for _ in 0..60 {
        nonce_after = rpc.nonce_value(&nonce_b58).unwrap();
        if nonce_after != nonce_before {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert_ne!(nonce_after, nonce_before, "nonce was not consumed");
    assert!(broadcast(&rpc, &payment).is_err(), "a replay was accepted");
}
