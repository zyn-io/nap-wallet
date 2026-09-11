//! A mirrored NFT, round trip, on a local validator: minted to a wallet,
//! deposited into the vault's token account with the memo, seen by the
//! watcher as a deposit of the item's asset, then paid back out by the
//! threshold key as an SPL transfer into the recipient's token account.
//!
//! Opt-in: `ZYN_SOLANA_LIVE=1 cargo test -p zyn-custody --test solana_nft_live`
//! with `solana-test-validator` and `spl-token` available.

use std::process::Command;

use rand::rngs::OsRng;
use zyn_bridge::solana::{associated_token_address, chunk, SolPayout, VaultAccounts};
use zyn_custody::solana::custody::{broadcast, ceremony, prepare, vault_address, Id, Keys};
use zyn_custody::solana::{base58_encode, pubkey, Cluster, Mirrored, Observed, Rpc};
use zyn_custody::watcher::ChainView;
use zyn_vm::Fixed;

const URL: &str = "http://127.0.0.1:8899";

fn run(bin: &str, args: &[&str]) -> String {
    let out = Command::new(bin).args(args).output().expect(bin);
    assert!(out.status.success(), "{} {:?}: {}", bin, args, String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn a_mirrored_nft_is_deposited_seen_and_paid_back() {
    if std::env::var("ZYN_SOLANA_LIVE").is_err() {
        eprintln!("skipped: set ZYN_SOLANA_LIVE=1 with solana-test-validator running");
        return;
    }
    let dir = std::env::temp_dir().join(format!("zyn-nft-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payer = dir.join("payer.json");
    let nonce_kp = dir.join("nonce.json");
    for f in [&payer, &nonce_kp] {
        run("solana-keygen", &["new", "--no-bip39-passphrase", "-f", "-s", "-o", f.to_str().unwrap()]);
    }
    let payer_s = payer.to_str().unwrap();
    run("solana", &["airdrop", "5", "-k", payer_s, "-u", URL]);

    // The vault, funded (it pays the recipient's token-account rent).
    let keys: Vec<(Id, Keys)> = ceremony(2, 3, &mut OsRng).unwrap().into_iter().collect();
    let vault = vault_address(&keys[0].1);
    let vault_b58 = base58_encode(&vault);
    run("solana", &["airdrop", "2", &vault_b58, "-u", URL]);
    run("solana", &["create-nonce-account", nonce_kp.to_str().unwrap(), "0.01", "--nonce-authority", &vault_b58, "-k", payer_s, "-u", URL]);
    let nonce_b58 = run("solana", &["address", "-k", nonce_kp.to_str().unwrap()]);

    // An NFT: a mint with zero decimals and a supply of one, in the payer's wallet.
    let created = run("spl-token", &["create-token", "--decimals", "0", "-u", URL, "--fee-payer", payer_s, "--mint-authority", payer_s]);
    let mint_b58 = created.lines().find_map(|l| l.strip_prefix("Creating token ")).unwrap().split_whitespace().next().unwrap().to_string();
    run("spl-token", &["create-account", &mint_b58, "-u", URL, "--fee-payer", payer_s, "--owner", payer_s]);
    let mint = pubkey(&mint_b58).unwrap();
    // Mint into the payer's token account — derived here, which also checks
    // the derivation against the account the CLI just created.
    let payer_pk = pubkey(&run("solana", &["address", "-k", payer_s])).unwrap();
    let payer_ata = base58_encode(&associated_token_address(&payer_pk, &mint));
    run("spl-token", &["mint", &mint_b58, "1", &payer_ata, "-u", URL, "--fee-payer", payer_s, "--mint-authority", payer_s]);
    let vault_ata = associated_token_address(&vault, &mint);
    let mirrored = Mirrored { mint: mint_b58.clone(), asset: 7, ata: base58_encode(&vault_ata), per_unit: 1 };

    // Deposit: the wallet sends the token to the vault, memo naming account 0x44.
    let memo = zyn_custody::memo::encode_text(&[0x44u8; 32]);
    run("spl-token", &["transfer", &mint_b58, "1", &vault_b58, "--fund-recipient", "--allow-unfunded-recipient", "--with-memo", &memo, "-u", URL, "--fee-payer", payer_s, "--owner", payer_s]);

    // The watcher, over the vault and its token account.
    let rpc = Rpc::connect_unchecked(URL, Cluster::Devnet);
    let mut observed = Observed::new(rpc, &vault_b58).unwrap().with_mirrored(vec![mirrored.clone()]);
    let mut found = None;
    for _ in 0..40 {
        let tip = observed.refresh().unwrap();
        for slot in tip.saturating_sub(200)..=tip {
            for d in observed.deposits_at(slot) {
                if d.asset == Some(7) { found = Some(d); }
            }
        }
        if found.is_some() { break; }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let d = found.expect("the item deposit was never seen");
    assert_eq!(d.amount, Fixed::whole(1));
    assert_eq!(d.account, [0x44u8; 32]);
    assert_eq!(observed.balance_of(7, 0), Some(Fixed::whole(1)), "the vault holds the item");

    // Exit: the threshold key sends it to a fresh recipient.
    let recipient_kp = dir.join("recipient.json");
    run("solana-keygen", &["new", "--no-bip39-passphrase", "-f", "-s", "-o", recipient_kp.to_str().unwrap()]);
    let recipient = pubkey(&run("solana", &["address", "-k", recipient_kp.to_str().unwrap()])).unwrap();
    let rpc = Rpc::connect_unchecked(URL, Cluster::Devnet);
    for _ in 0..40 {
        if rpc.nonce_value(&nonce_b58).is_ok() { break; }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let groups = chunk(VaultAccounts { vault, nonce_account: pubkey(&nonce_b58).unwrap() }, &[SolPayout::token(recipient, mint, 1)]).unwrap();
    let quorum: Vec<(Id, &Keys)> = keys.iter().take(2).map(|(i, k)| (*i, k)).collect();
    let payment = prepare(&rpc, &quorum, 2, &nonce_b58, &groups[0], &mut OsRng).unwrap();
    let sig = broadcast(&rpc, &payment).expect("the node accepted the token payout");
    for _ in 0..60 {
        let st = run("solana", &["confirm", &sig, "-u", URL]);
        if st.contains("Confirmed") || st.contains("Finalized") { break; }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let got = run("spl-token", &["balance", &mint_b58, "--owner", &base58_encode(&recipient), "-u", URL]);
    assert_eq!(got.trim(), "1", "the recipient did not receive the item");
    let left = run("spl-token", &["balance", &mint_b58, "--owner", &vault_b58, "-u", URL]);
    assert_eq!(left.trim(), "0", "the vault still holds the item");
}
