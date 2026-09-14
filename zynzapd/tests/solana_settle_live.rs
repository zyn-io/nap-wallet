//! An exit, end to end: requested on Zyn, paid on Solana by a key nobody
//! holds, burned on Zyn once final.
//!
//! Opt-in: `ZYN_SOLANA_LIVE=1 cargo test -p zynzapd --test solana_settle_live`
//! with `solana-test-validator` on localhost.

use std::process::Command;
use std::sync::{Arc, Mutex};

use rand::rngs::OsRng;
use swapvm::state::{symbol, SwapState, TokenInfo};
use swapvm::tx::Intent;
use swapvm::types::ORIGIN_SOLANA;
use swapvm::{Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_bridge::solana::commitment;
use zyn_custody::solana::custody::{ceremony, vault_address, Id, Keys};
use zyn_custody::solana::{base58_encode, pubkey, shares, Cluster, Rpc};
use zyn_vm::spec::MicrochainVm;
use zynzapd::settle::{load_reveals, SolanaSettler, Status};

const URL: &str = "http://127.0.0.1:8899";
const ACCOUNT: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [9u8; 32];

fn cli(args: &[&str]) -> String {
    let out = Command::new("solana")
        .args(args)
        .args(["-u", URL])
        .output()
        .expect("solana cli");
    assert!(
        out.status.success(),
        "solana {:?}: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
fn lamports_of(who: &str) -> u64 {
    cli(&["balance", "--lamports", who])
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The V0 posture: the shares are in this process.
#[test]
fn an_exit_requested_on_zyn_is_paid_on_solana_and_burned() {
    run(false)
}

/// The same exit, paid by three daemons that each hold one share and answer
/// over a socket. The settler here holds no secret at all — only the public
/// package and three addresses.
#[test]
fn the_same_exit_is_paid_by_custodians_holding_one_share_each() {
    run(true)
}

fn run(federated: bool) {
    if std::env::var("ZYN_SOLANA_LIVE").is_err() {
        eprintln!("skipped: set ZYN_SOLANA_LIVE=1 with solana-test-validator running");
        return;
    }
    let dir = std::env::temp_dir().join(format!(
        "zyn-settle-live-{}-{}",
        std::process::id(),
        federated
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // --- the chain: one Solana-vaulted asset, one account with a balance ---
    let mut s = SwapState::new(3, Params::testnet());
    let sol = swapvm::types::SOL_ZY;
    s.tokens
        .insert(sol, TokenInfo::bridged(symbol(b"SOL.zy"), ORIGIN_SOLANA));
    let policy = EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let node = Arc::new(Mutex::new(Node::resume(
        s,
        policy,
        Economics::flat(10_000),
        0,
    )));

    // --- the vault: a 2-of-3 key born in a ceremony, funded, with a nonce ---
    let keys: Vec<(Id, Keys)> = ceremony(2, 3, &mut OsRng).unwrap().into_iter().collect();
    let vault = vault_address(&keys[0].1);
    let vault_b58 = base58_encode(&vault);
    shares::save(&dir.join("shares"), &keys).unwrap();
    let payer = dir.join("payer.json");
    let nonce_kp = dir.join("nonce.json");
    for f in [&payer, &nonce_kp] {
        assert!(Command::new("solana-keygen")
            .args(["new", "--no-bip39-passphrase", "-f", "-s", "-o"])
            .arg(f)
            .output()
            .unwrap()
            .status
            .success());
    }
    cli(&["airdrop", "5", "-k", payer.to_str().unwrap()]);
    cli(&["airdrop", "2", &vault_b58]);
    cli(&[
        "create-nonce-account",
        nonce_kp.to_str().unwrap(),
        "0.01",
        "--nonce-authority",
        &vault_b58,
        "-k",
        payer.to_str().unwrap(),
    ]);
    let nonce_b58 = cli(&["address", "-k", nonce_kp.to_str().unwrap()]);
    let rpc = Rpc::connect_unchecked(URL, Cluster::Devnet);
    for _ in 0..40 {
        if rpc.nonce_value(&nonce_b58).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // --- where the user wants to go, committed on-chain and revealed to us ---
    let dest = pubkey(&cli(&["address", "-k", payer.to_str().unwrap()])).unwrap();
    let destination = commitment(&dest, &SALT);
    let reveals = dir.join("reveals");
    std::fs::write(
        &reveals,
        format!(
            "{} {} {}\n",
            hex(&ACCOUNT),
            base58_encode(&dest),
            hex(&SALT)
        ),
    )
    .unwrap();

    // --- the user's side on Zyn: credited, released, bound, exiting ---
    {
        let mut n = node.lock().unwrap();
        let go = |n: &mut Node<SwapState>, i: Intent| {
            let step = n.submit_operator(i, 0);
            assert!(
                !step.rejected(),
                "rejected at seq {}: {:?}",
                step.seq,
                step.receipts
            );
        };
        go(
            &mut n,
            Intent::AttestVaultBalance {
                asset: sol,
                observed: Fixed::whole(2),
            },
        );
        let index = n.state().next_deposit_index(sol);
        go(
            &mut n,
            Intent::CreditDeposit {
                account: ACCOUNT,
                asset: sol,
                amount: Fixed::whole(1),
                index,
                external_ref: [1u8; 32],
            },
        );
        let epoch = n.state().epoch();
        go(&mut n, Intent::Checkpoint);
        go(&mut n, Intent::ConfirmAnchor { epoch });
        go(
            &mut n,
            Intent::BindWithdrawal {
                account: ACCOUNT,
                destination,
            },
        );
        go(
            &mut n,
            Intent::RequestWithdrawal {
                account: ACCOUNT,
                asset: sol,
                amount: Fixed::whole(1),
                destination,
            },
        );
        assert_eq!(
            n.state().balance(&ACCOUNT, sol),
            Fixed::ZERO,
            "units left the balance on request"
        );
        assert_eq!(
            n.state().accounts[&ACCOUNT].pending[&sol].amount,
            Fixed::whole(1)
        );
    }

    // --- the settler ---
    // Federated, the shares move out to three daemons on loopback and the
    // settler keeps none: what it can still do is exactly what a quorum of
    // custodians agrees to.
    let (held, custodians) = if federated {
        let mut addrs = Vec::new();
        for (_, k) in &keys {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            addrs.push(listener.local_addr().unwrap().to_string());
            let c = Arc::new(Mutex::new(zyn_custody::custody_net::Custodian {
                zcash: None,
                solana: Some(zyn_custody::custodian::solana::Participant::new(k.clone())),
            }));
            std::thread::spawn(move || zyn_custody::custody_net::serve(c, listener, now_secs));
        }
        (Vec::new(), Some(addrs))
    } else {
        (shares::load(&dir.join("shares")).unwrap(), None)
    };
    let public =
        zyn_custody::shares::load_public::<zyn_custody::ceremony::Solana>(&dir.join("shares"))
            .unwrap();
    let mut settler = SolanaSettler::new(
        rpc,
        held,
        public,
        custodians,
        2,
        &nonce_b58,
        load_reveals(&reveals).unwrap(),
        sol,
        dir.clone(),
        3,
    )
    .unwrap();
    assert_eq!(settler.vault_address(), vault_b58);
    let dest_before = lamports_of(&base58_encode(&dest));
    let vault_before = lamports_of(&vault_b58);

    let mut confirmed = 0;
    for _ in 0..120 {
        confirmed += settler.poll_once(&node, 0).expect("settle pass");
        if confirmed > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    assert_eq!(confirmed, 1, "the exit was never confirmed on Zyn");

    // Paid, exactly, and nothing else left the vault.
    // The exit pays the fee: exactly the burned amount leaves the vault.
    assert_eq!(
        lamports_of(&base58_encode(&dest)) - dest_before,
        1_000_000_000 - 5_000
    );
    assert_eq!(vault_before - lamports_of(&vault_b58), 1_000_000_000);

    // Burned: nothing pending, and the vault's backing went with it.
    let n = node.lock().unwrap();
    // An account holding nothing is pruned, so absence is the expected shape.
    let pending = n
        .state()
        .accounts
        .get(&ACCOUNT)
        .and_then(|a| a.pending.get(&sol))
        .map(|p| p.amount);
    assert!(
        pending.map(|p| p.is_zero()).unwrap_or(true),
        "still pending: {:?}",
        pending
    );
    assert_eq!(
        n.state().backing_of(sol),
        Fixed::ZERO,
        "backing was not released"
    );

    // And the ledger remembers it as done.
    let ledger = zynzapd::settle::Ledger::load(&dir, 3, sol).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].status, Status::Confirmed);
    assert_eq!(ledger.entries[0].covers, vec![(ACCOUNT, Fixed::whole(1))]);

    // A second pass has nothing to do and sends nothing.
    drop(n);
    assert_eq!(settler.poll_once(&node, 0).unwrap(), 0);
    assert_eq!(
        zynzapd::settle::Ledger::load(&dir, 3, sol)
            .unwrap()
            .entries
            .len(),
        1
    );
}
