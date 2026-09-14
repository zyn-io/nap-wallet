//! A Zcash exit, end to end, short of the network: requested on Zyn, built,
//! proven and threshold-signed by the daemon's settler, broadcast to a node
//! that answers like Zebra, confirmed, and burned on Zyn.
//!
//! The node is faked; nothing else is. The proof is real (so this runs in
//! release), the signatures are FROST over a key nobody holds, and the bytes
//! sent are parsed back with the standard reader and checked to pay exactly
//! what was requested to exactly where it was committed.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::Note;
use orchard::ValuePool;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zcash_protocol::consensus::{BranchId, Network};
use zcash_transparent::address::TransparentAddress;
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_custody::ceremony::{orchard_viewing_key, Ceremony, Zcash};
use zyn_custody::notes::NoteStore;
use zyn_custody::shielded::PoolStores;
use zyn_custody::zebra::{Network as ZebraNet, Zebra};
use zyn_custody::{payout, shares};
use zyn_vm::spec::MicrochainVm;
use zynzapd::settle::{
    load_zcash_reveals, zcash_commitment, Ledger, Status, ZcashDestination, ZcashSettler,
};

const ACCOUNT: [u8; 32] = [7u8; 32];
const SALT: [u8; 32] = [9u8; 32];
const ZAT: i128 = 10_000_000_000;
const TIP: u64 = 4_300_000;

/// A node that knows the height, accepts one transaction and then reports it
/// six deep.
fn fake_zebra(sent: Arc<AtomicBool>, captured: Arc<Mutex<String>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            // Read the whole request: a signed transaction is a few kilobytes,
            // and closing with unread bytes resets the client's connection.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some(split) = text.find("\r\n\r\n") {
                    let want: usize = text[..split]
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= split + 4 + want {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&raw).to_string();
            let body: serde_json::Value =
                serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap_or("{}"))
                    .unwrap_or_default();
            let method = body["method"].as_str().unwrap_or("");
            let result = match method {
                "getblockcount" => format!("{}", TIP),
                "sendrawtransaction" => {
                    *captured.lock().unwrap() =
                        body["params"][0].as_str().unwrap_or("").to_string();
                    sent.store(true, Ordering::SeqCst);
                    "\"deadbeef\"".to_string()
                }
                "getrawtransaction" if sent.load(Ordering::SeqCst) => {
                    r#"{"confirmations":6,"height":4300001}"#.to_string()
                }
                "getrawtransaction" => {
                    let resp = r#"{"result":null,"error":{"code":-5,"message":"No such mempool or main chain transaction"},"id":"zyn"}"#;
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp).as_bytes());
                    continue;
                }
                _ => "null".to_string(),
            };
            let resp = format!(r#"{{"result":{},"error":null,"id":"zyn"}}"#, result);
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp).as_bytes());
        }
    });
    addr
}

fn t_address(hash: [u8; 20]) -> (TransparentAddress, String) {
    use sha2::Digest;
    let body = [&[0x1Du8, 0x25][..], &hash[..]].concat();
    let chk = sha2::Sha256::digest(sha2::Sha256::digest(&body));
    (
        TransparentAddress::PublicKeyHash(hash),
        zyn_custody::solana::base58_encode(&[&body[..], &chk[..4]].concat()),
    )
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn funded(vault_addr: orchard::Address, version: NoteVersion) -> Arc<Mutex<NoteStore>> {
    let mut store = NoteStore::new();
    store.begin_block(1);
    let other = {
        let ofvk = FullViewingKey::from(&SpendingKey::from_bytes([9u8; 32]).unwrap());
        let rho = Rho::from_bytes(&[8u8; 32]).unwrap();
        Note::from_parts(
            ofvk.address_at(0u32, Scope::External),
            NoteValue::from_raw(1),
            rho,
            RandomSeed::from_bytes([7u8; 32], &rho).unwrap(),
            version,
        )
        .unwrap()
    };
    store.append(&ExtractedNoteCommitment::from(other.commitment()), false);
    let rho = Rho::from_bytes(&[5u8; 32]).unwrap();
    let note = Note::from_parts(
        vault_addr,
        NoteValue::from_raw(10_000_000),
        rho,
        RandomSeed::from_bytes([6u8; 32], &rho).unwrap(),
        version,
    )
    .unwrap();
    let pos = store
        .append(&ExtractedNoteCommitment::from(note.commitment()), true)
        .unwrap();
    store.hold(note, pos, 1, [1u8; 32]);
    store.finish_block(1);
    Arc::new(Mutex::new(store))
}

#[test]
fn an_exit_requested_on_zyn_is_paid_transparently_and_burned() {
    run(ValuePool::Orchard);
}

/// The same loop from the Ironwood pool: the exit goes to a shielded address,
/// in a v6 transaction, and the recipient decrypts it.
#[test]
fn an_exit_from_ironwood_is_paid_to_a_shielded_address() {
    run(ValuePool::Ironwood);
}

fn run(pool: ValuePool) {
    let dir = std::env::temp_dir().join(format!("zyn-zsettle-{:?}-{}", pool, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // --- the vault: a 2-of-3 key, and a viewing key that is *its* ---
    let keys: Vec<_> = Ceremony::new(2, 3)
        .unwrap()
        .run_for::<Zcash, _>(&mut rand::rngs::OsRng)
        .unwrap()
        .into_iter()
        .collect();
    shares::save::<Zcash>(&dir.join("shares"), &keys).unwrap();
    let group = keys[0].1.group_key();
    let fvk: FullViewingKey = (0u8..64)
        .find_map(|n| orchard_viewing_key(&group, [n; 32], [n; 32]))
        .unwrap();
    let vault_addr = fvk.address_at(0u32, Scope::External);

    // --- the vault holds one note of 0.1 TAZ in the pool under test ---
    let empty = || Arc::new(Mutex::new(NoteStore::new()));
    let notes = match pool {
        ValuePool::Orchard => PoolStores {
            orchard: funded(vault_addr, NoteVersion::V2),
            ironwood: empty(),
        },
        ValuePool::Ironwood => PoolStores {
            orchard: empty(),
            ironwood: funded(vault_addr, NoteVersion::V3),
        },
    };

    // --- where the user goes, committed on Zyn and revealed to us ---
    let their_fvk = FullViewingKey::from(&SpendingKey::from_bytes([42u8; 32]).unwrap());
    let (dest, dest_str) = match pool {
        ValuePool::Orchard => {
            let (t, s) = t_address([3u8; 20]);
            (ZcashDestination::Transparent(t), s)
        }
        ValuePool::Ironwood => {
            use zcash_address::unified::{Address, Encoding, Receiver};
            let a = their_fvk.address_at(0u32, Scope::External);
            let ua =
                Address::try_from_items(vec![Receiver::Orchard(a.to_raw_address_bytes())]).unwrap();
            (
                ZcashDestination::Shielded(a),
                ua.encode(&zcash_protocol::consensus::NetworkType::Test),
            )
        }
    };
    let destination = zcash_commitment(&dest, &SALT);
    let reveals = dir.join("reveals");
    std::fs::write(
        &reveals,
        format!("{} {} {}\n", hex(&ACCOUNT), dest_str, hex(&SALT)),
    )
    .unwrap();

    // --- the user's side on Zyn ---
    let policy = EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let node: Arc<Mutex<Node<SwapState>>> = Arc::new(Mutex::new(Node::new(
        3,
        Params::testnet(),
        policy,
        Economics::flat(10_000),
    )));
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
                asset: XZEC,
                observed: Fixed::raw(10_000_000 * ZAT),
            },
        );
        let index = n.state().next_deposit_index(XZEC);
        go(
            &mut n,
            Intent::CreditDeposit {
                account: ACCOUNT,
                asset: XZEC,
                amount: Fixed::raw(5_000_000 * ZAT),
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
                asset: XZEC,
                amount: Fixed::raw(2_000_000 * ZAT),
                destination,
            },
        );
    }

    // --- the settler ---
    let sent = Arc::new(AtomicBool::new(false));
    let captured = Arc::new(Mutex::new(String::new()));
    let addr = fake_zebra(sent.clone(), captured.clone());
    let zebra =
        Zebra::connect(&addr.ip().to_string(), addr.port(), None, ZebraNet::Testnet).unwrap();
    let mut settler = ZcashSettler::new(
        zebra,
        Network::TestNetwork,
        shares::load::<Zcash>(&dir.join("shares")).unwrap(),
        2,
        fvk.clone(),
        notes.clone(),
        load_zcash_reveals(&reveals, Network::TestNetwork).unwrap(),
        XZEC,
        6,
        dir.clone(),
        3,
        shares::load_public::<Zcash>(&dir.join("shares")).unwrap(),
        None,
    )
    .unwrap();

    // Pass one builds, proves, signs and sends. Pass two sees it six deep.
    assert_eq!(settler.poll_once(&node, 0).unwrap(), 0);
    assert!(sent.load(Ordering::SeqCst), "nothing was broadcast");
    assert_eq!(
        settler.poll_once(&node, 0).unwrap(),
        1,
        "the exit was not confirmed on Zyn"
    );

    // What went over the wire: a v5 transaction paying 0.02 TAZ to the
    // committed address, and the rest less the fee back to the vault.
    let raw = captured.lock().unwrap().clone();
    let bytes: Vec<u8> = (0..raw.len() / 2)
        .map(|i| u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let env = payout::Envelope::testnet_at(TIP as u32);
    let tx = zcash_primitives::transaction::Transaction::read(&bytes[..], env.branch)
        .expect("a transaction");
    assert_eq!(
        env.branch,
        BranchId::Nu6_3,
        "testnet at this height is NU6.3"
    );
    let version = env.bundle_version_for(pool).unwrap();
    match pool {
        ValuePool::Orchard => {
            let t = tx.transparent_bundle().expect("a transparent output");
            assert_eq!(t.vout.len(), 1);
            let o = tx.orchard_bundle().expect("an orchard bundle");
            o.verify_proof(&payout::verifying_key(version))
                .expect("the proof verifies");
            // The exit pays the fee: the recipient gets the exit less the fee,
            // and exactly the exit leaves the vault.
            let fee = payout::zip317_fee(o.actions().len(), 1);
            assert_eq!(u64::from(t.vout[0].value()), 2_000_000 - fee);
            assert_eq!(
                ZcashDestination::Transparent(t.vout[0].recipient_address().unwrap()),
                dest
            );
            assert_eq!(
                i64::from(*o.value_balance()),
                2_000_000,
                "exactly the burned amount leaves the pool"
            );
        }
        ValuePool::Ironwood => {
            assert_eq!(tx.version(), zcash_primitives::transaction::TxVersion::V6);
            assert!(tx.transparent_bundle().is_none() && tx.orchard_bundle().is_none());
            let b = tx.ironwood_bundle().expect("an ironwood bundle");
            b.verify_proof(&payout::verifying_key(version))
                .expect("the proof verifies");
            let ivk =
                orchard::keys::PreparedIncomingViewingKey::new(&their_fvk.to_ivk(Scope::External));
            let got: Vec<u64> = b
                .actions()
                .iter()
                .filter_map(|a| {
                    zcash_note_encryption::try_note_decryption(
                        &orchard::note_encryption::IronwoodDomain::for_action(a),
                        &ivk,
                        a,
                    )
                })
                .map(|(n, _, _)| n.value().inner())
                .collect();
            let fee = payout::zip317_fee(b.actions().len(), 0);
            assert_eq!(
                got,
                vec![2_000_000 - fee],
                "the recipient receives the exit less the fee it pays"
            );
            // The recipient's note stays in the pool; only the fee leaves it. The
            // vault's own holdings drop by exactly the exit.
            assert_eq!(i64::from(*b.value_balance()), fee as i64);
        }
    }

    // Burned on Zyn, spent in the store, remembered in the ledger.
    let n = node.lock().unwrap();
    let pending = n
        .state()
        .accounts
        .get(&ACCOUNT)
        .and_then(|a| a.pending.get(&XZEC))
        .map(|p| p.amount);
    assert!(
        pending.map(|p| p.is_zero()).unwrap_or(true),
        "still pending: {:?}",
        pending
    );
    assert_eq!(
        n.state().backing_of(XZEC),
        Fixed::raw(3_000_000 * ZAT),
        "backing was not released"
    );
    assert_eq!(
        notes.of(pool).lock().unwrap().balance(),
        0,
        "the spent note is still held"
    );
    let ledger = Ledger::load(&dir, 3, XZEC).unwrap();
    assert_eq!(ledger.entries.len(), 1);
    assert_eq!(ledger.entries[0].status, Status::Confirmed);
    assert_eq!(
        ledger.entries[0].id,
        hex(&{
            let mut t = *tx.txid().as_ref();
            t.reverse();
            t
        })
    );
    drop(n);
    assert_eq!(
        settler.poll_once(&node, 0).unwrap(),
        0,
        "a second pass had nothing to do"
    );
}
