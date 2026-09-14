//! A deposit, from JSON on a socket to a credited balance.
//!
//! Everything between is separately tested. What this catches is the seams:
//! the HTTP framing, the shape of Zebra's replies, zatoshi becoming `Fixed`,
//! and the watcher's actions becoming intents the VM accepts.
//!
//! The node is a fake, because the real one takes a day to sync and cannot be
//! made to produce a specific deposit on demand. The replies are shaped as
//! Zebra documents them.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_custody::zebra::{Network, Zebra};
use zyn_vm::spec::MicrochainVm;
use zynzapd::bridge::Bridge;

const ACCOUNT: [u8; 32] = [7u8; 32];
const ADDRESS: &str = "tmEXAMPLEwatchedaddress";
const TXID: &str = "aa00000000000000000000000000000000000000000000000000000000000011";

/// A Zebra that answers three methods and nothing else.
fn fake_zebra(tip: u64, deposit_height: u64, zat: i64) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();

            let result = if req.contains("getblockcount") {
                tip.to_string()
            } else if req.contains("getaddresstxids") {
                format!("[\"{}\"]", TXID)
            } else if req.contains("getrawtransaction") {
                format!(
                    r#"{{"txid":"{}","height":{},"vout":[
                        {{"value":0.001,"valueZat":{},"n":0,
                          "scriptPubKey":{{"addresses":["{}"]}}}},
                        {{"value":1.0,"valueZat":100000000,"n":1,
                          "scriptPubKey":{{"addresses":["tmSOMEONEELSE"]}}}}
                    ]}}"#,
                    TXID, deposit_height, zat, ADDRESS
                )
            } else {
                "null".to_string()
            };

            let body = format!(r#"{{"result":{},"error":null,"id":"zyn"}}"#, result);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes());
            let _ = s.flush();
        }
    });
    addr
}

fn node() -> Arc<Mutex<Node<SwapState>>> {
    let policy = EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let n: Node<SwapState> = Node::new(3, Params::testnet(), policy, Economics::flat(10_000));
    Arc::new(Mutex::new(n))
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("zyn-dep-{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bridge(addr: SocketAddr, dir: &std::path::Path, node: &Arc<Mutex<Node<SwapState>>>) -> Bridge {
    let zebra = Zebra::connect(&addr.ip().to_string(), addr.port(), None, Network::Testnet)
        .expect("client");
    let mut addresses = std::collections::BTreeMap::new();
    addresses.insert(ADDRESS.to_string(), ACCOUNT);
    let start = node.lock().unwrap().state().next_deposit_index(XZEC);
    Bridge::new(
        zynzapd::bridge::Custody::Zcash {
            zebra,
            source: zynzapd::bridge::Source::Transparent(addresses),
        },
        6,
        XZEC,
        dir.to_path_buf(),
        3,
        start,
    )
    .expect("bridge")
}

/// Deposits are credited *unspendable* and released when the epoch holding
/// them is anchored — the same quorum step a withdrawal needs. So a credited
/// deposit is not yet a usable balance, and this walks it through both.
fn release(node: &Arc<Mutex<Node<SwapState>>>) {
    let mut n = node.lock().unwrap();
    let epoch = n.state().epoch();
    n.submit_operator(Intent::Checkpoint, 0);
    n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
}

#[test]
fn a_transparent_deposit_becomes_a_credited_balance() {
    let dir = tmpdir("credit");
    // 0.001 ZEC == 100_000 zatoshi, mined at 10, tip at 20 — six confirmations
    // deep, so it is safe to credit.
    let addr = fake_zebra(20, 10, 100_000);
    let node = node();
    let mut b = bridge(addr, &dir, &node);

    let credited = b.poll_once(&node, 0).expect("poll");
    assert_eq!(credited, 1, "the deposit was not credited");

    let expected = Fixed::raw(100_000 * 10_000_000_000); // 100_000 zat == 0.001
    {
        let n = node.lock().unwrap();
        // The attestation landed before the credit, or the credit would have
        // been refused: units issued can never exceed units last observed.
        assert_eq!(n.state().backing_of(XZEC), expected, "backing did not move");
        assert_eq!(
            n.state().balance(&ACCOUNT, XZEC),
            Fixed::ZERO,
            "a deposit must not be spendable before its epoch is anchored"
        );
    }

    release(&node);
    let n = node.lock().unwrap();
    assert_eq!(
        n.state().balance(&ACCOUNT, XZEC),
        expected,
        "zatoshi did not convert to the ledger's scale"
    );
    drop(n);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Outputs to addresses we do not watch are not our deposits, even in a
/// transaction that also pays us.
#[test]
fn only_watched_addresses_are_credited() {
    let dir = tmpdir("watched");
    let addr = fake_zebra(20, 10, 100_000);
    let node = node();
    let mut b = bridge(addr, &dir, &node);
    b.poll_once(&node, 0).expect("poll");
    release(&node);

    let n = node.lock().unwrap();
    // The second output was 1 ZEC to a stranger. If it had been credited the
    // balance would be a thousand times larger.
    assert_eq!(
        n.state().balance(&ACCOUNT, XZEC),
        Fixed::raw(100_000 * 10_000_000_000)
    );
    drop(n);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The property the bridge is built around: scanning twice must not credit
/// twice.
#[test]
fn a_second_scan_credits_nothing() {
    let dir = tmpdir("once");
    let addr = fake_zebra(20, 10, 100_000);
    let node = node();
    let mut b = bridge(addr, &dir, &node);

    assert_eq!(b.poll_once(&node, 0).expect("first"), 1);
    let after_first = node.lock().unwrap().state().balance(&ACCOUNT, XZEC);
    assert_eq!(
        b.poll_once(&node, 0).expect("second"),
        0,
        "the deposit was credited twice"
    );
    assert_eq!(
        node.lock().unwrap().state().balance(&ACCOUNT, XZEC),
        after_first
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// And a restart must not credit twice either — the in-memory dedup set is
/// gone by then, so only the persisted progress prevents it.
#[test]
fn a_restart_does_not_re_credit() {
    let dir = tmpdir("restart");
    let addr = fake_zebra(20, 10, 100_000);
    let node = node();

    let mut first = bridge(addr, &dir, &node);
    assert_eq!(first.poll_once(&node, 0).expect("first"), 1);
    let balance = node.lock().unwrap().state().balance(&ACCOUNT, XZEC);
    drop(first);

    // A completely fresh bridge, as after a process restart.
    let mut second = bridge(addr, &dir, &node);
    assert_eq!(second.poll_once(&node, 0).expect("after restart"), 0);
    assert_eq!(
        node.lock().unwrap().state().balance(&ACCOUNT, XZEC),
        balance,
        "a restart re-credited a deposit — this is how unbacked units happen"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Too shallow to be safe: a deposit inside the confirmation window is seen
/// and deliberately not acted on.
#[test]
fn a_deposit_without_enough_confirmations_waits() {
    let dir = tmpdir("shallow");
    let addr = fake_zebra(12, 10, 100_000); // only two deep, six required
    let node = node();
    let mut b = bridge(addr, &dir, &node);

    assert_eq!(b.poll_once(&node, 0).expect("poll"), 0);
    assert_eq!(
        node.lock().unwrap().state().balance(&ACCOUNT, XZEC),
        Fixed::ZERO
    );
    let _ = std::fs::remove_dir_all(&dir);
}
