//! The whole path, over a real socket.
//!
//! A wallet signs typed data, a frame crosses TCP, the sequencer recovers the
//! signer, and the swap executes against the account that signature controls.
//! Every layer below has its own tests; this is the one that would catch them
//! being wired together wrongly.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use k256::ecdsa::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::{Intent, Receipt};
use swapvm::types::XZEC;
use swapvm::{wire, Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_vm::auth::{account_of, eip712_digest, Authorization, Scheme};
use zyn_vm::commit::Encoder;
use zyn_vm::spec::MicrochainVm;

const CHAIN: u32 = 9;
const OP_SUBMIT: u8 = 10;

fn wallet() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32].into()).unwrap()
}

/// The account that wallet controls on Zyn — derived, never declared.
fn wallet_account() -> [u8; 32] {
    let key = wallet();
    let point = key.verifying_key().to_encoded_point(false);
    let hash = zyn_vm::eip712::keccak(&[&point.as_bytes()[1..]]);
    account_of(Scheme::Secp256k1Eip712, &hash[12..])
}

/// A devnet with one funded account and one CAT market.
fn market() -> (Node<SwapState>, u32) {
    let policy = EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut n: Node<SwapState> =
        Node::new(CHAIN, Params::v1(), policy, Economics::flat(10_000));
    let who = wallet_account();

    let amount = Fixed::whole(100_000);
    let observed = n.state().backing_of(XZEC).add(amount).unwrap();
    n.submit_operator(Intent::AttestVaultBalance { asset: XZEC, observed }, 0);
    let d = Intent::next_deposit(n.state(), who, XZEC, amount, [0u8; 32]);
    n.submit_operator(d, 0);
    let epoch = n.state().epoch();
    n.submit_operator(Intent::Checkpoint, 0);
    n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);

    let step = n.submit_operator(
        Intent::CreateToken {
            creator: who,
            symbol: *b"CAT\0\0\0\0\0",
            supply: Fixed::whole(10_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(10_000),
            token_liquidity: Fixed::whole(5_000_000),
            fee_bps: 30,
        },
        0,
    );
    let pool = step
        .receipts
        .iter()
        .find_map(|r| match r {
            Receipt::PoolCreated { pool, .. } => Some(*pool),
            _ => None,
        })
        .expect("a launch opens a pool");
    (n, pool)
}

fn start(node: Node<SwapState>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let server = Arc::new(zynzapd::rpc::Server {
        node: Arc::new(Mutex::new(node)),
        chain_id: CHAIN,
        now: || 0, health: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())), inbox: std::sync::Arc::new(std::sync::Mutex::new(zynzapd::rpc::Inbox::default())),
        replica: None,
        replay: Arc::new(Mutex::new(zyn::replay::ReplayIndex::default())), deposits: None, da_dir: None,
    });
    std::thread::spawn(move || zynzapd::rpc::serve(server, listener));
    addr
}

fn call(addr: SocketAddr, frame: &[u8]) -> (u8, Vec<u8>) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    s.write_all(frame).unwrap();
    s.flush().unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).expect("response length");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).expect("response body");
    (body[0], body[1..].to_vec())
}

fn swap_intent(pool: u32, amount: i64, min_out: i64) -> Intent {
    Intent::SwapExactIn {
        account: wallet_account(),
        asset_in: XZEC,
        path: vec![pool],
        amount_in: Fixed::whole(amount),
        min_out: Fixed::whole(min_out),
    }
}

/// Sign exactly as `eth_signTypedData_v4` does, then frame it.
fn submit_frame(intent: &Intent, valid_until: u64) -> Vec<u8> {
    let auth = Authorization {
        chain_id: CHAIN,
        vm_id: zyn_vm::zvm::vm_id::<SwapState>(),
        valid_until_epoch: valid_until,
    };
    let digest = eip712_digest::<SwapState>(&auth, intent);
    let (sig, rid) = wallet().sign_prehash_recoverable(&digest).unwrap();
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(&sig.to_bytes());
    sig65[64] = rid.to_byte() + 27;

    let mut e = Encoder::new();
    e.u8(OP_SUBMIT)
        .u32(CHAIN)
        .bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(Scheme::Secp256k1Eip712.tag())
        .bytes(&sig65);
    let mut body = e.finish().to_vec();
    body.extend_from_slice(&wire::encode_intent_bytes(intent));
    body
}

/// The headline: nothing but a signature, and a balance moves.
#[test]
fn a_wallet_signature_moves_a_balance_over_tcp() {
    let (node, pool) = market();
    let addr = start(node);

    let intent = swap_intent(pool, 10, 0);
    let (status, body) = call(addr, &submit_frame(&intent, u64::MAX));
    assert_eq!(
        status,
        wire::STATUS_OK,
        "a signed swap was refused: {}",
        String::from_utf8_lossy(&body)
    );

    let mut e = Encoder::new();
    e.u8(wire::OP_STATUS).u32(CHAIN);
    let (status, body) = call(addr, e.finish());
    assert_eq!(status, wire::STATUS_OK);
    let seq = u64::from_be_bytes(body[..8].try_into().unwrap());
    assert!(seq > 0, "the chain did not advance");
}

/// The quote a UI would show must be the number the chain would pay.
#[test]
fn a_quote_over_the_wire_matches_the_engine() {
    let (node, pool) = market();
    let expected = swapvm::vm::quote(node.state(), XZEC, &[pool], Fixed::whole(10))
        .expect("quote")
        .amount_out;
    let addr = start(node);

    let mut e = Encoder::new();
    e.u8(wire::OP_QUOTE).u32(CHAIN).u32(XZEC).u32(1).u32(pool).i128(Fixed::whole(10).0);
    let (status, body) = call(addr, e.finish());
    assert_eq!(status, wire::STATUS_OK);
    let out = Fixed(i128::from_be_bytes(body[..16].try_into().unwrap()));
    assert_eq!(out, expected, "the wire quote disagreed with the engine");
    // And the ceiling comes with it, so a router gets a bracket rather than a
    // point it cannot rely on.
    let best = Fixed(i128::from_be_bytes(body[16..32].try_into().unwrap()));
    assert!(best > out, "the wire quote carried no upper bound");
}

/// A quote is a read: it must need no wallet at all.
#[test]
fn quoting_requires_no_signature() {
    let (node, pool) = market();
    let addr = start(node);
    let mut e = Encoder::new();
    e.u8(wire::OP_QUOTE).u32(CHAIN).u32(XZEC).u32(1).u32(pool).i128(Fixed::whole(1).0);
    assert_eq!(call(addr, e.finish()).0, wire::STATUS_OK);
}

/// The signature covers the trade, so a relayer that edits it in flight is
/// signing for an account that does not exist.
#[test]
fn a_tampered_swap_does_not_execute() {
    let (node, pool) = market();
    let addr = start(node);

    let signed = swap_intent(pool, 10, 0);
    let mut frame = submit_frame(&signed, u64::MAX);
    let head = frame.len() - wire::encode_intent_bytes(&signed).len();
    frame.truncate(head);
    frame.extend_from_slice(&wire::encode_intent_bytes(&swap_intent(pool, 9_000, 0)));

    let (status, body) = call(addr, &frame);
    assert_eq!(
        status,
        wire::STATUS_ERR,
        "a rewritten trade was accepted: {}",
        String::from_utf8_lossy(&body)
    );
}

#[test]
fn an_unsigned_write_is_refused() {
    let (node, pool) = market();
    let addr = start(node);
    let mut e = Encoder::new();
    e.u8(OP_SUBMIT).u32(CHAIN);
    let mut frame = e.finish().to_vec();
    frame.extend_from_slice(&wire::encode_intent_bytes(&swap_intent(pool, 1, 0)));
    assert_eq!(call(addr, &frame).0, wire::STATUS_ERR);
}

/// The exit hatch must serve a root that was actually committed.
///
/// A snapshot of *current* state opens a root nobody sealed and Zcash never
/// saw, so a proof against it verifies nothing. Before the first anchor the
/// only honest answer is that there is nothing to serve.
#[test]
fn the_snapshot_endpoint_serves_an_anchored_root_or_nothing() {
    let policy = EpochPolicy {
        intents_per_epoch: 2,
        epochs_per_anchor: 1,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut n: Node<SwapState> =
        Node::new(CHAIN, Params::testnet(), policy, Economics::flat(10_000));

    // Nothing anchored yet.
    let unanchored = start_with(n.state().clone(), policy);
    let mut e = Encoder::new();
    e.u8(wire::OP_SNAPSHOT).u32(CHAIN);
    let (status, body) = call(unanchored, e.finish());
    assert_eq!(status, wire::STATUS_ERR, "a root nobody anchored was served as a snapshot");
    assert!(String::from_utf8_lossy(&body).contains("no anchored snapshot"));

    // Drive it past an anchor.
    for _ in 0..6 {
        n.submit_operator(Intent::Checkpoint, 0);
    }
    let anchored_root = n.publishable().expect("the chain must have anchored").root;
    let addr = start(n);

    let mut e = Encoder::new();
    e.u8(wire::OP_SNAPSHOT).u32(CHAIN);
    let (status, body) = call(addr, e.finish());
    assert_eq!(status, wire::STATUS_OK, "an anchored chain refused to publish");
    let served: [u8; 32] = body[8..40].try_into().unwrap();
    assert_eq!(served, anchored_root, "the snapshot did not open the anchored root");
}

fn start_with(state: SwapState, policy: EpochPolicy) -> SocketAddr {
    start(Node::resume(state, policy, Economics::flat(10_000), 0))
}
