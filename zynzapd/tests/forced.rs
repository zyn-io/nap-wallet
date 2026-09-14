//! A forced intent is applied once, whichever route it takes.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{wire, Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn::replay::ReplayIndex;
use zyn_custody::shielded::ForcedSighting;
use zyn_vm::commit::Encoder;
use zyn_vm::spec::MicrochainVm;
use zynzapd::bridge::{apply_forced, ForcedOutcome};
use zynzapd::client::{account, frame_submission};
use zynzapd::rpc::{self, Inbox, Server};

const CHAIN: u32 = 41;

fn funded_node(k: &SigningKey) -> Node<SwapState> {
    let policy = EpochPolicy {
        intents_per_epoch: 1_000,
        epochs_per_anchor: 1_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut s = SwapState::new(CHAIN, Params::testnet());
    s.tokens
        .get_mut(&XZEC)
        .unwrap()
        .vault
        .as_mut()
        .unwrap()
        .observed = Fixed::whole(1_000);
    let mut n = Node::resume(s, policy, Economics::flat(1), 0);
    let d = Intent::next_deposit(n.state(), account(k), XZEC, Fixed::whole(10), [0u8; 32]);
    assert!(!n.submit_operator(d, 0).rejected());
    // A credit is spendable once its epoch is anchored.
    n.seal_now(0).expect("seal");
    n.anchor_now(0).expect("anchor");
    assert_eq!(balance(&n, &account(k)), Fixed::whole(10));
    n
}

fn transfer(k: &SigningKey) -> Intent {
    Intent::Transfer {
        from: account(k),
        to: [0xAB; 32],
        asset: XZEC,
        amount: Fixed::whole(1),
    }
}

fn balance(n: &Node<SwapState>, who: &[u8; 32]) -> Fixed {
    n.state()
        .accounts
        .get(who)
        .and_then(|a| a.balances.get(&XZEC).copied())
        .unwrap_or(Fixed::ZERO)
}

#[test]
fn a_forced_intent_at_depth_is_applied_once_and_junk_is_ignored() {
    let k = SigningKey::from_bytes(&[5u8; 32]);
    let mut n = funded_node(&k);
    let replay = Arc::new(Mutex::new(ReplayIndex::default()));
    let mut seen = BTreeSet::new();
    let frame = frame_submission(&k, CHAIN, n.state().epoch(), &transfer(&k));
    let sighting = ForcedSighting {
        txid: [1u8; 32],
        height: 100,
        amount: Fixed::raw(1),
        frame: frame.clone(),
    };

    // Not deep enough: nothing happens, and it is not marked seen.
    let out = apply_forced(
        &mut n,
        &replay,
        CHAIN,
        &[sighting.clone()],
        104,
        6,
        &mut seen,
        0,
    );
    assert_eq!(out[0].1, ForcedOutcome::Waiting);
    assert!(seen.is_empty());
    assert_eq!(balance(&n, &[0xAB; 32]), Fixed::ZERO);

    // At depth: applied, exactly once, whatever the sighting is called.
    let out = apply_forced(
        &mut n,
        &replay,
        CHAIN,
        &[sighting.clone()],
        105,
        6,
        &mut seen,
        0,
    );
    assert_eq!(out[0].1, ForcedOutcome::Applied);
    assert_eq!(balance(&n, &[0xAB; 32]), Fixed::whole(1));
    let again = apply_forced(
        &mut n,
        &replay,
        CHAIN,
        &[sighting.clone()],
        200,
        6,
        &mut seen,
        0,
    );
    assert!(again.is_empty(), "a handled sighting is skipped");
    let twin = ForcedSighting {
        txid: [2u8; 32],
        ..sighting.clone()
    };
    let out = apply_forced(&mut n, &replay, CHAIN, &[twin], 200, 6, &mut seen, 0);
    assert_eq!(
        out[0].1,
        ForcedOutcome::Replay,
        "the same signature on another note is a replay"
    );
    assert_eq!(balance(&n, &[0xAB; 32]), Fixed::whole(1));

    // Junk frames are ignored and remembered.
    let junk = ForcedSighting {
        txid: [3u8; 32],
        height: 100,
        amount: Fixed::raw(1),
        frame: b"nonsense".to_vec(),
    };
    let out = apply_forced(&mut n, &replay, CHAIN, &[junk], 200, 6, &mut seen, 0);
    assert_eq!(out[0].1, ForcedOutcome::Junk);
    // A frame whose signature is for another chain does not verify.
    let foreign = frame_submission(&k, CHAIN + 1, n.state().epoch(), &transfer(&k));
    let out = apply_forced(
        &mut n,
        &replay,
        CHAIN,
        &[ForcedSighting {
            txid: [4u8; 32],
            height: 100,
            amount: Fixed::raw(1),
            frame: foreign,
        }],
        200,
        6,
        &mut seen,
        0,
    );
    assert_eq!(out[0].1, ForcedOutcome::Junk);
}

#[test]
fn rpc_then_memo_applies_once_and_the_rpc_refuses_a_replay() {
    let k = SigningKey::from_bytes(&[6u8; 32]);
    let n = funded_node(&k);
    let replay = Arc::new(Mutex::new(ReplayIndex::default()));
    let server = Server {
        node: Arc::new(Mutex::new(n)),
        chain_id: CHAIN,
        now: || 0,
        health: Arc::new(Mutex::new(Vec::new())),
        inbox: Arc::new(Mutex::new(Inbox::default())),
        replica: None,
        replay: Arc::clone(&replay),
        deposits: None,
        da_dir: None,
    };
    let epoch = server.node.lock().unwrap().state().epoch();
    let frame = frame_submission(&k, CHAIN, epoch, &transfer(&k));
    let mut e = Encoder::new();
    e.u8(rpc::OP_SUBMIT).u32(CHAIN).bytes(&frame);
    let req = e.finish().to_vec();
    let out = rpc::dispatch(&server, &req);
    assert_eq!(
        out[0],
        wire::STATUS_OK,
        "{}",
        String::from_utf8_lossy(&out[3..])
    );
    assert_eq!(
        balance(&server.node.lock().unwrap(), &[0xAB; 32]),
        Fixed::whole(1)
    );
    // The identical frame over RPC again: refused as a replay.
    let out = rpc::dispatch(&server, &req);
    assert_eq!(out[0], wire::STATUS_ERR);
    assert!(String::from_utf8_lossy(&out[3..]).contains("replay"));
    // And the same frame arriving by memo is a replay too.
    let mut seen = BTreeSet::new();
    let s = ForcedSighting {
        txid: [9u8; 32],
        height: 1,
        amount: Fixed::raw(1),
        frame,
    };
    let out = apply_forced(
        &mut server.node.lock().unwrap(),
        &replay,
        CHAIN,
        &[s],
        100,
        6,
        &mut seen,
        0,
    );
    assert_eq!(out[0].1, ForcedOutcome::Replay);
    assert_eq!(
        balance(&server.node.lock().unwrap(), &[0xAB; 32]),
        Fixed::whole(1)
    );
    // A fresh signature over the same intent is a new submission.
    let frame2 = frame_submission(&k, CHAIN, epoch + 1, &transfer(&k));
    let mut e = Encoder::new();
    e.u8(rpc::OP_SUBMIT).u32(CHAIN).bytes(&frame2);
    let out = rpc::dispatch(&server, e.finish());
    assert_eq!(
        out[0],
        wire::STATUS_OK,
        "{}",
        String::from_utf8_lossy(&out[3..])
    );
    assert_eq!(
        balance(&server.node.lock().unwrap(), &[0xAB; 32]),
        Fixed::whole(2)
    );
}
