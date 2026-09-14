//! The hackathon sequence, over a real socket.
//!
//! Claim, sell, sell back, redeem — the four beats that happen on Zyn, driven
//! through the same client a storefront would use. Every layer below has its
//! own tests; this is the one that would catch the paid claim or the resting
//! offer being unreachable from outside the VM, which is exactly what they
//! were before this ran.

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node as VmNode;
use zynzapd::client::{account, Node};

const CHAIN: u32 = 9;

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

/// A chain where the creator and both traders hold spendable ZEC.zy.
fn funded_chain() -> VmNode<SwapState> {
    let policy = EpochPolicy {
        intents_per_epoch: 10_000,
        epochs_per_anchor: 10_000,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    let mut n: VmNode<SwapState> =
        VmNode::new(CHAIN, Params::v1(), policy, Economics::flat(10_000));
    let each = Fixed::whole(100);
    let total = Fixed::whole(300);
    n.submit_operator(
        Intent::AttestVaultBalance {
            asset: XZEC,
            observed: total,
        },
        0,
    );
    for (i, k) in [key(1), key(2), key(3)].iter().enumerate() {
        let idx = n.state().next_deposit_index(XZEC);
        n.submit_operator(
            Intent::CreditDeposit {
                account: account(k),
                asset: XZEC,
                amount: each,
                index: idx,
                external_ref: [i as u8 + 60; 32],
            },
            0,
        );
    }
    let epoch = n.state().epoch;
    n.submit_operator(Intent::Checkpoint, 0);
    n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
    n
}

fn start(node: VmNode<SwapState>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    let server = Arc::new(zynzapd::rpc::Server {
        node: Arc::new(Mutex::new(node)),
        chain_id: CHAIN,
        now: || 0,
        health: Arc::new(Mutex::new(Vec::new())),
        inbox: Arc::new(Mutex::new(zynzapd::rpc::Inbox::default())),
        replica: None,
        replay: Arc::new(Mutex::new(zyn::replay::ReplayIndex::default())),
        deposits: None,
        da_dir: None,
    });
    std::thread::spawn(move || zynzapd::rpc::serve(server, listener));
    addr
}

/// Claim, sell, sell back, redeem.
///
/// The assertion that matters is the last one: the piece redeems for more than
/// the claim cost, and the difference is exactly the traders' fees. That is the
/// floor being built by trading, which is the whole argument the demo makes.
#[test]
fn a_piece_is_claimed_traded_twice_and_redeemed_above_its_claim_price() {
    let addr = start(funded_chain());
    let node = Node::new(&format!("{}", addr), CHAIN);

    let creator = key(1);
    let a = key(2);
    let b = key(3);

    // The sale: a collection of one, at 1% a side.
    node.create_collection(&creator, swapvm::state::symbol(b"NAP"), 1, 100)
        .expect("create");
    let collection = node.collections().expect("collections")[0].id;
    node.advance_collection(&creator, collection, 1)
        .expect("open claiming");

    // The paid claim, as two honest intents: the buyer pays into the pool
    // themselves, and the creator hands the piece over. Nothing here is
    // privileged except the mint, which is the creator's to sign.
    let price = Fixed::whole(5);
    node.fund_collection(&a, collection, price)
        .expect("buyer pays");
    node.mint_collection_item(
        &creator,
        collection,
        0,
        account(&a),
        swapvm::state::symbol(b"NAP"),
        [7u8; 32],
    )
    .expect("mint");
    let item = node
        .assets()
        .expect("assets")
        .iter()
        .find(|x| x.is_item())
        .map(|x| x.id)
        .expect("an item exists");

    // The market opens; only now is there a floor.
    node.advance_collection(&creator, collection, 2)
        .expect("close claiming");
    node.advance_collection(&creator, collection, 3)
        .expect("list");
    let floor_at_claim = node.collection(collection).unwrap().unwrap().redeem_price;
    assert_eq!(
        floor_at_claim, price,
        "one piece, one claim: the floor is what was paid"
    );

    // A rests an offer; B takes it without A being asked again.
    let sale = Fixed::whole(6);
    node.place_offer(&a, item, Fixed::ONE, XZEC, sale, u64::MAX)
        .expect("A lists");
    let offer = node.offers().expect("book")[0].id;
    node.take_offer(&b, offer).expect("B buys");

    // And back the other way, so the fee is charged twice.
    node.place_offer(&b, item, Fixed::ONE, XZEC, sale, u64::MAX)
        .expect("B lists");
    let offer = node.offers().expect("book")[0].id;
    node.take_offer(&a, offer).expect("A buys back");

    // Two trades, each charging 1% to both sides, 40% of every charge to the
    // pool: 4 x 1% of 6 x 40% is 0.096 on top of the 5 that was claimed.
    let each = Fixed::raw(sale.0 / 100);
    let to_pool = each
        .add(each)
        .unwrap()
        .mul_div(Fixed::whole(4_000), Fixed::whole(10_000))
        .unwrap();
    let expected = price.add(to_pool).unwrap().add(to_pool).unwrap();
    let floor_now = node.collection(collection).unwrap().unwrap().redeem_price;
    assert_eq!(floor_now, expected, "the floor is built by trading");
    assert!(floor_now > floor_at_claim, "and it only went up");

    // The holder takes the pool's share and the piece stops existing.
    let before = node
        .account(&a)
        .expect("account")
        .expect("a record")
        .spendable
        .iter()
        .find(|(x, _)| *x == XZEC)
        .map(|(_, v)| *v)
        .unwrap_or(Fixed::ZERO);
    node.redeem_collection_item(&a, item).expect("redeem");
    let after = node
        .account(&a)
        .expect("account")
        .expect("a record")
        .spendable
        .iter()
        .find(|(x, _)| *x == XZEC)
        .map(|(_, v)| *v)
        .unwrap_or(Fixed::ZERO);
    assert_eq!(
        after.sub(before).unwrap(),
        floor_now,
        "paid exactly the floor"
    );
    assert_eq!(
        node.collection(collection).unwrap().unwrap().outstanding,
        0,
        "nothing left outstanding"
    );
}

/// The property a marketplace needs and `AcceptOffer` cannot give: the seller
/// is not consulted when the sale happens, and is not even reachable.
#[test]
fn a_resting_offer_is_taken_without_the_maker_signing_anything() {
    let addr = start(funded_chain());
    let node = Node::new(&format!("{}", addr), CHAIN);
    let creator = key(1);
    let a = key(2);
    let b = key(3);

    node.create_collection(&creator, swapvm::state::symbol(b"NAP"), 1, 100)
        .expect("create");
    let collection = node.collections().expect("collections")[0].id;
    node.advance_collection(&creator, collection, 1)
        .expect("minting");
    node.mint_collection_item(
        &creator,
        collection,
        0,
        account(&a),
        swapvm::state::symbol(b"NAP"),
        [3u8; 32],
    )
    .expect("mint");
    let item = node
        .assets()
        .expect("assets")
        .iter()
        .find(|x| x.is_item())
        .map(|x| x.id)
        .expect("item");
    node.advance_collection(&creator, collection, 2)
        .expect("closed");
    node.advance_collection(&creator, collection, 3)
        .expect("live");

    node.place_offer(&a, item, Fixed::ONE, XZEC, Fixed::whole(6), u64::MAX)
        .expect("list");
    let book = node.offers().expect("book");
    assert_eq!(book.len(), 1, "the order book is public");
    assert_eq!(book[0].maker, account(&a));

    // Nothing signed by A takes part in what follows.
    node.take_offer(&b, book[0].id).expect("B takes it alone");
    assert!(
        node.offers().expect("book").is_empty(),
        "and it leaves the book"
    );

    let held = node
        .account(&b)
        .expect("account")
        .expect("a record")
        .spendable
        .iter()
        .any(|(x, v)| *x == item && *v == Fixed::ONE);
    assert!(held, "B holds the piece");
}
