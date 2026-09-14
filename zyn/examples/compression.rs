//! Is the microchain actually batching anything?
//!
//! The architecture's whole claim is that many actions settle as one Zcash
//! transaction. That is a number, so it should be measured rather than
//! asserted.

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{Fixed, Params};
use zyn::epoch::{Economics, EpochPolicy};
use zyn::node::Node;
use zyn_vm::spec::MicrochainVm;

fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    // A plausible production policy: seal every 256 actions, anchor every 30
    // epochs. One Zcash transaction should therefore carry ~7,680 actions.
    let policy = EpochPolicy {
        intents_per_epoch: 256,
        epochs_per_anchor: 30,
        max_seconds_per_epoch: 0,
        max_seconds_per_anchor: 0,
    };
    // ~0.0001 ZEC, an ordinary Zcash transaction.
    let mut node: Node<SwapState> =
        Node::new(1, Params::testnet(), policy, Economics::flat(10_000));

    let who = [1u8; 32];
    let amount = Fixed::whole(1_000_000);
    let observed = node.state().backing_of(XZEC).add(amount).unwrap();
    node.submit_operator(
        Intent::AttestVaultBalance {
            asset: XZEC,
            observed,
        },
        0,
    );
    let d = Intent::next_deposit(node.state(), who, XZEC, amount, [0u8; 32]);
    node.submit_operator(d, 0);
    let e = node.state().epoch();
    node.submit_operator(Intent::Checkpoint, 0);
    node.submit_operator(Intent::ConfirmAnchor { epoch: e }, 0);

    let mut anchors_seen = 0u64;
    let mut seals_seen = 0u64;
    for i in 0..n {
        let step = node.submit_operator(
            Intent::Transfer {
                from: who,
                to: [(i % 200) as u8 + 2; 32],
                asset: XZEC,
                amount: Fixed::raw(1_000),
            },
            0,
        );
        if step.sealed.is_some() {
            seals_seen += 1;
        }
        if step.anchor.is_some() {
            anchors_seen += 1;
        }
    }

    let r = node.report();
    println!("{} actions submitted\n", n);
    println!("  epochs sealed        {}", r.compression.epochs);
    println!("  anchors produced     {}", r.compression.anchors);
    println!(
        "  (observed: {} seals, {} anchors)",
        seals_seen, anchors_seen
    );
    println!("  epochs still pending {}", node.pending().len());
    println!();
    match r.ratio {
        None => println!("  no anchor yet — nothing has been batched"),
        Some(ratio) => {
            println!("  actions per Zcash transaction   {}", ratio);
            println!("  Zcash transactions absorbed     {}", r.transactions_saved);
            if let Some(c) = r.cost_per_action {
                println!("  L1 cost per action              {} zatoshi", c);
            }
            println!("  L1 cost avoided                 {} zatoshi", r.l1_saved);
        }
    }
    println!();
    println!(
        "  final seq {}  epoch {}",
        node.state().seq(),
        node.state().epoch()
    );
    println!(
        "  a snapshot is {}",
        if node.publishable().is_some() {
            "available to publish"
        } else {
            "NOT available"
        }
    );
}
