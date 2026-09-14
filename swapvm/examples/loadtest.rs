//! What a Zyn node actually costs to run.
//!
//! Hardware requirements for an execution layer are usually quoted from
//! intuition. This measures instead: throughput, state growth, the cost of a
//! state root, and the cost of the two things a node does that are *not* O(1) —
//! sealing an epoch and publishing the data holders exit against.
//!
//! Run with `cargo run --release --example loadtest`. Debug figures are
//! meaningless here; the release profile also turns on `overflow-checks`, so
//! these numbers include the checked arithmetic the VM is required to do.

use std::time::Instant;

use swapvm::state::{symbol, SwapState};
use swapvm::tx::{Intent, SequencedIntent};
use swapvm::types::{AccountId, AssetId, Params, PoolId, ADDRESS_SCOPE_V1, XZEC};
use swapvm::{vm, Fixed};

fn acct(n: u64) -> AccountId {
    let mut a = [0u8; 32];
    a[..8].copy_from_slice(&n.to_be_bytes());
    a
}

struct Chain {
    state: SwapState,
}

impl Chain {
    fn go(&mut self, intent: Intent) {
        let seq = self.state.seq + 1;
        let r = vm::apply(&mut self.state, &SequencedIntent { seq, intent });
        assert!(
            !r.iter().any(|x| x.is_rejection()),
            "setup rejected: {:?}",
            r
        );
    }
}

/// A market with `traders` funded accounts and one CAT/xZEC pool.
fn market(traders: u64) -> (Chain, AssetId, PoolId) {
    let mut c = Chain {
        state: SwapState::new(1, Params::v1()),
    };
    let observed = Fixed::whole(10_000_000_000);
    c.go(Intent::AttestVaultBalance {
        asset: XZEC,
        observed,
    });
    c.go(Intent::next_deposit(
        &c.state,
        acct(0),
        XZEC,
        Fixed::whole(10_000_000),
        [0u8; 32],
    ));
    for n in 1..=traders {
        c.go(Intent::next_deposit(
            &c.state,
            acct(n),
            XZEC,
            Fixed::whole(10_000),
            [0u8; 32],
        ));
    }
    let at = c.state.epoch;
    c.go(Intent::Checkpoint);
    c.go(Intent::ConfirmAnchor { epoch: at });

    c.go(Intent::CreateToken {
        creator: acct(0),
        symbol: symbol(b"CAT"),
        supply: Fixed::whole(1_000_000_000),
        unit: Fixed::raw(1),
        xzec_liquidity: Fixed::whole(1_000_000),
        token_liquidity: Fixed::whole(500_000_000),
        fee_bps: 30,
    });
    let cat = zyn_vm::asset_address(ADDRESS_SCOPE_V1, &acct(0), b"CAT");
    let pool = zyn_vm::pool_address(ADDRESS_SCOPE_V1, &XZEC, &cat);
    (c, cat, pool)
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn main() {
    println!("Zyn node cost, measured. Release build, overflow checks on.\n");

    // --- throughput -------------------------------------------------------
    let (mut c, _cat, pool) = market(1_000);
    let swaps = 100_000u64;
    let t = Instant::now();
    for i in 0..swaps {
        c.go(Intent::SwapExactIn {
            account: acct(1 + (i % 1_000)),
            asset_in: XZEC,
            path: vec![pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        });
    }
    let d = t.elapsed();
    println!("throughput");
    println!("  {} swaps in {:.0} ms", swaps, ms(d));
    println!("  {:.0} swaps/sec", swaps as f64 / d.as_secs_f64());
    println!(
        "  {:.1} us per swap\n",
        d.as_secs_f64() * 1e6 / swaps as f64
    );

    // --- state root, by account count -------------------------------------
    println!("state root (the cost of sealing an epoch)");
    for n in [1_000u64, 10_000, 50_000] {
        let (mut c, _, _) = market(n);
        // Warm: compute once, then time.
        let _ = c.state.state_root();
        let t = Instant::now();
        let root = c.state.state_root();
        let d = t.elapsed();
        let bytes = c.state.encode_state().len();
        println!(
            "  {:>6} accounts  root {:>7.1} ms   state {:>7.2} MiB   ({:.0} B/account)",
            n,
            ms(d),
            bytes as f64 / (1024.0 * 1024.0),
            bytes as f64 / n as f64,
        );
        let _ = root;
        c.go(Intent::Checkpoint);
    }
    println!();

    // --- the exit hatch ---------------------------------------------------
    println!("serving withdrawal proofs (the endpoint read path)");
    for n in [1_000u64, 10_000, 50_000] {
        let (c, _, _) = market(n);

        // Naive: rebuild the tree per request.
        let t = Instant::now();
        let path = c.state.account_proof(&acct(1)).expect("provable");
        let naive = t.elapsed();

        // Indexed: build once per root, then serve.
        let t = Instant::now();
        let index = c.state.account_index();
        let build = t.elapsed();
        let reqs = 1_000;
        let t = Instant::now();
        for i in 0..reqs {
            let (leaf, p) = index.proof(&acct(1 + (i % n))).expect("provable");
            std::hint::black_box((leaf, p.len()));
        }
        let served = t.elapsed();

        println!(
            "  {:>6} accounts  rebuild-per-request {:>7.2} ms ({:>5.0}/s)   \
indexed: build {:>5.1} ms, then {:>6.1} us each ({:>9.0}/s)   {} siblings",
            n,
            ms(naive),
            1.0 / naive.as_secs_f64(),
            ms(build),
            served.as_secs_f64() * 1e6 / reqs as f64,
            reqs as f64 / served.as_secs_f64(),
            path.len(),
        );
    }
    println!();

    // --- what has to be published, and how often --------------------------
    println!("data availability (published per anchor, so holders can exit)");
    for n in [1_000u64, 10_000, 50_000] {
        let (c, _, _) = market(n);
        let payload: usize = c
            .state
            .accounts
            .keys()
            .map(|id| c.state.account_record(id).map(|r| r.len()).unwrap_or(0))
            .sum();
        // A day of anchors at the v1 policy: 250 intents/epoch x 7 epochs.
        let per_day = 24.0 * 60.0 * 60.0 / (15.0 * 60.0); // the anchor failsafe
        println!(
            "  {:>6} accounts  {:>7.2} MiB per publish   {:>6.1} GiB/day at one publish per 15 min",
            n,
            payload as f64 / (1024.0 * 1024.0),
            payload as f64 * per_day / (1024.0 * 1024.0 * 1024.0),
        );
    }
    println!();

    // --- what an epoch and an anchor cost ---------------------------------
    let (mut c, _, pool) = market(10_000);
    for i in 0..20_000u64 {
        c.go(Intent::SwapExactIn {
            account: acct(1 + (i % 10_000)),
            asset_in: XZEC,
            path: vec![pool],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        });
    }
    let t = Instant::now();
    c.go(Intent::Checkpoint);
    println!(
        "sealing an epoch over 10,000 accounts: {:.1} ms",
        ms(t.elapsed())
    );

    let t = Instant::now();
    let blob = c.state.encode_state();
    let d_enc = t.elapsed();
    let t = Instant::now();
    let back = SwapState::decode_state(&blob).expect("decode");
    let d_dec = t.elapsed();
    println!(
        "restart from a saved state ({:.2} MiB): encode {:.1} ms, decode {:.1} ms",
        blob.len() as f64 / (1024.0 * 1024.0),
        ms(d_enc),
        ms(d_dec),
    );
    assert_eq!(back.state_root(), c.state.state_root());
    c.state.check_invariants().expect("consistent");
}
