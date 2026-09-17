//! Collection Z's sale policy and terms, assembled from what was decided.
//!
//! Every value here was settled somewhere else and is repeated rather than
//! chosen: quantity on 9 Sep, prices in §64.17, the manifest root by building
//! it, the close rule in §100.8. What did not exist was anything that put them
//! in one object and printed a digest — so the terms could not be published,
//! and until terms are published nothing may be sold (§64.16).
//!
//! It prints. It does not broadcast, sign, or write to the chain: publishing is
//! a deliberate act and this is the thing you read before taking it.
//!
//!   zyn-cave-terms                 print the policy and terms, with digests
//!   zyn-cave-terms announce <H>    the close announcement for close height H

use cave_randomness::{
    AllocationPolicy, AnnouncedClose, CloseAnnouncement, IdentityPolicy, QuantityPolicy,
    RandomnessPlan, SaleTerms, WeightedOutcome, QUICKNET_CHAIN_HASH,
};
use swapvm::types::TREASURY_26460;
use zyn_vm::derive::ADDRESS_SCOPE_V1;

const SYMBOL: &str = "CAVEZ";
const SUPPLY: u32 = 4_444;

/// The manifest root over all 4,444, from `zyn-cave-manifest` (§86.3). Pinned
/// rather than recomputed: the terms must commit to a root someone checked,
/// not to whatever a rebuild happens to produce today.
const MANIFEST_ROOT: &str = "02b01b16da58e0d71ae27099daba30a0a7936cdd852ee325853f679886dd8f19";

/// §64.17, frozen: entry / claim / open mint, in zatoshi.
const ENTRY: u64 = 1_000_000; // 0.01 ZEC
const CLAIM: u64 = 500_000; // 0.005 ZEC
const OPEN_MINT: u64 = 1_330_000; // 0.0133 ZEC
/// 10% to the treasury; the remaining 90% funds the collection and is the floor.
const TREASURY_BPS: u16 = 1_000;
/// Six confirmations before a deposit is a ticket.
const CONFIRMATIONS: u32 = 6;
/// A claim may be made for about a fortnight of mainnet blocks after the close.
const CLAIM_WINDOW: u32 = 16_128;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

pub fn policy() -> AllocationPolicy {
    AllocationPolicy {
        collection_id: zyn_vm::collection_address(ADDRESS_SCOPE_V1, &TREASURY_26460, SYMBOL.as_bytes()),
        supply: SUPPLY,
        entry_price_zatoshi: ENTRY,
        // Announced, not committed: how long to run is judged by watching
        // demand, and the reveal is derived from whatever is announced so the
        // timing stays a decision and the outcome does not (§100.2).
        deposit_close_zcash_height: 0,
        // Decided 9 Sep: one ticket draws 1, 2 or 3 items.
        quantity: QuantityPolicy::Weighted {
            outcomes: vec![
                WeightedOutcome { items: 1, weight: 80 },
                WeightedOutcome { items: 2, weight: 19 },
                WeightedOutcome { items: 3, weight: 1 },
            ],
        },
        identity: IdentityPolicy::ConcealedShuffle,
        manifest_root: unhex32(MANIFEST_ROOT),
        randomness: RandomnessPlan {
            drand_chain_hash: QUICKNET_CHAIN_HASH,
            // A weighted draw resolves at a round this far past the ticket's
            // own, so it cannot be known when the ticket is made.
            ticket_round_delay: 10,
            reveal_drand_round: None,
            reveal_zcash_height: None,
            announced_close: Some(AnnouncedClose {
                reveal_offset_blocks: 100,   // ~2 h past the close
                reveal_offset_rounds: 2_400, // ~2 h of 3 s drand rounds
                min_notice_blocks: 1_152,    // ~1 day of notice
            }),
        },
    }
}

pub fn terms(p: &AllocationPolicy) -> SaleTerms {
    SaleTerms {
        policy_digest: p.digest().expect("the policy must validate"),
        collection_id: p.collection_id,
        manifest_root: p.manifest_root,
        treasury: TREASURY_26460,
        network: 0, // Zcash mainnet
        entry_price_zatoshi: ENTRY,
        claim_price_zatoshi: CLAIM,
        open_mint_price_zatoshi: OPEN_MINT,
        min_confirmations: CONFIRMATIONS,
        claim_window_blocks: CLAIM_WINDOW,
        treasury_bps: TREASURY_BPS,
    }
}

fn main() {
    let p = policy();
    if let Err(e) = p.validate() {
        eprintln!("zyn-cave-terms: the policy does not validate: {e}");
        std::process::exit(1);
    }
    let t = terms(&p);
    if let Err(e) = t.check(&p) {
        eprintln!("zyn-cave-terms: the terms do not agree with the policy: {e}");
        std::process::exit(1);
    }

    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("announce") {
        let close: u32 = args
            .next()
            .and_then(|h| h.parse().ok())
            .unwrap_or_else(|| {
                eprintln!("zyn-cave-terms announce <close-height>");
                std::process::exit(2);
            });
        // Built, not published: there is no proof yet, because publishing it is
        // what creates one. `resolve_unproven` is the honest call here and is
        // named so that using it anywhere else is visible (§101.4).
        let a = CloseAnnouncement {
            policy_digest: t.policy_digest,
            // Filled in by whoever broadcasts: the tip and round at that moment.
            announced_at_zcash_height: 0,
            announced_at_drand_round: 0,
            deposit_close_zcash_height: close,
        };
        println!("close announcement for height {close}");
        println!("  policy digest   {}", hex(&a.policy_digest));
        println!("  fill in announced_at_zcash_height and announced_at_drand_round");
        println!("  at broadcast, then publish digest(announcement) in a ZYP memo");
        println!("  reveal will be   close + {} blocks", 100);
        println!("  drand round      announced_round + {}", 2_400);
        return;
    }

    println!("Cave Collection Z — sale policy and terms");
    println!();
    println!("collection {}   {}", SYMBOL, hex(&p.collection_id));
    println!("supply                {}", p.supply);
    println!("manifest root         {}", hex(&p.manifest_root));
    println!("quantity              weighted 1:80  2:19  3:1");
    println!("identity              concealed shuffle");
    println!("close                 announced, >= 1152 blocks' notice");
    println!("reveal                close + 100 blocks, announced round + 2400");
    println!("treasury              {}", hex(&t.treasury));
    println!(
        "prices (zatoshi)      entry {}  claim {}  open mint {}",
        t.entry_price_zatoshi, t.claim_price_zatoshi, t.open_mint_price_zatoshi
    );
    println!("confirmations         {}", t.min_confirmations);
    println!("claim window          {} blocks", t.claim_window_blocks);
    let (pool, treasury) = t.split(t.entry_price_zatoshi);
    println!(
        "split of one entry    {} to the pool, {} to the treasury",
        pool, treasury
    );
    println!();
    println!("POLICY DIGEST  {}", hex(&t.policy_digest));
    println!("TERMS DIGEST   {}", hex(&t.digest()));
    println!();
    println!("Publish both before the first deposit. A ticket references the");
    println!("terms digest, so anything changed after this is a different sale.");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values are settled elsewhere; this asserts they were transcribed,
    /// not re-decided. A digest is only worth publishing if the inputs are the
    /// ones people agreed to.
    #[test]
    fn the_published_values_are_the_recorded_ones() {
        let p = policy();
        p.validate().expect("valid");
        assert_eq!(hex(&p.collection_id), "024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e");
        assert_eq!(hex(&p.manifest_root), MANIFEST_ROOT);
        assert_eq!(p.supply, 4_444);
        // The draw recorded on 9 Sep, and the reservation it forces.
        assert_eq!(p.maximum_receipt(), 3);
        let t = terms(&p);
        t.check(&p).expect("terms agree");
        assert_eq!(
            (t.entry_price_zatoshi, t.claim_price_zatoshi, t.open_mint_price_zatoshi),
            (1_000_000, 500_000, 1_330_000),
            "§64.17, frozen"
        );
        assert_eq!(t.split(1_000_000), (900_000, 100_000), "90 to the pool, 10 to the treasury");
        assert_eq!(t.treasury, TREASURY_26460);
    }

    /// An announced close means the policy must *not* carry reveal targets;
    /// this is the assertion that would catch someone filling them in later.
    #[test]
    fn the_close_is_announced_and_the_reveal_is_derived() {
        let p = policy();
        assert_eq!(p.deposit_close_zcash_height, 0);
        assert!(p.randomness.reveal_zcash_height.is_none());
        assert!(p.randomness.reveal_drand_round.is_none());
        let rule = p.randomness.announced_close.expect("announced");
        assert_eq!(rule.reveal_offset_blocks, 100);
        assert_eq!(rule.min_notice_blocks, 1_152);
    }

    /// Both digests are deterministic, or publishing one means nothing.
    #[test]
    fn the_digests_are_stable_across_builds() {
        let a = terms(&policy());
        let b = terms(&policy());
        assert_eq!(a.digest(), b.digest());
        assert_eq!(a.policy_digest, b.policy_digest);
    }
}
