//! Grouping exits into settlements.
//!
//! A withdrawal is a request on Zyn and a transaction on some other chain, and
//! the two are not one-to-one. Treating them as one-to-one is what makes most
//! bridges expensive: NEAR's Rainbow Bridge spends an L1 transaction per
//! withdrawal, so the cost per exit is the full L1 fee regardless of size.
//!
//! The compression that makes the microchain worth running applies here too.
//! Exits to one chain in one epoch are one signing round and one transaction,
//! so the fee amortises across everyone leaving together — and a small exit
//! stops being uneconomic, which is the same argument as a small trade.
//!
//! ```text
//!   40 pending exits to Solana  ->  1 signing round  ->  1 Solana transaction
//! ```
//!
//! Only the *grouping* lives here. Observing a chain, holding its keys and
//! broadcasting to it are the operator's, and deliberately outside any VM — a
//! VM that could see Solana would not be deterministic.

use alloc::vec::Vec;
use zyn_vm::spec::AccountId;
use zyn_vm::Fixed;

use crate::vault::ChainOrigin;

/// The embedding VM's opaque deterministic asset identity.
pub type AssetId = [u8; 32];

/// One account's exit, as it will be paid out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Payout {
    pub account: AccountId,
    /// The application's own asset id. Opaque here.
    pub asset: AssetId,
    pub amount: Fixed,
    /// Epoch the exit was requested in. Carried so a settlement can be paid
    /// oldest-first.
    pub since: u64,
}

/// Every exit bound for one chain, ready to be signed as a unit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Settlement {
    pub origin: ChainOrigin,
    /// Payouts oldest first, then by account and asset.
    ///
    /// Ordered by wait rather than by address on purpose. If a settlement ever
    /// has to be truncated — a transaction size limit, a partially funded
    /// vault — the person who has waited longest is paid first, rather than
    /// whoever happens to sort low. Address order would silently make some keys
    /// permanently unlucky.
    ///
    /// Deterministic either way, which is what actually matters for signing:
    /// two nodes must agree byte-for-byte on what they are signing.
    pub payouts: Vec<Payout>,
    /// Total per asset, in asset order — what the vault must be able to cover.
    pub totals: Vec<(AssetId, Fixed)>,
}

impl Settlement {
    pub fn is_empty(&self) -> bool {
        self.payouts.is_empty()
    }
    pub fn len(&self) -> usize {
        self.payouts.len()
    }

    /// Total owed in one asset.
    pub fn total_of(&self, asset: AssetId) -> Fixed {
        self.totals
            .iter()
            .find(|(a, _)| *a == asset)
            .map(|(_, v)| *v)
            .unwrap_or(Fixed::ZERO)
    }

    /// Whether `confirmed` covers everything this settlement promises.
    ///
    /// A vault cannot pay out more than it holds, and discovering that during
    /// signing is far better than discovering it after broadcast. Pending exits
    /// are still counted in backing, so this should always hold — which is
    /// exactly why checking it is worth doing: it fails only if something else
    /// already went wrong.
    pub fn is_covered(&self, confirmed: impl Fn(AssetId) -> Fixed) -> bool {
        self.totals
            .iter()
            .all(|(asset, owed)| confirmed(*asset) >= *owed)
    }
}

/// Group exits by the chain that must pay them.
///
/// The caller supplies `(account, asset, origin, amount, since)` in whatever
/// order it holds them; the result is canonical, so two nodes building a
/// settlement from the same state produce identical bytes for the signers to
/// agree on.
pub fn group(
    exits: impl IntoIterator<Item = (AccountId, AssetId, ChainOrigin, Fixed, u64)>,
) -> Vec<Settlement> {
    let mut out: Vec<Settlement> = Vec::new();
    for (account, asset, origin, amount, since) in exits {
        if !amount.is_positive() {
            continue;
        }
        let idx = match out.iter().position(|s| s.origin == origin) {
            Some(i) => i,
            None => {
                out.push(Settlement {
                    origin,
                    payouts: Vec::new(),
                    totals: Vec::new(),
                });
                out.len() - 1
            }
        };
        out[idx].payouts.push(Payout {
            account,
            asset,
            amount,
            since,
        });
        match out[idx].totals.iter_mut().find(|(a, _)| *a == asset) {
            Some((_, t)) => *t = t.add(amount).unwrap_or(*t),
            None => out[idx].totals.push((asset, amount)),
        }
    }
    for s in out.iter_mut() {
        s.payouts.sort_by_key(|p| (p.since, p.account, p.asset));
        s.totals.sort_by_key(|(a, _)| *a);
    }
    out.sort_by_key(|s| s.origin);
    out
}

/// Exits per external transaction — the bridge's compression ratio, and the
/// reason a small exit is worth making: the L1 fee is divided by this.
pub fn exits_per_transaction(settlements: &[Settlement]) -> u64 {
    let exits: usize = settlements.iter().map(|s| s.len()).sum();
    let txs = settlements.iter().filter(|s| !s.is_empty()).count();
    if txs == 0 {
        return 0;
    }
    (exits / txs) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{ORIGIN_BITCOIN, ORIGIN_SOLANA, ORIGIN_ZCASH};
    use alloc::vec;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    fn asset(n: u32) -> AssetId {
        let mut out = [0u8; 32];
        out[28..].copy_from_slice(&n.to_be_bytes());
        out
    }

    #[test]
    fn exits_to_one_chain_become_one_settlement() {
        let mut exits = vec![];
        for n in 1..=20u8 {
            exits.push((
                acct(n),
                asset(1),
                ORIGIN_ZCASH,
                Fixed::whole(n as i64),
                n as u64,
            ));
            exits.push((
                acct(n),
                asset(5),
                ORIGIN_SOLANA,
                Fixed::whole(n as i64),
                n as u64,
            ));
        }
        let all = group(exits);
        assert_eq!(all.len(), 2, "one settlement per chain with exits waiting");
        let sol = all.iter().find(|s| s.origin == ORIGIN_SOLANA).unwrap();
        assert_eq!(sol.len(), 20, "twenty users leaving in one transaction");
        assert_eq!(sol.total_of(asset(5)), Fixed::whole(210)); // 1 + 2 + ... + 20
        assert_eq!(exits_per_transaction(&all), 20);
        assert!(sol.is_covered(|_| Fixed::whole(210)));
        assert!(
            !sol.is_covered(|_| Fixed::whole(209)),
            "an uncovered settlement passed"
        );
    }

    #[test]
    fn grouping_is_canonical_whatever_order_it_is_given() {
        let a = vec![
            (acct(3), asset(1), ORIGIN_ZCASH, Fixed::whole(1), 7),
            (acct(1), asset(5), ORIGIN_SOLANA, Fixed::whole(2), 7),
            (acct(2), asset(1), ORIGIN_ZCASH, Fixed::whole(3), 7),
        ];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(
            group(a),
            group(b),
            "the order it was collected in leaked through"
        );

        let g = group(vec![
            (acct(9), asset(1), ORIGIN_BITCOIN, Fixed::whole(1), 0),
            (acct(1), asset(1), ORIGIN_ZCASH, Fixed::whole(1), 0),
        ]);
        assert!(
            g[0].origin < g[1].origin,
            "settlements are not in chain order"
        );
    }

    /// Oldest first. If a settlement is ever truncated, the person who has
    /// waited longest is paid, not whoever sorts low.
    #[test]
    fn a_settlement_pays_the_longest_wait_first() {
        let g = group(vec![
            (acct(1), asset(1), ORIGIN_ZCASH, Fixed::whole(1), 90),
            (acct(9), asset(1), ORIGIN_ZCASH, Fixed::whole(1), 10),
            (acct(5), asset(1), ORIGIN_ZCASH, Fixed::whole(1), 50),
        ]);
        let order: Vec<u64> = g[0].payouts.iter().map(|p| p.since).collect();
        assert_eq!(order, vec![10, 50, 90], "settlement was not oldest-first");
        // The low address did not win.
        assert_eq!(g[0].payouts[0].account, acct(9));
    }

    #[test]
    fn a_chain_with_nothing_waiting_is_not_settled() {
        assert!(group(vec![]).is_empty());
        assert_eq!(exits_per_transaction(&[]), 0);
        // A zero exit is not a payout.
        assert!(group(vec![(acct(1), asset(1), ORIGIN_ZCASH, Fixed::ZERO, 0)]).is_empty());
    }
}
