//! ZynZap's exits, grouped for settlement.
//!
//! Almost nothing: the grouping rules are `zyn_bridge::settle`, shared by every
//! VM that holds bridged value. What is ZynZap's is only knowing where its own
//! pending exits live.

use alloc::vec::Vec;

use crate::state::SwapState;
use crate::types::ChainOrigin;
use zyn_bridge::settle;

pub use zyn_bridge::settle::{exits_per_transaction, Payout, Settlement};

/// Group every pending exit by the chain that must pay it.
pub fn settlements(state: &SwapState) -> Vec<Settlement> {
    settle::group(state.accounts.iter().flat_map(|(account, acct)| {
        acct.pending.iter().filter_map(move |(&asset, exit)| {
            let origin = state.token(asset).and_then(|t| t.vault).map(|v| v.origin)?;
            Some((*account, asset, origin, exit.amount, exit.since))
        })
    }))
}

/// The settlement bound for one chain, if it has any exits waiting.
pub fn settlement_for(state: &SwapState, origin: ChainOrigin) -> Option<Settlement> {
    settlements(state).into_iter().find(|s| s.origin == origin)
}

/// Whether the vaults can cover everything a settlement promises.
pub fn is_covered(state: &SwapState, s: &Settlement) -> bool {
    s.is_covered(|asset| state.backing_of(asset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::state::{symbol, TokenInfo};
    use crate::tx::{Intent, SequencedIntent};
    use crate::types::{AccountId, AssetId, Params, ORIGIN_BITCOIN, ORIGIN_SOLANA, XZEC};
    use crate::vm;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    fn chain() -> (SwapState, AssetId, AssetId) {
        let mut s = SwapState::new(1, Params::v1());
        let xsol = s.next_asset_id;
        s.next_asset_id += 1;
        s.tokens.insert(xsol, TokenInfo::bridged(symbol(b"xSOL"), ORIGIN_SOLANA));
        let xbtc = s.next_asset_id;
        s.next_asset_id += 1;
        s.tokens.insert(xbtc, TokenInfo::bridged(symbol(b"xBTC"), ORIGIN_BITCOIN));

        let go = |s: &mut SwapState, i: Intent| {
            let at = s.seq;
            let r = vm::apply(s, &SequencedIntent { seq: at + 1, intent: i });
            assert!(!r.iter().any(|x| x.is_rejection()), "rejected: {:?}", r);
        };
        for n in 1..=20u8 {
            for asset in [XZEC, xsol] {
                let observed = s.backing_of(asset).add(Fixed::whole(100)).unwrap();
                go(&mut s, Intent::AttestVaultBalance { asset, observed });
                let credit =
                    Intent::next_deposit(&s, acct(n), asset, Fixed::whole(100), [n; 32]);
                go(&mut s, credit);
            }
        }
        // Anchor the epoch so the deposits become spendable.
        let at = s.epoch;
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch: at });
        for n in 1..=20u8 {
            for asset in [XZEC, xsol] {
                go(&mut s, Intent::RequestWithdrawal {
                    account: acct(n),
                    asset,
                    amount: Fixed::whole(n as i64),
                    destination: [0u8; 32],
                });
            }
        }
        s.check_invariants().unwrap();
        (s, xsol, xbtc)
    }

    /// Many exits, one transaction per chain — and the vaults cover them.
    #[test]
    fn exits_to_one_chain_become_one_settlement() {
        let (s, xsol, _) = chain();
        let all = settlements(&s);
        assert_eq!(all.len(), 2, "one settlement per chain with exits waiting");

        let sol = settlement_for(&s, ORIGIN_SOLANA).expect("Solana exits");
        assert_eq!(sol.len(), 20, "twenty users leaving in one transaction");
        assert_eq!(sol.total_of(xsol), Fixed::whole(210)); // 1 + 2 + ... + 20
        assert!(is_covered(&s, &sol), "the vault cannot cover what it promised");
        assert_eq!(exits_per_transaction(&all), 20);
    }

    #[test]
    fn a_chain_with_no_exits_is_not_settled() {
        let (s, _, xbtc) = chain();
        assert!(settlement_for(&s, ORIGIN_BITCOIN).is_none());
        assert_eq!(s.backing_of(xbtc), Fixed::ZERO);
    }

    /// Two nodes must produce identical bytes, or the signers cannot agree on
    /// what they are signing.
    #[test]
    fn grouping_is_deterministic() {
        let (s, _, _) = chain();
        assert_eq!(settlements(&s), settlements(&s));
        let carried = SwapState::decode_state(&s.encode_state()).unwrap();
        assert_eq!(settlements(&carried), settlements(&s));
    }

    /// Confirming an exit removes it from the next settlement, so a payout is
    /// never signed twice.
    #[test]
    fn a_confirmed_exit_leaves_the_queue() {
        let (mut s, xsol, _) = chain();
        let before = settlement_for(&s, ORIGIN_SOLANA).unwrap().len();
        let at = s.seq;
        vm::apply(
            &mut s,
            &SequencedIntent {
                seq: at + 1,
                intent: Intent::ConfirmWithdrawal {
                    account: acct(3),
                    asset: xsol,
                    amount: Fixed::whole(3),
                },
            },
        );
        let after = settlement_for(&s, ORIGIN_SOLANA).unwrap();
        assert_eq!(after.len(), before - 1);
        assert!(after.payouts.iter().all(|p| p.account != acct(3)));
        s.check_invariants().unwrap();
    }
}
