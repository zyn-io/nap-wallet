//! What ZynZap's flow earns.
//!
//! Deliberately here and not in the microchain layer. A fee is an application
//! concept: an auction VM has a clearing spread, a game has none at all, and a
//! sequencer that understood "fee" would be a sequencer with an opinion about
//! what it is sequencing. The microchain measures compression and settlement
//! cost, which are true of every VM; this measures the half that is ZynZap's.
//!
//! Read off receipts rather than modelled, so the figure an operator reports is
//! the figure traders actually paid. Diffing treasury balances would work too,
//! but only in aggregate — this attributes revenue to the swaps that produced
//! it, which is what makes it a per-period number rather than a running total.

use crate::fixed::Fixed;
use crate::tx::Receipt;

/// Fees charged and the protocol's share of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Revenue {
    /// Fees charged to traders across every hop, in the input asset of each.
    ///
    /// Mixed units, so it is a flow indicator rather than an accounting figure —
    /// the authoritative per-asset totals are treasury balances, which this is
    /// checked against in the tests.
    pub fees_charged: Fixed,
    /// The protocol's slice of those fees.
    pub protocol_share: Fixed,
    /// Swaps that executed. Submitted-and-rejected swaps are not counted:
    /// they earned nothing.
    pub swaps: u64,
}

impl Revenue {
    /// Fold in whatever one intent produced.
    ///
    /// Saturating on overflow rather than failing: losing a statistic is not a
    /// reason to stop a chain that priced the trade correctly, and a counter
    /// that can halt execution is a counter that has more authority than it
    /// should.
    pub fn absorb(&mut self, receipts: &[Receipt]) {
        for r in receipts {
            if let Receipt::Swapped { hops, .. } = r {
                self.swaps = self.swaps.saturating_add(1);
                for h in hops {
                    self.fees_charged =
                        self.fees_charged.add(h.fee).unwrap_or(Fixed::raw(i128::MAX));
                    self.protocol_share = self
                        .protocol_share
                        .add(h.protocol_fee)
                        .unwrap_or(Fixed::raw(i128::MAX));
                }
            }
        }
    }

    /// What LPs kept: everything charged that the protocol did not take.
    pub fn lp_share(&self) -> Option<Fixed> {
        self.fees_charged.sub(self.protocol_share)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::Hop;
    use alloc::vec;

    fn swap(fee: i64, protocol: i64) -> Receipt {
        Receipt::Swapped {
            account: [1u8; 32],
            asset_in: 1,
            asset_out: 2,
            amount_in: Fixed::whole(10),
            amount_out: Fixed::whole(9),
            hops: vec![Hop {
                pool: 1,
                asset_in: 1,
                asset_out: 2,
                amount_in: Fixed::whole(10),
                amount_out: Fixed::whole(9),
                fee: Fixed::whole(fee),
                protocol_fee: Fixed::whole(protocol),
            }],
        }
    }

    #[test]
    fn revenue_accumulates_across_swaps() {
        let mut r = Revenue::default();
        r.absorb(&[swap(3, 1)]);
        r.absorb(&[swap(6, 2)]);
        assert_eq!(r.fees_charged, Fixed::whole(9));
        assert_eq!(r.protocol_share, Fixed::whole(3));
        assert_eq!(r.lp_share().unwrap(), Fixed::whole(6));
        assert_eq!(r.swaps, 2);
    }

    #[test]
    fn a_routed_swap_earns_on_every_hop() {
        let mut r = Revenue::default();
        r.absorb(&[Receipt::Swapped {
            account: [1u8; 32],
            asset_in: 2,
            asset_out: 3,
            amount_in: Fixed::whole(10),
            amount_out: Fixed::whole(5),
            hops: vec![
                Hop {
                    pool: 1,
                    asset_in: 2,
                    asset_out: 1,
                    amount_in: Fixed::whole(10),
                    amount_out: Fixed::whole(7),
                    fee: Fixed::whole(1),
                    protocol_fee: Fixed::ZERO,
                },
                Hop {
                    pool: 2,
                    asset_in: 1,
                    asset_out: 3,
                    amount_in: Fixed::whole(7),
                    amount_out: Fixed::whole(5),
                    fee: Fixed::whole(2),
                    protocol_fee: Fixed::whole(1),
                },
            ],
        }]);
        assert_eq!(r.fees_charged, Fixed::whole(3), "only one hop was counted");
        assert_eq!(r.protocol_share, Fixed::whole(1));
        assert_eq!(r.swaps, 1, "a routed swap is one swap, not one per hop");
    }

    #[test]
    fn nothing_but_a_swap_earns() {
        let mut r = Revenue::default();
        r.absorb(&[
            Receipt::ParamsUpdated,
            Receipt::Rejected { reason: crate::tx::Reject::InsufficientBalance },
            Receipt::DepositCredited {
                account: [1u8; 32],
                asset: 1,
                index: 1,
                external_ref: [0u8; 32],
                amount: Fixed::whole(5),
                backing: Fixed::whole(5),
            },
        ]);
        assert_eq!(r, Revenue::default());
    }
}
