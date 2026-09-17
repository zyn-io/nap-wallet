//! Turning a paid deposit into a ticket the allocator can run on.
//!
//! `cave-randomness` decides which items go to whom, and it consumes
//! [`Ticket`]s: a ticket *is* a confirmed Zcash payment, named by its exact
//! outpoint and amount. The engine was complete and had no caller, because
//! nothing built that bridge — a buyer could pay and no ticket existed, so
//! there was nothing to allocate over (§102).
//!
//! # Admission is where the rules bite
//!
//! Everything a ticket has to satisfy is checked once, here, on the way in:
//! the amount is exactly the entry price, it has enough confirmations, it is
//! not after the close, and the same outpoint is not admitted twice. A ticket
//! that passes has nothing left to argue about, which is what lets the
//! allocator be a pure function over the ledger.
//!
//! # The order is part of the result
//!
//! §64.12 orders tickets by confirmed height, then transaction index, then
//! output index, then derived ticket id — all facts about the Zcash chain, none
//! about when this process happened to see them. A ledger rebuilt from the same
//! deposits in a different order is byte-identical, which is what makes the
//! allocation replayable by a stranger.

use std::collections::BTreeSet;

use cave_randomness::{derive_ticket_id, AllocationPolicy, Hash, Ticket};

/// A confirmed Zcash payment, as the scanner saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub txid: Hash,
    pub output_index: u32,
    pub amount_zatoshi: u64,
    pub confirmed_height: u32,
    /// Position of the transaction within its block. Part of the ordering, so
    /// two deposits in one block still have a defined sequence.
    pub tx_index: u32,
    /// The Zyn account that will receive whatever this ticket is allocated.
    pub recipient: Hash,
    /// The drand round observed when this ticket was committed publicly.
    pub issued_at_drand_round: u64,
}

/// Why a deposit is not a ticket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotATicket {
    /// Not the entry price. The engine requires exactness, so a near miss is
    /// refused here where it can still be refunded by hand rather than at
    /// allocation time where it cannot.
    WrongAmount { paid: u64, expected: u64 },
    /// Too few confirmations: it can still be reorged away.
    Unconfirmed { have: u32, need: u32 },
    /// After the close. The sale ended; this is a payment, not an entry.
    AfterClose { height: u32, close: u32 },
    /// This outpoint is already a ticket.
    AlreadyAdmitted,
    /// The recipient is the zero account.
    NoRecipient,
}

/// The tickets of one sale, in the order the allocator will read them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    tickets: Vec<Ticket>,
    seen: BTreeSet<(Hash, u32)>,
}

impl Ledger {
    pub fn new() -> Ledger {
        Ledger::default()
    }

    pub fn len(&self) -> usize {
        self.tickets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tickets.is_empty()
    }

    /// The tickets, ordered as §64.12 requires.
    pub fn tickets(&self) -> &[Ticket] {
        &self.tickets
    }

    /// Admit a deposit, or say why it is not a ticket.
    ///
    /// `close` is the deposit-close height — from the policy when it committed
    /// one, or from a resolved announcement when it did not. Passing it in
    /// rather than reading the policy is deliberate: under an announced close
    /// the policy does not know it, and a function that quietly admitted
    /// everything when the close was unknown would be the worst of both.
    pub fn admit(
        &mut self,
        policy: &AllocationPolicy,
        close: u32,
        min_confirmations: u32,
        tip: u32,
        deposit: &Deposit,
    ) -> Result<Ticket, NotATicket> {
        if deposit.recipient == [0u8; 32] {
            return Err(NotATicket::NoRecipient);
        }
        if self.seen.contains(&(deposit.txid, deposit.output_index)) {
            return Err(NotATicket::AlreadyAdmitted);
        }
        if deposit.amount_zatoshi != policy.entry_price_zatoshi {
            return Err(NotATicket::WrongAmount {
                paid: deposit.amount_zatoshi,
                expected: policy.entry_price_zatoshi,
            });
        }
        let depth = tip.saturating_sub(deposit.confirmed_height).saturating_add(1);
        if depth < min_confirmations {
            return Err(NotATicket::Unconfirmed {
                have: depth,
                need: min_confirmations,
            });
        }
        if deposit.confirmed_height > close {
            return Err(NotATicket::AfterClose {
                height: deposit.confirmed_height,
                close,
            });
        }

        let mut ticket = Ticket {
            ticket_id: [0u8; 32],
            deposit_txid: deposit.txid,
            deposit_output_index: deposit.output_index,
            deposit_amount_zatoshi: deposit.amount_zatoshi,
            recipient: deposit.recipient,
            confirmed_height: deposit.confirmed_height,
            tx_index: deposit.tx_index,
            issued_at_drand_round: deposit.issued_at_drand_round,
            // A weighted quantity resolves at its own future round; the
            // identity is decided by the collection-wide reveal. Both are
            // filled by whoever gathers the evidence, not here.
            quantity_drand_round: None,
            identity_drand_round: None,
            requested_items: None,
        };
        // The id covers every field above, so a ticket edited after admission
        // stops being the ticket that was admitted.
        ticket.ticket_id = derive_ticket_id(
            policy.digest().map_err(|_| NotATicket::NoRecipient)?,
            &ticket,
        );

        self.seen.insert((deposit.txid, deposit.output_index));
        self.tickets.push(ticket.clone());
        self.sort();
        Ok(ticket)
    }

    /// §64.12's order: facts about Zcash, never about this process.
    fn sort(&mut self) {
        self.tickets.sort_by(|a, b| {
            (a.confirmed_height, a.tx_index, a.deposit_output_index, a.ticket_id).cmp(&(
                b.confirmed_height,
                b.tx_index,
                b.deposit_output_index,
                b.ticket_id,
            ))
        });
    }

    /// How many items are held against unresolved tickets (§64.7): a weighted
    /// draw reserves its largest outcome until it lands.
    pub fn reserved(&self, policy: &AllocationPolicy) -> u64 {
        self.tickets.len() as u64 * policy.maximum_receipt() as u64
    }

    /// Whether admitting one more would reserve past the supply. Checked
    /// *before* taking the money, because a ticket that cannot be honoured is
    /// a refund and an apology.
    pub fn would_exceed_supply(&self, policy: &AllocationPolicy) -> bool {
        self.reserved(policy) + policy.maximum_receipt() as u64 > policy.supply as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cave_randomness::{
        AnnouncedClose, IdentityPolicy, QuantityPolicy, RandomnessPlan, WeightedOutcome,
        QUICKNET_CHAIN_HASH,
    };

    fn policy() -> AllocationPolicy {
        AllocationPolicy {
            collection_id: [2; 32],
            supply: 4_444,
            entry_price_zatoshi: 1_000_000,
            deposit_close_zcash_height: 0,
            quantity: QuantityPolicy::Weighted {
                outcomes: vec![
                    WeightedOutcome { items: 1, weight: 80 },
                    WeightedOutcome { items: 2, weight: 19 },
                    WeightedOutcome { items: 3, weight: 1 },
                ],
            },
            identity: IdentityPolicy::ConcealedShuffle,
            manifest_root: [3; 32],
            randomness: RandomnessPlan {
                drand_chain_hash: QUICKNET_CHAIN_HASH,
                ticket_round_delay: 10,
                reveal_drand_round: None,
                reveal_zcash_height: None,
                announced_close: Some(AnnouncedClose {
                    reveal_offset_blocks: 100,
                    reveal_offset_rounds: 2_400,
                    min_notice_blocks: 1_152,
                }),
            },
        }
    }

    fn deposit(txid: u8, height: u32, tx_index: u32) -> Deposit {
        Deposit {
            txid: [txid; 32],
            output_index: 0,
            amount_zatoshi: 1_000_000,
            confirmed_height: height,
            tx_index,
            recipient: [9; 32],
            issued_at_drand_round: 5_000_000,
        }
    }

    const CLOSE: u32 = 3_500_000;
    const TIP: u32 = 3_500_010;

    #[test]
    fn a_correct_deposit_becomes_a_ticket_with_a_bound_id() {
        let p = policy();
        let mut l = Ledger::new();
        let t = l.admit(&p, CLOSE, 6, TIP, &deposit(1, 3_499_000, 0)).unwrap();
        assert_ne!(t.ticket_id, [0u8; 32]);
        assert_eq!(l.len(), 1);
        // The id covers the deposit, so the same payment under another policy
        // is a different ticket.
        let mut other = p.clone();
        other.supply = 4_443;
        let mut l2 = Ledger::new();
        let t2 = l2.admit(&other, CLOSE, 6, TIP, &deposit(1, 3_499_000, 0)).unwrap();
        assert_ne!(t.ticket_id, t2.ticket_id);
    }

    #[test]
    fn the_same_outpoint_is_admitted_once() {
        let p = policy();
        let mut l = Ledger::new();
        l.admit(&p, CLOSE, 6, TIP, &deposit(1, 3_499_000, 0)).unwrap();
        assert_eq!(
            l.admit(&p, CLOSE, 6, TIP, &deposit(1, 3_499_000, 0)),
            Err(NotATicket::AlreadyAdmitted)
        );
        assert_eq!(l.len(), 1);
        // A second output of the same transaction is a different ticket, which
        // is how several entries ride in one payment.
        let mut second = deposit(1, 3_499_000, 0);
        second.output_index = 1;
        assert!(l.admit(&p, CLOSE, 6, TIP, &second).is_ok());
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn a_near_miss_on_the_price_is_refused_where_it_can_still_be_refunded() {
        let p = policy();
        let mut l = Ledger::new();
        let mut short = deposit(1, 3_499_000, 0);
        short.amount_zatoshi -= 1;
        assert_eq!(
            l.admit(&p, CLOSE, 6, TIP, &short),
            Err(NotATicket::WrongAmount { paid: 999_999, expected: 1_000_000 })
        );
        // Overpaying is refused too: the engine requires exactness, and
        // silently keeping the difference is not a rounding decision.
        let mut over = deposit(2, 3_499_000, 0);
        over.amount_zatoshi += 1;
        assert!(matches!(l.admit(&p, CLOSE, 6, TIP, &over), Err(NotATicket::WrongAmount { .. })));
    }

    #[test]
    fn too_few_confirmations_and_past_the_close_are_different_refusals() {
        let p = policy();
        let mut l = Ledger::new();
        // Two blocks deep where six are needed.
        assert_eq!(
            l.admit(&p, CLOSE, 6, 3_499_001, &deposit(1, 3_499_000, 0)),
            Err(NotATicket::Unconfirmed { have: 2, need: 6 })
        );
        assert_eq!(
            l.admit(&p, CLOSE, 6, TIP, &deposit(2, CLOSE + 1, 0)),
            Err(NotATicket::AfterClose { height: CLOSE + 1, close: CLOSE })
        );
        // The block of the close itself is still inside it.
        assert!(l.admit(&p, CLOSE, 6, TIP, &deposit(3, CLOSE, 0)).is_ok());
    }

    /// The ordering is the part a stranger replays, so it must depend only on
    /// Zcash and not on the order deposits happened to arrive here.
    #[test]
    fn the_ledger_is_the_same_whatever_order_deposits_arrive_in() {
        let p = policy();
        let ds = [
            deposit(3, 3_499_002, 0),
            deposit(1, 3_499_000, 1),
            deposit(2, 3_499_000, 0),
        ];
        let mut forward = Ledger::new();
        for d in &ds {
            forward.admit(&p, CLOSE, 6, TIP, d).unwrap();
        }
        let mut backward = Ledger::new();
        for d in ds.iter().rev() {
            backward.admit(&p, CLOSE, 6, TIP, d).unwrap();
        }
        assert_eq!(forward.tickets(), backward.tickets());
        // And it really is height, then transaction index.
        let order: Vec<_> = forward
            .tickets()
            .iter()
            .map(|t| (t.confirmed_height, t.tx_index))
            .collect();
        assert_eq!(order, vec![(3_499_000, 0), (3_499_000, 1), (3_499_002, 0)]);
    }

    /// A weighted draw reserves its largest outcome until it lands, so the
    /// sale must stop admitting well before the supply is reached (§64.7).
    #[test]
    fn reservations_use_the_largest_outcome_not_the_likeliest() {
        let p = policy();
        let mut l = Ledger::new();
        l.admit(&p, CLOSE, 6, TIP, &deposit(1, 3_499_000, 0)).unwrap();
        assert_eq!(l.reserved(&p), 3, "one ticket holds three items, not one");
        assert!(!l.would_exceed_supply(&p));
    }

    #[test]
    fn a_deposit_to_nobody_is_not_a_ticket() {
        let p = policy();
        let mut l = Ledger::new();
        let mut orphan = deposit(1, 3_499_000, 0);
        orphan.recipient = [0u8; 32];
        assert_eq!(l.admit(&p, CLOSE, 6, TIP, &orphan), Err(NotATicket::NoRecipient));
    }
}
