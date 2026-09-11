//! A vault: units issued here against value custodied elsewhere.

use zyn_vm::Fixed;

/// Which external chain custodies the value behind a bridged asset.
///
/// A `u16` with constants rather than an enum, deliberately. Adding a chain
/// should be a new constant and a new vault, not a change to the state model —
/// and a state-model change is the one thing that is expensive once a chain is
/// live and holding other people's money.
pub type ChainOrigin = u16;

pub const ORIGIN_ZCASH: ChainOrigin = 1;
pub const ORIGIN_BITCOIN: ChainOrigin = 2;
pub const ORIGIN_ETHEREUM: ChainOrigin = 3;
pub const ORIGIN_SOLANA: ChainOrigin = 4;

/// Why a custody operation was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BridgeError {
    NonPositive,
    /// The deposit index was not the next one — a replay, or a gap that would
    /// let one be inserted later.
    DepositOutOfOrder,
    /// Below what the custodying chain can actually pay out.
    BelowExitMinimum,
    /// Would take total backing past the vault's ceiling.
    AboveCap,
    /// Would issue more units than the vault was last observed to hold.
    AboveObserved,
    /// The reported balance is below what has already been issued against it.
    /// The vault is short: not a condition to record quietly and carry on.
    AttestedShortfall,
    /// An observation that does not move the record forward.
    StaleObservation,
    /// An exit to somewhere other than where the account is bound.
    WrongDestination,
    /// A redirect that has not waited out its delay.
    RedirectTooSoon,
    /// Would take this epoch's minting past its ceiling.
    AboveEpochCap,
    /// Nothing outstanding, or less than was asked for.
    NothingPending,
    /// The epoch containing this credit has not been anchored yet.
    NotFinalized,
    /// The exit has not been outstanding long enough to be taken back.
    NotTimedOut,
    /// Cancellation is switched off for this chain.
    NoTimeout,
    Overflow,
}

/// What custodies an asset's value, and what it has issued against it.
///
/// The identity every bridge rests on, and the reason the fields sit together:
///
/// ```text
/// units issued == confirmed
/// ```
///
/// Only [`Vault::credit`] raises `confirmed` and only [`Vault::release`] lowers
/// it, and an application must move its own supply in the same step. Keeping
/// the two operations here, rather than open-coded per VM, is what makes that
/// pairing hard to get wrong.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vault {
    pub origin: ChainOrigin,
    /// Units confirmed in the custodying chain's vault.
    pub confirmed: Fixed,
    /// Deposits credited so far.
    ///
    /// A monotonic counter, and the cheapest thing that makes crediting the
    /// same external deposit twice impossible. O(1) — a counter, not a set of
    /// every transaction id ever seen. The id itself belongs in the intent,
    /// where the epoch's commitment already keeps it.
    pub deposits: u64,
    /// Smallest exit this chain can actually pay out.
    ///
    /// Not anti-spam — correctness. Bitcoin will not relay an output below its
    /// dust limit, so an exit under it is a payout that cannot be broadcast:
    /// units burned here and nothing delivered there.
    pub min_exit: Fixed,
    /// Ceiling on total backing. Zero means no ceiling.
    ///
    /// The plan's staged mainnet posture: open with a limited deposit cap and
    /// raise it only after sustained operation. A ceiling costs nothing while
    /// the vault is small and is the difference between a bad day and a total
    /// loss once it is not.
    pub cap: Fixed,
    /// Ceiling on what may be credited within a single epoch. Zero means none.
    ///
    /// This is the one that bounds a *compromise*. The VM cannot verify that a
    /// deposit happened — it cannot see the other chain — so a sequencer able
    /// to fabricate credits could otherwise mint without limit between one
    /// anchor and the next. A per-epoch ceiling turns that from unbounded into
    /// one epoch's worth, which is a quantity signers can be asked to check
    /// before they sign the anchor that settles it.
    ///
    /// It does not make fabrication impossible. It makes it bounded, visible,
    /// and survivable — which is what is available without putting signature
    /// verification inside a deterministic VM.
    pub epoch_cap: Fixed,
    /// What the vault on the custodying chain was last **observed** to hold.
    ///
    /// The point of a shielded vault as a mint signal. A Zcash vault cannot
    /// emit anything — there are no contracts — and its balance is not public,
    /// so someone with the viewing key has to look. What this field does is
    /// make that looking into a *recorded number* the chain enforces against,
    /// instead of an assumption behind an operator's word.
    ///
    /// The rule it buys: **units issued can never exceed units last observed.**
    /// A fabricated credit is then not merely unattested — it requires a
    /// separate, explicit, dated lie about a balance that every viewing-key
    /// holder can check independently.
    pub observed: Fixed,
    /// Epoch the observation was reported in.
    pub observed_epoch: u64,
    /// Credited so far within `epoch`.
    pub epoch_credited: Fixed,
    /// The epoch `epoch_credited` counts. Rolled forward lazily on the first
    /// credit of a new one, so nothing has to remember to reset it.
    pub epoch: u64,
}

impl Vault {
    pub fn new(origin: ChainOrigin) -> Vault {
        Vault {
            origin,
            confirmed: Fixed::ZERO,
            deposits: 0,
            min_exit: Fixed::raw(1),
            observed: Fixed::ZERO,
            observed_epoch: 0,
            cap: Fixed::ZERO,
            epoch_cap: Fixed::ZERO,
            epoch_credited: Fixed::ZERO,
            epoch: 0,
        }
    }

    /// The index the next deposit must carry.
    ///
    /// Public because an operator needs it to build a credit at all: the
    /// sequence is the chain's, not theirs, which is what stops two operators —
    /// or one operator twice — crediting the same external deposit.
    pub fn next_index(&self) -> u64 {
        self.deposits.saturating_add(1)
    }

    /// Record a confirmed deposit. The caller must mint the same amount.
    ///
    /// `epoch` is the chain's current epoch, used to roll the per-epoch
    /// allowance. Nothing else has to reset it, which is deliberate: a counter
    /// someone must remember to clear is a counter that will eventually not be.
    pub fn credit(&mut self, amount: Fixed, index: u64, epoch: u64) -> Result<(), BridgeError> {
        if !amount.is_positive() {
            return Err(BridgeError::NonPositive);
        }
        // Strictly the next index. A repeat replays a deposit already credited;
        // a gap would leave room to insert one afterwards and have it accepted
        // out of order.
        if index != self.next_index() {
            return Err(BridgeError::DepositOutOfOrder);
        }
        let confirmed = self.confirmed.add(amount).ok_or(BridgeError::Overflow)?;
        if self.cap.is_positive() && confirmed > self.cap {
            return Err(BridgeError::AboveCap);
        }
        // Cannot issue more than the vault was last seen holding. This is the
        // check that ties minting to something outside the sequencer's control:
        // to mint beyond it, the balance itself has to be misreported first.
        if confirmed > self.observed {
            return Err(BridgeError::AboveObserved);
        }
        // A new epoch restores the allowance. Checked against the *incoming*
        // epoch rather than a stored flag, so a vault that sat idle for a
        // hundred epochs is not owed a hundred allowances.
        let used = if epoch == self.epoch { self.epoch_credited } else { Fixed::ZERO };
        let used = used.add(amount).ok_or(BridgeError::Overflow)?;
        if self.epoch_cap.is_positive() && used > self.epoch_cap {
            return Err(BridgeError::AboveEpochCap);
        }

        self.confirmed = confirmed;
        self.deposits = index;
        self.epoch = epoch;
        self.epoch_credited = used;
        Ok(())
    }

    /// Record what the vault on the custodying chain holds.
    ///
    /// Must be reported *before* the deposits it covers are credited, which is
    /// also the operational order: see the balance rise, report it, then credit
    /// against it.
    ///
    /// A report below what has already been issued is refused rather than
    /// recorded. The vault being short is real information and must not be
    /// absorbed quietly — but nor should the chain silently freeze on it by
    /// failing an invariant. Naming the condition and refusing it leaves the
    /// decision where it belongs, with whoever can do something about it.
    pub fn attest(&mut self, observed: Fixed, epoch: u64) -> Result<(), BridgeError> {
        if observed.is_negative() {
            return Err(BridgeError::NonPositive);
        }
        if observed < self.confirmed {
            return Err(BridgeError::AttestedShortfall);
        }
        // An observation from an epoch already covered says nothing new, and
        // accepting it would let a stale figure overwrite a fresher one.
        if self.observed_epoch > 0 && epoch < self.observed_epoch {
            return Err(BridgeError::StaleObservation);
        }
        self.observed = observed;
        self.observed_epoch = epoch;
        Ok(())
    }

    /// Units that may still be issued against the last observation.
    pub fn observed_headroom(&self) -> Fixed {
        self.observed.sub(self.confirmed).unwrap_or(Fixed::ZERO)
    }

    /// Units that may still be credited in `epoch` before the allowance runs
    /// out. `None` when there is no per-epoch ceiling.
    pub fn epoch_headroom(&self, epoch: u64) -> Option<Fixed> {
        if !self.epoch_cap.is_positive() {
            return None;
        }
        if epoch != self.epoch {
            return Some(self.epoch_cap);
        }
        Some(self.epoch_cap.sub(self.epoch_credited).unwrap_or(Fixed::ZERO))
    }

    /// Whether an exit of `amount` is one this chain could broadcast.
    pub fn admits_exit(&self, amount: Fixed) -> Result<(), BridgeError> {
        if !amount.is_positive() {
            return Err(BridgeError::NonPositive);
        }
        if amount < self.min_exit {
            return Err(BridgeError::BelowExitMinimum);
        }
        Ok(())
    }

    /// Release backing for a settled exit. The caller must burn the same amount.
    pub fn release(&mut self, amount: Fixed) -> Result<(), BridgeError> {
        if !amount.is_positive() {
            return Err(BridgeError::NonPositive);
        }
        let next = self.confirmed.sub(amount).ok_or(BridgeError::Overflow)?;
        if next.is_negative() {
            return Err(BridgeError::Overflow);
        }
        self.confirmed = next;
        Ok(())
    }

    /// Whether this vault's books are internally coherent.
    pub fn check(&self, issued: Fixed) -> Result<(), &'static str> {
        if self.confirmed.is_negative() {
            return Err("negative backing");
        }
        if !self.min_exit.is_positive() {
            return Err("a vault's minimum exit must be positive");
        }
        if self.confirmed.is_positive() && self.deposits == 0 {
            return Err("a vault holds units no deposit accounts for");
        }
        if issued != self.confirmed {
            return Err("issued units do not equal confirmed backing");
        }
        if self.cap.is_negative() || self.epoch_cap.is_negative() {
            return Err("a vault ceiling must not be negative");
        }
        if self.epoch_credited.is_negative() {
            return Err("negative epoch minting");
        }
        if self.cap.is_positive() && self.confirmed > self.cap {
            return Err("a vault holds more than its ceiling");
        }
        if self.confirmed > self.observed {
            return Err("more units issued than the vault was observed to hold");
        }
        Ok(())
    }
}

/// Units minted against a deposit that is not yet spendable.
///
/// The symmetric half of [`PendingExit`], and the thing that makes a deposit
/// require the same quorum a withdrawal does.
///
/// A VM cannot see the chain a deposit arrived on, so nothing in it can verify
/// that one happened — the credit is an operator's word. Crediting straight to
/// a balance makes that word immediately spendable: a fabricated deposit could
/// be swapped, and the proceeds taken, before anyone with a node had reason to
/// look. Holding it here until the epoch containing it has been **anchored**
/// means a fabricated credit sits in plain view, inside the intent set a
/// threshold of signers must endorse, before it can move.
///
/// It is still the signers' word in the end — that is the custody model the
/// plan states. What changes is that it is *their* word rather than one
/// operator's, and that it is checkable before the money moves rather than
/// after.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PendingCredit {
    pub amount: Fixed,
    /// Epoch the deposit was credited in.
    pub epoch: u64,
}

impl PendingCredit {
    pub fn new(amount: Fixed, epoch: u64) -> PendingCredit {
        PendingCredit { amount, epoch }
    }

    /// Add to a credit still waiting. Takes the **later** epoch, so a fresh
    /// deposit cannot ride out on an older one's finality.
    pub fn extend(&self, amount: Fixed, epoch: u64) -> Result<PendingCredit, BridgeError> {
        Ok(PendingCredit {
            amount: self.amount.add(amount).ok_or(BridgeError::Overflow)?,
            epoch: self.epoch.max(epoch),
        })
    }

    /// Whether the epoch that contains this credit has been anchored.
    pub fn is_final(&self, finalized_epoch: u64) -> bool {
        self.epoch <= finalized_epoch
    }
}

/// Where an account's exits are allowed to go.
///
/// The withdrawal destination is the one thing a compromised key most wants to
/// change, and until now nothing recorded it at all: the intent said how much
/// to pay and not to whom, so the destination lived entirely in whatever the
/// operator was told out of band.
///
/// Held as a **commitment**, never an address. The plan lists the withdrawal
/// destination among the things that should be private (§12), and a Zcash
/// address written into Zyn's state would be readable by everyone who can read
/// the state — which is everyone. The operator learns the address itself
/// out of band and can be checked against this afterwards by anyone the user
/// shows the preimage to.
///
/// Changing it is deliberately slow. That delay is the entire protection: a key
/// that has been stolen can request a redirect, and the owner has a window to
/// notice and empty the account before it takes effect.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Binding {
    /// `H(address, salt)` — what payouts must be checked against.
    pub destination: [u8; 32],
    /// A redirect requested but not yet in force.
    pub pending: Option<([u8; 32], u64)>,
}

impl Binding {
    pub fn new(destination: [u8; 32]) -> Binding {
        Binding { destination, pending: None }
    }

    /// Ask to redirect. Re-asking with a different address restarts the clock,
    /// so an attacker cannot queue a redirect and let it mature quietly while
    /// the owner watches a different one. Re-asking with the **same** address
    /// keeps the clock: the owner checking on a redirect must not be the thing
    /// that postpones it.
    pub fn request(&self, destination: [u8; 32], now: u64) -> Binding {
        let since = match self.pending {
            Some((d, since)) if d == destination => since,
            _ => now,
        };
        Binding { destination: self.destination, pending: Some((destination, since)) }
    }

    /// Whether a pending redirect to `destination` may now take effect.
    pub fn may_apply(&self, destination: [u8; 32], now: u64, delay: u64) -> bool {
        match self.pending {
            Some((d, since)) => d == destination && now.saturating_sub(since) >= delay,
            None => false,
        }
    }

    /// Apply it.
    pub fn apply(&self, destination: [u8; 32]) -> Binding {
        Binding { destination, pending: None }
    }

    /// Whether a payout to `destination` is allowed.
    pub fn admits(&self, destination: [u8; 32]) -> bool {
        self.destination == destination
    }
}

/// Units committed to an exit, and when.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PendingExit {
    pub amount: Fixed,
    /// Epoch in which this exit was last increased.
    ///
    /// The clock a timeout runs against. Adding to an exit restarts it, so a
    /// claim cannot be accumulated over many small requests and then cancelled
    /// whole the moment the oldest one ages out.
    pub since: u64,
}

impl PendingExit {
    pub fn new(amount: Fixed, since: u64) -> PendingExit {
        PendingExit { amount, since }
    }

    /// Add to an outstanding exit, restarting its clock.
    pub fn extend(&self, amount: Fixed, now: u64) -> Result<PendingExit, BridgeError> {
        Ok(PendingExit {
            amount: self.amount.add(amount).ok_or(BridgeError::Overflow)?,
            since: now,
        })
    }

    /// Take `amount` off an outstanding exit, keeping its clock.
    pub fn settle(&self, amount: Fixed) -> Result<PendingExit, BridgeError> {
        if self.amount < amount {
            return Err(BridgeError::NothingPending);
        }
        Ok(PendingExit {
            amount: self.amount.sub(amount).ok_or(BridgeError::Overflow)?,
            since: self.since,
        })
    }

    /// Whether this exit may be taken back.
    ///
    /// The answer to the plan's ninth invariant — a failed sequencer must not
    /// make reserves permanently inaccessible. Not cancellable on demand: an
    /// exit that could be withdrawn at will could race a payout already in
    /// flight and be paid on both sides.
    ///
    /// A `timeout` of zero switches cancellation off entirely.
    pub fn may_cancel(&self, now: u64, timeout: u64) -> Result<u64, BridgeError> {
        if timeout == 0 {
            return Err(BridgeError::NoTimeout);
        }
        if !self.amount.is_positive() {
            return Err(BridgeError::NothingPending);
        }
        let waited = now.saturating_sub(self.since);
        if waited < timeout {
            return Err(BridgeError::NotTimedOut);
        }
        Ok(waited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deposit_is_credited_once_and_only_once() {
        let mut v = Vault::new(ORIGIN_BITCOIN);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        assert_eq!(v.next_index(), 1);
        v.credit(Fixed::whole(5), 1, 0).unwrap();
        assert_eq!(v.confirmed, Fixed::whole(5));

        // The same credit again, and any gap, are both refused.
        assert_eq!(v.credit(Fixed::whole(5), 1, 0), Err(BridgeError::DepositOutOfOrder));
        assert_eq!(v.credit(Fixed::whole(5), 3, 0), Err(BridgeError::DepositOutOfOrder));
        assert_eq!(v.confirmed, Fixed::whole(5), "a refused credit moved the vault");
        v.credit(Fixed::whole(2), 2, 0).unwrap();
        assert_eq!(v.confirmed, Fixed::whole(7));
    }

    #[test]
    fn a_vault_never_releases_more_than_it_holds() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        v.credit(Fixed::whole(10), 1, 0).unwrap();
        assert_eq!(v.release(Fixed::whole(11)), Err(BridgeError::Overflow));
        assert_eq!(v.confirmed, Fixed::whole(10));
        v.release(Fixed::whole(10)).unwrap();
        assert_eq!(v.confirmed, Fixed::ZERO);
    }

    #[test]
    fn an_exit_below_the_dust_limit_is_refused() {
        let mut v = Vault::new(ORIGIN_BITCOIN);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        v.min_exit = Fixed::raw(5_460_000_000_000);
        assert_eq!(
            v.admits_exit(v.min_exit.sub(Fixed::raw(1)).unwrap()),
            Err(BridgeError::BelowExitMinimum)
        );
        v.admits_exit(v.min_exit).unwrap();
        assert_eq!(v.admits_exit(Fixed::ZERO), Err(BridgeError::NonPositive));
    }

    #[test]
    fn the_books_must_balance() {
        let mut v = Vault::new(ORIGIN_SOLANA);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        v.credit(Fixed::whole(3), 1, 0).unwrap();
        v.check(Fixed::whole(3)).unwrap();
        assert!(v.check(Fixed::whole(4)).is_err(), "an over-issue passed");

        // Backing that no deposit accounts for is the fabrication case.
        let mut forged = Vault::new(ORIGIN_SOLANA);
        forged.confirmed = Fixed::whole(3);
        assert!(forged.check(Fixed::whole(3)).is_err());
    }

    /// A total ceiling: the plan's staged mainnet posture, and the difference
    /// between a bad day and a total loss.
    #[test]
    fn a_vault_will_not_hold_more_than_its_ceiling() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        v.cap = Fixed::whole(100);
        v.credit(Fixed::whole(90), 1, 0).unwrap();
        assert_eq!(v.credit(Fixed::whole(11), 2, 0), Err(BridgeError::AboveCap));
        assert_eq!(v.confirmed, Fixed::whole(90), "a refused credit moved the vault");
        assert_eq!(v.deposits, 1, "a refused credit consumed an index");
        v.credit(Fixed::whole(10), 2, 0).unwrap();
        assert_eq!(v.confirmed, Fixed::whole(100));
    }

    /// The per-epoch ceiling is what bounds a *compromise*. The VM cannot
    /// verify a deposit happened, so this turns unbounded fabrication into one
    /// epoch's worth — a quantity signers can check before they sign.
    #[test]
    fn minting_is_bounded_within_an_epoch_and_restored_by_the_next() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        v.epoch_cap = Fixed::whole(50);
        assert_eq!(v.epoch_headroom(0), Some(Fixed::whole(50)));

        v.credit(Fixed::whole(30), 1, 0).unwrap();
        assert_eq!(v.epoch_headroom(0), Some(Fixed::whole(20)));
        assert_eq!(v.credit(Fixed::whole(21), 2, 0), Err(BridgeError::AboveEpochCap));
        v.credit(Fixed::whole(20), 2, 0).unwrap();
        assert_eq!(v.epoch_headroom(0), Some(Fixed::ZERO));
        assert_eq!(v.credit(Fixed::raw(1), 3, 0), Err(BridgeError::AboveEpochCap));

        // The next epoch restores the allowance — and only one allowance,
        // however long the vault sat idle.
        assert_eq!(v.epoch_headroom(1), Some(Fixed::whole(50)));
        assert_eq!(v.epoch_headroom(1_000), Some(Fixed::whole(50)));
        v.credit(Fixed::whole(50), 3, 1_000).unwrap();
        assert_eq!(v.epoch_headroom(1_000), Some(Fixed::ZERO));
        assert_eq!(v.confirmed, Fixed::whole(100));
    }

    #[test]
    fn no_ceiling_means_no_ceiling() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(1_000_000_000), 0).unwrap();
        assert_eq!(v.epoch_headroom(0), None);
        v.credit(Fixed::whole(1_000_000), 1, 0).unwrap();
        v.check(Fixed::whole(1_000_000)).unwrap();
    }

    /// The shielded-vault rule: units issued can never exceed units observed.
    ///
    /// A fabricated credit is not merely unattested — it needs a separate,
    /// dated lie about a balance that every viewing-key holder can check.
    #[test]
    fn a_vault_cannot_issue_more_than_it_was_observed_to_hold() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        // Nothing observed yet, so nothing may be issued.
        assert_eq!(v.credit(Fixed::whole(1), 1, 0), Err(BridgeError::AboveObserved));

        v.attest(Fixed::whole(100), 0).unwrap();
        assert_eq!(v.observed_headroom(), Fixed::whole(100));
        v.credit(Fixed::whole(60), 1, 0).unwrap();
        assert_eq!(v.observed_headroom(), Fixed::whole(40));

        // Past the observation, however much room the other ceilings leave.
        assert_eq!(v.credit(Fixed::whole(41), 2, 0), Err(BridgeError::AboveObserved));
        v.credit(Fixed::whole(40), 2, 0).unwrap();
        assert_eq!(v.credit(Fixed::raw(1), 3, 0), Err(BridgeError::AboveObserved));

        // More arrives on the far chain, is observed, and may then be issued.
        v.attest(Fixed::whole(150), 1).unwrap();
        v.credit(Fixed::whole(50), 3, 1).unwrap();
        v.check(Fixed::whole(150)).unwrap();
    }

    /// A vault reported short is refused, not recorded. The chain neither
    /// absorbs the loss quietly nor freezes itself on an invariant — it names
    /// the condition and leaves the decision to whoever can act on it.
    #[test]
    fn a_reported_shortfall_is_refused_rather_than_absorbed() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(100), 0).unwrap();
        v.credit(Fixed::whole(100), 1, 0).unwrap();

        assert_eq!(
            v.attest(Fixed::whole(99), 1),
            Err(BridgeError::AttestedShortfall),
            "a vault short of what it issued was recorded silently"
        );
        assert_eq!(v.observed, Fixed::whole(100), "a refused report moved the record");
        v.check(Fixed::whole(100)).unwrap();

        // A payout legitimately lowers both, and that reports fine.
        v.release(Fixed::whole(40)).unwrap();
        v.attest(Fixed::whole(60), 1).unwrap();
        v.check(Fixed::whole(60)).unwrap();
    }

    #[test]
    fn a_stale_observation_cannot_overwrite_a_fresher_one() {
        let mut v = Vault::new(ORIGIN_ZCASH);
        v.attest(Fixed::whole(100), 5).unwrap();
        assert_eq!(v.attest(Fixed::whole(200), 4), Err(BridgeError::StaleObservation));
        assert_eq!(v.observed, Fixed::whole(100));
        v.attest(Fixed::whole(200), 5).unwrap();
    }

    /// A redirect must wait, and re-asking restarts the wait — otherwise an
    /// attacker queues one and lets it mature while the owner is watching a
    /// different address.
    #[test]
    fn a_redirect_waits_and_re_asking_restarts_the_wait() {
        let b = Binding::new([1u8; 32]);
        assert!(b.admits([1u8; 32]));
        assert!(!b.admits([2u8; 32]));

        let asked = b.request([2u8; 32], 100);
        assert!(asked.admits([1u8; 32]), "a request should not take effect on its own");
        assert!(!asked.may_apply([2u8; 32], 109, 10));
        assert!(asked.may_apply([2u8; 32], 110, 10));
        // A different address is a different request, from now.
        let again = asked.request([3u8; 32], 105);
        assert!(!again.may_apply([3u8; 32], 110, 10));
        assert!(!again.may_apply([2u8; 32], 200, 10), "the abandoned request stayed live");

        let applied = again.apply([3u8; 32]);
        assert!(applied.admits([3u8; 32]));
        assert!(applied.pending.is_none());
    }

    #[test]
    fn a_credit_waits_for_the_epoch_that_contains_it() {
        let c = PendingCredit::new(Fixed::whole(5), 7);
        assert!(!c.is_final(6));
        assert!(c.is_final(7), "finality should include the epoch itself");
        assert!(c.is_final(8));

        // A later deposit cannot ride out on an earlier one's finality.
        let topped = c.extend(Fixed::whole(5), 9).unwrap();
        assert_eq!(topped.amount, Fixed::whole(10));
        assert_eq!(topped.epoch, 9);
        assert!(!topped.is_final(8));

        // Nor can an out-of-order report drag it backwards.
        assert_eq!(topped.extend(Fixed::whole(1), 3).unwrap().epoch, 9);
    }

    #[test]
    fn an_exit_is_irrevocable_until_it_times_out() {
        let e = PendingExit::new(Fixed::whole(5), 100);
        assert_eq!(e.may_cancel(100, 10), Err(BridgeError::NotTimedOut));
        assert_eq!(e.may_cancel(109, 10), Err(BridgeError::NotTimedOut));
        assert_eq!(e.may_cancel(110, 10), Ok(10));
        // Switched off entirely.
        assert_eq!(e.may_cancel(u64::MAX, 0), Err(BridgeError::NoTimeout));
    }

    #[test]
    fn topping_up_restarts_the_clock_but_settling_does_not() {
        let e = PendingExit::new(Fixed::whole(5), 100);
        let topped = e.extend(Fixed::whole(5), 200).unwrap();
        assert_eq!(topped.amount, Fixed::whole(10));
        assert_eq!(topped.since, 200, "topping up did not restart the clock");

        // A partial settlement must not restart it, or an operator could keep
        // an exit permanently uncancellable by paying a raw unit at a time.
        let settled = topped.settle(Fixed::whole(4)).unwrap();
        assert_eq!(settled.amount, Fixed::whole(6));
        assert_eq!(settled.since, 200);
        assert_eq!(settled.settle(Fixed::whole(7)), Err(BridgeError::NothingPending));
    }

    /// The owner asking again about the same redirect must not reset it — or
    /// "try again after the delay" can never succeed, because trying is what
    /// restarts the delay. A different address still restarts it.
    #[test]
    fn re_asking_the_same_redirect_keeps_its_clock() {
        let b = Binding::new([1u8; 32]).request([2u8; 32], 100);
        let again = b.request([2u8; 32], 105);
        assert_eq!(again.pending, Some(([2u8; 32], 100)), "the same request restarted the clock");
        assert!(again.may_apply([2u8; 32], 110, 10));
        let other = again.request([3u8; 32], 106);
        assert_eq!(other.pending, Some(([3u8; 32], 106)), "a different address must restart it");
    }
}
