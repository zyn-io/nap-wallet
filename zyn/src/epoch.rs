//! The compression policy, and what it is worth.
//!
//! Two levers, at two different costs:
//!
//! ```text
//!   intents ──(intents_per_epoch)──> epoch ──(epochs_per_anchor)──> Zcash tx
//!             cheap, in-VM                    expensive, on-chain
//! ```
//!
//! Sealing an epoch is a state root and a hash — the microchain does it
//! constantly. Anchoring is a Zcash transaction with a Zcash fee and Zcash
//! latency — the microchain does it rarely. Separating the two is what lets the
//! chain checkpoint often enough to bound how much history a failure can lose,
//! while paying an L1 fee only a few times an hour.
//!
//! The product of the two levers is the compression ratio, and the compression
//! ratio is the denominator of the unit economics: it is what turns a fixed L1
//! fee into a per-trade cost small enough that a small trade is still worth
//! making.

/// How often the chain seals and how often it settles.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochPolicy {
    /// Actions before an epoch is sealed. Bounds how much execution a crash can
    /// leave unattested, so it is a durability knob, not a cost knob.
    pub intents_per_epoch: u64,
    /// Sealed epochs before one Zcash transaction. This is the cost knob, and
    /// with `intents_per_epoch` it is the compression ratio.
    pub epochs_per_anchor: u64,
    /// Seal anyway after this many seconds of quiet, so a thin market still
    /// produces a recent root to recover from and prove balances against.
    ///
    /// Zero disables the failsafe. Time is supplied by the caller rather than
    /// read from a clock: the VM must stay deterministic, and a policy that
    /// consulted the wall clock inside the transition would make replay
    /// impossible.
    pub max_seconds_per_epoch: u64,
    /// Anchor anyway after this many seconds, however little traded. An anchor
    /// is what a withdrawal proves against, so exits must not be hostage to
    /// volume.
    pub max_seconds_per_anchor: u64,
}

impl EpochPolicy {
    /// The plan's first target: roughly 1,700 actions per Zcash transaction,
    /// with a seal often enough that no more than a few hundred actions are
    /// ever unattested.
    ///
    /// The failsafes matter more than the counts on a young market: early on
    /// there is not enough flow to fill an epoch, and a chain that only settles
    /// when busy would leave its first users unable to exit.
    pub fn v1() -> Self {
        EpochPolicy {
            intents_per_epoch: 250,
            epochs_per_anchor: 7,
            max_seconds_per_epoch: 60,
            max_seconds_per_anchor: 15 * 60,
        }
    }

    /// Actions per Zcash transaction at full epochs — the headline ratio.
    ///
    /// A ceiling, not a promise: the failsafes seal and anchor early on a quiet
    /// market, so the realised ratio is whatever [`Compression`] measured.
    pub fn target_ratio(&self) -> u64 {
        self.intents_per_epoch
            .saturating_mul(self.epochs_per_anchor)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.intents_per_epoch == 0 {
            return Err("an epoch must cover at least one action");
        }
        if self.epochs_per_anchor == 0 {
            return Err("an anchor must cover at least one epoch");
        }
        // Anchoring more often than sealing is not wrong so much as incoherent:
        // an anchor commits a sealed epoch, so there would be nothing new to
        // carry.
        if self.max_seconds_per_anchor != 0
            && self.max_seconds_per_epoch != 0
            && self.max_seconds_per_anchor < self.max_seconds_per_epoch
        {
            return Err("the anchor failsafe must not fire before the seal failsafe");
        }
        Ok(())
    }

    /// Whether the epoch should be sealed now.
    pub fn should_seal(&self, actions_since_seal: u64, seconds_since_seal: u64) -> bool {
        if actions_since_seal == 0 {
            return false; // never seal an empty epoch: nothing moved to attest
        }
        actions_since_seal >= self.intents_per_epoch
            || (self.max_seconds_per_epoch > 0 && seconds_since_seal >= self.max_seconds_per_epoch)
    }

    /// Whether the sealed epochs should be carried to Zcash now.
    pub fn should_anchor(&self, epochs_since_anchor: u64, seconds_since_anchor: u64) -> bool {
        if epochs_since_anchor == 0 {
            return false; // nothing sealed since the last anchor
        }
        epochs_since_anchor >= self.epochs_per_anchor
            || (self.max_seconds_per_anchor > 0
                && seconds_since_anchor >= self.max_seconds_per_anchor)
    }
}

/// What the chain actually compressed, as opposed to what it aimed at.
///
/// The realised figures, because the failsafes mean the target is a ceiling.
/// This is the number that goes on a dashboard and into a pitch, so it is
/// measured rather than assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Compression {
    /// Microchain actions applied, rejections included — a rejected intent
    /// consumed sequencing and settlement capacity like any other.
    pub actions: u64,
    pub epochs: u64,
    /// Zcash transactions spent carrying this chain's state.
    pub anchors: u64,
}

impl Compression {
    /// Actions per Zcash transaction, rounded down. `None` before the first
    /// anchor, when the ratio is not yet defined rather than infinite.
    pub fn realised_ratio(&self) -> Option<u64> {
        if self.anchors == 0 {
            return None;
        }
        Some(self.actions / self.anchors)
    }

    /// Zcash transactions the chain did **not** need.
    ///
    /// The plan's "Zcash transactions saved": settling one by one would have
    /// cost one transaction per action, so everything past `anchors` is the
    /// L1 load the microchain absorbed.
    pub fn transactions_saved(&self) -> u64 {
        self.actions.saturating_sub(self.anchors)
    }
}

/// A unit of account for L1 costs, in the smallest indivisible unit.
///
/// Zatoshi for ZEC. Kept as an integer with no scaling because a fee is a fee —
/// it is quoted by the network, not derived, and putting it through `Fixed`
/// would invite it into arithmetic it has no business in.
pub type Unit = u64;

/// The unit economics of running the chain.
///
/// Answers the question the whole architecture exists to answer: what does one
/// swap cost to settle, and what does it earn?
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Economics {
    /// What one anchoring transaction costs on Zcash, in zatoshi.
    pub anchor_fee: Unit,
    /// What a single directly-settled trade would cost on Zcash, in zatoshi.
    ///
    /// The counterfactual the microchain is measured against — usually the same
    /// as `anchor_fee`, since a trade and an anchor are both one transaction,
    /// which is exactly why settling per trade does not scale.
    pub direct_fee: Unit,
}

impl Economics {
    /// A plausible Zcash cost: both a settlement and a direct trade are one
    /// ordinary transaction.
    pub fn flat(fee: Unit) -> Self {
        Economics {
            anchor_fee: fee,
            direct_fee: fee,
        }
    }

    /// Total L1 cost the chain has actually incurred.
    pub fn spent(&self, c: &Compression) -> Unit {
        self.anchor_fee.saturating_mul(c.anchors)
    }

    /// What settling those actions one by one would have cost.
    pub fn counterfactual(&self, c: &Compression) -> Unit {
        self.direct_fee.saturating_mul(c.actions)
    }

    /// L1 cost avoided. The microchain's gross contribution before any fee
    /// revenue at all.
    pub fn saved(&self, c: &Compression) -> Unit {
        self.counterfactual(c).saturating_sub(self.spent(c))
    }

    /// Settlement cost carried by one action, rounded **up**.
    ///
    /// Up, because this figure is used to decide whether a trade is worth
    /// accepting, and a cost estimate that rounds in the operator's favour is
    /// the kind that makes a business look profitable until it is measured.
    pub fn cost_per_action(&self, c: &Compression) -> Option<Unit> {
        if c.actions == 0 {
            return None;
        }
        let spent = self.spent(c);
        Some(spent.div_ceil(c.actions))
    }

    /// The settlement cost a single trade must clear at a given compression
    /// ratio — the break-even a fee has to beat.
    pub fn cost_per_action_at(&self, ratio: u64) -> Option<Unit> {
        if ratio == 0 {
            return None;
        }
        Some(self.anchor_fee.div_ceil(ratio))
    }
}

/// A period's headline figures, for a dashboard or a status endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Report {
    pub compression: Compression,
    /// Realised actions per Zcash transaction.
    pub ratio: Option<u64>,
    /// Zcash transactions the microchain absorbed.
    pub transactions_saved: u64,
    /// L1 cost carried by one action, in zatoshi.
    pub cost_per_action: Option<Unit>,
    /// L1 cost avoided against settling one by one, in zatoshi.
    pub l1_saved: Unit,
}

impl Report {
    pub fn build(c: Compression, e: Economics) -> Report {
        Report {
            compression: c,
            ratio: c.realised_ratio(),
            transactions_saved: c.transactions_saved(),
            cost_per_action: e.cost_per_action(&c),
            l1_saved: e.saved(&c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_is_coherent() {
        let p = EpochPolicy::v1();
        p.validate().expect("v1 policy must validate");
        assert_eq!(p.target_ratio(), 250 * 7);
    }

    #[test]
    fn incoherent_policies_are_refused() {
        let mut p = EpochPolicy::v1();
        p.intents_per_epoch = 0;
        assert!(p.validate().is_err());

        let mut p = EpochPolicy::v1();
        p.epochs_per_anchor = 0;
        assert!(p.validate().is_err());

        // Anchoring before sealing would carry nothing.
        let mut p = EpochPolicy::v1();
        p.max_seconds_per_epoch = 600;
        p.max_seconds_per_anchor = 60;
        assert!(p.validate().is_err());
    }

    #[test]
    fn an_empty_epoch_is_never_sealed() {
        let p = EpochPolicy::v1();
        // Not even when the failsafe has long expired: there is nothing to
        // attest, and sealing would spend an anchor slot on no history.
        assert!(!p.should_seal(0, 99_999));
        assert!(!p.should_anchor(0, 99_999));
    }

    #[test]
    fn either_the_count_or_the_clock_triggers_a_seal() {
        let p = EpochPolicy::v1();
        assert!(!p.should_seal(249, 59));
        assert!(p.should_seal(250, 0), "the count should have sealed it");
        assert!(p.should_seal(1, 60), "the failsafe should have sealed it");
    }

    #[test]
    fn a_quiet_market_still_anchors() {
        // The property that keeps exits from being hostage to volume.
        let p = EpochPolicy::v1();
        assert!(!p.should_anchor(1, 899));
        assert!(p.should_anchor(1, 900));
        assert!(p.should_anchor(7, 0));
    }

    #[test]
    fn failsafes_can_be_switched_off() {
        let p = EpochPolicy {
            intents_per_epoch: 10,
            epochs_per_anchor: 2,
            max_seconds_per_epoch: 0,
            max_seconds_per_anchor: 0,
        };
        p.validate().unwrap();
        assert!(!p.should_seal(9, u64::MAX));
        assert!(!p.should_anchor(1, u64::MAX));
    }

    #[test]
    fn the_ratio_is_undefined_before_the_first_anchor() {
        let c = Compression {
            actions: 500,
            epochs: 2,
            anchors: 0,
        };
        assert_eq!(
            c.realised_ratio(),
            None,
            "a ratio over zero anchors is not infinity"
        );
        assert_eq!(c.transactions_saved(), 500);
    }

    /// The plan's headline: 25,000 actions into 15 Zcash transactions.
    #[test]
    fn the_compression_figure_is_the_one_the_plan_quotes() {
        let c = Compression {
            actions: 25_000,
            epochs: 105,
            anchors: 15,
        };
        assert_eq!(c.realised_ratio(), Some(1_666));
        assert_eq!(c.transactions_saved(), 24_985);
    }

    #[test]
    fn economics_price_the_compression() {
        // 1000 zatoshi per Zcash transaction.
        let e = Economics::flat(1_000);
        let c = Compression {
            actions: 25_000,
            epochs: 105,
            anchors: 15,
        };
        assert_eq!(e.spent(&c), 15_000);
        assert_eq!(e.counterfactual(&c), 25_000_000);
        assert_eq!(e.saved(&c), 24_985_000);
        // Under a zatoshi per trade: the point of the exercise.
        assert_eq!(e.cost_per_action(&c), Some(1));
    }

    /// Cost per action must round up, or an operator's break-even is optimistic
    /// by exactly the amount that matters at scale.
    #[test]
    fn cost_per_action_never_rounds_in_the_operators_favour() {
        let e = Economics::flat(1_000);
        // 3000 zatoshi spent over 7 actions is 428.57; a floor would say 428.
        let c = Compression {
            actions: 7,
            epochs: 3,
            anchors: 3,
        };
        assert_eq!(e.cost_per_action(&c), Some(429));
        assert_eq!(e.cost_per_action(&Compression::default()), None);
    }

    #[test]
    fn break_even_falls_as_compression_rises() {
        let e = Economics::flat(10_000);
        let a = e.cost_per_action_at(100).unwrap();
        let b = e.cost_per_action_at(1_750).unwrap();
        assert_eq!(a, 100);
        assert_eq!(b, 6);
        assert!(b < a, "more compression must cost less per trade");
        assert_eq!(e.cost_per_action_at(0), None);
    }

    #[test]
    fn saturation_beats_overflow_on_the_counterfactual() {
        // A dashboard figure must not wrap into a negative-looking number.
        let e = Economics::flat(u64::MAX);
        let c = Compression {
            actions: u64::MAX,
            epochs: 1,
            anchors: 1,
        };
        assert_eq!(e.counterfactual(&c), u64::MAX);
        assert_eq!(e.saved(&c), 0);
    }
}
