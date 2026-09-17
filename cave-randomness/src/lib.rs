//! Verifiable allocation for Cave collection launches.
//!
//! This crate owns no network, clock, database, wallet, or Zyn authority. It
//! consumes a policy and external evidence, verifies drand inside the process,
//! and produces bytes that any independent verifier can replay. The caller is
//! responsible for proving that a named Zcash block hash is canonical at the
//! policy's precommitted height.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use drand_verify::{derive_randomness, G2PubkeyRfc, Pubkey};
use hex_literal::hex;
use hkdf::Hkdf;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

// v2 adds the announced-close rule to the canonical bytes. The version is in
// the bytes themselves, so a v1 digest and a v2 digest cannot be confused and
// an old published commitment still means what it meant. §64.16 already called
// for a format migration before production; this is it.
pub const POLICY_VERSION: &str = "cave-allocation/v2";
pub const RECEIPT_VERSION: &str = "cave-allocation-receipt/v1";
pub const BATCH_VERSION: &str = "cave-allocation-batch/v1";
pub const ANNOUNCE_VERSION: &str = "cave-close-announcement/v1";
pub const TERMS_VERSION: &str = "cave-sale-terms/v1";
pub const QUICKNET_CHAIN_HASH: Hash =
    hex!("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971");
pub const QUICKNET_PUBLIC_KEY: [u8; 96] = hex!(
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
);

const POLICY_DIGEST_DOMAIN: &[u8] = b"cave.policy.digest.v1";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"cave.receipt.digest.v1";
const BATCH_DIGEST_DOMAIN: &[u8] = b"cave.batch.digest.v1";
const ANNOUNCE_DIGEST_DOMAIN: &[u8] = b"cave.close.announcement.v1";
const TERMS_DIGEST_DOMAIN: &[u8] = b"cave.sale.terms.v1";
const MANIFEST_LEAF_DOMAIN: &[u8] = b"cave.manifest.entry.v1";
const TICKET_ID_DOMAIN: &[u8] = b"cave.ticket.id.v1";
const TICKET_LEAF_DOMAIN: &[u8] = b"cave.ticket.resolved.v1";
const ASSIGNMENT_LEAF_DOMAIN: &[u8] = b"cave.assignment.v1";
const QUANTITY_INFO: &[u8] = b"cave/quantity/v1";
const CONCEALED_INFO: &[u8] = b"cave/index-shuffle/v1";
const INSTANT_INFO: &[u8] = b"cave/instant-index/v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidPolicy(&'static str),
    InvalidManifest(&'static str),
    InvalidTicket(&'static str),
    CapacityExceeded { requested: u64, supply: u32 },
    MissingEvidence(&'static str),
    UnexpectedEvidence(&'static str),
    WrongDrandChain,
    WrongDrandRound { expected: u64, got: u64 },
    InvalidDrandPublicKey,
    InvalidDrandBeacon,
    WrongRevealHeight { expected: u32, got: u32 },
    DerivationFailed,
    VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPolicy(message) => write!(f, "invalid policy: {message}"),
            Error::InvalidManifest(message) => write!(f, "invalid manifest: {message}"),
            Error::InvalidTicket(message) => write!(f, "invalid ticket: {message}"),
            Error::CapacityExceeded { requested, supply } => {
                write!(
                    f,
                    "allocation requests {requested} objects from supply {supply}"
                )
            }
            Error::MissingEvidence(name) => write!(f, "missing evidence: {name}"),
            Error::UnexpectedEvidence(name) => write!(f, "unexpected evidence: {name}"),
            Error::WrongDrandChain => write!(f, "beacon is not from pinned drand Quicknet"),
            Error::WrongDrandRound { expected, got } => {
                write!(f, "wrong drand round: expected {expected}, got {got}")
            }
            Error::InvalidDrandPublicKey => write!(f, "pinned drand public key is invalid"),
            Error::InvalidDrandBeacon => write!(f, "drand BLS signature is invalid"),
            Error::WrongRevealHeight { expected, got } => {
                write!(
                    f,
                    "wrong Zcash reveal height: expected {expected}, got {got}"
                )
            }
            Error::DerivationFailed => write!(f, "HKDF expansion failed"),
            Error::VerificationFailed => write!(f, "allocation replay did not match"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WeightedOutcome {
    pub items: u32,
    /// Relative weight. It does not need to total 100 and is never interpreted
    /// as an integer range; sampling is unbiased over the sum of all weights.
    pub weight: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuantityPolicy {
    Fixed { items: u32 },
    Weighted { outcomes: Vec<WeightedOutcome> },
    BuyerChooses { minimum: u32, maximum: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityPolicy {
    ConcealedShuffle,
    InstantRandom,
    Sequential,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RandomnessPlan {
    pub drand_chain_hash: Hash,
    /// A ticket's target round must be at least this far beyond the round
    /// recorded when the ticket was committed.
    pub ticket_round_delay: u64,
    /// Required only for a collection-wide concealed shuffle whose close height
    /// was committed up front.
    pub reveal_drand_round: Option<u64>,
    /// Required only for a collection-wide concealed shuffle whose close height
    /// was committed up front.
    pub reveal_zcash_height: Option<u32>,
    /// The **announced-close** rule, for a sale whose length is decided by
    /// watching demand rather than fixed weeks in advance.
    ///
    /// The operator names the close height when they choose; the reveal then
    /// follows mechanically from it. Committing the *offsets* before any
    /// deposit arrives is what keeps that safe: an operator who could pick the
    /// reveal target after seeing the final ticket ledger could try candidate
    /// heights until one produced a mapping they liked, and nobody could tell.
    /// Naming the close is a timing decision; deriving the reveal from it takes
    /// the outcome out of their hands (§100.2).
    pub announced_close: Option<AnnouncedClose>,
}

/// The rule that turns an announced close height into reveal targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnouncedClose {
    /// Reveal at `close + this`. Enough blocks that the close is past
    /// ordinary reorg depth, and few enough that buyers are not left waiting.
    pub reveal_offset_blocks: u32,
    /// And at `announced_round + this`, so the drand leg is equally derived.
    /// Drand output is unpredictable, so a round this far ahead cannot be
    /// ground against — which is the whole reason the reveal binds two
    /// independent sources (§64.11).
    pub reveal_offset_rounds: u64,
    /// The least warning a close must give. An announcement naming a height
    /// already reached, or nearly, is not notice — it is closing the door and
    /// saying so afterwards.
    pub min_notice_blocks: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationPolicy {
    pub collection_id: Hash,
    pub supply: u32,
    pub entry_price_zatoshi: u64,
    /// Last Zcash height at which a confirmed deposit can enter this sale.
    pub deposit_close_zcash_height: u32,
    pub quantity: QuantityPolicy,
    pub identity: IdentityPolicy,
    pub manifest_root: Hash,
    pub randomness: RandomnessPlan,
}

impl AllocationPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.collection_id == [0; 32] {
            return Err(Error::InvalidPolicy("collection id is zero"));
        }
        if self.supply == 0 {
            return Err(Error::InvalidPolicy("supply is zero"));
        }
        if self.entry_price_zatoshi == 0 {
            return Err(Error::InvalidPolicy("entry price is zero"));
        }
        // Zero means "announced later", and is only meaningful when the rule
        // for deriving the reveal from that announcement is already committed.
        // Without it, zero would simply be a sale with no end.
        if self.deposit_close_zcash_height == 0 && self.randomness.announced_close.is_none() {
            return Err(Error::InvalidPolicy("deposit close height is zero"));
        }
        if self.deposit_close_zcash_height != 0 && self.randomness.announced_close.is_some() {
            return Err(Error::InvalidPolicy(
                "a close height is committed and also announced later; it is one or the other",
            ));
        }
        if let Some(a) = &self.randomness.announced_close {
            // A reveal at the close height itself would be decided by a block
            // that already existed when the close was named.
            if a.reveal_offset_blocks == 0 {
                return Err(Error::InvalidPolicy("the reveal must be after the close"));
            }
            if a.reveal_offset_rounds == 0 {
                return Err(Error::InvalidPolicy(
                    "the reveal drand round must be ahead of the announcement",
                ));
            }
            if a.min_notice_blocks == 0 {
                return Err(Error::InvalidPolicy(
                    "a close with no notice is not an announcement",
                ));
            }
        }
        if self.manifest_root == [0; 32] {
            return Err(Error::InvalidPolicy("manifest root is zero"));
        }
        if self.randomness.drand_chain_hash != QUICKNET_CHAIN_HASH {
            return Err(Error::InvalidPolicy(
                "only the pinned Quicknet chain is supported",
            ));
        }

        let uses_ticket_randomness = matches!(self.quantity, QuantityPolicy::Weighted { .. })
            || self.identity == IdentityPolicy::InstantRandom;
        if uses_ticket_randomness && self.randomness.ticket_round_delay == 0 {
            return Err(Error::InvalidPolicy(
                "ticket randomness must target a future round",
            ));
        }

        match &self.quantity {
            QuantityPolicy::Fixed { items } => self.validate_amount(*items)?,
            QuantityPolicy::BuyerChooses { minimum, maximum } => {
                self.validate_amount(*minimum)?;
                self.validate_amount(*maximum)?;
                if minimum > maximum {
                    return Err(Error::InvalidPolicy("buyer range is reversed"));
                }
            }
            QuantityPolicy::Weighted { outcomes } => {
                if outcomes.is_empty() {
                    return Err(Error::InvalidPolicy("weighted policy has no outcomes"));
                }
                let mut seen = BTreeSet::new();
                let mut total = 0u64;
                for outcome in outcomes {
                    self.validate_amount(outcome.items)?;
                    if outcome.weight == 0 {
                        return Err(Error::InvalidPolicy("weighted outcome has zero weight"));
                    }
                    if !seen.insert(outcome.items) {
                        return Err(Error::InvalidPolicy(
                            "weighted outcome amount is duplicated",
                        ));
                    }
                    total = total
                        .checked_add(outcome.weight)
                        .ok_or(Error::InvalidPolicy("weight sum overflows u64"))?;
                }
                if total == 0 {
                    return Err(Error::InvalidPolicy("weight sum is zero"));
                }
            }
        }

        match self.identity {
            IdentityPolicy::ConcealedShuffle => match &self.randomness.announced_close {
                // Announced form: the targets do not exist yet and must not,
                // or naming them up front would defeat the point of announcing.
                Some(_) => {
                    if self.randomness.reveal_drand_round.is_some()
                        || self.randomness.reveal_zcash_height.is_some()
                    {
                        return Err(Error::InvalidPolicy(
                            "an announced close derives its reveal targets; they cannot also be fixed",
                        ));
                    }
                }
                None => {
                    if self.randomness.reveal_drand_round.is_none()
                        || self.randomness.reveal_zcash_height.is_none()
                    {
                        return Err(Error::InvalidPolicy(
                            "concealed shuffle has no exact reveal targets",
                        ));
                    }
                    if self.randomness.reveal_zcash_height.unwrap()
                        <= self.deposit_close_zcash_height
                    {
                        return Err(Error::InvalidPolicy(
                            "concealed reveal height is not after deposit close",
                        ));
                    }
                }
            },
            IdentityPolicy::InstantRandom | IdentityPolicy::Sequential => {
                if self.randomness.reveal_drand_round.is_some()
                    || self.randomness.reveal_zcash_height.is_some()
                {
                    return Err(Error::InvalidPolicy(
                        "unused collection reveal targets are set",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_amount(&self, amount: u32) -> Result<(), Error> {
        if amount == 0 || amount > self.supply {
            return Err(Error::InvalidPolicy("receipt amount is outside supply"));
        }
        Ok(())
    }

    /// Fixed-width, length-delimited bytes. JSON object order never enters the
    /// commitment. Weighted outcomes are sorted by item count.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut out = Vec::new();
        put_bytes(&mut out, POLICY_VERSION.as_bytes());
        out.extend_from_slice(&self.collection_id);
        put_u32(&mut out, self.supply);
        put_u64(&mut out, self.entry_price_zatoshi);
        put_u32(&mut out, self.deposit_close_zcash_height);
        match &self.quantity {
            QuantityPolicy::Fixed { items } => {
                out.push(0);
                put_u32(&mut out, *items);
            }
            QuantityPolicy::Weighted { outcomes } => {
                out.push(1);
                let mut sorted = outcomes.clone();
                sorted.sort_by_key(|outcome| outcome.items);
                put_u32(&mut out, sorted.len() as u32);
                for outcome in sorted {
                    put_u32(&mut out, outcome.items);
                    put_u64(&mut out, outcome.weight);
                }
            }
            QuantityPolicy::BuyerChooses { minimum, maximum } => {
                out.push(2);
                put_u32(&mut out, *minimum);
                put_u32(&mut out, *maximum);
            }
        }
        out.push(match self.identity {
            IdentityPolicy::ConcealedShuffle => 0,
            IdentityPolicy::InstantRandom => 1,
            IdentityPolicy::Sequential => 2,
        });
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.randomness.drand_chain_hash);
        put_u64(&mut out, self.randomness.ticket_round_delay);
        put_opt_u64(&mut out, self.randomness.reveal_drand_round);
        put_opt_u32(&mut out, self.randomness.reveal_zcash_height);
        match &self.randomness.announced_close {
            None => out.push(0),
            Some(a) => {
                out.push(1);
                put_u32(&mut out, a.reveal_offset_blocks);
                put_u64(&mut out, a.reveal_offset_rounds);
                put_u32(&mut out, a.min_notice_blocks);
            }
        }
        Ok(out)
    }

    pub fn digest(&self) -> Result<Hash, Error> {
        Ok(domain_hash(POLICY_DIGEST_DOMAIN, &self.canonical_bytes()?))
    }

    pub fn maximum_receipt(&self) -> u32 {
        match &self.quantity {
            QuantityPolicy::Fixed { items } => *items,
            QuantityPolicy::Weighted { outcomes } => outcomes
                .iter()
                .map(|outcome| outcome.items)
                .max()
                .unwrap_or(0),
            QuantityPolicy::BuyerChooses { maximum, .. } => *maximum,
        }
    }
}

/// The whole primary-sale promise, in one commitment (§64.16).
///
/// The allocation policy says how items are assigned. It says nothing about
/// what anything costs, who receives the money, or how much of it reaches the
/// pool — and those are the parts a buyer is trusting. Left in a web form or a
/// service environment variable they can be changed between two buyers without
/// either knowing, which is exactly the shape of the rug-pulls this collection
/// is trying not to resemble.
///
/// So they are committed here, once, before the first deposit, and the digest
/// is what a ticket references. Anything that could change what a buyer gets
/// for their money belongs in these bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SaleTerms {
    /// The allocation policy these terms sit over.
    pub policy_digest: Hash,
    /// Repeated from the policy rather than referenced, so the terms can be
    /// read without it. A mismatch is caught by [`SaleTerms::check`].
    pub collection_id: Hash,
    pub manifest_root: Hash,
    /// Where the money goes. `TREASURY_26460` in production (§83.1).
    pub treasury: Hash,
    /// 0 = Zcash mainnet, 1 = Zcash testnet. Named because paying the right
    /// price on the wrong network is a complete loss and an easy mistake.
    pub network: u8,
    /// The three prices, in zatoshi (§64.17).
    pub entry_price_zatoshi: u64,
    pub claim_price_zatoshi: u64,
    pub open_mint_price_zatoshi: u64,
    /// Confirmations before a deposit counts. Below this a ticket is not a
    /// ticket, so it is part of the promise rather than an operational knob.
    pub min_confirmations: u32,
    /// Blocks after the deposit close during which an allocation may still be
    /// claimed. An offset rather than a height, because the close itself is
    /// announced (§100.2) and a fixed claim height would drift out of step.
    pub claim_window_blocks: u32,
    /// Basis points of every primary-sale payment retained by the treasury;
    /// the remainder funds the collection and becomes the floor. 1,000 = 10%
    /// (§64.17).
    pub treasury_bps: u16,
}

impl SaleTerms {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, TERMS_VERSION.as_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.collection_id);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.treasury);
        out.push(self.network);
        put_u64(&mut out, self.entry_price_zatoshi);
        put_u64(&mut out, self.claim_price_zatoshi);
        put_u64(&mut out, self.open_mint_price_zatoshi);
        put_u32(&mut out, self.min_confirmations);
        put_u32(&mut out, self.claim_window_blocks);
        put_u32(&mut out, self.treasury_bps as u32);
        out
    }

    pub fn digest(&self) -> Hash {
        domain_hash(TERMS_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    /// Everything checkable without leaving the process.
    pub fn check(&self, policy: &AllocationPolicy) -> Result<(), Error> {
        if self.policy_digest != policy.digest()? {
            return Err(Error::InvalidPolicy("terms are for another policy"));
        }
        // Repeated fields must agree with the policy, or the two documents
        // describe different sales and a reader has no way to know which won.
        if self.collection_id != policy.collection_id || self.manifest_root != policy.manifest_root
        {
            return Err(Error::InvalidPolicy("terms contradict the policy"));
        }
        if self.entry_price_zatoshi != policy.entry_price_zatoshi {
            return Err(Error::InvalidPolicy("terms price a different entry"));
        }
        if self.treasury == [0; 32] {
            return Err(Error::InvalidPolicy("the zero account is not a treasury"));
        }
        if self.network > 1 {
            return Err(Error::InvalidPolicy("unknown Zcash network"));
        }
        if self.entry_price_zatoshi == 0
            || self.claim_price_zatoshi == 0
            || self.open_mint_price_zatoshi == 0
        {
            return Err(Error::InvalidPolicy("a zero price is not a price"));
        }
        // A treasury taking everything leaves nothing behind the items, and
        // the floor is the thing a buyer is actually trusting.
        if self.treasury_bps >= 10_000 {
            return Err(Error::InvalidPolicy(
                "the treasury cannot take the whole payment; the remainder is the floor",
            ));
        }
        if self.min_confirmations == 0 {
            return Err(Error::InvalidPolicy(
                "a deposit with no confirmations can still be reorged away",
            ));
        }
        if self.claim_window_blocks == 0 {
            return Err(Error::InvalidPolicy("a claim window of zero blocks is no window"));
        }
        Ok(())
    }

    /// What reaches the collection's pool from one payment, and what the
    /// treasury keeps. Rounding goes to the pool: the floor is what buyers are
    /// trusting, so a spare zatoshi belongs on their side of the split.
    pub fn split(&self, paid_zatoshi: u64) -> (u64, u64) {
        let treasury = paid_zatoshi.saturating_mul(self.treasury_bps as u64) / 10_000;
        (paid_zatoshi.saturating_sub(treasury), treasury)
    }
}

/// The operator naming when deposits close, under an [`AnnouncedClose`] rule.
///
/// This is the one decision left to a person, and it is deliberately the only
/// one: how long to run the sale, judged by watching demand. Everything the
/// outcome depends on is derived from it by rules committed before any deposit
/// arrived.
///
/// What it cannot do is help the operator choose who wins. The close is in the
/// future when it is named, the reveal block is further ahead still, and the
/// reveal drand round is a round whose output does not yet exist. There is
/// nothing to try candidates against.
///
/// **Its integrity rests on being published before the height it names.** This
/// type enforces the ordering it can see — notice, offsets, the policy it
/// belongs to — but nothing here proves *when* an announcement was written. A
/// verifier needs the publication to be timestamped by something outside the
/// operator's control, which is the publication service §64.4 already requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseAnnouncement {
    /// The policy this closes. Binding it means an announcement cannot be
    /// lifted from one sale to another.
    pub policy_digest: Hash,
    /// The Zcash tip when this was announced.
    pub announced_at_zcash_height: u32,
    /// The drand round observed at the same moment.
    pub announced_at_drand_round: u64,
    /// When deposits stop. Strictly after the announcement, by the policy's
    /// notice.
    pub deposit_close_zcash_height: u32,
}

/// Evidence that an announcement was on Zcash by a given height.
///
/// The engine cannot fetch anything, so this is supplied by a caller who has
/// checked it — the same arrangement as [`RevealEvidence`], and the same
/// obligation: the caller must confirm that the transaction at `txid` is in the
/// canonical chain at `height` and that its memo is
/// `memo::encode_publication(announcement.digest())`.
///
/// Without it an announcement is a document the operator could have written at
/// any time, including after seeing what it would produce (§100.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicationProof {
    /// The Zcash transaction carrying the announcement's digest in its memo.
    pub txid: Hash,
    /// The height it confirmed at. Notice is measured from here, not from what
    /// the announcement says about itself.
    pub height: u32,
}

/// The targets an announcement resolves to, all derived and none chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedClose {
    pub deposit_close_zcash_height: u32,
    pub reveal_zcash_height: u32,
    pub reveal_drand_round: u64,
}

impl CloseAnnouncement {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, ANNOUNCE_VERSION.as_bytes());
        out.extend_from_slice(&self.policy_digest);
        put_u32(&mut out, self.announced_at_zcash_height);
        put_u64(&mut out, self.announced_at_drand_round);
        put_u32(&mut out, self.deposit_close_zcash_height);
        out
    }

    pub fn digest(&self) -> Hash {
        domain_hash(ANNOUNCE_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    /// Check this announcement against its policy and its publication, and
    /// derive the targets.
    ///
    /// `proof` is what makes the notice real. The announcement's own
    /// `announced_at_zcash_height` is the operator's claim about when it acted;
    /// the proof is Zcash's. They must agree, and the notice is measured from
    /// the proof — so an announcement written late and backdated fails here
    /// rather than passing quietly.
    pub fn resolve(
        &self,
        policy: &AllocationPolicy,
        proof: &PublicationProof,
    ) -> Result<ResolvedClose, Error> {
        // The claim and the chain must say the same thing. Taking the lower of
        // the two, or ignoring the field, would leave a number in the canonical
        // bytes that means nothing.
        if proof.height != self.announced_at_zcash_height {
            return Err(Error::InvalidTicket(
                "the announcement claims a different height than the block that carries it",
            ));
        }
        self.resolve_unproven(policy)
    }

    /// The derivation without the publication check.
    ///
    /// Separate and named so that using it is a decision. It is correct for
    /// building an announcement — there is no proof yet, because it has not
    /// been published — and wrong for accepting one.
    pub fn resolve_unproven(&self, policy: &AllocationPolicy) -> Result<ResolvedClose, Error> {
        let rule = policy
            .randomness
            .announced_close
            .ok_or(Error::InvalidPolicy("this policy commits its close height"))?;
        if self.policy_digest != policy.digest()? {
            return Err(Error::InvalidTicket("announcement is for another policy"));
        }
        // Named in the future, with the notice the policy promised. An
        // announcement of a height already passed is a closed door described
        // afterwards.
        let earliest = self
            .announced_at_zcash_height
            .checked_add(rule.min_notice_blocks)
            .ok_or(Error::DerivationFailed)?;
        if self.deposit_close_zcash_height < earliest {
            return Err(Error::InvalidTicket("the close gives less notice than the policy promised"));
        }
        let reveal_zcash_height = self
            .deposit_close_zcash_height
            .checked_add(rule.reveal_offset_blocks)
            .ok_or(Error::DerivationFailed)?;
        let reveal_drand_round = self
            .announced_at_drand_round
            .checked_add(rule.reveal_offset_rounds)
            .ok_or(Error::DerivationFailed)?;
        Ok(ResolvedClose {
            deposit_close_zcash_height: self.deposit_close_zcash_height,
            reveal_zcash_height,
            reveal_drand_round,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub global_index: u32,
    pub item_id: Hash,
    pub content_hash: Hash,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: Hash,
    pub node_is_right: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrandBeacon {
    pub chain_hash: Hash,
    pub round: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealEvidence {
    pub beacon: DrandBeacon,
    pub zcash_height: u32,
    pub zcash_block_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    pub ticket_id: Hash,
    pub deposit_txid: Hash,
    /// Exact output/note position within the Zcash transaction. Together with
    /// `deposit_txid`, this permits several independent tickets in one tx.
    pub deposit_output_index: u32,
    /// Value of that exact output. A ticket is valid only when it equals the
    /// policy's committed entry price.
    pub deposit_amount_zatoshi: u64,
    /// Zyn account that alone may receive every item allocated to this ticket.
    pub recipient: Hash,
    pub confirmed_height: u32,
    pub tx_index: u32,
    /// The drand round observed when this target was committed publicly.
    pub issued_at_drand_round: u64,
    pub quantity_drand_round: Option<u64>,
    pub identity_drand_round: Option<u64>,
    pub requested_items: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketEvidence {
    pub ticket: Ticket,
    pub quantity_beacon: Option<DrandBeacon>,
    pub identity_beacon: Option<DrandBeacon>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatedItem {
    pub global_index: u32,
    pub item_id: Hash,
    pub content_hash: Hash,
    pub manifest_proof: Vec<ProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationReceipt {
    pub ticket: Ticket,
    pub quantity: u32,
    pub slot_start: u32,
    pub items: Vec<AllocatedItem>,
    pub policy_digest: Hash,
    pub manifest_root: Hash,
    pub ticket_ledger_root: Hash,
    /// Ledger root for concealed/sequential allocation, prefix root for an
    /// instant ticket. It makes the exact shuffle context explicit.
    pub identity_context: Hash,
}

impl AllocationReceipt {
    /// Stable publication bytes for a receipt produced by `allocate`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, RECEIPT_VERSION.as_bytes());
        put_ticket(&mut out, &self.ticket);
        put_u32(&mut out, self.quantity);
        put_u32(&mut out, self.slot_start);
        put_u32(&mut out, self.items.len() as u32);
        for item in &self.items {
            put_u32(&mut out, item.global_index);
            out.extend_from_slice(&item.item_id);
            out.extend_from_slice(&item.content_hash);
            put_u32(&mut out, item.manifest_proof.len() as u32);
            for step in &item.manifest_proof {
                out.extend_from_slice(&step.sibling);
                out.push(u8::from(step.node_is_right));
            }
        }
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.ticket_ledger_root);
        out.extend_from_slice(&self.identity_context);
        out
    }

    pub fn digest(&self) -> Hash {
        domain_hash(RECEIPT_DIGEST_DOMAIN, &self.canonical_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationBatch {
    pub policy_digest: Hash,
    pub manifest_root: Hash,
    pub ticket_ledger_root: Hash,
    pub assignment_root: Hash,
    pub receipts: Vec<AllocationReceipt>,
    pub unused_indices: Vec<u32>,
}

impl AllocationBatch {
    /// Stable publication bytes for the complete replay result.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, BATCH_VERSION.as_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.manifest_root);
        out.extend_from_slice(&self.ticket_ledger_root);
        out.extend_from_slice(&self.assignment_root);
        put_u32(&mut out, self.receipts.len() as u32);
        for receipt in &self.receipts {
            put_bytes(&mut out, &receipt.canonical_bytes());
        }
        put_u32(&mut out, self.unused_indices.len() as u32);
        for index in &self.unused_indices {
            put_u32(&mut out, *index);
        }
        out
    }

    pub fn digest(&self) -> Hash {
        domain_hash(BATCH_DIGEST_DOMAIN, &self.canonical_bytes())
    }
}

#[derive(Clone)]
struct ResolvedTicket {
    evidence: TicketEvidence,
    quantity: u32,
    leaf: Hash,
}

/// Validate, draw quantities, assign unique indices, and emit replayable
/// receipts. Input ticket order is ignored; canonical order is confirmed
/// height, transaction index, then ticket id.
pub fn allocate(
    policy: &AllocationPolicy,
    manifest: &[ManifestEntry],
    tickets: &[TicketEvidence],
    reveal: Option<&RevealEvidence>,
) -> Result<AllocationBatch, Error> {
    policy.validate()?;
    let manifest = validated_manifest(policy, manifest)?;
    let manifest_leaves: Vec<Hash> = manifest.iter().map(manifest_leaf).collect();
    let manifest_proofs = merkle_proofs(&manifest_leaves);
    let manifest_root = merkle_root(&manifest_leaves);
    if manifest_root != policy.manifest_root {
        return Err(Error::InvalidManifest("root does not match policy"));
    }

    let policy_digest = policy.digest()?;
    let mut ordered = tickets.to_vec();
    ordered.sort_by_key(|entry| {
        (
            entry.ticket.confirmed_height,
            entry.ticket.tx_index,
            entry.ticket.deposit_output_index,
            entry.ticket.ticket_id,
        )
    });
    validate_ticket_uniqueness(policy, policy_digest, &ordered)?;

    let mut resolved = Vec::with_capacity(ordered.len());
    let mut total = 0u64;
    // One drand round may resolve thousands of tickets. A valid BLS signature
    // is unique for a round, so verify it once per allocation replay and reject
    // conflicting bytes for that round.
    let mut beacon_cache = BTreeMap::new();
    for evidence in ordered {
        validate_identity_evidence(policy, &evidence)?;
        let quantity = resolve_quantity(policy, policy_digest, &evidence, &mut beacon_cache)?;
        total = total
            .checked_add(quantity as u64)
            .ok_or(Error::CapacityExceeded {
                requested: u64::MAX,
                supply: policy.supply,
            })?;
        let leaf = resolved_ticket_leaf(&evidence.ticket, quantity);
        resolved.push(ResolvedTicket {
            evidence,
            quantity,
            leaf,
        });
    }
    if total > policy.supply as u64 {
        return Err(Error::CapacityExceeded {
            requested: total,
            supply: policy.supply,
        });
    }

    let ledger_leaves: Vec<Hash> = resolved.iter().map(|ticket| ticket.leaf).collect();
    let ticket_ledger_root = merkle_root(&ledger_leaves);
    let mut remaining: Vec<u32> = (0..policy.supply).collect();

    match policy.identity {
        IdentityPolicy::Sequential => {
            if reveal.is_some() {
                return Err(Error::UnexpectedEvidence("sequential reveal"));
            }
        }
        IdentityPolicy::ConcealedShuffle => {
            let reveal = reveal.ok_or(Error::MissingEvidence("concealed reveal"))?;
            let randomness = verify_reveal(policy, reveal)?;
            let seed = concealed_seed(
                policy_digest,
                policy.manifest_root,
                ticket_ledger_root,
                reveal,
                randomness,
            )?;
            shuffle(&mut remaining, seed);
        }
        IdentityPolicy::InstantRandom => {
            if reveal.is_some() {
                return Err(Error::UnexpectedEvidence(
                    "collection reveal for instant policy",
                ));
            }
        }
    }

    let mut receipts = Vec::with_capacity(resolved.len());
    let mut cursor = 0usize;
    let mut prefix = Vec::new();
    for resolved_ticket in &resolved {
        let prefix_root = if policy.identity == IdentityPolicy::InstantRandom {
            prefix.push(resolved_ticket.leaf);
            merkle_root(&prefix)
        } else {
            ticket_ledger_root
        };
        let indices = match policy.identity {
            IdentityPolicy::Sequential | IdentityPolicy::ConcealedShuffle => {
                let end = cursor + resolved_ticket.quantity as usize;
                let picked = remaining[cursor..end].to_vec();
                cursor = end;
                picked
            }
            IdentityPolicy::InstantRandom => {
                let beacon = resolved_ticket
                    .evidence
                    .identity_beacon
                    .as_ref()
                    .ok_or(Error::MissingEvidence("ticket identity beacon"))?;
                let expected = resolved_ticket.evidence.ticket.identity_drand_round.ok_or(
                    Error::InvalidTicket("instant ticket has no identity target round"),
                )?;
                validate_future_round(policy, &resolved_ticket.evidence.ticket, expected)?;
                let randomness = verify_beacon_cached(beacon, expected, &mut beacon_cache)?;
                let seed = instant_seed(
                    policy_digest,
                    prefix_root,
                    &resolved_ticket.evidence.ticket,
                    beacon.round,
                    randomness,
                )?;
                let mut rng = ChaCha20Rng::from_seed(seed);
                let mut picked = Vec::with_capacity(resolved_ticket.quantity as usize);
                for _ in 0..resolved_ticket.quantity {
                    let at = uniform_below(&mut rng, remaining.len() as u64) as usize;
                    picked.push(remaining.swap_remove(at));
                }
                picked
            }
        };

        let mut items = Vec::with_capacity(indices.len());
        for index in indices {
            let entry = &manifest[index as usize];
            items.push(AllocatedItem {
                global_index: index,
                item_id: entry.item_id,
                content_hash: entry.content_hash,
                manifest_proof: manifest_proofs[index as usize].clone(),
            });
        }
        receipts.push(AllocationReceipt {
            ticket: resolved_ticket.evidence.ticket.clone(),
            quantity: resolved_ticket.quantity,
            slot_start: receipts
                .last()
                .map(|receipt: &AllocationReceipt| receipt.slot_start + receipt.quantity)
                .unwrap_or(0),
            items,
            policy_digest,
            manifest_root,
            ticket_ledger_root,
            identity_context: if policy.identity == IdentityPolicy::InstantRandom {
                prefix_root
            } else {
                ticket_ledger_root
            },
        });
    }

    let unused_indices = match policy.identity {
        IdentityPolicy::InstantRandom => remaining,
        IdentityPolicy::Sequential | IdentityPolicy::ConcealedShuffle => {
            remaining[cursor..].to_vec()
        }
    };
    let assignment_leaves: Vec<Hash> = receipts.iter().map(assignment_leaf).collect();

    Ok(AllocationBatch {
        policy_digest,
        manifest_root,
        ticket_ledger_root,
        assignment_root: merkle_root(&assignment_leaves),
        receipts,
        unused_indices,
    })
}

/// Full independent replay. This verifies all beacons again and compares every
/// receipt, proof, unused index, and commitment root.
pub fn verify_batch(
    policy: &AllocationPolicy,
    manifest: &[ManifestEntry],
    tickets: &[TicketEvidence],
    reveal: Option<&RevealEvidence>,
    expected: &AllocationBatch,
) -> Result<(), Error> {
    let replayed = allocate(policy, manifest, tickets, reveal)?;
    if &replayed == expected {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

pub fn manifest_root(collection_id: Hash, entries: &[ManifestEntry]) -> Result<Hash, Error> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|entry| entry.global_index);
    validate_manifest_entries(&sorted, sorted.len() as u32, collection_id)?;
    Ok(merkle_root(
        &sorted.iter().map(manifest_leaf).collect::<Vec<_>>(),
    ))
}

pub fn verify_allocated_item(item: &AllocatedItem, root: Hash) -> bool {
    let entry = ManifestEntry {
        global_index: item.global_index,
        item_id: item.item_id,
        content_hash: item.content_hash,
    };
    verify_proof(manifest_leaf(&entry), &item.manifest_proof, root)
}

pub fn verify_quicknet_beacon(beacon: &DrandBeacon) -> Result<Hash, Error> {
    verify_beacon(beacon, beacon.round)
}

fn resolve_quantity(
    policy: &AllocationPolicy,
    policy_digest: Hash,
    evidence: &TicketEvidence,
    beacon_cache: &mut BTreeMap<u64, (Vec<u8>, Hash)>,
) -> Result<u32, Error> {
    validate_ticket_shape(policy, policy_digest, &evidence.ticket)?;
    if evidence.ticket.confirmed_height > policy.deposit_close_zcash_height {
        return Err(Error::InvalidTicket(
            "deposit confirmed after the committed close height",
        ));
    }
    match &policy.quantity {
        QuantityPolicy::Fixed { items } => {
            reject_quantity_randomness(evidence)?;
            if evidence.ticket.requested_items.is_some() {
                return Err(Error::InvalidTicket(
                    "fixed ticket carries a requested quantity",
                ));
            }
            Ok(*items)
        }
        QuantityPolicy::BuyerChooses { minimum, maximum } => {
            reject_quantity_randomness(evidence)?;
            let requested = evidence.ticket.requested_items.ok_or(Error::InvalidTicket(
                "buyer-selected ticket has no quantity",
            ))?;
            if requested < *minimum || requested > *maximum {
                return Err(Error::InvalidTicket(
                    "buyer-selected quantity is outside policy",
                ));
            }
            Ok(requested)
        }
        QuantityPolicy::Weighted { outcomes } => {
            if evidence.ticket.requested_items.is_some() {
                return Err(Error::InvalidTicket(
                    "weighted ticket carries a requested quantity",
                ));
            }
            let expected = evidence
                .ticket
                .quantity_drand_round
                .ok_or(Error::InvalidTicket(
                    "weighted ticket has no quantity target round",
                ))?;
            validate_future_round(policy, &evidence.ticket, expected)?;
            let beacon = evidence
                .quantity_beacon
                .as_ref()
                .ok_or(Error::MissingEvidence("ticket quantity beacon"))?;
            let randomness = verify_beacon_cached(beacon, expected, beacon_cache)?;
            let seed = quantity_seed(policy_digest, &evidence.ticket, beacon.round, randomness)?;
            let mut rng = ChaCha20Rng::from_seed(seed);
            let mut sorted = outcomes.clone();
            sorted.sort_by_key(|outcome| outcome.items);
            let total = sorted.iter().try_fold(0u64, |sum, outcome| {
                sum.checked_add(outcome.weight)
                    .ok_or(Error::InvalidPolicy("weight sum overflows u64"))
            })?;
            let draw = uniform_below(&mut rng, total);
            let mut cursor = 0u64;
            for outcome in sorted {
                cursor += outcome.weight;
                if draw < cursor {
                    return Ok(outcome.items);
                }
            }
            Err(Error::DerivationFailed)
        }
    }
}

fn reject_quantity_randomness(evidence: &TicketEvidence) -> Result<(), Error> {
    if evidence.ticket.quantity_drand_round.is_some() || evidence.quantity_beacon.is_some() {
        return Err(Error::UnexpectedEvidence(
            "quantity randomness for non-random policy",
        ));
    }
    Ok(())
}

fn validate_identity_evidence(
    policy: &AllocationPolicy,
    evidence: &TicketEvidence,
) -> Result<(), Error> {
    match policy.identity {
        IdentityPolicy::InstantRandom => {
            if evidence.ticket.identity_drand_round.is_none() {
                return Err(Error::InvalidTicket(
                    "instant ticket has no identity target round",
                ));
            }
            if evidence.identity_beacon.is_none() {
                return Err(Error::MissingEvidence("ticket identity beacon"));
            }
        }
        IdentityPolicy::ConcealedShuffle | IdentityPolicy::Sequential => {
            if evidence.ticket.identity_drand_round.is_some() || evidence.identity_beacon.is_some()
            {
                return Err(Error::UnexpectedEvidence(
                    "per-ticket identity randomness for collection policy",
                ));
            }
        }
    }
    Ok(())
}

fn validated_manifest(
    policy: &AllocationPolicy,
    entries: &[ManifestEntry],
) -> Result<Vec<ManifestEntry>, Error> {
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|entry| entry.global_index);
    validate_manifest_entries(&sorted, policy.supply, policy.collection_id)?;
    Ok(sorted)
}

fn validate_manifest_entries(
    entries: &[ManifestEntry],
    expected: u32,
    collection_id: Hash,
) -> Result<(), Error> {
    if entries.len() != expected as usize {
        return Err(Error::InvalidManifest("entry count does not equal supply"));
    }
    let mut item_ids = BTreeSet::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.global_index != index as u32 {
            return Err(Error::InvalidManifest(
                "indices are not contiguous from zero",
            ));
        }
        if entry.item_id == [0; 32] || entry.content_hash == [0; 32] {
            return Err(Error::InvalidManifest(
                "entry contains a zero identity or content hash",
            ));
        }
        let canonical = zyn_vm::item_address(
            zyn_vm::derive::ADDRESS_SCOPE_V1,
            &collection_id,
            entry.global_index,
        );
        if entry.item_id != canonical {
            return Err(Error::InvalidManifest(
                "item id is not canonical for collection and index",
            ));
        }
        if !item_ids.insert(entry.item_id) {
            return Err(Error::InvalidManifest("item id is duplicated"));
        }
    }
    Ok(())
}

fn validate_ticket_shape(
    policy: &AllocationPolicy,
    policy_digest: Hash,
    ticket: &Ticket,
) -> Result<(), Error> {
    if ticket.ticket_id == [0; 32] || ticket.deposit_txid == [0; 32] {
        return Err(Error::InvalidTicket("ticket or deposit id is zero"));
    }
    if ticket.recipient == [0; 32] {
        return Err(Error::InvalidTicket("recipient is zero"));
    }
    if ticket.deposit_amount_zatoshi != policy.entry_price_zatoshi {
        return Err(Error::InvalidTicket(
            "deposit amount does not equal committed entry price",
        ));
    }
    if ticket.ticket_id != derive_ticket_id(policy_digest, ticket) {
        return Err(Error::InvalidTicket(
            "ticket id does not match all committed ticket fields",
        ));
    }
    Ok(())
}

fn validate_ticket_uniqueness(
    policy: &AllocationPolicy,
    policy_digest: Hash,
    tickets: &[TicketEvidence],
) -> Result<(), Error> {
    let mut ids = BTreeSet::new();
    let mut outputs = BTreeSet::new();
    let mut positions = BTreeSet::new();
    for evidence in tickets {
        validate_ticket_shape(policy, policy_digest, &evidence.ticket)?;
        if !ids.insert(evidence.ticket.ticket_id) {
            return Err(Error::InvalidTicket("ticket id is duplicated"));
        }
        if !outputs.insert((
            evidence.ticket.deposit_txid,
            evidence.ticket.deposit_output_index,
        )) {
            return Err(Error::InvalidTicket("deposit output is duplicated"));
        }
        if !positions.insert((
            evidence.ticket.confirmed_height,
            evidence.ticket.tx_index,
            evidence.ticket.deposit_output_index,
        )) {
            return Err(Error::InvalidTicket(
                "two deposits claim the same output position",
            ));
        }
    }
    Ok(())
}

fn validate_future_round(
    policy: &AllocationPolicy,
    ticket: &Ticket,
    target: u64,
) -> Result<(), Error> {
    let earliest = ticket
        .issued_at_drand_round
        .checked_add(policy.randomness.ticket_round_delay)
        .ok_or(Error::InvalidTicket("future drand round overflows"))?;
    if target < earliest {
        return Err(Error::InvalidTicket(
            "drand target was not committed far enough ahead",
        ));
    }
    Ok(())
}

fn verify_beacon(beacon: &DrandBeacon, expected_round: u64) -> Result<Hash, Error> {
    if beacon.chain_hash != QUICKNET_CHAIN_HASH {
        return Err(Error::WrongDrandChain);
    }
    if beacon.round != expected_round {
        return Err(Error::WrongDrandRound {
            expected: expected_round,
            got: beacon.round,
        });
    }
    let public_key =
        G2PubkeyRfc::from_fixed(QUICKNET_PUBLIC_KEY).map_err(|_| Error::InvalidDrandPublicKey)?;
    let valid = public_key
        .verify(beacon.round, b"", &beacon.signature)
        .map_err(|_| Error::InvalidDrandBeacon)?;
    if !valid {
        return Err(Error::InvalidDrandBeacon);
    }
    Ok(derive_randomness(&beacon.signature))
}

fn verify_beacon_cached(
    beacon: &DrandBeacon,
    expected_round: u64,
    cache: &mut BTreeMap<u64, (Vec<u8>, Hash)>,
) -> Result<Hash, Error> {
    if beacon.chain_hash != QUICKNET_CHAIN_HASH {
        return Err(Error::WrongDrandChain);
    }
    if beacon.round != expected_round {
        return Err(Error::WrongDrandRound {
            expected: expected_round,
            got: beacon.round,
        });
    }
    if let Some((signature, randomness)) = cache.get(&beacon.round) {
        if signature == &beacon.signature {
            return Ok(*randomness);
        }
        return Err(Error::InvalidDrandBeacon);
    }
    let randomness = verify_beacon(beacon, expected_round)?;
    cache.insert(beacon.round, (beacon.signature.clone(), randomness));
    Ok(randomness)
}

fn verify_reveal(policy: &AllocationPolicy, reveal: &RevealEvidence) -> Result<Hash, Error> {
    let round = policy
        .randomness
        .reveal_drand_round
        .ok_or(Error::InvalidPolicy("concealed reveal round is absent"))?;
    let height = policy
        .randomness
        .reveal_zcash_height
        .ok_or(Error::InvalidPolicy("concealed Zcash height is absent"))?;
    if reveal.zcash_height != height {
        return Err(Error::WrongRevealHeight {
            expected: height,
            got: reveal.zcash_height,
        });
    }
    if reveal.zcash_block_hash == [0; 32] {
        return Err(Error::MissingEvidence("Zcash reveal block hash"));
    }
    verify_beacon(&reveal.beacon, round)
}

fn quantity_seed(
    policy_digest: Hash,
    ticket: &Ticket,
    round: u64,
    randomness: Hash,
) -> Result<Hash, Error> {
    let mut input = Vec::new();
    input.extend_from_slice(&randomness);
    put_u64(&mut input, round);
    input.extend_from_slice(&ticket.ticket_id);
    input.extend_from_slice(&ticket.deposit_txid);
    put_u32(&mut input, ticket.confirmed_height);
    put_u32(&mut input, ticket.tx_index);
    hkdf_seed(policy_digest, &input, QUANTITY_INFO)
}

fn concealed_seed(
    policy_digest: Hash,
    manifest_root: Hash,
    ledger_root: Hash,
    reveal: &RevealEvidence,
    randomness: Hash,
) -> Result<Hash, Error> {
    let mut input = Vec::new();
    input.extend_from_slice(&randomness);
    put_u64(&mut input, reveal.beacon.round);
    input.extend_from_slice(&reveal.zcash_block_hash);
    put_u32(&mut input, reveal.zcash_height);
    input.extend_from_slice(&manifest_root);
    input.extend_from_slice(&ledger_root);
    hkdf_seed(policy_digest, &input, CONCEALED_INFO)
}

fn instant_seed(
    policy_digest: Hash,
    prefix_root: Hash,
    ticket: &Ticket,
    round: u64,
    randomness: Hash,
) -> Result<Hash, Error> {
    let mut input = Vec::new();
    input.extend_from_slice(&randomness);
    put_u64(&mut input, round);
    input.extend_from_slice(&ticket.ticket_id);
    input.extend_from_slice(&ticket.deposit_txid);
    input.extend_from_slice(&prefix_root);
    hkdf_seed(policy_digest, &input, INSTANT_INFO)
}

fn hkdf_seed(salt: Hash, input: &[u8], info: &[u8]) -> Result<Hash, Error> {
    let hk = Hkdf::<Sha256>::new(Some(&salt), input);
    let mut output = [0u8; 32];
    hk.expand(info, &mut output)
        .map_err(|_| Error::DerivationFailed)?;
    Ok(output)
}

fn uniform_below(rng: &mut impl RngCore, upper: u64) -> u64 {
    debug_assert!(upper > 0);
    // 2^64 mod upper. Values below this threshold are discarded so the
    // remaining interval contains an exact number of complete modulo buckets.
    let threshold = upper.wrapping_neg() % upper;
    loop {
        let value = rng.next_u64();
        if value >= threshold {
            return value % upper;
        }
    }
}

fn shuffle(values: &mut [u32], seed: Hash) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    for end in (1..values.len()).rev() {
        let other = uniform_below(&mut rng, (end + 1) as u64) as usize;
        values.swap(end, other);
    }
}

fn manifest_leaf(entry: &ManifestEntry) -> Hash {
    let mut bytes = Vec::new();
    put_u32(&mut bytes, entry.global_index);
    bytes.extend_from_slice(&entry.item_id);
    bytes.extend_from_slice(&entry.content_hash);
    domain_hash(MANIFEST_LEAF_DOMAIN, &bytes)
}

fn resolved_ticket_leaf(ticket: &Ticket, quantity: u32) -> Hash {
    let mut bytes = Vec::new();
    put_ticket(&mut bytes, ticket);
    put_u32(&mut bytes, quantity);
    domain_hash(TICKET_LEAF_DOMAIN, &bytes)
}

fn put_ticket(out: &mut Vec<u8>, ticket: &Ticket) {
    out.extend_from_slice(&ticket.ticket_id);
    put_ticket_body(out, ticket);
}

fn put_ticket_body(out: &mut Vec<u8>, ticket: &Ticket) {
    out.extend_from_slice(&ticket.deposit_txid);
    put_u32(out, ticket.deposit_output_index);
    put_u64(out, ticket.deposit_amount_zatoshi);
    out.extend_from_slice(&ticket.recipient);
    put_u32(out, ticket.confirmed_height);
    put_u32(out, ticket.tx_index);
    put_u64(out, ticket.issued_at_drand_round);
    put_opt_u64(out, ticket.quantity_drand_round);
    put_opt_u64(out, ticket.identity_drand_round);
    put_opt_u32(out, ticket.requested_items);
}

/// Derive the only valid ticket identity for a deposit output and recipient.
/// The policy digest prevents the same payment reference being replayed into a
/// different collection or sale policy.
pub fn derive_ticket_id(policy_digest: Hash, ticket: &Ticket) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&policy_digest);
    put_ticket_body(&mut bytes, ticket);
    domain_hash(TICKET_ID_DOMAIN, &bytes)
}

fn assignment_leaf(receipt: &AllocationReceipt) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&receipt.ticket.ticket_id);
    put_u32(&mut bytes, receipt.slot_start);
    put_u32(&mut bytes, receipt.quantity);
    for item in &receipt.items {
        put_u32(&mut bytes, item.global_index);
        bytes.extend_from_slice(&item.item_id);
        bytes.extend_from_slice(&item.content_hash);
    }
    domain_hash(ASSIGNMENT_LEAF_DOMAIN, &bytes)
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Hash {
    let mut hash = Sha256::new();
    put_hash_bytes(&mut hash, domain);
    put_hash_bytes(&mut hash, payload);
    hash.finalize().into()
}

fn put_hash_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_opt_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            put_u32(out, value);
        }
        None => {
            out.push(0);
            put_u32(out, 0);
        }
    }
}

fn put_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            put_u64(out, value);
        }
        None => {
            out.push(0);
            put_u64(out, 0);
        }
    }
}

fn hash_node(left: Hash, right: Hash) -> Hash {
    let mut hash = Sha256::new();
    hash.update([1]);
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return [0; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index + 1 < level.len() {
            next.push(hash_node(level[index], level[index + 1]));
            index += 2;
        }
        if index < level.len() {
            next.push(level[index]);
        }
        level = next;
    }
    level[0]
}

fn merkle_proofs(leaves: &[Hash]) -> Vec<Vec<ProofStep>> {
    if leaves.is_empty() {
        return Vec::new();
    }
    let mut levels = vec![leaves.to_vec()];
    while levels.last().unwrap().len() > 1 {
        let level = levels.last().unwrap();
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut cursor = 0;
        while cursor + 1 < level.len() {
            next.push(hash_node(level[cursor], level[cursor + 1]));
            cursor += 2;
        }
        if cursor < level.len() {
            next.push(level[cursor]);
        }
        levels.push(next);
    }

    (0..leaves.len())
        .map(|index| {
            let mut proof = Vec::new();
            let mut at = index;
            for level in levels.iter().take(levels.len() - 1) {
                if at % 2 == 0 && at + 1 < level.len() {
                    proof.push(ProofStep {
                        sibling: level[at + 1],
                        node_is_right: false,
                    });
                } else if at % 2 == 1 {
                    proof.push(ProofStep {
                        sibling: level[at - 1],
                        node_is_right: true,
                    });
                }
                at /= 2;
            }
            proof
        })
        .collect()
}

fn verify_proof(mut leaf: Hash, proof: &[ProofStep], root: Hash) -> bool {
    for step in proof {
        leaf = if step.node_is_right {
            hash_node(step.sibling, leaf)
        } else {
            hash_node(leaf, step.sibling)
        };
    }
    leaf == root
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_COLLECTION: Hash = [7; 32];

    fn quicknet_round_42() -> DrandBeacon {
        DrandBeacon {
            chain_hash: QUICKNET_CHAIN_HASH,
            round: 42,
            signature: hex::decode("95a9f9f5b231b7714de1553105d8ffdf3dcda24cfdb1e689319bccf79a9c8ce430a91b811fbfaf763900bc998b5d686a").unwrap(),
        }
    }

    fn manifest(collection_id: Hash, size: u32) -> Vec<ManifestEntry> {
        (0..size)
            .map(|index| ManifestEntry {
                global_index: index,
                item_id: zyn_vm::item_address(
                    zyn_vm::derive::ADDRESS_SCOPE_V1,
                    &collection_id,
                    index,
                ),
                content_hash: domain_hash(b"test-content", &index.to_be_bytes()),
            })
            .collect()
    }

    fn weighted_policy(size: u32) -> AllocationPolicy {
        let entries = manifest(TEST_COLLECTION, size);
        AllocationPolicy {
            collection_id: TEST_COLLECTION,
            supply: size,
            entry_price_zatoshi: 1_000_000,
            deposit_close_zcash_height: 2_899_900,
            quantity: QuantityPolicy::Weighted {
                outcomes: vec![
                    WeightedOutcome {
                        items: 3,
                        weight: 100,
                    },
                    WeightedOutcome {
                        items: 1,
                        weight: 8_000,
                    },
                    WeightedOutcome {
                        items: 2,
                        weight: 1_900,
                    },
                ],
            },
            identity: IdentityPolicy::ConcealedShuffle,
            manifest_root: manifest_root(TEST_COLLECTION, &entries).unwrap(),
            randomness: RandomnessPlan {
                drand_chain_hash: QUICKNET_CHAIN_HASH,
                ticket_round_delay: 2,
                announced_close: None,
                reveal_drand_round: Some(42),
                reveal_zcash_height: Some(2_900_000),
            },
        }
    }

    fn ticket(policy: &AllocationPolicy, seed: u8) -> TicketEvidence {
        let deposit_txid = [seed.wrapping_add(80); 32];
        let deposit_output_index = seed as u32 % 2;
        let recipient = [seed.wrapping_add(160); 32];
        let mut ticket = Ticket {
            ticket_id: [0; 32],
            deposit_txid,
            deposit_output_index,
            deposit_amount_zatoshi: policy.entry_price_zatoshi,
            recipient,
            confirmed_height: 100 + seed as u32,
            tx_index: seed as u32,
            issued_at_drand_round: 40,
            quantity_drand_round: Some(42),
            identity_drand_round: None,
            requested_items: None,
        };
        ticket.ticket_id = derive_ticket_id(policy.digest().unwrap(), &ticket);
        TicketEvidence {
            ticket,
            quantity_beacon: Some(quicknet_round_42()),
            identity_beacon: None,
        }
    }

    fn reseal(policy: &AllocationPolicy, evidence: &mut TicketEvidence) {
        evidence.ticket.ticket_id = derive_ticket_id(policy.digest().unwrap(), &evidence.ticket);
    }

    fn reveal() -> RevealEvidence {
        RevealEvidence {
            beacon: quicknet_round_42(),
            zcash_height: 2_900_000,
            zcash_block_hash: [0x44; 32],
        }
    }

    #[test]
    fn the_official_quicknet_round_42_signature_verifies() {
        let randomness = verify_quicknet_beacon(&quicknet_round_42()).unwrap();
        assert_eq!(
            hex::encode(randomness),
            "8ada64bae5c6c0f5540a6a13af56e663240edfbd2c76ac6a8f27671eb7259ce3"
        );

        let mut altered = quicknet_round_42();
        altered.signature[0] ^= 1;
        assert_eq!(
            verify_quicknet_beacon(&altered),
            Err(Error::InvalidDrandBeacon)
        );
    }

    #[test]
    fn weighted_policy_is_canonical_and_not_tied_to_zero_through_ninety_nine() {
        let policy = weighted_policy(20);
        policy.validate().unwrap();
        let digest = policy.digest().unwrap();

        let mut reordered = policy.clone();
        if let QuantityPolicy::Weighted { outcomes } = &mut reordered.quantity {
            outcomes.reverse();
        }
        assert_eq!(reordered.digest().unwrap(), digest);
        assert_eq!(policy.maximum_receipt(), 3);
        assert_eq!(digest, reordered.digest().unwrap());
        assert_eq!(
            hex::encode(digest),
            "488795635f2c9651d0ae58d108c042a87f7008289cfaf9c18f8b0129895c2cd8"
        );
    }

    #[test]
    fn manifest_order_is_irrelevant_but_identity_and_index_are_committed() {
        let entries = manifest(TEST_COLLECTION, 9);
        let root = manifest_root(TEST_COLLECTION, &entries).unwrap();
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(manifest_root(TEST_COLLECTION, &reversed).unwrap(), root);

        let mut changed = entries;
        changed[3].content_hash[0] ^= 1;
        assert_ne!(manifest_root(TEST_COLLECTION, &changed).unwrap(), root);

        let mut wrong_id = manifest(TEST_COLLECTION, 9);
        wrong_id[3].item_id[0] ^= 1;
        assert_eq!(
            manifest_root(TEST_COLLECTION, &wrong_id),
            Err(Error::InvalidManifest(
                "item id is not canonical for collection and index"
            ))
        );
    }

    #[test]
    fn ticket_binds_policy_exact_output_payment_and_recipient() {
        let entries = manifest(TEST_COLLECTION, 4);
        let mut policy = weighted_policy(4);
        policy.quantity = QuantityPolicy::Fixed { items: 1 };
        policy.identity = IdentityPolicy::Sequential;
        policy.randomness.ticket_round_delay = 0;
        policy.randomness.reveal_drand_round = None;
        policy.randomness.reveal_zcash_height = None;

        let mut first = ticket(&policy, 1);
        first.ticket.quantity_drand_round = None;
        first.quantity_beacon = None;
        reseal(&policy, &mut first);

        let mut redirected = first.clone();
        redirected.ticket.recipient[0] ^= 1;
        assert_eq!(
            allocate(&policy, &entries, &[redirected], None),
            Err(Error::InvalidTicket(
                "ticket id does not match all committed ticket fields"
            ))
        );

        let mut underpaid = first.clone();
        underpaid.ticket.deposit_amount_zatoshi -= 1;
        assert_eq!(
            allocate(&policy, &entries, &[underpaid], None),
            Err(Error::InvalidTicket(
                "deposit amount does not equal committed entry price"
            ))
        );

        // A second output in the same transaction is a distinct ticket. Its
        // block transaction position is intentionally identical.
        let mut second = first.clone();
        second.ticket.deposit_output_index = first.ticket.deposit_output_index + 1;
        second.ticket.recipient = [0x55; 32];
        second.ticket.ticket_id = derive_ticket_id(policy.digest().unwrap(), &second.ticket);
        let batch = allocate(&policy, &entries, &[second, first], None).unwrap();
        assert_eq!(batch.receipts.len(), 2);
        assert_ne!(
            batch.receipts[0].ticket.recipient,
            batch.receipts[1].ticket.recipient
        );

        let mut free = policy;
        free.entry_price_zatoshi = 0;
        assert_eq!(
            free.validate(),
            Err(Error::InvalidPolicy("entry price is zero"))
        );
    }

    #[test]
    fn concealed_allocation_is_deterministic_unique_and_replayable() {
        let entries = manifest(TEST_COLLECTION, 20);
        let policy = weighted_policy(20);
        let tickets = vec![ticket(&policy, 3), ticket(&policy, 1), ticket(&policy, 2)];
        let batch = allocate(&policy, &entries, &tickets, Some(&reveal())).unwrap();
        let again = allocate(&policy, &entries, &tickets, Some(&reveal())).unwrap();
        assert_eq!(batch, again);
        assert_eq!(
            hex::encode(batch.digest()),
            "11696813b33cd8b85c8935a0f2bb70da30ddc31f4c8e1e05c05f95c61b2eafd4"
        );
        verify_batch(&policy, &entries, &tickets, Some(&reveal()), &batch).unwrap();

        let allocated: Vec<u32> = batch
            .receipts
            .iter()
            .flat_map(|receipt| receipt.items.iter().map(|item| item.global_index))
            .collect();
        assert_eq!(
            allocated.len(),
            allocated.iter().copied().collect::<BTreeSet<_>>().len()
        );
        assert!(batch
            .receipts
            .iter()
            .flat_map(|r| &r.items)
            .all(|item| { verify_allocated_item(item, batch.manifest_root) }));

        let mut other_reveal = reveal();
        other_reveal.zcash_block_hash[0] ^= 1;
        let other = allocate(&policy, &entries, &tickets, Some(&other_reveal)).unwrap();
        assert_ne!(batch.assignment_root, other.assignment_root);
    }

    #[test]
    fn fixed_and_buyer_selected_policies_need_no_quantity_randomness() {
        let entries = manifest(TEST_COLLECTION, 12);
        let mut fixed = weighted_policy(12);
        fixed.quantity = QuantityPolicy::Fixed { items: 2 };
        let mut evidence = ticket(&fixed, 1);
        evidence.ticket.quantity_drand_round = None;
        evidence.quantity_beacon = None;
        reseal(&fixed, &mut evidence);
        let fixed_batch = allocate(&fixed, &entries, &[evidence.clone()], Some(&reveal())).unwrap();
        assert_eq!(fixed_batch.receipts[0].quantity, 2);

        fixed.quantity = QuantityPolicy::BuyerChooses {
            minimum: 1,
            maximum: 4,
        };
        evidence = ticket(&fixed, 1);
        evidence.ticket.quantity_drand_round = None;
        evidence.quantity_beacon = None;
        evidence.ticket.requested_items = Some(4);
        evidence.ticket.ticket_id = derive_ticket_id(fixed.digest().unwrap(), &evidence.ticket);
        let buyer_batch = allocate(&fixed, &entries, &[evidence], Some(&reveal())).unwrap();
        assert_eq!(buyer_batch.receipts[0].quantity, 4);
    }

    #[test]
    fn instant_random_uses_ticket_beacons_and_never_duplicates_an_index() {
        let entries = manifest(TEST_COLLECTION, 12);
        let mut policy = weighted_policy(12);
        policy.quantity = QuantityPolicy::Fixed { items: 2 };
        policy.identity = IdentityPolicy::InstantRandom;
        policy.randomness.reveal_drand_round = None;
        policy.randomness.reveal_zcash_height = None;

        let mut tickets = vec![ticket(&policy, 2), ticket(&policy, 1), ticket(&policy, 3)];
        for evidence in &mut tickets {
            evidence.ticket.quantity_drand_round = None;
            evidence.quantity_beacon = None;
            evidence.ticket.identity_drand_round = Some(42);
            evidence.identity_beacon = Some(quicknet_round_42());
            reseal(&policy, evidence);
        }
        let batch = allocate(&policy, &entries, &tickets, None).unwrap();
        let assigned: BTreeSet<u32> = batch
            .receipts
            .iter()
            .flat_map(|receipt| receipt.items.iter().map(|item| item.global_index))
            .collect();
        assert_eq!(assigned.len(), 6);
        assert_eq!(batch.unused_indices.len(), 6);
        verify_batch(&policy, &entries, &tickets, None, &batch).unwrap();
    }

    #[test]
    fn capacity_and_future_round_fail_closed() {
        let entries = manifest(TEST_COLLECTION, 4);
        let mut policy = weighted_policy(4);
        policy.quantity = QuantityPolicy::Fixed { items: 3 };
        let mut first = ticket(&policy, 1);
        first.ticket.quantity_drand_round = None;
        first.quantity_beacon = None;
        reseal(&policy, &mut first);
        let mut second = ticket(&policy, 2);
        second.ticket.quantity_drand_round = None;
        second.quantity_beacon = None;
        reseal(&policy, &mut second);
        assert_eq!(
            allocate(&policy, &entries, &[first, second], Some(&reveal())),
            Err(Error::CapacityExceeded {
                requested: 6,
                supply: 4
            })
        );

        let policy = weighted_policy(4);
        let mut too_early = ticket(&policy, 1);
        too_early.ticket.quantity_drand_round = Some(41);
        too_early.quantity_beacon.as_mut().unwrap().round = 41;
        reseal(&policy, &mut too_early);
        assert!(matches!(
            allocate(&policy, &entries, &[too_early], Some(&reveal())),
            Err(Error::InvalidTicket(
                "drand target was not committed far enough ahead"
            ))
        ));

        let mut unused_identity = ticket(&policy, 2);
        unused_identity.ticket.identity_drand_round = Some(42);
        unused_identity.identity_beacon = Some(quicknet_round_42());
        reseal(&policy, &mut unused_identity);
        assert_eq!(
            allocate(&policy, &entries, &[unused_identity], Some(&reveal())),
            Err(Error::UnexpectedEvidence(
                "per-ticket identity randomness for collection policy"
            ))
        );
    }

    #[test]
    fn replay_rejects_tampered_receipts_and_public_evidence() {
        let entries = manifest(TEST_COLLECTION, 20);
        let policy = weighted_policy(20);
        let tickets = vec![ticket(&policy, 2), ticket(&policy, 1)];
        let reveal = reveal();
        let batch = allocate(&policy, &entries, &tickets, Some(&reveal)).unwrap();
        assert_eq!(batch.digest(), batch.clone().digest());
        assert_eq!(
            batch.receipts[0].digest(),
            batch.receipts[0].clone().digest()
        );

        let mut changed = batch.clone();
        changed.receipts[0].items[0].content_hash[0] ^= 1;
        assert_ne!(changed.digest(), batch.digest());
        assert_eq!(
            verify_batch(&policy, &entries, &tickets, Some(&reveal), &changed),
            Err(Error::VerificationFailed)
        );

        let mut wrong_height = reveal.clone();
        wrong_height.zcash_height += 1;
        assert!(matches!(
            allocate(&policy, &entries, &tickets, Some(&wrong_height)),
            Err(Error::WrongRevealHeight { .. })
        ));

        let mut wrong_chain = tickets.clone();
        wrong_chain[0].quantity_beacon.as_mut().unwrap().chain_hash[0] ^= 1;
        assert_eq!(
            allocate(&policy, &entries, &wrong_chain, Some(&reveal)),
            Err(Error::WrongDrandChain)
        );

        let mut late = tickets.clone();
        late[0].ticket.confirmed_height = policy.deposit_close_zcash_height + 1;
        reseal(&policy, &mut late[0]);
        assert_eq!(
            allocate(&policy, &entries, &late, Some(&reveal)),
            Err(Error::InvalidTicket(
                "deposit confirmed after the committed close height"
            ))
        );

        let mut unsafe_reveal = policy.clone();
        unsafe_reveal.randomness.reveal_zcash_height =
            Some(unsafe_reveal.deposit_close_zcash_height);
        assert_eq!(
            unsafe_reveal.validate(),
            Err(Error::InvalidPolicy(
                "concealed reveal height is not after deposit close"
            ))
        );
    }

    #[test]
    fn collection_z_scale_assigns_every_index_once() {
        let supply = 4_444;
        let entries = manifest(TEST_COLLECTION, supply);
        let mut policy = weighted_policy(supply);
        policy.quantity = QuantityPolicy::Fixed { items: 1 };

        let tickets: Vec<TicketEvidence> = (0..supply)
            .map(|number| {
                let deposit_txid = domain_hash(b"scale-deposit", &number.to_be_bytes());
                let recipient = domain_hash(b"scale-recipient", &number.to_be_bytes());
                let mut ticket = Ticket {
                    ticket_id: [0; 32],
                    deposit_txid,
                    deposit_output_index: 0,
                    deposit_amount_zatoshi: policy.entry_price_zatoshi,
                    recipient,
                    confirmed_height: 1_000 + number / 100,
                    tx_index: number % 100,
                    issued_at_drand_round: 40,
                    quantity_drand_round: None,
                    identity_drand_round: None,
                    requested_items: None,
                };
                ticket.ticket_id = derive_ticket_id(policy.digest().unwrap(), &ticket);
                TicketEvidence {
                    ticket,
                    quantity_beacon: None,
                    identity_beacon: None,
                }
            })
            .collect();

        let batch = allocate(&policy, &entries, &tickets, Some(&reveal())).unwrap();
        assert_eq!(batch.receipts.len(), supply as usize);
        assert!(batch.unused_indices.is_empty());
        let indices: BTreeSet<u32> = batch
            .receipts
            .iter()
            .map(|receipt| receipt.items[0].global_index)
            .collect();
        assert_eq!(indices, (0..supply).collect());
        assert!(batch
            .receipts
            .iter()
            .all(|receipt| { verify_allocated_item(&receipt.items[0], batch.manifest_root) }));
    }
}

#[cfg(test)]
mod announced_close_tests {
    use super::*;

    pub fn rule() -> AnnouncedClose {
        AnnouncedClose {
            // ~2 hours of mainnet blocks: past ordinary reorg depth, and not
            // long enough that buyers are left waiting on nothing.
            reveal_offset_blocks: 100,
            // Quicknet rounds are 3s, so ~2 hours ahead of the announcement.
            reveal_offset_rounds: 2_400,
            // A day of notice, so a close is something people can react to.
            min_notice_blocks: 1_152,
        }
    }

    pub fn policy() -> AllocationPolicy {
        AllocationPolicy {
            collection_id: [2; 32],
            supply: 4_444,
            entry_price_zatoshi: 1_000_000,
            // Zero: decided later, by watching demand.
            deposit_close_zcash_height: 0,
            // Collection Z's draw, recorded 9 Sep: 1 item 80%, 2 items 19%,
            // 3 items 1%.
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
                announced_close: Some(rule()),
            },
        }
    }

    /// A proof that agrees with what the announcement says about itself —
    /// the honest case. Tests that care about disagreement build their own.
    fn proof(a: &CloseAnnouncement) -> PublicationProof {
        PublicationProof {
            txid: a.digest(),
            height: a.announced_at_zcash_height,
        }
    }

    fn announce(p: &AllocationPolicy, at: u32, close: u32) -> CloseAnnouncement {
        CloseAnnouncement {
            policy_digest: p.digest().unwrap(),
            announced_at_zcash_height: at,
            announced_at_drand_round: 5_000_000,
            deposit_close_zcash_height: close,
        }
    }

    /// The shape the operator asked for: they decide three days or five by
    /// watching demand, and everything the outcome depends on follows.
    #[test]
    fn the_operator_picks_the_length_and_nothing_else() {
        let p = policy();
        p.validate().expect("an announced-close policy is valid with no close height");

        let three_days = announce(&p, 3_486_737, 3_486_737 + 3 * 1_152);
        let five_days = announce(&p, 3_486_737, 3_486_737 + 5 * 1_152);
        let a = three_days.resolve(&p, &proof(&three_days)).unwrap();
        let b = five_days.resolve(&p, &proof(&five_days)).unwrap();

        // Both legal, and in both the reveal is derived rather than chosen.
        assert_eq!(a.reveal_zcash_height, a.deposit_close_zcash_height + 100);
        assert_eq!(b.reveal_zcash_height, b.deposit_close_zcash_height + 100);
        assert_eq!(a.reveal_drand_round, 5_000_000 + 2_400);
        assert_ne!(a.deposit_close_zcash_height, b.deposit_close_zcash_height);
    }

    /// The attack the whole shape exists to prevent: naming a reveal target
    /// after seeing the ticket ledger, trying candidates until one produces a
    /// mapping you like. There is no field to put the answer in.
    #[test]
    fn an_announced_policy_cannot_also_name_its_reveal_targets() {
        let mut p = policy();
        p.randomness.reveal_zcash_height = Some(3_500_000);
        assert_eq!(
            p.validate(),
            Err(Error::InvalidPolicy(
                "an announced close derives its reveal targets; they cannot also be fixed"
            ))
        );
    }

    #[test]
    fn a_close_with_too_little_notice_is_refused() {
        let p = policy();
        let hasty = announce(&p, 3_486_737, 3_486_737 + 10);
        assert!(hasty.resolve(&p, &proof(&hasty)).is_err(), "ten blocks is not notice");
        // And a close already in the past is the same failure, not a special
        // case: it gives negative notice.
        let backdated = announce(&p, 3_486_737, 3_486_000);
        assert!(backdated.resolve(&p, &proof(&backdated)).is_err());
    }

    #[test]
    fn an_announcement_cannot_be_moved_between_sales() {
        let p = policy();
        let mut other = policy();
        other.collection_id = [9; 32];
        let a = announce(&p, 3_486_737, 3_486_737 + 3 * 1_152);
        assert!(a.resolve(&p, &proof(&a)).is_ok());
        assert_eq!(
            a.resolve(&other, &proof(&a)),
            Err(Error::InvalidTicket("announcement is for another policy"))
        );
    }

    /// Committing a close *and* announcing one is a contradiction, and the two
    /// forms must not silently coexist with one quietly winning.
    #[test]
    fn a_policy_is_one_form_or_the_other() {
        let mut p = policy();
        p.deposit_close_zcash_height = 3_500_000;
        assert!(p.validate().is_err());

        // And the committed form still works exactly as it did.
        let mut fixed = policy();
        fixed.deposit_close_zcash_height = 3_500_000;
        fixed.randomness.announced_close = None;
        fixed.randomness.reveal_zcash_height = Some(3_500_100);
        fixed.randomness.reveal_drand_round = Some(5_002_400);
        fixed.validate().expect("the committed form is unchanged");
    }

    #[test]
    fn a_rule_that_reveals_at_the_close_is_refused() {
        let mut p = policy();
        p.randomness.announced_close = Some(AnnouncedClose {
            reveal_offset_blocks: 0,
            ..rule()
        });
        assert!(p.validate().is_err(), "a reveal at the close uses a block that already existed");
    }

    /// The point of the proof: an announcement written after the fact, claiming
    /// to have been made earlier so that a short notice looks long, is refused
    /// by the block that actually carries it.
    #[test]
    fn a_backdated_claim_fails_against_the_block_that_carries_it() {
        let p = policy();
        // Claims to have been announced a day earlier than it really was.
        let a = announce(&p, 3_486_737, 3_486_737 + 1_152);
        let truth = PublicationProof {
            txid: a.digest(),
            height: 3_486_737 + 1_000,
        };
        assert_eq!(
            a.resolve(&p, &truth),
            Err(Error::InvalidTicket(
                "the announcement claims a different height than the block that carries it"
            ))
        );
        // And with an honest proof the same announcement is fine, so the
        // refusal is about the disagreement and not about the notice.
        assert!(a.resolve(&p, &proof(&a)).is_ok());
    }

    /// The announcement's digest must cover everything that could change the
    /// outcome, or a published announcement could be restated differently.
    #[test]
    fn every_field_moves_the_announcement_digest() {
        let p = policy();
        let base = announce(&p, 3_486_737, 3_486_737 + 3 * 1_152);
        let d = base.digest();
        for mutate in [
            |a: &mut CloseAnnouncement| a.announced_at_zcash_height += 1,
            |a: &mut CloseAnnouncement| a.announced_at_drand_round += 1,
            |a: &mut CloseAnnouncement| a.deposit_close_zcash_height += 1,
            |a: &mut CloseAnnouncement| a.policy_digest[0] ^= 1,
        ] {
            let mut m = base.clone();
            mutate(&mut m);
            assert_ne!(m.digest(), d);
        }
    }
}

#[cfg(test)]
mod terms_tests {
    use super::*;
    use super::announced_close_tests::policy;

    fn terms(p: &AllocationPolicy) -> SaleTerms {
        SaleTerms {
            policy_digest: p.digest().unwrap(),
            collection_id: p.collection_id,
            manifest_root: p.manifest_root,
            treasury: [0xa7; 32],
            network: 0,
            entry_price_zatoshi: 1_000_000,
            claim_price_zatoshi: 500_000,
            open_mint_price_zatoshi: 1_330_000,
            min_confirmations: 6,
            claim_window_blocks: 20_000,
            treasury_bps: 1_000,
        }
    }

    #[test]
    fn terms_bind_to_their_policy_and_refuse_another() {
        let p = policy();
        let t = terms(&p);
        t.check(&p).unwrap();
        let mut other = policy();
        other.collection_id = [9; 32];
        assert!(t.check(&other).is_err());
    }

    #[test]
    fn terms_that_contradict_the_policy_are_refused() {
        let p = policy();
        let mut t = terms(&p);
        t.entry_price_zatoshi = 2_000_000;
        assert!(t.check(&p).is_err(), "two documents, two prices");
        let mut t = terms(&p);
        t.manifest_root = [1; 32];
        assert!(t.check(&p).is_err());
    }

    /// The split is the floor, so rounding goes to the pool and a treasury
    /// taking everything is refused outright.
    #[test]
    fn the_split_favours_the_pool_and_cannot_take_everything() {
        let p = policy();
        let t = terms(&p);
        let (pool, treasury) = t.split(1_000_000);
        assert_eq!((pool, treasury), (900_000, 100_000));
        // A payment that does not divide evenly leaves the remainder behind the
        // items rather than in the treasury.
        let (pool, treasury) = t.split(7);
        assert_eq!((pool, treasury), (7, 0));
        assert_eq!(pool + treasury, 7, "nothing is created or lost");

        let mut greedy = t;
        greedy.treasury_bps = 10_000;
        assert!(greedy.check(&p).is_err());
    }

    #[test]
    fn a_zero_price_confirmation_or_window_is_refused() {
        let p = policy();
        for mutate in [
            |t: &mut SaleTerms| t.claim_price_zatoshi = 0,
            |t: &mut SaleTerms| t.open_mint_price_zatoshi = 0,
            |t: &mut SaleTerms| t.min_confirmations = 0,
            |t: &mut SaleTerms| t.claim_window_blocks = 0,
            |t: &mut SaleTerms| t.treasury = [0; 32],
            |t: &mut SaleTerms| t.network = 7,
        ] {
            let mut m = terms(&p);
            mutate(&mut m);
            assert!(m.check(&p).is_err());
        }
    }

    /// Every field must move the digest, or something a buyer is trusting
    /// could be changed after publication without the reference changing.
    #[test]
    fn every_field_moves_the_terms_digest() {
        let p = policy();
        let base = terms(&p);
        let d = base.digest();
        for mutate in [
            |t: &mut SaleTerms| t.policy_digest[0] ^= 1,
            |t: &mut SaleTerms| t.collection_id[0] ^= 1,
            |t: &mut SaleTerms| t.manifest_root[0] ^= 1,
            |t: &mut SaleTerms| t.treasury[0] ^= 1,
            |t: &mut SaleTerms| t.network = 1,
            |t: &mut SaleTerms| t.entry_price_zatoshi += 1,
            |t: &mut SaleTerms| t.claim_price_zatoshi += 1,
            |t: &mut SaleTerms| t.open_mint_price_zatoshi += 1,
            |t: &mut SaleTerms| t.min_confirmations += 1,
            |t: &mut SaleTerms| t.claim_window_blocks += 1,
            |t: &mut SaleTerms| t.treasury_bps += 1,
        ] {
            let mut m = base;
            mutate(&mut m);
            assert_ne!(m.digest(), d);
        }
    }
}
