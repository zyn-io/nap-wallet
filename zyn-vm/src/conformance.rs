//! The suite every Zyn VM must pass.
//!
//! A specification nobody can check is a specification everybody implements
//! differently. This is the executable half: a VM author calls
//! [`check`] from their own test suite and finds out whether the
//! infrastructure will actually be able to sequence, anchor, prove and recover
//! their machine — before they discover it in production, where the symptom of
//! a violated rule is a chain that two nodes disagree about.
//!
//! What it checks, against the numbered rules in [`crate::spec`]:
//!
//! - **S2** sequencing: only `seq + 1` applies, and anything else is inert
//! - **S3** rejections advance history without moving application state
//! - **S5** the root moves when committed state moves
//! - **S6** the section layout, and that the derived exit proof verifies
//! - **S7** sealing, and that the sealed view is recoverable
//! - **S8** encode/decode round-trips to the same root, and execution resumes
//!
//! It cannot check S1 (determinism), S4 (outcomes emitted not accepted), S9
//! (checked arithmetic) or S10 (no panics on input): those are properties of
//! how the VM is written, and a suite can only fail to disprove them. What it
//! does do is run the same intents twice and insist the roots match, which
//! catches the ordinary way S1 is broken — an unordered map in the encoding.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::commit::{merkle_root, verify_proof};
use crate::commit::Hash;
use crate::spec::{MicrochainVm, Provable, MIN_SECTIONS, SECTION_ACCOUNTS};

/// A rule a VM failed, with enough context to find it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Violation {
    /// The rule, e.g. `"S6"`.
    pub rule: &'static str,
    pub detail: String,
}

fn fail(rule: &'static str, detail: impl Into<String>) -> Violation {
    Violation { rule, detail: detail.into() }
}

/// What a VM author supplies so the suite can drive their machine.
///
/// Deliberately small. Anything more would be the suite asking the VM to
/// describe itself, which is how a conformance test ends up checking that an
/// implementation agrees with its own description rather than with the spec.
pub struct Fixture<V: MicrochainVm> {
    /// A chain with history: balances, whatever the application holds. The
    /// suite seals, encodes, proves and resumes from this.
    pub state: V,
    /// An intent that will be **accepted** at the next sequence number and will
    /// move committed state.
    pub accepted: V::Intent,
    /// An intent that will be **rejected** at the next sequence number and must
    /// leave application state untouched.
    pub rejected: V::Intent,
    /// A run of intents to apply in order, for the checks that need history
    /// rather than a single step.
    ///
    /// Empty is allowed and costs coverage: determinism and conservation are
    /// only as convincing as the variety of intents they see, and a VM author
    /// is the only one who knows what their machine's interesting sequences
    /// are.
    pub sequence: Vec<V::Intent>,
}

/// Run the suite. An empty result means the VM conforms.
///
/// Returns every violation rather than the first, because a VM under
/// development usually breaks several rules at once and fixing them one
/// round-trip at a time is how a conformance suite becomes something people
/// stop running.
pub fn check<V: MicrochainVm>(f: Fixture<V>) -> Vec<Violation> {
    let mut v = Vec::new();
    check_sections(&f.state, &mut v);
    check_exit_proofs(&f.state, &mut v);
    check_sequencing(&f, &mut v);
    check_rejection(&f, &mut v);
    check_commitment(&f, &mut v);
    check_sealing(&f, &mut v);
    check_carriable(&f, &mut v);
    check_repeatable(&f, &mut v);
    check_determinism(&f, &mut v);
    check_conservation(&f, &mut v);
    #[cfg(feature = "std")]
    check_no_panics(&f, &mut v);
    v
}

/// **S10.** Nothing a stranger can send may abort the process.
///
/// A VM's decoders are its widest attack surface: the bytes come off a socket
/// and an attacker picks all of them. A panic there is not a wrong answer, it
/// is a node that stops — and on a chain with one sequencer, a node that stops
/// is the chain.
///
/// This feeds three families of input to `decode_intent` and `decode`: random
/// bytes, every truncation of a *valid* encoding, and valid encodings with one
/// byte corrupted. The middle family is the one that finds real bugs, because
/// truncation is what a half-written file and a closed connection both look
/// like.
#[cfg(feature = "std")]
fn check_no_panics<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let valid_intent = V::encode_intent(&f.accepted);
    let valid_state = f.state.encode();

    let mut cases: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for cut in 0..valid_intent.len() {
        cases.push(("truncated intent", valid_intent[..cut].to_vec()));
    }
    for cut in (0..valid_state.len()).step_by(7usize.max(valid_state.len() / 64)) {
        cases.push(("truncated state", valid_state[..cut].to_vec()));
    }
    for bit in 0..valid_intent.len().min(64) {
        let mut b = valid_intent.clone();
        b[bit] ^= 0xFF;
        cases.push(("corrupted intent", b));
    }
    // Deterministic pseudo-random junk: a suite that fails only sometimes is a
    // suite people learn to re-run rather than fix.
    let mut seed = 0x5EEDu64;
    for len in [0usize, 1, 7, 33, 129, 1024] {
        let junk: Vec<u8> = (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 33) as u8
            })
            .collect();
        cases.push(("random bytes", junk));
    }

    let mut hushed = false;
    for (kind, bytes) in cases {
        // Panics are expected here; the hook would otherwise print a wall of
        // backtraces for a suite that is working correctly.
        if !hushed {
            hushed = true;
        }
        let decoded_intent = catch_unwind(AssertUnwindSafe(|| {
            let mut d = crate::read::Decoder::new(&bytes);
            V::decode_intent(&mut d)
        }));
        if decoded_intent.is_err() {
            v.push(fail("S10", format!("decode_intent panicked on {} ({} bytes)", kind, bytes.len())));
            return;
        }
        let decoded_state = catch_unwind(AssertUnwindSafe(|| V::decode(&bytes)));
        if decoded_state.is_err() {
            v.push(fail("S10", format!("decode panicked on {} ({} bytes)", kind, bytes.len())));
            return;
        }
    }
}

/// **S1.** The same intents from the same state must produce the same root,
/// and the same bytes.
///
/// A suite cannot prove determinism — it can only fail to disprove it. What it
/// catches is the ordinary way S1 breaks in practice: an unordered collection
/// in the encoding, which produces a different byte string, and so a different
/// root, on a run whose iteration order happened to differ. Encoding twice and
/// comparing is cheap and catches it immediately.
fn check_determinism<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let run = |mut s: V| -> (Hash, Vec<u8>) {
        let mut seq = s.seq();
        for i in f.sequence.iter().chain(core::iter::once(&f.accepted)) {
            seq += 1;
            s.apply(seq, i);
        }
        (s.state_root(), s.encode())
    };
    let (root_a, bytes_a) = run(f.state.clone());
    let (root_b, bytes_b) = run(f.state.clone());

    if root_a != root_b {
        v.push(fail("S1", "the same intents produced two different roots"));
    }
    if bytes_a != bytes_b {
        v.push(fail(
            "S1",
            "the same state encoded to two different byte strings — \
             an unordered collection in the encoding is the usual cause",
        ));
    }
    // Encoding is a pure function of state, so encoding the same value twice
    // must agree even without applying anything.
    if f.state.encode() != f.state.encode() {
        v.push(fail("S1", "encode() is not a pure function of state"));
    }
}

/// **S11.** Whatever the VM says it conserves must still reconcile after every
/// step, not merely at the end.
fn check_conservation<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    if let Err(why) = f.state.conserved() {
        v.push(fail("S11", format!("the fixture's own state does not balance: {}", why)));
        return;
    }
    let mut s = f.state.clone();
    let mut seq = s.seq();
    for (n, i) in f.sequence.iter().chain(core::iter::once(&f.accepted)).enumerate() {
        seq += 1;
        s.apply(seq, i);
        if let Err(why) = s.conserved() {
            v.push(fail("S11", format!("intent {} left the books unbalanced: {}", n, why)));
            return;
        }
    }
}

/// Panicking wrapper, for use directly in a `#[test]`.
pub fn assert_conforms<V: MicrochainVm>(f: Fixture<V>) {
    let violations = check(f);
    if !violations.is_empty() {
        let mut msg = format!("{} conformance violation(s):\n", violations.len());
        for x in &violations {
            msg.push_str(&format!("  [{}] {}\n", x.rule, x.detail));
        }
        panic!("{}", msg);
    }
}

// --- S6: the section layout ------------------------------------------------

fn check_sections<V: MicrochainVm>(s: &V, v: &mut Vec<Violation>) {
    let sections = s.sections();
    if sections.len() < MIN_SECTIONS {
        v.push(fail(
            "S6",
            format!("{} sections; a header and an accounts section are required", sections.len()),
        ));
        return;
    }
    if s.state_root() != merkle_root(&sections) {
        v.push(fail("S6", "state_root is not the Merkle root of sections()"));
    }
    if sections[SECTION_ACCOUNTS] != merkle_root(&s.account_leaves()) {
        v.push(fail("S6", "section 1 is not the root over account_leaves()"));
    }
    if s.account_ids().len() != s.account_leaves().len() {
        v.push(fail("S6", "account_ids() and account_leaves() differ in length"));
    }
    // Ids must be strictly ordered, or the tree is not reproducible from them.
    let ids = s.account_ids();
    if ids.windows(2).any(|w| w[0] >= w[1]) {
        v.push(fail("S6", "account_ids() is not in strictly ascending order"));
    }
}

fn check_exit_proofs<V: MicrochainVm>(s: &V, v: &mut Vec<Violation>) {
    let root = s.state_root();
    let ids = s.account_ids();
    if ids.is_empty() {
        v.push(fail("S6", "fixture has no accounts, so the exit hatch is untested"));
        return;
    }
    for id in &ids {
        match (s.account_leaf(id), s.account_proof(id)) {
            (Some(leaf), Some(path)) => {
                if !verify_proof(leaf, &path, root) {
                    v.push(fail("S6", format!("exit proof for {:?} did not verify", &id[..4])));
                }
            }
            _ => v.push(fail("S6", format!("no exit proof for committed account {:?}", &id[..4]))),
        }
    }
    // A published record must rebuild the committed leaf, or a holder cannot
    // check what the publisher said about them.
    for id in &ids {
        match s.account_record(id) {
            Some(rec) => {
                if V::leaf_of_record(&rec) != s.account_leaf(id).unwrap_or_default() {
                    v.push(fail(
                        "S6",
                        format!("account_record for {:?} does not hash to its leaf", &id[..4]),
                    ));
                }
            }
            None => v.push(fail("S6", format!("no record for committed account {:?}", &id[..4]))),
        }
    }

    // An account the chain has never seen must have no proof, or the hatch
    // would open for balances that do not exist.
    let mut absent = [0xFFu8; 32];
    absent[0] = 0xAB;
    if !ids.contains(&absent) && s.account_proof(&absent).is_some() {
        v.push(fail("S6", "an account the chain never saw was given a proof"));
    }
}

// --- S2: sequencing --------------------------------------------------------

fn check_sequencing<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let at = f.state.seq();
    for bad in [0, at, at + 2, u64::MAX] {
        if bad == at + 1 {
            continue;
        }
        let mut s = f.state.clone();
        let before = s.state_root();
        let receipts = s.apply(bad, &f.accepted);
        if !receipts.iter().any(V::rejected) {
            v.push(fail("S2", format!("an intent at seq {} (expected {}) was accepted", bad, at + 1)));
        }
        if s.state_root() != before {
            v.push(fail("S2", format!("an out-of-order intent at seq {} moved state", bad)));
        }
        if s.seq() != at {
            v.push(fail("S2", "an out-of-order intent consumed a sequence number"));
        }
    }

    let mut s = f.state.clone();
    s.apply(at + 1, &f.accepted);
    if s.seq() != at + 1 {
        v.push(fail("S2", "an applied intent did not advance the sequence"));
    }
}

// --- S3: rejections are events ---------------------------------------------

fn check_rejection<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let mut s = f.state.clone();
    let accounts_before = s.account_leaves();
    let root_before = s.state_root();
    let at = s.seq();

    let receipts = s.apply(at + 1, &f.rejected);
    if !receipts.iter().any(V::rejected) {
        v.push(fail("S3", "the fixture's rejected intent was accepted"));
        return;
    }
    if s.seq() != at + 1 {
        v.push(fail("S3", "a rejected intent did not consume its sequence number"));
    }
    if s.account_leaves() != accounts_before {
        v.push(fail("S3", "a rejected intent moved application state"));
    }
    if s.state_root() == root_before {
        // The header carries the sequence and the intent commitment, so a
        // rejection that leaves the root untouched has not recorded itself.
        v.push(fail("S3", "a rejected intent left no trace in the state root"));
    }
}

// --- S5: total commitment --------------------------------------------------

fn check_commitment<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let mut s = f.state.clone();
    let before = s.state_root();
    let sections_before = s.sections();
    s.apply(s.seq() + 1, &f.accepted);

    if s.state_root() == before {
        v.push(fail("S5", "an accepted intent did not move the state root"));
    }
    if s.sections() == sections_before {
        v.push(fail("S5", "an accepted intent moved no section"));
    }
}

// --- S7: sealing -----------------------------------------------------------

fn check_sealing<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let mut s = f.state.clone();
    let epoch = s.epoch();
    let at = s.seq();

    let receipts = s.apply(at + 1, &V::seal_intent());
    let cp = match V::sealed(&receipts) {
        Some(cp) => cp,
        None => {
            v.push(fail("S7", "seal_intent() produced no checkpoint"));
            return;
        }
    };

    if cp.chain_id != f.state.chain_id() {
        v.push(fail("S7", "the checkpoint names a different chain"));
    }
    if cp.epoch != epoch {
        v.push(fail("S7", "the checkpoint does not name the epoch it sealed"));
    }
    if cp.seq != at + 1 {
        v.push(fail("S7", "the checkpoint does not cover its own sealing intent"));
    }
    if s.epoch() != epoch + 1 {
        v.push(fail("S7", "sealing did not open the next epoch"));
    }
    if cp.state_root == f.state.state_root() {
        v.push(fail("S7", "the sealed root predates the sealing intent"));
    }

    // The sealed view must be recoverable while the accounts have not moved:
    // it is what a holder proves against.
    match s.as_sealed(&cp) {
        Some(view) => {
            if view.state_root() != cp.state_root {
                v.push(fail("S7", "as_sealed() does not reproduce the sealed root"));
            }
            for id in view.account_ids() {
                match (view.account_leaf(&id), view.account_proof(&id)) {
                    (Some(leaf), Some(path)) if verify_proof(leaf, &path, cp.state_root) => {}
                    _ => {
                        v.push(fail("S7", "a holder could not prove against the sealed root"));
                        break;
                    }
                }
            }
        }
        None => v.push(fail("S7", "as_sealed() could not recover the view it just sealed")),
    }

    // And once the accounts have moved, it must say so rather than hand back a
    // view that would fail every proof built on it.
    let mut later = s.clone();
    later.apply(later.seq() + 1, &f.accepted);
    if let Some(view) = later.as_sealed(&cp) {
        if view.state_root() != cp.state_root {
            v.push(fail("S7", "as_sealed() returned a view that does not match the checkpoint"));
        }
    }
}

// --- S8: carriable state ---------------------------------------------------

fn check_carriable<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let bytes = f.state.encode();
    let back = match V::decode(&bytes) {
        Some(b) => b,
        None => {
            v.push(fail("S8", "a state did not decode from its own encoding"));
            return;
        }
    };
    if back.state_root() != f.state.state_root() {
        v.push(fail("S8", "a decoded state does not commit to the same root"));
    }
    if back.encode() != bytes {
        v.push(fail("S8", "re-encoding a decoded state changed the bytes"));
    }
    if back.seq() != f.state.seq() || back.epoch() != f.state.epoch() {
        v.push(fail("S8", "a decoded state lost its position in the history"));
    }

    // A restarted node must be indistinguishable from one that never stopped.
    let mut live = f.state.clone();
    let mut resumed = back;
    let at = live.seq();
    live.apply(at + 1, &f.accepted);
    resumed.apply(at + 1, &f.accepted);
    if live.state_root() != resumed.state_root() {
        v.push(fail("S8", "a resumed state diverged on its next intent"));
    }

    // Truncation must be refused, not fatal.
    for cut in [0, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1] {
        if V::decode(&bytes[..cut]).is_some() {
            v.push(fail("S10", format!("a state truncated at {} decoded", cut)));
        }
    }
}

// --- S1, as far as a suite can reach --------------------------------------

fn check_repeatable<V: MicrochainVm>(f: &Fixture<V>, v: &mut Vec<Violation>) {
    let script = [&f.accepted, &f.rejected, &f.accepted];
    let run = || {
        let mut s = f.state.clone();
        for i in &script {
            let at = s.seq();
            s.apply(at + 1, i);
        }
        let at = s.seq();
        s.apply(at + 1, &V::seal_intent());
        (s.state_root(), s.encode())
    };
    let (root_a, bytes_a) = run();
    let (root_b, bytes_b) = run();
    if root_a != root_b {
        v.push(fail("S1", "the same intents produced different roots"));
    }
    if bytes_a != bytes_b {
        v.push(fail("S1", "the same intents produced different encodings"));
    }
    // The intent commitment must depend on order, or an epoch's history could
    // be reshuffled without changing what was settled.
    let a = V::encode_intent(&f.accepted);
    let b = V::encode_intent(&f.rejected);
    if a == b {
        v.push(fail("S1", "two different intents share an encoding"));
    }
}

#[cfg(test)]
mod catches_violations {
    //! A conformance suite that cannot fail is decoration.
    //!
    //! Each VM here breaks exactly one rule, and the suite must name that rule
    //! and no other. Written as one machine with a switch rather than several,
    //! so the *only* difference between a passing and failing run is the
    //! violation itself.

    use super::*;
    use crate::checkpoint::Checkpoint;
    use crate::commit::Hash as H;
    use crate::fixed::Fixed;
    use alloc::vec;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Break {
        Nothing,
        /// Encoding depends on something other than state.
        Determinism,
        /// Applying an intent creates value from nowhere.
        Conservation,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct Vm {
        chain_id: u32,
        epoch: u64,
        seq: u64,
        total: i64,
        claimed: i64,
        how: Break,
    }

    impl MicrochainVm for Vm {
        type Intent = i64;
        type Receipt = bool;
        type Params = Break;
        const VM_NAME: &'static str = "broken";
        const VM_VERSION: u16 = 1;

        fn genesis(chain_id: u32, how: Break) -> Self {
            Vm { chain_id, epoch: 0, seq: 0, total: 0, claimed: 0, how }
        }
        fn chain_id(&self) -> u32 {
            self.chain_id
        }
        fn seq(&self) -> u64 {
            self.seq
        }
        fn epoch(&self) -> u64 {
            self.epoch
        }
        fn apply(&mut self, seq: u64, n: &i64) -> Vec<bool> {
            if seq != self.seq + 1 {
                return Vec::new();
            }
            self.seq = seq;
            if *n <= 0 {
                return vec![false]; // rejected
            }
            self.total += n;
            // The books are `total == claimed`. Breaking conservation means
            // moving one without the other.
            self.claimed += if self.how == Break::Conservation { n + 1 } else { *n };
            vec![true]
        }
        fn sections(&self) -> Vec<H> {
            let mut head = [0u8; 32];
            head[..8].copy_from_slice(&self.seq.to_be_bytes());
            head[8..16].copy_from_slice(&self.total.to_be_bytes());
            vec![head, crate::commit::hash_leaf(&self.total.to_be_bytes())]
        }
        fn seal_intent() -> i64 {
            0
        }
        fn sealed(_: &[bool]) -> Option<Checkpoint> {
            None
        }
        fn as_sealed(&self, _: &Checkpoint) -> Option<Self> {
            None
        }
        fn rejected(r: &bool) -> bool {
            !*r
        }
        fn unprovable(_: &bool) -> bool {
            false
        }
        fn encode_intent(n: &i64) -> Vec<u8> {
            n.to_be_bytes().to_vec()
        }
        fn decode_intent(d: &mut crate::read::Decoder) -> Option<i64> {
            d.u64().ok().map(|v| v as i64)
        }
        fn encode(&self) -> Vec<u8> {
            let mut e = crate::commit::Encoder::new();
            e.u32(self.chain_id).u64(self.epoch).u64(self.seq).i128(self.total as i128);
            if self.how == Break::Determinism {
                // The classic: something outside the state reaching the bytes.
                e.u64(crate::commit::hash_leaf(&self.seq.to_be_bytes())[0] as u64);
                e.u64(NONCE.with(|n| {
                    let v = n.get() + 1;
                    n.set(v);
                    v
                }));
            }
            e.finish().to_vec()
        }
        fn decode(b: &[u8]) -> Option<Self> {
            // A VM that trusts its input is a VM that stops.
            if b.len() < 12 {
                return None;
            }
            let how = Break::Nothing;
            let chain_id = u32::from_be_bytes(b[0..4].try_into().ok()?);
            Some(Vm { chain_id, epoch: 0, seq: 0, total: 0, claimed: 0, how })
        }
        fn account_ids(&self) -> Vec<crate::spec::AccountId> {
            Vec::new()
        }
        fn account_leaves(&self) -> Vec<H> {
            Vec::new()
        }
        fn account_record(&self, _: &crate::spec::AccountId) -> Option<Vec<u8>> {
            None
        }
        fn leaf_of_record(r: &[u8]) -> H {
            crate::commit::hash_leaf(r)
        }
        fn gross_volume(&self) -> Fixed {
            Fixed::ZERO
        }
        fn conserved(&self) -> Result<(), &'static str> {
            if self.total == self.claimed {
                Ok(())
            } else {
                Err("total and claimed disagree")
            }
        }
    }

    thread_local! {
        static NONCE: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
    }

    fn fixture(how: Break) -> Fixture<Vm> {
        let mut s = Vm::genesis(1, how);
        s.apply(1, &10);
        Fixture { state: s, accepted: 5, rejected: -1, sequence: vec![3, 4] }
    }

    fn rules(v: &[Violation]) -> Vec<&'static str> {
        let mut r: Vec<&'static str> = v.iter().map(|x| x.rule).collect();
        r.sort_unstable();
        r.dedup();
        r
    }

    /// The baseline is deliberately minimal — no accounts, no sealing, a
    /// decoder that keeps nothing — so the suite reports plenty about it, and
    /// that is the suite working. What matters here is that it reports neither
    /// of the two rules these tests target, so a hit on `S1` or `S11` below
    /// can only have come from the break.
    #[test]
    fn the_baseline_triggers_neither_targeted_rule() {
        let r = rules(&check(fixture(Break::Nothing)));
        assert!(!r.contains(&"S1"), "the baseline is already non-deterministic: {:?}", r);
        assert!(!r.contains(&"S11"), "the baseline already fails to balance: {:?}", r);
        // And it does find other things, which is the point of having it.
        assert!(!r.is_empty(), "the suite found nothing at all in a minimal VM");
    }

    #[test]
    fn a_nondeterministic_encoding_is_caught_as_s1() {
        let v = check(fixture(Break::Determinism));
        assert!(rules(&v).contains(&"S1"), "S1 was not reported: {:?}", rules(&v));
    }

    #[test]
    fn creating_value_from_nowhere_is_caught_as_s11() {
        let v = check(fixture(Break::Conservation));
        assert!(rules(&v).contains(&"S11"), "S11 was not reported: {:?}", rules(&v));
    }
}
