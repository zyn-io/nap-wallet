//! ZVM — how a Zyn program is executed and, later, proved.
//!
//! The whole interface a Zyn application has to the outside world:
//!
//! ```text
//!   bytes in  ──>  run  ──>  bytes out
//! ```
//!
//! No storage calls, no network, no clock, no randomness, no allocator
//! callbacks. Two operations — read the input, write the output — which is the
//! smallest sandbox that can still run a state machine, and the reason
//! determinism here is cheap rather than something the host has to police.
//!
//! # The statement
//!
//! > Starting from a state whose commitment is `base_root`, applying `batch` in
//! > order yields a state whose commitment is `final_root`.
//!
//! Today the sequencer asserts it and threshold signers endorse it. Later a
//! prover establishes it. The bytes are the same either way, which is the point:
//! the settlement path can be replaced without an application changing.
//!
//! `base_root` is an *input to the statement*, not something the caller is
//! trusted to have checked. Without it a proof would say only that some state
//! transitioned correctly, leaving a sequencer free to prove a transition from a
//! state that was never anchored.
//!
//! # What a proof does not establish
//!
//! It proves the transition was applied faithfully **to the intents it was
//! given**. It says nothing about whether those intents were true.
//!
//! A fabricated `CreditDeposit` — units minted against a Zcash deposit that
//! never happened — is proved exactly as faithfully as a real one. The prover
//! has no more access to Zcash than the VM does, and for the same reason: a
//! program that could reach outside would not be deterministic (**S1**).
//!
//! This is the same rule as **S4**, seen from the other side. S4 says outcomes
//! must be computed here, never accepted, so that a proof covers them. Its
//! corollary is that anything the VM genuinely *cannot* compute — the state of
//! another chain — stays outside what a proof can reach, however good the
//! prover gets.
//!
//! So proofs are not the answer to bridge trust. They replace the *certificate*
//! over a transition, not the *attestation* over an input. Attestation is
//! handled where it has to be: deposits are provisional until a quorum has
//! endorsed the epoch that contains them (`DECISIONS` §10.12). Reading a proof
//! as covering deposits would be a serious misreading, and an easy one.
//!
//! # Why the target is rv32im
//!
//! The [`Output`] binds a [`vm_id`](Output::vm_id), so a run of one program can
//! never be presented as another's. What it does not need to bind is *which
//! implementation* executed — because there is only ever one artefact. A Zyn
//! program is an `rv32im` ELF, and the same ELF is what a zkVM proves. This
//! module runs it natively; SP1 or RISC Zero prove it; neither is a
//! reimplementation of the other.
//!
//! Two properties fall out of the instruction set rather than out of policy:
//!
//! - **No floating point.** `rv32im` is integer and multiply. There is no `F`
//!   or `D` extension to disable, so the determinism rule that every other
//!   platform enforces by convention is enforced here by the absence of the
//!   instructions.
//! - **Metering is cycle counting.** A prover already counts cycles because
//!   that is what a proof costs. Using the same number as the execution budget
//!   means an application has one resource limit, not two that must agree.
//!
//! See `ZVM.md` for how this compares with WASM and Move, and for the staged
//! path from today's compiled-in applications to permissionless ones.

use alloc::vec::Vec;

use crate::commit::{Encoder, Hash};
use crate::read::{Decoder, WireError};
use crate::spec::MicrochainVm;
use crate::verify::{decode_authorized, encode_authorized, Authorized, CommittedError};

/// Input format version. Bumped when the tape layout changes.
pub const ZVM_VERSION: u16 = 2;

/// A guard on how much a single call may be asked to do.
///
/// The host, not the guest, decides this — a program cannot be trusted to
/// bound itself. It is a decode-time limit rather than a metering system: real
/// metering is cycle-counting inside the executor, which is a Stage 2 concern.
/// This only stops a malformed tape from sizing an allocation.
pub const MAX_BATCH: usize = 65_536;

/// What a program is asked to do.
pub struct Input<V: MicrochainVm> {
    pub base_root: Hash,
    pub state: V,
    /// Sequenced committed authorization records, in canonical order.
    pub batch: Vec<(u64, Vec<u8>)>,
}

/// What a program commits publicly.
///
/// Deliberately small: a settlement verifier compares these against what it
/// already holds, so anything larger would be paying to publish data the
/// verifier does not need.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Output {
    /// Which program ran. Binds the run to a VM name and version, so a
    /// transition proved for one application cannot be presented as another's —
    /// the failure that matters most once Zyn hosts more than one.
    pub vm_id: Hash,
    pub chain_id: u32,
    pub base_root: Hash,
    pub final_root: Hash,
    pub epoch: u64,
    pub seq: u64,
}

/// The identity a program commits to: its name and version, hashed.
pub fn vm_id<V: MicrochainVm>() -> Hash {
    let mut e = Encoder::new();
    e.bytes(b"zyn.vm.v1").bytes(V::VM_NAME.as_bytes()).u16(V::VM_VERSION);
    e.leaf()
}

impl Output {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(&self.vm_id)
            .u32(self.chain_id)
            .bytes(&self.base_root)
            .bytes(&self.final_root)
            .u64(self.epoch)
            .u64(self.seq);
        e.finish().to_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<Output, WireError> {
        let mut d = Decoder::new(buf);
        let out = Output {
            vm_id: d.hash()?,
            chain_id: d.u32()?,
            base_root: d.hash()?,
            final_root: d.hash()?,
            epoch: d.u64()?,
            seq: d.u64()?,
        };
        if d.remaining() != 0 {
            return Err(WireError::TrailingBytes);
        }
        Ok(out)
    }
}

/// Write an input tape.
pub fn encode_input<V: MicrochainVm>(
    base_root: Hash,
    state: &V,
    batch: &[(u64, V::Intent)],
) -> Vec<u8> {
    let committed: Vec<(u64, Vec<u8>)> = batch
        .iter()
        .map(|(seq, intent)| {
            (*seq, encode_authorized::<V>(&Authorized::operator(intent.clone())))
        })
        .collect();
    encode_committed_input::<V>(base_root, state, &committed)
}

/// Write a proof input tape from the exact records carried by the journal.
///
/// This is the production path. [`encode_input`] remains a convenience for
/// operator-only VM fixtures; it cannot turn a user-authorized action into an
/// operator action because [`run`] independently checks each record.
pub fn encode_committed_input<V: MicrochainVm>(
    base_root: Hash,
    state: &V,
    batch: &[(u64, Vec<u8>)],
) -> Vec<u8> {
    let mut e = Encoder::new();
    let state_bytes = state.encode();
    e.u16(ZVM_VERSION)
        .bytes(&base_root)
        .u32(state_bytes.len() as u32)
        .bytes(&state_bytes)
        .u32(batch.len() as u32);
    for (seq, committed) in batch {
        e.u64(*seq)
            .u32(committed.len() as u32)
            .bytes(committed);
    }
    e.finish().to_vec()
}

/// Read an input tape.
pub fn decode_input<V: MicrochainVm>(buf: &[u8]) -> Result<Input<V>, WireError> {
    let mut d = Decoder::new(buf);
    if d.u16()? != ZVM_VERSION {
        return Err(WireError::UnknownDiscriminant(0));
    }
    let base_root = d.hash()?;
    let state_len = d.u32()? as usize;
    let state = V::decode(d.take_bytes(state_len)?).ok_or(WireError::Truncated)?;
    let n = d.u32()? as usize;
    if n > MAX_BATCH {
        return Err(WireError::TooLong);
    }
    let mut batch = Vec::with_capacity(n);
    for _ in 0..n {
        let seq = d.u64()?;
        let len = d.u32()? as usize;
        let committed = d.take_bytes(len)?.to_vec();
        batch.push((seq, committed));
    }
    if d.remaining() != 0 {
        return Err(WireError::TrailingBytes);
    }
    Ok(Input { base_root, state, batch })
}

/// Why a run produced nothing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ZvmError {
    /// The supplied state does not commit to the claimed base root.
    BaseRootMismatch,
    /// An intent could not be executed at all. **S9** — an unprovable step, so
    /// the batch is discarded rather than partially applied.
    Unprovable,
    /// The batch left the VM's conserved quantities out of balance. **S11.**
    ///
    /// Not a rejected intent: a rejection is a rule the VM enforced correctly,
    /// and this is the VM having failed to. The batch is discarded whole and
    /// the failure is loud, because the alternative is a committed root that
    /// says value was created.
    NotConserved(&'static str),
    /// A signature, delegation, entitlement, or authorization envelope did
    /// not justify the action at the state where it would execute.
    Unauthorized,
    Malformed,
}

/// Apply a batch atomically.
///
/// Soft rejections do not abort a batch — they are ordinary history. Only an
/// unprovable step does, because that is the one path that can leave a
/// half-applied intent behind, and a half-applied intent must never reach a
/// committed root.
pub fn apply_batch<V: MicrochainVm>(
    state: &mut V,
    batch: &[(u64, V::Intent)],
) -> Result<Vec<V::Receipt>, ZvmError> {
    let mut scratch = state.clone();
    let mut all = Vec::with_capacity(batch.len());
    for (seq, intent) in batch {
        let receipts = scratch.apply(*seq, intent);
        if receipts.iter().any(V::unprovable) {
            return Err(ZvmError::Unprovable);
        }
        all.extend(receipts);
    }
    // S11, checked against the scratch copy before it is allowed to become the
    // committed state. Running it here rather than per intent is a deliberate
    // choice of granularity: a batch is the unit that reaches a root, so it is
    // the unit conservation has to hold at, and a per-intent scan would cost
    // O(state) per action.
    scratch.conserved().map_err(ZvmError::NotConserved)?;
    *state = scratch;
    Ok(all)
}

/// Verify and apply the committed journal records a proof is asked to attest.
///
/// Verification happens against the evolving scratch state, exactly as it
/// does during replica replay. A proof therefore establishes both the VM
/// transition and the authority for every user action in it.
pub fn apply_committed_batch<V: MicrochainVm>(
    state: &mut V,
    batch: &[(u64, Vec<u8>)],
) -> Result<Vec<V::Receipt>, ZvmError> {
    let mut scratch = state.clone();
    let mut all = Vec::with_capacity(batch.len());
    for (seq, committed) in batch {
        let authorized = decode_authorized::<V>(committed, &scratch).map_err(|e| match e {
            CommittedError::Malformed => ZvmError::Malformed,
            CommittedError::Unauthorised(_) => ZvmError::Unauthorized,
        })?;
        let receipts = scratch.apply_committed(*seq, authorized.intent(), committed);
        if receipts.iter().any(V::unprovable) {
            return Err(ZvmError::Unprovable);
        }
        all.extend(receipts);
    }
    scratch.conserved().map_err(ZvmError::NotConserved)?;
    *state = scratch;
    Ok(all)
}

/// The transition, with the base-root binding that makes it a statement.
pub fn transition<V: MicrochainVm>(
    mut state: V,
    expected_base: Hash,
    batch: &[(u64, V::Intent)],
) -> Result<(V, Hash), ZvmError> {
    if state.state_root() != expected_base {
        return Err(ZvmError::BaseRootMismatch);
    }
    apply_batch(&mut state, batch)?;
    let root = state.state_root();
    Ok((state, root))
}

/// The proof transition over committed authorization records.
pub fn transition_committed<V: MicrochainVm>(
    mut state: V,
    expected_base: Hash,
    batch: &[(u64, Vec<u8>)],
) -> Result<(V, Hash), ZvmError> {
    if state.state_root() != expected_base {
        return Err(ZvmError::BaseRootMismatch);
    }
    apply_committed_batch(&mut state, batch)?;
    let root = state.state_root();
    Ok((state, root))
}

/// The whole program. A zkVM binary reads its tape, calls this, and commits the
/// returned bytes; nothing in the state machine changes when a prover is
/// attached.
pub fn run<V: MicrochainVm>(tape: &[u8]) -> Result<Vec<u8>, ZvmError> {
    let input: Input<V> = decode_input(tape).map_err(|_| ZvmError::Malformed)?;
    let chain_id = input.state.chain_id();
    let (state, final_root) =
        transition_committed(input.state, input.base_root, &input.batch)?;
    Ok(Output {
        vm_id: vm_id::<V>(),
        chain_id,
        base_root: input.base_root,
        final_root,
        epoch: state.epoch(),
        seq: state.seq(),
    }
    .encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_round_trips_and_refuses_trailing_bytes() {
        let o = Output {
            vm_id: [3u8; 32],
            chain_id: 9,
            base_root: [1u8; 32],
            final_root: [2u8; 32],
            epoch: 7,
            seq: 12_345,
        };
        assert_eq!(Output::decode(&o.encode()).unwrap(), o);
        let mut extra = o.encode();
        extra.push(0);
        assert_eq!(Output::decode(&extra), Err(WireError::TrailingBytes));
    }

    #[test]
    fn a_truncated_output_is_refused_rather_than_panicking() {
        let o = Output {
            vm_id: [3u8; 32],
            chain_id: 1,
            base_root: [0u8; 32],
            final_root: [0u8; 32],
            epoch: 0,
            seq: 0,
        };
        let bytes = o.encode();
        for cut in 0..bytes.len() {
            assert!(Output::decode(&bytes[..cut]).is_err(), "truncation at {} decoded", cut);
        }
    }
}
