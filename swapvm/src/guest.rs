//! ZynZap's zkVM entry point.
//!
//! Almost nothing, because the ABI is the microchain spec's: `zyn_vm::zvm`
//! defines the tape, the statement and the public output for *every* Zyn
//! program, and this module only pins them to ZynZap's types.
//!
//! That is deliberate. A per-application guest ABI would mean a per-application
//! verifier, and a per-application verifier is a settlement contract that has to
//! be redeployed every time Zyn hosts something new. One ABI means one verifier,
//! whatever is running behind it.
//!
//! The statement a proof over [`run`] establishes:
//!
//! > Starting from a state whose commitment is `base_root`, applying `batch` in
//! > order yields a state whose commitment is `final_root`.
//!
//! Nothing here is live yet: V1 settles with threshold signatures, per the
//! project plan, and this exists so the settlement path can be swapped for a
//! proof without the AMM changing. The crate builds for
//! `riscv32im-unknown-none-elf` with `--no-default-features`, which is the
//! target SP1 and RISC Zero compile guests to — and, per `ZVM.md`, the target a
//! third-party Zyn program would be shipped as.

use alloc::vec::Vec;

use crate::state::SwapState;
use crate::tx::SequencedIntent;
use zyn_vm::commit::Hash;
use zyn_vm::zvm;

pub use zyn_vm::zvm::{Output, ZvmError, ZVM_VERSION};

/// ZynZap's program identity, as committed in every [`Output`].
pub fn vm_id() -> Hash {
    zvm::vm_id::<SwapState>()
}

/// Sequenced intents in the shape the shared ABI expects.
fn as_pairs(batch: &[SequencedIntent]) -> Vec<(u64, crate::tx::Intent)> {
    batch.iter().map(|si| (si.seq, si.intent.clone())).collect()
}

/// Write an input tape for ZynZap.
pub fn encode_input(base_root: Hash, state: &SwapState, batch: &[SequencedIntent]) -> Vec<u8> {
    zvm::encode_input::<SwapState>(base_root, state, &as_pairs(batch))
}

/// Write the production proof tape from journal authorization records.
pub fn encode_committed_input(
    base_root: Hash,
    state: &SwapState,
    batch: &[(u64, Vec<u8>)],
) -> Vec<u8> {
    zvm::encode_committed_input::<SwapState>(base_root, state, batch)
}

/// Run the transition and produce the public output. This is the whole guest.
pub fn run(tape: &[u8]) -> Result<Vec<u8>, ZvmError> {
    zvm::run::<SwapState>(tape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::Fixed;
    use crate::tx::Intent;
    use crate::types::{AccountId, Params, XZEC};
    use ed25519_dalek::{Signer, SigningKey};
    use zyn_vm::auth::{account_of, delegation_bytes_as, Authorization, Scheme, Signed};
    use zyn_vm::session::{session_payload, Delegation};
    use zyn_vm::verify::{authorize_delegated_intent, encode_authorized, Credential, Delegated};
    use zyn_vm::MicrochainVm;

    fn acct(n: u8) -> AccountId {
        [n; 32]
    }

    fn chain() -> SwapState {
        let mut s = SwapState::new(3, Params::v1());
        let observed = s.backing_of(XZEC).add(Fixed::whole(5_000)).unwrap();
        let at = s.seq;
        crate::vm::apply(&mut s, &SequencedIntent { seq: at + 1, intent: Intent::AttestVaultBalance { asset: XZEC, observed } });
        let intent = Intent::next_deposit(&s, acct(1), XZEC, Fixed::whole(5_000), [0u8; 32]);
        crate::vm::apply(&mut s, &SequencedIntent { seq: 1, intent });
        s
    }

    fn market(account: AccountId) -> SwapState {
        let mut s = SwapState::new(3, Params::v1());
        let go = |s: &mut SwapState, intent: Intent| {
            let seq = s.seq + 1;
            crate::vm::apply(s, &SequencedIntent { seq, intent });
        };
        go(&mut s, Intent::AttestVaultBalance { asset: XZEC, observed: Fixed::whole(10_000) });
        let deposit = Intent::next_deposit(&s, account, XZEC, Fixed::whole(10_000), [0u8; 32]);
        go(&mut s, deposit);
        go(&mut s, Intent::Checkpoint);
        go(&mut s, Intent::ConfirmAnchor { epoch: 0 });
        go(&mut s, Intent::CreateToken {
            creator: account,
            symbol: crate::state::symbol(b"CAT"),
            supply: Fixed::whole(1_000_000),
            unit: Fixed::raw(1),
            xzec_liquidity: Fixed::whole(1_000),
            token_liquidity: Fixed::whole(500_000),
            fee_bps: 30,
        });
        s
    }

    fn batch(s: &SwapState, from: u64) -> Vec<SequencedIntent> {
        alloc::vec![
            SequencedIntent {
                seq: from + 1,
                intent: Intent::AttestVaultBalance {
                    asset: XZEC,
                    observed: s.backing_of(XZEC),
                },
            },
            SequencedIntent {
                seq: from + 2,
                intent: Intent::next_deposit(s, acct(2), XZEC, Fixed::whole(9_000), [0u8; 32]),
            },
            SequencedIntent { seq: from + 3, intent: Intent::Checkpoint },
        ]
    }

    fn committed(batch: &[SequencedIntent]) -> Vec<(u64, Vec<u8>)> {
        batch
            .iter()
            .map(|si| {
                let authorized = zyn_vm::verify::Authorized::operator(si.intent.clone());
                (si.seq, zyn_vm::verify::encode_authorized::<SwapState>(&authorized))
            })
            .collect()
    }

    /// The proved program and the natively executed program must agree, or the
    /// proof attests to something other than what the chain did.
    #[test]
    fn the_guest_reproduces_native_execution() {
        let s = chain();
        let b = batch(&s, s.seq);
        let committed = committed(&b);

        let mut native = s.clone();
        for ((seq, bytes), si) in committed.iter().zip(&b) {
            native.apply_committed(*seq, &si.intent, bytes);
        }

        let out = Output::decode(
            &run(&encode_committed_input(s.state_root(), &s, &committed)).expect("run"),
        )
        .expect("output");
        assert_eq!(out.base_root, s.state_root());
        assert_eq!(out.final_root, native.state_root());
        assert_eq!(out.seq, native.seq);
        assert_eq!(out.epoch, native.epoch);
        assert_eq!(out.chain_id, native.chain_id);
        assert_eq!(out.vm_id, vm_id());
    }

    /// The base-root check is part of the statement, so a state that does not
    /// commit to the claimed root produces no proof at all.
    #[test]
    fn a_state_that_does_not_match_the_base_root_is_refused() {
        let s = chain();
        let tape = encode_input([0xAB; 32], &s, &batch(&s, s.seq));
        assert_eq!(run(&tape), Err(ZvmError::BaseRootMismatch));
    }

    #[test]
    fn a_malformed_tape_is_refused_rather_than_panicking() {
        assert_eq!(run(&[]), Err(ZvmError::Malformed));
        assert_eq!(run(&[0xFF, 0xFF]), Err(ZvmError::Malformed));
        let s = chain();
        let good = encode_input(s.state_root(), &s, &batch(&s, s.seq));
        for cut in 0..good.len() {
            assert!(run(&good[..cut]).is_err(), "truncation at {} ran", cut);
        }
    }

    /// Running the same tape twice must produce identical output: the statement
    /// is a function, which is what makes it provable at all.
    #[test]
    fn the_guest_is_deterministic() {
        let s = chain();
        let tape = encode_input(s.state_root(), &s, &batch(&s, s.seq));
        assert_eq!(run(&tape).unwrap(), run(&tape).unwrap());
    }

    /// The identity a proof commits to is ZynZap's, not some other program's.
    /// Once Zyn hosts more than one application this is what stops a
    /// transition proved for one being presented as another's.
    #[test]
    fn the_output_names_the_program_that_ran() {
        let s = chain();
        let out = Output::decode(&run(&encode_input(s.state_root(), &s, &batch(&s, s.seq))).unwrap())
            .unwrap();
        assert_eq!(out.vm_id, vm_id());
        assert_ne!(out.vm_id, [0u8; 32]);
    }

    #[test]
    fn the_guest_reverifies_a_delegated_action_from_committed_bytes() {
        let owner = SigningKey::from_bytes(&[71u8; 32]);
        let session = SigningKey::from_bytes(&[72u8; 32]);
        let owner_key = owner.verifying_key().to_bytes();
        let account = account_of(Scheme::Ed25519, &owner_key);
        let state = market(account);
        let amount = Fixed::whole(1);
        let quote = crate::vm::quote(&state, XZEC, &[1], amount).unwrap();
        let mut delegation = Delegation::session(
            account,
            session.verifying_key().to_bytes(),
            state.epoch(),
            2,
        );
        delegation.allowed_assets = alloc::vec![XZEC, quote.asset_out];
        delegation.allowed_assets.sort_unstable();
        delegation.allowed_pools = alloc::vec![1];
        delegation.max_per_action = alloc::vec![zyn_vm::session::AssetLimit { asset: XZEC, amount }];
        delegation.max_slippage_bps = 100;
        delegation.salt = [73u8; 32];
        let Signed::Message(certificate) =
            delegation_bytes_as::<SwapState>(Scheme::Ed25519, state.chain_id(), &delegation)
        else {
            panic!("native keys sign delegation bytes")
        };
        let auth = Authorization::for_vm::<SwapState>(state.chain_id(), state.epoch(), 1);
        let intent = Intent::SwapExactIn {
            account,
            asset_in: XZEC,
            path: alloc::vec![1],
            amount_in: amount,
            min_out: Fixed::raw(quote.amount_out.0 * 9_900 / 10_000),
        };
        let id = delegation.id(state.chain_id(), &auth.vm_id);
        let delegated = Delegated {
            delegation,
            owner: Credential::Ed25519 {
                key: owner_key,
                signature: owner.sign(&certificate).to_bytes(),
            },
            session_signature: session
                .sign(&session_payload::<SwapState>(&id, &auth, &intent))
                .to_bytes(),
        };
        let authorized =
            authorize_delegated_intent(&delegated, &auth, intent.clone(), &state).unwrap();
        let bytes = encode_authorized::<SwapState>(&authorized);
        let tape = encode_committed_input(
            state.state_root(),
            &state,
            &[(state.seq() + 1, bytes.clone())],
        );
        let out = Output::decode(&run(&tape).expect("delegated proof transition")).unwrap();
        assert_eq!(out.seq, state.seq() + 1);

        let mut tampered = bytes;
        let intent_len = SwapState::encode_intent(&intent).len();
        let session_signature = tampered.len() - 4 - intent_len - 64;
        tampered[session_signature] ^= 1;
        let tape = encode_committed_input(
            state.state_root(),
            &state,
            &[(state.seq() + 1, tampered)],
        );
        assert_eq!(run(&tape), Err(ZvmError::Unauthorized));
    }
}
