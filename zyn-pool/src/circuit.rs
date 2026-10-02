//! The spend statement, as constraints.
//!
//! Public: the tree `root`, the note's `nullifier_hash`, and the `binding`
//! (what the spend is for). Private: the note's nullifier and secret, and its
//! path. Proven: the note's commitment is a leaf under `root` along that
//! path, and `nullifier_hash` is the hash of its nullifier. The binding is
//! squared into the system so a proof holds for that binding only.

use crate::tree::Path;
use crate::DEPTH;
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

/// Circom's Poseidon in constraints: the same rounds `light-poseidon` runs,
/// state `[0, inputs…]`, output the first element.
pub fn poseidon_var(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let width = inputs.len() + 1;
    let p = get_poseidon_parameters::<Fr>(width as u8).map_err(|_| SynthesisError::Unsatisfiable)?;
    let mut state: Vec<FpVar<Fr>> = std::iter::once(FpVar::constant(Fr::zero())).chain(inputs.iter().cloned()).collect();
    let half = p.full_rounds / 2;
    let rounds = p.full_rounds + p.partial_rounds;
    let pow5 = |x: &FpVar<Fr>| -> Result<FpVar<Fr>, SynthesisError> {
        let x2 = x.square()?;
        let x4 = x2.square()?;
        Ok(x4 * x)
    };
    for round in 0..rounds {
        for (i, s) in state.iter_mut().enumerate() {
            *s += p.ark[round * width + i];
        }
        let full = round < half || round >= half + p.partial_rounds;
        if full {
            for s in state.iter_mut() {
                *s = pow5(s)?;
            }
        } else {
            state[0] = pow5(&state[0])?;
        }
        state = (0..width)
            .map(|i| state.iter().enumerate().fold(FpVar::constant(Fr::zero()), |acc, (j, s)| acc + s * p.mds[i][j]))
            .collect();
    }
    Ok(state.swap_remove(0))
}

/// One spend. `Default` gives the shape for key generation.
#[derive(Clone)]
pub struct Spend {
    pub root: Fr,
    pub nullifier_hash: Fr,
    pub binding: Fr,
    pub nullifier: Fr,
    pub secret: Fr,
    pub path: Path,
}

impl Default for Spend {
    fn default() -> Self {
        Spend {
            root: Fr::zero(),
            nullifier_hash: Fr::zero(),
            binding: Fr::zero(),
            nullifier: Fr::zero(),
            secret: Fr::zero(),
            path: Path { siblings: [Fr::zero(); DEPTH], right: [false; DEPTH] },
        }
    }
}

impl Spend {
    /// The public inputs, in the order the verifier takes them.
    pub fn public_inputs(&self) -> [Fr; 3] {
        [self.root, self.nullifier_hash, self.binding]
    }
}

impl ConstraintSynthesizer<Fr> for Spend {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let root = FpVar::new_input(cs.clone(), || Ok(self.root))?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || Ok(self.nullifier_hash))?;
        let binding = FpVar::new_input(cs.clone(), || Ok(self.binding))?;
        let nullifier = FpVar::new_witness(cs.clone(), || Ok(self.nullifier))?;
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.secret))?;

        poseidon_var(&[nullifier.clone()])?.enforce_equal(&nullifier_hash)?;

        let mut cur = poseidon_var(&[nullifier, secret])?;
        for i in 0..DEPTH {
            let sib = FpVar::new_witness(cs.clone(), || Ok(self.path.siblings[i]))?;
            let right = Boolean::new_witness(cs.clone(), || Ok(self.path.right[i]))?;
            let left = FpVar::conditionally_select(&right, &sib, &cur)?;
            let other = FpVar::conditionally_select(&right, &cur, &sib)?;
            cur = poseidon_var(&[left, other])?;
        }
        cur.enforce_equal(&root)?;

        // Tie the binding into the system (Tornado's recipient trick): an
        // input no constraint touches could be swapped under a valid proof.
        let _ = binding.square()?;
        Ok(())
    }
}
