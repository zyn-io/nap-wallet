//! The spend circuit against its promises. Run with `--release`: arkworks
//! proving in a debug build takes minutes.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zyn_pool::circuit::{poseidon_var, Spend};
use zyn_pool::export::{ProofBytes, VkBytes};
use zyn_pool::tree::Tree;
use zyn_pool::{binding_to_address, binding_to_zyn, fr_be, keys, poseidon, Note};

fn rng(n: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([n; 32])
}

/// A tree with some notes in it, and one of ours at `mine`.
fn pool_with(mine: &Note, others: usize) -> (Tree, usize) {
    let mut t = Tree::default();
    let mut r = rng(7);
    for _ in 0..others {
        t.insert(Fr::rand(&mut r));
    }
    let at = t.insert(mine.commitment());
    for _ in 0..3 {
        t.insert(Fr::rand(&mut r));
    }
    (t, at)
}

fn spend(note: &Note, tree: &Tree, at: usize, binding: Fr) -> Spend {
    Spend { root: tree.root(), nullifier_hash: note.nullifier_hash(), binding, nullifier: note.nullifier, secret: note.secret, path: tree.path(at) }
}

#[test]
fn the_circuit_hashes_exactly_as_light_poseidon_does() {
    let mut r = rng(1);
    for width in 1..=2 {
        let xs: Vec<Fr> = (0..width).map(|_| Fr::rand(&mut r)).collect();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<FpVar<Fr>> = xs.iter().map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap()).collect();
        let out = poseidon_var(&vars).unwrap();
        assert_eq!(out.value().unwrap(), poseidon(&xs), "{width} input(s)");
    }
}

#[test]
fn every_path_reaches_the_root() {
    let mut t = Tree::default();
    let mut r = rng(2);
    assert_eq!(t.root(), zyn_pool::tree::zeros()[zyn_pool::DEPTH], "an empty tree is all zeros");
    let leaves: Vec<Fr> = (0..9).map(|_| Fr::rand(&mut r)).collect();
    for l in &leaves {
        t.insert(*l);
    }
    for (i, l) in leaves.iter().enumerate() {
        assert_eq!(t.path(i).root(*l), t.root(), "leaf {i}");
    }
}

#[test]
fn a_spend_proves_verifies_and_holds_only_for_its_binding() {
    let note = Note::from_seed(&[9u8; 64]);
    let (tree, at) = pool_with(&note, 5);
    let code = [0x42u8; 32];
    let s = spend(&note, &tree, at, binding_to_zyn(&code));

    let cs = ConstraintSystem::<Fr>::new_ref();
    s.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    println!("spend circuit: {} constraints", cs.num_constraints());

    let (pk, vk) = keys::setup([1u8; 32]);
    let proof = keys::prove(&pk, s.clone(), [2u8; 32]).unwrap();
    assert!(keys::verify(&vk, &s.public_inputs(), &proof), "the honest spend verifies");

    // The same proof, pointed at another deposit code or an address: no.
    let mut other = s.public_inputs();
    other[2] = binding_to_zyn(&[0x43u8; 32]);
    assert!(!keys::verify(&vk, &other, &proof), "a proof cannot be redirected");
    other[2] = binding_to_address(b"someone", b"relayer", 1);
    assert!(!keys::verify(&vk, &other, &proof));
    // Nor claimed under another root or nullifier hash.
    let mut other = s.public_inputs();
    other[0] = poseidon(&[other[0]]);
    assert!(!keys::verify(&vk, &other, &proof), "another root");
    let mut other = s.public_inputs();
    other[1] = Note::from_seed(&[8u8; 64]).nullifier_hash();
    assert!(!keys::verify(&vk, &other, &proof), "another nullifier hash");
}

#[test]
fn a_note_not_in_the_tree_cannot_be_spent() {
    let note = Note::from_seed(&[9u8; 64]);
    let (tree, at) = pool_with(&note, 2);
    let stranger = Note::from_seed(&[5u8; 64]);
    let mut s = spend(&note, &tree, at, binding_to_zyn(&[1u8; 32]));
    s.nullifier = stranger.nullifier;
    s.secret = stranger.secret;
    s.nullifier_hash = stranger.nullifier_hash();
    let cs = ConstraintSystem::<Fr>::new_ref();
    s.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap(), "its commitment is not under the root");

    // Nor spent with a nullifier hash that is not its own.
    let mut s = spend(&note, &tree, at, binding_to_zyn(&[1u8; 32]));
    s.nullifier_hash = stranger.nullifier_hash();
    let cs = ConstraintSystem::<Fr>::new_ref();
    s.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap(), "the nullifier hash must be the note's");
}

/// What the Solana program will run: `groth16-solana` over the exported
/// bytes (its syscalls have a host implementation for tests).
#[test]
fn the_exported_proof_verifies_under_groth16_solana() {
    let note = Note::from_seed(&[3u8; 64]);
    let (tree, at) = pool_with(&note, 4);
    let s = spend(&note, &tree, at, binding_to_address(&[7u8; 32], &[8u8; 32], 5_000));
    let (pk, vk) = keys::setup([1u8; 32]);
    let proof = keys::prove(&pk, s.clone(), [4u8; 32]).unwrap();

    let p = ProofBytes::of(&proof);
    let v = VkBytes::of(&vk);
    let key = groth16_solana::groth16::Groth16Verifyingkey {
        nr_pubinputs: v.ic.len(),
        vk_alpha_g1: v.alpha_g1,
        vk_beta_g2: v.beta_g2,
        vk_gamme_g2: v.gamma_g2,
        vk_delta_g2: v.delta_g2,
        vk_ic: &v.ic,
    };
    let inputs = s.public_inputs().map(fr_be);
    let mut ver = groth16_solana::groth16::Groth16Verifier::new(&p.a, &p.b, &p.c, &inputs, &key).unwrap();
    assert!(ver.verify().is_ok(), "groth16-solana accepts it");

    let mut wrong = inputs;
    wrong[2] = fr_be(binding_to_address(&[9u8; 32], &[8u8; 32], 5_000));
    let mut ver = groth16_solana::groth16::Groth16Verifier::new(&p.a, &p.b, &p.c, &wrong, &key).unwrap();
    assert!(ver.verify().is_err(), "and refuses another recipient");
}
