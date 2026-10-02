//! The private bridge channel (DECISIONS §158): notes, the tree they sit in,
//! and the proof that spends one without saying which.
//!
//! A note is `Poseidon(nullifier, secret)`, one fixed size, in a Merkle tree
//! of depth [`DEPTH`] held by the pool on the other chain. Spending it proves
//! "I know the secrets of one leaf under this root" and publishes
//! `Poseidon(nullifier)` so it cannot be spent twice. The proof also binds
//! what it is for — a Zyn deposit code, or a recipient with a relayer and fee
//! — so nobody who sees it in flight can point it elsewhere.
//!
//! Poseidon here is circom's (via `light-poseidon`), the same one Solana
//! computes with its Poseidon syscall and that the EVM pool implements, so a
//! root built here, on Solana and on Ethereum is the same root.

pub mod circuit;
pub mod export;
pub mod keys;
pub mod tree;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use sha3::{Digest, Keccak256};

/// Levels in the note tree: about a million notes per pool.
pub const DEPTH: usize = 20;

/// Circom's Poseidon over `inputs` (1 to 12 of them).
pub fn poseidon(inputs: &[Fr]) -> Fr {
    Poseidon::<Fr>::new_circom(inputs.len()).expect("a supported width").hash(inputs).expect("the width matches")
}

/// The leaf a note puts in the tree.
pub fn commitment(nullifier: Fr, secret: Fr) -> Fr {
    poseidon(&[nullifier, secret])
}

/// What a spend publishes, so the note cannot be spent again.
pub fn nullifier_hash(nullifier: Fr) -> Fr {
    poseidon(&[nullifier])
}

/// What a proof is for, as one field element: `keccak256(domain ‖ data)`
/// with its top byte cleared, read big-endian. Keccak because both Solana
/// and the EVM have it natively; 248 bits so it always fits the field.
pub fn binding(domain: &[u8], data: &[u8]) -> Fr {
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(data);
    let mut out: [u8; 32] = h.finalize().into();
    out[0] = 0;
    Fr::from_be_bytes_mod_order(&out)
}

/// The binding for a spend into Zyn: the §146.3 deposit code it credits.
pub fn binding_to_zyn(deposit_code: &[u8; 32]) -> Fr {
    binding(b"zyn-pool.to-zyn.v1", deposit_code)
}

/// The binding for a spend to an address: who is paid, who relayed, and the
/// relayer's fee, so none of them can be changed after the proof is made.
pub fn binding_to_address(recipient: &[u8], relayer: &[u8], fee: u64) -> Fr {
    let mut data = Vec::with_capacity(recipient.len() + relayer.len() + 10);
    data.extend_from_slice(&(recipient.len() as u16).to_be_bytes());
    data.extend_from_slice(recipient);
    data.extend_from_slice(relayer);
    data.extend_from_slice(&fee.to_be_bytes());
    binding(b"zyn-pool.to-address.v1", &data)
}

/// A field element as 32 big-endian bytes, the form both chains take.
pub fn fr_be(x: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// 32 big-endian bytes as a field element, refusing anything not below the
/// modulus rather than reducing it: a root or nullifier hash that is not
/// canonical is not one this code produced.
pub fn fr_from_be(bytes: &[u8; 32]) -> Option<Fr> {
    let x = Fr::from_be_bytes_mod_order(bytes);
    (fr_be(x) == *bytes).then_some(x)
}

/// A note's two secrets, as a wallet keeps them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub nullifier: Fr,
    pub secret: Fr,
}

impl Note {
    /// Both secrets from 64 bytes of the wallet's own randomness (or a
    /// derivation from its key), each reduced into the field.
    pub fn from_seed(seed: &[u8; 64]) -> Note {
        Note { nullifier: Fr::from_le_bytes_mod_order(&seed[..31]), secret: Fr::from_le_bytes_mod_order(&seed[32..63]) }
    }

    pub fn commitment(&self) -> Fr {
        commitment(self.nullifier, self.secret)
    }

    pub fn nullifier_hash(&self) -> Fr {
        nullifier_hash(self.nullifier)
    }
}
