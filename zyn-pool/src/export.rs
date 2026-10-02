//! Keys and proofs in the byte layout both chains verify: EIP-197, which is
//! what Solana's alt_bn128 syscalls and the EVM's pairing precompile take.
//! G1 is `x ‖ y`, G2 is `x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0`, every coordinate 32
//! big-endian bytes. The proof's A point is negated, so the verifier checks
//! one product of pairings against 1 (`groth16-solana`'s convention).

use ark_bn254::{Bn254, Fq, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use std::ops::Neg;

fn fq_be(x: Fq) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

pub fn g1_be(p: G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((x, y)) = p.xy() {
        out[..32].copy_from_slice(&fq_be(x));
        out[32..].copy_from_slice(&fq_be(y));
    }
    out
}

pub fn g2_be(p: G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((x, y)) = p.xy() {
        out[..32].copy_from_slice(&fq_be(x.c1));
        out[32..64].copy_from_slice(&fq_be(x.c0));
        out[64..96].copy_from_slice(&fq_be(y.c1));
        out[96..].copy_from_slice(&fq_be(y.c0));
    }
    out
}

/// A proof as the pools take it: `a` (negated), `b`, `c`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofBytes {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

impl ProofBytes {
    pub fn of(proof: &Proof<Bn254>) -> ProofBytes {
        ProofBytes { a: g1_be(proof.a.neg()), b: g2_be(proof.b), c: g1_be(proof.c) }
    }

    /// `a ‖ b ‖ c`, 256 bytes: how a proof travels in an instruction or call.
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[..64].copy_from_slice(&self.a);
        out[64..192].copy_from_slice(&self.b);
        out[192..].copy_from_slice(&self.c);
        out
    }
}

/// A verifying key as the pools embed it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkBytes {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

impl VkBytes {
    pub fn of(vk: &VerifyingKey<Bn254>) -> VkBytes {
        VkBytes {
            alpha_g1: g1_be(vk.alpha_g1),
            beta_g2: g2_be(vk.beta_g2),
            gamma_g2: g2_be(vk.gamma_g2),
            delta_g2: g2_be(vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(|p| g1_be(*p)).collect(),
        }
    }

    /// The key as Rust source for the Solana program, a
    /// `groth16_solana::groth16::Groth16Verifyingkey` constant.
    pub fn to_rust(&self, name: &str) -> String {
        let bytes = |b: &[u8]| b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", ");
        let ic = self.ic.iter().map(|p| format!("        [{}],", bytes(p))).collect::<Vec<_>>().join("\n");
        format!(
            "pub const {name}: groth16_solana::groth16::Groth16Verifyingkey = groth16_solana::groth16::Groth16Verifyingkey {{\n    nr_pubinputs: {n},\n    vk_alpha_g1: [{a}],\n    vk_beta_g2: [{b}],\n    vk_gamme_g2: [{g}],\n    vk_delta_g2: [{d}],\n    vk_ic: &[\n{ic}\n    ],\n}};\n",
            n = self.ic.len(),
            a = bytes(&self.alpha_g1),
            b = bytes(&self.beta_g2),
            g = bytes(&self.gamma_g2),
            d = bytes(&self.delta_g2),
        )
    }
}
