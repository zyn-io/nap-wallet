//! What authorisation costs, measured rather than assumed.
//!
//! The engine's throughput is not the chain's throughput. Every user intent
//! carries a signature, and verifying one is arithmetic on a curve — orders of
//! magnitude more expensive than applying a swap. This measures the real
//! ceiling.

use std::time::Instant;

use k256::ecdsa::SigningKey;
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::Fixed;
use zyn::verify::{resolve_batch, signer_of, Credential, Pending};
use zyn_vm::auth::{eip712_digest, signed_bytes_as, Authorization, Scheme, Signed};

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    let auth = Authorization::for_vm::<SwapState>(1, 0, 1_000);
    let intent = Intent::Transfer {
        from: [1u8; 32],
        to: [2u8; 32],
        asset: XZEC,
        amount: Fixed::whole(1),
    };

    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(eip712_digest::<SwapState>(&auth, &intent));
    }
    println!(
        "eip712 digest      {:>10.0}/sec",
        n as f64 / t.elapsed().as_secs_f64()
    );

    let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
    let digest = eip712_digest::<SwapState>(&auth, &intent);
    let (sig, rid) = key.sign_prehash_recoverable(&digest).unwrap();
    let mut sig65 = [0u8; 65];
    sig65[..64].copy_from_slice(&sig.to_bytes());
    sig65[64] = rid.to_byte() + 27;
    let evm = Credential::Evm { signature: sig65 };

    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(signer_of::<SwapState>(&evm, &auth, &intent).unwrap());
    }
    println!(
        "secp256k1 recover  {:>10.0}/sec",
        n as f64 / t.elapsed().as_secs_f64()
    );

    use ed25519_dalek::{Signer, SigningKey as EdKey};
    let ed = EdKey::from_bytes(&[9u8; 32]);
    let Signed::Message(msg) = signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, &intent) else {
        unreachable!()
    };
    let cred = Credential::Ed25519 {
        key: ed.verifying_key().to_bytes(),
        signature: ed.sign(&msg).to_bytes(),
    };
    let t = Instant::now();
    for _ in 0..n {
        std::hint::black_box(signer_of::<SwapState>(&cred, &auth, &intent).unwrap());
    }
    println!(
        "ed25519 verify     {:>10.0}/sec",
        n as f64 / t.elapsed().as_secs_f64()
    );

    // --- the same work, spread across cores ---
    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1);
    println!("\nbatched across {} cores", cores);

    for (name, c) in [("secp256k1", evm.clone()), ("ed25519", cred.clone())] {
        let pending: Vec<Pending> = (0..n)
            .map(|_| Pending::of::<SwapState>(c.clone(), &auth, &intent))
            .collect();
        let t = Instant::now();
        let out = resolve_batch(&pending);
        let rate = n as f64 / t.elapsed().as_secs_f64();
        assert!(out.iter().all(Result::is_ok));
        println!("{:<18} {:>10.0}/sec", name, rate);
    }
}
