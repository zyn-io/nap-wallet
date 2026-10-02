//! The private bridge channel in the browser (DECISIONS §158): what Nap needs
//! to put a note into a pool and take it out again without saying which.
//!
//! Hex in, hex out (field elements as 32 big-endian bytes, the form both
//! chains use). The proving key is handed over once (`load_key`) and kept.

use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use serde_json::json;
use std::cell::RefCell;
use wasm_bindgen::prelude::*;
use zyn_pool::circuit::Spend;
use zyn_pool::export::ProofBytes;
use zyn_pool::tree::Tree;
use zyn_pool::{fr_be, fr_from_be, keys, Note};

thread_local! {
    static KEY: RefCell<Option<ProvingKey<Bn254>>> = const { RefCell::new(None) };
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn bytes<const N: usize>(s: &str) -> Result<[u8; N], JsError> {
    let s = s.trim_start_matches("0x");
    if s.len() != N * 2 {
        return Err(JsError::new(&format!("expected {N} bytes of hex")));
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| JsError::new("not hex"))?;
    }
    Ok(out)
}

fn field(s: &str) -> Result<Fr, JsError> {
    fr_from_be(&bytes::<32>(s)?).ok_or_else(|| JsError::new("not a field element"))
}

/// A note from 64 bytes of the wallet's own derivation: its secrets, and the
/// commitment and nullifier hash they make.
#[wasm_bindgen]
pub fn note(seed_hex: &str) -> Result<String, JsError> {
    let n = Note::from_seed(&bytes::<64>(seed_hex)?);
    Ok(json!({
        "nullifier": hex(&fr_be(n.nullifier)),
        "secret": hex(&fr_be(n.secret)),
        "commitment": hex(&fr_be(n.commitment())),
        "nullifier_hash": hex(&fr_be(n.nullifier_hash())),
    })
    .to_string())
}

fn tree(leaves_json: &str) -> Result<Tree, JsError> {
    let leaves: Vec<String> = serde_json::from_str(leaves_json).map_err(|_| JsError::new("leaves: a JSON array of hex"))?;
    let mut t = Tree::default();
    for l in &leaves {
        t.insert(field(l)?);
    }
    Ok(t)
}

/// The root of a pool's tree, from its leaves in order.
#[wasm_bindgen]
pub fn root(leaves_json: &str) -> Result<String, JsError> {
    Ok(hex(&fr_be(tree(leaves_json)?.root())))
}

/// The binding for a spend into Zyn under this deposit code.
#[wasm_bindgen]
pub fn binding_to_zyn(code_hex: &str) -> Result<String, JsError> {
    Ok(hex(&fr_be(zyn_pool::binding_to_zyn(&bytes::<32>(code_hex)?))))
}

fn address(s: &str) -> Result<Vec<u8>, JsError> {
    let s = s.trim_start_matches("0x");
    match s.len() {
        40 => Ok(bytes::<20>(s)?.to_vec()),
        64 => Ok(bytes::<32>(s)?.to_vec()),
        _ => Err(JsError::new("an address is 20 bytes (EVM) or 32 (Solana), as hex")),
    }
}

/// The binding for a spend to `recipient`, relayed by `relayer` for `fee`:
/// 32-byte Solana keys or 20-byte EVM addresses, as hex.
#[wasm_bindgen]
pub fn binding_to_address(recipient_hex: &str, relayer_hex: &str, fee: u64) -> Result<String, JsError> {
    Ok(hex(&fr_be(zyn_pool::binding_to_address(&address(recipient_hex)?, &address(relayer_hex)?, fee))))
}

/// The proving key, once: arkworks, uncompressed (`spend.pk.raw`).
#[wasm_bindgen]
pub fn load_key(pk: &[u8]) -> Result<(), JsError> {
    let key = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(pk).map_err(|_| JsError::new("that is not a spend proving key"))?;
    KEY.with(|k| *k.borrow_mut() = Some(key));
    Ok(())
}

/// A proof that this note is one of `leaves`, bound to `binding_hex`.
/// `rand_hex`: 32 fresh random bytes from the page.
#[wasm_bindgen]
pub fn prove(leaves_json: &str, nullifier_hex: &str, secret_hex: &str, binding_hex: &str, rand_hex: &str) -> Result<String, JsError> {
    let t = tree(leaves_json)?;
    let n = Note { nullifier: field(nullifier_hex)?, secret: field(secret_hex)? };
    let c = n.commitment();
    let leaves: Vec<String> = serde_json::from_str(leaves_json).unwrap_or_default();
    let at = leaves.iter().position(|l| field(l).ok() == Some(c)).ok_or_else(|| JsError::new("this note is not in the pool yet"))?;
    let spend = Spend { root: t.root(), nullifier_hash: n.nullifier_hash(), binding: field(binding_hex)?, nullifier: n.nullifier, secret: n.secret, path: t.path(at) };
    let proof = KEY.with(|k| {
        let k = k.borrow();
        let pk = k.as_ref().ok_or_else(|| JsError::new("load the proving key first"))?;
        keys::prove(pk, spend.clone(), bytes::<32>(rand_hex)?).map_err(|e| JsError::new(&e))
    })?;
    Ok(json!({
        "proof": hex(&ProofBytes::of(&proof).to_bytes()),
        "root": hex(&fr_be(spend.root)),
        "nullifier_hash": hex(&fr_be(spend.nullifier_hash)),
        "index": at,
    })
    .to_string())
}
