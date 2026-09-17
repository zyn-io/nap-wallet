//! `zyn-cave-manifest` — derive Collection Z's item ids and manifest root.
//!
//! `build_collection_z_manifests.py` produces the content hashes; this produces
//! the identity around them. The split is deliberate: Python can reproduce the
//! `zyn.manifest.v1` preimage because that format is frozen and tested against
//! the Rust, but nothing reimplements `item_address` or the manifest Merkle
//! tree. Those come from `zyn-vm` and `cave-randomness` — the normative code
//! that `AllocationPolicy::validate` will later check this root against.
//!
//! The root printed here is what §64.16's `cave-sale-terms/v1` commitment binds
//! and what every allocation receipt proves inclusion against. It is a function
//! of the collection address and of every item's index and content, so it moves
//! if the art moves, if the species order moves, or if a single attribute
//! changes — which is the property that makes publishing it worth anything.
//!
//! Usage:
//!   zyn-cave-manifest [path/to/content.json]   (default: the builder's `out/`)

use std::collections::BTreeMap;

use cave_randomness::{manifest_root, ManifestEntry};
use swapvm::types::TREASURY_26460;
use zyn_vm::derive::ADDRESS_SCOPE_V1;

const CAVE_SYMBOL: &str = "CAVEZ";
const CAVE_CAP: u32 = 4444;

const DEFAULT_CONTENT: &str = "examples/zyn-pfp-concepts/out/content.json";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unhex32(text: &str, what: &str) -> Result<[u8; 32], String> {
    let raw = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<Vec<u8>, String>>()
        .map_err(|e| format!("{what}: {e}"))?;
    raw.try_into()
        .map_err(|_| format!("{what}: expected 32 bytes, got {}", text.len() / 2))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("zyn-cave-manifest: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let path = std::env::args().nth(1).unwrap_or_else(|| DEFAULT_CONTENT.to_string());
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
    let doc: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("{path}: {e}"))?;
    let map = doc.as_object().ok_or("content.json is not an object")?;

    let collection = zyn_vm::collection_address(ADDRESS_SCOPE_V1, &TREASURY_26460, CAVE_SYMBOL.as_bytes());

    // Read into a BTreeMap keyed by index so a missing or duplicated index is
    // caught here, by count, rather than surfacing as a confusing Merkle
    // mismatch later.
    let mut by_index: BTreeMap<u32, [u8; 32]> = BTreeMap::new();
    for (key, value) in map {
        let index: u32 = key.parse().map_err(|_| format!("index {key} is not a number"))?;
        let content = value
            .get("content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("index {index} has no content hash"))?;
        if by_index.insert(index, unhex32(content, &format!("index {index} content"))?).is_some() {
            return Err(format!("index {index} appears twice"));
        }
    }
    if by_index.len() != CAVE_CAP as usize {
        return Err(format!(
            "{} entries, expected {CAVE_CAP} — the manifest must cover the whole collection",
            by_index.len()
        ));
    }

    let entries: Vec<ManifestEntry> = by_index
        .iter()
        .map(|(&global_index, &content_hash)| ManifestEntry {
            global_index,
            item_id: zyn_vm::item_address(ADDRESS_SCOPE_V1, &collection, global_index),
            content_hash,
        })
        .collect();

    // `manifest_root` re-checks every item id against `item_address` itself and
    // rejects a gap, a duplicate or a zero hash, so a root coming back at all
    // is already the §64.13 guarantee: claim order cannot change identity.
    let root = manifest_root(collection, &entries).map_err(|e| e.to_string())?;

    println!("collection   {CAVE_SYMBOL}  {}", hex(&collection));
    println!("supply       {CAVE_CAP}");
    println!("manifest root {}", hex(&root));
    println!();
    for &index in &[0u32, 2222, 3555, CAVE_CAP - 1] {
        let e = &entries[index as usize];
        println!("  {index:>4}  item {}  content {}", hex(&e.item_id), hex(&e.content_hash));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The collection address and every item id are pure derivations — they do
    /// not depend on the art, so they can be pinned here even though the
    /// manifest root cannot. A transcribed constant can be transcribed wrongly
    /// (§83.4), and every allocation receipt names these.
    #[test]
    fn collection_z_addresses_are_pinned() {
        let collection =
            zyn_vm::collection_address(ADDRESS_SCOPE_V1, &TREASURY_26460, CAVE_SYMBOL.as_bytes());
        assert_eq!(
            hex(&collection),
            "024277b607ce4edbf78fe2855aba562096d00264729168bd0ddea71bdf5b5f1e",
            "CAVEZ moved: every item id and the manifest root move with it"
        );

        // Serial 0 is the first item, not the second: the VM requires
        // `serial < cap`, so 4,444 items occupy 0..=4443.
        assert_eq!(
            hex(&zyn_vm::item_address(ADDRESS_SCOPE_V1, &collection, 0)),
            "ae9836991024b77a1875de7328fc4666cdd3a5d286625dd07e57dc67d8442bdd"
        );
        assert_eq!(
            hex(&zyn_vm::item_address(ADDRESS_SCOPE_V1, &collection, CAVE_CAP - 1)),
            "7765c2956fa542b4a39d9e9a0eed4c24bb4bb3a345ba78432bfa39419a79dac4"
        );
    }

    /// `manifest_root` rejects a manifest that does not cover the collection,
    /// so a partial build cannot produce a publishable root.
    #[test]
    fn a_short_manifest_has_no_root() {
        let collection =
            zyn_vm::collection_address(ADDRESS_SCOPE_V1, &TREASURY_26460, CAVE_SYMBOL.as_bytes());
        let entries: Vec<ManifestEntry> = (0..3)
            .map(|i| ManifestEntry {
                global_index: i,
                item_id: zyn_vm::item_address(ADDRESS_SCOPE_V1, &collection, i),
                content_hash: [7; 32],
            })
            .collect();
        // Three entries is a valid three-item manifest, and that is the point:
        // the count is checked against what is supplied, so the caller must be
        // the one insisting on 4,444.
        assert!(manifest_root(collection, &entries).is_ok());
    }
}
