//! Check a chain's 333 against the manifest, item by item.
//!
//! Counting minted items proves only that 333 mints were accepted. This proves
//! each one is the *right* item: that its address derives from its serial, that
//! it is bound to the collection, and that the content it commits to is the
//! manifest's. Reads only — it holds no key and submits nothing.
//!
//! Uses the same ZYN_GENESIS_* variables as `zyn-genesis`.
fn main() {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let node = env("ZYN_GENESIS_NODE", "127.0.0.1:18099");
    let chain: u32 = env("ZYN_GENESIS_CHAIN", "26460").parse().expect("chain");
    let c = zynzapd::client::Node::new(&node, chain);
    let assets = c.assets().expect("assets");
    let scope = zyn_vm::derive::ADDRESS_SCOPE_V1;

    let treasury_dir = env("ZYN_GENESIS_TREASURY", "");
    let dir = std::path::Path::new(&treasury_dir);
    let public =
        zyn_custody::shares::load_public::<zyn_custody::treasury::ZynAccount>(dir).expect("public");
    let treasury = zyn_custody::treasury::account_of_group(&public).expect("account");
    let collection = zyn_vm::collection_address(scope, &treasury, b"NAPMOLE");

    let raw = std::fs::read_to_string(env("ZYN_GENESIS_MANIFEST", "")).expect("manifest");

    let mut bad = Vec::new();
    for n in 1..=333u32 {
        let symbol = format!("MOLE{:03}", n);
        let serial = n - 1;
        // The address must derive from (collection, serial) — not from the name.
        let want_id = zyn_vm::item_address(scope, &collection, serial);
        let Some(a) = assets.iter().find(|a| a.symbol == symbol) else {
            bad.push(format!("{}: absent", symbol));
            continue;
        };
        if a.id != want_id {
            bad.push(format!("{}: address is not item({}, {})", symbol, "NAPMOLE", serial));
        }
        if a.collection != Some(collection) {
            bad.push(format!("{}: not bound to the collection", symbol));
        }
        // And the committed content must be the manifest's, byte for byte.
        let key = format!("\"{:04}\"", n);
        let at = raw.find(&key).expect("entry");
        let after = &raw[at..];
        let ct = after.find("\"content\"").expect("content");
        let tail = &after[ct + 9..];
        let q1 = tail.find('"').unwrap() + 1;
        let q2 = tail[q1..].find('"').unwrap() + q1;
        let hex: String = a
            .content
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect())
            .unwrap_or_default();
        if hex != tail[q1..q2] {
            bad.push(format!("{}: content does not match the manifest", symbol));
        }
    }
    println!("chain {} — items checked: 333", chain);
    println!("mismatches: {}", if bad.is_empty() { "none".to_string() } else { bad.join("; ") });
}
