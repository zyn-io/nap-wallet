//! Is the chain's Zcash clock advancing? The market's grace period depends on it.
fn main() {
    let node = std::env::var("ZYN_GENESIS_NODE").unwrap_or("127.0.0.1:18099".into());
    let chain: u32 = std::env::var("ZYN_GENESIS_CHAIN")
        .unwrap_or("26460".into())
        .parse()
        .unwrap();
    let c = zynzapd::client::Node::new(&node, chain);
    let v = c.pots().expect("pots");
    println!("chain {} — zcash height {}", chain, v.zcash_height);
    match v.schedule {
        None => println!("market: no date yet (the POL pot has not filled)"),
        Some(s) => println!(
            "market: armed {} opens {} ({} blocks to go)",
            s.armed,
            s.opens,
            s.blocks_remaining(v.zcash_height)
        ),
    }
}
