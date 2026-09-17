//! Check ZYN's genesis: the supply, where it sits, and that it cannot grow.
fn main() {
    let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let chain: u32 = env("ZYN_GENESIS_CHAIN", "26460").parse().expect("chain");
    let c = zynzapd::client::Node::new(&env("ZYN_GENESIS_NODE", "127.0.0.1:18099"), chain);

    // ZYN is native, so its address comes from the chain id, not from any
    // account. On chain 26460 this must equal the pinned `ZYN_MAINNET`.
    let zyn = zyn_vm::native_address(zyn_vm::derive::ADDRESS_SCOPE_V1, chain, b"ZYN");
    if chain == 26_460 {
        assert_eq!(zyn, swapvm::types::ZYN_MAINNET, "ZYN must be the pinned mainnet asset");
    }
    assert!(
        swapvm::types::is_official_asset(chain, &zyn) || chain != 26_460,
        "ZYN must read as an official asset"
    );

    let a = c.assets().expect("assets");
    let t = a.iter().find(|x| x.id == zyn).expect("ZYN is on chain");
    println!("ZYN            {}", hex(&t.id));
    println!("supply         {}", t.supply);
    println!("supply_policy  {:?}", t.supply_policy);
    assert_eq!(
        t.supply_policy,
        swapvm::state::SupplyPolicy::Fixed,
        "ZYN must carry no mint authority"
    );

    // Where it sits. Read back from the chain, not from what we meant to send.
    let view = c.pots().expect("pots");
    let pots = &view.pots;
    let held = |name: &str| -> swapvm::fixed::Fixed {
        pots.iter()
            .find(|(n, _, _)| n == name)
            .map(|(_, _, hs)| {
                hs.iter()
                    .filter(|(a, _)| *a == zyn)
                    .fold(swapvm::fixed::Fixed::ZERO, |s, (_, amt)| s.add(*amt).unwrap())
            })
            .unwrap_or(swapvm::fixed::Fixed::ZERO)
    };
    // At genesis everything is in the reserve; the POL pot fills from accrual.
    for (name, want) in [("zyn-pol-zyn", 0i64), ("zyn-reserve", 21_000_000i64)] {
        let b = held(name);
        println!("{:<12}   {}", name, b);
        assert_eq!(b, swapvm::fixed::Fixed::whole(want), "{} holds the wrong amount", name);
    }
    let total = held("zyn-pol-zyn").add(held("zyn-reserve")).unwrap();
    assert_eq!(total, t.supply, "every issued unit must be in a pot");

    match view.schedule {
        None => println!("market: not due — the POL pot has not filled"),
        Some(sch) => println!(
            "market: armed at Zcash {}, opens at {} ({} blocks to go)",
            sch.armed,
            sch.opens,
            sch.blocks_remaining(view.zcash_height)
        ),
    }
    println!("ok — 21,000,000 ZYN, fixed, all of it in the keyless pots");
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
