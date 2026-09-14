//! Derived addresses — Solana's PDA idea, without the part that was a
//! workaround.
//!
//! An address computed from a program and a list of seeds:
//!
//! ```text
//!   pool  = derive(zynzap, "pool", [asset0, asset1])
//!   vault = derive(zynzap, "vault", [pool])
//! ```
//!
//! Three properties, all of which our monotonic `u32` ids lack:
//!
//! 1. **Computable offline.** A client derives a pool's address before it
//!    exists and before talking to any node. A swap UI can build a route with
//!    no round trip, and a route is not hostage to a receipt it has not read
//!    yet.
//! 2. **Content-addressed.** The same pair yields the same address on every
//!    chain that follows the spec. A monotonic id depends on the order intents
//!    happened to be sequenced, so two chains holding the same pools can
//!    disagree about their names.
//! 3. **No allocation and no scan.** Derive, do not look up. `find_pool`
//!    currently walks every pool because a maintained index is a second thing
//!    that can disagree with the data it came from; a derivation cannot
//!    disagree with anything.
//!
//! # What we drop from PDAs, and why
//!
//! Solana addresses are ed25519 public keys, so a program-owned address has to
//! be proved to have *no* private key — hence the off-curve requirement and the
//! bump seed ground down from 255. That is a workaround for addresses being
//! keys.
//!
//! Zyn's [`crate::spec::AccountId`] is an opaque 32-byte identity with no curve
//! behind it, so there is nothing to be off. No bump, no grinding loop, no
//! canonical-bump confusion — the derivation is one hash.
//!
//! # What we fix
//!
//! Solana concatenates seeds. `["ab", "c"]` and `["a", "bc"]` therefore produce
//! the same preimage, which is only survivable because seeds are individually
//! length-capped. That is a sharp edge inherited rather than chosen, so this
//! length-prefixes every seed: two different seed lists cannot collide, at any
//! length.

use sha2::{Digest, Sha256};

/// A derived address. The same 32 bytes as an account id, deliberately: a
/// derived address *is* an account id, so a pool can hold a balance through the
/// ordinary path and be proved through the ordinary exit hatch.
pub type Address = [u8; 32];

/// Domain tag, so a derived address can never collide with a leaf, an internal
/// node, or an intent commitment.
const DERIVE_DOMAIN: &[u8] = b"zyn.derive.v1";

/// Derive an address under a program from a namespace and a list of seeds.
///
/// `program` scopes the address so two applications on the same microchain
/// cannot derive each other's. `namespace` separates kinds within one program
/// — a pool from a vault from an LP asset — so `["pool", x]` and
/// `["vault", x]` are unrelated.
pub fn derive(program: &[u8], namespace: &[u8], seeds: &[&[u8]]) -> Address {
    let mut h = Sha256::new();
    h.update(DERIVE_DOMAIN);
    // Every component is length-prefixed, so no regrouping of the same bytes
    // produces the same preimage.
    h.update((program.len() as u32).to_be_bytes());
    h.update(program);
    h.update((namespace.len() as u32).to_be_bytes());
    h.update(namespace);
    h.update((seeds.len() as u32).to_be_bytes());
    for s in seeds {
        h.update((s.len() as u32).to_be_bytes());
        h.update(s);
    }
    h.finalize().into()
}

/// Derive under a VM's own identity, which is the usual case.
///
/// The program scope is the VM name and version, so an address derived by
/// ZynZap v1 is not the address ZynZap v2 derives from the same seeds — a
/// version bump that changes what a record means should change where it lives.
pub fn derive_for<V: crate::spec::MicrochainVm>(namespace: &[u8], seeds: &[&[u8]]) -> Address {
    derive(&program_scope::<V>(), namespace, seeds)
}

/// The program scope for a VM: its name followed by its version, big-endian.
///
/// Split out and made exact because it was wrong. The version used to be
/// written at a fixed offset in a 34-byte buffer while only the first
/// `name.len() + 2` bytes were hashed, so for any name shorter than 32 bytes
/// the version bytes sat outside the preimage and every version derived the
/// same addresses — the precise opposite of what §4 promises. A bug that
/// silently collapses two namespaces into one cannot be caught by a test that
/// only checks a derivation is deterministic, which is why there is now a test
/// asserting two versions disagree.
pub fn program_scope<V: crate::spec::MicrochainVm>() -> alloc::vec::Vec<u8> {
    program_scope_of(V::VM_NAME, V::VM_VERSION)
}

/// The program scope from a name and version directly.
///
/// Non-generic so the scope can be built by a client that has no VM type to
/// hand — and so the rule that the version is *in* the preimage can be tested
/// without standing up a whole VM, which is why the original bug survived.
pub fn program_scope_of(name: &str, version: u16) -> alloc::vec::Vec<u8> {
    try_program_scope_of(name, version).expect("VM name longer than 32 bytes")
}

/// The frozen scope for **persistent identities** (§66.10).
///
/// Assets, pools, collections and items must not move when `VM_VERSION` or
/// `STATE_VERSION` advances — an execution change is not a re-identification of
/// everything the chain holds. So persistent addresses derive under this
/// constant rather than under the live VM version, and changing it is an
/// explicit address-schema fork, not a side effect of shipping a new VM.
///
/// Its bytes are what `program_scope_of("zynzap", 2)` produced when the genesis
/// address table was pinned, so freezing it moves nothing.
pub const ADDRESS_SCOPE_V1: &[u8] = b"zynzap\x00\x02";

/// Like [`program_scope_of`], but returns `None` for a name over 32 bytes.
///
/// Truncating was the original behaviour and is worse than refusing: two VMs
/// whose names share a 32-byte prefix would silently derive each other's
/// addresses, which is the collision the program scope exists to prevent
/// (§66.10).
pub fn try_program_scope_of(name: &str, version: u16) -> Option<alloc::vec::Vec<u8>> {
    let name = name.as_bytes();
    if name.len() > 32 {
        return None;
    }
    let mut program = alloc::vec::Vec::with_capacity(name.len() + 2);
    program.extend_from_slice(name);
    program.extend_from_slice(&version.to_be_bytes());
    Some(program)
}

/// A canonically ordered pair of addresses.
///
/// A pool over `(A, B)` and one over `(B, A)` must be the same pool, or the
/// pair has two names and liquidity splits between them. Sorting the seeds is
/// what makes the derivation itself enforce that, rather than a rule every
/// caller has to remember.
pub fn ordered_pair(a: &Address, b: &Address) -> [Address; 2] {
    if a <= b {
        [*a, *b]
    } else {
        [*b, *a]
    }
}

/// Derive the address of a pool over an unordered pair.
pub fn pool_address(program: &[u8], a: &Address, b: &Address) -> Address {
    let [lo, hi] = ordered_pair(a, b);
    derive(program, b"pool", &[&lo, &hi])
}

/// Derive the LP asset for a pool.
pub fn lp_address(program: &[u8], pool: &Address) -> Address {
    derive(program, b"lp", &[pool])
}

/// Derive a program-controlled holding address.
///
/// The other half of what PDAs are for: an address the program can move value
/// from because the runtime grants authority by derivation, not by signature.
/// Zyn has no signature check inside the VM at all — the sequencer establishes
/// authorisation upstream — so here the derivation is purely a naming
/// discipline. It becomes an authority mechanism the moment a VM holds value at
/// an address no user should be able to spend from.
pub fn vault_address(program: &[u8], owner: &Address) -> Address {
    derive(program, b"vault", &[owner])
}

/// Derive the address of a chain's **own** token.
///
/// The Zyn chain id is a seed because this asset represents value on one
/// specific chain: without it, mainnet ZYN and testnet ZYN are the same 32
/// bytes, and an address shown on its own could not tell a holder which one
/// they have. Bridged assets do not need this — their origin network already
/// distinguishes them — so the scoping goes exactly where the ambiguity is.
pub fn native_address(program: &[u8], chain_id: u32, symbol: &[u8]) -> Address {
    derive(program, b"native", &[&chain_id.to_be_bytes(), symbol])
}

/// Derive the address of a bridged asset.
///
/// `origin_network` names the network the asset actually comes from, not the
/// chain family: `b"zcash"` and `b"zcash-test"` are different assets because
/// ZEC and TAZ are different assets, and a testnet bridge that minted something
/// addressed as mainnet ZEC would be claiming backing it does not have.
///
/// `origin_asset` is empty for a network's own coin and carries the origin
/// contract or mint for a token issued on it, so the address can be recomputed
/// from public facts about the other chain with nothing to look up here.
pub fn bridged_address(program: &[u8], origin_network: &[u8], origin_asset: &[u8]) -> Address {
    derive(program, b"bridged", &[origin_network, origin_asset])
}

/// Derive the address of a user-launched token.
///
/// Keyed by creator and symbol, so two creators may both issue `CAT` and get
/// different addresses, while one creator cannot issue `CAT` twice.
pub fn asset_address(program: &[u8], creator: &Address, symbol: &[u8]) -> Address {
    derive(program, b"asset", &[creator, symbol])
}

/// Derive the address of an item collection.
pub fn collection_address(program: &[u8], creator: &Address, symbol: &[u8]) -> Address {
    derive(program, b"collection", &[creator, symbol])
}

/// Derive an item's id within its collection, from its serial number.
///
/// Derived rather than allocated so that every item's identity is computable
/// before the collection mints — which is what a reveal schedule or an
/// allowlist needs — and so that two nodes cannot disagree about which item is
/// which. [`crate::collection::item_leaf`] binds the collection address into
/// the leaf as well, so an item proved against one collection cannot be
/// replayed against another.
pub fn item_address(program: &[u8], collection: &Address, serial: u32) -> Address {
    derive(program, b"item", &[collection, &serial.to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn addr(n: u8) -> Address {
        [n; 32]
    }

    fn hex(a: &Address) -> alloc::string::String {
        use core::fmt::Write as _;
        let mut o = alloc::string::String::new();
        for b in a {
            let _ = write!(o, "{:02x}", b);
        }
        o
    }

    /// §66.10: a VM name over 32 bytes is refused, not truncated. Truncating
    /// would let two VMs sharing a 32-byte prefix derive each other's
    /// addresses — the exact collision the program scope exists to prevent.
    #[test]
    fn an_over_long_vm_name_is_refused_rather_than_truncated() {
        let long = "z".repeat(33);
        assert!(
            try_program_scope_of(&long, 2).is_none(),
            "33 bytes must be refused"
        );
        let at_limit = "z".repeat(32);
        assert!(
            try_program_scope_of(&at_limit, 2).is_some(),
            "32 bytes is still valid"
        );
        // Two names that a truncating implementation would have conflated.
        let a = "z".repeat(32) + "a";
        let b = "z".repeat(32) + "b";
        assert!(try_program_scope_of(&a, 2).is_none() && try_program_scope_of(&b, 2).is_none());
    }

    /// The frozen scope must equal what the genesis table was pinned under, or
    /// freezing it would silently move every persistent address (§66.10).
    #[test]
    fn the_frozen_address_scope_is_the_scope_the_table_was_pinned_under() {
        assert_eq!(ADDRESS_SCOPE_V1, &program_scope_of("zynzap", 2)[..]);
        assert_eq!(
            native_address(ADDRESS_SCOPE_V1, 26460, b"ZYN"),
            native_address(&program_scope_of("zynzap", 2), 26460, b"ZYN"),
        );
    }

    /// The genesis address table, pinned.
    ///
    /// These are the addresses ZynZap v2 gives the first assets. They are
    /// asserted rather than documented because a silent change to the
    /// derivation would otherwise only be discovered by a wallet showing a
    /// balance at an address nothing else recognises. If this test fails, the
    /// derivation changed and every published address moved with it — that is
    /// a fork, not a refactor.
    #[test]
    fn the_genesis_addresses_are_what_was_published() {
        let p = program_scope_of("zynzap", 2);
        for (label, got, want) in [
            (
                "ZYN mainnet",
                native_address(&p, 26460, b"ZYN"),
                "49eb9241e2a0b1163a1eed09bb91a575c93bbc6e76cd7afeb65263640fd169d5",
            ),
            (
                "ZYN testnet",
                native_address(&p, 11, b"ZYN"),
                "893e745e33b40310003011a14651dc3cf173f71b92ee6e77ef62b7ba5a84e56e",
            ),
            (
                "ZEC.zy",
                bridged_address(&p, b"zcash", b""),
                "0e212262cb35bf6e88bc7d0a52b60a5cc70c2859b65966a2557229d2ea469201",
            ),
            (
                "TAZ.zy",
                bridged_address(&p, b"zcash-test", b""),
                "bf244a27ad73fea5128fead691c647fe1c5a5cddde0a847b24ca20041250da48",
            ),
            (
                "SOL.zy",
                bridged_address(&p, b"solana", b""),
                "0f61f4340cd6a910ec8d7e73ef239569b83f16099e620786e71e7e7395c9f6df",
            ),
            (
                "BTC.zy",
                bridged_address(&p, b"bitcoin", b""),
                "0e7faa55f3bdb12e80781da88fb5ac4eb7e24d1935494b9aabd84c4565bbffca",
            ),
            (
                "BOLD.zy",
                bridged_address(
                    &p,
                    b"eip155:1",
                    &[
                        0x64, 0x40, 0xf1, 0x44, 0xb7, 0xe5, 0x0d, 0x6a, 0x84, 0x39, 0x33, 0x65,
                        0x10, 0x31, 0x2d, 0x2f, 0x54, 0xbe, 0xb0, 0x1d,
                    ],
                ),
                "ddf2b7ecc2634e39a891a19020205ae26a87e9f753e492e03b84e7dc627f250f",
            ),
        ] {
            assert_eq!(hex(&got), want, "{} moved", label);
        }

        // And the pools over them, which follow from the assets alone.
        let zyn = native_address(&p, 26460, b"ZYN");
        let zec = bridged_address(&p, b"zcash", b"");
        let sol = bridged_address(&p, b"solana", b"");
        let btc = bridged_address(&p, b"bitcoin", b"");
        assert_eq!(
            hex(&pool_address(&p, &zec, &zyn)),
            "4d9b08dbee9c82781b59dfa144730399c2b23ad320a2610601702ff305ddd999"
        );
        assert_eq!(
            hex(&pool_address(&p, &sol, &zec)),
            "142639c35adc1be4183c2268146f069d3b188988cb143b89be7ba1a67b2b68d7"
        );
        assert_eq!(
            hex(&pool_address(&p, &btc, &zec)),
            "ed3fef337e34a8c7b3343fc832f9ae4c289226cb51cebd5813b53746df18cab8"
        );
    }

    /// The version used to land outside the hashed slice, so every version of a
    /// VM derived the same addresses. §4 promises the opposite, and a bug that
    /// collapses two scopes into one is invisible to any test that only checks
    /// determinism.
    #[test]
    fn two_vm_versions_do_not_share_addresses() {
        let v1 = program_scope_of("zynzap", 1);
        let v2 = program_scope_of("zynzap", 2);
        assert_ne!(
            v1, v2,
            "the version must be inside the scope, not beside it"
        );
        assert_eq!(v2, b"zynzap\x00\x02", "name then version, big-endian");
        assert_ne!(
            derive(&v1, b"native", &[b"ZYN"]),
            derive(&v2, b"native", &[b"ZYN"]),
            "a version bump must move every address it derives"
        );
    }

    /// ZEC and TAZ are different assets. A testnet bridge minting something
    /// addressed as mainnet ZEC would claim backing it does not hold.
    #[test]
    fn a_testnet_origin_is_a_different_asset_from_its_mainnet_one() {
        let p = b"zynzap\x00\x02";
        assert_ne!(
            bridged_address(p, b"zcash", b""),
            bridged_address(p, b"zcash-test", b""),
        );
    }

    /// A network's own coin and a token issued on it must not collide, and two
    /// tokens on one network must not either.
    #[test]
    fn a_bridged_coin_and_a_token_on_the_same_network_differ() {
        let p = b"zynzap\x00\x02";
        let mint_a = [7u8; 32];
        let mint_b = [8u8; 32];
        assert_ne!(
            bridged_address(p, b"solana", b""),
            bridged_address(p, b"solana", &mint_a)
        );
        assert_ne!(
            bridged_address(p, b"solana", &mint_a),
            bridged_address(p, b"solana", &mint_b)
        );
    }

    /// Without the chain id, mainnet ZYN and testnet ZYN are one address and a
    /// holder cannot tell from it which chain's token they hold.
    #[test]
    fn a_chains_own_token_is_scoped_to_that_chain() {
        let p = b"zynzap\x00\x02";
        assert_ne!(
            native_address(p, 26460, b"ZYN"),
            native_address(p, 11, b"ZYN")
        );
    }

    /// Two creators may both issue `CAT`; one creator may not issue it twice.
    #[test]
    fn a_symbol_is_unique_per_creator_not_globally() {
        let p = b"zynzap\x00\x02";
        assert_ne!(
            asset_address(p, &addr(1), b"CAT"),
            asset_address(p, &addr(2), b"CAT")
        );
        assert_eq!(
            asset_address(p, &addr(1), b"CAT"),
            asset_address(p, &addr(1), b"CAT")
        );
    }

    /// Every kind of address stays in its own namespace, including the ones
    /// that take the same seeds.
    #[test]
    fn a_collection_and_a_token_from_one_creator_and_symbol_differ() {
        let p = b"zynzap\x00\x02";
        assert_ne!(
            asset_address(p, &addr(3), b"CAVE"),
            collection_address(p, &addr(3), b"CAVE")
        );
    }

    /// Item ids are computable before a collection mints, and distinct.
    #[test]
    fn item_ids_are_derivable_in_advance_and_distinct() {
        let p = b"zynzap\x00\x02";
        let c = collection_address(p, &addr(4), b"CAVE");
        let ids: Vec<Address> = (0..4444).map(|i| item_address(p, &c, i)).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ids.len(),
            "4,444 serials must give 4,444 distinct ids"
        );
        assert_eq!(
            item_address(p, &c, 0),
            ids[0],
            "and recomputing one offline agrees"
        );
    }

    #[test]
    fn derivation_is_deterministic_and_offline() {
        // The property the whole idea rests on: no state, no lookup, no node.
        let a = pool_address(b"zynzap", &addr(1), &addr(2));
        let b = pool_address(b"zynzap", &addr(1), &addr(2));
        assert_eq!(a, b);
    }

    #[test]
    fn a_pair_has_exactly_one_address() {
        // Otherwise CAT/ZEC.zy and ZEC.zy/CAT are two pools and liquidity splits.
        assert_eq!(
            pool_address(b"zynzap", &addr(1), &addr(2)),
            pool_address(b"zynzap", &addr(2), &addr(1))
        );
        assert_ne!(
            pool_address(b"zynzap", &addr(1), &addr(2)),
            pool_address(b"zynzap", &addr(1), &addr(3))
        );
    }

    /// The sharp edge Solana inherited: concatenated seeds mean `["ab","c"]`
    /// and `["a","bc"]` share a preimage. Length-prefixing removes it.
    #[test]
    fn regrouping_the_same_bytes_does_not_collide() {
        let x = derive(b"p", b"n", &[b"ab", b"c"]);
        let y = derive(b"p", b"n", &[b"a", b"bc"]);
        let z = derive(b"p", b"n", &[b"abc"]);
        assert_ne!(x, y);
        assert_ne!(y, z);
        assert_ne!(x, z);

        // Including the empty-seed cases, where a naive concatenation is worst.
        assert_ne!(
            derive(b"p", b"n", &[b"", b"a"]),
            derive(b"p", b"n", &[b"a", b""])
        );
        assert_ne!(
            derive(b"p", b"n", &[b"a"]),
            derive(b"p", b"n", &[b"a", b""])
        );
    }

    #[test]
    fn a_boundary_between_program_and_namespace_cannot_be_slid() {
        // "zyn" + "zap" must not equal "zynzap" + "".
        assert_ne!(derive(b"zyn", b"zap", &[]), derive(b"zynzap", b"", &[]));
    }

    #[test]
    fn namespaces_separate_kinds() {
        let pool = addr(7);
        assert_ne!(
            lp_address(b"zynzap", &pool),
            vault_address(b"zynzap", &pool)
        );
        assert_ne!(
            lp_address(b"zynzap", &pool),
            derive(b"zynzap", b"pool", &[&pool])
        );
    }

    #[test]
    fn programs_cannot_derive_each_others_addresses() {
        // The isolation that matters once Zyn hosts more than one application.
        assert_ne!(
            pool_address(b"zynzap", &addr(1), &addr(2)),
            pool_address(b"other", &addr(1), &addr(2))
        );
    }

    #[test]
    fn a_derived_address_is_not_a_commitment_leaf() {
        // Domain separation against the rest of the crate's hashing, so a
        // derived address can never be mistaken for a tree node.
        assert_ne!(derive(b"", b"", &[]), crate::commit::hash_leaf(b""));
        assert_ne!(
            derive(b"", b"", &[]),
            crate::commit::hash_node(&[0u8; 32], &[0u8; 32])
        );
    }

    /// Grinding resistance is the reason addresses are full width. A truncated
    /// id would let an attacker search for a collision with an existing pool;
    /// at 32 bytes there is nothing to search.
    #[test]
    fn distinct_inputs_stay_distinct_in_bulk() {
        let mut seen: Vec<Address> = Vec::new();
        for i in 0..64u8 {
            for j in 0..64u8 {
                if i < j {
                    seen.push(pool_address(b"zynzap", &addr(i), &addr(j)));
                }
            }
        }
        let before = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            before,
            "two distinct pairs derived the same address"
        );
    }
}

#[cfg(test)]
mod client_tests {
    //! The property a swap frontend actually cares about.

    use super::*;

    /// Stand-in for the seeds a client already has: it knows the two assets it
    /// wants to trade, because the user picked them.
    fn asset(sym: &str) -> Address {
        derive(b"zynzap", b"asset", &[sym.as_bytes()])
    }

    /// A route built with no node, no receipt and no round trip.
    ///
    /// Today a client must submit `CreatePool`, read the `PoolCreated` receipt,
    /// and learn the id the sequencer happened to assign — so a route cannot be
    /// constructed until the chain has answered. With derived addresses the
    /// whole path is computable from the pair the user picked.
    #[test]
    fn a_client_can_build_a_route_offline() {
        let xzec = asset("ZEC.zy");
        let cat = asset("CAT");
        let dog = asset("DOG");

        // CAT -> ZEC.zy -> DOG, derived rather than looked up.
        let hop1 = pool_address(b"zynzap", &cat, &xzec);
        let hop2 = pool_address(b"zynzap", &xzec, &dog);
        assert_ne!(hop1, hop2);

        // A node that has the pools derives exactly the same addresses, which
        // is what makes the offline route the same route.
        assert_eq!(hop1, pool_address(b"zynzap", &xzec, &cat));
        assert_eq!(hop2, pool_address(b"zynzap", &dog, &xzec));

        // And the LP asset the route's pools mint, for a position UI.
        assert_ne!(lp_address(b"zynzap", &hop1), lp_address(b"zynzap", &hop2));
    }

    /// Addresses do not depend on the order intents were sequenced, so two
    /// chains that ended up with the same pools agree on their names.
    #[test]
    fn addressing_is_independent_of_history() {
        let (a, b, c) = (asset("CAT"), asset("DOG"), asset("ZEC.zy"));
        // One chain created CAT/ZEC.zy first, another created DOG/ZEC.zy first.
        // Under monotonic ids they would disagree; under derivation they cannot.
        let chain_1 = [
            pool_address(b"zynzap", &a, &c),
            pool_address(b"zynzap", &b, &c),
        ];
        let chain_2 = [
            pool_address(b"zynzap", &b, &c),
            pool_address(b"zynzap", &a, &c),
        ];
        assert_eq!(chain_1[0], chain_2[1]);
        assert_eq!(chain_1[1], chain_2[0]);
    }
}
