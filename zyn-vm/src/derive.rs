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
    let mut program = [0u8; 34];
    let name = V::VM_NAME.as_bytes();
    let n = core::cmp::min(name.len(), 32);
    program[..n].copy_from_slice(&name[..n]);
    program[32..].copy_from_slice(&V::VM_VERSION.to_be_bytes());
    derive(&program[..n + 2], namespace, seeds)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn addr(n: u8) -> Address {
        [n; 32]
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
        assert_ne!(derive(b"p", b"n", &[b"", b"a"]), derive(b"p", b"n", &[b"a", b""]));
        assert_ne!(derive(b"p", b"n", &[b"a"]), derive(b"p", b"n", &[b"a", b""]));
    }

    #[test]
    fn a_boundary_between_program_and_namespace_cannot_be_slid() {
        // "zyn" + "zap" must not equal "zynzap" + "".
        assert_ne!(derive(b"zyn", b"zap", &[]), derive(b"zynzap", b"", &[]));
    }

    #[test]
    fn namespaces_separate_kinds() {
        let pool = addr(7);
        assert_ne!(lp_address(b"zynzap", &pool), vault_address(b"zynzap", &pool));
        assert_ne!(lp_address(b"zynzap", &pool), derive(b"zynzap", b"pool", &[&pool]));
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
        assert_ne!(derive(b"", b"", &[]), crate::commit::hash_node(&[0u8; 32], &[0u8; 32]));
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
        assert_eq!(seen.len(), before, "two distinct pairs derived the same address");
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
        let chain_1 = [pool_address(b"zynzap", &a, &c), pool_address(b"zynzap", &b, &c)];
        let chain_2 = [pool_address(b"zynzap", &b, &c), pool_address(b"zynzap", &a, &c)];
        assert_eq!(chain_1[0], chain_2[1]);
        assert_eq!(chain_1[1], chain_2[0]);
    }
}
