//! What a transaction says it is.
//!
//! A spend does not merely move objects; it moves them *under some rule*. A
//! private transfer conserves value. A swap conserves it against a pool's
//! invariant. Adding liquidity conserves it into a position. Same objects,
//! same nullifiers, different law — and something has to name which law the
//! transaction was meant to obey, or the verifier is guessing.
//!
//! ```text
//!   Transaction {
//!       inputs · outputs · nullifiers · public state
//!       program_id    ← this
//!       proof
//!   }
//! ```
//!
//! # Why this field exists before anything needs it
//!
//! Today every one of these maps to a fixed rule the VM enforces directly.
//! Later some of them map to a proof that an arbitrary program ran (DECISIONS
//! §131). The difference between those two worlds is entirely on the verifier's
//! side — the *transaction* looks identical — but only if the field is there
//! from the start. Added afterwards it is a `STATE_VERSION` bump and a
//! coordinated replacement of every node, which §71.34 is explicit about.
//!
//! One field now, while `objectvm` exists only in tests, is the whole cost.
//!
//! # Why a fixed id can never collide with a program hash
//!
//! Both are 32 bytes, and a caller who could make a zkVM program whose hash
//! equals [`private_transfer`] would have a program the VM executes under the
//! transfer rule without checking it. The two are therefore derived under
//! **different domains**: a named rule hashes its name, a program hashes its
//! code, and no input to one is an input to the other.

use crate::commit::{Encoder, Hash};

/// Which rule a transaction claims to obey.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct ProgramId(pub Hash);

/// Domain for the rules the VM implements itself.
const NAMED: &[u8] = b"zyn.program.named.v1";
/// Domain for a program named by its code. Distinct from [`NAMED`] so that no
/// program hash can ever equal a named rule's id.
const CODE: &[u8] = b"zyn.program.code.v1";

fn named(name: &[u8]) -> ProgramId {
    let mut e = Encoder::new();
    e.bytes(NAMED).u32(name.len() as u32).bytes(name);
    ProgramId(e.leaf())
}

/// Consume objects and create others, conserving value. The rule behind
/// transfer, split and merge, which are the same transaction seen three ways.
pub fn private_transfer() -> ProgramId {
    named(b"private-transfer")
}

/// Trade against a pool, conserving value under the pool's invariant.
pub fn amm_swap() -> ProgramId {
    named(b"amm-swap")
}

/// Convert objects into a liquidity position.
pub fn add_liquidity() -> ProgramId {
    named(b"add-liquidity")
}

/// Turn a position back into objects.
pub fn remove_liquidity() -> ProgramId {
    named(b"remove-liquidity")
}

/// Leave for Zcash: consume objects and authorise a vault payout.
pub fn withdraw() -> ProgramId {
    named(b"withdraw")
}

/// Record that the vault paid an exit it owed.
///
/// Separate from [`withdraw`] because they are different claims made by
/// different parties: a holder says "I am leaving", and later the operator
/// says "I paid them, here is the transaction". Collapsing the two would mean
/// the chain forgot the debt at the moment it was incurred, and nobody could
/// see an exit that was owed and never honoured.
pub fn settle_exit() -> ProgramId {
    named(b"settle-exit")
}

/// Publish where to pay an account: bind it to a viewing key.
///
/// An account id is `H(domain ‖ scheme ‖ len ‖ key)` and one-way, so nobody —
/// including the sequencer crediting a deposit — can recover a viewing key
/// from it. Somebody paying you has to be told, and this is the telling. It
/// is the object ledger's equivalent of having an address at all.
pub fn register_viewing_key() -> ProgramId {
    named(b"register-viewing-key")
}

/// Create an object against ZEC confirmed in the vault. The one rule that
/// makes value rather than moving it, which is why it names an external
/// reference the backing signers can check (DECISIONS §130.13).
pub fn deposit() -> ProgramId {
    named(b"deposit")
}

/// Encumber an object against a price, without moving it (DECISIONS §132.1).
pub fn place_offer() -> ProgramId {
    named(b"place-offer")
}

/// Lift an encumbrance. Transfers nothing, because nothing was transferred.
pub fn cancel_offer() -> ProgramId {
    named(b"cancel-offer")
}

/// Pay the asked price and take the encumbered object, atomically
/// (DECISIONS §132.2). The only rule permitted to spend an object it does not
/// own — the entitlement comes from the encumbrance, not from a signature.
pub fn take_offer() -> ProgramId {
    named(b"take-offer")
}

/// Redeem what the ledger owes an account — a swap's proceeds, a refund, a
/// launch allocation — into objects its owner encrypted for themselves.
pub fn claim() -> ProgramId {
    named(b"claim")
}

/// Open a token sale: issue a token into escrow against a raise.
pub fn launch_create() -> ProgramId {
    named(b"launch-create")
}

/// Commit to a sale. Escrowed until the sale closes, then allocated at one
/// price for everybody or refunded.
pub fn launch_commit() -> ProgramId {
    named(b"launch-commit")
}

/// Set the chain's fee schedule. The operator's act, recorded like any other,
/// so every replica charges exactly what the chain charged.
pub fn configure_fees() -> ProgramId {
    named(b"configure-fees")
}

/// Give a collection its resale terms: creator, quote asset and fee.
pub fn register_collection() -> ProgramId {
    named(b"register-collection")
}

/// Mint one item of a registered collection to its buyer: the primary sale.
pub fn mint_item() -> ProgramId {
    named(b"mint-item")
}

/// Burn items for their share of the collection's redemption floor.
pub fn redeem_item() -> ProgramId {
    named(b"redeem-item")
}

/// Open a collection's primary sale: its ticket, claim and open-mint prices
/// (DECISIONS §144). Operator only.
pub fn sale_open() -> ProgramId {
    named(b"sale-open")
}

/// Buy lottery tickets in a collection's primary sale.
pub fn sale_tickets() -> ProgramId {
    named(b"sale-tickets")
}

/// Close a sale at the announced Zcash height. Operator only.
pub fn sale_close() -> ProgramId {
    named(b"sale-close")
}

/// Post the draw's result root. Operator only.
pub fn sale_draw() -> ProgramId {
    named(b"sale-draw")
}

/// Claim a ticket's drawn items against the posted root.
pub fn sale_claim() -> ProgramId {
    named(b"sale-claim")
}

/// End claims and post the open-mint order. Operator only.
pub fn sale_open_mint() -> ProgramId {
    named(b"sale-open-mint")
}

/// Mint the next item of the open-mint order.
pub fn sale_mint() -> ProgramId {
    named(b"sale-mint")
}

/// Burn tickets: set a sale's cap on them, and post one burn's tickets.
/// Operator only (DECISIONS §145).
pub fn sale_vouchers() -> ProgramId {
    named(b"sale-vouchers")
}

/// Register an asset bridged from another chain beside ZEC. Operator only
/// (DECISIONS §146).
pub fn bridge_register() -> ProgramId {
    named(b"bridge-register")
}

/// Open a lending pool for an asset, with its collateral risk. Operator only.
pub fn lend_list() -> ProgramId {
    named(b"lend-list")
}

/// Post the prices and time lending runs on. Operator only.
pub fn lend_prices() -> ProgramId {
    named(b"lend-prices")
}

/// Lend an asset into its pool for receipt shares.
pub fn lend_supply() -> ProgramId {
    named(b"lend-supply")
}

/// Burn receipt shares for the asset they are worth.
pub fn lend_withdraw() -> ProgramId {
    named(b"lend-withdraw")
}

/// Lock collateral and borrow against it.
pub fn lend_open() -> ProgramId {
    named(b"lend-open")
}

/// Pay down a position's debt.
pub fn lend_repay() -> ProgramId {
    named(b"lend-repay")
}

/// Add collateral to a position, or take some out within its limit.
pub fn lend_collateral() -> ProgramId {
    named(b"lend-collateral")
}

/// Bid in a liquidation auction.
pub fn lend_bid() -> ProgramId {
    named(b"lend-bid")
}

/// Add to a lending pool's insurance (rules v2, DECISIONS §160).
pub fn lend_insure() -> ProgramId {
    named(b"lend-insure")
}

/// Make a bonding-curve token (DECISIONS §141).
pub fn curve_create() -> ProgramId {
    named(b"curve-create")
}

/// Buy from or sell to a token's bonding curve.
pub fn curve_trade() -> ProgramId {
    named(b"curve-trade")
}

/// Set what curves charge: the trading fee and the creation bond.
pub fn configure_curves() -> ProgramId {
    named(b"configure-curves")
}

/// A program named by its code rather than by a rule the VM knows.
///
/// `code` is the hash of the program as shipped — an rv32im ELF, per §2.5's
/// Stage 1. Nothing accepts one of these yet, and teaching a VM to accept them
/// is the deliberate act that opens permissionless deployment. It should look
/// like a decision in a diff, not like a default.
pub fn of_code(code: &Hash) -> ProgramId {
    let mut e = Encoder::new();
    e.bytes(CODE).bytes(code);
    ProgramId(e.leaf())
}

/// Whether this is a rule the VM implements directly.
///
/// A VM should refuse anything else rather than ignore it: an unknown program
/// id on a transaction that otherwise verifies is a transaction obeying a rule
/// nobody checked.
pub fn is_named(id: &ProgramId) -> bool {
    [
        private_transfer(),
        amm_swap(),
        add_liquidity(),
        remove_liquidity(),
        withdraw(),
        place_offer(),
        cancel_offer(),
        take_offer(),
        deposit(),
        register_viewing_key(),
        settle_exit(),
        claim(),
        launch_create(),
        launch_commit(),
        configure_fees(),
        register_collection(),
        redeem_item(),
        mint_item(),
        curve_create(),
        curve_trade(),
        configure_curves(),
        sale_open(),
        sale_tickets(),
        sale_close(),
        sale_draw(),
        sale_claim(),
        sale_open_mint(),
        sale_mint(),
        sale_vouchers(),
        bridge_register(),
        lend_list(),
        lend_prices(),
        lend_supply(),
        lend_withdraw(),
        lend_open(),
        lend_repay(),
        lend_collateral(),
        lend_bid(),
    ]
    .contains(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Distinct rules must be distinct ids, or a swap could be presented as a
    /// transfer and checked under the wrong law.
    #[test]
    fn every_named_rule_has_its_own_id() {
        let all = [
            private_transfer(),
            amm_swap(),
            add_liquidity(),
            remove_liquidity(),
            withdraw(),
            place_offer(),
            cancel_offer(),
            take_offer(),
            deposit(),
            register_viewing_key(),
            settle_exit(),
            claim(),
            launch_create(),
            launch_commit(),
            configure_fees(),
            register_collection(),
            redeem_item(),
            mint_item(),
            curve_create(),
            curve_trade(),
            configure_curves(),
            sale_open(),
            sale_tickets(),
            sale_close(),
            sale_draw(),
            sale_claim(),
            sale_open_mint(),
            sale_mint(),
            sale_vouchers(),
            bridge_register(),
        lend_list(),
        lend_prices(),
        lend_supply(),
        lend_withdraw(),
        lend_open(),
        lend_repay(),
        lend_collateral(),
        lend_bid(),
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b, "ids {i} and {j} must differ");
            }
        }
    }

    /// The ids are a wire format: a transaction signed today names a rule, and
    /// that name may not drift under it.
    #[test]
    fn the_ids_are_stable() {
        assert_eq!(private_transfer(), private_transfer());
        assert_eq!(private_transfer(), named(b"private-transfer"));
        assert_ne!(private_transfer(), named(b"private-transfer "));
    }

    /// The collision that would matter: a program whose code hashed to a named
    /// rule's id would be run under that rule without being checked. Separate
    /// domains are what make it impossible rather than merely unlikely.
    #[test]
    fn a_program_hash_can_never_equal_a_named_rule() {
        // Even handing `of_code` the exact preimage the named domain uses.
        let mut e = Encoder::new();
        e.bytes(NAMED)
            .u32(b"private-transfer".len() as u32)
            .bytes(b"private-transfer");
        let same_preimage: Hash = e.leaf();

        assert_ne!(of_code(&same_preimage), private_transfer());
        assert!(!is_named(&of_code(&same_preimage)));
        assert!(!is_named(&of_code(&[0u8; 32])));
    }

    /// A VM must be able to tell "a rule I implement" from "a program I have
    /// not been taught", so that accepting the second is a change someone made.
    #[test]
    fn an_unknown_program_is_not_mistaken_for_a_named_rule() {
        assert!(is_named(&private_transfer()));
        assert!(is_named(&withdraw()));
        assert!(!is_named(&ProgramId([0u8; 32])));
        assert!(!is_named(&ProgramId([0xFF; 32])));
    }
}
