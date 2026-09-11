//! How each intent is shown to a wallet before it is signed.
//!
//! This is ZynZap's answer to **S13**. A wallet renders these field names and
//! these values, so this file is the last thing standing between a user and
//! approving something they did not mean.
//!
//! Two rules it follows.
//!
//! **Every field that changes the outcome appears.** Especially `path`: a swap
//! routed through an attacker's pool is a different trade at identical amounts,
//! and it is the one parameter a compromised front end would most like to
//! change quietly. It is signed, so it cannot be.
//!
//! **One representation per value.** Amounts appear as the raw `int256` and
//! nowhere else. A friendlier decimal string beside it would be two encodings
//! of one number, and two encodings can disagree — which is exactly the lie a
//! malicious interface wants to tell. Wallets show the raw integer for ERC-20
//! approvals for the same reason.
//!
//! Operator intents are here too, rendered opaquely. Nothing signs them with a
//! wallet — the node emits them — but a total function has no gap for someone
//! to later fill in wrongly.

use alloc::string::{String, ToString};

use zyn_vm::eip712::{TypedData, Value};
use zyn_vm::fixed::Fixed;
use zyn_vm::spec::AccountId;

use crate::tx::Intent;

fn account(a: &AccountId) -> Value {
    Value::Bytes32(*a)
}

fn amount(f: Fixed) -> Value {
    Value::int(f.0)
}

/// A symbol is fixed-width and NUL-padded on the wire; a wallet should show
/// the name, not the padding.
fn symbol(s: &[u8; 8]) -> Value {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    Value::String(String::from_utf8_lossy(&s[..end]).to_string())
}

fn path(p: &[u32]) -> Value {
    Value::uints(p.iter().map(|&x| x as u64))
}

pub fn typed_intent(intent: &Intent) -> TypedData {
    let t = TypedData::new;
    match intent {
        Intent::SwapExactIn { account: a, asset_in, path: p, amount_in, min_out } => {
            t("SwapExactIn")
                .field("account", account(a))
                .field("assetIn", Value::uint(*asset_in as u64))
                .field("path", path(p))
                .field("amountIn", amount(*amount_in))
                .field("minOut", amount(*min_out))
        }
        Intent::SwapExactOut { account: a, asset_in, path: p, amount_out, max_in } => {
            t("SwapExactOut")
                .field("account", account(a))
                .field("assetIn", Value::uint(*asset_in as u64))
                .field("path", path(p))
                .field("amountOut", amount(*amount_out))
                .field("maxIn", amount(*max_in))
        }
        Intent::Transfer { from, to, asset, amount: v } => t("Transfer")
            .field("from", account(from))
            .field("to", account(to))
            .field("asset", Value::uint(*asset as u64))
            .field("amount", amount(*v)),
        Intent::AcceptOffer { maker, taker, offer_asset, offer_amount, want_asset, want_amount } => {
            t("AcceptOffer")
                .field("maker", account(maker))
                .field("taker", account(taker))
                .field("offerAsset", Value::uint(*offer_asset as u64))
                .field("offerAmount", amount(*offer_amount))
                .field("wantAsset", Value::uint(*want_asset as u64))
                .field("wantAmount", amount(*want_amount))
        }
        Intent::AddLiquidity { account: a, pool, max0, max1, min_shares } => t("AddLiquidity")
            .field("account", account(a))
            .field("pool", Value::uint(*pool as u64))
            .field("max0", amount(*max0))
            .field("max1", amount(*max1))
            .field("minShares", amount(*min_shares)),
        Intent::RemoveLiquidity { account: a, pool, shares, min0, min1 } => t("RemoveLiquidity")
            .field("account", account(a))
            .field("pool", Value::uint(*pool as u64))
            .field("shares", amount(*shares))
            .field("min0", amount(*min0))
            .field("min1", amount(*min1)),
        Intent::CreatePool { creator, asset_a, asset_b, amount_a, amount_b, fee_bps } => {
            t("CreatePool")
                .field("creator", account(creator))
                .field("assetA", Value::uint(*asset_a as u64))
                .field("assetB", Value::uint(*asset_b as u64))
                .field("amountA", amount(*amount_a))
                .field("amountB", amount(*amount_b))
                .field("feeBps", Value::uint(*fee_bps as u64))
        }
        Intent::CreateToken {
            creator,
            symbol: sym,
            supply,
            unit,
            xzec_liquidity,
            token_liquidity,
            fee_bps,
        } => t("CreateToken")
            .field("creator", account(creator))
            .field("symbol", symbol(sym))
            .field("supply", amount(*supply))
            .field("unit", amount(*unit))
            .field("xzecLiquidity", amount(*xzec_liquidity))
            .field("tokenLiquidity", amount(*token_liquidity))
            .field("feeBps", Value::uint(*fee_bps as u64)),
        Intent::MintItem { creator, symbol: sym, supply, bond, content } => t("MintItem")
            .field("creator", account(creator))
            .field("symbol", symbol(sym))
            .field("supply", amount(*supply))
            .field("bond", amount(*bond))
            .field("content", Value::Bytes32(*content)),
        Intent::Reblind { account: a, blind } => t("Reblind")
            .field("account", account(a))
            .field("blind", Value::Bytes32(*blind)),
        Intent::BurnItem { holder, asset } => t("BurnItem")
            .field("holder", account(holder))
            .field("asset", Value::uint(*asset as u64)),

        // The custody intents. `destination` is a commitment to a payout
        // address, never the address — Zyn's state is public and a withdrawal
        // destination should not be. The wallet shows the commitment, and the
        // interface that produced it is what shows the address.
        Intent::RequestWithdrawal { account: a, asset, amount: v, destination } => {
            t("RequestWithdrawal")
                .field("account", account(a))
                .field("asset", Value::uint(*asset as u64))
                .field("amount", amount(*v))
                .field("destinationCommitment", Value::Bytes32(*destination))
        }
        Intent::BindWithdrawal { account: a, destination } => t("BindWithdrawal")
            .field("account", account(a))
            .field("destinationCommitment", Value::Bytes32(*destination)),
        Intent::CancelWithdrawal { account: a, asset } => t("CancelWithdrawal")
            .field("account", account(a))
            .field("asset", Value::uint(*asset as u64)),

        Intent::PlaceOffer { maker, offer_asset, offer_amount, want_asset, want_amount, expires_at_epoch } => {
            t("PlaceOffer")
                .field("maker", account(maker))
                .field("offerAsset", Value::uint(*offer_asset as u64))
                .field("offerAmount", amount(*offer_amount))
                .field("wantAsset", Value::uint(*want_asset as u64))
                .field("wantAmount", amount(*want_amount))
                .field("expiresAtEpoch", Value::uint(*expires_at_epoch))
        }
        Intent::TakeOffer { taker, offer } => t("TakeOffer")
            .field("taker", account(taker))
            .field("offer", Value::uint(*offer)),
        Intent::CancelOffer { maker, offer } => t("CancelOffer")
            .field("maker", account(maker))
            .field("offer", Value::uint(*offer)),
        // Operator intents: emitted by the node, never signed by a wallet.
        // Rendered as the hash of their canonical encoding — accurate, and
        // conspicuously not something a person should be approving.
        other => {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(crate::wire::encode_intent_bytes(other));
            let d: [u8; 32] = h.finalize().into();
            t("OperatorIntent").field("intent", Value::Bytes32(d))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::XZEC;

    fn swap(path_ids: Vec<u32>) -> Intent {
        Intent::SwapExactIn {
            account: [1u8; 32],
            asset_in: XZEC,
            path: path_ids,
            amount_in: Fixed::whole(100),
            min_out: Fixed::whole(90),
        }
    }

    /// What a user is shown must name the route, or a compromised interface
    /// can swap a good trade for a bad one without invalidating the signature.
    #[test]
    fn a_swap_shows_its_route_and_its_limits() {
        assert_eq!(
            typed_intent(&swap(vec![1, 2])).encode_type(),
            "SwapExactIn(bytes32 account,uint256 assetIn,uint256[] path,int256 amountIn,int256 minOut)"
        );
        assert_ne!(
            typed_intent(&swap(vec![1, 2])).struct_hash(),
            typed_intent(&swap(vec![1, 3])).struct_hash(),
            "rerouting a swap did not change what was signed"
        );
    }

    /// Weakening a slippage bound must invalidate the signature.
    #[test]
    fn slippage_limits_are_signed() {
        let a = swap(vec![1]);
        let Intent::SwapExactIn { account, asset_in, path, amount_in, .. } = a.clone() else {
            unreachable!()
        };
        let weakened = Intent::SwapExactIn {
            account,
            asset_in,
            path,
            amount_in,
            min_out: Fixed::whole(1),
        };
        assert_ne!(typed_intent(&a).struct_hash(), typed_intent(&weakened).struct_hash());
    }

    /// Two different operations must never share a digest, whatever their
    /// fields — the type name is part of the hash.
    #[test]
    fn operations_are_distinguished_by_name() {
        let a = typed_intent(&Intent::CancelWithdrawal { account: [1u8; 32], asset: XZEC });
        let b = typed_intent(&Intent::BurnItem { holder: [1u8; 32], asset: XZEC });
        assert_ne!(a.struct_hash(), b.struct_hash());
    }

    #[test]
    fn a_symbol_is_shown_without_its_padding() {
        let Value::String(s) = symbol(b"CAT\0\0\0\0\0") else { panic!("wrong variant") };
        assert_eq!(s, "CAT");
    }

    /// The destination commitment is signed, so the binding that protects a
    /// withdrawal cannot be changed by whoever relays the intent.
    #[test]
    fn a_withdrawal_destination_is_signed() {
        let mk = |d: [u8; 32]| Intent::RequestWithdrawal {
            account: [1u8; 32],
            asset: XZEC,
            amount: Fixed::whole(5),
            destination: d,
        };
        assert_ne!(
            typed_intent(&mk([7u8; 32])).struct_hash(),
            typed_intent(&mk([8u8; 32])).struct_hash()
        );
    }
}
