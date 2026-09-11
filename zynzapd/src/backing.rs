//! What a verifier can confirm for itself about a deposit.
//!
//! Replaying the published intents proves the sequencer computed honestly over
//! what it published. It does not prove the *inputs* were true: a fabricated
//! `CreditDeposit`, paired with an `AttestVaultBalance` raised to clear the
//! vault's `AboveObserved` check, replays identically on every signer and
//! produces a matching root. Every signer would endorse it.
//!
//! So a signer asks its **own** Zcash node whether the money is there. Each
//! credit names the transaction it came from ([`SeenCredit::external_ref`], the
//! txid), which is the hook: fetch that transaction, decrypt what is payable to
//! the vault, and refuse to endorse anything the chain does not show.
//!
//! # What this settles, and what it does not
//!
//! Settled: units cannot be minted against a transaction that does not exist,
//! does not pay the vault, or pays it less than was credited. For a deposit
//! whose memo names an account, ownership is settled too.
//!
//! Not settled: a **memo-less** deposit's owner. The chain shows the money
//! arriving and nothing about whose it is; today the sequencer says so out of
//! `ZYN_ZEBRA_ATTRIBUTIONS`, a file no verifier can see. Such a credit passes
//! this check on the strength of the money being real, and its ownership stays
//! the operator's word. Per-account deposit addresses would close it — the
//! receiving address would name the account — and would also separate a
//! stranger's deposit from the vault's own change without a note store.

use std::collections::BTreeMap;

use swapvm::types::AssetId;
use swapvm::Fixed;
use zyn_vm::spec::AccountId;

use zyn_custody::shielded::{deposit_index, VaultKeys, VAULT_INDEX};
use zyn_custody::zebra::Zebra;

/// One zatoshi in `Fixed`'s scale.
const ZAT: i128 = 10_000_000_000;

/// A credit as the intent stream states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeenCredit {
    pub account: AccountId,
    pub asset: AssetId,
    pub amount: Fixed,
    pub index: u64,
    /// The custodying chain's transaction id — what makes this checkable.
    pub external_ref: [u8; 32],
}

/// A verifier's own view of the custodying chain.
pub trait Backing {
    /// Confirm every credit in an epoch. `Err` is refusal to endorse, and the
    /// string says what the chain did not show.
    fn check(&self, credits: &[SeenCredit]) -> Result<(), String>;
}

/// Confirms credits against a Zcash node this process trusts because it runs
/// it. Holds the vault's viewing key only — it can read what arrives, and can
/// sign nothing.
pub struct ZcashBacking {
    zebra: Zebra,
    keys: VaultKeys,
    confirmations: u64,
    /// The asset this vault backs. Credits for anything else are another
    /// bridge's business and are not checked here.
    asset: AssetId,
    /// Refuse a credit whose ownership rests on nothing but the operator's
    /// word — a memo-less note at the vault's own address. Off until deposits
    /// have moved to per-account addresses, because the credits already on the
    /// chain were made the old way.
    strict: bool,
}

impl ZcashBacking {
    pub fn new(zebra: Zebra, keys: VaultKeys, confirmations: u64, asset: AssetId) -> ZcashBacking {
        ZcashBacking { zebra, keys, confirmations, asset, strict: false }
    }

    /// Refuse credits whose ownership only the operator can vouch for.
    pub fn strict(mut self, strict: bool) -> ZcashBacking {
        self.strict = strict;
        self
    }

    /// The txid as Zcash displays it: byte-reversed from the internal form.
    fn txid_hex(txid: &[u8; 32]) -> String {
        txid.iter().rev().map(|b| format!("{:02x}", b)).collect()
    }
}

impl Backing for ZcashBacking {
    fn check(&self, credits: &[SeenCredit]) -> Result<(), String> {
        // A transaction pays what it pays once. Two credits against one txid
        // is a replay however the indices are arranged, so they are summed and
        // checked against the transaction together.
        let mut wanted: BTreeMap<[u8; 32], (Fixed, Vec<AccountId>)> = BTreeMap::new();
        for c in credits.iter().filter(|c| c.asset == self.asset) {
            let e = wanted.entry(c.external_ref).or_insert((Fixed::ZERO, Vec::new()));
            e.0 = e.0.add(c.amount).ok_or_else(|| "credited amounts overflow".to_string())?;
            e.1.push(c.account);
        }

        for (txid, (amount, accounts)) in wanted {
            let hex = Self::txid_hex(&txid);
            let depth = self
                .zebra
                .confirmations(&hex)
                .map_err(|e| format!("cannot ask our own node about {}: {:?}", hex, e))?
                .ok_or_else(|| format!("credited against {}, which our node does not have", hex))?;
            if depth < self.confirmations {
                return Err(format!(
                    "credited against {} at {} confirmation(s), fewer than the {} required",
                    hex, depth, self.confirmations
                ));
            }
            let raw = self
                .zebra
                .raw_transaction_bytes(&hex)
                .map_err(|e| format!("cannot read {} from our own node: {:?}", hex, e))?;
            let scanned = self
                .keys
                .scan_actions_lenient(&raw, txid, 0)
                .map_err(|e| format!("{} does not parse as a transaction: {:?}", hex, e))?;

            // What this transaction actually paid the vault. An anchor is the
            // vault's own self-send and backs nothing.
            let mut paid: i128 = 0;
            let mut named: Vec<AccountId> = Vec::new();
            let mut addressed: Vec<([u8; 11], i128)> = Vec::new();
            let mut vault_indexed = false;
            for a in &scanned.actions {
                let Some(note) = &a.ours else { continue };
                if a.anchor {
                    continue;
                }
                let value = i128::from(note.value().inner()).saturating_mul(ZAT);
                paid = paid.saturating_add(value);
                if let Some(acct) = a.account {
                    named.push(acct);
                }
                match a.to_index {
                    Some(i) if i != VAULT_INDEX => addressed.push((i, value)),
                    Some(_) => vault_indexed = true,
                    None => {}
                }
            }
            if paid < amount.0 {
                return Err(format!(
                    "credited {} against {}, which pays the vault {}",
                    amount.0 / ZAT,
                    hex,
                    paid / ZAT
                ));
            }
            // Where a memo names the account, the sequencer does not get to
            // disagree with it.
            for acct in &named {
                if !accounts.contains(acct) {
                    return Err(format!(
                        "{} carries a memo naming an account the credit does not pay",
                        hex
                    ));
                }
            }
            // Stronger, and needing nothing from the sender: a note that
            // arrived at an account's own deposit address can only be that
            // account's. The index is recomputed here from the account the
            // credit names, so the operator asserts nothing.
            for (index, _) in &addressed {
                if !accounts.iter().any(|a| deposit_index(a).as_bytes() == index) {
                    return Err(format!(
                        "{} paid a deposit address belonging to an account the credit does not pay",
                        hex
                    ));
                }
            }
            // A note at the vault's own index is change, an anchor or a
            // top-up. Crediting against one mints against the vault paying
            // itself. Refused outright in strict mode; until deposits have
            // moved to per-account addresses, such a credit still rests on
            // the operator's attribution file.
            if self.strict && vault_indexed && named.is_empty() {
                return Err(format!(
                    "{} pays the vault's own address with no memo — that is change or a top-up, not a deposit",
                    hex
                ));
            }
        }
        Ok(())
    }
}
