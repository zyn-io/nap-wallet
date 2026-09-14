//! Watching a vault account on Solana.
//!
//! The third chain, and the one that reuses the most: `Watcher` holds the
//! confirmation, ordering and replay rules, and this only has to answer "what
//! arrived at slot *n*, and for whom".
//!
//! # Deposits carry a memo, as on Zcash — and unlike on EVM
//!
//! §14d had to put a contract on every EVM chain because an ERC-20 `transfer`
//! carries nothing that could name a recipient. Solana has the **Memo
//! program**, so the deposit can say who it is for without a program of our
//! own — which is the same shape as the Zcash design ([`crate::memo`]) rather
//! than a Solana-specific workaround.
//!
//! That matters for more than symmetry. A Solana program would need an
//! **upgrade authority**, and a key that can replace the program is a key that
//! can drain the vault. Not deploying one removes that key rather than securing
//! it.
//!
//! The cost is the same one Zcash has: a depositor who omits the memo sends
//! unattributable funds, and no automatic rule can decide whose they are.
//! [`crate::watcher`] already models that, and it stays a manual refund.
//!
//! **The memo is public here.** On Zcash it sits inside the encrypted note; on
//! Solana anyone can read it, so it links a Solana address to a Zyn account.
//! That is a real privacy difference and it is the depositor's to make — the
//! account named need not be one they have ever otherwise used.
//!
//! # Finality is a commitment level, not a depth
//!
//! Like the EVM watcher and unlike Zcash, the tip is the **finalized** slot.
//! `crate::watcher`'s own notes anticipated this: a chain with explicit
//! finality reports finalized as the tip and the confirmation count goes to
//! zero.
//!
//! # What this cannot do, and says so
//!
//! Solana RPC has no historical balance query — `getBalance` answers for a
//! commitment, not a slot. So [`Observed::balance_at`] reports the balance at
//! the **finalized tip** regardless of the slot asked about. See the note on
//! that method for why this is the safe direction and not a shortcut.

use std::time::Duration;

use serde_json::Value;
use zyn_vm::eip712::keccak;
use zyn_vm::Fixed;

use crate::memo;
use crate::watcher::{AssetId, ChainView, ObservedDeposit};

/// One lamport in `Fixed`'s 1e18 scale. SOL has 9 decimals.
pub const LAMPORT: i128 = 1_000_000_000;

/// The Solana Memo program, v2. Deposits are recognised by an instruction to
/// this program in the same transaction as the transfer.
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Which cluster a client is pointed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cluster {
    Devnet,
    Testnet,
    /// Refused at construction, like [`crate::zebra::Network::Mainnet`]: no
    /// signer set is stood up and custody cannot pay out yet.
    MainnetBeta,
}

#[derive(Debug)]
pub enum SolanaError {
    Http(String),
    Node(String),
    Malformed(&'static str),
    RefusingMainnet,
    /// The endpoint is not the cluster configured.
    WrongCluster {
        expected: Cluster,
        found: String,
    },
}

impl std::fmt::Display for SolanaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SolanaError::Http(e) => write!(f, "rpc transport: {}", e),
            SolanaError::Node(e) => write!(f, "rpc error: {}", e),
            SolanaError::Malformed(w) => write!(f, "malformed response: {}", w),
            SolanaError::RefusingMainnet => write!(f, "refusing to run against mainnet-beta"),
            SolanaError::WrongCluster { expected, found } => {
                write!(
                    f,
                    "endpoint reports genesis {}, expected {:?}",
                    found, expected
                )
            }
        }
    }
}

/// Genesis hashes, so a misconfigured URL is caught rather than watched.
const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const TESTNET_GENESIS: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";

pub struct Rpc {
    url: String,
    cluster: Cluster,
    agent: ureq::Agent,
}

impl Rpc {
    /// Connect, refusing mainnet and checking the endpoint is the cluster we
    /// think it is.
    pub fn connect(url: &str, cluster: Cluster) -> Result<Rpc, SolanaError> {
        if cluster == Cluster::MainnetBeta {
            return Err(SolanaError::RefusingMainnet);
        }
        let rpc = Rpc {
            url: url.to_string(),
            cluster,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        };
        let found = rpc.genesis_hash()?;
        let expected = match cluster {
            Cluster::Devnet => DEVNET_GENESIS,
            Cluster::Testnet => TESTNET_GENESIS,
            Cluster::MainnetBeta => unreachable!("refused above"),
        };
        if found != expected {
            return Err(SolanaError::WrongCluster {
                expected: cluster,
                found,
            });
        }
        Ok(rpc)
    }

    /// Connect without the genesis check — for a local test validator, which
    /// has a genesis of its own. Never for a public endpoint.
    pub fn connect_unchecked(url: &str, cluster: Cluster) -> Rpc {
        Rpc {
            url: url.to_string(),
            cluster,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    pub fn cluster(&self) -> Cluster {
        self.cluster
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, SolanaError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        });
        // The public endpoints rate-limit. Three tries with a short back-off
        // absorb the ordinary case; a sustained limit still surfaces.
        let mut attempt = 0;
        let resp: Value = loop {
            match self.agent.post(&self.url).send_json(body.clone()) {
                Ok(r) => {
                    break r
                        .into_json()
                        .map_err(|_| SolanaError::Malformed("not json"))?
                }
                Err(ureq::Error::Status(429, _)) if attempt < 3 => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(400 * (1 << attempt)));
                }
                Err(e) => return Err(SolanaError::Http(e.to_string())),
            }
        };
        if let Some(e) = resp.get("error") {
            if !e.is_null() {
                return Err(SolanaError::Node(e.to_string()));
            }
        }
        resp.get("result")
            .cloned()
            .ok_or(SolanaError::Malformed("no result"))
    }

    pub fn genesis_hash(&self) -> Result<String, SolanaError> {
        Ok(self
            .call("getGenesisHash", serde_json::json!([]))?
            .as_str()
            .ok_or(SolanaError::Malformed("genesis hash"))?
            .to_string())
    }

    /// The latest finalized slot.
    pub fn finalized_slot(&self) -> Result<u64, SolanaError> {
        self.call("getSlot", serde_json::json!([{"commitment": "finalized"}]))?
            .as_u64()
            .ok_or(SolanaError::Malformed("slot"))
    }

    /// Deposits to `vault` in one slot.
    ///
    /// A **skipped slot is not an error**. Solana produces no block for a slot
    /// whose leader failed, and treating that as a failure would stall the
    /// watcher on an entirely ordinary event.
    pub fn deposits_at(&self, vault: &str, slot: u64) -> Result<Vec<ObservedDeposit>, SolanaError> {
        let params = serde_json::json!([slot, {
            "encoding": "jsonParsed",
            "transactionDetails": "full",
            "maxSupportedTransactionVersion": 0,
            "rewards": false,
            "commitment": "finalized",
        }]);
        let block = match self.call("getBlock", params) {
            Ok(b) => b,
            Err(SolanaError::Node(e)) if is_skipped(&e) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let txs = match block.get("transactions").and_then(Value::as_array) {
            None => return Ok(Vec::new()),
            Some(t) => t,
        };
        Ok(txs
            .iter()
            .filter_map(|tx| decode_deposit(tx, vault, slot))
            .collect())
    }

    /// Signatures of finalized transactions touching `address`, newest first,
    /// stopping at `until` (exclusive) when given. One call for the whole
    /// history since the cursor, instead of one per slot.
    pub fn signatures_for_address(
        &self,
        address: &str,
        until: Option<&str>,
    ) -> Result<Vec<(u64, String)>, SolanaError> {
        let mut opts = serde_json::json!({"commitment": "finalized", "limit": 1000});
        if let Some(u) = until {
            opts["until"] = Value::String(u.to_string());
        }
        let v = self.call(
            "getSignaturesForAddress",
            serde_json::json!([address, opts]),
        )?;
        let arr = v.as_array().ok_or(SolanaError::Malformed("signatures"))?;
        let mut out = Vec::with_capacity(arr.len());
        for e in arr {
            let (Some(slot), Some(sig)) = (
                e.get("slot").and_then(Value::as_u64),
                e.get("signature").and_then(Value::as_str),
            ) else {
                return Err(SolanaError::Malformed("signature entry"));
            };
            out.push((slot, sig.to_string()));
        }
        Ok(out)
    }

    /// One finalized transaction, parsed, in the shape a block lists it.
    pub fn transaction(&self, signature: &str) -> Result<Option<Value>, SolanaError> {
        let v = self.call(
            "getTransaction",
            serde_json::json!([signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0, "commitment": "finalized"}]),
        )?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// Base units held by a token account, at the finalized commitment.
    /// Zero for an account that does not exist yet.
    pub fn token_balance(&self, ata: &str) -> Result<u64, SolanaError> {
        match self.call(
            "getTokenAccountBalance",
            serde_json::json!([ata, {"commitment": "finalized"}]),
        ) {
            Ok(v) => v
                .get("value")
                .and_then(|x| x.get("amount"))
                .and_then(Value::as_str)
                .and_then(|a| a.parse().ok())
                .ok_or(SolanaError::Malformed("token balance")),
            // "could not find account": nothing has been sent there yet.
            Err(SolanaError::Node(e)) if e.contains("could not find") || e.contains("-32602") => {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    /// Lamports held by the vault, at the finalized commitment.
    pub fn balance(&self, vault: &str) -> Result<u64, SolanaError> {
        let v = self.call(
            "getBalance",
            serde_json::json!([vault, {"commitment": "finalized"}]),
        )?;
        v.get("value")
            .and_then(Value::as_u64)
            .ok_or(SolanaError::Malformed("balance"))
    }
}

/// A node's way of saying "there is no block here", which is normal.
fn is_skipped(err: &str) -> bool {
    err.contains("-32009") || err.contains("was skipped")
}

/// Read one transaction as a deposit, or decline it.
///
/// Every rejection below is a transaction that must **not** credit:
///
/// - a failed transaction moved no lamports, but still appears in the block;
/// - a transfer with no memo names nobody;
/// - a memo that is not a Zyn instruction names nobody either.
///
/// Declining is always safe. Crediting wrongly is not.
pub fn decode_deposit(tx: &Value, vault: &str, slot: u64) -> Option<ObservedDeposit> {
    // A transaction can be included and still have failed. Its transfers did
    // not happen; its memo did.
    if !tx.get("meta")?.get("err")?.is_null() {
        return None;
    }
    let message = tx.get("transaction")?.get("message")?;
    let instructions = message.get("instructions")?.as_array()?;

    // Inner instructions count too: a transfer made by a program on the user's
    // behalf still moves lamports into the vault.
    let mut all: Vec<&Value> = instructions.iter().collect();
    if let Some(inner) = tx.get("meta").and_then(|m| m.get("innerInstructions")) {
        if let Some(groups) = inner.as_array() {
            for g in groups {
                if let Some(list) = g.get("instructions").and_then(Value::as_array) {
                    all.extend(list.iter());
                }
            }
        }
    }

    let account = find_memo(&all)?;
    let lamports = total_transferred(&all, vault)?;
    if lamports == 0 {
        return None;
    }
    let amount = Fixed::raw(i128::from(lamports).checked_mul(LAMPORT)?);

    // A Solana signature is 64 bytes and `external_ref` is 32, so the dedup key
    // is a hash of it rather than a prefix — two signatures sharing a prefix
    // would silently suppress a real deposit.
    let sig = tx
        .get("transaction")?
        .get("signatures")?
        .as_array()?
        .first()?
        .as_str()?;
    Some(ObservedDeposit {
        txid: keccak(&[sig.as_bytes()]),
        account,
        amount,
        height: slot,
        asset: None,
    })
}

/// A transfer of a mirrored token into the vault's token account, with the
/// memo naming the recipient — the SPL counterpart of [`decode_deposit`].
pub fn decode_token_deposit(tx: &Value, m: &Mirrored, slot: u64) -> Option<ObservedDeposit> {
    if !tx.get("meta")?.get("err")?.is_null() {
        return None;
    }
    let message = tx.get("transaction")?.get("message")?;
    let mut all: Vec<&Value> = message.get("instructions")?.as_array()?.iter().collect();
    if let Some(groups) = tx
        .get("meta")
        .and_then(|x| x.get("innerInstructions"))
        .and_then(Value::as_array)
    {
        for g in groups {
            if let Some(list) = g.get("instructions").and_then(Value::as_array) {
                all.extend(list.iter());
            }
        }
    }
    let account = find_memo(&all)?;
    let mut units: u64 = 0;
    for ix in &all {
        if ix.get("program").and_then(Value::as_str) != Some("spl-token") {
            continue;
        }
        let parsed = ix.get("parsed")?;
        let kind = parsed.get("type").and_then(Value::as_str)?;
        let info = parsed.get("info")?;
        if info.get("destination").and_then(Value::as_str) != Some(m.ata.as_str()) {
            continue;
        }
        let amount = match kind {
            "transfer" => info
                .get("amount")
                .and_then(Value::as_str)?
                .parse::<u64>()
                .ok()?,
            "transferChecked" => {
                if info.get("mint").and_then(Value::as_str) != Some(m.mint.as_str()) {
                    continue;
                }
                info.get("tokenAmount")?
                    .get("amount")
                    .and_then(Value::as_str)?
                    .parse::<u64>()
                    .ok()?
            }
            _ => continue,
        };
        units = units.checked_add(amount)?;
    }
    if units == 0 {
        return None;
    }
    let amount = Fixed::raw(i128::from(units).checked_mul(Fixed::ONE.0 / m.per_unit as i128)?);
    let sig = tx
        .get("transaction")?
        .get("signatures")?
        .as_array()?
        .first()?
        .as_str()?;
    Some(ObservedDeposit {
        txid: keccak(&[sig.as_bytes()]),
        account,
        amount,
        height: slot,
        asset: Some(m.asset),
    })
}

/// The Zyn account named by a memo instruction, if exactly one names anything.
///
/// More than one differing instruction is refused rather than resolved: two
/// memos disagreeing about the recipient is not a case any rule should settle
/// silently.
fn find_memo(instructions: &[&Value]) -> Option<[u8; 32]> {
    let mut found: Option<[u8; 32]> = None;
    for ix in instructions {
        if ix.get("programId").and_then(Value::as_str) != Some(MEMO_PROGRAM) {
            continue;
        }
        // spl-memo parses to the memo string itself.
        let text = ix.get("parsed").and_then(Value::as_str)?;
        let Ok(account) = memo::decode_text(text) else {
            continue;
        };
        match found {
            Some(prev) if prev != account => return None,
            _ => found = Some(account),
        }
    }
    found
}

/// Lamports moved into `vault` by this transaction's system transfers.
fn total_transferred(instructions: &[&Value], vault: &str) -> Option<u64> {
    let mut total: u64 = 0;
    for ix in instructions {
        if ix.get("program").and_then(Value::as_str) != Some("system") {
            continue;
        }
        let parsed = ix.get("parsed")?;
        let kind = parsed.get("type").and_then(Value::as_str)?;
        if kind != "transfer" && kind != "transferWithSeed" {
            continue;
        }
        let info = parsed.get("info")?;
        if info.get("destination").and_then(Value::as_str) != Some(vault) {
            continue;
        }
        total = total.checked_add(info.get("lamports").and_then(Value::as_u64)?)?;
    }
    Some(total)
}

/// A vault account on Solana.
///
/// Address-indexed rather than slot-by-slot: a pass asks the node once for
/// the signatures that touched the vault since the last pass, files them by
/// slot, and fetches only those transactions. The watcher still walks every
/// slot, but a slot with nothing filed costs nothing — which is what keeps a
/// public endpoint's rate limit from being the bottleneck.
/// A mirrored token the vault custodies: an SPL mint, the Zyn asset it
/// backs, and the vault's token account for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mirrored {
    pub mint: String,
    pub asset: AssetId,
    pub ata: String,
    /// Base units per whole unit: `1` for an NFT (0 decimals), `10^d` else.
    pub per_unit: u64,
}

pub struct Observed {
    rpc: Rpc,
    vault: String,
    /// Tokens the vault custodies besides SOL, by the token account that
    /// receives them.
    mirrored: Vec<Mirrored>,
    tip: u64,
    /// Signatures by slot, for slots not yet handed to the watcher.
    filed: std::cell::RefCell<std::collections::BTreeMap<u64, Vec<String>>>,
    /// The newest signature seen per indexed address; the next refresh reads
    /// up to it.
    cursor: std::cell::RefCell<Option<Vec<Option<String>>>>,
    /// Set when an answer was forced by a failure. See `ChainView::failed`.
    failed: std::cell::Cell<bool>,
}

impl Observed {
    pub fn new(rpc: Rpc, vault: &str) -> Result<Observed, SolanaError> {
        let tip = rpc.finalized_slot()?;
        Ok(Observed {
            rpc,
            vault: vault.to_string(),
            mirrored: Vec::new(),
            tip,
            filed: Default::default(),
            cursor: Default::default(),
            failed: std::cell::Cell::new(false),
        })
    }

    /// Custody these mints too. Their token accounts are indexed alongside
    /// the vault, and a transfer into one is a deposit of the named asset.
    pub fn with_mirrored(mut self, mirrored: Vec<Mirrored>) -> Observed {
        self.mirrored = mirrored;
        self
    }

    pub fn mirrored(&self) -> &[Mirrored] {
        &self.mirrored
    }

    /// Re-read the finalized slot and file every new signature. Clears the
    /// failure flag: a fresh pass starts clean.
    pub fn refresh(&mut self) -> Result<u64, SolanaError> {
        self.tip = self.rpc.finalized_slot()?;
        // The vault, and each token account it owns: a transfer into a token
        // account names only that account, not its owner.
        let mut addresses = vec![self.vault.clone()];
        addresses.extend(self.mirrored.iter().map(|m| m.ata.clone()));
        let mut filed = self.filed.borrow_mut();
        let mut newest: Option<String> = None;
        for (i, addr) in addresses.iter().enumerate() {
            let until = self
                .cursor
                .borrow()
                .as_ref()
                .and_then(|c: &Vec<Option<String>>| c.get(i).cloned().flatten());
            let fresh = self.rpc.signatures_for_address(addr, until.as_deref())?;
            if i == 0 {
                newest = fresh.first().map(|(_, s)| s.clone());
            }
            let mut cursors = self.cursor.borrow_mut();
            let cur = cursors.get_or_insert_with(|| vec![None; addresses.len()]);
            if cur.len() < addresses.len() {
                cur.resize(addresses.len(), None);
            }
            if let Some((_, s)) = fresh.first() {
                cur[i] = Some(s.clone());
            }
            for (slot, sig) in fresh {
                let list = filed.entry(slot).or_default();
                if !list.contains(&sig) {
                    list.push(sig);
                }
            }
        }
        let _ = newest;
        self.failed.set(false);
        Ok(self.tip)
    }

    /// Slots filed but not yet asked for — for a restart that must not lose
    /// what a previous pass saw.
    pub fn pending_slots(&self) -> usize {
        self.filed.borrow().len()
    }

    pub fn vault(&self) -> &str {
        &self.vault
    }
}

impl ChainView for Observed {
    fn tip(&self) -> u64 {
        self.tip
    }

    fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
        let sigs = match self.filed.borrow().get(&height) {
            Some(s) => s.clone(),
            None => return Vec::new(), // nothing touched the vault in this slot
        };
        let mut out = Vec::new();
        for sig in &sigs {
            match self.rpc.transaction(sig) {
                Ok(Some(tx)) => {
                    out.extend(decode_deposit(&tx, &self.vault, height));
                    for m in &self.mirrored {
                        out.extend(decode_token_deposit(&tx, m, height));
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    // The answer below is a guess; say so, and keep the slot
                    // filed for the next pass.
                    self.failed.set(true);
                    return Vec::new();
                }
            }
        }
        // Handed over; a later pass over the same slot (after a rewind) will
        // find it filed again by the refresh's `until` cursor being behind it.
        out
    }

    fn failed(&self) -> bool {
        self.failed.get()
    }

    /// What the vault holds of a mirrored token: its token account's balance,
    /// in whole units. `None` for an asset this vault does not custody.
    fn balance_of(&self, asset: AssetId, _height: u64) -> Option<Fixed> {
        let m = self.mirrored.iter().find(|m| m.asset == asset)?;
        match self.rpc.token_balance(&m.ata) {
            Ok(units) => Some(Fixed::raw(
                i128::from(units).checked_mul(Fixed::ONE.0 / m.per_unit as i128)?,
            )),
            Err(_) => {
                self.failed.set(true);
                None
            }
        }
    }

    /// The vault's balance **now**, at the finalized commitment — not at
    /// `_height`.
    ///
    /// Solana RPC cannot answer a historical balance; `getBalance` takes a
    /// commitment, not a slot. Reporting the current one is the safe direction
    /// rather than a shortcut, and the asymmetry is worth stating:
    ///
    /// - too **low** is safe — the ceiling binds harder than it needs to, and a
    ///   credit waits for the next pass.
    /// - too **high** would be unsafe, because the ceiling is what stops units
    ///   being issued against money the vault does not hold.
    ///
    /// A balance read after the slot in question differs by deposits and
    /// withdrawals since. Withdrawals make it smaller — safe. Deposits make it
    /// larger, but those lamports **are in the vault**, so the ceiling is
    /// ahead of the credits rather than above the backing, and `Vault::attest`
    /// still refuses a reported shortfall.
    fn balance_at(&self, _height: u64) -> Option<Fixed> {
        let lamports = match self.rpc.balance(&self.vault) {
            Ok(l) => l,
            Err(_) => {
                self.failed.set(true);
                return None;
            }
        };
        Some(Fixed::raw(i128::from(lamports).checked_mul(LAMPORT)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VAULT: &str = "VauLtzynzap1111111111111111111111111111111";
    const OTHER: &str = "0therzynzap1111111111111111111111111111111";
    const SIG: &str =
        "5j7s6NiJS3JAkvgkoc18WVAsiSaci2pxB2A6ueCJP4tprA2TFg9wSyTLeYouxPBJEMzJinENTkpA52YStRW5Dia7";

    fn transfer(to: &str, lamports: u64) -> Value {
        json!({
            "program": "system",
            "programId": "11111111111111111111111111111111",
            "parsed": {"type": "transfer", "info": {
                "source": "SenderPubkey11111111111111111111111111111",
                "destination": to,
                "lamports": lamports,
            }},
        })
    }

    fn memo_ix(text: &str) -> Value {
        json!({"program": "spl-memo", "programId": MEMO_PROGRAM, "parsed": text})
    }

    fn tx(instructions: Vec<Value>, err: Value) -> Value {
        json!({
            "meta": {"err": err, "innerInstructions": []},
            "transaction": {
                "signatures": [SIG],
                "message": {"instructions": instructions},
            },
        })
    }

    fn account(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn a_transfer_with_a_memo_is_a_deposit() {
        let t = tx(
            vec![
                transfer(VAULT, 2_500_000_000),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        let d = decode_deposit(&t, VAULT, 900).unwrap();
        assert_eq!(d.account, account(4));
        assert_eq!(d.amount, Fixed::raw(25 * LAMPORT * LAMPORT / 10)); // 2.5 SOL
        assert_eq!(d.height, 900);
        assert_eq!(d.txid, keccak(&[SIG.as_bytes()]));
    }

    /// A failed transaction is still in the block. Its transfers did not
    /// happen — but its memo did, so a decoder that only looked at the memo
    /// would credit an account for nothing.
    #[test]
    fn a_failed_transaction_credits_nothing() {
        let t = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            json!({"InstructionError": [0, "Custom"]}),
        );
        assert!(decode_deposit(&t, VAULT, 900).is_none());
    }

    #[test]
    fn a_transfer_without_a_memo_names_nobody() {
        let t = tx(vec![transfer(VAULT, 1_000_000_000)], Value::Null);
        assert!(decode_deposit(&t, VAULT, 900).is_none());
    }

    #[test]
    fn a_memo_without_a_transfer_credits_nothing() {
        let t = tx(vec![memo_ix(&memo::encode_text(&account(4)))], Value::Null);
        assert!(decode_deposit(&t, VAULT, 900).is_none());
    }

    /// Someone else's transfer in the same transaction is not ours. A decoder
    /// that summed every transfer would credit us for a payment we never
    /// received.
    #[test]
    fn only_transfers_to_the_vault_count() {
        let t = tx(
            vec![
                transfer(OTHER, 9_000_000_000),
                transfer(VAULT, 1_000_000_000),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        assert_eq!(
            decode_deposit(&t, VAULT, 900).unwrap().amount,
            Fixed::whole(1)
        );

        let only_theirs = tx(
            vec![transfer(OTHER, 5), memo_ix(&memo::encode_text(&account(4)))],
            Value::Null,
        );
        assert!(decode_deposit(&only_theirs, VAULT, 900).is_none());
    }

    /// Two transfers to us in one transaction are one deposit of their sum,
    /// not two deposits or one of the first.
    #[test]
    fn transfers_to_the_vault_are_summed() {
        let t = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                transfer(VAULT, 500_000_000),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        assert_eq!(
            decode_deposit(&t, VAULT, 900).unwrap().amount,
            Fixed::raw(15 * LAMPORT * LAMPORT / 10)
        );
    }

    /// Two memos naming different accounts is not something a rule should
    /// settle. It is a manual decision.
    #[test]
    fn conflicting_memos_are_refused_rather_than_resolved() {
        let t = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                memo_ix(&memo::encode_text(&account(4))),
                memo_ix(&memo::encode_text(&account(5))),
            ],
            Value::Null,
        );
        assert!(decode_deposit(&t, VAULT, 900).is_none());

        // The same account twice is not a conflict.
        let same = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                memo_ix(&memo::encode_text(&account(4))),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        assert_eq!(
            decode_deposit(&same, VAULT, 900).unwrap().account,
            account(4)
        );
    }

    /// A memo that is not a Zyn instruction is the common case and must be
    /// ignored, not guessed at — including alongside a valid one.
    #[test]
    fn an_unrelated_memo_is_ignored() {
        let t = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                memo_ix("gm"),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        assert_eq!(decode_deposit(&t, VAULT, 900).unwrap().account, account(4));

        let only_junk = tx(vec![transfer(VAULT, 1), memo_ix("gm")], Value::Null);
        assert!(decode_deposit(&only_junk, VAULT, 900).is_none());
    }

    /// A program moving lamports on a user's behalf still funds the vault.
    #[test]
    fn an_inner_transfer_counts() {
        let mut t = tx(vec![memo_ix(&memo::encode_text(&account(4)))], Value::Null);
        t["meta"]["innerInstructions"] =
            json!([{"index": 0, "instructions": [transfer(VAULT, 3_000_000_000)]}]);
        assert_eq!(
            decode_deposit(&t, VAULT, 900).unwrap().amount,
            Fixed::whole(3)
        );
    }

    /// An SPL `transferChecked` into the vault's token account for a mirrored
    /// mint is a deposit of that item; one into some other token account, or
    /// of another mint, is not.
    #[test]
    fn a_token_transfer_into_the_vaults_token_account_is_an_item_deposit() {
        let m = Mirrored {
            mint: "MintPubkey1111111111111111111111111111111111".into(),
            asset: [7; 32],
            ata: "VaultAta111111111111111111111111111111111111".into(),
            per_unit: 1,
        };
        let ix = |dest: &str, mint: &str, amount: &str| {
            json!({
                "program": "spl-token", "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "parsed": {"type": "transferChecked", "info": {"source": "Src", "destination": dest, "mint": mint, "authority": "Auth",
                    "tokenAmount": {"amount": amount, "decimals": 0, "uiAmount": 1.0}}},
            })
        };
        let t = tx(
            vec![
                ix(&m.ata, &m.mint, "1"),
                memo_ix(&memo::encode_text(&account(4))),
            ],
            Value::Null,
        );
        let d = decode_token_deposit(&t, &m, 5).unwrap();
        assert_eq!(
            (d.asset, d.amount, d.account, d.height),
            (Some([7; 32]), Fixed::whole(1), account(4), 5)
        );
        // Not ours: a different token account, or a different mint.
        assert!(decode_token_deposit(
            &tx(
                vec![
                    ix("SomeoneElse", &m.mint, "1"),
                    memo_ix(&memo::encode_text(&account(4)))
                ],
                Value::Null
            ),
            &m,
            5
        )
        .is_none());
        assert!(decode_token_deposit(
            &tx(
                vec![
                    ix(&m.ata, "OtherMint", "1"),
                    memo_ix(&memo::encode_text(&account(4)))
                ],
                Value::Null
            ),
            &m,
            5
        )
        .is_none());
        // No memo: names nobody, like a SOL deposit.
        assert!(
            decode_token_deposit(&tx(vec![ix(&m.ata, &m.mint, "1")], Value::Null), &m, 5).is_none()
        );
        // Failed transaction: moved nothing.
        assert!(decode_token_deposit(
            &tx(
                vec![
                    ix(&m.ata, &m.mint, "1"),
                    memo_ix(&memo::encode_text(&account(4)))
                ],
                json!({"InstructionError": [0, "Custom"]})
            ),
            &m,
            5
        )
        .is_none());
        // A SOL decoder must not see a token transfer as SOL.
        assert!(decode_deposit(&t, VAULT, 5).is_none());
    }

    /// A leader that produces no block is ordinary. Treating it as a failure
    /// would stall the watcher on every skipped slot.
    #[test]
    fn a_skipped_slot_is_not_a_failure() {
        assert!(is_skipped(
            "{\"code\":-32009,\"message\":\"Slot 12 was skipped\"}"
        ));
        assert!(is_skipped(
            "Slot 5 was skipped, or missing due to ledger jump"
        ));
        assert!(!is_skipped(
            "{\"code\":-32001,\"message\":\"Block not available\"}"
        ));
    }

    /// SOL has 9 decimals and `Fixed` has 18, so the multiplier and the
    /// lamports-per-SOL figure are the same number — which makes it very easy
    /// to apply once too often or once too few. Pinned in whole units.
    #[test]
    fn one_sol_is_one_unit() {
        let one = tx(
            vec![
                transfer(VAULT, 1_000_000_000),
                memo_ix(&memo::encode_text(&account(1))),
            ],
            Value::Null,
        );
        assert_eq!(
            decode_deposit(&one, VAULT, 1).unwrap().amount,
            Fixed::whole(1)
        );

        let dust = tx(
            vec![transfer(VAULT, 1), memo_ix(&memo::encode_text(&account(1)))],
            Value::Null,
        );
        assert_eq!(
            decode_deposit(&dust, VAULT, 1).unwrap().amount,
            Fixed::raw(LAMPORT)
        );
    }

    #[test]
    fn mainnet_is_refused() {
        match Rpc::connect("http://127.0.0.1:1", Cluster::MainnetBeta) {
            Err(SolanaError::RefusingMainnet) => {}
            other => panic!("mainnet was not refused: {:?}", other.err()),
        }
    }
}

// ------------------------------------------------------------ base58

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Decode base58, the encoding of every Solana address and signature.
///
/// Hand-rolled for the same reason the transaction bytes are: it is thirty
/// lines, the alternative is a dependency tree, and an address that decodes
/// wrongly here pays the wrong person.
pub fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut big: Vec<u8> = Vec::new(); // little-endian base-256 accumulator
    for c in s.bytes() {
        let d = B58.iter().position(|x| *x == c)? as u32;
        let mut carry = d;
        for b in big.iter_mut() {
            let v = (*b as u32) * 58 + carry;
            *b = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            big.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = s.bytes().take_while(|c| *c == b'1').count();
    let mut out = vec![0u8; zeros];
    out.extend(big.iter().rev());
    Some(out)
}

pub fn base58_encode(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-58
    for &b in bytes {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let v = (*d as u32) * 256 + carry;
            *d = (v % 58) as u8;
            carry = v / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::new();
    for _ in bytes.iter().take_while(|b| **b == 0) {
        out.push('1');
    }
    for d in digits.iter().rev() {
        out.push(B58[*d as usize] as char);
    }
    out
}

/// A base58 address as 32 bytes, or nothing.
pub fn pubkey(s: &str) -> Option<[u8; 32]> {
    base58_decode(s)?.try_into().ok()
}

impl Rpc {
    /// The durable nonce's current value — what the settlement message names
    /// in place of a blockhash.
    pub fn nonce_value(&self, nonce_account: &str) -> Result<[u8; 32], SolanaError> {
        let v = self.call(
            "getAccountInfo",
            serde_json::json!([nonce_account, {"encoding": "jsonParsed", "commitment": "finalized"}]),
        )?;
        let info = v
            .get("value")
            .and_then(|a| a.get("data"))
            .and_then(|d| d.get("parsed"))
            .and_then(|p| p.get("info"))
            .ok_or(SolanaError::Malformed("not a nonce account"))?;
        let hash = info
            .get("blockhash")
            .and_then(Value::as_str)
            .ok_or(SolanaError::Malformed("nonce blockhash"))?;
        pubkey(hash).ok_or(SolanaError::Malformed("nonce blockhash width"))
    }

    /// Broadcast a signed transaction. Returns its signature, base58.
    ///
    /// Preflight is left on: a transaction the node would reject is better
    /// refused here, where the nonce has not been consumed, than on-chain.
    pub fn send_transaction(&self, tx: &[u8]) -> Result<String, SolanaError> {
        let v = self.call(
            "sendTransaction",
            serde_json::json!([crate::zebra::base64(tx), {"encoding": "base64", "preflightCommitment": "finalized"}]),
        )?;
        Ok(v.as_str()
            .ok_or(SolanaError::Malformed("signature"))?
            .to_string())
    }
}

// ------------------------------------------------------------ custody

/// Signing for the Solana vault: the threshold key *is* the account.
pub mod custody {
    use std::collections::BTreeMap;

    use zyn_bridge::solana::{self as settle, SolPayout, VaultAccounts};

    use super::{Rpc, SolanaError};
    use crate::ceremony::{Ceremony, CeremonyError, IdentifierFor, Solana, ThresholdKeys};
    use crate::signing::{Aggregator, LocalSolanaQuorum, SigningError, SolanaQuorum};

    pub type Id = IdentifierFor<Solana>;
    pub type Keys = ThresholdKeys<Solana>;

    #[derive(Debug)]
    pub enum PayError {
        Ceremony(CeremonyError),
        Signing(SigningError),
        Settlement(settle::SolanaError),
        Rpc(SolanaError),
        /// The aggregated signature did not verify as ordinary ed25519. Not
        /// broadcast: a share was wrong, and the network's rejection would
        /// have cost the nonce.
        DoesNotVerify,
    }

    /// Run the ceremony for a Solana vault.
    pub fn ceremony<R: rand_core::RngCore + rand_core::CryptoRng>(
        threshold: u16,
        participants: u16,
        rng: &mut R,
    ) -> Result<BTreeMap<Id, Keys>, CeremonyError> {
        Ceremony::new(threshold, participants)?.run_for::<Solana, R>(rng)
    }

    /// The vault's address: the group key, which Solana treats as an ordinary
    /// ed25519 account. Nothing is derived — this *is* the account.
    pub fn vault_address(keys: &Keys) -> [u8; 32] {
        keys.group_key()
            .serialize()
            .ok()
            .and_then(|v| v.try_into().ok())
            .expect("ed25519 keys are 32 bytes")
    }

    /// The same address, from the public package alone — what a sequencer
    /// holding no share knows about its own vault.
    pub fn vault_address_of(public: &frost_core::keys::PublicKeyPackage<Solana>) -> [u8; 32] {
        public
            .verifying_key()
            .serialize()
            .ok()
            .and_then(|v| v.try_into().ok())
            .expect("ed25519 keys are 32 bytes")
    }

    /// Produce one ed25519 signature over `message` with a quorum of shares.
    ///
    /// Both FROST rounds, driven in-process the way the ceremony is: a real
    /// deployment runs the same sequence with messages between machines. The
    /// result is checked with `ed25519-dalek` before it is returned — the same
    /// verification Solana performs — so a bad share is found here.
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        shares: &[(Id, &Keys)],
        threshold: u16,
        message: &[u8],
        _rng: &mut R,
    ) -> Result<[u8; 64], PayError> {
        let public = shares
            .first()
            .ok_or(PayError::Signing(SigningError::BelowThreshold))?
            .1
            .public_package
            .clone();
        let mut quorum = LocalSolanaQuorum::new(shares.iter().map(|(_, k)| (*k).clone()).collect());
        sign_with(&mut quorum, threshold, &public, message, 0)
    }

    /// The same signature, with the shares wherever they are.
    ///
    /// Solana's path is the simple one: one message, one signature, no
    /// re-randomization — so a custodian commits to one nonce per request and
    /// releases one share. The quorum is untrusted: it forwards packages and
    /// collects shares, and a wrong share is caught by `verify` below rather
    /// than by trusting whoever sent it.
    pub fn sign_with(
        quorum: &mut dyn SolanaQuorum,
        threshold: u16,
        public: &frost_core::keys::PublicKeyPackage<Solana>,
        message: &[u8],
        now: u64,
    ) -> Result<[u8; 64], PayError> {
        // Fresh per attempt, so a retry after a timeout never collides with
        // the request whose nonces a custodian still holds.
        let request_id: u64 = rand::RngCore::next_u64(&mut rand::rngs::OsRng);
        let commitments = quorum.round1(request_id, message, now);
        let want = usize::from(threshold);
        if commitments.len() < want {
            return Err(PayError::Signing(SigningError::BelowThreshold));
        }
        let mut coord: Aggregator<Solana> = Aggregator::new(message.to_vec(), threshold);
        let chosen: Vec<Id> = commitments.keys().copied().take(want).collect();
        for id in &chosen {
            coord.add_commitment(*id, commitments[id].clone());
        }
        let package = coord.package().map_err(PayError::Signing)?;
        let shares = quorum.round2(request_id, &chosen, &package);
        if shares.len() < want {
            return Err(PayError::Signing(SigningError::BelowThreshold));
        }
        let sig = coord
            .aggregate(&package, &shares, public)
            .map_err(PayError::Signing)?;
        let bytes: [u8; 64] = sig
            .serialize()
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(PayError::DoesNotVerify)?;
        verify(&vault_address_of(public), message, &bytes)?;
        Ok(bytes)
    }

    pub fn verify(vault: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<(), PayError> {
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(vault).map_err(|_| PayError::DoesNotVerify)?;
        vk.verify_strict(message, &ed25519_dalek::Signature::from_bytes(sig))
            .map_err(|_| PayError::DoesNotVerify)
    }

    /// A signed, unsent settlement transaction.
    ///
    /// Split from [`broadcast`] on purpose: the operator must **record** what
    /// it is about to send before sending it. A crash between the two must
    /// lose a payout (re-signable, the nonce unconsumed) and never repeat one.
    pub struct Payment {
        pub message: Vec<u8>,
        pub signature: [u8; 64],
        pub transaction: Vec<u8>,
        pub payouts: Vec<SolPayout>,
    }

    impl Payment {
        /// The transaction's signature, base58 — its id on the chain.
        pub fn id(&self) -> String {
            super::base58_encode(&self.signature)
        }
    }

    /// Build and sign one transaction-sized group of payouts.
    pub fn prepare<R: rand_core::RngCore + rand_core::CryptoRng>(
        rpc: &Rpc,
        shares: &[(Id, &Keys)],
        threshold: u16,
        nonce_account: &str,
        payouts: &[SolPayout],
        rng: &mut R,
    ) -> Result<Payment, PayError> {
        let vault = vault_address(
            shares
                .first()
                .ok_or(PayError::Signing(SigningError::BelowThreshold))?
                .1,
        );
        let nonce_pk = super::pubkey(nonce_account)
            .ok_or(PayError::Rpc(SolanaError::Malformed("nonce account")))?;
        let accounts = VaultAccounts {
            vault,
            nonce_account: nonce_pk,
        };
        let nonce = rpc.nonce_value(nonce_account).map_err(PayError::Rpc)?;
        let message = settle::message(accounts, nonce, payouts).map_err(PayError::Settlement)?;
        let signature = sign(shares, threshold, &message, rng)?;
        let transaction = settle::transaction(&message, &signature);
        Ok(Payment {
            message,
            signature,
            transaction,
            payouts: payouts.to_vec(),
        })
    }

    /// [`prepare`] with the shares held elsewhere. The vault address comes
    /// from the public package, so the caller need hold no share at all.
    pub fn prepare_with(
        rpc: &Rpc,
        quorum: &mut dyn SolanaQuorum,
        threshold: u16,
        public: &frost_core::keys::PublicKeyPackage<Solana>,
        nonce_account: &str,
        payouts: &[SolPayout],
        now: u64,
    ) -> Result<Payment, PayError> {
        let vault = vault_address_of(public);
        let nonce_pk = super::pubkey(nonce_account)
            .ok_or(PayError::Rpc(SolanaError::Malformed("nonce account")))?;
        let accounts = VaultAccounts {
            vault,
            nonce_account: nonce_pk,
        };
        let nonce = rpc.nonce_value(nonce_account).map_err(PayError::Rpc)?;
        let message = settle::message(accounts, nonce, payouts).map_err(PayError::Settlement)?;
        let signature = sign_with(quorum, threshold, public, &message, now)?;
        let transaction = settle::transaction(&message, &signature);
        Ok(Payment {
            message,
            signature,
            transaction,
            payouts: payouts.to_vec(),
        })
    }

    pub fn broadcast(rpc: &Rpc, payment: &Payment) -> Result<String, PayError> {
        rpc.send_transaction(&payment.transaction)
            .map_err(PayError::Rpc)
    }
}

#[cfg(test)]
mod custody_tests {
    use super::custody::*;
    use super::*;
    use crate::signing::SigningError;
    use rand::rngs::OsRng;
    use zyn_bridge::solana::{message, SolPayout, VaultAccounts};

    #[test]
    fn base58_round_trips_and_matches_known_addresses() {
        assert_eq!(pubkey("11111111111111111111111111111111"), Some([0u8; 32]));
        assert_eq!(
            pubkey("SysvarRecentB1ockHashes11111111111111111111"),
            Some(zyn_bridge::solana::RECENT_BLOCKHASHES_SYSVAR)
        );
        assert_eq!(
            pubkey(MEMO_PROGRAM).map(|p| base58_encode(&p)).as_deref(),
            Some(MEMO_PROGRAM)
        );
        for b in [vec![0u8], vec![0, 0, 1], vec![255; 64], vec![1, 2, 3]] {
            assert_eq!(base58_decode(&base58_encode(&b)), Some(b.clone()));
        }
        assert_eq!(base58_decode("0OIl"), None, "not base58 characters");
    }

    fn shares() -> (Vec<(Id, Keys)>, u16) {
        let keys = ceremony(2, 3, &mut OsRng).unwrap();
        (keys.into_iter().collect(), 2)
    }

    /// The property the whole Solana leg rests on: a threshold signature from
    /// the ceremony verifies as an **ordinary** ed25519 signature under the
    /// account's key — the check Solana performs, done by `ed25519-dalek`.
    #[test]
    fn a_threshold_signature_is_an_ordinary_ed25519_signature() {
        let (keys, t) = shares();
        let quorum: Vec<(Id, &Keys)> = keys.iter().take(2).map(|(i, k)| (*i, k)).collect();
        let vault = vault_address(&keys[0].1);
        let sig = sign(&quorum, t, b"settle", &mut OsRng).unwrap();
        assert!(verify(&vault, b"settle", &sig).is_ok());
        assert!(
            verify(&vault, b"settle!", &sig).is_err(),
            "another message verified"
        );
        let other = vault_address(
            &ceremony(2, 3, &mut OsRng)
                .unwrap()
                .into_iter()
                .next()
                .unwrap()
                .1,
        );
        assert!(
            verify(&other, b"settle", &sig).is_err(),
            "another vault verified"
        );
    }

    #[test]
    fn below_the_threshold_there_is_no_signature() {
        let (keys, t) = shares();
        let one: Vec<(Id, &Keys)> = keys.iter().take(1).map(|(i, k)| (*i, k)).collect();
        assert!(matches!(
            sign(&one, t, b"x", &mut OsRng),
            Err(PayError::Signing(SigningError::BelowThreshold))
        ));
    }

    /// End to end short of the network: a real settlement message, signed by
    /// a quorum, verifying under the vault's address.
    #[test]
    fn a_settlement_message_signs_and_verifies() {
        let (keys, t) = shares();
        let vault = vault_address(&keys[0].1);
        let accounts = VaultAccounts {
            vault,
            nonce_account: [9u8; 32],
        };
        let m = message(
            accounts,
            [3u8; 32],
            &[SolPayout::native([1u8; 32], 500_000_000)],
        )
        .unwrap();
        let quorum: Vec<(Id, &Keys)> = keys.iter().skip(1).map(|(i, k)| (*i, k)).collect();
        let sig = sign(&quorum, t, &m, &mut OsRng).unwrap();
        let tx = zyn_bridge::solana::transaction(&m, &sig);
        assert_eq!(&tx[1..65], &sig[..]);
        assert!(verify(&vault, &tx[65..], &sig).is_ok());
    }
}

/// Where the chain says a transaction is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TxStatus {
    /// Not seen — never broadcast, dropped, or not yet.
    Unknown,
    /// Processed but not final. Can still be rolled back.
    Confirmed,
    /// Cannot be rolled back. The only status a burn on Zyn may follow.
    Finalized,
    /// Included and failed. Moved nothing; the nonce it named is spent.
    Failed,
}

impl Rpc {
    /// Status of a broadcast transaction, by signature.
    pub fn signature_status(&self, signature: &str) -> Result<TxStatus, SolanaError> {
        let v = self.call(
            "getSignatureStatuses",
            serde_json::json!([[signature], {"searchTransactionHistory": true}]),
        )?;
        let entry = v
            .get("value")
            .and_then(Value::as_array)
            .and_then(|a| a.first());
        let Some(entry) = entry else {
            return Ok(TxStatus::Unknown);
        };
        if entry.is_null() {
            return Ok(TxStatus::Unknown);
        }
        if entry.get("err").map(|e| !e.is_null()).unwrap_or(false) {
            return Ok(TxStatus::Failed);
        }
        Ok(
            match entry.get("confirmationStatus").and_then(Value::as_str) {
                Some("finalized") => TxStatus::Finalized,
                Some("confirmed") | Some("processed") => TxStatus::Confirmed,
                _ => TxStatus::Unknown,
            },
        )
    }
}

/// Shares on disk — the generic [`crate::shares`], for the Solana suite.
pub mod shares {
    use std::path::Path;

    use super::custody::{Id, Keys};
    use crate::ceremony::Solana;

    pub fn save(dir: &Path, keys: &[(Id, Keys)]) -> std::io::Result<()> {
        crate::shares::save::<Solana>(dir, keys)
    }
    pub fn load(dir: &Path) -> std::io::Result<Vec<(Id, Keys)>> {
        crate::shares::load::<Solana>(dir)
    }
}

#[cfg(test)]
mod share_tests {
    use super::custody::*;
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn shares_round_trip_through_disk_and_still_sign() {
        let dir = std::env::temp_dir().join(format!("zyn-shares-{}", std::process::id()));
        let keys: Vec<(Id, Keys)> = ceremony(2, 3, &mut OsRng).unwrap().into_iter().collect();
        shares::save(&dir, &keys).unwrap();
        let back = shares::load(&dir).unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(vault_address(&back[0].1), vault_address(&keys[0].1));
        let quorum: Vec<(Id, &Keys)> = back.iter().take(2).map(|(i, k)| (*i, k)).collect();
        let sig = sign(&quorum, 2, b"after a restart", &mut OsRng).unwrap();
        assert!(verify(&vault_address(&keys[0].1), b"after a restart", &sig).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
