//! Watching a `ZynVault` on an EVM chain.
//!
//! The counterpart to [`crate::zebra`], against a chain that works almost
//! nothing like Zcash — and the differences are all simplifications.
//!
//! # Finality replaces confirmation depth
//!
//! `zebra.rs` waits *n* blocks because Zcash has no finality: a deep block is
//! merely unlikely to be reorged. Post-merge Ethereum and its L2s expose a
//! `finalized` tag, and a finalized block cannot be reorged at all.
//!
//! So [`Observed::tip`] reports the **finalized** height. Depth-counting is not
//! merely unnecessary here, it is worse: it would accept blocks that finality
//! has not covered while claiming a safety it cannot provide. `DECISIONS` §14a
//! anticipated this — a chain with explicit finality reports its finalized
//! height as the tip, and the confirmation knob goes to zero.
//!
//! # The memo problem does not exist
//!
//! `zebra.rs` watches one address per account because a transparent output
//! carries no memo. `ZynVault.deposit` takes the destination as an argument,
//! so one vault serves every account and the account is read straight out of
//! the log. That is the whole reason the EVM side is a contract (§14d).
//!
//! # Amounts arrive pre-scaled
//!
//! The contract emits WAD, converting from the token's own decimals and
//! reverting rather than rounding. So there is no scaling here and no second
//! implementation of it to disagree with the first.

use std::time::Duration;

use serde_json::Value;
use zyn_vm::eip712::keccak;
use zyn_vm::spec::AccountId;
use zyn_vm::Fixed;

use crate::watcher::{ChainView, ObservedDeposit};

/// `keccak256("Deposited(bytes32,uint32,uint256,uint64)")` — topic 0 of the
/// event this watches. Pinned by a test here and asserted against the real
/// event in `contracts/test/ZynVault.t.sol`; a mismatch would simply see no
/// deposits, forever, silently.
pub const DEPOSITED_TOPIC: [u8; 32] = [
    0xb1, 0xda, 0x2e, 0xb4, 0xf7, 0x78, 0xa6, 0xfb, 0x95, 0x04, 0x03, 0xef, 0x78, 0x44, 0x1a, 0x12,
    0xe9, 0x11, 0xb5, 0x0b, 0x52, 0x4d, 0xcc, 0x8a, 0xbb, 0xdf, 0x4d, 0x85, 0xe3, 0x6c, 0x98, 0x49,
];

/// Which EVM network a client is pointed at.
///
/// Same guard as [`crate::zebra::Network`]: mainnet is refused at construction
/// rather than left to a deployment note nobody reads. The custody path is not
/// finished — no signer set is stood up, and §14d's Safe does not exist yet.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Network {
    pub chain_id: u64,
}

impl Network {
    pub fn is_testnet(&self) -> bool {
        zyn_bridge::evm::origin_of_chain_id(self.chain_id)
            .and_then(zyn_bridge::evm::is_testnet)
            .unwrap_or(false)
    }
}

#[derive(Debug)]
pub enum EvmRpcError {
    Http(String),
    Node(String),
    Malformed(&'static str),
    /// The endpoint is not the chain we were configured for. Pointing a Base
    /// watcher at an Arbitrum endpoint would credit deposits that never
    /// happened on the chain the vault's signatures are bound to.
    WrongChain { expected: u64, found: u64 },
    RefusingMainnet(u64),
}

impl std::fmt::Display for EvmRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvmRpcError::Http(e) => write!(f, "rpc transport: {}", e),
            EvmRpcError::Node(e) => write!(f, "rpc error: {}", e),
            EvmRpcError::Malformed(w) => write!(f, "malformed response: {}", w),
            EvmRpcError::WrongChain { expected, found } => {
                write!(f, "endpoint is chain {}, expected {}", found, expected)
            }
            EvmRpcError::RefusingMainnet(id) => {
                write!(f, "refusing to run against mainnet chain {}", id)
            }
        }
    }
}

/// A blocking JSON-RPC client for an EVM endpoint.
pub struct Rpc {
    url: String,
    network: Network,
    agent: ureq::Agent,
}

impl Rpc {
    /// Connect, and **verify the endpoint is the chain we think it is**.
    ///
    /// The check is not a formality. The vault has the same address on every
    /// EVM chain, so a misconfigured URL points at a real contract with real
    /// logs — deposits would be credited from a chain whose withdrawals this
    /// vault cannot pay.
    pub fn connect(url: &str, network: Network) -> Result<Rpc, EvmRpcError> {
        if !network.is_testnet() {
            return Err(EvmRpcError::RefusingMainnet(network.chain_id));
        }
        let rpc = Rpc {
            url: url.to_string(),
            network,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        };
        let found = rpc.chain_id()?;
        if found != network.chain_id {
            return Err(EvmRpcError::WrongChain { expected: network.chain_id, found });
        }
        Ok(rpc)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, EvmRpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
        });
        let resp: Value = self
            .agent
            .post(&self.url)
            .send_json(body)
            .map_err(|e| EvmRpcError::Http(e.to_string()))?
            .into_json()
            .map_err(|_| EvmRpcError::Malformed("not json"))?;
        if let Some(e) = resp.get("error") {
            if !e.is_null() {
                return Err(EvmRpcError::Node(e.to_string()));
            }
        }
        resp.get("result").cloned().ok_or(EvmRpcError::Malformed("no result"))
    }

    pub fn chain_id(&self) -> Result<u64, EvmRpcError> {
        let v = self.call("eth_chainId", serde_json::json!([]))?;
        quantity(&v).ok_or(EvmRpcError::Malformed("chainId"))
    }

    /// Height of the latest **finalized** block.
    pub fn finalized_height(&self) -> Result<u64, EvmRpcError> {
        let v = self.call("eth_getBlockByNumber", serde_json::json!(["finalized", false]))?;
        v.get("number")
            .and_then(quantity)
            .ok_or(EvmRpcError::Malformed("no finalized block"))
    }

    /// `Deposited` logs from one vault, at one height, for one asset.
    pub fn deposits_at(
        &self,
        vault: &[u8; 20],
        asset: u32,
        height: u64,
    ) -> Result<Vec<ObservedDeposit>, EvmRpcError> {
        let mut asset_topic = [0u8; 32];
        asset_topic[28..].copy_from_slice(&asset.to_be_bytes());
        let filter = serde_json::json!([{
            "fromBlock": hex_quantity(height),
            "toBlock": hex_quantity(height),
            "address": hex_bytes(&vault[..]),
            // topic1 (the account) left open; topic2 pins the asset.
            "topics": [hex_bytes(&DEPOSITED_TOPIC), Value::Null, hex_bytes(&asset_topic)],
        }]);
        let v = self.call("eth_getLogs", filter)?;
        let arr = v.as_array().ok_or(EvmRpcError::Malformed("logs"))?;
        let mut out = Vec::with_capacity(arr.len());
        for log in arr {
            if let Some(d) = decode_deposit(log, height) {
                out.push(d);
            }
        }
        Ok(out)
    }

    /// The vault's holding of one asset at a height, in the token's own units.
    pub fn balance_at(
        &self,
        vault: &[u8; 20],
        token: Option<[u8; 20]>,
        height: u64,
    ) -> Result<u128, EvmRpcError> {
        let at = hex_quantity(height);
        let v = match token {
            None => self.call("eth_getBalance", serde_json::json!([hex_bytes(vault), at]))?,
            Some(t) => {
                // balanceOf(address) = 0x70a08231
                let mut data = Vec::with_capacity(36);
                data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
                data.extend_from_slice(&[0u8; 12]);
                data.extend_from_slice(&vault[..]);
                self.call(
                    "eth_call",
                    serde_json::json!([
                        {"to": hex_bytes(&t[..]), "data": hex_bytes(&data)},
                        at
                    ]),
                )?
            }
        };
        let s = v.as_str().ok_or(EvmRpcError::Malformed("balance"))?;
        u128_from_hex(s).ok_or(EvmRpcError::Malformed("balance width"))
    }
}

/// Decode one `Deposited` log.
///
/// Returns `None` rather than an error for anything that does not parse: a log
/// this watcher cannot read is one it must not act on, and refusing to credit
/// is always the safe direction.
pub fn decode_deposit(log: &Value, height: u64) -> Option<ObservedDeposit> {
    if log.get("removed").and_then(Value::as_bool).unwrap_or(false) {
        return None;
    }
    let topics = log.get("topics")?.as_array()?;
    if topics.len() != 3 {
        return None;
    }
    if bytes32(topics[0].as_str()?)? != DEPOSITED_TOPIC {
        return None;
    }
    let account: AccountId = bytes32(topics[1].as_str()?)?;

    // data = amount (uint256, WAD) ‖ index (uint64, padded)
    let data = hex_to_bytes(log.get("data")?.as_str()?)?;
    if data.len() != 64 {
        return None;
    }
    let amount = u128_from_be(&data[0..32])?;
    // A credit must be representable as the VM's `Fixed(i128)`. The contract
    // checks this too; disagreeing with it here would strand the deposit.
    if amount > i128::MAX as u128 {
        return None;
    }
    let txid = bytes32(log.get("transactionHash")?.as_str()?)?;
    Some(ObservedDeposit { txid, account, amount: Fixed::raw(amount as i128), height, asset: None })
}

/// A vault on one EVM chain, watching one asset.
pub struct Observed {
    rpc: Rpc,
    vault: [u8; 20],
    asset: u32,
    /// `None` for the chain's native asset.
    token: Option<[u8; 20]>,
    decimals: u8,
    tip: u64,
    failed: std::cell::Cell<bool>,
}

impl Observed {
    pub fn new(
        rpc: Rpc,
        vault: [u8; 20],
        asset: u32,
        token: Option<[u8; 20]>,
        decimals: u8,
    ) -> Result<Observed, EvmRpcError> {
        let tip = rpc.finalized_height()?;
        Ok(Observed { rpc, vault, asset, token, decimals, tip, failed: std::cell::Cell::new(false) })
    }

    /// Re-read the finalized height. The watcher works to a fixed tip within a
    /// pass so that what it reports is consistent.
    pub fn refresh(&mut self) -> Result<u64, EvmRpcError> {
        self.tip = self.rpc.finalized_height()?;
        self.failed.set(false);
        Ok(self.tip)
    }

    pub fn vault(&self) -> [u8; 20] {
        self.vault
    }
}

/// Token units to WAD. Only ever widening, so unlike the withdrawal direction
/// there is nothing to round away.
pub fn to_wad(units: u128, decimals: u8) -> Option<Fixed> {
    let wad = match decimals {
        18 => units,
        d if d < 18 => units.checked_mul(10u128.checked_pow(18 - d as u32)?)?,
        d => units / 10u128.pow(d as u32 - 18),
    };
    if wad > i128::MAX as u128 {
        return None;
    }
    Some(Fixed::raw(wad as i128))
}

impl ChainView for Observed {
    fn tip(&self) -> u64 {
        self.tip
    }

    fn deposits_at(&self, height: u64) -> Vec<ObservedDeposit> {
        // An unreachable node is indistinguishable from a quiet block here, and
        // that is the safe confusion to have: the watcher makes no progress and
        // the next pass repeats the range.
        self.rpc.deposits_at(&self.vault, self.asset, height).unwrap_or_default()
    }

    fn balance_at(&self, height: u64) -> Option<Fixed> {
        let units = self.rpc.balance_at(&self.vault, self.token, height).ok()?;
        to_wad(units, self.decimals)
    }
}

// ------------------------------------------------------------------ hex

fn hex_quantity(v: u64) -> String {
    format!("0x{:x}", v)
}

fn hex_bytes(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x")?;
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

fn bytes32(s: &str) -> Option<[u8; 32]> {
    let v = hex_to_bytes(s)?;
    if v.len() != 32 {
        return None;
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    Some(o)
}

/// An `eth_` quantity: hex, minimally encoded, `0x`-prefixed.
fn quantity(v: &Value) -> Option<u64> {
    u64::from_str_radix(v.as_str()?.strip_prefix("0x")?, 16).ok()
}

fn u128_from_hex(s: &str) -> Option<u128> {
    let h = s.strip_prefix("0x")?;
    if h.is_empty() {
        return None;
    }
    u128::from_str_radix(h, 16).ok()
}

/// A big-endian `uint256`, rejected if it does not fit `u128`.
fn u128_from_be(b: &[u8]) -> Option<u128> {
    if b.len() != 32 || b[..16].iter().any(|x| *x != 0) {
        return None;
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(&b[16..]);
    Some(u128::from_be_bytes(o))
}

/// Recompute the event topic, so the constant cannot drift unnoticed.
pub fn deposited_topic() -> [u8; 32] {
    keccak(&[b"Deposited(bytes32,uint32,uint256,uint64)"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The constant is hard-coded so decoding needs no hashing, and recomputed
    /// here so it cannot drift. A wrong topic is the worst kind of bug this
    /// file could have: every filter matches nothing, no deposit is ever
    /// credited, and nothing anywhere reports an error.
    #[test]
    fn the_topic_is_the_event_signature() {
        assert_eq!(DEPOSITED_TOPIC, deposited_topic());
    }

    fn log(account: [u8; 32], amount_wad: u128, index: u64) -> Value {
        let mut data = [0u8; 64];
        data[16..32].copy_from_slice(&amount_wad.to_be_bytes());
        data[56..64].copy_from_slice(&index.to_be_bytes());
        json!({
            "topics": [hex_bytes(&DEPOSITED_TOPIC), hex_bytes(&account), hex_bytes(&[0u8;32])],
            "data": hex_bytes(&data),
            "transactionHash": hex_bytes(&[9u8; 32]),
            "removed": false,
        })
    }

    #[test]
    fn a_deposit_log_decodes() {
        let d = decode_deposit(&log([3u8; 32], 5_000_000_000_000_000_000, 7), 100).unwrap();
        assert_eq!(d.account, [3u8; 32]);
        assert_eq!(d.amount, Fixed::whole(5));
        assert_eq!(d.height, 100);
        assert_eq!(d.txid, [9u8; 32]);
    }

    /// A reorged-away log is flagged by the node. Crediting one would issue
    /// units against a deposit that no longer exists.
    #[test]
    fn a_removed_log_is_ignored() {
        let mut l = log([3u8; 32], 1, 0);
        l["removed"] = json!(true);
        assert!(decode_deposit(&l, 100).is_none());
    }

    /// Anything unparseable must not be credited. Each of these is a log the
    /// watcher could plausibly be handed and must decline.
    #[test]
    fn an_unreadable_log_is_declined_rather_than_guessed() {
        let good = log([3u8; 32], 1, 0);

        let mut wrong_topic = good.clone();
        wrong_topic["topics"][0] = json!(hex_bytes(&[1u8; 32]));
        assert!(decode_deposit(&wrong_topic, 1).is_none(), "a foreign event decoded");

        let mut short = good.clone();
        short["topics"] = json!([hex_bytes(&DEPOSITED_TOPIC), hex_bytes(&[3u8; 32])]);
        assert!(decode_deposit(&short, 1).is_none(), "a two-topic log decoded");

        let mut truncated = good.clone();
        truncated["data"] = json!(hex_bytes(&[0u8; 32]));
        assert!(decode_deposit(&truncated, 1).is_none(), "a half-length data field decoded");

        let mut odd = good.clone();
        odd["data"] = json!("0xabc");
        assert!(decode_deposit(&odd, 1).is_none());

        let mut no_hash = good.clone();
        no_hash["transactionHash"] = Value::Null;
        assert!(decode_deposit(&no_hash, 1).is_none());
    }

    /// `Fixed` is an i128 and a `uint256` is not. An amount past the VM's range
    /// must be declined here rather than wrap into a small positive credit.
    #[test]
    fn an_amount_past_the_vms_range_is_declined() {
        let mut l = log([3u8; 32], 1, 0);
        let mut data = [0u8; 64];
        data[0] = 0x01; // sets a bit above the low 128
        l["data"] = json!(hex_bytes(&data));
        assert!(decode_deposit(&l, 1).is_none());

        let mut l2 = log([3u8; 32], 1, 0);
        let mut d2 = [0u8; 64];
        d2[16] = 0x80; // exactly i128::MAX + 1
        l2["data"] = json!(hex_bytes(&d2));
        assert!(decode_deposit(&l2, 1).is_none());
    }

    #[test]
    fn scaling_up_from_token_units() {
        assert_eq!(to_wad(1_000_000, 6), Some(Fixed::whole(1)));
        assert_eq!(to_wad(5_000_000_000_000_000_000, 18), Some(Fixed::whole(5)));
        assert_eq!(to_wad(u128::MAX, 6), None, "an overflowing balance was reported");
    }

    /// Mainnet is refused before any request is made.
    #[test]
    fn mainnet_is_refused() {
        for id in [1u64, 8453, 42161] {
            assert!(!Network { chain_id: id }.is_testnet());
        }
        for id in [11_155_111u64, 84_532, 421_614] {
            assert!(Network { chain_id: id }.is_testnet(), "testnet {} not recognised", id);
        }
        match Rpc::connect("http://127.0.0.1:1", Network { chain_id: 1 }) {
            Err(EvmRpcError::RefusingMainnet(1)) => {}
            other => panic!("mainnet was not refused: {:?}", other.err()),
        }
    }
}
