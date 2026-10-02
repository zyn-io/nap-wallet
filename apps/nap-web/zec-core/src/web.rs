//! The page's handle on [`crate::Wallet`]. Heights and amounts cross as
//! JavaScript numbers: every Zcash height and every zatoshi amount is far
//! below 2^53, so nothing is lost.

use wasm_bindgen::prelude::*;
use zyn_custody::lightd::request;

fn err(e: String) -> JsError {
    JsError::new(&e)
}

fn whole(v: f64, what: &str) -> Result<u64, JsError> {
    if v.is_finite() && v >= 0.0 && v.fract() == 0.0 && v <= 9_007_199_254_740_991.0 {
        Ok(v as u64)
    } else {
        Err(JsError::new(&format!("{what} must be a whole number")))
    }
}

/// The Orchard spending key for a recovery phrase, to seal. See
/// [`crate::spending_key_from_phrase`].
#[wasm_bindgen(js_name = spendingKeyFromPhrase)]
pub fn spending_key_from_phrase(
    phrase: &str,
    passphrase: &str,
    network: &str,
    account: u32,
) -> Result<Vec<u8>, JsError> {
    let net = crate::network_named(network).map_err(err)?;
    crate::spending_key_from_phrase(phrase, passphrase, net, account)
        .map(|k| k.to_vec())
        .map_err(err)
}

/// The transparent secret key for a recovery phrase, to seal. See
/// [`crate::transparent_key_from_phrase`].
#[wasm_bindgen(js_name = transparentKeyFromPhrase)]
pub fn transparent_key_from_phrase(
    phrase: &str,
    passphrase: &str,
    network: &str,
    account: u32,
) -> Result<Vec<u8>, JsError> {
    let net = crate::network_named(network).map_err(err)?;
    crate::transparent_key_from_phrase(phrase, passphrase, net, account)
        .map(|k| k.to_vec())
        .map_err(err)
}

/// A reply frame's body, or the server's refusal as an error.
#[wasm_bindgen(js_name = replyBody)]
pub fn reply_body(reply: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::reply_body(reply).map_err(err)
}

#[wasm_bindgen(js_name = infoRequest)]
pub fn info_request() -> Vec<u8> {
    request::info()
}

/// `{network: "mainnet"|"testnet", tip, estimated, branch, blocksPerOldBlock}`
/// from an INFO body. `branch` is the one the server says the next block is
/// under; pass it to `buildPayment`.
#[wasm_bindgen(js_name = decodeInfo)]
pub fn decode_info(body: &[u8]) -> Result<String, JsError> {
    let i = zyn_custody::lightd::decode::info(body).map_err(|e| err(e.to_string()))?;
    let network = match i.network {
        zyn_custody::lightd::NET_MAINNET => "mainnet",
        zyn_custody::lightd::NET_TESTNET => "testnet",
        _ => "unknown",
    };
    Ok(serde_json::json!({
        "network": network,
        "tip": i.tip,
        "estimated": i.estimated,
        "branch": i.branch,
        // Blocks that make the time one block made before NU7 (ZIP 218).
        "blocksPerOldBlock": zyn_custody::payout::blocks_per_old_block(i.branch),
    })
    .to_string())
}

#[wasm_bindgen(js_name = blocksRequest)]
pub fn blocks_request(from: f64, count: u32) -> Result<Vec<u8>, JsError> {
    Ok(request::blocks(whole(from, "height")?, count))
}

/// TREESTATE for Orchard (`pool` 0) or Ironwood (1).
#[wasm_bindgen(js_name = treeStateRequest)]
pub fn tree_state_request(height: f64, pool: u8) -> Result<Vec<u8>, JsError> {
    let pool = match pool {
        0 => orchard::ValuePool::Orchard,
        1 => orchard::ValuePool::Ironwood,
        _ => return Err(JsError::new("pool is 0 (Orchard) or 1 (Ironwood)")),
    };
    Ok(request::tree_state(whole(height, "height")?, pool))
}

#[wasm_bindgen(js_name = sendRequest)]
pub fn send_request(raw: &[u8]) -> Vec<u8> {
    request::send(raw)
}

/// The txid the server reports for a SEND body.
#[wasm_bindgen(js_name = decodeSent)]
pub fn decode_sent(body: &[u8]) -> Result<String, JsError> {
    zyn_custody::lightd::decode::sent(body).map_err(|e| err(e.to_string()))
}

#[wasm_bindgen]
pub struct ZecWallet(crate::Wallet);

#[wasm_bindgen]
impl ZecWallet {
    #[wasm_bindgen(constructor)]
    pub fn new(spending_key: &[u8], network: &str) -> Result<ZecWallet, JsError> {
        let key: [u8; 32] = spending_key
            .try_into()
            .map_err(|_| JsError::new("a spending key is 32 bytes"))?;
        let net = crate::network_named(network).map_err(err)?;
        crate::Wallet::new(key, net).map(ZecWallet).map_err(err)
    }

    pub fn address(&self) -> String {
        self.0.address()
    }

    /// Give the wallet its transparent key, 32 bytes.
    #[wasm_bindgen(js_name = setTransparent)]
    pub fn set_transparent(&mut self, secret: &[u8]) -> Result<(), JsError> {
        let key: [u8; 32] = secret
            .try_into()
            .map_err(|_| JsError::new("a transparent key is 32 bytes"))?;
        self.0.set_transparent(key).map_err(err)
    }

    /// The transparent address, or undefined without a key.
    #[wasm_bindgen(js_name = transparentAddress)]
    pub fn transparent_address(&self) -> Option<String> {
        self.0.transparent_address()
    }

    #[wasm_bindgen(js_name = utxosRequest)]
    pub fn utxos_request(&self) -> Result<Vec<u8>, JsError> {
        self.0.utxos_request().map_err(err)
    }

    /// Read a UTXOS body, leaving out the outpoints in `exclude` (a JSON
    /// array of `txid:index`). Returns `{address, total, fee, net, count,
    /// utxos}` as JSON, amounts in zatoshi.
    #[wasm_bindgen(js_name = takeUtxos)]
    pub fn take_utxos(&mut self, body: &[u8], exclude: &str) -> Result<String, JsError> {
        let exclude: Vec<String> = serde_json::from_str(if exclude.is_empty() { "[]" } else { exclude })
            .map_err(|e| JsError::new(&format!("exclude is a JSON list: {e}")))?;
        self.0.take_utxos(body, &exclude).map(|v| v.to_string()).map_err(err)
    }

    /// Build, prove and sign the sweep of the outputs last read. Slow.
    #[wasm_bindgen(js_name = buildShield)]
    pub fn build_shield(&mut self, tip: f64, branch: u32) -> Result<Vec<u8>, JsError> {
        self.0.build_shield(whole(tip, "height")?, branch).map_err(err)
    }

    #[wasm_bindgen(js_name = hasState)]
    pub fn has_state(&self) -> bool {
        self.0.has_state()
    }

    pub fn birthday(&self) -> f64 {
        self.0.birthday() as f64
    }

    /// Seed fresh trees from two TREESTATE bodies at `birthday - 1`.
    pub fn seed(&mut self, birthday: f64, orchard: &[u8], ironwood: &[u8]) -> Result<(), JsError> {
        self.0.seed(whole(birthday, "birthday")?, orchard, ironwood).map_err(err)
    }

    /// The last scanned height, or -1 before the first block.
    #[wasm_bindgen(js_name = syncedTo)]
    pub fn synced_to(&self) -> f64 {
        self.0.synced_to().map(|h| h as f64).unwrap_or(-1.0)
    }

    #[wasm_bindgen(js_name = nextHeight)]
    pub fn next_height(&self) -> f64 {
        self.0.next_height() as f64
    }

    /// `{orchard, ironwood, inFlight}` in zatoshi.
    pub fn balance(&self) -> String {
        let (o, i, f) = self.0.balance();
        serde_json::json!({"orchard": o, "ironwood": i, "inFlight": f}).to_string()
    }

    /// The notes held, newest first, as JSON.
    pub fn notes(&self) -> String {
        serde_json::Value::Array(self.0.notes()).to_string()
    }

    pub fn state(&self) -> Result<Vec<u8>, JsError> {
        self.0.encode_state().map_err(err)
    }

    #[wasm_bindgen(js_name = loadState)]
    pub fn load_state(&mut self, bytes: &[u8]) -> Result<(), JsError> {
        self.0.load_state(bytes).map_err(err)
    }

    /// Read a BLOCKS body up to height `to`; returns how many transactions
    /// to fetch with [`Self::transaction_request`] before [`Self::apply`].
    #[wasm_bindgen(js_name = takeBlocks)]
    pub fn take_blocks(&mut self, body: &[u8], to: f64) -> Result<u32, JsError> {
        self.0
            .take_blocks(body, whole(to, "height")?)
            .map(|n| n as u32)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = transactionRequest)]
    pub fn transaction_request(&self, i: u32) -> Result<Vec<u8>, JsError> {
        let txid = self
            .0
            .wanted(i as usize)
            .ok_or_else(|| JsError::new("no such transaction is wanted"))?;
        Ok(request::transaction(&txid))
    }

    #[wasm_bindgen(js_name = giveTransaction)]
    pub fn give_transaction(&mut self, i: u32, body: &[u8]) -> Result<(), JsError> {
        self.0.give_transaction(i as usize, body).map_err(err)
    }

    /// Apply the waiting blocks; returns what happened, as a JSON array.
    pub fn apply(&mut self) -> Result<String, JsError> {
        let events = self.0.apply().map_err(err)?;
        Ok(serde_json::Value::Array(events.iter().map(crate::Event::json).collect()).to_string())
    }

    /// Build, prove and sign a payment. Slow: proving runs here, on one
    /// thread, so call it from a worker.
    #[wasm_bindgen(js_name = buildPayment)]
    pub fn build_payment(
        &mut self,
        to: &str,
        zatoshi: f64,
        memo: &str,
        tip: f64,
        branch: u32,
    ) -> Result<Vec<u8>, JsError> {
        self.0
            .build_payment(to, whole(zatoshi, "amount")?, memo, whole(tip, "height")?, branch)
            .map_err(err)
    }

    #[wasm_bindgen(js_name = confirmSent)]
    pub fn confirm_sent(&mut self) -> Result<(), JsError> {
        self.0.confirm_sent().map_err(err)
    }
}
