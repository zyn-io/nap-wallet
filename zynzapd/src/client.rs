//! A client for the node's framed RPC, as a library: what `zyn-cli` does by
//! hand, with errors instead of exits, so a UI can call it.

use std::io::{Read, Write};
use std::net::TcpStream;

use ed25519_dalek::{Signer, SigningKey};
use swapvm::state::SwapState;
use swapvm::tx::{Hop, Intent};
use swapvm::types::{AssetId, CollectionId, PoolId};
use swapvm::{wire, Fixed};
use zyn::verify::{Credential, Delegated};
use zyn_vm::auth::{account_of, signed_bytes_as, Authorization, Scheme, Signed};
use zyn_vm::commit::Encoder;
use zyn_vm::read::Decoder;

use crate::rpc::{
    read_challenge, OP_ACCOUNT, OP_ASSETS, OP_CURVE, OP_CURVES, OP_CURVE_QUOTE, OP_LAUNCH,
    OP_LAUNCH_ME, OP_ORDERS, OP_REVEAL, OP_SUBMIT, OP_SUBMIT_DELEGATED, OP_SUBMIT_MULTI,
};

/// One ZEC.zy unit is 10^18; one zatoshi is 10^10 of those.
pub const ZAT: i128 = 10_000_000_000;

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn unhex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err("expected 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "not hex".to_string())?;
    }
    Ok(out)
}

/// A decimal amount in whole units, e.g. `0.05`, as a `Fixed`.
pub fn fixed_of(s: &str) -> Result<Fixed, String> {
    let s = s.trim();
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let whole: i128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| format!("not an amount: {}", s))?
    };
    // Beyond 18 decimals nothing is representable; drop it rather than refuse.
    let frac = &frac[..frac.len().min(18)];
    let frac: i128 = if frac.is_empty() {
        0
    } else {
        format!("{:0<18}", frac)
            .parse()
            .map_err(|_| format!("not an amount: {}", s))?
    };
    Ok(Fixed::raw(whole * 1_000_000_000_000_000_000 + frac))
}

pub fn load_key(path: &str) -> Result<SigningKey, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "a key file is 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The account a signing key speaks for.
fn account_of_key(k: &SigningKey) -> [u8; 32] {
    account(k)
}

pub fn account(k: &SigningKey) -> [u8; 32] {
    account_of(Scheme::Ed25519, k.verifying_key().as_bytes())
}

pub fn reject_name(code: u8) -> &'static str {
    match code {
        1 => "out of order",
        2 => "amount must be positive",
        3 => "insufficient balance",
        4 => "more than the free balance",
        5 => "unknown asset",
        6 => "unknown pool",
        7 => "pool exists",
        8 => "degenerate pair",
        9 => "too little liquidity minted",
        10 => "too little liquidity burned",
        11 => "slippage exceeded",
        12 => "invalid path",
        13 => "insufficient reserves",
        14 => "invalid fee",
        18 => "indivisible",
        19 => "below the launch bond",
        20 => "degenerate offer",
        21 => "below the minimum trade",
        22 => "not the sole holder",
        23 => "asset is not bridged",
        24 => "deposit out of order",
        25 => "below the exit minimum",
        26 => "exit has not timed out",
        27 => "above the vault cap",
        28 => "not finalized yet",
        29 => "invalid finality",
        30 => "above what the vault holds",
        31 => "vault attested short",
        33 => "not the bound destination",
        34 => "rebinding too soon (a redirect must wait out its delay)",
        35 => "symbol already taken",
        47 => "invalid metadata",
        48 => "invalid developer buy",
        49 => "launch rate limited",
        50 => "unknown curve",
        51 => "curve already graduated",
        52 => "insufficient curve inventory",
        _ => "rejected",
    }
}

#[derive(Clone, Debug, Default)]
pub struct Health {
    pub name: String,
    pub scanned_to: u64,
    pub down: bool,
    pub error: String,
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub seq: u64,
    pub epoch: u64,
    pub root: [u8; 32],
    pub backing: Fixed,
    pub pools: u32,
    pub accounts: u32,
    pub health: Vec<Health>,
    /// Swaps queue for the seal and clear together.
    pub clearing: bool,
    /// 0 sequencer, 1 replica.
    pub role: u8,
    /// Sequencer: the epoch of the last anchor in its ledger. Replica: the
    /// last epoch it verified.
    pub anchored_epoch: u64,
    /// Replica: the Zcash height of the last anchor it verified.
    pub verified_height: u64,
    /// Replica: forced intents it is still waiting to see applied.
    pub forced_pending: u32,
    /// Replica: forced intents the sequencer failed to apply in time.
    pub censored: u32,
}

/// The signed submission frame for `intent`, valid for 100 epochs from
/// `now_epoch`: what `OP_SUBMIT` carries after the op and chain id, and what a
/// forced memo carries whole. One function, so the two routes cannot drift.
pub fn frame_submission(k: &SigningKey, chain: u32, now_epoch: u64, intent: &Intent) -> Vec<u8> {
    let auth = Authorization::for_vm::<SwapState>(chain, now_epoch, 100);
    let payload = match signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, intent) {
        Signed::Message(m) => m,
        Signed::Prehash(h) => h.to_vec(),
    };
    let sig = k.sign(&payload).to_bytes();
    let mut e = Encoder::new();
    e.bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(Scheme::Ed25519.tag())
        .bytes(k.verifying_key().as_bytes())
        .bytes(&sig);
    wire::encode_intent(&mut e, intent);
    e.finish().to_vec()
}

/// One party's signature over an intent, for a co-signed submission.
///
/// A trade needs both sides to agree to the *same* intent, so each signs the
/// identical payload under the identical authorization. Kept as bytes so a
/// maker can sign a listing now and a taker accept it later, from a different
/// machine, without either holding the other's key.
pub fn signed_credential(k: &SigningKey, auth: &Authorization, intent: &Intent) -> Vec<u8> {
    let payload = match signed_bytes_as::<SwapState>(Scheme::Ed25519, auth, intent) {
        Signed::Message(m) => m,
        Signed::Prehash(h) => h.to_vec(),
    };
    let sig = k.sign(&payload).to_bytes();
    let mut e = Encoder::new();
    e.u8(Scheme::Ed25519.tag())
        .bytes(k.verifying_key().as_bytes())
        .bytes(&sig);
    e.finish().to_vec()
}

/// The authorization a listing is signed under.
///
/// Made once and shared by both signers: an offer signed under one expiry and
/// accepted under another is two different intents, and neither would clear.
pub fn offer_authorization(chain: u32, now_epoch: u64, epochs_valid: u64) -> Authorization {
    Authorization::for_vm::<SwapState>(chain, now_epoch, epochs_valid)
}

/// A co-signed submission: one intent, the credentials of everyone it names.
pub fn frame_co_signed(auth: &Authorization, creds: &[Vec<u8>], intent: &Intent) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(creds.len() as u8);
    for c in creds {
        e.bytes(c);
    }
    wire::encode_intent(&mut e, intent);
    e.finish().to_vec()
}

/// The transport frame for an owner certificate plus one session-signed
/// intent. The server commits the same fields in its `ZYNAUTH1` journal record.
pub fn frame_delegated(auth: &Authorization, delegated: &Delegated, intent: &Intent) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .bytes(&delegated.delegation.account)
        .bytes(&delegated.delegation.session_key)
        .u32(delegated.delegation.capabilities)
        .u8(delegated.delegation.allowed_assets.len() as u8);
    for asset in &delegated.delegation.allowed_assets {
        e.bytes(asset);
    }
    e.u8(delegated.delegation.allowed_pools.len() as u8);
    for pool in &delegated.delegation.allowed_pools {
        e.bytes(pool);
    }
    e.u8(delegated.delegation.max_per_action.len() as u8);
    for limit in &delegated.delegation.max_per_action {
        e.bytes(&limit.asset).fixed(limit.amount);
    }
    e.u16(delegated.delegation.max_slippage_bps)
        .u64(delegated.delegation.valid_from_epoch)
        .bytes(&delegated.delegation.salt)
        .u64(delegated.delegation.valid_until_epoch)
        .u8(delegated.owner.scheme().tag());
    match &delegated.owner {
        Credential::Ed25519 { key, signature } | Credential::Solana { key, signature } => {
            e.bytes(key).bytes(signature);
        }
        Credential::Evm { signature } => {
            e.bytes(signature);
        }
    }
    e.bytes(&delegated.session_signature);
    wire::encode_intent(&mut e, intent);
    e.finish().to_vec()
}

/// A record and its path to an anchored root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Proof {
    pub epoch: u64,
    pub root: [u8; 32],
    pub record: Vec<u8>,
    pub index: u32,
    pub path: Vec<zyn_vm::commit::ProofStep>,
}

#[derive(Clone, Debug)]
pub struct Pool {
    pub id: PoolId,
    pub asset0: AssetId,
    pub asset1: AssetId,
    pub reserve0: Fixed,
    pub reserve1: Fixed,
    pub fee_bps: u16,
    /// The posted market price (asset1 per asset0) and the sequence it was
    /// posted at, if a feed has set one.
    pub reference: Option<(Fixed, u64)>,
    /// The fee actually charged now: the pool's own, or the divergence fee.
    pub effective_fee_bps: u16,
}

#[derive(Clone, Debug)]
pub struct Asset {
    pub id: AssetId,
    pub symbol: String,
    pub supply: Fixed,
    pub lp_of: Option<PoolId>,
    /// What an item is: the content hash committed at mint. `None` for
    /// ordinary tokens — this is what tells an artwork from a currency.
    pub content: Option<[u8; 32]>,
    /// The collection whose pool backs it, if it is a collection item.
    pub collection: Option<CollectionId>,
}

/// A Cave launch as committed by the chain.
#[derive(Clone, Debug)]
pub struct CurveView {
    pub asset: AssetId,
    pub creator: [u8; 32],
    pub symbol: String,
    pub display_name: String,
    pub metadata_hash: [u8; 32],
    pub fee_bps: u16,
    pub sold: Fixed,
    /// Principal ZEC.zy backing the still-open reversible curve.
    pub curve_reserve: Fixed,
    /// Current ZEC.zy in the active venue: curve reserve or graduated pool.
    pub market_zec: Fixed,
    pub creator_fees: Fixed,
    pub graduation_fees: Fixed,
    pub graduated_token_liquidity: Fixed,
    pub graduated_zec_liquidity: Fixed,
    pub graduation_overflow: Fixed,
    pub graduated_locked_lp: Fixed,
    pub marginal_price: Fixed,
    pub pool: Option<PoolId>,
}

#[derive(Clone, Copy, Debug)]
pub struct CurveQuote {
    pub principal: Fixed,
    pub fee: Fixed,
    /// Buy: total ZEC.zy paid. Sell: net ZEC.zy received.
    pub settlement: Fixed,
    pub sold_after: Fixed,
    pub price_after: Fixed,
    pub graduates: bool,
}

/// A routed exact-input quote, including the fee evidence for every hop.
#[derive(Clone, Debug)]
pub struct SwapQuote {
    pub amount_out: Fixed,
    pub best_case: Fixed,
    pub asset_out: AssetId,
    pub hops: Vec<Hop>,
}

fn decode_curve(d: &mut Decoder<'_>) -> Result<CurveView, String> {
    let asset = d.array::<32>().map_err(|_| "truncated curve".to_string())?;
    let creator = d.array::<32>().map_err(|_| "truncated curve".to_string())?;
    let symbol_len = d.u8().map_err(|_| "truncated curve symbol".to_string())? as usize;
    let symbol = String::from_utf8(
        d.take_bytes(symbol_len)
            .map_err(|_| "truncated curve symbol".to_string())?
            .to_vec(),
    )
    .map_err(|_| "invalid curve symbol UTF-8".to_string())?;
    let name_len = d.u8().map_err(|_| "truncated curve name".to_string())? as usize;
    let display_name = String::from_utf8(
        d.take_bytes(name_len)
            .map_err(|_| "truncated curve name".to_string())?
            .to_vec(),
    )
    .map_err(|_| "invalid curve name UTF-8".to_string())?;
    let metadata_hash = d
        .array::<32>()
        .map_err(|_| "truncated curve metadata".to_string())?;
    let fee_bps = d.u16().map_err(|_| "truncated curve fee".to_string())?;
    let sold = d
        .fixed()
        .map_err(|_| "truncated curve sold amount".to_string())?;
    let curve_reserve = d
        .fixed()
        .map_err(|_| "truncated curve reserve".to_string())?;
    let market_zec = d.fixed().map_err(|_| "truncated market ZEC".to_string())?;
    let creator_fees = d
        .fixed()
        .map_err(|_| "truncated creator fees".to_string())?;
    let graduation_fees = d
        .fixed()
        .map_err(|_| "truncated graduation fees".to_string())?;
    let graduated_token_liquidity = d
        .fixed()
        .map_err(|_| "truncated graduation token liquidity".to_string())?;
    let graduated_zec_liquidity = d
        .fixed()
        .map_err(|_| "truncated graduation ZEC liquidity".to_string())?;
    let graduation_overflow = d
        .fixed()
        .map_err(|_| "truncated graduation overflow".to_string())?;
    let graduated_locked_lp = d.fixed().map_err(|_| "truncated locked LP".to_string())?;
    let marginal_price = d.fixed().map_err(|_| "truncated curve price".to_string())?;
    let pool = match d.u8().map_err(|_| "truncated curve status".to_string())? {
        0 => None,
        1 => Some(
            d.array::<32>()
                .map_err(|_| "truncated graduation pool".to_string())?,
        ),
        _ => return Err("unknown curve status".into()),
    };
    Ok(CurveView {
        asset,
        creator,
        symbol,
        display_name,
        metadata_hash,
        fee_bps,
        sold,
        curve_reserve,
        market_zec,
        creator_fees,
        graduation_fees,
        graduated_token_liquidity,
        graduated_zec_liquidity,
        graduation_overflow,
        graduated_locked_lp,
        marginal_price,
        pool,
    })
}

impl Asset {
    /// An indivisible thing with content, rather than a token.
    pub fn is_item(&self) -> bool {
        self.content.is_some()
    }
}

/// One published anchor: the Zcash transaction carrying an epoch's root.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AnchorView {
    pub epoch: u64,
    pub root: [u8; 32],
    pub anchor_id: [u8; 32],
    /// The Zcash txid, as the explorer shows it.
    pub txid: String,
    /// The Zcash height it confirmed at.
    pub height: u64,
}

/// A resting offer as the chain reports it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OfferView {
    pub id: u64,
    pub maker: [u8; 32],
    /// What the maker gives up. Held in escrow since the offer was placed.
    pub offer_asset: AssetId,
    pub offer_amount: Fixed,
    /// What the maker wants for it.
    pub want_asset: AssetId,
    pub want_amount: Fixed,
    /// Last epoch in which it may be taken, inclusive.
    pub expires_at_epoch: u64,
}

/// A collection as the chain reports it.
#[derive(Clone, Debug)]
pub struct CollectionView {
    pub id: CollectionId,
    pub creator: [u8; 32],
    pub symbol: String,
    pub cap: u32,
    pub minted: u32,
    pub outstanding: u32,
    /// xZEC behind the outstanding items.
    pub pool: Fixed,
    pub fee_bps: u16,
    /// `0` depositing, `1` minting, `2` closed, `3` live.
    pub phase: u8,
    /// `pool / outstanding` — zero until the market opens, because before
    /// then it is not a floor, only an artefact of how far the sale has got.
    pub redeem_price: Fixed,
}

impl CollectionView {
    pub fn phase_name(&self) -> &'static str {
        match self.phase {
            0 => "depositing",
            1 => "minting",
            2 => "closed",
            3 => "live",
            _ => "unknown",
        }
    }
    /// Items the sale may still hand out.
    pub fn remaining(&self) -> u32 {
        self.cap.saturating_sub(self.minted)
    }
}

#[derive(Clone, Debug, Default)]
pub struct AccountRecord {
    pub spendable: Vec<(AssetId, Fixed)>,
    /// (asset, amount, requested epoch)
    pub exiting: Vec<(AssetId, Fixed, u64)>,
    /// (asset, amount, credited epoch)
    pub unreleased: Vec<(AssetId, Fixed, u64)>,
    pub binding: Option<[u8; 32]>,
    pub redirect: Option<([u8; 32], u64)>,
}

/// An open order: (seq, pool, asset_in, amount_in, min_out).
pub type OpenOrder = (u64, PoolId, AssetId, Fixed, Fixed);

#[derive(Clone, Debug, Default)]
pub struct Accepted {
    pub seq: u64,
    pub epoch: u64,
    pub receipts: u32,
    /// For a swap: (amount in, amount out) as the chain executed it.
    pub swapped: Option<(Fixed, Fixed)>,
    /// For liquidity added or removed: (amount0, amount1, shares).
    pub liquidity: Option<(Fixed, Fixed, Fixed)>,
    /// A swap that was queued for the seal rather than executed.
    pub queued: bool,
}

fn decode_accepted(body: &[u8]) -> Result<Accepted, String> {
    let mut d = Decoder::new(body);
    let seq = d.u64().unwrap_or(0);
    let epoch = d.u64().unwrap_or(0);
    let _root = d.hash().unwrap_or([0; 32]);
    let receipts = d.u32().unwrap_or(0);
    let tag = d.u8().unwrap_or(0);
    let mut acc = Accepted {
        seq,
        epoch,
        receipts,
        ..Default::default()
    };
    match tag {
        12 => {
            let code = d.u8().unwrap_or(0);
            return Err(format!("rejected: {} (code {})", reject_name(code), code));
        }
        5 | 6 => {
            let _ = d.account();
            let _ = d.array::<32>();
            let a0 = d.fixed().unwrap_or(Fixed::ZERO);
            let a1 = d.fixed().unwrap_or(Fixed::ZERO);
            let sh = d.fixed().unwrap_or(Fixed::ZERO);
            acc.liquidity = Some((a0, a1, sh));
        }
        7 => {
            let _ = d.account();
            let _ = (d.array::<32>(), d.array::<32>());
            let ain = d.fixed().unwrap_or(Fixed::ZERO);
            let aout = d.fixed().unwrap_or(Fixed::ZERO);
            acc.swapped = Some((ain, aout));
        }
        19 => acc.queued = true,
        _ => {}
    }
    Ok(acc)
}

pub struct Node {
    pub addr: String,
    pub chain: u32,
}

/// The ZYN launch as the node reports it.
#[derive(Clone, Debug)]
pub struct LaunchView {
    pub params: swapvm::launch::Launch,
    pub zcash_height: u64,
    pub graduated_at: u64,
    pub zyn: AssetId,
    pub genesis_pool: PoolId,
    pub minted: Fixed,
    pub last_mint_height: u64,
    pub pot: Fixed,
    pub lp_pot: Fixed,
    pub bridge_pot: Fixed,
    pub pol_zyn: Fixed,
    pub pol_zec: Fixed,
    pub fee_pot: Fixed,
    pub supply: Fixed,
    pub contributors: u32,
    pub contributed: Fixed,
    /// Bridged assets with a pot: on their way to a market, or opened.
    pub assets: Vec<AssetLaunchView>,
    pub asset_threshold: Fixed,
    pub bootstrap_bps: u16,
}

/// A bridged asset's own launch.
#[derive(Clone, Debug)]
pub struct AssetLaunchView {
    pub asset: AssetId,
    pub pot: Fixed,
    /// Units of the asset per ZEC.zy, as the feed last reported.
    pub price: Fixed,
    pub opened_at: u64,
    pub pool: PoolId,
    pub grant: Fixed,
    pub contributors: u32,
    pub contributed: Fixed,
}

#[derive(Clone, Debug, Default)]
pub struct LaunchMe {
    pub contribution: Fixed,
    pub epoch_fees: Fixed,
    pub vest_total: Fixed,
    pub vest_released: Fixed,
    pub vest_end: u64,
    /// Per market this account helped open: (asset, contributed, vest total,
    /// vest released, vest end).
    pub markets: Vec<(AssetId, Fixed, Fixed, Fixed, u64)>,
}

impl Node {
    pub fn new(addr: &str, chain: u32) -> Node {
        Node {
            addr: addr.to_string(),
            chain,
        }
    }

    /// Submit a signer's endorsement of an anchor. `Ok(true)` if it was
    /// counted and the certificate now clears; `Ok(false)` if counted but
    /// short, or not counted (an outsider, a stale id).
    pub fn endorse(
        &self,
        anchor_id: [u8; 32],
        signer: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(bool, bool), String> {
        let mut e = Encoder::new();
        e.u8(crate::rpc::OP_ENDORSE)
            .u32(self.chain)
            .bytes(&anchor_id)
            .bytes(&signer)
            .bytes(&signature);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        Ok((d.u8().unwrap_or(0) != 0, d.u8().unwrap_or(0) != 0))
    }

    /// The shielded address this account's Zcash deposits should be sent to.
    ///
    /// One address per account, so nothing has to travel in a memo and any
    /// shielded wallet can pay it. Asking twice returns the same address.
    pub fn deposit_address(&self, account: [u8; 32]) -> Result<String, String> {
        let mut e = Encoder::new();
        e.u8(crate::rpc::OP_DEPOSIT_ADDRESS)
            .u32(self.chain)
            .bytes(&account);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d
            .u32()
            .map_err(|_| "malformed deposit address reply".to_string())? as usize;
        let raw = d
            .take_bytes(n)
            .map_err(|_| "truncated deposit address".to_string())?;
        String::from_utf8(raw.to_vec()).map_err(|_| "deposit address is not text".to_string())
    }

    /// Every collection the chain knows, with its floor.
    pub fn collections(&self) -> Result<Vec<CollectionView>, String> {
        let mut e = Encoder::new();
        e.u8(crate::rpc::OP_COLLECTIONS).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d
            .u32()
            .map_err(|_| "malformed collection list".to_string())?;
        let mut out = Vec::new();
        for _ in 0..n {
            let id = d
                .array::<32>()
                .map_err(|_| "truncated collection".to_string())?;
            let creator = d
                .array::<32>()
                .map_err(|_| "truncated collection".to_string())?;
            let symbol_len = d.u8().map_err(|_| "truncated collection".to_string())? as usize;
            let sym = d
                .take_bytes(symbol_len)
                .map_err(|_| "truncated collection".to_string())?;
            out.push(CollectionView {
                id,
                creator,
                symbol: String::from_utf8_lossy(sym).to_string(),
                cap: d.u32().unwrap_or(0),
                minted: d.u32().unwrap_or(0),
                outstanding: d.u32().unwrap_or(0),
                pool: d.fixed().unwrap_or(Fixed::ZERO),
                fee_bps: d.u16().unwrap_or(0),
                phase: d.u8().unwrap_or(0),
                redeem_price: d.fixed().unwrap_or(Fixed::ZERO),
            });
        }
        Ok(out)
    }

    /// One collection by id.
    pub fn collection(&self, id: CollectionId) -> Result<Option<CollectionView>, String> {
        Ok(self.collections()?.into_iter().find(|c| c.id == id))
    }

    /// The order book: every offer resting on the chain.
    pub fn offers(&self) -> Result<Vec<OfferView>, String> {
        let mut e = Encoder::new();
        e.u8(crate::rpc::OP_OFFERS).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().map_err(|_| "malformed offer list".to_string())?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(OfferView {
                id: d.u64().map_err(|_| "truncated offer".to_string())?,
                maker: d.array::<32>().map_err(|_| "truncated offer".to_string())?,
                offer_asset: d.array::<32>().unwrap_or([0; 32]),
                offer_amount: d.fixed().unwrap_or(Fixed::ZERO),
                want_asset: d.array::<32>().unwrap_or([0; 32]),
                want_amount: d.fixed().unwrap_or(Fixed::ZERO),
                expires_at_epoch: d.u64().unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// One offer by id.
    pub fn offer(&self, id: u64) -> Result<Option<OfferView>, String> {
        Ok(self.offers()?.into_iter().find(|o| o.id == id))
    }

    /// Anchors published so far, oldest first. `limit` of 0 means all of them.
    ///
    /// This is the mapping anyone checking the chain actually wants: which
    /// Zcash transaction carries the root for a given epoch.
    pub fn anchors(&self, limit: u32) -> Result<Vec<AnchorView>, String> {
        let mut e = Encoder::new();
        e.u8(crate::rpc::OP_ANCHORS).u32(self.chain).u32(limit);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().map_err(|_| "malformed anchor list".to_string())?;
        let mut out = Vec::new();
        for _ in 0..n {
            let epoch = d.u64().map_err(|_| "truncated anchor".to_string())?;
            let root = d
                .array::<32>()
                .map_err(|_| "truncated anchor".to_string())?;
            let anchor_id = d
                .array::<32>()
                .map_err(|_| "truncated anchor".to_string())?;
            let len = d.u16().map_err(|_| "truncated anchor".to_string())? as usize;
            let txid = d
                .take_bytes(len)
                .map_err(|_| "truncated anchor".to_string())?;
            out.push(AnchorView {
                epoch,
                root,
                anchor_id,
                txid: String::from_utf8_lossy(txid).to_string(),
                height: d.u64().unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Submit a co-signed intent — a trade both sides agreed to.
    pub fn submit_co_signed(
        &self,
        auth: &Authorization,
        creds: &[Vec<u8>],
        intent: &Intent,
    ) -> Result<Vec<u8>, String> {
        let mut e = Encoder::new();
        e.u8(OP_SUBMIT_MULTI).u32(self.chain);
        e.bytes(&frame_co_signed(auth, creds, intent));
        self.call(e.finish())
    }

    // Thin wrappers on `submit`, so applications state what they mean rather
    // than assembling intents by hand. The chain enforces the rules; these
    // only spell them.

    // ---- Cave launches ----

    #[allow(clippy::too_many_arguments)]
    pub fn launch_curve(
        &self,
        k: &SigningKey,
        symbol: swapvm::state::Symbol,
        display_name: Vec<u8>,
        metadata_hash: [u8; 32],
        fee_bps: u16,
        dev_buy: Fixed,
        max_zec: Fixed,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::LaunchCurve {
                creator: account_of_key(k),
                symbol,
                display_name,
                metadata_hash,
                fee_bps,
                dev_buy,
                max_zec,
            },
        )
    }

    pub fn buy_curve(
        &self,
        k: &SigningKey,
        asset: AssetId,
        tokens: Fixed,
        max_zec: Fixed,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::BuyCurve {
                buyer: account_of_key(k),
                asset,
                tokens,
                max_zec,
            },
        )
    }

    pub fn sell_curve(
        &self,
        k: &SigningKey,
        asset: AssetId,
        tokens: Fixed,
        min_zec: Fixed,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::SellCurve {
                seller: account_of_key(k),
                asset,
                tokens,
                min_zec,
            },
        )
    }

    // ---- collections ----

    // ---- offers ----

    /// Commit an asset at a price and leave it resting until someone takes it.
    pub fn place_offer(
        &self,
        k: &SigningKey,
        offer_asset: AssetId,
        offer_amount: Fixed,
        want_asset: AssetId,
        want_amount: Fixed,
        expires_at_epoch: u64,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::PlaceOffer {
                maker: account_of_key(k),
                offer_asset,
                offer_amount,
                want_asset,
                want_amount,
                expires_at_epoch,
            },
        )
    }

    /// Take a resting offer at its stated price. Signed by the taker alone.
    pub fn take_offer(&self, k: &SigningKey, offer: u64) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::TakeOffer {
                taker: account_of_key(k),
                offer,
            },
        )
    }

    /// Withdraw a resting offer and take the asset back.
    pub fn cancel_offer(&self, k: &SigningKey, offer: u64) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::CancelOffer {
                maker: account_of_key(k),
                offer,
            },
        )
    }

    pub fn create_collection(
        &self,
        k: &SigningKey,
        symbol: swapvm::state::Symbol,
        cap: u32,
        fee_bps: u16,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::CreateCollection {
                creator: account_of_key(k),
                symbol,
                cap,
                fee_bps,
            },
        )
    }

    /// Mint one item to `to`. Creator only, and only while claiming is open.
    pub fn mint_collection_item(
        &self,
        k: &SigningKey,
        collection: CollectionId,
        serial: u32,
        to: [u8; 32],
        symbol: swapvm::state::Symbol,
        content: [u8; 32],
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::MintCollectionItem {
                creator: account_of_key(k),
                collection,
                serial,
                to,
                symbol,
                content,
            },
        )
    }

    /// Pay into the pool. The mint proceeds, a trade fee, a gift — all the
    /// same to the holders, and all of them raise the floor.
    pub fn fund_collection(
        &self,
        k: &SigningKey,
        collection: CollectionId,
        amount: Fixed,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::FundCollection {
                from: account_of_key(k),
                collection,
                amount,
            },
        )
    }

    /// Burn one item for its share of the pool. Only once the market is open.
    pub fn redeem_collection_item(
        &self,
        k: &SigningKey,
        asset: AssetId,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::RedeemCollectionItem {
                holder: account_of_key(k),
                asset,
            },
        )
    }

    /// Move the collection on: depositing → minting → closed → live.
    pub fn advance_collection(
        &self,
        k: &SigningKey,
        collection: CollectionId,
        to: u8,
    ) -> Result<Accepted, String> {
        self.submit(
            k,
            Intent::AdvanceCollection {
                creator: account_of_key(k),
                collection,
                to,
            },
        )
    }

    pub fn call(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        let mut s = TcpStream::connect(&self.addr)
            .map_err(|e| format!("cannot reach the node at {}: {}", self.addr, e))?;
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        s.write_all(&(frame.len() as u32).to_be_bytes())
            .and_then(|_| s.write_all(frame))
            .map_err(|e| e.to_string())?;
        let mut len = [0u8; 4];
        s.read_exact(&mut len)
            .map_err(|_| "no reply from the node".to_string())?;
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut body)
            .map_err(|_| "truncated reply".to_string())?;
        if body.first() == Some(&wire::STATUS_ERR) {
            let n = u16::from_be_bytes([
                body.get(1).copied().unwrap_or(0),
                body.get(2).copied().unwrap_or(0),
            ]) as usize;
            return Err(format!(
                "node refused: {}",
                String::from_utf8_lossy(body.get(3..3 + n).unwrap_or(b""))
            ));
        }
        if body.is_empty() {
            return Err("empty reply".into());
        }
        Ok(body[1..].to_vec())
    }

    pub fn status(&self) -> Result<Status, String> {
        let mut e = Encoder::new();
        e.u8(wire::OP_STATUS).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let bad = |_| "bad status".to_string();
        let mut st = Status {
            seq: d.u64().map_err(bad)?,
            epoch: d.u64().map_err(bad)?,
            root: d.hash().map_err(bad)?,
            backing: d.fixed().map_err(bad)?,
            pools: d.u32().map_err(bad)?,
            accounts: d.u32().map_err(bad)?,
            health: Vec::new(),
            clearing: false,
            role: 0,
            anchored_epoch: 0,
            verified_height: 0,
            forced_pending: 0,
            censored: 0,
        };
        if let Ok(n) = d.u32() {
            for _ in 0..n {
                let name = d
                    .u16()
                    .ok()
                    .and_then(|l| d.take_bytes(l as usize).ok())
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .unwrap_or_default();
                let scanned_to = d.u64().unwrap_or(0);
                let down = d.u8().unwrap_or(0) != 0;
                let _fails = d.u32().unwrap_or(0);
                let error = d
                    .u16()
                    .ok()
                    .and_then(|l| d.take_bytes(l as usize).ok())
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .unwrap_or_default();
                st.health.push(Health {
                    name,
                    scanned_to,
                    down,
                    error,
                });
            }
            st.clearing = d.u8().map(|b| b != 0).unwrap_or(false);
            st.role = d.u8().unwrap_or(0);
            st.anchored_epoch = d.u64().unwrap_or(0);
            st.verified_height = d.u64().unwrap_or(0);
            st.forced_pending = d.u32().unwrap_or(0);
            st.censored = d.u32().unwrap_or(0);
        }
        Ok(st)
    }

    /// The published leaves at the anchored root, every page of them.
    pub fn published(&self) -> Result<zyn::da::Published, String> {
        let mut offset = 0u32;
        let mut out: Option<zyn::da::Published> = None;
        loop {
            let mut e = Encoder::new();
            e.u8(wire::OP_SNAPSHOT)
                .u32(self.chain)
                .u32(offset)
                .u32(crate::rpc::SNAPSHOT_PAGE);
            let body = self.call(e.finish())?;
            let mut d = Decoder::new(&body);
            let bad = |_| "malformed snapshot".to_string();
            let epoch = d.u64().map_err(bad)?;
            let root = d.hash().map_err(bad)?;
            let ns = d.u32().map_err(bad)? as usize;
            let mut sections = Vec::with_capacity(ns.min(64));
            for _ in 0..ns {
                sections.push(d.hash().map_err(bad)?);
            }
            let k = d.u32().map_err(bad)? as usize;
            let mut leaves = Vec::with_capacity(k);
            for _ in 0..k {
                leaves.push(d.hash().map_err(bad)?);
            }
            let total = d.u32().unwrap_or(k as u32);
            let p = out.get_or_insert(zyn::da::Published {
                chain_id: self.chain,
                epoch,
                root,
                sections,
                leaves: Vec::new(),
            });
            p.leaves.extend(leaves);
            offset += k as u32;
            if k == 0 || offset >= total {
                break;
            }
        }
        out.ok_or_else(|| "empty snapshot".to_string())
    }

    pub fn pools(&self) -> Result<Vec<Pool>, String> {
        let mut e = Encoder::new();
        e.u8(wire::OP_POOLS).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().unwrap_or(0);
        let mut out = Vec::new();
        for _ in 0..n {
            let (id, asset0, asset1) = (
                d.array::<32>().unwrap_or([0; 32]),
                d.array::<32>().unwrap_or([0; 32]),
                d.array::<32>().unwrap_or([0; 32]),
            );
            let (reserve0, reserve1, fee_bps) = (
                d.fixed().unwrap_or(Fixed::ZERO),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.u16().unwrap_or(0),
            );
            let has = d.u8().unwrap_or(0) != 0;
            let price = d.fixed().unwrap_or(Fixed::ZERO);
            let at = d.u64().unwrap_or(0);
            let effective_fee_bps = d.u16().unwrap_or(fee_bps);
            out.push(Pool {
                id,
                asset0,
                asset1,
                reserve0,
                reserve1,
                fee_bps,
                reference: has.then_some((price, at)),
                effective_fee_bps,
            });
        }
        Ok(out)
    }

    pub fn assets(&self) -> Result<Vec<Asset>, String> {
        let mut e = Encoder::new();
        e.u8(OP_ASSETS).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().unwrap_or(0);
        let mut out = Vec::new();
        for _ in 0..n {
            let id = d.array::<32>().unwrap_or([0; 32]);
            let symbol_len = d.u8().unwrap_or(0) as usize;
            let sym = d.take_bytes(symbol_len).unwrap_or(&[]);
            let symbol = String::from_utf8_lossy(sym).to_string();
            let supply = d.fixed().unwrap_or(Fixed::ZERO);
            let has_lp = d.u8().unwrap_or(0) != 0;
            let lp_id = d.array::<32>().unwrap_or([0; 32]);
            let lp = has_lp.then_some(lp_id);
            let has_content = d.u8().unwrap_or(0) != 0;
            let content = d.array::<32>().unwrap_or([0u8; 32]);
            let has_collection = d.u8().unwrap_or(0) != 0;
            let collection_id = d.array::<32>().unwrap_or([0; 32]);
            let collection = has_collection.then_some(collection_id);
            out.push(Asset {
                id,
                symbol,
                supply,
                lp_of: lp,
                content: has_content.then_some(content),
                collection,
            });
        }
        Ok(out)
    }

    /// Every Cave curve, including graduated launches and their ZynZap pool.
    pub fn curves(&self) -> Result<Vec<CurveView>, String> {
        let mut e = Encoder::new();
        e.u8(OP_CURVES).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().map_err(|_| "malformed curve list".to_string())?;
        let mut out = Vec::with_capacity(n as usize);
        for _ in 0..n {
            out.push(decode_curve(&mut d)?);
        }
        if d.remaining() != 0 {
            return Err("trailing curve list bytes".into());
        }
        Ok(out)
    }

    /// One Cave launch by its immutable asset address.
    pub fn curve(&self, asset: AssetId) -> Result<Option<CurveView>, String> {
        let mut e = Encoder::new();
        e.u8(OP_CURVE).u32(self.chain).bytes(&asset);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let found = d.u8().map_err(|_| "malformed curve reply".to_string())?;
        if found == 0 {
            if d.remaining() != 0 {
                return Err("trailing curve reply bytes".into());
            }
            return Ok(None);
        }
        if found != 1 {
            return Err("unknown curve reply status".into());
        }
        let curve = decode_curve(&mut d)?;
        if curve.asset != asset {
            return Err("curve reply asset mismatch".into());
        }
        if d.remaining() != 0 {
            return Err("trailing curve reply bytes".into());
        }
        Ok(Some(curve))
    }

    /// Quote an exact token amount against the reversible launch curve.
    pub fn curve_quote(
        &self,
        buy: bool,
        asset: AssetId,
        tokens: Fixed,
    ) -> Result<CurveQuote, String> {
        let mut e = Encoder::new();
        e.u8(OP_CURVE_QUOTE)
            .u32(self.chain)
            .u8((!buy) as u8)
            .bytes(&asset)
            .fixed(tokens);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let quote = CurveQuote {
            principal: d.fixed().map_err(|_| "truncated curve quote".to_string())?,
            fee: d.fixed().map_err(|_| "truncated curve quote".to_string())?,
            settlement: d.fixed().map_err(|_| "truncated curve quote".to_string())?,
            sold_after: d.fixed().map_err(|_| "truncated curve quote".to_string())?,
            price_after: d.fixed().map_err(|_| "truncated curve quote".to_string())?,
            graduates: d.u8().map_err(|_| "truncated curve quote".to_string())? != 0,
        };
        if d.remaining() != 0 {
            return Err("trailing curve quote bytes".into());
        }
        Ok(quote)
    }

    /// Exact-input quote plus its complete, independently displayable fee path.
    pub fn quote(
        &self,
        asset_in: AssetId,
        path: &[PoolId],
        amount: Fixed,
    ) -> Result<SwapQuote, String> {
        let mut e = Encoder::new();
        e.u8(wire::OP_QUOTE)
            .u32(self.chain)
            .bytes(&asset_in)
            .u32(path.len() as u32);
        for p in path {
            e.bytes(p);
        }
        e.i128(amount.0);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let amount_out = d.fixed().map_err(|_| "truncated quote".to_string())?;
        let best_case = d.fixed().map_err(|_| "truncated quote".to_string())?;
        let asset_out = d.array::<32>().map_err(|_| "truncated quote".to_string())?;
        let count = d.u32().map_err(|_| "truncated quote".to_string())?;
        if count as usize > wire::MAX_PATH_WIRE {
            return Err("quote path too long".into());
        }
        let mut hops = Vec::with_capacity(count as usize);
        for _ in 0..count {
            hops.push(Hop {
                pool: d
                    .array::<32>()
                    .map_err(|_| "truncated quote hop".to_string())?,
                asset_in: d
                    .array::<32>()
                    .map_err(|_| "truncated quote hop".to_string())?,
                asset_out: d
                    .array::<32>()
                    .map_err(|_| "truncated quote hop".to_string())?,
                amount_in: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                amount_out: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                fee_asset: d
                    .array::<32>()
                    .map_err(|_| "truncated quote hop".to_string())?,
                fee: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                pool_fee: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                protocol_fee: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                creator_fee: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
                pol_fee: d.fixed().map_err(|_| "truncated quote hop".to_string())?,
            });
        }
        if d.remaining() != 0 {
            return Err("trailing quote bytes".into());
        }
        Ok(SwapQuote {
            amount_out,
            best_case,
            asset_out,
            hops,
        })
    }

    fn signed_read_header(&self, k: &SigningKey, op: u8) -> Result<Encoder, String> {
        let id = account(k);
        let epoch = self.status()?.epoch;
        let sig = k.sign(&read_challenge(self.chain, &id, epoch)).to_bytes();
        let mut e = Encoder::new();
        e.u8(op)
            .u32(self.chain)
            .bytes(&id)
            .u64(epoch)
            .u8(Scheme::Ed25519.tag())
            .bytes(k.verifying_key().as_bytes())
            .bytes(&sig);
        Ok(e)
    }

    /// The account's record — a signed read; the node serves it only to the
    /// holder. `Ok(None)` when the chain has never seen the account.
    pub fn account(&self, k: &SigningKey) -> Result<Option<AccountRecord>, String> {
        let e = self.signed_read_header(k, OP_ACCOUNT)?;
        self.account_body(e.finish())
    }

    /// Serve a signed read the caller built and signed themselves.
    ///
    /// `OP_ACCOUNT` derives the account from the signature, which is what
    /// keeps balances unreadable by strangers. A gateway must relay that
    /// payload rather than accept an account id, or it would turn a signed
    /// read into a public lookup.
    pub fn account_raw(&self, payload: &[u8]) -> Result<Option<AccountRecord>, String> {
        let mut e = Encoder::new();
        e.u8(OP_ACCOUNT).u32(self.chain).bytes(payload);
        self.account_body(e.finish())
    }

    fn account_body(&self, frame: &[u8]) -> Result<Option<AccountRecord>, String> {
        let body = match self.call(frame) {
            Ok(b) => b,
            Err(e) if e.contains("no such account") => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut d = Decoder::new(&body);
        let bad = || "bad account record".to_string();
        if d.take_bytes(17).map_err(|_| bad())? != b"swapvm.account.v1" {
            return Err(bad());
        }
        d.account().map_err(|_| bad())?;
        let mut r = AccountRecord::default();
        for _ in 0..d.u32().map_err(|_| bad())? {
            r.spendable.push((
                d.array::<32>().unwrap_or([0; 32]),
                d.fixed().unwrap_or(Fixed::ZERO),
            ));
        }
        for _ in 0..d.u32().unwrap_or(0) {
            r.exiting.push((
                d.array::<32>().unwrap_or([0; 32]),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.u64().unwrap_or(0),
            ));
        }
        for _ in 0..d.u32().unwrap_or(0) {
            r.unreleased.push((
                d.array::<32>().unwrap_or([0; 32]),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.u64().unwrap_or(0),
            ));
        }
        if let Ok(dest) = d.hash() {
            if dest != [0u8; 32] {
                r.binding = Some(dest)
            }
            if let Ok(1) = d.u8() {
                r.redirect = Some((d.hash().unwrap_or([0; 32]), d.u64().unwrap_or(0)));
            }
        }
        Ok(Some(r))
    }

    /// The holder's record and path against the anchored root — the exit
    /// proof. `Ok(None)` if the account has no record in the anchored
    /// snapshot; an `Err` before the first anchor, since there is nothing to
    /// prove against yet.
    pub fn account_proof(&self, k: &SigningKey) -> Result<Option<Proof>, String> {
        let e = self.signed_read_header(k, wire::OP_ACCOUNT_PROOF)?;
        let body = match self.call(e.finish()) {
            Ok(b) => b,
            Err(e) if e.contains("no such account") => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut d = Decoder::new(&body);
        let bad = |_| "bad proof".to_string();
        let len = d.u32().map_err(bad)? as usize;
        let record = d.take_bytes(len).map_err(bad)?.to_vec();
        let index = d.u32().map_err(bad)?;
        let n = d.u32().map_err(bad)? as usize;
        let mut path = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let right = d.u8().map_err(bad)? != 0;
            path.push(zyn_vm::commit::ProofStep {
                node_is_right: right,
                sibling: d.hash().map_err(bad)?,
            });
        }
        let epoch = d.u64().map_err(bad)?;
        let root = d.hash().map_err(bad)?;
        Ok(Some(Proof {
            epoch,
            root,
            record,
            index,
            path,
        }))
    }

    /// Sign and submit one intent. A rejection is an `Err` naming the reason.
    pub fn submit(&self, k: &SigningKey, intent: Intent) -> Result<Accepted, String> {
        let now = self.status()?.epoch;
        let frame = frame_submission(k, self.chain, now, &intent);
        self.submit_raw(&frame)
    }

    /// Submit a submission frame the caller already built and signed.
    ///
    /// A public gateway holds no key, and the signature commits to these exact
    /// bytes — so they travel from the caller untouched rather than being
    /// re-encoded on the way through. It is the reason Bitcoin has
    /// `sendrawtransaction` instead of structured parameters.
    pub fn submit_raw(&self, frame: &[u8]) -> Result<Accepted, String> {
        let mut e = Encoder::new();
        e.u8(OP_SUBMIT).u32(self.chain).bytes(frame);
        let body = self.call(e.finish())?;
        decode_accepted(&body)
    }

    /// Submit an intent signed by an expiring session key under an owner-issued
    /// delegation. The owner credential is reusable; the session signature is
    /// unique to this intent and is the replay-protected value.
    pub fn submit_delegated(
        &self,
        auth: &Authorization,
        delegated: &Delegated,
        intent: &Intent,
    ) -> Result<Accepted, String> {
        let mut e = Encoder::new();
        e.u8(OP_SUBMIT_DELEGATED)
            .u32(self.chain)
            .bytes(&frame_delegated(auth, delegated, intent));
        let body = self.call(e.finish())?;
        decode_accepted(&body)
    }

    pub fn launch(&self) -> Result<Option<LaunchView>, String> {
        let mut e = Encoder::new();
        e.u8(OP_LAUNCH).u32(self.chain);
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        if d.u8().unwrap_or(0) == 0 {
            return Ok(None);
        }
        let params = swapvm::wire::decode_launch(&mut d).map_err(|_| "bad launch")?;
        let f = |d: &mut Decoder| d.fixed().unwrap_or(Fixed::ZERO);
        Ok(Some(LaunchView {
            params,
            zcash_height: d.u64().unwrap_or(0),
            graduated_at: d.u64().unwrap_or(0),
            zyn: d.array::<32>().unwrap_or([0; 32]),
            genesis_pool: d.array::<32>().unwrap_or([0; 32]),
            minted: f(&mut d),
            last_mint_height: d.u64().unwrap_or(0),
            pot: f(&mut d),
            lp_pot: f(&mut d),
            bridge_pot: f(&mut d),
            pol_zyn: f(&mut d),
            pol_zec: f(&mut d),
            fee_pot: f(&mut d),
            supply: f(&mut d),
            contributors: d.u32().unwrap_or(0),
            contributed: f(&mut d),
            assets: {
                let n = d.u32().unwrap_or(0);
                (0..n)
                    .map(|_| AssetLaunchView {
                        asset: d.array::<32>().unwrap_or([0; 32]),
                        pot: f(&mut d),
                        price: f(&mut d),
                        opened_at: d.u64().unwrap_or(0),
                        pool: d.array::<32>().unwrap_or([0; 32]),
                        grant: f(&mut d),
                        contributors: d.u32().unwrap_or(0),
                        contributed: f(&mut d),
                    })
                    .collect()
            },
            asset_threshold: f(&mut d),
            bootstrap_bps: d.u16().unwrap_or(0),
        }))
    }

    pub fn launch_me(&self, k: &SigningKey) -> Result<LaunchMe, String> {
        let e = self.signed_read_header(k, OP_LAUNCH_ME)?;
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        if d.u8().unwrap_or(0) == 0 {
            return Ok(LaunchMe::default());
        }
        let mut me = LaunchMe {
            contribution: d.fixed().unwrap_or(Fixed::ZERO),
            epoch_fees: d.fixed().unwrap_or(Fixed::ZERO),
            vest_total: d.fixed().unwrap_or(Fixed::ZERO),
            vest_released: d.fixed().unwrap_or(Fixed::ZERO),
            vest_end: d.u64().unwrap_or(0),
            markets: Vec::new(),
        };
        let n = d.u32().unwrap_or(0);
        for _ in 0..n {
            me.markets.push((
                d.array::<32>().unwrap_or([0; 32]),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.u64().unwrap_or(0),
            ));
        }
        Ok(me)
    }

    /// The caller's open orders.
    pub fn orders(&self, k: &SigningKey) -> Result<Vec<OpenOrder>, String> {
        let e = self.signed_read_header(k, OP_ORDERS)?;
        let body = self.call(e.finish())?;
        let mut d = Decoder::new(&body);
        let n = d.u32().unwrap_or(0);
        let mut out = Vec::new();
        for _ in 0..n {
            out.push((
                d.u64().unwrap_or(0),
                d.array::<32>().unwrap_or([0; 32]),
                d.array::<32>().unwrap_or([0; 32]),
                d.fixed().unwrap_or(Fixed::ZERO),
                d.fixed().unwrap_or(Fixed::ZERO),
            ));
        }
        Ok(out)
    }

    /// Tell the operator where the bound exit goes. `kind` 0 = Zcash, 1 = Solana.
    pub fn reveal(
        &self,
        k: &SigningKey,
        kind: u8,
        address: &str,
        salt: &[u8; 32],
    ) -> Result<(), String> {
        let mut e = self.signed_read_header(k, OP_REVEAL)?;
        e.u8(kind)
            .u16(address.len() as u16)
            .bytes(address.as_bytes())
            .bytes(salt);
        self.call(e.finish()).map(|_| ())
    }
}

#[cfg(test)]
mod forced_frame_tests {
    use super::*;
    use swapvm::tx::Intent;

    /// The frame a forced memo carries must survive the round trip the scanner
    /// puts it through: wrapped by `encode_forced`, recovered by
    /// `forced_frame`, and — the part that decides whether a sighting is made
    /// at all — its signer recovered by `forced_account`.
    ///
    /// `shielded.rs` makes a `ForcedSighting` only when **both** helpers return
    /// `Some`. If `forced_account` says `None` the note falls through as an
    /// ordinary memo and the intent is silently never applied, which is
    /// exactly what a forced intent must never do.
    #[test]
    fn a_real_submission_frame_survives_the_memo_and_names_its_signer() {
        let k = SigningKey::from_bytes(&[3u8; 32]);
        let intent = Intent::Transfer {
            from: account(&k),
            to: [2u8; 32],
            asset: swapvm::types::legacy_id(1),
            amount: Fixed::raw(10_000),
        };
        let frame = frame_submission(&k, 11, 4000, &intent);

        let memo = zyn_custody::memo::encode_forced(&frame)
            .expect("a transfer must fit in a memo; if it does not, forcing one is impossible");

        let back = zyn_custody::memo::forced_frame(&memo)
            .expect("the scanner must recognise the memo it was given");
        assert_eq!(back, &frame[..], "the frame changed in transit");

        let signer = zyn_custody::memo::forced_account(back)
            .expect("the scanner must recover the signer, or it makes no sighting");
        assert_eq!(signer, account(&k), "the frame named the wrong account");
    }

    #[test]
    fn browser_protocol_fixture_matches_rust_byte_for_byte() {
        let seed = crate::client::unhex32(
            "57d47cefdba062bb9669a7a64e9072e49d2b5bc66892952429240e4c91b16183",
        )
        .unwrap();
        let k = SigningKey::from_bytes(&seed);
        let id = account(&k);
        let signature = k.sign(&read_challenge(11, &id, 42)).to_bytes();
        let mut read = Encoder::new();
        read.bytes(&id)
            .u64(42)
            .u8(Scheme::Ed25519.tag())
            .bytes(k.verifying_key().as_bytes())
            .bytes(&signature);
        assert_eq!(hex(read.finish()), "b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea000000000000002a01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a612d919d7b6805ae80ff169cbbf7be20b8548456aaf38d6c60a892dc25be1c0fa28d8e5af2a0bb8411aec809507942a8e1b58219c97f151141b172e16b18d210e");

        let intent = Intent::Transfer {
            from: id,
            to: [0x11; 32],
            asset: swapvm::types::legacy_id(7),
            amount: Fixed::ONE,
        };
        assert_eq!(hex(&frame_submission(&k, 11, 42, &intent)), "5cf4557b297390b6c6d08f752fc04a0ac8496349d6fbd0f68657328812d4e5ee000000000000008e01308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a653e89fba1119f7490c8b9c0e58f89db87d4b1e1402b1e9335d05a72b5440f4f4b492289fab01e5a1b05dd80879d1b80ecef529c4c3ff3d7e433a6a7b4305360602b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000700000000000000000de0b6b3a7640000");
    }
}
