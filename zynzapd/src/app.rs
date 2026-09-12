//! Nap Wallet behind every face: a Zcash wallet on either network, a Zyn
//! account on the side, and one JSON API over both. `nap-wallet` serves it
//! over loopback HTTP; the desktop and mobile shells call it in-process;
//! the browser extension talks to whichever of those is running.
//!
//! Every call is `api(method, path, input) -> Result<Value, String>`, so a
//! new face needs no new logic — only a way to carry JSON in and out.
//!
//! Files under the app dir: `settings.json`, `wallet-<network>` (+ `.state`),
//! `history-<network>.json`, `zyn.key`, `binding`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::Fixed;
use zcash_protocol::consensus::Network;
use zyn_custody::lightd::Client;
use zyn_vm::auth::{delegation_bytes_as, Authorization, Scheme, Signed};
use zyn_vm::session::{session_payload, AssetLimit, Delegation, CAP_SWAP};
use zyn_vm::verify::{Credential, Delegated};

use crate::client::{account, fixed_of, hex, load_key, unhex32, Node, ZAT};
use crate::settle::{parse_destination, zcash_commitment};
use crate::wallet::{network_name, unit, Event, Wallet, WalletBackup, CONFIRMATIONS, ZAT_PER_ZEC};

pub const DEFAULT_LIGHTD_TESTNET: &str = "168.119.53.39:8098";
pub const DEFAULT_NODE: &str = "168.119.53.39:8099";
pub const DEFAULT_CHAIN: u32 = 11;
pub const DEFAULT_VAULT: &str = "utest1h6sfz7alnztp0vst6u0s8sxj9zhzrv5s7qjy5897qcdse75epp43x4uus90naxaea973q22nshuggyywujdj5zulckj2vppz85x2t407";

/// Where the keys live and what the app talks to.
#[derive(Clone, Debug)]
pub struct Config {
    pub dir: PathBuf,
    /// A wallet key to use instead of `dir/wallet-<network>` for the
    /// network the app opens on (the CLI's `ZYN_APP_WALLET`).
    pub wallet_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub node: String,
    pub chain: u32,
    pub vault: String,
}

impl Config {
    /// Defaults under `dir`, overridable from the environment the way the
    /// CLI tools are (`ZYN_NODE`, `ZYN_CHAIN`, `ZYN_VAULT`, `ZYN_APP_WALLET`,
    /// `ZYN_APP_KEY`). Block servers live in settings, not here.
    pub fn in_dir(dir: PathBuf) -> Config {
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Config {
            wallet_path: std::env::var("ZYN_APP_WALLET").ok().map(PathBuf::from),
            key_path: std::env::var("ZYN_APP_KEY").ok().map(PathBuf::from),
            node: env("ZYN_NODE", DEFAULT_NODE),
            chain: env("ZYN_CHAIN", &DEFAULT_CHAIN.to_string()).parse().unwrap_or(DEFAULT_CHAIN),
            vault: env("ZYN_VAULT", DEFAULT_VAULT),
            dir,
        }
    }
}

/// Refresh the displayed price after this long, and stop showing it entirely
/// past the second. Ten minutes is far finer than a wallet balance needs and
/// keeps the wallet to a handful of price requests an hour.
const PRICE_TTL: u64 = 600;
const PRICE_MAX_AGE: u64 = 3600;

/// What the person chose: which network, which block servers.
#[derive(Clone, Debug)]
pub struct Settings {
    pub network: Network,
    pub lightd_testnet: String,
    pub lightd_mainnet: String,
    /// Whether to ask the outside world what ZEC is worth. Every fetch tells
    /// a price host that this wallet is awake, so it is the holder's switch
    /// and not a default buried in the code.
    pub price: bool,
}

impl Settings {
    fn load(dir: &std::path::Path) -> Settings {
        let v: Value = std::fs::read(dir.join("settings.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
        let env_lightd = std::env::var("ZYN_LIGHTD").ok();
        Settings {
            network: if v.get("network").and_then(Value::as_str) == Some("mainnet") { Network::MainNetwork } else { Network::TestNetwork },
            lightd_testnet: v.get("lightd_testnet").and_then(Value::as_str).map(String::from).or(env_lightd).unwrap_or_else(|| DEFAULT_LIGHTD_TESTNET.to_string()),
            lightd_mainnet: v.get("lightd_mainnet").and_then(Value::as_str).map(String::from).unwrap_or_default(),
            price: v.get("price").and_then(Value::as_bool).unwrap_or(true),
        }
    }

    fn save(&self, dir: &std::path::Path) -> Result<(), String> {
        std::fs::write(dir.join("settings.json"), self.json().to_string()).map_err(|e| e.to_string())
    }

    fn json(&self) -> Value {
        json!({ "network": network_name(self.network), "lightd_testnet": self.lightd_testnet, "lightd_mainnet": self.lightd_mainnet, "price": self.price })
    }

    fn lightd(&self, network: Network) -> Result<&str, String> {
        let s = if network == Network::MainNetwork { &self.lightd_mainnet } else { &self.lightd_testnet };
        if s.trim().is_empty() {
            return Err(format!("no {} block server is configured yet (Settings)", network_name(network)));
        }
        Ok(s.trim())
    }
}

/// Something slow running on its own thread: a sync, or a payment being
/// proved. The page polls `overview` and shows it; nothing blocks.
#[derive(Clone, Debug)]
pub struct Job {
    pub kind: String,
    pub progress: Option<(u64, u64)>,
    pub started: u64,
}

/// The exit destination this account is bound to: our own wallet address
/// and the salt that hides it in the commitment.
#[derive(Clone)]
pub struct Binding {
    pub address: String,
    pub salt: [u8; 32],
    pub revealed: bool,
    /// 0 = Zcash address, 1 = Solana address.
    pub kind: u8,
}

const AGENT_SCHEMA: &str = "nap.agent.v1";
const MAX_MANDATE_EPOCHS: u64 = 100;
const MAX_AGENT_LIST: usize = 16;

/// Nap-owned authority and policy. The session seed never crosses the agent
/// API; callers refer to this record by id.
#[derive(Clone, Debug)]
struct AgentMandate {
    id: String,
    session_seed: [u8; 32],
    allowed_assets: Vec<u32>,
    allowed_pools: Vec<u32>,
    max_per_action: Vec<(u32, Fixed)>,
    max_slippage_bps: u16,
    valid_from_epoch: u64,
    valid_until_epoch: u64,
    created_at: u64,
    state: String,
}

#[derive(Clone, Debug, Default)]
struct AgentStore {
    mandates: BTreeMap<String, AgentMandate>,
    actions: BTreeMap<String, Value>,
}

impl Binding {
    fn commitment(&self, network: Network) -> Result<[u8; 32], String> {
        match self.kind {
            0 => {
                let dest = parse_destination(&self.address, network).ok_or("bound address does not parse")?;
                Ok(zcash_commitment(&dest, &self.salt))
            }
            _ => {
                let pk = zyn_custody::solana::pubkey(&self.address).ok_or("bound Solana address does not parse")?;
                Ok(zyn_bridge::solana::commitment(&pk, &self.salt))
            }
        }
    }
}

pub struct App {
    cfg: Config,
    pub wallet: Mutex<Wallet>,
    pub settings: Mutex<Settings>,
    pub key: SigningKey,
    pub node: Node,
    pub vault: String,
    binding_path: PathBuf,
    binding: Mutex<Option<Binding>>,
    /// This account's own deposit address, once the node has issued one.
    /// Asked for lazily and remembered: it is a function of the account, so
    /// it never changes, and a wallet that cannot reach the node still has it.
    deposit_address: Mutex<Option<String>>,
    /// What happened, newest last.
    log: Mutex<Vec<String>>,
    job: Mutex<Option<Job>>,
    /// The wallet part of the last overview, served while the wallet is
    /// busy on a job and cannot be read.
    view: Mutex<Option<Value>>,
    /// ZEC in dollars, and when it was fetched. Only for display: nothing in
    /// the protocol reads it, and §8 keeps it that way. Refreshed off the
    /// request thread, so a slow or dead price host never stalls the wallet.
    price: Arc<Mutex<Option<(f64, u64)>>>,
    price_fetching: Arc<Mutex<bool>>,
    agent_path: PathBuf,
    agent: Mutex<AgentStore>,
}

impl App {
    /// Open (or create) the wallet for the chosen network and the account
    /// key, reaching the block server once to confirm the network.
    pub fn open(cfg: &Config) -> Result<App, String> {
        std::fs::create_dir_all(&cfg.dir).map_err(|e| format!("app dir: {}", e))?;
        let settings = Settings::load(&cfg.dir);
        let wallet = App::open_wallet(cfg, &settings, settings.network, true)?;
        let key_path = cfg.key_path.clone().unwrap_or_else(|| cfg.dir.join("zyn.key"));
        if !key_path.exists() {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            std::fs::write(&key_path, seed).map_err(|e| format!("write key: {}", e))?;
        }
        let key = load_key(&key_path.to_string_lossy())?;
        let binding_path = cfg.dir.join("binding");
        let binding = App::load_binding(&binding_path);
        let agent_path = cfg.dir.join("agent.json");
        let agent = App::load_agent_store(&agent_path, account(&key));
        Ok(App {
            cfg: cfg.clone(),
            wallet: Mutex::new(wallet),
            settings: Mutex::new(settings),
            key,
            node: Node::new(&cfg.node, cfg.chain),
            vault: cfg.vault.clone(),
            binding_path,
            binding: Mutex::new(binding),
            deposit_address: Mutex::new(App::load_deposit_address(&cfg.dir)),
            log: Mutex::new(Vec::new()),
            job: Mutex::new(None),
            view: Mutex::new(None),
            price: Arc::new(Mutex::new(None)),
            price_fetching: Arc::new(Mutex::new(false)),
            agent_path,
            agent: Mutex::new(agent),
        })
    }

    pub fn job(&self) -> Option<Job> {
        self.job.lock().ok().and_then(|j| j.clone())
    }

    /// Run `f` on its own thread as the one job; refuse if one is running.
    /// What one ZEC is worth in dollars, for display only.
    ///
    /// Never fetches on the caller's thread. The wallet's overview is polled
    /// every second and a half while a job runs; a price host having a bad day
    /// must not be able to stall that. A refresh is started behind a stale
    /// value and the caller gets what is already known.
    fn zec_usd(app: &App) -> Option<f64> {
        if !app.settings.lock().ok()?.price { return None }
        let now = App::now();
        let cached = app.price.lock().ok().and_then(|p| *p);
        if cached.is_none_or(|(_, at)| now.saturating_sub(at) > PRICE_TTL) { app.refresh_price() }
        // Past the hard limit nothing is shown. A price from yesterday
        // presented as today's is worse than admitting there is none.
        cached.filter(|(_, at)| now.saturating_sub(*at) <= PRICE_MAX_AGE).map(|(px, _)| px)
    }

    /// Fetch in the background. Only the two price cells travel to the thread,
    /// so this needs no `Arc<App>` and stays callable from `overview`.
    fn refresh_price(&self) {
        {
            let Ok(mut f) = self.price_fetching.lock() else { return };
            if *f { return }
            *f = true;
        }
        let (cell, flag) = (Arc::clone(&self.price), Arc::clone(&self.price_fetching));
        std::thread::spawn(move || {
            // The same two sources, spread check and jump guard the sequencer
            // uses for pool references. A wallet inventing its own weaker
            // price path would be the second answer to a solved question.
            let mut feeds = crate::feeds::Feeds::new(
                crate::feeds::FeedConfig::default(),
                crate::feeds::default_map(),
                crate::feeds::Http::default(),
            );
            let (prices, _) = feeds.prices(&["ZEC".to_string()]);
            if let Some(px) = prices.get("ZEC").filter(|p| **p > 0.0) {
                if let Ok(mut c) = cell.lock() { *c = Some((*px, App::now())) }
            }
            if let Ok(mut f) = flag.lock() { *f = false }
        });
    }

    fn start_job(app: &Arc<App>, kind: &str, f: impl FnOnce(&App) -> Result<String, String> + Send + 'static) -> Result<Value, String> {
        {
            let mut j = app.job.lock().map_err(|_| "busy")?;
            if let Some(j) = j.as_ref() {
                return Err(format!("still busy: {}", j.kind));
            }
            *j = Some(Job { kind: kind.to_string(), progress: None, started: App::now() });
        }
        let app2 = Arc::clone(app);
        let kind = kind.to_string();
        let kind2 = kind.clone();
        std::thread::spawn(move || {
            match f(&app2) {
                Ok(msg) => { if !msg.is_empty() { app2.note(msg) } }
                Err(e) => app2.note(format!("error: {} failed: {}", kind2, e)),
            }
            if let Ok(mut j) = app2.job.lock() { *j = None; }
        });
        Ok(json!({ "started": true, "job": kind }))
    }

    fn set_progress(&self, at: u64, to: u64) {
        if let Ok(mut j) = self.job.lock() {
            if let Some(j) = j.as_mut() { j.progress = Some((at, to)); }
        }
    }

    fn open_wallet(cfg: &Config, settings: &Settings, network: Network, allow_override: bool) -> Result<Wallet, String> {
        let lightd = settings.lightd(network)?;
        let path = match (&cfg.wallet_path, allow_override) {
            (Some(p), true) => p.clone(),
            _ => cfg.dir.join(format!("wallet-{}", network_name(network))),
        };
        let p = path.to_string_lossy().to_string();
        let w = if path.exists() { Wallet::open(&p, Client::new(lightd))? } else { Wallet::create(&p, Client::new(lightd))? };
        if w.network() != network {
            return Err(format!("the block server at {} is {}, not {}", lightd, network_name(w.network()), network_name(network)));
        }
        Ok(w)
    }

    pub fn note(&self, s: String) {
        eprintln!("nap: {}", s);
        if let Ok(mut l) = self.log.lock() {
            l.push(s);
            if l.len() > 200 { l.remove(0); }
        }
    }

    fn load_deposit_address(dir: &std::path::Path) -> Option<String> {
        let s = std::fs::read_to_string(dir.join("deposit-address")).ok()?;
        let s = s.trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    /// This account's deposit address, asking the node the first time.
    ///
    /// One address per account and no memo, so any shielded wallet can pay it
    /// — including this one. Falls back to the shared vault address on a node
    /// too old to issue them, where a memo is still the only attribution.
    pub fn deposit_address(&self) -> Option<String> {
        if let Some(a) = self.deposit_address.lock().ok()?.clone() {
            return Some(a);
        }
        let addr = self.node.deposit_address(account(&self.key)).ok()?;
        let _ = std::fs::write(self.cfg.dir.join("deposit-address"), &addr);
        *self.deposit_address.lock().ok()? = Some(addr.clone());
        Some(addr)
    }

    /// `Some(why)` when this wallet and its Zyn node are on different chains.
    ///
    /// Checked from the deposit address the node hands out, which is already
    /// fetched and already encoded for the node's own network — so a testnet
    /// node answers a mainnet wallet with `utest1…` and gives itself away. No
    /// extra round trip, and no new protocol to keep in step.
    pub fn chain_mismatch(&self) -> Option<String> {
        let network = self.wallet.lock().ok()?.network();
        let addr = self.deposit_address()?;
        let mainnet_wallet = network == Network::MainNetwork;
        let mainnet_node = !addr.starts_with("utest1");
        if mainnet_wallet == mainnet_node {
            return None;
        }
        Some(format!(
            "this wallet is on {} but its Zyn node custodies {} — refusing to mix them",
            if mainnet_wallet { "mainnet" } else { "testnet" },
            if mainnet_node { "mainnet" } else { "testnet" }
        ))
    }

    fn load_binding(path: &PathBuf) -> Option<Binding> {
        let s = std::fs::read_to_string(path).ok()?;
        let mut it = s.split_whitespace();
        let address = it.next()?.to_string();
        let salt = unhex32(it.next()?).ok()?;
        let revealed = it.next() == Some("1");
        let kind = it.next().and_then(|k| k.parse().ok()).unwrap_or(0);
        Some(Binding { address, salt, revealed, kind })
    }

    fn save_binding(&self, b: &Binding) -> Result<(), String> {
        std::fs::write(&self.binding_path, format!("{} {} {} {}\n", b.address, hex(&b.salt), if b.revealed { 1 } else { 0 }, b.kind)).map_err(|e| e.to_string())
    }

    /// Bind the account's exits to `address` (kind 0 Zcash, 1 Solana), keep
    /// the salt, and reveal the preimage to the operator. Idempotent.
    fn bind_to(&self, address: &str, kind: u8, network: Network) -> Result<(), String> {
        use rand::RngCore;
        let existing = self.binding.lock().map_err(|_| "busy")?.clone();
        let mut b = match existing {
            Some(b) if b.address == address && b.kind == kind => b,
            _ => {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                Binding { address: address.to_string(), salt, revealed: false, kind }
            }
        };
        let commitment = b.commitment(network)?;
        let record = self.node.account(&self.key)?.unwrap_or_default();
        if record.binding != Some(commitment) {
            let acc = self.node.submit(&self.key, Intent::BindWithdrawal { account: account(&self.key), destination: commitment })?;
            self.note(format!("bound exits to {}… (seq {})", &address[..address.len().min(12)], acc.seq));
            b.revealed = false;
        }
        self.save_binding(&b)?;
        *self.binding.lock().map_err(|_| "busy")? = Some(b.clone());
        if !b.revealed {
            self.node.reveal(&self.key, kind, &b.address, &b.salt)?;
            b.revealed = true;
            self.save_binding(&b)?;
            *self.binding.lock().map_err(|_| "busy")? = Some(b.clone());
            self.note("revealed the destination to the operator; exits can be paid".to_string());
        }
        Ok(())
    }

    // ---- history: what the wallet has seen, per network, on disk --------

    fn history_path(&self, network: Network) -> PathBuf {
        self.cfg.dir.join(format!("history-{}.json", network_name(network)))
    }

    fn history(&self, network: Network) -> Vec<Value> {
        std::fs::read(self.history_path(network)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).and_then(|v| v.as_array().cloned()).unwrap_or_default()
    }

    fn write_history(&self, network: Network, h: &[Value]) {
        let _ = std::fs::write(self.history_path(network), Value::Array(h.to_vec()).to_string());
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    fn agent_mandate_id(owner: [u8; 32], m: &AgentMandate) -> String {
        let session = SigningKey::from_bytes(&m.session_seed);
        let mut h = Sha256::new();
        h.update(b"nap.agent.mandate.v1");
        h.update(owner);
        h.update(session.verifying_key().as_bytes());
        h.update(CAP_SWAP.to_be_bytes());
        for asset in &m.allowed_assets { h.update(asset.to_be_bytes()); }
        h.update([0xff]);
        for pool in &m.allowed_pools { h.update(pool.to_be_bytes()); }
        h.update([0xfe]);
        for (asset, amount) in &m.max_per_action {
            h.update(asset.to_be_bytes());
            h.update(amount.0.to_be_bytes());
        }
        h.update(m.max_slippage_bps.to_be_bytes());
        h.update(m.valid_from_epoch.to_be_bytes());
        h.update(m.valid_until_epoch.to_be_bytes());
        hex(&h.finalize())
    }

    fn mandate_json(m: &AgentMandate) -> Value {
        json!({
            "id": m.id,
            "capabilities": ["swap"],
            "allowed_assets": m.allowed_assets,
            "allowed_pools": m.allowed_pools,
            "max_per_action_raw": m.max_per_action.iter().map(|(asset, amount)| json!({"asset": asset, "amount": amount.0.to_string()})).collect::<Vec<_>>(),
            "max_slippage_bps": m.max_slippage_bps,
            "valid_from_epoch": m.valid_from_epoch,
            "valid_until_epoch": m.valid_until_epoch,
            "created_at": m.created_at,
            "state": m.state,
            "on_chain_revocation": false,
        })
    }

    fn agent_store_json(store: &AgentStore) -> Value {
        json!({
            "schema": AGENT_SCHEMA,
            "mandates": store.mandates.values().map(|m| json!({
                "id": m.id,
                "session_seed": hex(&m.session_seed),
                "allowed_assets": m.allowed_assets,
                "allowed_pools": m.allowed_pools,
                "max_per_action_raw": m.max_per_action.iter().map(|(asset, amount)| json!([asset, amount.0.to_string()])).collect::<Vec<_>>(),
                "max_slippage_bps": m.max_slippage_bps,
                "valid_from_epoch": m.valid_from_epoch,
                "valid_until_epoch": m.valid_until_epoch,
                "created_at": m.created_at,
                "state": m.state,
            })).collect::<Vec<_>>(),
            "actions": store.actions,
        })
    }

    fn load_agent_store(path: &Path, owner: [u8; 32]) -> AgentStore {
        let Some(root) = std::fs::read(path).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
            return AgentStore::default();
        };
        if root.get("schema").and_then(Value::as_str) != Some(AGENT_SCHEMA) {
            return AgentStore::default();
        }
        let mut store = AgentStore::default();
        for v in root.get("mandates").and_then(Value::as_array).into_iter().flatten() {
            let Some(seed) = v.get("session_seed").and_then(Value::as_str).and_then(|s| unhex32(s).ok()) else { continue };
            let list = |name: &str| -> Option<Vec<u32>> {
                let values = v.get(name)?.as_array()?;
                if values.is_empty() || values.len() > MAX_AGENT_LIST { return None; }
                let mut out: Vec<u32> = values.iter().map(|x| x.as_u64().and_then(|n| u32::try_from(n).ok())).collect::<Option<_>>()?;
                out.sort_unstable();
                out.dedup();
                (out.len() == values.len()).then_some(out)
            };
            let Some(allowed_assets) = list("allowed_assets") else { continue };
            let Some(allowed_pools) = list("allowed_pools") else { continue };
            let Some(limits) = v.get("max_per_action_raw").and_then(Value::as_array) else { continue };
            if limits.is_empty() || limits.len() > MAX_AGENT_LIST { continue; }
            let mut max_per_action = Vec::with_capacity(limits.len());
            for limit in limits {
                let Some(pair) = limit.as_array().filter(|x| x.len() == 2) else { max_per_action.clear(); break };
                let Some(asset) = pair[0].as_u64().and_then(|n| u32::try_from(n).ok()) else { max_per_action.clear(); break };
                let Some(amount) = pair[1].as_str().and_then(|s| s.parse::<i128>().ok()).filter(|n| *n > 0) else { max_per_action.clear(); break };
                max_per_action.push((asset, Fixed::raw(amount)));
            }
            if max_per_action.is_empty() { continue; }
            max_per_action.sort_by_key(|x| x.0);
            if max_per_action.windows(2).any(|w| w[0].0 == w[1].0) { continue; }
            let Some(max_slippage_bps) = v.get("max_slippage_bps").and_then(Value::as_u64).and_then(|n| u16::try_from(n).ok()).filter(|n| *n <= 2_000) else { continue };
            let Some(valid_from_epoch) = v.get("valid_from_epoch").and_then(Value::as_u64) else { continue };
            let Some(valid_until_epoch) = v.get("valid_until_epoch").and_then(Value::as_u64).filter(|n| *n >= valid_from_epoch && n.saturating_sub(valid_from_epoch) <= MAX_MANDATE_EPOCHS) else { continue };
            let Some(created_at) = v.get("created_at").and_then(Value::as_u64) else { continue };
            let state = v.get("state").and_then(Value::as_str).filter(|s| matches!(*s, "active" | "paused" | "closed")).unwrap_or("paused").to_string();
            let mut mandate = AgentMandate { id: String::new(), session_seed: seed, allowed_assets, allowed_pools, max_per_action, max_slippage_bps, valid_from_epoch, valid_until_epoch, created_at, state };
            mandate.id = App::agent_mandate_id(owner, &mandate);
            if v.get("id").and_then(Value::as_str) != Some(mandate.id.as_str()) { continue; }
            store.mandates.insert(mandate.id.clone(), mandate);
        }
        if let Some(actions) = root.get("actions").and_then(Value::as_object) {
            for (request, action) in actions {
                if valid_request_id(request) { store.actions.insert(request.clone(), action.clone()); }
            }
        }
        store
    }

    fn save_agent_store(&self, store: &AgentStore) -> Result<(), String> {
        let tmp = self.agent_path.with_extension("json.tmp");
        let bytes = App::agent_store_json(store).to_string();
        let mut options = std::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options.open(&tmp).map_err(|e| format!("write agent store: {e}"))?;
        file.write_all(bytes.as_bytes()).map_err(|e| format!("write agent store: {e}"))?;
        file.sync_all().map_err(|e| format!("sync agent store: {e}"))?;
        std::fs::rename(&tmp, &self.agent_path).map_err(|e| format!("replace agent store: {e}"))
    }

    /// Fold sync events into the history. A received note is a receipt
    /// unless it is the change of something we sent; a spend confirms the
    /// send it belongs to — or, on a rescan that finds a send this file
    /// never saw, reconstructs it from the chain: what left minus the
    /// change that came back.
    fn record(&self, network: Network, events: &[Event]) {
        let mut h = self.history(network);
        let mut changed = false;
        // Per spending txid: value spent, and memo-less value received back (change).
        let mut spent_by: std::collections::BTreeMap<String, (u64, u64, u64)> = Default::default();
        for e in events {
            match e {
                Event::Spent { txid_hex, zatoshi, height, .. } => { let x = spent_by.entry(txid_hex.clone()).or_insert((0, 0, *height)); x.0 += zatoshi; }
                Event::Received { txid_hex, zatoshi, memo, .. } if memo.is_empty() => { let x = spent_by.entry(txid_hex.clone()).or_insert((0, 0, 0)); x.1 += zatoshi; }
                _ => {}
            }
        }
        for e in events {
            match e {
                Event::Received { zatoshi, height, txid_hex, memo, pool } => {
                    let ours = spent_by.get(txid_hex).map(|x| x.0 > 0).unwrap_or(false);
                    let sent = h.iter().any(|x| x["kind"] != "received" && x["txid"] == txid_hex.as_str());
                    let seen = h.iter().any(|x| x["kind"] == "received" && x["txid"] == txid_hex.as_str() && x["zatoshi"] == *zatoshi);
                    // Change from our own transaction is not a receipt; a
                    // memo'd note in it is (someone, maybe us, wrote to us).
                    if !seen && !((ours || sent) && memo.is_empty()) {
                        h.push(json!({ "kind": "received", "txid": txid_hex, "zatoshi": zatoshi, "height": height, "memo": memo, "pool": format!("{:?}", pool), "at": App::now() }));
                        changed = true;
                    }
                }
                Event::Spent { txid_hex, height, .. } => {
                    let mut known = false;
                    for x in h.iter_mut() {
                        if x["kind"] != "received" && x["txid"] == txid_hex.as_str() {
                            known = true;
                            if x["height"] == 0 { x["height"] = json!(height); changed = true; }
                        }
                    }
                    if !known {
                        let (spent, change, at_height) = spent_by[txid_hex];
                        h.push(json!({ "kind": "sent", "txid": txid_hex, "zatoshi": spent.saturating_sub(change), "height": at_height, "memo": "", "to": "", "reconstructed": true, "at": App::now() }));
                        spent_by.insert(txid_hex.clone(), (0, 0, at_height)); // once
                        changed = true;
                    }
                }
                Event::Progress { .. } => {}
            }
        }
        if changed { self.write_history(network, &h); }
    }
}

// ---------------------------------------------------------------------------
// The API
// ---------------------------------------------------------------------------

fn str_of<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.trim().is_empty()).ok_or_else(|| format!("{} is required", k))
}

fn zatoshi_of(v: &Value, k: &str) -> Result<u64, String> {
    let s = str_of(v, k)?;
    let zec: f64 = s.trim().parse().map_err(|_| format!("{} is not an amount", s))?;
    if zec.is_nan() || zec <= 0.0 { return Err("amount must be positive".into()) }
    Ok((zec * ZAT_PER_ZEC).round() as u64)
}

fn zec(zat: u64) -> f64 {
    zat as f64 / ZAT_PER_ZEC
}

fn valid_request_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn agent_u32_list(input: &Value, name: &str) -> Result<Vec<u32>, String> {
    let values = input.get(name).and_then(Value::as_array).ok_or_else(|| format!("{name} is required"))?;
    if values.is_empty() || values.len() > MAX_AGENT_LIST { return Err(format!("{name} must contain 1-{MAX_AGENT_LIST} ids")); }
    let mut out: Vec<u32> = values.iter().map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| format!("invalid {name}"))).collect::<Result<_, _>>()?;
    out.sort_unstable();
    out.dedup();
    if out.len() != values.len() { return Err(format!("{name} contains duplicates")); }
    Ok(out)
}

fn agent_fixed(input: &Value, name: &str) -> Result<Fixed, String> {
    let raw = input.get(name).and_then(Value::as_str).ok_or_else(|| format!("{name} is required"))?;
    let n = raw.parse::<i128>().map_err(|_| format!("invalid {name}"))?;
    if n <= 0 { return Err(format!("{name} must be positive")); }
    Ok(Fixed::raw(n))
}

fn agent_swap(app: &App, input: &Value) -> Result<Intent, String> {
    let asset_in = input.get("asset_in").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or("asset_in is required")?;
    agent_u32_list(input, "path")?;
    // A route may revisit neither a pool nor an id. Sorting would destroy its
    // order, so recover the original after using the helper's validation.
    let path: Vec<u32> = input["path"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
    let amount_in = agent_fixed(input, "amount_in_raw")?;
    let min_out_raw = input.get("min_out_raw").and_then(Value::as_str).ok_or("min_out_raw is required")?.parse::<i128>().map_err(|_| "invalid min_out_raw")?;
    if min_out_raw < 0 { return Err("min_out_raw cannot be negative".into()); }
    Ok(Intent::SwapExactIn { account: account(&app.key), asset_in, path, amount_in, min_out: Fixed::raw(min_out_raw) })
}

fn agent_policy(app: &App, mandate: &AgentMandate, intent: &Intent, epoch: u64) -> Result<Value, String> {
    if mandate.state != "active" { return Err(format!("mandate_{}", mandate.state)); }
    if epoch < mandate.valid_from_epoch { return Err("mandate_not_started".into()); }
    if epoch > mandate.valid_until_epoch { return Err("mandate_expired".into()); }
    let Intent::SwapExactIn { account: owner, asset_in, path, amount_in, min_out } = intent else {
        return Err("operation_permanently_unavailable".into());
    };
    if *owner != account(&app.key) { return Err("wrong_account".into()); }
    if !mandate.allowed_assets.contains(asset_in) { return Err("wrong_asset".into()); }
    if path.iter().any(|p| !mandate.allowed_pools.contains(p)) { return Err("wrong_pool".into()); }
    let max = mandate.max_per_action.iter().find(|(asset, _)| asset == asset_in).map(|(_, amount)| *amount).ok_or("no_amount_limit_for_asset")?;
    if *amount_in > max { return Err("over_limit".into()); }

    let pools = app.node.pools()?;
    let mut asset = *asset_in;
    for id in path {
        let pool = pools.iter().find(|p| p.id == *id).ok_or("unknown_pool")?;
        asset = if pool.asset0 == asset { pool.asset1 } else if pool.asset1 == asset { pool.asset0 } else { return Err("invalid_path".into()); };
        if !mandate.allowed_assets.contains(&asset) { return Err("wrong_asset".into()); }
    }
    let (quoted, best, asset_out) = app.node.quote(*asset_in, path, *amount_in)?;
    let floor = quoted.0.checked_mul((10_000u16 - mandate.max_slippage_bps) as i128).and_then(|n| n.checked_div(10_000)).ok_or("arithmetic")?;
    if min_out.0 < floor { return Err("excessive_slippage".into()); }
    Ok(json!({
        "allowed": true,
        "quote_raw": quoted.0.to_string(),
        "best_case_raw": best.0.to_string(),
        "asset_out": asset_out,
        "required_min_out_raw": floor.to_string(),
    }))
}

pub fn api(app: &Arc<App>, method: &str, path: &str, input: &Value) -> Result<Value, String> {
    match (method, path) {
        ("GET", "/api/agent/status") => {
            zyn_only(app)?;
            let s = app.node.status()?;
            Ok(json!({ "schema": AGENT_SCHEMA, "seq": s.seq, "epoch": s.epoch, "state_root": hex(&s.root), "role": if s.role == 1 { "replica" } else { "sequencer" }, "anchored_epoch": s.anchored_epoch }))
        }
        ("GET", "/api/agent/assets") => {
            zyn_only(app)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "assets": app.node.assets()?.into_iter().map(|a| json!({"id": a.id, "symbol": a.symbol, "supply_raw": a.supply.0.to_string(), "lp_of": a.lp_of, "content": a.content.map(|v| hex(&v)), "collection": a.collection})).collect::<Vec<_>>() }))
        }
        ("GET", "/api/agent/pools") => {
            zyn_only(app)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "pools": app.node.pools()?.into_iter().map(|p| json!({"id": p.id, "asset0": p.asset0, "asset1": p.asset1, "reserve0_raw": p.reserve0.0.to_string(), "reserve1_raw": p.reserve1.0.to_string(), "fee_bps": p.fee_bps, "effective_fee_bps": p.effective_fee_bps, "reference": p.reference.map(|(price, seq)| json!({"price_raw": price.0.to_string(), "seq": seq}))})).collect::<Vec<_>>() }))
        }
        ("GET", "/api/agent/offers") => {
            zyn_only(app)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "offers": app.node.offers()?.into_iter().map(|o| json!({"id": o.id, "maker": hex(&o.maker), "offer_asset": o.offer_asset, "offer_amount_raw": o.offer_amount.0.to_string(), "want_asset": o.want_asset, "want_amount_raw": o.want_amount.0.to_string(), "expires_at_epoch": o.expires_at_epoch})).collect::<Vec<_>>() }))
        }
        ("GET", "/api/agent/anchors") => {
            zyn_only(app)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "anchors": app.node.anchors(20)?.into_iter().map(|a| json!({"epoch": a.epoch, "state_root": hex(&a.root), "anchor_id": hex(&a.anchor_id), "zcash_txid": a.txid, "zcash_height": a.height})).collect::<Vec<_>>() }))
        }
        ("GET", "/api/agent/portfolio") => {
            zyn_only(app)?;
            let record = app.node.account(&app.key)?.unwrap_or_default();
            Ok(json!({ "schema": AGENT_SCHEMA, "account": hex(&account(&app.key)), "spendable": record.spendable.into_iter().map(|(asset, amount)| json!({"asset": asset, "amount_raw": amount.0.to_string()})).collect::<Vec<_>>(), "exiting": record.exiting.into_iter().map(|(asset, amount, epoch)| json!({"asset": asset, "amount_raw": amount.0.to_string(), "requested_epoch": epoch})).collect::<Vec<_>>() }))
        }
        ("POST", "/api/agent/quote") => {
            zyn_only(app)?;
            let asset = input.get("asset_in").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or("asset_in is required")?;
            agent_u32_list(input, "path")?;
            let path: Vec<u32> = input["path"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u32).collect();
            let amount = agent_fixed(input, "amount_in_raw")?;
            let (out, best, asset_out) = app.node.quote(asset, &path, amount)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "asset_in": asset, "asset_out": asset_out, "path": path, "amount_in_raw": amount.0.to_string(), "amount_out_raw": out.0.to_string(), "best_case_raw": best.0.to_string() }))
        }
        ("POST", "/api/agent/draft-swap") => {
            zyn_only(app)?;
            let intent = agent_swap(app, input)?;
            let bytes = swapvm::wire::encode_intent_bytes(&intent);
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let Intent::SwapExactIn { account, asset_in, path, amount_in, min_out } = intent else { unreachable!() };
            Ok(json!({ "schema": AGENT_SCHEMA, "intent": "swap_exact_in", "canonical_hex": hex(&bytes), "intent_digest": hex(&digest), "fields": {"account": hex(&account), "asset_in": asset_in, "path": path, "amount_in_raw": amount_in.0.to_string(), "min_out_raw": min_out.0.to_string()}, "signed": false }))
        }
        ("GET", "/api/agent/mandates") => {
            let store = app.agent.lock().map_err(|_| "agent store busy")?;
            Ok(json!({ "schema": AGENT_SCHEMA, "mandates": store.mandates.values().map(App::mandate_json).collect::<Vec<_>>() }))
        }
        ("POST", "/api/agent/mandates") => {
            zyn_only(app)?;
            let status = app.node.status()?;
            let epochs = input.get("valid_for_epochs").and_then(Value::as_u64).filter(|n| *n > 0 && *n <= MAX_MANDATE_EPOCHS).ok_or("valid_for_epochs must be 1-100")?;
            let allowed_assets = agent_u32_list(input, "allowed_assets")?;
            let allowed_pools = agent_u32_list(input, "allowed_pools")?;
            let max_slippage_bps = input.get("max_slippage_bps").and_then(Value::as_u64).and_then(|n| u16::try_from(n).ok()).filter(|n| *n <= 2_000).ok_or("max_slippage_bps must be 0-2000")?;
            let limits = input.get("max_per_action_raw").and_then(Value::as_array).ok_or("max_per_action_raw is required")?;
            if limits.is_empty() || limits.len() > MAX_AGENT_LIST { return Err("max_per_action_raw must contain 1-16 limits".into()); }
            let mut max_per_action = Vec::with_capacity(limits.len());
            for limit in limits {
                let asset = limit.get("asset").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or("invalid limit asset")?;
                let amount = match limit.get("amount_raw") {
                    Some(_) => agent_fixed(limit, "amount_raw")?,
                    None => fixed_of(str_of(limit, "amount")?)?,
                };
                if !amount.is_positive() { return Err("amount limit must be positive".into()); }
                max_per_action.push((asset, amount));
            }
            max_per_action.sort_by_key(|x| x.0);
            if max_per_action.windows(2).any(|w| w[0].0 == w[1].0) { return Err("duplicate amount limit".into()); }
            if max_per_action.iter().any(|(asset, _)| !allowed_assets.contains(asset)) { return Err("an amount limit names a disallowed asset".into()); }
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let mut mandate = AgentMandate { id: String::new(), session_seed: seed, allowed_assets, allowed_pools, max_per_action, max_slippage_bps, valid_from_epoch: status.epoch, valid_until_epoch: status.epoch.saturating_add(epochs), created_at: App::now(), state: "active".into() };
            mandate.id = App::agent_mandate_id(account(&app.key), &mandate);
            let public = App::mandate_json(&mandate);
            let mut store = app.agent.lock().map_err(|_| "agent store busy")?;
            store.mandates.insert(mandate.id.clone(), mandate);
            app.save_agent_store(&store)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "mandate": public, "warning": "pause is local; chain authority remains valid until expiry" }))
        }
        ("POST", "/api/agent/check-swap") => {
            zyn_only(app)?;
            let id = str_of(input, "mandate_id")?;
            let intent = agent_swap(app, input)?;
            let status = app.node.status()?;
            let store = app.agent.lock().map_err(|_| "agent store busy")?;
            let mandate = store.mandates.get(id).ok_or("unknown_mandate")?;
            let decision = agent_policy(app, mandate, &intent, status.epoch)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "mandate_id": id, "decision": decision }))
        }
        ("POST", "/api/agent/execute-swap") => {
            zyn_only(app)?;
            let request_id = str_of(input, "request_id")?.to_string();
            if !valid_request_id(&request_id) { return Err("invalid_request_id".into()); }
            let mandate_id = str_of(input, "mandate_id")?.to_string();
            let intent = agent_swap(app, input)?;
            {
                let mut store = app.agent.lock().map_err(|_| "agent store busy")?;
                if let Some(existing) = store.actions.get(&request_id) { return Ok(existing.clone()); }
                store.actions.insert(request_id.clone(), json!({ "schema": AGENT_SCHEMA, "request_id": request_id, "mandate_id": mandate_id, "state": "submitting" }));
                app.save_agent_store(&store)?;
            }
            let outcome = (|| -> Result<Value, String> {
                let status = app.node.status()?;
                let mandate = app.agent.lock().map_err(|_| "agent store busy")?.mandates.get(&mandate_id).cloned().ok_or("unknown_mandate")?;
                let decision = agent_policy(app, &mandate, &intent, status.epoch)?;
                let session = SigningKey::from_bytes(&mandate.session_seed);
                let salt: [u8; 32] = Sha256::digest([b"nap.agent.policy.v1".as_slice(), &mandate.session_seed].concat()).into();
                let delegation = Delegation {
                    account: account(&app.key),
                    session_key: session.verifying_key().to_bytes(),
                    capabilities: CAP_SWAP,
                    allowed_assets: mandate.allowed_assets.clone(),
                    allowed_pools: mandate.allowed_pools.clone(),
                    max_per_action: mandate.max_per_action.iter().map(|(asset, amount)| AssetLimit { asset: *asset, amount: *amount }).collect(),
                    max_slippage_bps: mandate.max_slippage_bps,
                    valid_from_epoch: mandate.valid_from_epoch,
                    salt,
                    valid_until_epoch: mandate.valid_until_epoch,
                };
                let Signed::Message(certificate) = delegation_bytes_as::<SwapState>(Scheme::Ed25519, app.cfg.chain, &delegation) else { return Err("internal_signature_scheme".into()) };
                let auth = Authorization::for_vm::<SwapState>(app.cfg.chain, status.epoch, 1.min(mandate.valid_until_epoch.saturating_sub(status.epoch)));
                let delegation_id = delegation.id(app.cfg.chain, &auth.vm_id);
                let delegated = Delegated { delegation, owner: Credential::Ed25519 { key: app.key.verifying_key().to_bytes(), signature: app.key.sign(&certificate).to_bytes() }, session_signature: session.sign(&session_payload::<SwapState>(&delegation_id, &auth, &intent)).to_bytes() };
                let accepted = app.node.submit_delegated(&auth, &delegated, &intent)?;
                Ok(json!({ "schema": AGENT_SCHEMA, "request_id": request_id, "mandate_id": mandate_id, "state": if accepted.queued { "queued" } else { "accepted" }, "seq": accepted.seq, "epoch": accepted.epoch, "receipts": accepted.receipts, "amount_out_raw": accepted.swapped.map(|(_, out)| out.0.to_string()), "decision": decision }))
            })();
            let action = match outcome { Ok(v) => v, Err(error) => json!({ "schema": AGENT_SCHEMA, "request_id": request_id, "mandate_id": mandate_id, "state": "rejected", "reason": error }) };
            let mut store = app.agent.lock().map_err(|_| "agent store busy")?;
            store.actions.insert(request_id, action.clone());
            app.save_agent_store(&store)?;
            Ok(action)
        }
        ("POST", "/api/agent/action") => {
            let request_id = str_of(input, "request_id")?;
            if !valid_request_id(request_id) { return Err("invalid_request_id".into()); }
            app.agent.lock().map_err(|_| "agent store busy")?.actions.get(request_id).cloned().ok_or_else(|| "unknown_request".to_string())
        }
        ("POST", "/api/agent/pause") | ("POST", "/api/agent/close") => {
            let id = str_of(input, "mandate_id")?;
            let mut store = app.agent.lock().map_err(|_| "agent store busy")?;
            let mandate = store.mandates.get_mut(id).ok_or("unknown_mandate")?;
            mandate.state = if path.ends_with("close") { "closed" } else { "paused" }.into();
            let public = App::mandate_json(mandate);
            let on_chain_until = mandate.valid_until_epoch;
            app.save_agent_store(&store)?;
            Ok(json!({ "schema": AGENT_SCHEMA, "mandate": public, "on_chain_authority_ends_at_epoch": on_chain_until }))
        }
        ("GET", "/api/overview") => overview(app),
        ("POST", "/api/sync") => App::start_job(app, "sync", |a| {
            let events = sync(a)?;
            Ok(if events.is_empty() { String::new() } else { format!("sync: {} new", events.len()) })
        }),
        // Sweep the doormat. No amount and no destination: everything goes,
        // to this wallet's own shielded address. Offering a choice would be
        // offering to spend transparently, which is the thing being avoided.
        ("POST", "/api/shield") => {
            // Sweeping syncs first and proves a shielded output, so it runs on
            // the app's thread like /api/send rather than holding the wallet
            // lock inside the request for a minute or more.
            App::start_job(app, "shield", move |a| {
                let mut w = a.wallet.lock().map_err(|_| "wallet busy")?;
                let network = w.network();
                a.note("moving the transparent balance in; proving takes a minute".into());
                let mut events = Vec::new();
                let txid = w.shield_transparent(|e| if !matches!(e, Event::Progress { .. }) { events.push(e) })?;
                drop(w);
                a.record(network, &events);
                let _ = overview(a);
                Ok(format!("moved in privately; the note appears after the next sync: {}", txid))
            })
        }
        ("GET", "/api/transparent") => {
            let w = app.wallet.lock().map_err(|_| "wallet busy")?;
            let addr = w.transparent_address();
            let s = w.transparent_balance().ok();
            // ZEC, like every other amount this API returns. The sweep plans
            // in zatoshi; converting here keeps one unit on the wire.
            Ok(json!({
                "address": addr,
                "total": s.as_ref().map(|x| zec(x.total)),
                "fee": s.as_ref().map(|x| zec(x.fee)),
                // What would actually land shielded. Zero means the fee eats it.
                "net": s.as_ref().map(|x| zec(x.net)),
                "outputs": s.as_ref().map(|x| x.count),
            }))
        }
        ("POST", "/api/send") => {
            let to = str_of(input, "to")?.trim().to_string();
            let zat = zatoshi_of(input, "amount")?;
            let memo = input.get("memo").and_then(Value::as_str).filter(|m| !m.is_empty()).map(String::from);
            {
                let w = app.wallet.try_lock().map_err(|_| "wallet busy")?;
                parse_destination(&to, w.network()).ok_or_else(|| format!("not a {} address", network_name(w.network())))?;
                if zat + zyn_custody::payout::zip317_fee(2, 0) > w.balance().0 + w.balance().1 {
                    return Err("not enough for that amount plus the fee".into());
                }
            }
            App::start_job(app, "send", move |a| {
                let txid = send(a, &to, zat, memo.as_deref(), "sent")?;
                Ok(format!("sent {:.8} to {}…: {}", zec(zat), &to[..to.len().min(12)], txid))
            })
        }
        ("GET", "/api/deposit-address") => {
            zyn_only(app)?;
            match app.deposit_address() {
                Some(address) => Ok(json!({ "address": address, "memo": false })),
                // The node cannot issue one: the shared vault address still
                // works, but only with the account memo attached.
                None => Ok(json!({ "address": app.vault, "memo": true })),
            }
        }
        ("POST", "/api/deposit") => {
            zyn_only(app)?;
            let zat = zatoshi_of(input, "amount")?;
            // Its own address needs no memo — the address is the attribution.
            // Without one, fall back to the shared vault address and a memo.
            let (to, memo) = match app.deposit_address() {
                Some(a) => (a, None),
                None => (app.vault.clone(), Some(zyn_custody::memo::encode_text(&account(&app.key)))),
            };
            App::start_job(app, "deposit", move |a| {
                let txid = send(a, &to, zat, memo.as_deref(), "deposit")?;
                Ok(format!("deposited {:.8} to the Zyn vault: {}", zec(zat), txid))
            })
        }
        ("POST", "/api/import") => {
            let mut w = app.wallet.try_lock().map_err(|_| "wallet busy")?;
            let network = w.network();
            // Parse and derive the replacement before removing even an empty
            // wallet. `backup` is the complete portable form; mnemonic and
            // raw key fields keep manual and legacy restores straightforward.
            let restore = if let Some(value) = input.get("backup") {
                let text = match value {
                    Value::String(s) => s.clone(),
                    other => serde_json::to_string(other).map_err(|e| e.to_string())?,
                };
                WalletBackup::parse(&text)?
            } else {
                let birthday = input.get("birthday").and_then(Value::as_u64).ok_or("birthday is required")?;
                if let Some(words) = input.get("mnemonic").and_then(Value::as_str) {
                    let passphrase = input.get("passphrase").and_then(Value::as_str).unwrap_or("");
                    let account = input.get("account").and_then(Value::as_u64).unwrap_or(0);
                    WalletBackup::from_mnemonic(network, birthday, words, passphrase, u32::try_from(account).map_err(|_| "account is too large")?)?
                } else {
                    WalletBackup::from_raw(network, birthday, unhex32(str_of(input, "key")?.trim())?)?
                }
            };
            if restore.network != network {
                return Err(format!("this backup is for {}, but Nap is showing {}", network_name(restore.network), network_name(network)));
            }
            let (o, i) = w.balance();
            if o + i > 0 || w.pending() > 0 || !app.history(network).is_empty() {
                return Err("this wallet holds funds or history; back it up and remove it before restoring another".into());
            }
            let path = w.path().to_string();
            let lightd = app.settings.lock().map_err(|_| "busy")?.lightd(network)?.to_string();
            let staged_path = format!("{}.restore", path);
            let _ = std::fs::remove_file(&staged_path);
            let _ = std::fs::remove_file(format!("{}.state", staged_path));
            // Seed and open the replacement completely before touching the
            // current wallet. A bad phrase, wrong network, unavailable tree
            // frontier, or unwritable disk therefore leaves the old key live.
            let staged = match Wallet::import_backup(&staged_path, restore, Client::new(&lightd)) {
                Ok(wallet) => wallet,
                Err(e) => {
                    let _ = std::fs::remove_file(&staged_path);
                    let _ = std::fs::remove_file(format!("{}.state", staged_path));
                    return Err(e);
                }
            };
            drop(staged);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(format!("{}.state", path));
            std::fs::rename(&staged_path, &path).map_err(|e| format!("cannot install restored wallet key: {}", e))?;
            std::fs::rename(format!("{}.state", staged_path), format!("{}.state", path)).map_err(|e| format!("cannot install restored wallet state: {}", e))?;
            let fresh = Wallet::open(&path, Client::new(&lightd))?;
            let birthday = fresh.state.birthday;
            let warning = fresh.mnemonic_word_count().filter(|n| *n < 24).map(|n| format!("this imported phrase has {} words and less than the 256 bits recommended for Zcash; move recovered funds to a new 24-word wallet", n));
            *w = fresh;
            app.note(format!("restored a {} wallet born at {}; sync to find its notes", network_name(network), birthday));
            Ok(json!({ "address": w.address(), "birthday": birthday, "warning": warning }))
        }
        ("POST", "/api/quote") => {
            zyn_only(app)?;
            let (asset_in, pool, amount) = swap_args(app, input)?;
            let (out, best, asset_out) = app.node.quote(asset_in, &[pool], amount)?;
            Ok(json!({ "out": out.to_string(), "best": best.to_string(), "asset_out": asset_out, "pool": pool }))
        }
        ("POST", "/api/swap") => {
            zyn_only(app)?;
            let (asset_in, pool, amount) = swap_args(app, input)?;
            let (out, _, asset_out) = app.node.quote(asset_in, &[pool], amount)?;
            let min_out = Fixed::raw(out.0 * 99 / 100);
            let acc = app.node.submit(&app.key, Intent::SwapExactIn { account: account(&app.key), asset_in, path: vec![pool], amount_in: amount, min_out })?;
            if acc.queued {
                app.note(format!("order queued: {} of asset {} for at least {} of asset {}; clears at the seal (seq {})", amount, asset_in, min_out, asset_out, acc.seq));
                return Ok(json!({ "seq": acc.seq, "epoch": acc.epoch, "queued": true, "min_out": min_out.to_string() }));
            }
            let got = acc.swapped.map(|(_, o)| o).unwrap_or(min_out);
            app.note(format!("swapped {} of asset {} for {} of asset {} (seq {})", amount, asset_in, got, asset_out, acc.seq));
            Ok(json!({ "seq": acc.seq, "epoch": acc.epoch, "queued": false, "min_out": min_out.to_string(), "amount_out": got.to_string() }))
        }
        // Every anchor this node knows: the epoch-to-Zcash mapping, which is
        // what turns "settled in batches" from a claim into something a
        // viewer can check on a chain they already trust.
        ("GET", "/api/anchors") => {
            zyn_only(app)?;
            let anchors = app.node.anchors(0).map_err(|e| e.to_string())?;
            Ok(json!({ "anchors": anchors.iter().map(|a| json!({
                "epoch": a.epoch,
                "root": hex(&a.root),
                "anchor_id": hex(&a.anchor_id),
                "txid": a.txid,
                "height": a.height,
            })).collect::<Vec<_>>() }))
        }
        // ---- offers ----
        //
        // The order book is a public read, so this is served whether or not
        // this wallet has anything in it.
        ("GET", "/api/offers") => {
            zyn_only(app)?;
            let offers = app.node.offers().map_err(|e| e.to_string())?;
            let me = account(&app.key);
            Ok(json!({ "offers": offers.iter().map(|o| json!({
                "id": o.id,
                "maker": hex(&o.maker),
                "mine": o.maker == me,
                "offer_asset": o.offer_asset,
                "offer_amount": o.offer_amount.to_string(),
                "want_asset": o.want_asset,
                "want_amount": o.want_amount.to_string(),
                "expires_at_epoch": o.expires_at_epoch,
            })).collect::<Vec<_>>() }))
        }
        ("POST", "/api/offer") => {
            zyn_only(app)?;
            let offer_asset = input.get("asset").and_then(Value::as_u64).ok_or("which asset?")? as u32;
            let want_amount = fixed_of(str_of(input, "price")?)?;
            if want_amount.0 <= 0 { return Err("price must be positive".into()) }
            // One whole unit unless told otherwise: an item is the case this
            // exists for, and an item moves in whole units or not at all.
            let offer_amount = match input.get("amount").and_then(Value::as_str) {
                Some(a) => fixed_of(a)?,
                None => Fixed::ONE,
            };
            // Absent an expiry the offer rests until cancelled, which is the
            // honest default for a listing: a silent lapse would look like a
            // theft to whoever was about to take it.
            let expires = input.get("expires_at_epoch").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let acc = app.node
                .place_offer(&app.key, offer_asset, offer_amount, swapvm::types::XZEC, want_amount, expires)
                .map_err(|e| e.to_string())?;
            app.note(format!("offered asset {} at {} ZEC.zy (seq {})", offer_asset, want_amount, acc.seq));
            Ok(json!({ "placed": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        ("POST", "/api/take") => {
            zyn_only(app)?;
            let offer = input.get("offer").and_then(Value::as_u64).ok_or("which offer?")?;
            let acc = app.node.take_offer(&app.key, offer).map_err(|e| e.to_string())?;
            app.note(format!("took offer {} (seq {})", offer, acc.seq));
            Ok(json!({ "taken": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        ("POST", "/api/cancel-offer") => {
            zyn_only(app)?;
            let offer = input.get("offer").and_then(Value::as_u64).ok_or("which offer?")?;
            let acc = app.node.cancel_offer(&app.key, offer).map_err(|e| e.to_string())?;
            app.note(format!("cancelled offer {} (seq {})", offer, acc.seq));
            Ok(json!({ "cancelled": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        // ---- collections ----
        //
        // The lifecycle is creator-only except for funding, which is signed by
        // whoever pays. That split is what makes a paid claim two honest
        // intents rather than one privileged one: the buyer pays into the pool
        // themselves, and the creator hands over the item.
        ("POST", "/api/collection") => {
            zyn_only(app)?;
            let sym = str_of(input, "symbol")?;
            let cap = input.get("cap").and_then(Value::as_u64).ok_or("how many items?")? as u32;
            let fee_bps = input.get("fee_bps").and_then(Value::as_u64).unwrap_or(100) as u16;
            let acc = app.node
                .create_collection(&app.key, swapvm::state::symbol(sym.as_bytes()), cap, fee_bps)
                .map_err(|e| e.to_string())?;
            app.note(format!("created collection {} capped at {} (seq {})", sym, cap, acc.seq));
            Ok(json!({ "created": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        // Anyone may pay into a collection: the pool is the floor, and a floor
        // only its creator could raise would be a promise rather than a claim.
        ("POST", "/api/fund") => {
            zyn_only(app)?;
            let collection = input.get("collection").and_then(Value::as_u64).ok_or("which collection?")? as u32;
            let amount = fixed_of(str_of(input, "amount")?)?;
            if amount.0 <= 0 { return Err("amount must be positive".into()) }
            let acc = app.node.fund_collection(&app.key, collection, amount).map_err(|e| e.to_string())?;
            app.note(format!("funded collection {} with {} ZEC.zy (seq {})", collection, amount, acc.seq));
            Ok(json!({ "funded": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        // Creator-only, and deliberately: this is the hand-over half of a
        // claim, and the payment half is the buyer's own `/api/fund`.
        ("POST", "/api/mint") => {
            zyn_only(app)?;
            let collection = input.get("collection").and_then(Value::as_u64).ok_or("which collection?")? as u32;
            let to = match input.get("to").and_then(Value::as_str) {
                Some(h) => unhex32(h).map_err(|_| "`to` is not a 32-byte account")?,
                None => account(&app.key),
            };
            let content = match input.get("content").and_then(Value::as_str) {
                Some(h) => unhex32(h).map_err(|_| "`content` is not a 32-byte hash")?,
                None => return Err("content hash is required — an item without one is unidentifiable".into()),
            };
            let sym = match input.get("symbol").and_then(Value::as_str) {
                Some(x) => swapvm::state::symbol(x.as_bytes()),
                None => swapvm::state::symbol(b"ITEM"),
            };
            let acc = app.node
                .mint_collection_item(&app.key, collection, to, sym, content)
                .map_err(|e| e.to_string())?;
            app.note(format!("minted an item of collection {} to {} (seq {})", collection, hex(&to), acc.seq));
            Ok(json!({ "minted": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        ("POST", "/api/advance") => {
            zyn_only(app)?;
            let collection = input.get("collection").and_then(Value::as_u64).ok_or("which collection?")? as u32;
            let to = input.get("to").and_then(Value::as_u64).ok_or("advance to which phase?")? as u8;
            let acc = app.node.advance_collection(&app.key, collection, to).map_err(|e| e.to_string())?;
            app.note(format!("collection {} advanced to phase {} (seq {})", collection, to, acc.seq));
            Ok(json!({ "advanced": true, "seq": acc.seq, "epoch": acc.epoch }))
        }
        ("POST", "/api/redeem") => {
            zyn_only(app)?;
            let asset = input.get("asset").and_then(Value::as_u64).ok_or("which item?")? as u32;
            let acc = app.node.redeem_collection_item(&app.key, asset).map_err(|e| e.to_string())?;
            app.note(format!("redeemed item {} at seq {}", asset, acc.seq));
            Ok(json!({ "redeemed": true, "seq": acc.seq }))
        }
        ("POST", "/api/bind") => {
            zyn_only(app)?;
            let (address, network) = { let w = app.wallet.lock().map_err(|_| "wallet busy")?; (w.address(), w.network()) };
            app.bind_to(&address, 0, network)?;
            Ok(json!({ "bound": true }))
        }
        ("POST", "/api/bind-sol") => {
            zyn_only(app)?;
            let address = str_of(input, "address")?.trim().to_string();
            zyn_custody::solana::pubkey(&address).ok_or("not a Solana address")?;
            let network = app.wallet.lock().map_err(|_| "wallet busy")?.network();
            app.bind_to(&address, 1, network)?;
            Ok(json!({ "bound": true }))
        }
        ("POST", "/api/withdraw-sol") => {
            zyn_only(app)?;
            let asset = input.get("asset").and_then(Value::as_u64).ok_or("asset is required")? as u32;
            let amount = fixed_of(str_of(input, "amount")?)?;
            let b = app.binding.lock().map_err(|_| "busy")?.clone().ok_or("bind a Solana address first")?;
            if b.kind != 1 { return Err("exits are bound to a Zcash address; bind a Solana address first (a rebind waits out the redirect delay)".into()) }
            let network = app.wallet.lock().map_err(|_| "wallet busy")?.network();
            let acc = app.node.submit(&app.key, Intent::RequestWithdrawal { account: account(&app.key), asset, amount, destination: b.commitment(network)? })?;
            app.note(format!("requested an exit of {} of asset {} to {}… (seq {})", amount, asset, &b.address[..8], acc.seq));
            Ok(json!({ "seq": acc.seq }))
        }
        ("POST", "/api/liquidity/add") => {
            zyn_only(app)?;
            let pool = input.get("pool").and_then(Value::as_u64).ok_or("pool is required")? as u32;
            let max0 = fixed_of(str_of(input, "amount0")?)?;
            let max1 = fixed_of(str_of(input, "amount1")?)?;
            let acc = app.node.submit(&app.key, Intent::AddLiquidity { account: account(&app.key), pool, max0, max1, min_shares: Fixed::ZERO })?;
            let (a0, a1, sh) = acc.liquidity.unwrap_or((Fixed::ZERO, Fixed::ZERO, Fixed::ZERO));
            app.note(format!("added liquidity to pool {}: {} + {} for {} shares (seq {})", pool, a0, a1, sh, acc.seq));
            Ok(json!({ "seq": acc.seq, "amount0": a0.to_string(), "amount1": a1.to_string(), "shares": sh.to_string() }))
        }
        ("POST", "/api/liquidity/remove") => {
            zyn_only(app)?;
            let pool = input.get("pool").and_then(Value::as_u64).ok_or("pool is required")? as u32;
            let shares = fixed_of(str_of(input, "shares")?)?;
            let acc = app.node.submit(&app.key, Intent::RemoveLiquidity { account: account(&app.key), pool, shares, min0: Fixed::ZERO, min1: Fixed::ZERO })?;
            let (a0, a1, sh) = acc.liquidity.unwrap_or((Fixed::ZERO, Fixed::ZERO, Fixed::ZERO));
            app.note(format!("removed {} shares from pool {}: {} + {} back (seq {})", sh, pool, a0, a1, acc.seq));
            Ok(json!({ "seq": acc.seq, "amount0": a0.to_string(), "amount1": a1.to_string(), "shares": sh.to_string() }))
        }
        ("POST", "/api/withdraw") => {
            zyn_only(app)?;
            let zat = zatoshi_of(input, "amount")?;
            let b = app.binding.lock().map_err(|_| "busy")?.clone().ok_or("bind this wallet first")?;
            if b.kind != 0 { return Err("exits are bound to a Solana address; bind this wallet first (a rebind waits out the redirect delay)".into()) }
            let network = app.wallet.lock().map_err(|_| "wallet busy")?.network();
            let commitment = b.commitment(network)?;
            let acc = app.node.submit(&app.key, Intent::RequestWithdrawal { account: account(&app.key), asset: XZEC, amount: Fixed::raw(zat as i128 * ZAT), destination: commitment })?;
            app.note(format!("requested an exit of {:.8} ZEC.zy to this wallet (seq {})", zec(zat), acc.seq));
            Ok(json!({ "seq": acc.seq }))
        }
        ("POST", "/api/transfer") => {
            zyn_only(app)?;
            let to = unhex32(str_of(input, "to")?.trim())?;
            let asset = input.get("asset").and_then(Value::as_u64).ok_or("asset is required")? as u32;
            let amount = fixed_of(str_of(input, "amount")?)?;
            let intent = Intent::Transfer { from: account(&app.key), to, asset, amount };
            if input.get("force").and_then(Value::as_bool).unwrap_or(false) {
                let txid = force_via_zcash(app, &intent)?;
                app.note(format!("FORCED on Zcash: transfer of {} of asset {} to {}… rides tx {} — the node must apply it within {} blocks", amount, asset, hex(&to[..4]), &txid[..12], 20));
                return Ok(json!({ "forced": true, "txid": txid }));
            }
            let acc = app.node.submit(&app.key, intent)?;
            app.note(format!("sent {} of asset {} on Zyn to {}… (seq {})", amount, asset, hex(&to[..4]), acc.seq));
            Ok(json!({ "seq": acc.seq }))
        }
        ("POST", "/api/force") => {
            // Any intent the wallet can build, forced. Today: a transfer.
            zyn_only(app)?;
            let to = unhex32(str_of(input, "to")?.trim())?;
            let asset = input.get("asset").and_then(Value::as_u64).ok_or("asset is required")? as u32;
            let amount = fixed_of(str_of(input, "amount")?)?;
            let intent = Intent::Transfer { from: account(&app.key), to, asset, amount };
            let txid = force_via_zcash(app, &intent)?;
            Ok(json!({ "forced": true, "txid": txid }))
        }
        ("POST", "/api/reset") => {
            let birthday = input.get("birthday").and_then(Value::as_u64).ok_or("birthday is required")?;
            app.wallet.lock().map_err(|_| "wallet busy")?.reset(birthday)?;
            app.note(format!("wallet reset to birthday {}; the next sync rescans", birthday));
            Ok(json!({ "ok": true }))
        }
        ("POST", "/api/export") => {
            let w = app.wallet.lock().map_err(|_| "wallet busy")?;
            app.note("wallet recovery material shown for backup".to_string());
            Ok(json!({
                "key": w.legacy_backup_key().map(|key| hex(&key)),
                "mnemonic": w.mnemonic(),
                "backup": w.export_backup(),
                "birthday": w.state.birthday,
                "network": network_name(w.network()),
            }))
        }
        ("GET", "/api/settings") => Ok(app.settings.lock().map_err(|_| "busy")?.json()),
        ("POST", "/api/settings") => {
            let mut s = app.settings.lock().map_err(|_| "busy")?.clone();
            if let Some(v) = input.get("lightd_testnet").and_then(Value::as_str) { s.lightd_testnet = v.trim().to_string(); }
            if let Some(v) = input.get("lightd_mainnet").and_then(Value::as_str) { s.lightd_mainnet = v.trim().to_string(); }
            if let Some(v) = input.get("price").and_then(Value::as_bool) { s.price = v; }
            let want = match input.get("network").and_then(Value::as_str) {
                Some("mainnet") => Network::MainNetwork,
                Some("testnet") => Network::TestNetwork,
                Some(other) => return Err(format!("unknown network {}", other)),
                None => s.network,
            };
            let mut w = app.wallet.lock().map_err(|_| "wallet busy")?;
            // Server addresses are kept even if the switch fails: a server
            // that is still syncing is still the right server.
            let before = Settings::load(&app.cfg.dir);
            s.network = before.network;
            s.save(&app.cfg.dir)?;
            *app.settings.lock().map_err(|_| "busy")? = s.clone();
            if want != w.network() || input.get("lightd_testnet").is_some() || input.get("lightd_mainnet").is_some() {
                // Reopen against the (possibly new) server: a wrong or
                // unready server is refused here, and the network stays.
                let fresh = App::open_wallet(&app.cfg, &s, want, want == before.network && app.cfg.wallet_path.is_some())?;
                *w = fresh;
            }
            s.network = want;
            s.save(&app.cfg.dir)?;
            *app.settings.lock().map_err(|_| "busy")? = s.clone();
            app.note(format!("now on {} via {}", network_name(want), s.lightd(want).unwrap_or("?")));
            Ok(s.json())
        }
        _ => Err("no such call".into()),
    }
}

/// Zyn follows whichever Zcash this wallet is on.
///
/// The gate used to be "testnet only". It is now the *mismatch* that is
/// refused: a wallet on one chain talking to a Zyn node custodying the other
/// would show balances backed by money it cannot see and hand out deposit
/// addresses nobody on this chain can pay. Which chain is fine; disagreeing
/// about it is not.
fn zyn_only(app: &App) -> Result<(), String> {
    match app.chain_mismatch() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// asset_in, the single pool that joins it to asset_out, and the amount.
fn swap_args(app: &App, input: &Value) -> Result<(u32, u32, Fixed), String> {
    let asset_in = input.get("asset_in").and_then(Value::as_u64).ok_or("asset_in is required")? as u32;
    let asset_out = input.get("asset_out").and_then(Value::as_u64).ok_or("asset_out is required")? as u32;
    if asset_in == asset_out { return Err("pick two different assets".into()) }
    let amount = fixed_of(str_of(input, "amount")?)?;
    if amount.0 <= 0 { return Err("amount must be positive".into()) }
    let pools = app.node.pools()?;
    let pool = pools.iter().find(|p| (p.asset0 == asset_in && p.asset1 == asset_out) || (p.asset1 == asset_in && p.asset0 == asset_out)).ok_or("no pool joins those two assets")?;
    Ok((asset_in, pool.id, amount))
}

fn sync(app: &App) -> Result<Vec<String>, String> {
    let mut events = Vec::new();
    let mut w = app.wallet.lock().map_err(|_| "wallet busy")?;
    w.sync(|e| {
        if let Event::Progress { at, to } = e { app.set_progress(at, to) } else { events.push(e) }
    })?;
    let network = w.network();
    drop(w);
    app.record(network, &events);
    let _ = overview(app); // refresh the cached view now that the wallet is free
    let lines: Vec<String> = events.iter().filter_map(|e| match e {
        Event::Progress { .. } => None,
        Event::Received { zatoshi, height, memo, .. } => Some(format!("received {:.8} at height {}{}", zec(*zatoshi), height, if memo.is_empty() { String::new() } else { format!(" — “{}”", memo) })),
        Event::Spent { zatoshi, height, .. } => Some(format!("a {:.8} note was spent (confirmed at height {})", zec(*zatoshi), height)),
    }).collect();
    for l in &lines { app.note(l.clone()); }
    Ok(lines)
}

fn send(app: &App, to: &str, zat: u64, memo: Option<&str>, kind: &str) -> Result<String, String> {
    let mut w = app.wallet.lock().map_err(|_| "wallet busy")?;
    app.note(format!("building a {:.8} payment; proving takes a minute", zec(zat)));
    let mut events = Vec::new();
    let txid = w.send(to, zat, memo, |e| if !matches!(e, Event::Progress { .. }) { events.push(e) })?;
    let network = w.network();
    drop(w);
    app.record(network, &events);
    let mut h = app.history(network);
    h.push(json!({ "kind": kind, "txid": txid, "zatoshi": zat, "height": 0, "memo": memo.unwrap_or(""), "to": to, "at": App::now() }));
    app.write_history(network, &h);
    let _ = overview(app);
    Ok(txid)
}

/// The other door: sign the intent exactly as for RPC, put the frame in a
/// `ZYF` memo, and pay the vault a small note carrying it. The sequencer must
/// apply it; a replica holds it to that.
fn force_via_zcash(app: &App, intent: &Intent) -> Result<String, String> {
    let epoch = app.node.status().map(|s| s.epoch).unwrap_or(0);
    let frame = crate::client::frame_submission(&app.key, app.node.chain, epoch, intent);
    let memo = zyn_custody::memo::encode_forced(&frame)
        .ok_or_else(|| format!("this intent is {} bytes signed; a memo carries at most {}", frame.len(), zyn_custody::memo::FORCED_MAX))?;
    let mut w = app.wallet.lock().map_err(|_| "wallet busy")?;
    app.note("forcing via Zcash: building a 0.0001 payment to the vault with the signed intent in its memo; proving takes a minute".to_string());
    let mut events = Vec::new();
    let txid = w.send_with_memo(&app.vault, 10_000, memo, |e| if !matches!(e, Event::Progress { .. }) { events.push(e) })?;
    let network = w.network();
    drop(w);
    app.record(network, &events);
    let mut h = app.history(network);
    h.push(json!({ "kind": "forced", "txid": txid, "zatoshi": 10_000u64, "height": 0, "memo": "forced intent", "to": app.vault, "at": App::now() }));
    app.write_history(network, &h);
    let _ = overview(app);
    Ok(txid)
}

/// base64url without padding — what ZIP-321 wants for a memo.
fn base64url(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

/// Percent-encode everything a URI query value may not carry literally.
fn percent(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// A ZIP-321 payment request for a deposit.
///
/// The depositor's wallet fills in the address itself — and the memo, where
/// one is still needed. That matters more than it sounds: a hundred-character
/// shielded address retyped by hand is the likeliest way a deposit goes
/// wrong, and a memo typed by hand is the likeliest way one arrives
/// unattributable.
pub fn deposit_uri(address: &str, memo: Option<&str>, zatoshi: Option<u64>) -> String {
    let mut uri = format!("zcash:{}?message={}", address, percent("Zyn deposit"));
    if let Some(zat) = zatoshi.filter(|z| *z > 0) {
        // ZIP-321 amounts are ZEC, decimal, at most eight places.
        uri.push_str(&format!("&amount={}", format!("{:.8}", zat as f64 / 100_000_000.0).trim_end_matches('0').trim_end_matches('.')));
    }
    if let Some(m) = memo {
        uri.push_str(&format!("&memo={}", base64url(m.as_bytes())));
    }
    uri
}

fn qr_svg(text: &str) -> String {
    match qrcode::QrCode::new(text.as_bytes()) {
        Ok(code) => code.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).quiet_zone(false).build(),
        Err(_) => String::new(),
    }
}

pub fn overview(app: &App) -> Result<Value, String> {
    let fresh = match app.wallet.try_lock() {
        Ok(w) => {
            let (orchard, ironwood) = w.balance();
            let v = json!({
                "network": network_name(w.network()),
                "tip": w.tip,
                "synced_to": w.synced_to(),
                "birthday": w.state.birthday,
                "address": w.address(),
                // The doormat: where an exchange withdrawal lands before being
                // shielded. Absent if this build cannot derive one.
                "transparent_address": w.transparent_address(),
                "qr_svg": qr_svg(&w.address()),
                "balance": { "ironwood": ironwood, "orchard": orchard, "total": zec(ironwood + orchard), "pending": zec(w.pending()) },
                "notes": w.notes().iter().map(|n| json!({ "pool": format!("{:?}", n.pool), "zec": zec(n.zatoshi), "height": n.height, "txid": n.txid_hex })).collect::<Vec<_>>(),
            });
            if let Ok(mut c) = app.view.lock() { *c = Some(v.clone()); }
            Some(v)
        }
        Err(_) => None,
    };
    let wallet = match fresh {
        Some(v) => v,
        None => app.view.lock().ok().and_then(|c| c.clone()).ok_or("the wallet is busy; try again in a moment")?,
    };
    let network = if wallet["network"] == "mainnet" { Network::MainNetwork } else { Network::TestNetwork };
    let address = wallet["address"].as_str().unwrap_or("").to_string();
    let settings = app.settings.lock().map_err(|_| "busy")?.clone();
    let mut history = app.history(network);
    history.sort_by(|a, b| b["at"].as_u64().cmp(&a["at"].as_u64()));
    for h in history.iter_mut() {
        let z = h["zatoshi"].as_u64().unwrap_or(0);
        h["zec"] = json!(zec(z));
    }
    let zyn = match app.chain_mismatch() {
        None => zyn_overview(app, network, &address)?,
        Some(why) => json!({ "available": false, "why": why }),
    };
    let job = app.job().map(|j| json!({ "kind": j.kind, "progress": j.progress.map(|(at, to)| json!({ "at": at, "to": to })), "started": j.started }));
    let mut o = json!({
        "app": "Nap Wallet",
        "unit": unit(network),
        "confirmations": CONFIRMATIONS,
        "fee_estimate": zec(zyn_custody::payout::zip317_fee(2, 0)),
        "explorer": if network == Network::MainNetwork { "https://mainnet.zcashexplorer.app/transactions/" } else { "https://testnet.zcashexplorer.app/transactions/" },
        // One ZEC in dollars, for display. Absent when the holder has the
        // price switch off, or nothing fresh has been fetched yet.
        "zec_usd": App::zec_usd(app),
        "history": history,
        "settings": settings.json(),
        "zyn": zyn,
        "job": job,
        "log": app.log.lock().map(|l| l.clone()).unwrap_or_default(),
    });
    for (k, v) in wallet.as_object().into_iter().flatten() { o[k] = v.clone(); }
    Ok(o)
}

impl App {
    fn exit_proof_path(&self, network: Network) -> PathBuf {
        self.cfg.dir.join(format!("exit-{}.json", network_name(network)))
    }

    /// Keep the exit proof current: whenever the chain has anchored past what
    /// is on disk, fetch the record and path again. Kilobytes per anchor, and
    /// the thing that lets this wallet leave with the sequencer gone.
    fn refresh_exit_proof(&self, network: Network, anchored_epoch: u64, has_anchor: bool) -> Option<crate::exitproof::ExitProof> {
        let path = self.exit_proof_path(network);
        let kept = crate::exitproof::ExitProof::load(&path);
        if !crate::exitproof::should_refresh(kept.as_ref().map(|p| p.epoch), anchored_epoch, has_anchor) {
            return kept;
        }
        match self.node.account_proof(&self.key) {
            Ok(Some(p)) => {
                let proof = crate::exitproof::ExitProof { chain_id: self.node.chain, epoch: p.epoch, root: p.root, record: p.record, index: p.index, path: p.path, fetched_at: App::now() };
                if proof.verify() {
                    let _ = proof.save(&path);
                    self.note(format!("exit proof refreshed for epoch {}", proof.epoch));
                    Some(proof)
                } else {
                    self.note("the node handed back an exit proof that does not open its own root — not kept".to_string());
                    kept
                }
            }
            _ => kept,
        }
    }
}

fn zyn_overview(app: &App, network: Network, address: &str) -> Result<Value, String> {
    let id = account(&app.key);
    let status = app.node.status();
    let exit = match &status {
        Ok(s) => app.refresh_exit_proof(network, s.anchored_epoch, s.anchored_epoch > 0 || s.role == 1),
        Err(_) => crate::exitproof::ExitProof::load(&app.exit_proof_path(network)),
    };
    let exit_json = json!({
        "epoch": exit.as_ref().map(|p| p.epoch),
        "root": exit.as_ref().map(|p| p.root.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        "verified": exit.as_ref().map(|p| p.verify()).unwrap_or(false),
        "fetched_at": exit.as_ref().map(|p| p.fetched_at),
        "file": app.exit_proof_path(network).to_string_lossy(),
        "anchored_epoch": status.as_ref().ok().map(|s| s.anchored_epoch),
    });
    let assets = app.node.assets().unwrap_or_default();
    let pools = app.node.pools().unwrap_or_default();
    let record = app.node.account(&app.key);
    let orders = app.node.orders(&app.key).unwrap_or_default();
    let launch = app.node.launch().ok().flatten();
    let me = app.node.launch_me(&app.key).unwrap_or_default();
    let symbol = |a: u32| assets.iter().find(|x| x.id == a).map(|x| x.symbol.clone()).unwrap_or_else(|| format!("asset {}", a));
    let binding = app.binding.lock().map_err(|_| "busy")?.clone();
    let bound_here = match (&binding, &record) {
        (Some(b), Ok(Some(r))) => b.kind == 0 && b.address == address && b.commitment(network).ok() == r.binding,
        _ => false,
    };
    let bound_sol = match (&binding, &record) {
        (Some(b), Ok(Some(r))) => b.kind == 1 && b.commitment(network).ok() == r.binding,
        _ => false,
    };
    // LP shares the account holds, as a share of each pool and its reserves.
    // What one unit of an asset is worth in ZEC, read off its xZEC pool.
    //
    // Only the pool that quotes it directly against xZEC counts: a price
    // routed through two hops is a guess about depth as well as price, and a
    // portfolio total built on guesses is worse than one that says "unpriced".
    let price_zec = |asset: u32| -> Option<Fixed> {
        if asset == swapvm::types::XZEC {
            return Some(Fixed::ONE);
        }
        pools.iter().find_map(|p| {
            let (zec, other) = if p.asset0 == swapvm::types::XZEC && p.asset1 == asset {
                (p.reserve0, p.reserve1)
            } else if p.asset1 == swapvm::types::XZEC && p.asset0 == asset {
                (p.reserve1, p.reserve0)
            } else {
                return None;
            };
            (other.0 > 0).then(|| Fixed::raw(((zec.0 as i128) * Fixed::ONE.0) / other.0))
        })
    };
    let value_of = |asset: u32, amount: Fixed| -> Option<Fixed> {
        price_zec(asset).map(|p| Fixed::raw((amount.0 * p.0) / Fixed::ONE.0))
    };

    // Collections, so an item can show what backs it.
    let collections = app.node.collections().unwrap_or_default();
    let offers = app.node.offers().unwrap_or_default();
    let anchors = app.node.anchors(0).unwrap_or_default();
    let floor_of = |asset: u32| -> Option<(u32, Fixed)> {
        let a = assets.iter().find(|x| x.id == asset)?;
        let c = collections.iter().find(|c| Some(c.id) == a.collection)?;
        Some((c.id, c.redeem_price))
    };

    // What this account has put into Zyn, in ZEC. Three buckets, because they
    // behave differently: idle balances can leave today, pool positions are
    // exposed to the pair, and an item's floor is the least it is worth rather
    // than what it would fetch. Anything the chain cannot price is counted in
    // `unpriced` rather than silently as zero — a total that quietly omits a
    // holding is worse than one that admits it does not know.
    let positions: Vec<Value> = match &record {
        Ok(Some(r)) => r.spendable.iter().filter_map(|(a, v)| {
            let lp = assets.iter().find(|x| x.id == *a && x.lp_of.is_some())?;
            let pool = pools.iter().find(|p| p.id == lp.lp_of.unwrap())?;
            let supply = lp.supply.0.max(1);
            let share = v.0 as f64 / supply as f64;
            // Both legs valued and summed, rather than doubling the xZEC
            // side: that shortcut is only right while a pool is balanced, and
            // a position is most worth checking when it is not.
            let a0 = Fixed::raw((pool.reserve0.0 * v.0) / supply);
            let a1 = Fixed::raw((pool.reserve1.0 * v.0) / supply);
            let value_zec = match (value_of(pool.asset0, a0), value_of(pool.asset1, a1)) {
                (Some(x), Some(y)) => x.add(y).map(|t| t.to_string()),
                _ => None,
            };
            Some(json!({ "pool": pool.id, "lp_asset": a, "shares": v.to_string(), "share": share,
                "symbol0": symbol(pool.asset0), "symbol1": symbol(pool.asset1),
                "amount0": a0.to_string(),
                "amount1": a1.to_string(),
                "value_zec": value_zec }))
        }).collect(),
        _ => Vec::new(),
    };
    let portfolio = {
        let mut idle = Fixed::ZERO;
        let mut items_floor = Fixed::ZERO;
        let mut unpriced = 0u32;
        if let Ok(Some(r)) = &record {
            for (a, v) in r.spendable.iter() {
                let info = assets.iter().find(|x| x.id == *a);
                if info.map(|i| i.lp_of.is_some()).unwrap_or(false) {
                    continue; // counted as a pool position instead
                }
                if info.map(|i| i.is_item()).unwrap_or(false) {
                    match floor_of(*a) {
                        Some((_, f)) => items_floor = items_floor.add(f).unwrap_or(items_floor),
                        None => unpriced += 1,
                    }
                    continue;
                }
                match value_of(*a, *v) {
                    Some(x) => idle = idle.add(x).unwrap_or(idle),
                    None => unpriced += 1,
                }
            }
        }
        let pooled: f64 = positions
            .iter()
            .filter_map(|p| p["value_zec"].as_str().and_then(|s| s.parse::<f64>().ok()))
            .sum();
        // IEEE-754 keeps the sign on zero, and "-0.00000000 ZEC" reads as a
        // bug to anyone who sees it. `-0.0 == 0.0`, so this normalises it.
        let pooled = if pooled == 0.0 { 0.0 } else { pooled };
        let idle_f: f64 = idle.to_string().parse().unwrap_or(0.0);
        let items_f: f64 = items_floor.to_string().parse().unwrap_or(0.0);
        json!({
            "idle_zec": idle.to_string(),
            "pooled_zec": format!("{:.8}", pooled),
            "items_floor_zec": items_floor.to_string(),
            "total_zec": format!("{:.8}", idle_f + pooled + items_f),
            "unpriced": unpriced,
            "open_orders": orders.len(),
        })
    };

    let markets: Vec<Value> = launch.as_ref().map(|l| l.assets.iter().map(|a| {
        let mine = me.markets.iter().find(|m| m.0 == a.asset);
        json!({
            "asset": a.asset, "symbol": symbol(a.asset), "pot": a.pot.to_string(), "price": a.price.to_string(),
            "opened": a.opened_at > 0, "opened_at": a.opened_at, "pool": a.pool, "grant": a.grant.to_string(),
            "contributors": a.contributors, "contributed": a.contributed.to_string(),
            "zec_needed": if a.price.0 > 0 { a.pot.div(a.price).unwrap_or(Fixed::ZERO).to_string() } else { "0".to_string() },
            "me": mine.map(|m| json!({ "contributed": m.1.to_string(), "vest_total": m.2.to_string(), "vest_released": m.3.to_string(), "vest_end": m.4 })),
        })
    }).collect()).unwrap_or_default();

    // Built outside the literal below: nesting these there outruns `json!`.
    let launch_json = launch.as_ref().map(|l| {
        let mut v = json!({
            "fee_bps": l.params.fee_bps, "threshold": l.params.threshold.to_string(), "genesis": l.params.genesis.to_string(), "cap": l.params.cap.to_string(),
            "rate0": l.params.rate0.to_string(), "halving_blocks": l.params.halving_blocks, "vesting_blocks": l.params.vesting_blocks,
            "zcash_height": l.zcash_height, "graduated": l.graduated_at > 0, "graduated_at": l.graduated_at, "zyn": l.zyn, "genesis_pool": l.genesis_pool,
        });
        for (k, val) in [
            ("minted", l.minted.to_string()), ("supply", l.supply.to_string()), ("pot", l.pot.to_string()),
            ("lp_pot", l.lp_pot.to_string()), ("bridge_pot", l.bridge_pot.to_string()), ("pol_zyn", l.pol_zyn.to_string()),
            ("pol_zec", l.pol_zec.to_string()), ("fee_pot", l.fee_pot.to_string()), ("contributed", l.contributed.to_string()),
            ("asset_threshold", l.asset_threshold.to_string()),
        ] { v[k] = json!(val); }
        v["contributors"] = json!(l.contributors);
        v["bootstrap_bps"] = json!(l.bootstrap_bps);
        v["markets"] = json!(markets);
        v["me"] = json!({ "contribution": me.contribution.to_string(), "epoch_fees": me.epoch_fees.to_string(), "vest_total": me.vest_total.to_string(), "vest_released": me.vest_released.to_string(), "vest_end": me.vest_end });
        v
    });
    // Built outside the literal below: nesting it there outruns `json!`.

    Ok(json!({
        "available": true,
        "exit": exit_json,
        "node": app.node.addr,
        "chain": app.node.chain,
        "account": hex(&id),
        // Zyn transfers address the account directly. Encode the same raw id
        // the send form accepts, so scanning needs no wallet-specific parser.
        "account_qr_svg": qr_svg(&hex(&id)),
        "memo": zyn_custody::memo::encode_text(&id),
        "vault": app.vault,
        // This account's own deposit address. Where present, deposits need no
        // memo — the address is the attribution — and the UI should show this
        // rather than the shared vault address.
        "deposit_address": app.deposit_address(),
        // The same thing as a payment request, so paying from another wallet
        // is a scan rather than a careful copy.
        "deposit_uri": deposit_uri(
            app.deposit_address().as_deref().unwrap_or(&app.vault),
            app.deposit_address().is_none().then(|| zyn_custody::memo::encode_text(&id)).as_deref(),
            None,
        ),
        "deposit_qr_svg": qr_svg(&deposit_uri(
            app.deposit_address().as_deref().unwrap_or(&app.vault),
            app.deposit_address().is_none().then(|| zyn_custody::memo::encode_text(&id)).as_deref(),
            None,
        )),
        "status": match &status {
            Ok(s) => json!({ "ok": true, "seq": s.seq, "epoch": s.epoch, "backing": s.backing.to_string(), "pools": s.pools, "accounts": s.accounts, "clearing": s.clearing,
                "health": s.health.iter().map(|h| json!({ "name": h.name, "scanned_to": h.scanned_to, "down": h.down, "error": h.error })).collect::<Vec<_>>() }),
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "record": match &record {
            Ok(Some(r)) => json!({
                "known": true,
                "spendable": r.spendable.iter().map(|(a, v)| json!({ "asset": a, "symbol": symbol(*a), "amount": v.to_string() })).collect::<Vec<_>>(),
                "exiting": r.exiting.iter().map(|(a, v, e)| json!({ "asset": a, "symbol": symbol(*a), "amount": v.to_string(), "since": e })).collect::<Vec<_>>(),
                "unreleased": r.unreleased.iter().map(|(a, v, e)| json!({ "asset": a, "symbol": symbol(*a), "amount": v.to_string(), "epoch": e })).collect::<Vec<_>>(),
                "bound": r.binding.is_some(),
                "bound_here": bound_here,
                "redirect_pending": r.redirect.is_some(),
            }),
            Ok(None) => json!({ "known": false, "spendable": [], "exiting": [], "unreleased": [], "bound": false, "bound_here": false }),
            Err(e) => json!({ "known": false, "error": e, "spendable": [], "exiting": [], "unreleased": [], "bound": false, "bound_here": false }),
        },
        "assets": assets.iter().filter(|a| a.lp_of.is_none()).map(|a| json!({
            "id": a.id, "symbol": a.symbol, "supply": a.supply.to_string(),
            "item": a.is_item(),
            "content": a.content.map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
            "collection": a.collection,
            "price_zec": price_zec(a.id).map(|p| p.to_string()),
        })).collect::<Vec<_>>(),
        // Every collection the chain knows, with the floor it publishes.
        "collections": collections.iter().map(|c| json!({
            "id": c.id, "symbol": c.symbol, "cap": c.cap, "minted": c.minted,
            "outstanding": c.outstanding, "pool": c.pool.to_string(),
            "fee_bps": c.fee_bps, "phase": c.phase, "phase_name": c.phase_name(),
            "remaining": c.remaining(), "redeem_price": c.redeem_price.to_string(),
        })).collect::<Vec<_>>(),
        // What the batching actually bought, as two numbers and a receipt:
        // how many epochs have been carried to Zcash, in how many
        // transactions, and the most recent one to link to.
        "settlement": json!({
            "anchors": anchors.len(),
            "epochs_anchored": anchors.last().map(|a| a.epoch).unwrap_or(0),
            "last": anchors.last().map(|a| json!({
                "epoch": a.epoch, "txid": a.txid, "height": a.height, "root": hex(&a.root),
            })),
        }),
        // Every offer resting on the chain. Public by the same argument as
        // the floor: an offer nobody can see is one nobody can take.
        "offers": offers.iter().map(|o| json!({
            "id": o.id,
            "maker": hex(&o.maker),
            "mine": o.maker == id,
            "offer_asset": o.offer_asset,
            "offer_amount": o.offer_amount.to_string(),
            "want_asset": o.want_asset,
            "want_amount": o.want_amount.to_string(),
            "expires_at_epoch": o.expires_at_epoch,
        })).collect::<Vec<_>>(),
        // The items this account holds, each with what backs it. Display
        // only: trading them is the storefront's job, not the wallet's.
        "items": match &record {
            Ok(Some(r)) => r.spendable.iter().filter(|(a, _)| assets.iter().any(|x| x.id == *a && x.is_item())).map(|(a, v)| {
                let info = assets.iter().find(|x| x.id == *a);
                let backing = floor_of(*a);
                json!({
                    "asset": a,
                    "symbol": symbol(*a),
                    "amount": v.to_string(),
                    "content": info.and_then(|i| i.content).map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
                    "collection": backing.map(|(id, _)| id),
                    "redeem_price": backing.map(|(_, f)| f.to_string()),
                })
            }).collect::<Vec<_>>(),
            _ => Vec::new(),
        },
        "pools": pools.iter().map(|p| {
            let lp = assets.iter().find(|a| a.lp_of == Some(p.id));
            json!({ "id": p.id, "asset0": p.asset0, "symbol0": symbol(p.asset0), "asset1": p.asset1, "symbol1": symbol(p.asset1), "reserve0": p.reserve0.to_string(), "reserve1": p.reserve1.to_string(), "fee_bps": p.fee_bps,
                "effective_fee_bps": p.effective_fee_bps, "reference": p.reference.map(|(px, at)| json!({ "price": px.to_string(), "seq": at })),
                "lp_asset": lp.map(|l| l.id), "lp_supply": lp.map(|l| l.supply.to_string()) })
        }).collect::<Vec<_>>(),
        "positions": positions,
        "portfolio": portfolio,
        "launch": launch_json,
        "orders": orders.iter().map(|(seq, pool, asset_in, amount_in, min_out)| json!({ "seq": seq, "pool": pool, "asset_in": asset_in, "symbol_in": symbol(*asset_in), "amount_in": amount_in.to_string(), "min_out": min_out.to_string() })).collect::<Vec<_>>(),
        "bound_sol": bound_sol,
        "solana_vault": std::env::var("ZYN_SOLANA_VAULT").unwrap_or_else(|_| "7KacSYXuVhKSf8dpXcLY3qFZQYiZg2m6vKh4m1HxKZmA".to_string()),
        "binding": binding.map(|b| json!({ "address": b.address, "revealed": b.revealed, "kind": b.kind })),
    }))
}

#[cfg(test)]
mod uri_tests {
    use super::*;

    /// ZIP-321: memos are base64url with no padding, which is exactly where a
    /// hand-rolled encoder goes wrong.
    #[test]
    fn a_memo_is_base64url_without_padding() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(b"foob"), "Zm9vYg");
        assert_eq!(base64url(b"fooba"), "Zm9vYmE");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        // The two characters that separate base64url from base64.
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert!(!base64url(b"any").contains('='), "no padding");
    }

    #[test]
    fn a_deposit_request_carries_the_address_and_only_what_is_needed() {
        let addr = "utest1abc";
        // With a per-account address there is nothing to remember: no memo.
        let u = deposit_uri(addr, None, None);
        assert_eq!(u, "zcash:utest1abc?message=Zyn%20deposit");
        assert!(!u.contains("memo="));

        // Falling back to the shared vault, the memo travels in the request
        // rather than in the depositor's fingers.
        let u = deposit_uri(addr, Some("ZYN1:aabb"), None);
        assert!(u.contains(&format!("memo={}", base64url(b"ZYN1:aabb"))), "{}", u);

        // Amounts are ZEC, decimal, trimmed — not zatoshi.
        assert!(deposit_uri(addr, None, Some(150_000_000)).ends_with("&amount=1.5"));
        assert!(deposit_uri(addr, None, Some(100_000_000)).ends_with("&amount=1"));
        assert!(deposit_uri(addr, None, Some(1)).ends_with("&amount=0.00000001"));
        // Zero is not an amount; leaving it out lets the payer choose.
        assert!(!deposit_uri(addr, None, Some(0)).contains("amount="));
    }
}
