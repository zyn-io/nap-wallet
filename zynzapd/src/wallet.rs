//! The wallet, as a library: recovery material on disk, both pool trees and the
//! held notes next to it, a `zyn-lightd` to scan from and send through.
//! `zyn-wallet` (the CLI) and `zyn-app` (the UI) are both thin over this.
//!
//! Files: `<path>` is either a legacy 32-byte spending key or a versioned
//! mnemonic-backed key record. `<path>.state` is the rest: network, birthday,
//! trees, notes. Losing the state costs a rescan from the birthday; losing the
//! recovery material costs the money.

use std::sync::{Arc, Mutex};

use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey};
use orchard::ValuePool;
use serde_json::{json, Value};
use zcash_protocol::consensus::{Network, NetworkConstants};
use zyn_custody::compact::{self, CompactBlock};
use zyn_custody::lightd::{Client, LightError, MAX_BLOCKS, NET_MAINNET, NET_TESTNET};
use zyn_custody::notes::NoteStore;
use zyn_custody::payout::{self, Destination, Envelope, Payment};
use zyn_custody::shielded::{PoolStores, VaultKeys};

use crate::settle::parse_destination;

pub const ZAT_PER_ZEC: f64 = 1e8;
/// How far behind the tip a block must be before we trust it enough to
/// scan it. Zcash reorgs deeper than this are news.
pub const CONFIRMATIONS: u64 = 3;
const STATE_MAGIC: &[u8; 8] = b"ZYNWAL01";
const KEY_FORMAT: &str = "nap-wallet-key";
const BACKUP_FORMAT: &str = "nap-wallet-backup";
const KEY_VERSION: u64 = 1;
const BACKUP_VERSION: u64 = 2;
pub const ZYN_DERIVATION_VERSION: u64 = 1;
const ZYN_DERIVATION_SALT: &[u8] = b"nap.zyn.ed25519.v1";
const ZYN_DERIVATION_INFO: &[u8] = b"account";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) { return Err("hex has an odd length".into()) }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex".to_string()))
        .collect()
}

fn write_key(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("cannot create wallet key: {}", e))?;
    file.write_all(bytes).map_err(|e| format!("cannot write wallet key: {}", e))?;
    file.sync_all().map_err(|e| format!("cannot sync wallet key: {}", e))
}

#[derive(Clone)]
enum KeyMaterial {
    /// The original Nap format. Keep reading and writing it so every existing
    /// wallet and raw-key backup remains recoverable byte for byte.
    Raw([u8; 32]),
    /// A BIP-39 seed, with the ZIP-32 account derived for the active network.
    Bip39 { entropy: Vec<u8>, passphrase: String, account: u32 },
}

impl KeyMaterial {
    fn generate() -> Result<KeyMaterial, String> {
        let words = Mnemonic::generate_in(Language::English, 24).map_err(|e| e.to_string())?;
        Ok(KeyMaterial::Bip39 { entropy: words.to_entropy(), passphrase: String::new(), account: 0 })
    }

    fn from_mnemonic(words: &str, passphrase: &str, account: u32) -> Result<KeyMaterial, String> {
        let words = Mnemonic::parse_in(Language::English, words.trim())
            .map_err(|e| format!("invalid BIP-39 recovery phrase: {}", e))?;
        Ok(KeyMaterial::Bip39 { entropy: words.to_entropy(), passphrase: passphrase.to_string(), account })
    }

    fn mnemonic(&self) -> Option<String> {
        match self {
            KeyMaterial::Raw(_) => None,
            KeyMaterial::Bip39 { entropy, .. } => Mnemonic::from_entropy(entropy).ok().map(|m| m.to_string()),
        }
    }

    fn passphrase(&self) -> Option<&str> {
        match self {
            KeyMaterial::Raw(_) => None,
            KeyMaterial::Bip39 { passphrase, .. } => Some(passphrase),
        }
    }

    fn account(&self) -> u32 {
        match self { KeyMaterial::Raw(_) => 0, KeyMaterial::Bip39 { account, .. } => *account }
    }

    fn seed(&self) -> Result<Vec<u8>, String> {
        match self {
            KeyMaterial::Raw(key) => Ok(key.to_vec()),
            KeyMaterial::Bip39 { entropy, passphrase, .. } => {
                let words = Mnemonic::from_entropy(entropy).map_err(|e| format!("invalid wallet entropy: {}", e))?;
                Ok(words.to_seed(passphrase).to_vec())
            }
        }
    }

    fn spending_key(&self, network: Network) -> Result<SpendingKey, String> {
        match self {
            KeyMaterial::Raw(bytes) => Option::<SpendingKey>::from(SpendingKey::from_bytes(*bytes))
                .ok_or_else(|| "not a valid spending key".into()),
            KeyMaterial::Bip39 { account, .. } => {
                let id = zip32::AccountId::try_from(*account).map_err(|_| "account must be below 2^31".to_string())?;
                SpendingKey::from_zip32_seed(&self.seed()?, network.coin_type(), id)
                    .map_err(|e| format!("cannot derive ZIP-32 account: {}", e))
            }
        }
    }

    fn zyn_signing_key(&self, account: u32) -> Result<SigningKey, String> {
        let KeyMaterial::Bip39 { account: wallet_account, .. } = self else {
            return Err("a derived Zyn key requires a BIP-39 wallet".into());
        };
        if account != *wallet_account { return Err("Zyn derivation account does not match the wallet account".into()) }
        let hk = Hkdf::<sha2::Sha256>::new(Some(ZYN_DERIVATION_SALT), &self.seed()?);
        let mut info = ZYN_DERIVATION_INFO.to_vec();
        info.extend_from_slice(&account.to_be_bytes());
        let mut seed = [0u8; 32];
        hk.expand(&info, &mut seed).map_err(|_| "cannot derive Zyn key".to_string())?;
        Ok(SigningKey::from_bytes(&seed))
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            KeyMaterial::Raw(key) => key.to_vec(),
            KeyMaterial::Bip39 { entropy, passphrase, account } => serde_json::to_vec_pretty(&json!({
                "format": KEY_FORMAT,
                "version": KEY_VERSION,
                "source": "bip39",
                "entropy": hex(entropy),
                "passphrase": passphrase,
                "account": account,
            })).expect("wallet key JSON is serializable"),
        }
    }

    fn decode(bytes: &[u8]) -> Result<KeyMaterial, String> {
        if bytes.len() == 32 {
            return Ok(KeyMaterial::Raw(bytes.try_into().expect("length checked")));
        }
        let v: Value = serde_json::from_slice(bytes).map_err(|_| "wallet key is neither a legacy 32-byte key nor a Nap key record".to_string())?;
        if v.get("format").and_then(Value::as_str) != Some(KEY_FORMAT) || v.get("version").and_then(Value::as_u64) != Some(KEY_VERSION) {
            return Err("unsupported wallet key format or version".into());
        }
        if v.get("source").and_then(Value::as_str) != Some("bip39") {
            return Err("unsupported wallet key source".into());
        }
        let entropy = unhex(v.get("entropy").and_then(Value::as_str).ok_or("wallet key has no entropy")?)?;
        Mnemonic::from_entropy(&entropy).map_err(|e| format!("invalid wallet entropy: {}", e))?;
        let passphrase = v.get("passphrase").and_then(Value::as_str).unwrap_or("").to_string();
        let account = v.get("account").and_then(Value::as_u64).unwrap_or(0);
        let account = u32::try_from(account).map_err(|_| "wallet account is too large".to_string())?;
        zip32::AccountId::try_from(account).map_err(|_| "account must be below 2^31".to_string())?;
        Ok(KeyMaterial::Bip39 { entropy, passphrase, account })
    }
}

/// A parsed portable backup, kept separate from installation so callers can
/// validate every byte before replacing an empty wallet.
pub struct WalletBackup {
    material: KeyMaterial,
    pub network: Network,
    pub birthday: u64,
    zyn: Option<ZynKeySource>,
}

/// How the independent Zyn signing authority is recovered. Derived keys carry
/// no duplicate secret: the BIP-39 seed in the same backup is authoritative.
/// Legacy keys must remain in the backup because their random seed cannot be
/// reconstructed from the recovery phrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZynKeySource {
    Derived { version: u64, account: u32 },
    Legacy { seed: [u8; 32] },
}

impl ZynKeySource {
    pub fn derived(account: u32) -> Self {
        Self::Derived { version: ZYN_DERIVATION_VERSION, account }
    }

    pub fn json(&self) -> Value {
        match self {
            Self::Derived { version, account } => json!({
                "source": "bip39-hkdf", "version": version, "account": account,
                "domain": "nap.zyn.ed25519.v1", "network_scoped": false,
            }),
            Self::Legacy { seed } => json!({
                "source": "legacy-ed25519", "seed": hex(seed),
            }),
        }
    }

    pub fn parse(v: &Value) -> Result<Self, String> {
        match v.get("source").and_then(Value::as_str) {
            Some("bip39-hkdf") => {
                let version = v.get("version").and_then(Value::as_u64).ok_or("Zyn derivation has no version")?;
                if version != ZYN_DERIVATION_VERSION { return Err("unsupported Zyn derivation version".into()) }
                let account = u32::try_from(v.get("account").and_then(Value::as_u64).unwrap_or(0))
                    .map_err(|_| "Zyn account is too large")?;
                Ok(Self::Derived { version, account })
            }
            Some("legacy-ed25519") => {
                let bytes = unhex(v.get("seed").and_then(Value::as_str).ok_or("legacy Zyn backup has no seed")?)?;
                Ok(Self::Legacy { seed: bytes.try_into().map_err(|_| "legacy Zyn seed must be 32 bytes")? })
            }
            _ => Err("unsupported Zyn key source".into()),
        }
    }
}

impl WalletBackup {
    pub fn from_raw(network: Network, birthday: u64, key: [u8; 32]) -> Result<WalletBackup, String> {
        let material = KeyMaterial::Raw(key);
        // Validate the Orchard scalar before a caller removes any old wallet.
        material.spending_key(network)?;
        Ok(WalletBackup { material, network, birthday, zyn: None })
    }

    pub fn from_mnemonic(network: Network, birthday: u64, words: &str, passphrase: &str, account: u32) -> Result<WalletBackup, String> {
        let material = KeyMaterial::from_mnemonic(words, passphrase, account)?;
        material.spending_key(network)?;
        Ok(WalletBackup { material, network, birthday, zyn: Some(ZynKeySource::derived(account)) })
    }

    pub fn parse(text: &str) -> Result<WalletBackup, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("backup is not JSON: {}", e))?;
        let version = v.get("version").and_then(Value::as_u64);
        if v.get("format").and_then(Value::as_str) != Some(BACKUP_FORMAT) || !matches!(version, Some(KEY_VERSION | BACKUP_VERSION)) {
            return Err("unsupported wallet backup format or version".into());
        }
        let network = match v.get("network").and_then(Value::as_str) {
            Some("mainnet") => Network::MainNetwork,
            Some("testnet") => Network::TestNetwork,
            _ => return Err("backup network must be mainnet or testnet".into()),
        };
        let birthday = v.get("birthday").and_then(Value::as_u64).ok_or("backup has no birthday")?;
        let source = v.get("source").and_then(Value::as_str).ok_or("backup has no key source")?;
        let material = match source {
            "bip39" => {
                let words = v.get("mnemonic").and_then(Value::as_str).ok_or("backup has no recovery phrase")?;
                let passphrase = v.get("passphrase").and_then(Value::as_str).unwrap_or("");
                let account = v.get("account").and_then(Value::as_u64).unwrap_or(0);
                KeyMaterial::from_mnemonic(words, passphrase, u32::try_from(account).map_err(|_| "backup account is too large")?)?
            }
            "raw-orchard" => {
                let bytes = unhex(v.get("spending_key").and_then(Value::as_str).ok_or("backup has no spending key")?)?;
                KeyMaterial::Raw(bytes.try_into().map_err(|_| "spending key must be 32 bytes")?)
            }
            _ => return Err("unsupported backup key source".into()),
        };
        material.spending_key(network)?;
        let zyn = match v.get("zyn") {
            Some(value) => Some(ZynKeySource::parse(value)?),
            None if version == Some(KEY_VERSION) => None,
            None => return Err("backup has no Zyn key descriptor".into()),
        };
        if let Some(ZynKeySource::Derived { account: zyn_account, .. }) = zyn {
            if !matches!(&material, KeyMaterial::Bip39 { account, .. } if *account == zyn_account) {
                return Err("Zyn derivation account does not match the BIP-39 account".into());
            }
        }
        Ok(WalletBackup { material, network, birthday, zyn })
    }

    pub fn to_json(&self) -> String {
        let source = match &self.material {
            KeyMaterial::Raw(key) => json!({
                "source": "raw-orchard",
                "spending_key": hex(key),
            }),
            KeyMaterial::Bip39 { .. } => json!({
                "source": "bip39",
                "mnemonic": self.material.mnemonic().expect("valid mnemonic material"),
                "passphrase": self.material.passphrase().unwrap_or(""),
                "account": self.material.account(),
                "derivation": format!("m/32'/{}'/{}'", self.network.coin_type(), self.material.account()),
            }),
        };
        let mut out = json!({
            "format": BACKUP_FORMAT,
            "version": if self.zyn.is_some() { BACKUP_VERSION } else { KEY_VERSION },
            "network": network_name(self.network),
            "birthday": self.birthday,
        });
        if let (Some(dst), Some(zyn)) = (out.as_object_mut(), self.zyn.as_ref()) {
            dst.insert("zyn".into(), zyn.json());
        }
        if let (Some(dst), Some(src)) = (out.as_object_mut(), source.as_object()) {
            dst.extend(src.clone());
        }
        serde_json::to_string_pretty(&out).expect("wallet backup JSON is serializable")
    }

    pub fn with_zyn(mut self, source: ZynKeySource) -> Self {
        self.zyn = Some(source);
        self
    }

    pub fn zyn(&self) -> Option<ZynKeySource> { self.zyn.clone() }

    pub fn effective_zyn_source(&self) -> Option<ZynKeySource> {
        self.zyn.clone().or_else(|| match &self.material {
            KeyMaterial::Bip39 { account, .. } => Some(ZynKeySource::derived(*account)),
            KeyMaterial::Raw(_) => None,
        })
    }
}

pub fn network_name(n: Network) -> &'static str {
    if n == Network::MainNetwork { "mainnet" } else { "testnet" }
}

pub fn unit(n: Network) -> &'static str {
    if n == Network::MainNetwork { "ZEC" } else { "TAZ" }
}

fn network_of(code: u8) -> Result<Network, String> {
    match code {
        NET_MAINNET => Ok(Network::MainNetwork),
        NET_TESTNET => Ok(Network::TestNetwork),
        _ => Err("the block server is on a network this wallet does not know".into()),
    }
}

fn light(e: LightError) -> String {
    e.to_string()
}

/// Everything the wallet knows besides its key.
pub struct State {
    pub network: Network,
    pub birthday: u64,
    pub stores: PoolStores,
}

impl State {
    fn path(wallet: &str) -> String {
        format!("{}.state", wallet)
    }

    fn save(&self, wallet: &str) -> Result<(), String> {
        let mut out = STATE_MAGIC.to_vec();
        out.push(if self.network == Network::MainNetwork { NET_MAINNET } else { NET_TESTNET });
        out.extend_from_slice(&self.birthday.to_le_bytes());
        for pool in [ValuePool::Orchard, ValuePool::Ironwood] {
            let enc = self.stores.of(pool).lock().map_err(|_| "state lock")?.encode();
            out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
            out.extend_from_slice(&enc);
        }
        let path = State::path(wallet);
        let tmp = format!("{}.tmp", path);
        std::fs::write(&tmp, &out).and_then(|_| std::fs::rename(&tmp, &path)).map_err(|e| format!("cannot save state: {}", e))
    }

    fn load(wallet: &str) -> Result<Option<State>, String> {
        let Ok(b) = std::fs::read(State::path(wallet)) else { return Ok(None) };
        let bad = || "state file is not a zyn-wallet state".to_string();
        if b.get(..8).ok_or_else(bad)? != STATE_MAGIC { return Err(bad()) }
        let network = network_of(*b.get(8).ok_or_else(bad)?)?;
        let birthday = u64::from_le_bytes(b.get(9..17).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let mut at = 17;
        let mut read = || -> Result<NoteStore, String> {
            let n = u32::from_le_bytes(b.get(at..at + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?) as usize;
            at += 4;
            let s = NoteStore::decode(b.get(at..at + n).ok_or_else(bad)?).ok_or_else(bad)?;
            at += n;
            Ok(s)
        };
        let orchard = read()?;
        let ironwood = read()?;
        Ok(Some(State { network, birthday, stores: PoolStores { orchard: Arc::new(Mutex::new(orchard)), ironwood: Arc::new(Mutex::new(ironwood)) } }))
    }

    /// Fresh trees seeded from the server at `birthday - 1`.
    fn seeded(client: &Client, network: Network, birthday: u64) -> Result<State, String> {
        let seed_height = birthday.saturating_sub(1);
        let seed = |pool: ValuePool| -> Result<Arc<Mutex<NoteStore>>, String> {
            let (root, frontier) = client.tree_state(seed_height, pool).map_err(light)?;
            if frontier.is_empty() {
                // The pool is not active yet at this height: its tree
                // starts empty and fills as blocks are scanned.
                return Ok(Arc::new(Mutex::new(NoteStore::empty_at(seed_height))));
            }
            let store = NoteStore::from_frontier(&frontier, seed_height).map_err(|e| format!("{:?}", e))?;
            if store.root_bytes() != Some(root) {
                return Err("the seeded tree does not match the server's root".into());
            }
            Ok(Arc::new(Mutex::new(store)))
        };
        Ok(State { network, birthday, stores: PoolStores { orchard: seed(ValuePool::Orchard)?, ironwood: seed(ValuePool::Ironwood)? } })
    }
}

/// One note we hold, for display.
#[derive(Clone, Debug)]
pub struct NoteView {
    pub pool: ValuePool,
    pub zatoshi: u64,
    pub height: u64,
    pub txid_hex: String,
}

/// What a sync saw, in order.
#[derive(Clone, Debug)]
pub enum Event {
    Progress { at: u64, to: u64 },
    Received { pool: ValuePool, zatoshi: u64, height: u64, txid_hex: String, memo: String },
    Spent { pool: ValuePool, zatoshi: u64, from_height: u64, txid_hex: String, height: u64 },
}

/// The txid as explorers show it.
pub fn txid_hex(txid: &[u8; 32]) -> String {
    txid.iter().rev().map(|b| format!("{:02x}", b)).collect()
}

/// A memo as text. Zcash marks "no memo" with a leading 0xF6; anything
/// else that is UTF-8 is shown as typed, and bytes that are not are hex.
pub fn memo_text(memo: &[u8]) -> String {
    if memo.first() == Some(&0xF6) || memo.iter().all(|b| *b == 0) {
        return String::new();
    }
    let end = memo.iter().rposition(|b| *b != 0).map(|p| p + 1).unwrap_or(0);
    match std::str::from_utf8(&memo[..end]) {
        Ok(t) if !t.chars().any(|c| c.is_control() && c != '\n') => t.to_string(),
        _ => format!("0x{}", memo[..end].iter().map(|b| format!("{:02x}", b)).collect::<String>()),
    }
}

pub struct Wallet {
    path: String,
    material: KeyMaterial,
    sk: SpendingKey,
    fvk: FullViewingKey,
    pub state: State,
    client: Client,
    /// The tip the server reported when the wallet was opened.
    pub tip: u64,
}

impl Wallet {
    /// A fresh 256-bit BIP-39 seed at `path`, born at the server's current tip.
    /// Account zero is derived with ZIP-32 for the server's network.
    pub fn create(path: &str, client: Client) -> Result<Wallet, String> {
        Wallet::install(path, KeyMaterial::generate()?, None, None, client)
    }

    /// Create the other Zcash network face from the same recovery material.
    /// Nap has one phrase and one Zyn identity even though each Zcash network
    /// keeps independent scan state and addresses.
    pub fn create_network_sibling(&self, path: &str, client: Client) -> Result<Wallet, String> {
        Wallet::install(path, self.material.clone(), None, None, client)
    }

    /// An existing raw Orchard key, with a birthday (or the tip if none).
    /// This is the legacy Nap import path; mnemonic wallets use ZIP-32.
    pub fn import(path: &str, seed: [u8; 32], birthday: Option<u64>, client: Client) -> Result<Wallet, String> {
        Wallet::install(path, KeyMaterial::Raw(seed), birthday, None, client)
    }

    /// Restore account `account` from an English BIP-39 recovery phrase.
    pub fn import_mnemonic(path: &str, words: &str, passphrase: &str, account: u32, birthday: u64, client: Client) -> Result<Wallet, String> {
        let material = KeyMaterial::from_mnemonic(words, passphrase, account)?;
        Wallet::install(path, material, Some(birthday), None, client)
    }

    /// Restore a versioned portable backup. Its network and birthday are part
    /// of the authenticated human artifact rather than separate guesses.
    pub fn import_backup(path: &str, backup: WalletBackup, client: Client) -> Result<Wallet, String> {
        Wallet::install(path, backup.material, Some(backup.birthday), Some(backup.network), client)
    }

    fn install(path: &str, material: KeyMaterial, birthday: Option<u64>, expected_network: Option<Network>, client: Client) -> Result<Wallet, String> {
        if std::path::Path::new(path).exists() {
            return Err(format!("{} exists; not overwriting a key", path));
        }
        let info = client.info().map_err(light)?;
        let network = network_of(info.network)?;
        if expected_network.is_some_and(|n| n != network) {
            return Err(format!("this backup is for {}, but the block server is {}", network_name(expected_network.unwrap()), network_name(network)));
        }
        // Derive before touching disk. This catches invalid raw keys, account
        // numbers and mnemonic material without leaving a partial wallet.
        material.spending_key(network)?;
        // A birthday is where scanning starts. A node still catching up
        // cannot say where "now" is, so a new wallet must not be born on it
        // — it would scan every block the node later fetches.
        match birthday {
            None if info.syncing() => return Err(format!("the block server is still syncing ({} of about {}); a new wallet can be created once it has caught up", info.tip, info.estimated)),
            Some(b) if b > info.tip => return Err(format!("the block server is at height {}; it has not reached the birthday {} yet", info.tip, b)),
            _ => {}
        }
        let state = State::seeded(&client, network, birthday.unwrap_or(info.tip).min(info.tip))?;
        if let Some(dir) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        write_key(path, &material.encode())?;
        state.save(path)?;
        Wallet::open(path, client)
    }

    /// Open the wallet against the server, seeding a state if there is none
    /// and refusing a state from the other network.
    pub fn open(path: &str, client: Client) -> Result<Wallet, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
        let material = KeyMaterial::decode(&bytes)?;
        let info = client.info().map_err(light)?;
        let network = network_of(info.network)?;
        let sk = material.spending_key(network)?;
        let fvk = FullViewingKey::from(&sk);
        let state = match State::load(path)? {
            Some(s) if s.network != network => return Err(format!("this wallet has been syncing {}; the block server is {}", network_name(s.network), network_name(network))),
            Some(s) => s,
            None => {
                let s = State::seeded(&client, network, info.tip)?;
                s.save(path)?;
                s
            }
        };
        Ok(Wallet { path: path.to_string(), material, sk, fvk, state, client, tip: info.tip })
    }

    pub fn network(&self) -> Network {
        self.state.network
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    /// The spending key, for a backup. Show it once, to the holder.
    pub fn export_key(&self) -> [u8; 32] {
        *self.sk.to_bytes()
    }

    /// The original backup value exists only for legacy wallets. Exporting a
    /// ZIP-32 child as if it were the mnemonic seed would restore shielded
    /// funds but derive the wrong transparent receiver.
    pub fn legacy_backup_key(&self) -> Option<[u8; 32]> {
        match &self.material { KeyMaterial::Raw(key) => Some(*key), KeyMaterial::Bip39 { .. } => None }
    }

    /// A complete, portable recovery artifact. Mnemonic-backed wallets export
    /// standard BIP-39 words and their ZIP-32 account. Legacy wallets remain
    /// recoverable through their raw Orchard spending key.
    pub fn export_backup(&self) -> String {
        WalletBackup {
            material: self.material.clone(),
            network: self.state.network,
            birthday: self.state.birthday,
            zyn: self.default_zyn_source(),
        }
        .to_json()
    }

    pub fn export_backup_with_zyn(&self, source: ZynKeySource) -> String {
        WalletBackup {
            material: self.material.clone(),
            network: self.state.network,
            birthday: self.state.birthday,
            zyn: Some(source),
        }
        .to_json()
    }

    pub fn default_zyn_source(&self) -> Option<ZynKeySource> {
        match &self.material {
            KeyMaterial::Bip39 { account, .. } => Some(ZynKeySource::derived(*account)),
            KeyMaterial::Raw(_) => None,
        }
    }

    /// Derive the Zyn Ed25519 seed from the full BIP-39 seed. The derivation is
    /// intentionally network-independent: a Nap recovery phrase has one Zyn
    /// identity, while signed intents still bind themselves to a chain id.
    pub fn zyn_signing_key(&self, source: &ZynKeySource) -> Result<SigningKey, String> {
        match source {
            ZynKeySource::Legacy { seed } => Ok(SigningKey::from_bytes(seed)),
            ZynKeySource::Derived { version, account } => {
                if *version != ZYN_DERIVATION_VERSION { return Err("unsupported Zyn derivation version".into()) }
                self.material.zyn_signing_key(*account)
            }
        }
    }

    pub fn mnemonic(&self) -> Option<String> {
        self.material.mnemonic()
    }

    pub fn mnemonic_word_count(&self) -> Option<usize> {
        self.material.mnemonic().map(|m| m.split_whitespace().count())
    }

    /// Value we have spent that the chain has not confirmed yet.
    pub fn pending(&self) -> u64 {
        [ValuePool::Orchard, ValuePool::Ironwood].iter().map(|p| self.state.stores.of(*p).lock().map(|s| s.in_flight_balance()).unwrap_or(0)).sum()
    }

    pub fn address(&self) -> String {
        // Encoded for the network this wallet is actually on, so it is an
        // address the sender's wallet will accept rather than reject.
        VaultKeys::from_full_viewing_key(self.fvk.clone())
            .address(0, <Network as zcash_protocol::consensus::Parameters>::network_type(&self.state.network))
    }

    /// The wallet's transparent receiving address — the doormat.
    ///
    /// Exists for one reason: exchanges pay out transparent, so without it a
    /// holder cannot fund this wallet without a second wallet in between.
    /// Money that arrives here is meant to be shielded immediately; see
    /// `zyn_custody::transparent`.
    pub fn transparent_address(&self) -> Option<String> {
        let net = <Network as zcash_protocol::consensus::Parameters>::network_type(&self.state.network);
        let seed = self.material.seed().ok()?;
        match self.state.network {
            Network::MainNetwork => zyn_custody::transparent::Receiver::derive(
                &zcash_protocol::consensus::MAIN_NETWORK, &seed, self.material.account(), 0),
            Network::TestNetwork => zyn_custody::transparent::Receiver::derive(
                &zcash_protocol::consensus::TEST_NETWORK, &seed, self.material.account(), 0),
        }
        .map(|r| r.encoded(net))
    }

    /// The transparent receiver, derived on demand.
    fn receiver(&self) -> Option<zyn_custody::transparent::Receiver> {
        let seed = self.material.seed().ok()?;
        match self.state.network {
            Network::MainNetwork => zyn_custody::transparent::Receiver::derive(
                &zcash_protocol::consensus::MAIN_NETWORK, &seed, self.material.account(), 0),
            Network::TestNetwork => zyn_custody::transparent::Receiver::derive(
                &zcash_protocol::consensus::TEST_NETWORK, &seed, self.material.account(), 0),
        }
    }

    /// What is sitting on the doormat, and what sweeping it would yield.
    pub fn transparent_balance(&self) -> Result<zyn_custody::transparent::Sweep, String> {
        let Some(addr) = self.transparent_address() else {
            return Err("this build cannot derive a transparent address".into());
        };
        let utxos = self.client.utxos(&addr).map_err(light)?;
        Ok(zyn_custody::transparent::plan(&utxos))
    }

    /// Sweep the doormat into one shielded note this wallet owns.
    ///
    /// The only thing that can be done with transparent funds here, on
    /// purpose: they are a state to leave, not one to transact from.
    pub fn shield_transparent(&mut self, mut on: impl FnMut(Event)) -> Result<String, String> {
        let addr = self.transparent_address().ok_or("no transparent address")?;
        let receiver = self.receiver().ok_or("cannot derive the transparent key")?;
        let utxos = self.client.utxos(&addr).map_err(light)?;
        if utxos.is_empty() {
            return Err("nothing on the transparent address to shield".into());
        }
        self.sync(&mut on)?;
        let env = Envelope::at(self.state.network, self.tip as u32);
        let to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));
        // Ironwood first, like `send_with_memo`: it is the pool a shielded
        // recipient can be paid in.
        let mut tried: Vec<String> = Vec::new();
        for pool in [ValuePool::Ironwood, ValuePool::Orchard] {
            let Ok(version) = env.bundle_version_for(pool) else { continue };
            match zyn_custody::transparent::shield(
                &[&receiver], &utxos, to, &self.fvk, &SpendAuthorizingKey::from(&self.sk), ovk.clone(), version, &env, rand::rngs::OsRng,
            ) {
                // A pool that builds may still be refused by consensus, so a
                // send failure has to fall through to the next pool rather
                // than end the attempt.
                Ok(sealed) => match self.client.send(&sealed.bytes) {
                    Ok(txid) => return Ok(txid),
                    Err(e) => tried.push(format!("{:?} refused by the network: {}", pool, e)),
                },
                Err(e) => tried.push(format!("{:?} could not build: {}", pool, e)),
            }
        }
        Err(if tried.is_empty() { "no pool could carry the sweep".into() } else { tried.join(" | ") })
    }

    pub fn synced_to(&self) -> Option<u64> {
        self.state.stores.synced_to()
    }

    /// (orchard, ironwood) in zatoshi.
    pub fn balance(&self) -> (u64, u64) {
        (self.state.stores.orchard.lock().map(|s| s.balance()).unwrap_or(0), self.state.stores.ironwood.lock().map(|s| s.balance()).unwrap_or(0))
    }

    pub fn notes(&self) -> Vec<NoteView> {
        let mut out = Vec::new();
        for pool in [ValuePool::Ironwood, ValuePool::Orchard] {
            if let Ok(s) = self.state.stores.of(pool).lock() {
                for h in s.held() {
                    let mut t = h.txid;
                    t.reverse();
                    out.push(NoteView { pool, zatoshi: h.value(), height: h.height, txid_hex: t.iter().map(|b| format!("{:02x}", b)).collect() });
                }
            }
        }
        out.sort_by_key(|n| std::cmp::Reverse(n.height));
        out
    }

    /// Throw the scan state away and start again from `birthday`.
    pub fn reset(&mut self, birthday: u64) -> Result<(), String> {
        let fresh = State::seeded(&self.client, self.state.network, birthday.min(self.tip))?;
        fresh.save(&self.path)?;
        self.state = fresh;
        Ok(())
    }

    /// Scan compact blocks from where the trees stopped up to the confirmed
    /// tip. A hit fetches the full transaction, so the note (and its memo)
    /// is held exactly as the vault would hold it.
    pub fn sync(&mut self, mut on: impl FnMut(Event)) -> Result<u64, String> {
        let info = self.client.info().map_err(light)?;
        self.tip = info.tip;
        let keys = VaultKeys::from_full_viewing_key(self.fvk.clone());
        let ivk = PreparedIncomingViewingKey::new(&self.fvk.to_ivk(Scope::External));
        let from = self.state.stores.synced_to().map(|h| h + 1).unwrap_or(self.state.birthday);
        let to = self.tip.saturating_sub(CONFIRMATIONS);
        if from > to {
            return Ok(self.state.stores.synced_to().unwrap_or(self.state.birthday.saturating_sub(1)));
        }
        let mut height = from;
        let mut since_save = 0u64;
        while height <= to {
            let want = (to - height + 1).min(MAX_BLOCKS as u64) as u32;
            let blocks = self.client.blocks(height, want).map_err(light)?;
            if blocks.is_empty() {
                return Err(format!("server has no block {}", height));
            }
            for block in &blocks {
                if block.height != height {
                    return Err(format!("server sent block {} where {} was expected", block.height, height));
                }
                self.scan_block(&keys, &ivk, block, &mut on)?;
                height += 1;
                since_save += 1;
            }
            if since_save >= 10_000 {
                self.state.save(&self.path)?;
                since_save = 0;
            }
            on(Event::Progress { at: height.min(to), to });
        }
        self.state.save(&self.path)?;
        Ok(to)
    }

    fn scan_block(&self, keys: &VaultKeys, ivk: &PreparedIncomingViewingKey, block: &CompactBlock, on: &mut impl FnMut(Event)) -> Result<(), String> {
        let hits = compact::scan(block, ivk);
        let mut o = self.state.stores.orchard.lock().map_err(|_| "state lock")?;
        let mut i = self.state.stores.ironwood.lock().map_err(|_| "state lock")?;
        o.begin_block(block.height);
        i.begin_block(block.height);
        for t in &block.txs {
            let hit_here = hits.iter().any(|h| h.tx_index == t.index);
            // The full transaction, only when something in it is ours: that
            // is what turns a compact hit into a spendable note with its memo.
            let full = if hit_here {
                let raw = self.client.transaction(&t.txid).map_err(light)?;
                keys.scan_actions_lenient(&raw, t.txid, block.height).ok()
            } else {
                None
            };
            let mut our_actions = full.as_ref().map(|s| s.actions.iter().filter(|a| a.ours.is_some())).into_iter().flatten();
            for (pool, list) in [(ValuePool::Orchard, &t.orchard), (ValuePool::Ironwood, &t.ironwood)] {
                let store = match pool { ValuePool::Orchard => &mut o, ValuePool::Ironwood => &mut i };
                for out in list {
                    let act = out.to_action().ok_or("malformed output in a compact block")?;
                    if let Some(spent) = store.spend_nullifier(&act.nullifier(), &self.fvk) {
                        on(Event::Spent { pool, zatoshi: spent.value(), from_height: spent.height, txid_hex: txid_hex(&t.txid), height: block.height });
                    }
                    let ours = hits.iter().any(|h| h.tx_index == t.index && h.pool == pool && h.cmx == out.cmx);
                    let pos = store.append(&act.cmx(), ours);
                    if ours {
                        let a = our_actions.find(|a| a.pool == pool && a.cmx == act.cmx()).ok_or("a compact hit did not decrypt in the full transaction")?;
                        if let (Some(note), Some(pos)) = (a.ours, pos) {
                            on(Event::Received { pool, zatoshi: note.value().inner(), height: block.height, txid_hex: txid_hex(&t.txid), memo: a.memo.as_deref().map(memo_text).unwrap_or_default() });
                            store.hold(note, pos, block.height, t.txid);
                        }
                    }
                }
            }
        }
        o.finish_block(block.height);
        i.finish_block(block.height);
        Ok(())
    }

    /// Build, prove, sign and broadcast one payment. Syncs first. Returns
    /// the txid as the network displays it.
    pub fn send(&mut self, to: &str, zatoshi: u64, memo: Option<&str>, on: impl FnMut(Event)) -> Result<String, String> {
        let mut field = [0u8; 512];
        if let Some(memo) = memo {
            if memo.len() > 512 { return Err("memo longer than 512 bytes".into()) }
            field[..memo.len()].copy_from_slice(memo.as_bytes());
        }
        self.send_with_memo(to, zatoshi, field, on)
    }

    /// Pay `to` with a memo given as the full 512-byte field — for memos that
    /// are bytes rather than text, like a forced intent to the vault.
    pub fn send_with_memo(&mut self, to: &str, zatoshi: u64, memo: [u8; 512], mut on: impl FnMut(Event)) -> Result<String, String> {
        let network = self.state.network;
        let to = parse_destination(to, network).ok_or_else(|| format!("not a {} address", network_name(network)))?;
        if zatoshi == 0 { return Err("amount is zero".into()) }
        let mut payment = Payment::new(to, zatoshi);
        payment.memo = memo;
        self.sync(&mut on)?;
        let env = Envelope::at(network, self.tip as u32);
        let change_to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));
        let mut built = None;
        for pool in [ValuePool::Ironwood, ValuePool::Orchard] {
            let Ok(version) = env.bundle_version_for(pool) else { continue };
            if matches!(to, Destination::Shielded(_)) && !version.default_flags().cross_address_enabled() {
                continue; // Orchard cannot pay a shielded address (NU6.3)
            }
            let store = self.state.stores.of(pool).lock().map_err(|_| "state lock")?;
            match payout::build(&store, &self.fvk, ovk.clone(), &[payment], change_to, version, rand::rngs::OsRng) {
                Ok(p) => { built = Some((p, version, pool)); break }
                Err(payout::PayoutError::Notes(_)) => continue,
                Err(e) => return Err(format!("cannot build: {}", e)),
            }
        }
        let Some((mut p, version, pool)) = built else {
            let (o, i) = self.balance();
            return Err(format!("no pool can cover {} zat (Ironwood {} zat, Orchard {} zat; a shielded recipient needs Ironwood)", zatoshi, i, o));
        };
        let sighash = p.sighash(&env).map_err(|e| e.to_string())?;
        p.finalize_io(sighash, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        p.prove(&payout::proving_key(version), rand::rngs::OsRng).map_err(|e| e.to_string())?;
        let ask = SpendAuthorizingKey::from(&self.sk);
        if payout::sign_with_key(&mut p, sighash, &ask, rand::rngs::OsRng) == 0 { return Err("nothing was signed".into()) }
        let sealed = p.extract(sighash, &env, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        let txid = self.client.send(&sealed.bytes).map_err(|e| format!("the network refused it: {}", e))?;
        // The spent notes leave the store now; the chain will show their
        // nullifiers and confirm it on the next sync.
        {
            let mut store = self.state.stores.of(pool).lock().map_err(|_| "state lock")?;
            for n in &sealed.spent { store.spend(n.position); }
        }
        self.state.save(&self.path)?;
        Ok(txid)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn bip39_uses_the_standard_zip32_orchard_account_path() {
        let material = KeyMaterial::from_mnemonic(WORDS, "", 0).unwrap();
        assert_eq!(
            hex(material.spending_key(Network::MainNetwork).unwrap().to_bytes()),
            "ba36a915cf195348f4f8bcd584e2635735778190071db2f2af78d80b44a97bcb"
        );
        assert_eq!(
            hex(material.spending_key(Network::TestNetwork).unwrap().to_bytes()),
            "13548ce4ac2ec6cc6b93a8f66f50ddce51e9e156cc084d3cef279873446f1b1b"
        );
    }

    #[test]
    fn mnemonic_key_record_round_trips_without_changing_the_seed() {
        let before = KeyMaterial::from_mnemonic(WORDS, "second factor", 7).unwrap();
        let after = KeyMaterial::decode(&before.encode()).unwrap();
        assert_eq!(after.mnemonic().as_deref(), Some(WORDS));
        assert_eq!(after.passphrase(), Some("second factor"));
        assert_eq!(after.account(), 7);
        assert_eq!(before.seed().unwrap(), after.seed().unwrap());
        assert_eq!(
            before.spending_key(Network::MainNetwork).unwrap().to_bytes(),
            after.spending_key(Network::MainNetwork).unwrap().to_bytes()
        );
    }

    #[test]
    fn portable_backup_carries_every_restore_parameter() {
        let backup = WalletBackup::from_mnemonic(Network::TestNetwork, 4_321_000, WORDS, "phrase pass", 3).unwrap();
        let json = backup.to_json();
        let restored = WalletBackup::parse(&json).unwrap();
        assert_eq!(restored.network, Network::TestNetwork);
        assert_eq!(restored.birthday, 4_321_000);
        assert_eq!(restored.material.mnemonic().as_deref(), Some(WORDS));
        assert_eq!(restored.material.passphrase(), Some("phrase pass"));
        assert_eq!(restored.material.account(), 3);
        assert_eq!(
            backup.material.spending_key(backup.network).unwrap().to_bytes(),
            restored.material.spending_key(restored.network).unwrap().to_bytes()
        );
        assert!(matches!(restored.zyn(), Some(ZynKeySource::Derived { version: 1, account: 3 })));
    }

    #[test]
    fn legacy_raw_key_files_and_backups_stay_supported() {
        let raw = [7u8; 32];
        let material = KeyMaterial::decode(&raw).unwrap();
        assert!(matches!(material, KeyMaterial::Raw(key) if key == raw));
        let backup = WalletBackup::from_raw(Network::MainNetwork, 2_000_000, raw).unwrap();
        let restored = WalletBackup::parse(&backup.to_json()).unwrap();
        assert!(matches!(restored.material, KeyMaterial::Raw(key) if key == raw));

        let complete = backup.with_zyn(ZynKeySource::Legacy { seed: [9u8; 32] });
        let restored = WalletBackup::parse(&complete.to_json()).unwrap();
        assert!(matches!(restored.zyn(), Some(ZynKeySource::Legacy { seed }) if seed == [9u8; 32]));
    }

    #[test]
    fn backup_parser_refuses_unknown_versions_and_bad_mnemonics() {
        let unknown = json!({
            "format": BACKUP_FORMAT, "version": 99, "network": "mainnet",
            "birthday": 1, "source": "bip39", "mnemonic": WORDS,
        });
        assert!(WalletBackup::parse(&unknown.to_string()).err().unwrap().contains("unsupported"));
        assert!(WalletBackup::from_mnemonic(Network::MainNetwork, 1, "abandon abandon", "", 0).is_err());
    }

    #[test]
    fn zyn_derivation_vectors_are_network_independent() {
        let vectors = [
            ("", 0, "57d47cefdba062bb9669a7a64e9072e49d2b5bc66892952429240e4c91b16183", "308ab8b209813f5912287682b50950d62782abc61507f0a80abafd0f7a33a7a6", "b85db260ec3a7c0a22c19c1f3380bfc75599c0ea4eeeeda69177ab12f9da56ea"),
            ("nap passphrase", 7, "f4e1b20f8a0cd2e19ae9d85ce3057cbb13863be3630e87972afce0b14c513c2e", "276237e6804911ecd6d44c3d170ac67ff8dc8abf87cf423489a71dddf68857eb", "4c976ef0d248340b910e246439c3139911f1752e6ba1d3c198f41071e4503604"),
        ];
        for (passphrase, account, seed_hex, public_hex, account_hex) in vectors {
            let material = KeyMaterial::from_mnemonic(WORDS, passphrase, account).unwrap();
            let key = material.zyn_signing_key(account).unwrap();
            let public = key.verifying_key().to_bytes();
            let id = zyn_vm::auth::account_of(zyn_vm::auth::Scheme::Ed25519, &public);
            assert_eq!(hex(&key.to_bytes()), seed_hex);
            assert_eq!(hex(&public), public_hex);
            assert_eq!(hex(&id), account_hex);
        }
    }
}
