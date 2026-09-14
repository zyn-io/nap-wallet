//! What the operator chooses, and what happens when they choose nothing.
//!
//! Environment variables rather than a config file or a flag parser: this
//! process runs under systemd, where `Environment=` is already the idiom, and
//! a parser is a dependency plus a second place for the defaults to live.
//!
//! Every value has a default that produces a working devnet, because a node
//! that will not start until it is fully configured is a node nobody starts.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use zyn::epoch::EpochPolicy;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Config {
    pub chain_id: u32,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Intents before an epoch seals.
    pub seal_every: u64,
    /// Seconds before an epoch seals regardless of traffic.
    ///
    /// The failsafe that makes an expiry expressed in epochs mean something in
    /// wall-clock terms (**S12**). Without it a quiet chain never advances, and
    /// a signed intent with a validity window never expires.
    pub seal_after_secs: u64,
    /// Epochs before an anchor is due.
    pub anchor_every: u64,
    pub anchor_after_secs: u64,
    /// Seconds between state saves, on top of the save every seal performs.
    pub save_every_secs: u64,
    /// Where the Zcash node is, and which addresses the vault watches.
    ///
    /// `None` for the bridge fields means **no bridge**: the node runs as a
    /// pure devnet. That is the default, because a bridge that starts itself
    /// because a variable happened to be set is a bridge nobody decided to run.
    pub zebra: Option<ZebraConfig>,
    /// A `ZynVault` to watch on an EVM chain. Independent of `zebra`: both may
    /// run at once, which is the point — the EVM vault is the **second**
    /// bridge, and a second one is what fault isolation was ever for
    /// (`DECISIONS` §14b).
    pub evm: Option<EvmConfig>,
    /// A vault account to watch on Solana.
    pub solana: Option<SolanaConfig>,
    /// Confirmations before a deposit is credited.
    pub confirmations: u64,
    /// Seconds between deposit scans.
    pub bridge_poll_secs: u64,
    /// Which Zcash this vault is on. **Testnet unless told otherwise**, so
    /// mainnet is always a deliberate act. Everything network-shaped derives
    /// from this one value — address encoding, the Zebra client, reveals — and
    /// the node is asked to confirm it at boot rather than assumed.
    pub network: zyn_custody::zebra::Network,
    /// How many settle passes an anchor may sit confirmed-but-unendorsed
    /// before the alerter calls the chain down. Deposits do not release while
    /// this is climbing, so silence here is the failure mode that hurts.
    pub endorse_stall_passes: u32,
    /// Which parameter profile a *new* chain starts with.
    ///
    /// Ignored on resume: parameters are committed state (**S5**), so a
    /// running chain's are whatever it already agreed to, not whatever this
    /// process was started with.
    pub profile: Profile,
    /// Testnet knob: set `exit_timeout_epochs` — which is also the withdrawal
    /// **redirect delay** — on a running chain. Sequenced as a `SetParams`,
    /// once, at startup, only when it differs. A 34-hour redirect delay is the
    /// right mainnet posture and the wrong demo one.
    pub exit_timeout_epochs: Option<u64>,
    /// `ZYN_BATCH_CLEARING=1|0`: whether single-hop swaps queue for the seal
    /// and clear together at one price. Unset leaves the chain as it is.
    pub batch_clearing: Option<bool>,
    /// `ZYN_FEEDS=1`: run the reference-price feed for bridged pairs
    /// (DECISIONS §5.7, `feeds.rs`). `ZYN_FEED_INTERVAL` seconds between
    /// cycles, `ZYN_FEED_MAP` per-symbol source overrides.
    /// Retired §30 switches retained only so startup can reject stale operator
    /// configuration explicitly instead of silently restoring old tokenomics.
    pub launch: bool,
    pub launch_threshold: Option<String>,
    pub feeds: bool,
    pub feed_interval: u64,
    pub feed_map: Option<String>,
    /// Where alerts go: a webhook taking `{"text": …}`. `None` is the journal only.
    pub alert_url: Option<String>,
    /// Consecutive failed passes before a component is announced down.
    pub alert_after_failures: u32,
    /// Seconds without a successful pass before a component is announced down.
    pub stall_secs: u64,
    /// Where anchored bundles are written before they are mirrored.
    pub da_dir: PathBuf,
    /// `url[|token],…` — where bundles are pushed. Empty means local only.
    pub da_mirrors: String,
    /// Re-read forced intents from this height at boot and queue the unhandled.
    pub forced_rescan_from: Option<u64>,
    /// Signer public keys (ed25519, hex, comma-separated) and the threshold —
    /// when set, a root's deposits release only after that many endorse it.
    pub signer_set: Option<(Vec<[u8; 32]>, usize)>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ZebraConfig {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub password: Option<String>,
    /// `<address> <account-hex>` per line. Transparent scaffold.
    pub addresses: Option<PathBuf>,
    /// Hex Orchard spending key. Its presence selects the **shielded** path,
    /// which is the design; `addresses` is the scaffold.
    pub vault_seed: Option<String>,
    /// Hex Orchard full viewing key (96 bytes) — the threshold vault's, from
    /// `zyn-ceremony zcash`. The shielded path with a key nobody holds; the
    /// only form under which exits can be signed.
    pub vault_fvk: Option<String>,
    /// Exits. `None` means deposits only.
    pub settle: Option<ZebraSettleConfig>,
    /// `<txid-hex> <account-hex>` per line: deposits without a memo that a
    /// human has assigned. Read at startup; the file is the audit trail.
    pub attributions: Option<PathBuf>,
    /// Never scan below here. A vault cannot have been paid before it existed,
    /// and trial-decrypting from genesis does not finish.
    pub from_height: u64,
    /// Blocks per scan pass. A pass cut short is resumed, not lost.
    pub max_blocks: u64,
    /// Re-read from this height on the next start, regardless of progress.
    /// Safe by construction — the dedup set is what prevents a re-credit, not
    /// the height — and the tool for "a deposit was missed".
    pub rescan_from: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EvmConfig {
    /// A JSON-RPC endpoint. HTTPS in practice.
    pub url: String,
    /// EIP-155 id, checked against the endpoint at startup. A vault has the
    /// same address on every EVM chain, so a wrong URL points at a *real*
    /// contract with real logs.
    pub chain_id: u64,
    pub vault: [u8; 20],
    /// The Zyn asset id this vault's deposits credit.
    pub asset: [u8; 32],
    /// `None` watches the chain's native asset.
    pub token: Option<[u8; 20]>,
    pub decimals: u8,
    /// Never scan below the block the vault was deployed in.
    pub from_height: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ZebraSettleConfig {
    /// Directory of RedPallas FROST shares (`zyn-ceremony zcash ...`). In
    /// custody-federation mode this holds only `public.bin` (no secret share).
    pub shares: PathBuf,
    pub threshold: u16,
    /// `<account-hex> <transparent-address> <salt-hex>` per line.
    pub reveals: PathBuf,
    /// `host:port,...` — sign anchors through these custodians instead of
    /// local shares. When set, the box holds no secret share.
    pub custodians: Option<Vec<String>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolanaConfig {
    pub url: String,
    /// `devnet` or `testnet`. Mainnet is refused by the client.
    pub cluster: String,
    /// The vault account, base58. Compared as a string, so it is never decoded
    /// and re-encoded into something subtly different.
    pub vault: String,
    /// The Zyn asset id these deposits credit.
    pub asset: [u8; 32],
    /// Never scan below the slot the vault was funded at. Solana's history is
    /// long and most nodes will not serve its start anyway.
    pub from_slot: u64,
    /// Re-read from this slot on the next start. Safe: the dedup set is what
    /// prevents a re-credit.
    pub rescan_from: Option<u64>,
    /// SPL mints the vault mirrors as items: `<mint>:<symbol>[,…]`. Each is
    /// created on the chain if absent (`CreateBridgedItem`), and its token
    /// account watched.
    pub mints: Vec<(String, String)>,
    /// Exits. `None` means deposits only: the vault fills and nothing leaves.
    pub settle: Option<SolanaSettleConfig>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolanaSettleConfig {
    /// Directory of FROST shares (`zyn-ceremony solana ...`). Holding a quorum
    /// of them in one place is a **devnet**: the key is whole in all but name.
    pub shares: PathBuf,
    pub threshold: u16,
    /// The vault's durable nonce account, base58. Created once, with the vault
    /// as its authority.
    pub nonce_account: String,
    /// `<account-hex> <address> <salt-hex>` per line: where exits may go.
    pub reveals: PathBuf,
    /// `host:port,...` — sign exits through these custodians instead of local
    /// shares. When set, `shares` holds only `public.bin`.
    pub custodians: Option<Vec<String>>,
}

/// A `0x`-prefixed 20-byte address.
fn address(key: &'static str, v: &str) -> Result<[u8; 20], ConfigError> {
    let h = v.strip_prefix("0x").unwrap_or(v);
    if h.len() != 40 {
        return Err(ConfigError::Bad(key, v.into()));
    }
    let mut out = [0u8; 20];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
            .map_err(|_| ConfigError::Bad(key, v.into()))?;
    }
    Ok(out)
}

fn asset_id(key: &'static str, default: [u8; 32]) -> Result<[u8; 32], ConfigError> {
    let Ok(value) = env::var(key) else {
        return Ok(default);
    };
    parse_hex(&value, 32, key)
        .map_err(|_| ConfigError::Bad(key, value))?
        .try_into()
        .map_err(|_| ConfigError::Bad(key, "expected 64 hex characters".into()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Profile {
    /// Production floors.
    V1,
    /// Floors scaled to what a testnet faucet dispenses — 0.1 TAZ a request.
    Testnet,
}

impl std::str::FromStr for Profile {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s {
            "v1" | "mainnet" => Ok(Profile::V1),
            "testnet" | "devnet" => Ok(Profile::Testnet),
            _ => Err(()),
        }
    }
}

impl Profile {
    pub fn params(self) -> swapvm::Params {
        match self {
            Profile::V1 => swapvm::Params::v1(),
            Profile::Testnet => swapvm::Params::testnet(),
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Bad(&'static str, String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Bad(k, v) => write!(f, "{} is not valid: {:?}", k, v),
        }
    }
}

fn parse_hex(s: &str, n: usize, key: &'static str) -> Result<Vec<u8>, ConfigError> {
    if s.len() != n * 2 {
        return Err(ConfigError::Bad(key, s.into()));
    }
    (0..n)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| ConfigError::Bad(key, s.into()))
        })
        .collect()
}

fn var<T: std::str::FromStr>(key: &'static str, fallback: T) -> Result<T, ConfigError> {
    match env::var(key) {
        Err(_) => Ok(fallback),
        Ok(v) => v.parse().map_err(|_| ConfigError::Bad(key, v)),
    }
}

impl Config {
    /// Read the environment, falling back to a devnet that works.
    ///
    /// Binds loopback by default. A sequencer with no consensus and no peer
    /// authentication should not be reachable from the internet by accident —
    /// putting it behind a reverse proxy is a decision someone makes, not a
    /// default they inherit.
    pub fn from_env() -> Result<Config, ConfigError> {
        Ok(Config {
            chain_id: var("ZYN_CHAIN_ID", 1u32)?,
            listen: var("ZYN_LISTEN", "127.0.0.1:8099".to_string())?
                .parse()
                .map_err(|_| ConfigError::Bad("ZYN_LISTEN", "expected host:port".into()))?,
            data_dir: var("ZYN_DATA_DIR", "./zyn-data".to_string())?.into(),
            seal_every: var("ZYN_SEAL_EVERY", 256u64)?,
            seal_after_secs: var("ZYN_SEAL_AFTER_SECS", 60u64)?,
            anchor_every: var("ZYN_ANCHOR_EVERY", 30u64)?,
            anchor_after_secs: var("ZYN_ANCHOR_AFTER_SECS", 1800u64)?,
            save_every_secs: var("ZYN_SAVE_EVERY_SECS", 30u64)?,
            profile: var("ZYN_PARAMS", Profile::Testnet)?,
            alert_url: env::var("ZYN_ALERT_URL").ok(),
            alert_after_failures: var("ZYN_ALERT_AFTER_FAILURES", 3u32)?,
            stall_secs: var("ZYN_STALL_SECS", 900u64)?,
            da_dir: match env::var("ZYN_DA_DIR") {
                Ok(d) => d.into(),
                Err(_) => PathBuf::from(var("ZYN_DATA_DIR", "./zyn-data".to_string())?).join("da"),
            },
            da_mirrors: env::var("ZYN_DA_MIRRORS").unwrap_or_default(),
            forced_rescan_from: env::var("ZYN_FORCED_RESCAN_FROM")
                .ok()
                .and_then(|v| v.parse().ok()),
            signer_set: match env::var("ZYN_SIGNER_SET").ok().filter(|s| !s.is_empty()) {
                None => None,
                Some(list) => {
                    let mut keys = Vec::new();
                    for h in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                        keys.push(
                            parse_hex(h, 32, "ZYN_SIGNER_SET")
                                .map_err(|_| ConfigError::Bad("ZYN_SIGNER_SET", h.into()))?
                                .try_into()
                                .expect("32 bytes"),
                        );
                    }
                    let threshold = var("ZYN_SIGNER_THRESHOLD", 0usize)?;
                    let threshold = if threshold == 0 {
                        keys.len() / 2 + 1
                    } else {
                        threshold
                    };
                    Some((keys, threshold))
                }
            },
            exit_timeout_epochs: env::var("ZYN_EXIT_TIMEOUT_EPOCHS")
                .ok()
                .map(|v| {
                    v.parse()
                        .map_err(|_| ConfigError::Bad("ZYN_EXIT_TIMEOUT_EPOCHS", v))
                })
                .transpose()?,
            batch_clearing: env::var("ZYN_BATCH_CLEARING")
                .ok()
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            launch: env::var("ZYN_LAUNCH")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            launch_threshold: env::var("ZYN_LAUNCH_THRESHOLD").ok(),
            feeds: env::var("ZYN_FEEDS")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            feed_interval: env::var("ZYN_FEED_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            feed_map: env::var("ZYN_FEED_MAP").ok(),
            confirmations: var("ZYN_CONFIRMATIONS", 10u64)?,
            bridge_poll_secs: var("ZYN_BRIDGE_POLL_SECS", 30u64)?,
            network: match env::var("ZYN_NETWORK")
                .unwrap_or_else(|_| "testnet".into())
                .as_str()
            {
                "mainnet" | "main" => zyn_custody::zebra::Network::Mainnet,
                "regtest" => zyn_custody::zebra::Network::Regtest,
                "testnet" | "test" => zyn_custody::zebra::Network::Testnet,
                other => return Err(ConfigError::Bad("ZYN_NETWORK", other.into())),
            },
            endorse_stall_passes: var("ZYN_ENDORSE_STALL_PASSES", 20u32)?,
            zebra: {
                let addresses = env::var("ZYN_BRIDGE_ADDRESSES").ok();
                let vault_fvk = env::var("ZYN_VAULT_FVK").ok();
                let vault_seed = env::var("ZYN_VAULT_SEED").ok();
                if vault_seed.is_some() && vault_fvk.is_some() {
                    return Err(ConfigError::Bad(
                        "ZYN_VAULT_FVK",
                        "set a seed or a viewing key, not both".into(),
                    ));
                }
                let settle = match env::var("ZYN_ZEBRA_SHARES").ok() {
                    None => None,
                    Some(shares) => {
                        if vault_fvk.is_none() {
                            return Err(ConfigError::Bad(
                                "ZYN_ZEBRA_SHARES",
                                "exits need ZYN_VAULT_FVK, the threshold key's viewing key".into(),
                            ));
                        }
                        Some(ZebraSettleConfig {
                            shares: shares.into(),
                            threshold: var("ZYN_ZEBRA_THRESHOLD", 2u16)?,
                            reveals: env::var("ZYN_ZEBRA_REVEALS")
                                .map_err(|_| {
                                    ConfigError::Bad(
                                        "ZYN_ZEBRA_REVEALS",
                                        "required when ZYN_ZEBRA_SHARES is set".into(),
                                    )
                                })?
                                .into(),
                            custodians: env::var("ZYN_CUSTODIANS")
                                .ok()
                                .filter(|v| !v.is_empty())
                                .map(|v| {
                                    v.split(',')
                                        .map(str::trim)
                                        .filter(|s| !s.is_empty())
                                        .map(String::from)
                                        .collect()
                                }),
                        })
                    }
                };
                match (&addresses, &vault_seed.clone().or(vault_fvk.clone())) {
                    (None, None) => None,
                    (Some(_), Some(_)) => {
                        return Err(ConfigError::Bad(
                            "ZYN_VAULT_SEED",
                            "set either a shielded vault seed or transparent addresses, \
                             not both — two scanners crediting one asset would double it"
                                .into(),
                        ))
                    }
                    _ => Some(ZebraConfig {
                        host: var("ZYN_ZEBRA_HOST", "127.0.0.1".to_string())?,
                        port: var("ZYN_ZEBRA_PORT", 18232u16)?,
                        user: env::var("ZYN_ZEBRA_USER").ok(),
                        password: env::var("ZYN_ZEBRA_PASS").ok(),
                        addresses: addresses.clone().map(Into::into),
                        vault_seed: vault_seed.clone(),
                        vault_fvk: vault_fvk.clone(),
                        settle: settle.clone(),
                        attributions: env::var("ZYN_ZEBRA_ATTRIBUTIONS").ok().map(Into::into),
                        from_height: var("ZYN_BRIDGE_FROM_HEIGHT", 0u64)?,
                        max_blocks: var("ZYN_BRIDGE_MAX_BLOCKS", 200u64)?,
                        rescan_from: env::var("ZYN_BRIDGE_RESCAN_FROM")
                            .ok()
                            .map(|v| {
                                v.parse()
                                    .map_err(|_| ConfigError::Bad("ZYN_BRIDGE_RESCAN_FROM", v))
                            })
                            .transpose()?,
                    }),
                }
            },
            solana: {
                match env::var("ZYN_SOLANA_RPC_URL").ok() {
                    None => None,
                    Some(url) => Some(SolanaConfig {
                        url,
                        cluster: var("ZYN_SOLANA_CLUSTER", "devnet".to_string())?,
                        vault: env::var("ZYN_SOLANA_VAULT").map_err(|_| {
                            ConfigError::Bad(
                                "ZYN_SOLANA_VAULT",
                                "a Solana RPC URL was set without a vault account".into(),
                            )
                        })?,
                        asset: asset_id("ZYN_SOLANA_ASSET", swapvm::types::SOL_ZY)?,
                        from_slot: var("ZYN_SOLANA_FROM_SLOT", 0u64)?,
                        mints: env::var("ZYN_SOLANA_MINTS")
                            .ok()
                            .map(|v| {
                                v.split(',')
                                    .filter(|x| !x.trim().is_empty())
                                    .map(|x| {
                                        let (m, sym) = x
                                            .trim()
                                            .split_once(':')
                                            .unwrap_or((x.trim(), "ITEM.zy"));
                                        (m.to_string(), sym.to_string())
                                    })
                                    .collect()
                            })
                            .unwrap_or_default(),
                        rescan_from: env::var("ZYN_SOLANA_RESCAN_FROM")
                            .ok()
                            .map(|v| {
                                v.parse()
                                    .map_err(|_| ConfigError::Bad("ZYN_SOLANA_RESCAN_FROM", v))
                            })
                            .transpose()?,
                        settle: match env::var("ZYN_SOLANA_SHARES").ok() {
                            None => None,
                            Some(shares) => {
                                let need = |k: &'static str| {
                                    env::var(k).map_err(|_| {
                                        ConfigError::Bad(
                                            k,
                                            "required when ZYN_SOLANA_SHARES is set".into(),
                                        )
                                    })
                                };
                                Some(SolanaSettleConfig {
                                    shares: shares.into(),
                                    threshold: var("ZYN_SOLANA_THRESHOLD", 2u16)?,
                                    nonce_account: need("ZYN_SOLANA_NONCE")?,
                                    reveals: need("ZYN_SOLANA_REVEALS")?.into(),
                                    custodians: env::var("ZYN_SOLANA_CUSTODIANS")
                                        .ok()
                                        .filter(|v| !v.is_empty())
                                        .map(|v| {
                                            v.split(',')
                                                .map(str::trim)
                                                .filter(|s| !s.is_empty())
                                                .map(String::from)
                                                .collect()
                                        }),
                                })
                            }
                        },
                    }),
                }
            },
            evm: {
                // The URL is the switch. Nothing starts an EVM watcher because
                // some other variable happened to be set.
                match env::var("ZYN_EVM_RPC_URL").ok() {
                    None => None,
                    Some(url) => {
                        let vault = env::var("ZYN_EVM_VAULT").map_err(|_| {
                            ConfigError::Bad(
                                "ZYN_EVM_VAULT",
                                "an EVM RPC URL was set without a vault address".into(),
                            )
                        })?;
                        let token = match env::var("ZYN_EVM_TOKEN").ok() {
                            None => None,
                            Some(t) => Some(address("ZYN_EVM_TOKEN", &t)?),
                        };
                        Some(EvmConfig {
                            url,
                            chain_id: var("ZYN_EVM_CHAIN_ID", 84_532u64)?,
                            vault: address("ZYN_EVM_VAULT", &vault)?,
                            asset: asset_id("ZYN_EVM_ASSET", [0; 32])?,
                            token,
                            decimals: var("ZYN_EVM_DECIMALS", 18u8)?,
                            from_height: var("ZYN_EVM_FROM_HEIGHT", 0u64)?,
                        })
                    }
                }
            },
        })
    }

    pub fn policy(&self) -> EpochPolicy {
        EpochPolicy {
            intents_per_epoch: self.seal_every,
            epochs_per_anchor: self.anchor_every,
            max_seconds_per_epoch: self.seal_after_secs,
            max_seconds_per_anchor: self.anchor_after_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defaults have to produce a running node, or the first thing anyone
    /// meets is a configuration error.
    #[test]
    fn the_defaults_are_a_working_devnet() {
        let c = Config::from_env().expect("defaults must parse");
        assert!(
            c.listen.ip().is_loopback(),
            "the default bind must not be public"
        );
        assert!(c.seal_every > 0);
        assert!(
            c.seal_after_secs > 0,
            "a quiet chain must still advance its epochs"
        );
        // A default of production floors on a devnet would wall off the
        // faucet path before anyone reached it.
        assert_eq!(c.profile, Profile::Testnet);
        // A bridge is opted into, never inherited.
        assert!(c.zebra.is_none(), "the bridge must not start by default");
        assert!(
            c.confirmations > 0,
            "crediting at zero confirmations credits reorgs"
        );
    }
}
