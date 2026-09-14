//! Paying exits out: pending withdrawals on Zyn become transactions elsewhere.
//!
//! The deposit side (`bridge.rs`) turns an observation into a credit. This is
//! the other direction, and it is where the money leaves — so the discipline is
//! the mirror image: **fail toward paying nobody, never toward paying twice.**
//!
//! # The shape
//!
//! 1. Pending exits for one asset are read from state and grouped by
//!    `zyn_bridge::settle::group` — canonical, oldest-first. Signers therefore
//!    attest to a list the state determined; nobody chooses it (§14e, level 1).
//! 2. Each is resolved to a destination the account committed to, or refused.
//! 3. One transaction-sized group is signed against the vault's **durable
//!    nonce**, recorded in the ledger, then broadcast.
//! 4. When the chain reports it **finalized**, the VM is told with
//!    `ConfirmWithdrawal`, which burns the units. A burn never precedes finality.
//!
//! # Why a double payment is impossible rather than unlikely
//!
//! Every transaction names the nonce's current value and consumes it. Two
//! transactions built against the same value cannot both land, whatever the
//! ledger says and whatever crashed in between. The ledger's job is therefore
//! not to prevent a repeat — the chain does that — but to remember which exits
//! a transaction covered, so they can be burned once it is final and re-settled
//! if it never is.
//!
//! One transaction is in flight at a time. That serialises on the nonce, which
//! is the point, and it caps throughput at one group per finality window —
//! twenty-odd exits per ~15 s, which is not the bottleneck anywhere.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use orchard::ValuePool;

use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::AssetId;
use zyn::verify::Authorized;
use zyn_bridge::solana::{chunk, resolve, Reveal, SolanaError as SettleError, VaultAccounts};
use zyn_bridge::{group, ChainOrigin, Settlement, ORIGIN_SOLANA, ORIGIN_ZCASH};
use zyn_custody::custody_net::SolanaPublicPackage;
use zyn_custody::solana::custody::{self, Id, Keys};
use zyn_custody::solana::{base58_encode, pubkey, Rpc, TxStatus};
use zyn_vm::spec::AccountId;
use zyn_vm::Fixed;

use crate::rpc::Shared;

/// One broadcast transaction and the exits it pays.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    /// The transaction's signature, base58 — its id on the chain.
    pub id: String,
    /// The nonce value it was built against. If the nonce moves on and this
    /// transaction is not the reason, something else spent it.
    pub nonce: [u8; 32],
    pub transaction: Vec<u8>,
    /// `(account, amount)` pairs to confirm once final, in the ledger's asset
    /// unless `cover_assets` says otherwise for that index.
    pub covers: Vec<(AccountId, Fixed)>,
    /// Per cover, the asset if it is not the ledger's own (a mirrored item
    /// paid in the same transaction as SOL).
    pub cover_assets: Vec<Option<AssetId>>,
    pub status: Status,
    /// Zcash: note positions this transaction spends, forgotten once final.
    pub spent: Vec<u64>,
    /// Zcash: the height from which the transaction is invalid. Past it and
    /// unseen, the entry is abandoned and its exits settled afresh — the two
    /// cannot both land, because the second is built after the first died.
    pub expiry: u64,
    /// Zcash: which pool's notes it spends, so the right tree forgets them.
    pub pool: ValuePool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Sent, or about to be. Watched every pass.
    Broadcast,
    /// Final on the chain and burned on Zyn. Done.
    Confirmed,
    /// Will never land: it failed, or its nonce was spent by something else.
    /// Its exits are still pending and will be settled again.
    Abandoned,
}

/// The settler's memory, on disk, written before anything is sent.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Ledger {
    pub entries: Vec<Entry>,
}

impl Ledger {
    fn path(dir: &Path, chain_id: u32, name: &str) -> PathBuf {
        dir.join(format!("settle-{}-{}.ledger", chain_id, name))
    }

    pub fn load(dir: &Path, chain_id: u32, asset: AssetId) -> Result<Ledger, String> {
        Self::load_named(dir, chain_id, &hex(&asset))
    }

    pub fn save(&self, dir: &Path, chain_id: u32, asset: AssetId) -> Result<(), String> {
        self.save_named(dir, chain_id, &hex(&asset))
    }

    /// A ledger for something other than one asset's exits — the anchors.
    pub fn load_named(dir: &Path, chain_id: u32, name: &str) -> Result<Ledger, String> {
        match std::fs::read_to_string(Self::path(dir, chain_id, name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
            Err(e) => Err(format!("cannot read settlement ledger: {}", e)),
            Ok(s) => Ledger::decode(&s)
                .ok_or_else(|| "settlement ledger is corrupt; refusing to guess".to_string()),
        }
    }

    pub fn save_named(&self, dir: &Path, chain_id: u32, name: &str) -> Result<(), String> {
        let tmp = dir.join(format!(".settle-{}-{}.tmp", chain_id, name));
        std::fs::write(&tmp, self.encode()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, Self::path(dir, chain_id, name)).map_err(|e| e.to_string())
    }

    pub fn in_flight(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|e| e.status == Status::Broadcast)
    }

    /// One line per entry: `id status nonce tx account:amount,...`
    pub fn encode(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            let status = match e.status {
                Status::Broadcast => "broadcast",
                Status::Confirmed => "confirmed",
                Status::Abandoned => "abandoned",
            };
            let covers: Vec<String> = e
                .covers
                .iter()
                .enumerate()
                .map(
                    |(i, (a, v))| match e.cover_assets.get(i).copied().flatten() {
                        Some(asset) => format!("{}:{}@{}", hex(a), v.0, hex(&asset)),
                        None => format!("{}:{}", hex(a), v.0),
                    },
                )
                .collect();
            let spent: Vec<String> = e.spent.iter().map(|p| p.to_string()).collect();
            s.push_str(&format!(
                "{} {} {} {} {} {} {} {}\n",
                e.id,
                status,
                hex(&e.nonce),
                hex(&e.transaction),
                covers.join(","),
                if spent.is_empty() {
                    "-".to_string()
                } else {
                    spent.join(",")
                },
                e.expiry,
                match e.pool {
                    ValuePool::Orchard => "orchard",
                    ValuePool::Ironwood => "ironwood",
                }
            ));
        }
        s
    }

    pub fn decode(s: &str) -> Option<Ledger> {
        let mut entries = Vec::new();
        for line in s.lines().filter(|l| !l.trim().is_empty()) {
            let mut f = line.split(' ');
            let id = f.next()?.to_string();
            let status = match f.next()? {
                "broadcast" => Status::Broadcast,
                "confirmed" => Status::Confirmed,
                "abandoned" => Status::Abandoned,
                _ => return None,
            };
            let nonce: [u8; 32] = unhex(f.next()?)?.try_into().ok()?;
            let transaction = unhex(f.next()?)?;
            let mut covers = Vec::new();
            let mut cover_assets = Vec::new();
            for c in f.next()?.split(',').filter(|c| !c.is_empty()) {
                let (a, v) = c.split_once(':')?;
                let (v, asset) = match v.split_once('@') {
                    Some((v, asset)) => (v, Some(unhex(asset)?.try_into().ok()?)),
                    None => (v, None),
                };
                let account: AccountId = unhex(a)?.try_into().ok()?;
                covers.push((account, Fixed::raw(v.parse().ok()?)));
                cover_assets.push(asset);
            }
            // Older ledgers stop here; Zcash entries carry two more fields.
            let spent = match f.next() {
                None | Some("-") => Vec::new(),
                Some(list) => list
                    .split(',')
                    .map(|p| p.parse().ok())
                    .collect::<Option<Vec<u64>>>()?,
            };
            let expiry = match f.next() {
                None => 0,
                Some(v) => v.parse().ok()?,
            };
            let pool = match f.next() {
                None | Some("orchard") => ValuePool::Orchard,
                Some("ironwood") => ValuePool::Ironwood,
                _ => return None,
            };
            if f.next().is_some() {
                return None;
            }
            entries.push(Entry {
                id,
                nonce,
                transaction,
                covers,
                cover_assets,
                status,
                spent,
                expiry,
                pool,
            });
        }
        Some(Ledger { entries })
    }
}

/// `<account-hex> <address-base58> <salt-hex>` per line. Comments with `#`.
///
/// The reveals are the preimages of the destination commitments the chain
/// holds (`Binding`). They are private to the operator and the user; this file
/// is what makes an exit payable and it says where the money goes, so it is
/// handled like a key.
pub fn load_reveals(path: &Path) -> Result<Vec<Reveal>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut f = line.split_whitespace();
        let (a, addr, salt) = (f.next(), f.next(), f.next());
        let (Some(a), Some(addr), Some(salt), None) = (a, addr, salt, f.next()) else {
            return Err(format!(
                "line {}: expected `<account-hex> <address> <salt-hex>`",
                n + 1
            ));
        };
        let account: AccountId = unhex(a)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("line {}: account must be 64 hex characters", n + 1))?;
        let address = pubkey(addr)
            .ok_or_else(|| format!("line {}: address is not a Solana address", n + 1))?;
        let salt: [u8; 32] = unhex(salt)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("line {}: salt must be 64 hex characters", n + 1))?;
        out.push(Reveal {
            account,
            address,
            salt,
        });
    }
    Ok(out)
}

/// Every pending exit for `asset`, grouped canonically. Pure: what the signers
/// would compute from the same state.
pub fn settlement_of(state: &SwapState, asset: AssetId) -> Option<Settlement> {
    settlement_for(state, asset, ORIGIN_SOLANA)
}

pub fn settlement_for(
    state: &SwapState,
    asset: AssetId,
    origin: ChainOrigin,
) -> Option<Settlement> {
    let exits = state.accounts.iter().filter_map(|(id, a)| {
        let p = a.pending.get(&asset)?;
        Some((*id, asset, origin, p.amount, p.since))
    });
    group(exits).into_iter().find(|s| s.origin == origin)
}

pub struct SolanaSettler {
    mirrored: Vec<zyn_custody::solana::Mirrored>,
    rpc: Rpc,
    shares: Vec<(Id, Keys)>,
    /// The vault's public package: the address, and what aggregation checks
    /// against. Held even when the shares are elsewhere.
    public: SolanaPublicPackage,
    /// Where the share-holders are, when they are not here. `None` keeps the
    /// V0 posture: shares in this process.
    custodians: Option<Vec<String>>,
    threshold: u16,
    nonce_account: String,
    reveals: Vec<Reveal>,
    asset: AssetId,
    ledger: Ledger,
    dir: PathBuf,
    chain_id: u32,
    /// Accounts already reported as unpayable, so the log says it once.
    warned: BTreeMap<AccountId, ()>,
}

impl SolanaSettler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rpc: Rpc,
        shares: Vec<(Id, Keys)>,
        public: SolanaPublicPackage,
        custodians: Option<Vec<String>>,
        threshold: u16,
        nonce_account: &str,
        reveals: Vec<Reveal>,
        asset: AssetId,
        dir: PathBuf,
        chain_id: u32,
    ) -> Result<SolanaSettler, String> {
        if custodians.is_none() && shares.len() < usize::from(threshold) {
            return Err(format!(
                "{} share(s) loaded, {} needed to sign",
                shares.len(),
                threshold
            ));
        }
        pubkey(nonce_account).ok_or("ZYN_SOLANA_NONCE is not a Solana address")?;
        let ledger = Ledger::load(&dir, chain_id, asset)?;
        if custodians.is_some() {
            eprintln!("zynzapd: Solana exits signed by custodians, threshold {} — this box holds no share", threshold);
        }
        Ok(SolanaSettler {
            mirrored: Vec::new(),
            rpc,
            shares,
            public,
            custodians,
            threshold,
            nonce_account: nonce_account.to_string(),
            reveals,
            asset,
            ledger,
            dir,
            chain_id,
            warned: BTreeMap::new(),
        })
    }

    /// Items this vault also pays out, as SPL transfers.
    pub fn with_mirrored(mut self, mirrored: Vec<zyn_custody::solana::Mirrored>) -> SolanaSettler {
        self.mirrored = mirrored;
        self
    }

    pub fn vault_address(&self) -> String {
        base58_encode(&custody::vault_address_of(&self.public))
    }

    /// A reveal that arrived over the channel. Replaces an earlier one for
    /// the same account: the newest is the one the holder means.
    pub fn add_reveal(&mut self, r: Reveal) {
        self.reveals.retain(|x| x.account != r.account);
        self.reveals.push(r);
        self.warned.remove(&r.account);
    }

    fn save(&self) -> Result<(), String> {
        self.ledger.save(&self.dir, self.chain_id, self.asset)
    }

    /// One pass. Returns how many exits were confirmed on Zyn.
    pub fn poll_once(&mut self, node: &Shared, now: u64) -> Result<usize, String> {
        let confirmed = self.follow_up(node, now)?;
        if self.ledger.in_flight().next().is_some() {
            return Ok(confirmed);
        }
        self.settle_next(node)?;
        Ok(confirmed)
    }

    /// Advance every in-flight entry by what the chain says.
    fn follow_up(&mut self, node: &Shared, now: u64) -> Result<usize, String> {
        let mut confirmed = 0;
        let mut changed = false;
        for i in 0..self.ledger.entries.len() {
            if self.ledger.entries[i].status != Status::Broadcast {
                continue;
            }
            let id = self.ledger.entries[i].id.clone();
            match self.rpc.signature_status(&id).map_err(|e| e.to_string())? {
                TxStatus::Finalized => {
                    // The chain cannot take this back, so Zyn may now burn.
                    let covers = self.ledger.entries[i].covers.clone();
                    let cover_assets = self.ledger.entries[i].cover_assets.clone();
                    let mut n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
                    for (k, (account, amount)) in covers.into_iter().enumerate() {
                        let asset = cover_assets.get(k).copied().flatten().unwrap_or(self.asset);
                        let step = n.submit(
                            Authorized::operator(Intent::ConfirmWithdrawal {
                                account,
                                asset,
                                amount,
                            }),
                            now,
                        );
                        if step.rejected() {
                            eprintln!("zynzapd: ConfirmWithdrawal for {} rejected at seq {} — chain and ledger disagree", hex(&account), step.seq);
                        } else {
                            confirmed += 1;
                        }
                    }
                    self.ledger.entries[i].status = Status::Confirmed;
                    changed = true;
                }
                TxStatus::Failed => {
                    eprintln!(
                        "zynzapd: settlement {} failed on chain; its exits stay pending",
                        id
                    );
                    self.ledger.entries[i].status = Status::Abandoned;
                    changed = true;
                }
                TxStatus::Confirmed => {}
                TxStatus::Unknown => {
                    let nonce_now = self
                        .rpc
                        .nonce_value(&self.nonce_account)
                        .map_err(|e| e.to_string())?;
                    if nonce_now != self.ledger.entries[i].nonce {
                        // Not ours, and not this one: the nonce was spent by a
                        // transaction this ledger never wrote. That is either a
                        // second operator or a stolen authority, and neither
                        // is something to carry on past quietly.
                        eprintln!("zynzapd: NONCE {} WAS SPENT BY A TRANSACTION NOT IN THE LEDGER — investigate before settling again", self.nonce_account);
                        self.ledger.entries[i].status = Status::Abandoned;
                        changed = true;
                    } else if let Err(e) = self
                        .rpc
                        .send_transaction(&self.ledger.entries[i].transaction)
                    {
                        eprintln!("zynzapd: rebroadcast of {} refused: {}", id, e);
                    }
                }
            }
        }
        if changed {
            self.save()?;
        }
        Ok(confirmed)
    }

    /// Sign and send the next group, if there is one.
    fn settle_next(&mut self, node: &Shared) -> Result<(), String> {
        let (settlement, bindings) = {
            let n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
            // SOL and every mirrored item leave through the same vault, in
            // the same transactions.
            let mut assets = vec![self.asset];
            assets.extend(self.mirrored.iter().map(|m| m.asset));
            let exits = n
                .state()
                .accounts
                .iter()
                .flat_map(|(id, a)| {
                    assets.iter().filter_map(move |asset| {
                        a.pending
                            .get(asset)
                            .map(|p| (*id, *asset, ORIGIN_SOLANA, p.amount, p.since))
                    })
                })
                .collect::<Vec<_>>();
            let Some(s) = group(exits).into_iter().find(|s| s.origin == ORIGIN_SOLANA) else {
                return Ok(());
            };
            let b: BTreeMap<AccountId, zyn_bridge::Binding> = s
                .payouts
                .iter()
                .filter_map(|p| Some((p.account, n.state().accounts.get(&p.account)?.binding?)))
                .collect();
            (s, b)
        };
        // Only exits that can be paid: bound, and disclosed to us. The rest
        // wait, and are named once.
        let payable: Vec<_> = settlement
            .payouts
            .iter()
            .filter(|p| {
                let ok = bindings.contains_key(&p.account)
                    && self.reveals.iter().any(|r| r.account == p.account);
                if !ok && self.warned.insert(p.account, ()).is_none() {
                    eprintln!(
                        "zynzapd: exit for {} is not payable (no binding or no reveal); waiting",
                        hex(&p.account)
                    );
                }
                ok
            })
            .copied()
            .collect();
        if payable.is_empty() {
            return Ok(());
        }
        let resolved = resolve(&payable, |a| bindings.get(&a).copied(), &self.reveals).map_err(
            |e| match e {
                SettleError::WrongDestination => {
                    "a reveal does not match its account's binding — REFUSING to pay".to_string()
                }
                e => format!("cannot resolve settlement: {:?}", e),
            },
        )?;
        // An item leaves as an SPL transfer of whole units; SOL as lamports.
        let resolved: Vec<zyn_bridge::solana::SolPayout> = resolved
            .into_iter()
            .zip(payable.iter())
            .map(
                |(sp, p)| match self.mirrored.iter().find(|m| m.asset == p.asset) {
                    Some(m) => {
                        let mint = zyn_custody::solana::pubkey(&m.mint).unwrap_or([0u8; 32]);
                        let units = (p.amount.0 / Fixed::ONE.0) as u64 * m.per_unit;
                        zyn_bridge::solana::SolPayout::token(sp.to, mint, units)
                    }
                    None => sp,
                },
            )
            .collect();
        let vault = custody::vault_address_of(&self.public);
        let accounts = VaultAccounts {
            vault,
            nonce_account: pubkey(&self.nonce_account).ok_or("nonce account")?,
        };
        let groups =
            chunk(accounts, &resolved).map_err(|e| format!("cannot split settlement: {:?}", e))?;
        // The exit pays the network fee, not the vault: units burned on Zyn
        // equal lamports leaving the vault, or the vault drifts below what it
        // has issued and the next attestation refuses. One fee per
        // transaction, taken from the first payout in it.
        let mut first = groups[0].clone();
        let fee = 5_000u64;
        // The fee comes from the first *native* payout in the group. A group
        // of items alone has no lamports to take it from; the vault's SOL
        // surplus covers it, which a top-up (all-zero memo) maintains.
        if let Some(n) = first.iter_mut().find(|p| p.token.is_none()) {
            if n.lamports <= fee {
                return Err("the first exit in the group cannot cover the network fee".into());
            }
            n.lamports -= fee;
        }
        let first = &first;
        let covers: Vec<(AccountId, Fixed)> = payable
            .iter()
            .take(first.len())
            .map(|p| (p.account, p.amount))
            .collect();
        let cover_assets: Vec<Option<AssetId>> = payable
            .iter()
            .take(first.len())
            .map(|p| (p.asset != self.asset).then_some(p.asset))
            .collect();

        let payment = match &self.custodians {
            Some(addrs) => {
                let mut q = zyn_custody::custody_net::RemoteSolanaQuorum::new(addrs.clone());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                custody::prepare_with(
                    &self.rpc,
                    &mut q,
                    self.threshold,
                    &self.public,
                    &self.nonce_account,
                    first,
                    now,
                )
            }
            None => {
                let quorum: Vec<(Id, &Keys)> = self
                    .shares
                    .iter()
                    .take(usize::from(self.threshold))
                    .map(|(i, k)| (*i, k))
                    .collect();
                custody::prepare(
                    &self.rpc,
                    &quorum,
                    self.threshold,
                    &self.nonce_account,
                    first,
                    &mut rand::rngs::OsRng,
                )
            }
        }
        .map_err(|e| format!("cannot prepare settlement: {:?}", e))?;
        let nonce = self
            .rpc
            .nonce_value(&self.nonce_account)
            .map_err(|e| e.to_string())?;

        // Recorded before it is sent. A crash after this line and before the
        // broadcast loses nothing: the entry is Unknown next pass and is
        // rebroadcast, or abandoned if the nonce moved.
        self.ledger.entries.push(Entry {
            id: payment.id(),
            nonce,
            transaction: payment.transaction.clone(),
            covers,
            cover_assets,
            status: Status::Broadcast,
            spent: Vec::new(),
            expiry: 0,
            pool: ValuePool::Orchard,
        });
        self.save()?;
        match custody::broadcast(&self.rpc, &payment) {
            Ok(sig) => eprintln!(
                "zynzapd: settlement {} broadcast, {} exit(s)",
                sig,
                first.len()
            ),
            Err(e) => eprintln!("zynzapd: broadcast deferred: {:?}", e),
        }
        Ok(())
    }
}

// ====================================================================
// Zcash
// ====================================================================

use orchard::bundle::BundleVersion;
use orchard::circuit::ProvingKey;
use orchard::keys::{FullViewingKey, Scope};
use zcash_protocol::consensus::Network;
use zcash_transparent::address::TransparentAddress;
use zyn_custody::ceremony::{Identifier as ZcashId, VaultKeys as ZcashKeys};

use zyn_custody::payout::{self, Envelope, Payment};
use zyn_custody::shielded::PoolStores;
use zyn_custody::zebra::Zebra;

/// One zatoshi in `Fixed`'s scale.
const ZAT: i128 = 10_000_000_000;

/// Where a Zcash exit may go.
pub use zyn_custody::payout::Destination as ZcashDestination;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZcashReveal {
    pub account: AccountId,
    pub address: ZcashDestination,
    pub salt: [u8; 32],
}

/// The destination commitment: `keccak(kind ‖ address ‖ salt)` — kind `0`
/// P2PKH, `1` P2SH (20 bytes), `2` an Orchard/Ironwood receiver (43 bytes).
pub fn zcash_commitment(address: &ZcashDestination, salt: &[u8; 32]) -> [u8; 32] {
    match address {
        ZcashDestination::Transparent(TransparentAddress::PublicKeyHash(h)) => {
            zyn_vm::eip712::keccak(&[&[0u8], &h[..], &salt[..]])
        }
        ZcashDestination::Transparent(TransparentAddress::ScriptHash(h)) => {
            zyn_vm::eip712::keccak(&[&[1u8], &h[..], &salt[..]])
        }
        ZcashDestination::Shielded(a) => {
            zyn_vm::eip712::keccak(&[&[2u8], &a.to_raw_address_bytes()[..], &salt[..]])
        }
    }
}

/// A transparent address or a unified address with an Orchard/Ironwood
/// receiver, for `network`.
pub fn parse_destination(s: &str, network: Network) -> Option<ZcashDestination> {
    if let Some(t) = payout::transparent_address(s, network) {
        return Some(ZcashDestination::Transparent(t));
    }
    use zcash_address::unified::{Container, Encoding, Receiver};
    let (net, ua) = zcash_address::unified::Address::decode(s).ok()?;
    let want = match network {
        Network::MainNetwork => zcash_protocol::consensus::NetworkType::Main,
        Network::TestNetwork => zcash_protocol::consensus::NetworkType::Test,
    };
    if net != want {
        return None;
    }
    let raw = ua.items().into_iter().find_map(|r| match r {
        Receiver::Orchard(raw) => Some(raw),
        _ => None,
    })?;
    let addr: Option<orchard::Address> = orchard::Address::from_raw_address_bytes(&raw).into();
    addr.map(ZcashDestination::Shielded)
}

/// `<account-hex> <transparent-address> <salt-hex>` per line.
pub fn load_zcash_reveals(path: &Path, network: Network) -> Result<Vec<ZcashReveal>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() != 3 {
            return Err(format!(
                "line {}: expected `<account-hex> <address> <salt-hex>`",
                n + 1
            ));
        }
        let account: AccountId = unhex(f[0])
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("line {}: account must be 64 hex characters", n + 1))?;
        let address = parse_destination(f[1], network).ok_or_else(|| {
            format!(
                "line {}: not a transparent or unified address for this network",
                n + 1
            )
        })?;
        let salt: [u8; 32] = unhex(f[2])
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| format!("line {}: salt must be 64 hex characters", n + 1))?;
        out.push(ZcashReveal {
            account,
            address,
            salt,
        });
    }
    Ok(out)
}

pub struct ZcashSettler {
    zebra: Zebra,
    network: Network,
    shares: Vec<(ZcashId, ZcashKeys)>,
    public: zyn_custody::custody_net::ZcashPublicPackage,
    custodians: Option<Vec<String>>,
    threshold: u16,
    fvk: FullViewingKey,
    notes: PoolStores,
    reveals: Vec<ZcashReveal>,
    asset: AssetId,
    confirmations: u64,
    ledger: Ledger,
    dir: PathBuf,
    chain_id: u32,
    /// Built once per bundle version; seconds and hundreds of megabytes.
    proving: Option<(BundleVersion, ProvingKey)>,
    warned: BTreeMap<AccountId, ()>,
}

impl ZcashSettler {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        zebra: Zebra,
        network: Network,
        shares: Vec<(ZcashId, ZcashKeys)>,
        threshold: u16,
        fvk: FullViewingKey,
        notes: PoolStores,
        reveals: Vec<ZcashReveal>,
        asset: AssetId,
        confirmations: u64,
        dir: PathBuf,
        chain_id: u32,
        public: zyn_custody::custody_net::ZcashPublicPackage,
        custodians: Option<Vec<String>>,
    ) -> Result<ZcashSettler, String> {
        if custodians.is_none() && shares.len() < usize::from(threshold) {
            return Err(format!(
                "{} share(s) loaded, {} needed to sign",
                shares.len(),
                threshold
            ));
        }
        // The viewing key must be the threshold key's, or notes arrive at an
        // address the signers cannot authorise (`ceremony::orchard_viewing_key`).
        let group = *public.verifying_key();
        let ak_matches = zyn_custody::ceremony::orchard_viewing_key(&group, [0u8; 32], [0u8; 32])
            .map(|k| k.to_bytes()[..32] == fvk.to_bytes()[..32])
            .unwrap_or(false);
        if !ak_matches {
            return Err("the vault's viewing key is not the threshold key's — see ceremony::orchard_viewing_key".into());
        }
        let ledger = Ledger::load(&dir, chain_id, asset)?;
        if custodians.is_some() {
            eprintln!(
                "zynzapd: Zcash exits signed by custodians, threshold {} — this box holds no share",
                threshold
            );
        }
        Ok(ZcashSettler {
            zebra,
            network,
            shares,
            public,
            custodians,
            threshold,
            fvk,
            notes,
            reveals,
            asset,
            confirmations,
            ledger,
            dir,
            chain_id,
            proving: None,
            warned: BTreeMap::new(),
        })
    }

    pub fn deposit_address(&self) -> String {
        // The network the settler was built for, so the address it prints is
        // one somebody on that chain can actually pay.
        zyn_custody::shielded::VaultKeys::from_full_viewing_key(self.fvk.clone()).address(
            0,
            <Network as zcash_protocol::consensus::Parameters>::network_type(&self.network),
        )
    }

    pub fn add_reveal(&mut self, r: ZcashReveal) {
        self.reveals.retain(|x| x.account != r.account);
        self.reveals.push(r);
        self.warned.remove(&r.account);
    }

    fn save(&self) -> Result<(), String> {
        self.ledger.save(&self.dir, self.chain_id, self.asset)
    }

    pub fn poll_once(&mut self, node: &Shared, now: u64) -> Result<usize, String> {
        let confirmed = self.follow_up(node, now)?;
        if self.ledger.in_flight().next().is_some() {
            return Ok(confirmed);
        }
        self.settle_next(node)?;
        Ok(confirmed)
    }

    fn follow_up(&mut self, node: &Shared, now: u64) -> Result<usize, String> {
        let mut confirmed = 0;
        let mut changed = false;
        let tip = self.zebra.block_count().map_err(|e| e.to_string())?;
        for i in 0..self.ledger.entries.len() {
            if self.ledger.entries[i].status != Status::Broadcast {
                continue;
            }
            let id = self.ledger.entries[i].id.clone();
            match self.zebra.confirmations(&id).map_err(|e| e.to_string())? {
                Some(depth) if depth >= self.confirmations => {
                    let covers = self.ledger.entries[i].covers.clone();
                    let mut n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
                    for (account, amount) in covers {
                        let step = n.submit(
                            Authorized::operator(Intent::ConfirmWithdrawal {
                                account,
                                asset: self.asset,
                                amount,
                            }),
                            now,
                        );
                        if step.rejected() {
                            eprintln!("zynzapd: ConfirmWithdrawal for {} rejected at seq {} — chain and ledger disagree", hex(&account), step.seq);
                        } else {
                            confirmed += 1;
                        }
                    }
                    // The notes are gone from the chain; forget them here.
                    if let Ok(mut store) = self.notes.of(self.ledger.entries[i].pool).lock() {
                        for pos in &self.ledger.entries[i].spent {
                            store.spend((*pos).into());
                        }
                    }
                    self.ledger.entries[i].status = Status::Confirmed;
                    changed = true;
                }
                Some(_) => {} // seen, not deep enough
                None if tip > self.ledger.entries[i].expiry => {
                    eprintln!("zynzapd: settlement {} expired unseen at {}; its exits will be settled afresh", id, tip);
                    self.ledger.entries[i].status = Status::Abandoned;
                    changed = true;
                }
                None => {
                    let hex_tx: String = self.ledger.entries[i]
                        .transaction
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    if let Err(e) = self.zebra.send_raw_transaction(&hex_tx) {
                        eprintln!("zynzapd: rebroadcast of {} refused: {}", id, e);
                    }
                }
            }
        }
        if changed {
            self.save()?;
        }
        Ok(confirmed)
    }

    fn settle_next(&mut self, node: &Shared) -> Result<(), String> {
        let (settlement, bindings) = {
            let n = node.lock().map_err(|_| "node lock poisoned".to_string())?;
            let Some(s) = settlement_for(n.state(), self.asset, ORIGIN_ZCASH) else {
                return Ok(());
            };
            let b: BTreeMap<AccountId, zyn_bridge::Binding> = s
                .payouts
                .iter()
                .filter_map(|p| Some((p.account, n.state().accounts.get(&p.account)?.binding?)))
                .collect();
            (s, b)
        };
        let mut payments = Vec::new();
        let mut covers = Vec::new();
        for p in &settlement.payouts {
            let reveal = self.reveals.iter().find(|r| r.account == p.account);
            let payable = match (bindings.get(&p.account), reveal) {
                (Some(b), Some(r)) if b.admits(zcash_commitment(&r.address, &r.salt)) => Some(r),
                (Some(_), Some(_)) => {
                    return Err(
                        "a reveal does not match its account's binding — REFUSING to pay".into(),
                    )
                }
                _ => None,
            };
            let Some(r) = payable else {
                if self.warned.insert(p.account, ()).is_none() {
                    eprintln!(
                        "zynzapd: exit for {} is not payable (no binding or no reveal); waiting",
                        hex(&p.account)
                    );
                }
                continue;
            };
            if p.amount.0 <= 0 || p.amount.0 % ZAT != 0 {
                if self.warned.insert(p.account, ()).is_none() {
                    eprintln!(
                        "zynzapd: exit for {} is not a whole number of zatoshi; waiting",
                        hex(&p.account)
                    );
                }
                continue;
            }
            payments.push(Payment::new(r.address, (p.amount.0 / ZAT) as u64));
            covers.push((p.account, p.amount));
        }
        if payments.is_empty() {
            return Ok(());
        }
        // The exit pays the network fee: build once to learn it, then take it
        // from the first payout, so what leaves the vault equals what is
        // burned on Zyn. Otherwise the vault drifts below its issuance and the
        // next attestation refuses.

        let tip = self.zebra.block_count().map_err(|e| e.to_string())?;
        let env = Envelope::at(self.network, tip as u32);
        let change_to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));

        // Ironwood first: it is where deposits arrive now and the only pool
        // that can pay a shielded address. Orchard, if that cannot cover it,
        // and then only the transparent recipients — an Orchard note cannot
        // reach a shielded one (§17), so those exits wait for Ironwood funds.
        let mut attempt = None;
        for pool in [ValuePool::Ironwood, ValuePool::Orchard] {
            let Ok(version) = env.bundle_version_for(pool) else {
                continue;
            };
            let (pay, cov): (Vec<Payment>, Vec<(AccountId, Fixed)>) =
                if version.default_flags().cross_address_enabled() {
                    (payments.clone(), covers.clone())
                } else {
                    payments
                        .iter()
                        .zip(covers.iter())
                        .filter(|(p, _)| matches!(p.to, ZcashDestination::Transparent(_)))
                        .map(|(p, c)| (*p, *c))
                        .unzip()
                };
            if pay.is_empty() {
                continue;
            }
            let store = self
                .notes
                .of(pool)
                .lock()
                .map_err(|_| "note store poisoned".to_string())?;
            let probe = match payout::build(
                &store,
                &self.fvk,
                ovk.clone(),
                &pay,
                change_to,
                version,
                rand::rngs::OsRng,
            ) {
                Ok(p) => p,
                Err(payout::PayoutError::Notes(_)) => continue,
                Err(e) => return Err(format!("cannot build payout: {}", e)),
            };
            let fee = probe.fee;
            let mut pay = pay;
            if pay[0].zatoshi <= fee {
                return Err("the first exit cannot cover the network fee".into());
            }
            pay[0].zatoshi -= fee;
            match payout::build(
                &store,
                &self.fvk,
                ovk.clone(),
                &pay,
                change_to,
                version,
                rand::rngs::OsRng,
            ) {
                Ok(p) => {
                    attempt = Some((p, cov, version));
                    break;
                }
                // This pool cannot cover it; try the next.
                Err(payout::PayoutError::Notes(_)) => continue,
                Err(e) => return Err(format!("cannot build payout: {}", e)),
            }
        }
        let Some((mut payout, covers, version)) = attempt else {
            // Deposits still confirming, a change note not yet scanned, or a
            // shielded exit waiting for Ironwood funds. Wait, loudly once.
            if self.warned.insert([0u8; 32], ()).is_none() {
                eprintln!(
                    "zynzapd: no pool can cover {} Zcash exit(s) yet; waiting",
                    payments.len()
                );
            }
            return Ok(());
        };
        let sighash = payout.sighash(&env).map_err(|e| e.to_string())?;
        payout
            .finalize_io(sighash, rand::rngs::OsRng)
            .map_err(|e| e.to_string())?;
        if self
            .proving
            .as_ref()
            .map(|(v, _)| *v != version)
            .unwrap_or(true)
        {
            eprintln!(
                "zynzapd: building the Orchard proving key ({:?})",
                version.circuit_version()
            );
            self.proving = Some((version, payout::proving_key(version)));
        }
        payout
            .prove(&self.proving.as_ref().unwrap().1, rand::rngs::OsRng)
            .map_err(|e| e.to_string())?;
        let group = *self.public.verifying_key();
        match &self.custodians {
            Some(addrs) => {
                let mut q = zyn_custody::custody_net::RemoteQuorum::new(addrs.clone());
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                payout::sign_all_with(
                    &mut payout,
                    sighash,
                    &mut q,
                    self.threshold,
                    &group,
                    &self.public,
                    now,
                )
                .map_err(|e| e.to_string())?;
            }
            None => {
                let quorum: Vec<(ZcashId, &ZcashKeys)> = self
                    .shares
                    .iter()
                    .take(usize::from(self.threshold))
                    .map(|(i, k)| (*i, k))
                    .collect();
                payout::sign_all(
                    &mut payout,
                    sighash,
                    &quorum,
                    self.threshold,
                    rand::rngs::OsRng,
                )
                .map_err(|e| e.to_string())?;
            }
        }
        let fee = payout.fee;
        let sealed = payout
            .extract(sighash, &env, rand::rngs::OsRng)
            .map_err(|e| e.to_string())?;

        // Recorded before it is sent. Unseen past `expiry`, it is abandoned
        // and rebuilt; the two cannot both land.
        self.ledger.entries.push(Entry {
            id: sealed.txid_hex(),
            nonce: [0u8; 32],
            transaction: sealed.bytes.clone(),
            cover_assets: vec![None; covers.len()],
            covers,
            status: Status::Broadcast,
            spent: sealed.spent.iter().map(|n| u64::from(n.position)).collect(),
            expiry: u64::from(u32::from(env.expiry)),
            pool: version.value_pool(),
        });
        self.save()?;
        match self.zebra.send_raw_transaction(&sealed.hex()) {
            Ok(txid) => eprintln!(
                "zynzapd: Zcash settlement {} broadcast from {:?}, {} exit(s), fee {} zat",
                txid,
                version.value_pool(),
                payments.len(),
                fee
            ),
            Err(e) => eprintln!("zynzapd: broadcast deferred: {}", e),
        }
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ledger_round_trips_and_refuses_junk() {
        let l = Ledger {
            entries: vec![
                Entry {
                    id: "5j7s".into(),
                    nonce: [3; 32],
                    transaction: vec![1, 2, 3],
                    covers: vec![([1; 32], Fixed::whole(2)), ([2; 32], Fixed::raw(-5))],
                    cover_assets: vec![None, Some([7; 32])],
                    status: Status::Broadcast,
                    spent: Vec::new(),
                    expiry: 0,
                    pool: ValuePool::Orchard,
                },
                Entry {
                    id: "ab".repeat(32),
                    nonce: [0; 32],
                    transaction: vec![9],
                    covers: vec![([4; 32], Fixed::whole(1))],
                    cover_assets: vec![None],
                    status: Status::Confirmed,
                    spent: vec![7, 12],
                    expiry: 4_300_040,
                    pool: ValuePool::Ironwood,
                },
            ],
        };
        assert_eq!(Ledger::decode(&l.encode()), Some(l.clone()));
        // A ledger written before the Zcash fields existed still loads.
        let old = format!(
            "x broadcast {} 0102 {}:5\n",
            "00".repeat(32),
            "01".repeat(32)
        );
        assert_eq!(
            Ledger::decode(&old).unwrap().entries[0].spent,
            Vec::<u64>::new()
        );
        assert_eq!(Ledger::decode("x broadcast 00 00 \n"), None);
        assert_eq!(Ledger::decode("x lost 00 00 \n"), None);
        assert_eq!(Ledger::decode(""), Some(Ledger::default()));
    }

    #[test]
    fn reveals_parse_and_bad_lines_are_named() {
        let dir = std::env::temp_dir().join(format!("zyn-reveals-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("reveals");
        std::fs::write(
            &f,
            format!(
                "# who goes where\n{} 11111111111111111111111111111111 {}\n",
                "ab".repeat(32),
                "cd".repeat(32)
            ),
        )
        .unwrap();
        let r = load_reveals(&f).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].address, [0u8; 32]);
        std::fs::write(&f, "abc 111 def\n").unwrap();
        assert!(load_reveals(&f).unwrap_err().starts_with("line 1"));
    }

    #[test]
    fn zcash_reveals_parse_and_commit() {
        let dir = std::env::temp_dir().join(format!("zyn-zreveals-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("reveals");
        // A testnet P2PKH for hash 0x07..07, as in zyn-custody's parser test.
        let addr = zyn_custody::solana::base58_encode(&{
            use sha2::Digest;
            let body = [&[0x1Du8, 0x25][..], &[7u8; 20][..]].concat();
            let chk = sha2::Sha256::digest(sha2::Sha256::digest(&body));
            [&body[..], &chk[..4]].concat()
        });
        std::fs::write(
            &f,
            format!("{} {} {}\n", "ab".repeat(32), addr, "cd".repeat(32)),
        )
        .unwrap();
        let r = load_zcash_reveals(&f, Network::TestNetwork).unwrap();
        assert_eq!(
            r[0].address,
            ZcashDestination::Transparent(TransparentAddress::PublicKeyHash([7u8; 20]))
        );
        assert_ne!(
            zcash_commitment(&r[0].address, &r[0].salt),
            zcash_commitment(
                &ZcashDestination::Transparent(TransparentAddress::ScriptHash([7u8; 20])),
                &r[0].salt
            ),
            "P2PKH and P2SH of the same hash must not share a commitment"
        );
        // A unified address with an Orchard receiver parses to a shielded one.
        let ua = "utest1h6sfz7alnztp0vst6u0s8sxj9zhzrv5s7qjy5897qcdse75epp43x4uus90naxaea973q22nshuggyywujdj5zulckj2vppz85x2t407";
        assert!(matches!(
            parse_destination(ua, Network::TestNetwork),
            Some(ZcashDestination::Shielded(_))
        ));
        assert_eq!(parse_destination(ua, Network::MainNetwork), None);
        assert!(
            load_zcash_reveals(&f, Network::MainNetwork).is_err(),
            "a testnet address on mainnet"
        );
    }
}
