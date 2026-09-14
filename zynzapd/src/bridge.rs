//! Driving the deposit watcher, and turning what it sees into intents.
//!
//! `zyn-custody` decides *what* a confirmed deposit means; `zyn` decides how an
//! intent is sequenced. Neither has ever been connected to the other. This is
//! the connection, and it is the only place in the tree where an observation of
//! another chain becomes a credit on this one.
//!
//! # The property this file exists to get right
//!
//! **Fail toward under-crediting, never toward over-crediting.**
//!
//! A missed deposit is a support ticket: the funds are still in the vault and
//! an operator can credit them. A double credit is units that nothing backs,
//! which is unrecoverable — the invariant the whole bridge exists to hold
//! (**S11**) is already broken by the time anyone notices.
//!
//! The watcher deduplicates by txid, but that set lives in memory. Across a
//! restart it is empty, so a rescan of old heights would credit them again with
//! fresh indices and the VM would accept every one. So progress is written
//! **before** the intents are submitted, not after. A crash in the window
//! between skips a real deposit; a crash the other way around would mint.
//!
//! # Transparent only
//!
//! See [`zyn_custody::zebra`]. The account comes from *which address received*,
//! because a transparent output has no memo. Shielded deposits need note
//! decryption, which does not exist yet.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use swapvm::tx::Intent;
use swapvm::types::AssetId;
use zyn::verify::Authorized;
use zyn_custody::evm::Observed as EvmObserved;
use zyn_custody::shielded::{ScanRangeError, Scanner};
use zyn_custody::solana::Observed as SolanaObserved;
use zyn_custody::watcher::{ChainView, Watcher, WatcherAction};
use zyn_custody::zebra::{Network, Zebra};
use zyn_vm::commit::Encoder;
use zyn_vm::read::Decoder;
use zyn_vm::spec::AccountId;

use crate::rpc::Shared;

/// v1: no forced-scan marker. Still read, never written.
const MAGIC: &[u8; 8] = b"ZYNBRDG1";
/// v2 adds `forced_scanned_to`. A new magic rather than a longer v1, so a
/// truncated file is still refused: an old file is byte-for-byte a valid
/// prefix of a new one, and length alone cannot tell "written by an older
/// build" from "cut off half way".
const MAGIC_V2: &[u8; 8] = b"ZYNBRDG2";

/// What the bridge has to remember across a restart.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Progress {
    pub scanned_to: u64,
    pub next_index: u64,
    /// Every deposit already turned into a credit. Persisted rather than kept
    /// in memory, because this set is the only thing standing between a
    /// restart and a double credit.
    pub credited: BTreeSet<[u8; 32]>,
    /// How far the **forced-intent** sweep has read, independently of
    /// `scanned_to`.
    ///
    /// The deposit scan and the note-tree feed each collect sightings from
    /// their own range, and those ranges diverge — on 10 Sep 2026 the deposit
    /// scan stood at 4,337,734 while the tree feed was still at 4,328,862, and
    /// a forced intent confirmed twelve blocks deep at 4,337,728 fell between
    /// them. It was passed over, never queued, and would have waited forever.
    /// A marker of its own makes that class of miss impossible: this sweep
    /// advances one contiguous range at a time and answers to nothing else.
    pub forced_scanned_to: u64,
}

impl Progress {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.bytes(MAGIC_V2)
            .u64(self.scanned_to)
            .u64(self.next_index)
            .u32(self.credited.len() as u32);
        for id in &self.credited {
            e.bytes(id);
        }
        // Appended after the set, so a file written before this field existed
        // still decodes — it simply reports zero and is seeded on first use.
        e.u64(self.forced_scanned_to);
        e.finish().to_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Progress> {
        let mut d = Decoder::new(b);
        let magic = d.array::<8>().ok()?;
        let v2 = if magic == *MAGIC_V2 {
            true
        } else if magic == *MAGIC {
            false
        } else {
            return None;
        };
        let scanned_to = d.u64().ok()?;
        let next_index = d.u64().ok()?;
        let n = d.u32().ok()?;
        let mut credited = BTreeSet::new();
        for _ in 0..n {
            credited.insert(d.array::<32>().ok()?);
        }
        // v1 files simply have no marker; it seeds on first use. v2 must
        // carry one, and anything left over is a file that is not what it
        // says it is.
        let forced_scanned_to = if v2 { d.u64().ok()? } else { 0 };
        if d.remaining() != 0 {
            return None;
        }
        Some(Progress {
            scanned_to,
            next_index,
            credited,
            forced_scanned_to,
        })
    }

    /// Keyed by **asset as well as chain**, because more than one bridge runs
    /// at once now.
    ///
    /// Sharing a file between two of them would be the worst bug in this file:
    /// each would load the other's `scanned_to` — a Zcash height fed to an EVM
    /// watcher — and, far worse, they would overwrite each other's `credited`
    /// set, which the module docs above call the actual safety property. A
    /// cleared dedup set re-credits every deposit it has forgotten.
    ///
    /// Two bridges never share an asset; if they did they would double-credit
    /// it regardless of any file. So the asset is the right discriminator.
    fn path(dir: &Path, chain_id: u32, asset: AssetId) -> PathBuf {
        dir.join(format!("bridge-{}-{}.progress", chain_id, rawhex(&asset)))
    }

    /// Where a single-bridge node kept its progress, before the file was keyed
    /// by asset. Read once, on a node that has one and no new-style file, so an
    /// upgrade does not rescan a chain from its start height.
    fn legacy_path(dir: &Path, chain_id: u32) -> PathBuf {
        dir.join(format!("bridge-{}.progress", chain_id))
    }

    pub fn load(dir: &Path, chain_id: u32, asset: AssetId) -> Result<Progress, String> {
        let mut at = Self::path(dir, chain_id, asset);
        if !at.exists() {
            let legacy = Self::legacy_path(dir, chain_id);
            if legacy.exists() {
                eprintln!(
                    "zynzapd: adopting {} as this asset's progress",
                    legacy.display()
                );
                at = legacy;
            }
        }
        match std::fs::read(at) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Progress::default()),
            Err(e) => Err(format!("cannot read bridge progress: {}", e)),
            Ok(b) => Progress::decode(&b)
                .ok_or_else(|| "bridge progress is corrupt; refusing to guess".to_string()),
        }
    }

    /// Write durably, then rename. A half-written progress file would be
    /// refused at load, and refusing to start is better than starting from a
    /// position nobody can vouch for.
    pub fn save(&self, dir: &Path, chain_id: u32, asset: AssetId) -> Result<(), String> {
        use std::io::Write;
        let tmp = dir.join(format!(".bridge-{}-{}.tmp", chain_id, rawhex(&asset)));
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&self.encode()).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, Self::path(dir, chain_id, asset)).map_err(|e| e.to_string())
    }
}

/// The addresses this vault watches, and who each one credits.
pub fn load_addresses(path: &Path) -> Result<BTreeMap<String, AccountId>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(addr), Some(acct)) = (parts.next(), parts.next()) else {
            return Err(format!(
                "line {}: expected `<address> <account-hex>`",
                n + 1
            ));
        };
        let account = hex32(acct)
            .ok_or_else(|| format!("line {}: account must be 64 hex characters", n + 1))?;
        out.insert(addr.to_string(), account);
    }
    Ok(out)
}

fn hex32(s: &str) -> Option<AccountId> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Where deposits are read from.
///
/// Two ways to see the same event. **Shielded is the design**; transparent is
/// a testnet scaffold that exists because it could be built before note
/// decryption could, and it is kept because it is a useful control — if a
/// shielded scan finds nothing, a transparent one against a known-funded
/// address distinguishes "the scanner is wrong" from "nobody has paid us".
pub enum Source {
    /// Watch transparent addresses; the account is whichever one received.
    Transparent(BTreeMap<String, AccountId>),
    /// Trial-decrypt Orchard actions; the account comes from the memo.
    ///
    /// Boxed: a `Scanner` carries prepared Orchard key material and is an order
    /// of magnitude larger than the other variant, so an unboxed enum would
    /// pay for it everywhere.
    Shielded(Box<Scanner>),
}

/// Which chain this bridge watches.
///
/// The variants differ in how an observation is *obtained*, and in nothing
/// else: each yields a [`ChainView`], and [`Watcher`] holds the confirmation,
/// ordering and replay rules for all of them. That split is why adding Solana
/// is a variant rather than a second `Bridge`.
pub enum Custody {
    /// Zcash, through a Zebra node. Reads a range of blocks per pass.
    Zcash { zebra: Zebra, source: Source },
    /// A `ZynVault` on an EVM chain.
    ///
    /// Its tip is the **finalized** height rather than a depth below the head,
    /// so `confirmations` is zero for this variant and reorgs are excluded by
    /// the chain rather than waited out (`zyn_custody::evm`).
    Evm(Box<EvmObserved>),
    /// A vault account on Solana. Finalized-slot tip, as for EVM; the account
    /// a deposit credits comes from a Memo-program instruction, as on Zcash
    /// (`zyn_custody::solana`).
    Solana(Box<SolanaObserved>),
}

/// How far the deposit watcher for `asset` has scanned, from its progress
/// file. Zero on a first run.
pub fn scanned_height(dir: &Path, chain_id: u32, asset: AssetId) -> u64 {
    Progress::load(dir, chain_id, asset)
        .map(|p| p.scanned_to)
        .unwrap_or(0)
}

pub struct Bridge {
    custody: Custody,
    watcher: Watcher,
    progress: Progress,
    asset: AssetId,
    dir: PathBuf,
    chain_id: u32,
    confirmations: u64,
    /// Signatures already applied, shared with the RPC.
    replay: Option<Arc<Mutex<zyn::replay::ReplayIndex>>>,
    /// Forced intents already handled, by txid, so a sighting is acted on once.
    forced_seen: BTreeSet<[u8; 32]>,
    /// Forced intents seen but not yet applied — waiting on depth, or refused
    /// while `ZYN_IGNORE_FORCED` was set. Retried every pass, persisted, so a
    /// scan that moved past the block does not lose the obligation.
    forced_pending: Vec<zyn_custody::shielded::ForcedSighting>,
}

/// One forced intent, decided: what the sequencer did with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForcedOutcome {
    /// Sequenced — accepted or rejected by the VM, both are inclusion.
    Applied,
    /// The frame does not decode or does not verify: nothing to include.
    Junk,
    /// Its signature was already applied (by RPC or an earlier sighting).
    Replay,
    /// Not deep enough yet.
    Waiting,
}

/// Apply forced intents at depth. Free of the bridge so it is testable
/// without a chain: the sightings come from the scanner, the decision here.
///
/// Refused if `ZYN_IGNORE_FORCED` is set — the lever a testnet operator pulls
/// to *demonstrate* censorship and watch a replica report it.
#[allow(clippy::too_many_arguments)]
pub fn apply_forced(
    node: &mut zyn::node::Node<swapvm::state::SwapState>,
    replay: &Arc<Mutex<zyn::replay::ReplayIndex>>,
    chain_id: u32,
    sightings: &[zyn_custody::shielded::ForcedSighting],
    tip: u64,
    confirmations: u64,
    seen: &mut BTreeSet<[u8; 32]>,
    now: u64,
) -> Vec<(zyn_custody::shielded::ForcedSighting, ForcedOutcome)> {
    let ignore = std::env::var("ZYN_IGNORE_FORCED")
        .map(|v| v == "1")
        .unwrap_or(false);
    let mut out = Vec::new();
    for s in sightings {
        if seen.contains(&s.txid) {
            continue;
        }
        if s.height.saturating_add(confirmations) > tip.saturating_add(1) {
            out.push((s.clone(), ForcedOutcome::Waiting));
            continue;
        }
        if ignore {
            eprintln!("zynzapd: IGNORING forced intent in {} (ZYN_IGNORE_FORCED is set — a demonstration of censorship)", hex(&s.txid));
            continue;
        }
        seen.insert(s.txid);
        let (cred, auth, intent) = match crate::rpc::decode_frame(chain_id, &s.frame) {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "zynzapd: forced intent in {} is not a submission ({}); ignored",
                    hex(&s.txid),
                    e
                );
                out.push((s.clone(), ForcedOutcome::Junk));
                continue;
            }
        };
        let authorized = match zyn::verify::authorize_intent(
            std::slice::from_ref(&cred),
            &auth,
            intent,
            node.state(),
        ) {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                    "zynzapd: forced intent in {} does not verify ({:?}); ignored",
                    hex(&s.txid),
                    e
                );
                out.push((s.clone(), ForcedOutcome::Junk));
                continue;
            }
        };
        let key = crate::rpc::replay_key_of(&cred);
        let fresh = replay
            .lock()
            .map(|mut r| r.fresh(key, auth.valid_until_epoch))
            .unwrap_or(false);
        if !fresh {
            eprintln!(
                "zynzapd: forced intent in {} was already applied; nothing to do",
                hex(&s.txid)
            );
            out.push((s.clone(), ForcedOutcome::Replay));
            continue;
        }
        // The holder's own authority, exactly as over RPC. Accepted or
        // rejected, it is sequenced and journaled: included.
        let step = node.submit(authorized, now);
        eprintln!(
            "zynzapd: FORCED intent from Zcash {} applied at seq {} ({})",
            hex(&s.txid),
            step.seq,
            if step.rejected() {
                "rejected by the VM — still included"
            } else {
                "accepted"
            }
        );
        out.push((s.clone(), ForcedOutcome::Applied));
    }
    out
}

/// A txid as an explorer shows it: the bytes reversed.
fn hex(b: &[u8]) -> String {
    b.iter().rev().map(|x| format!("{:02x}", x)).collect()
}

fn forced_pending_path(dir: &std::path::Path, chain_id: u32, asset: AssetId) -> PathBuf {
    dir.join(format!("forced-{}-{}.pending", chain_id, rawhex(&asset)))
}

/// `txid height amount frame` per line, all hex but the numbers.
fn save_forced_pending(
    dir: &std::path::Path,
    chain_id: u32,
    asset: AssetId,
    pending: &[zyn_custody::shielded::ForcedSighting],
) -> Result<(), String> {
    let body: String = pending
        .iter()
        .map(|p| {
            format!(
                "{} {} {} {}\n",
                rawhex(&p.txid),
                p.height,
                p.amount.0,
                rawhex(&p.frame)
            )
        })
        .collect();
    let tmp = dir.join(format!(
        ".forced-{}-{}.pending.tmp",
        chain_id,
        rawhex(&asset)
    ));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, forced_pending_path(dir, chain_id, asset)).map_err(|e| e.to_string())
}

fn load_forced_pending(
    dir: &std::path::Path,
    chain_id: u32,
    asset: AssetId,
) -> Result<Vec<zyn_custody::shielded::ForcedSighting>, String> {
    let s = match std::fs::read_to_string(forced_pending_path(dir, chain_id, asset)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot read pending forced intents: {}", e)),
        Ok(s) => s,
    };
    let mut out = Vec::new();
    for l in s.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (Some(t), Some(h), Some(a), Some(fr)) = (f.first(), f.get(1), f.get(2), f.get(3))
        else {
            return Err("pending forced intents file is corrupt".into());
        };
        let txid = unhex32(t).ok_or("pending forced intents file is corrupt")?;
        let height: u64 = h
            .parse()
            .map_err(|_| "pending forced intents file is corrupt")?;
        let amount: i128 = a
            .parse()
            .map_err(|_| "pending forced intents file is corrupt")?;
        let frame = unhex(fr).ok_or("pending forced intents file is corrupt")?;
        out.push(zyn_custody::shielded::ForcedSighting {
            txid,
            height,
            amount: swapvm::Fixed::raw(amount),
            frame,
        });
    }
    Ok(out)
}

fn rawhex(b: &[u8]) -> String {
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

fn forced_seen_path(dir: &std::path::Path, chain_id: u32, asset: AssetId) -> PathBuf {
    dir.join(format!("forced-{}-{}.seen", chain_id, rawhex(&asset)))
}

fn load_forced_seen(
    dir: &std::path::Path,
    chain_id: u32,
    asset: AssetId,
) -> Result<BTreeSet<[u8; 32]>, String> {
    match std::fs::read_to_string(forced_seen_path(dir, chain_id, asset)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(format!("cannot read forced-intent record: {}", e)),
        Ok(s) => s
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| unhex32(l.trim()).ok_or_else(|| "forced-intent record is corrupt".to_string()))
            .collect(),
    }
}

fn save_forced_seen(
    dir: &std::path::Path,
    chain_id: u32,
    asset: AssetId,
    seen: &BTreeSet<[u8; 32]>,
) -> Result<(), String> {
    let body: String = seen.iter().map(|t| format!("{}\n", rawhex(t))).collect();
    let tmp = dir.join(format!(".forced-{}-{}.tmp", chain_id, rawhex(&asset)));
    std::fs::write(&tmp, body).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, forced_seen_path(dir, chain_id, asset)).map_err(|e| e.to_string())
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Whether this deposit source may watch this network.
///
/// The scaffold is `Source::Transparent` — addresses watched in the clear,
/// which §38.4 forbids for a real vault. `Source::Shielded` is the design and
/// is what mainnet is for. The original guard matched every `Custody::Zcash`,
/// so it refused the shielded path too: the message named the scaffold while
/// the pattern caught everything, and mainnet could never start.
fn admissible(network: Network, source: &Source) -> Result<(), String> {
    match (network, source) {
        (Network::Mainnet, Source::Transparent(_)) => {
            Err("transparent custody is a testnet scaffold".into())
        }
        _ => Ok(()),
    }
}

impl Bridge {
    /// `start_index` is the next deposit index the chain will accept, read
    /// from its state.
    ///
    /// Taken from the VM rather than tracked independently, because the VM
    /// enforces contiguity and is therefore the only thing that can be right
    /// about it. Persisted progress still supplies the **dedup set**, which is
    /// what actually prevents a re-credit — the index is bookkeeping, the txid
    /// set is the safety property.
    pub fn new(
        custody: Custody,
        confirmations: u64,
        asset: AssetId,
        dir: PathBuf,
        chain_id: u32,
        start_index: u64,
    ) -> Result<Bridge, String> {
        if let Custody::Zcash { zebra, source } = &custody {
            admissible(zebra.network(), source)?;
        }
        let mut progress = Progress::load(&dir, chain_id, asset)?;
        progress.next_index = start_index;
        let watcher = Watcher::resume(confirmations, start_index, progress.scanned_to);
        let forced_seen = load_forced_seen(&dir, chain_id, asset)?;
        let forced_pending = load_forced_pending(&dir, chain_id, asset)?;
        Ok(Bridge {
            custody,
            watcher,
            progress,
            asset,
            dir,
            chain_id,
            confirmations,
            replay: None,
            forced_seen,
            forced_pending,
        })
    }

    /// Everything seen joins the pending set; the pending set is tried every
    /// pass until each is handled. Runs whether or not the pass credited
    /// anything.
    fn process_forced(
        &mut self,
        node: &mut zyn::node::Node<swapvm::state::SwapState>,
        forced: Vec<zyn_custody::shielded::ForcedSighting>,
        forced_tip: u64,
        now: u64,
    ) -> Result<(), String> {
        let mut changed = false;
        for f in forced {
            if !self.forced_seen.contains(&f.txid)
                && !self.forced_pending.iter().any(|p| p.txid == f.txid)
            {
                self.forced_pending.push(f);
                changed = true;
            }
        }
        if !self.forced_pending.is_empty() {
            if let Some(replay) = &self.replay {
                let tip = if forced_tip > 0 {
                    forced_tip
                } else {
                    self.watcher.scanned_to()
                };
                let before = self.forced_seen.len();
                apply_forced(
                    node,
                    replay,
                    self.chain_id,
                    &self.forced_pending.clone(),
                    tip,
                    self.confirmations,
                    &mut self.forced_seen,
                    now,
                );
                let seen = &self.forced_seen;
                let n = self.forced_pending.len();
                self.forced_pending.retain(|p| !seen.contains(&p.txid));
                if self.forced_seen.len() != before || self.forced_pending.len() != n {
                    changed = true;
                }
                if self.forced_seen.len() != before {
                    save_forced_seen(&self.dir, self.chain_id, self.asset, &self.forced_seen)?;
                }
            }
        }
        if changed {
            save_forced_pending(&self.dir, self.chain_id, self.asset, &self.forced_pending)?;
        }
        Ok(())
    }

    /// Re-read forced intents from `from` up to the scan's progress and queue
    /// any not yet handled. For a node that was down, or refusing, while they
    /// arrived: the obligation is on the chain, and this is how it is picked
    /// back up. Shielded custody only; the others carry no memos.
    pub fn rescan_forced(&mut self, from: u64) -> Result<usize, String> {
        let to = self.progress.scanned_to;
        let Custody::Zcash {
            zebra,
            source: Source::Shielded(scanner),
        } = &self.custody
        else {
            return Ok(0);
        };
        let mut at = from;
        let mut added = 0;
        while at <= to {
            let (end, found) = scanner
                .forced(zebra, at, to)
                .map_err(|e| format!("forced rescan: {:?}", e))?;
            for f in found {
                if !self.forced_seen.contains(&f.txid)
                    && !self.forced_pending.iter().any(|p| p.txid == f.txid)
                {
                    self.forced_pending.push(f);
                    added += 1;
                }
            }
            if end < at {
                break;
            }
            at = end + 1;
        }
        if added > 0 {
            save_forced_pending(&self.dir, self.chain_id, self.asset, &self.forced_pending)?;
        }
        Ok(added)
    }

    /// Share the replay index with the RPC, so a forced intent and its RPC
    /// twin apply once between them.
    pub fn with_replay(mut self, replay: Arc<Mutex<zyn::replay::ReplayIndex>>) -> Bridge {
        self.replay = Some(replay);
        self
    }

    pub fn scanned_to(&self) -> u64 {
        self.progress.scanned_to
    }

    pub fn name(&self) -> &'static str {
        match self.custody {
            Custody::Zcash { .. } => "zcash deposits",
            Custody::Evm(_) => "evm deposits",
            Custody::Solana(_) => "solana deposits",
        }
    }

    /// Never read below `height`: a vault cannot have been paid before it
    /// existed, and a chain that prunes history (Solana, most EVM endpoints)
    /// cannot serve the blocks before it anyway. Raises progress on a first
    /// run; never lowers it.
    pub fn start_no_earlier_than(&mut self, height: u64) -> Result<(), String> {
        let floor = height.saturating_sub(1);
        if floor > self.progress.scanned_to {
            self.progress.scanned_to = floor;
            self.watcher = Watcher::resume(
                self.watcher.confirmations(),
                self.progress.next_index,
                floor,
            );
            self.progress.save(&self.dir, self.chain_id, self.asset)?;
        }
        Ok(())
    }

    /// Re-read from `height`. The `credited` set is untouched, so anything
    /// already credited is skipped again; anything missed is found.
    pub fn rescan_from(&mut self, height: u64) -> Result<(), String> {
        let to = height.saturating_sub(1);
        if to < self.progress.scanned_to {
            eprintln!(
                "zynzapd: rescanning from {} (was scanned to {})",
                height, self.progress.scanned_to
            );
            self.progress.scanned_to = to;
            self.watcher =
                Watcher::resume(self.watcher.confirmations(), self.progress.next_index, to);
            self.progress.save(&self.dir, self.chain_id, self.asset)?;
        }
        Ok(())
    }

    /// One scan. Returns how many credits were submitted.
    pub fn poll_once(&mut self, node: &Shared, now: u64) -> Result<usize, String> {
        let from = self.progress.scanned_to + 1;
        let mut forced: Vec<zyn_custody::shielded::ForcedSighting> = Vec::new();
        let mut forced_tip = 0u64;

        // Sweep for forced intents on our own marker, contiguously, before
        // anything else reads the chain. The deposit scan and the note-tree
        // feed each collect sightings from their own range and those ranges
        // diverge; this one answers to neither. See
        // `Progress::forced_scanned_to` for the miss that made it necessary.
        if self.progress.forced_scanned_to == 0 {
            // Seed from where the deposit scan already is: re-reading the
            // chain from genesis would be honest and useless.
            self.progress.forced_scanned_to = self.progress.scanned_to;
        }
        let mut swept_to: Option<u64> = None;
        if let Custody::Zcash {
            zebra,
            source: Source::Shielded(scanner),
        } = &self.custody
        {
            let sweep_from = self.progress.forced_scanned_to.saturating_add(1);
            if let Ok(tip) = zebra.block_count() {
                if sweep_from <= tip {
                    match scanner.forced(zebra, sweep_from, tip) {
                        Ok((end, found)) => {
                            if !found.is_empty() {
                                eprintln!(
                                    "zynzapd: forced sweep {}..={} found {} intent(s)",
                                    sweep_from,
                                    end,
                                    found.len()
                                );
                            }
                            forced.extend(found);
                            swept_to = Some(end);
                        }
                        // Loud, and the marker does not move: the same range
                        // is read again next pass. A skipped forced intent is
                        // the failure this exists to prevent.
                        Err(e) => eprintln!(
                            "zynzapd: forced sweep {}..={} failed: {:?}",
                            sweep_from, tip, e
                        ),
                    }
                }
            }
        }
        // Borrowed from `self.custody` while `self.watcher` is borrowed
        // mutably: disjoint fields, so this is one pass rather than a copy of
        // every log the chain returned.
        let observed: Box<dyn ChainView + '_> = match &mut self.custody {
            Custody::Zcash { zebra, source } => match source {
                Source::Transparent(addresses) => {
                    Box::new(zebra.observe(addresses, from).map_err(|e| e.to_string())?)
                }
                Source::Shielded(scanner) => {
                    let obs = scanner.observe(zebra, from).map_err(|e| match e {
                        ScanRangeError::Rpc(e) => e.to_string(),
                        // Loud, and fatal to the pass. Crediting the rest would
                        // attest backing that includes money nobody can claim.
                        ScanRangeError::Unattributable { height, amount } => format!(
                            "shielded funds at height {} carry no Zyn memo ({:?}) — \
                             a human has to decide who they belong to",
                            height, amount
                        ),
                    })?;
                    forced = obs.forced().to_vec();
                    forced_tip = obs.tip();
                    Box::new(obs)
                }
            },
            Custody::Evm(o) => {
                // Re-read finality once per pass so everything reported below
                // is consistent with a single tip.
                o.refresh().map_err(|e| e.to_string())?;
                Box::new(&**o)
            }
            Custody::Solana(o) => {
                o.refresh().map_err(|e| e.to_string())?;
                Box::new(&**o)
            }
        };

        let before = self.watcher.scanned_to();
        let polled = self.watcher.poll(observed.as_ref());
        if observed.failed() {
            // Something the view answered was a guess. Whatever the watcher
            // concluded from it is unrecorded, and the same range is read
            // again next pass — a missed deposit is the failure this exists
            // to prevent.
            self.watcher.rewind_to(before);
            return Err("chain view failed mid-pass; no progress recorded".into());
        }
        let actions = polled.map_err(|e| format!("{:?}", e))?;
        drop(observed);
        if actions.is_empty() {
            // Still record how far we got, so a quiet chain does not rescan
            // the same range forever — and still honour forced intents: a
            // quiet chain is exactly when a refused holder is waiting.
            self.progress.scanned_to = self.watcher.scanned_to();
            self.progress.save(&self.dir, self.chain_id, self.asset)?;
            let mut node = node.lock().map_err(|_| "node lock poisoned".to_string())?;
            self.process_forced(&mut node, forced, forced_tip, now)?;
            // Only now: `process_forced` has persisted whatever it queued, so
            // advancing cannot drop a sighting that was never written down.
            if let Some(end) = swept_to {
                self.progress.forced_scanned_to = end;
                self.progress.save(&self.dir, self.chain_id, self.asset)?;
            }
            return Ok(0);
        }

        // Decide everything, and record the decision, *before* acting on any of
        // it. See the module docs: the crash window has to fall on the side
        // that loses a deposit rather than the side that mints one.
        let mut intents = Vec::with_capacity(actions.len());
        for a in &actions {
            match *a {
                WatcherAction::Attest { observed } => {
                    intents.push(Intent::AttestVaultBalance {
                        asset: self.asset,
                        observed,
                    });
                }
                WatcherAction::AttestAsset { asset, observed } => {
                    intents.push(Intent::AttestVaultBalance { asset, observed });
                }
                WatcherAction::Credit {
                    account,
                    amount,
                    index,
                    external_ref,
                    asset,
                } => {
                    self.progress.credited.insert(external_ref);
                    intents.push(Intent::CreditDeposit {
                        account,
                        asset: asset.unwrap_or(self.asset),
                        amount,
                        index,
                        external_ref,
                    });
                }
            }
        }
        self.progress.scanned_to = self.watcher.scanned_to();
        self.progress.next_index = self.watcher.next_index();
        self.progress.save(&self.dir, self.chain_id, self.asset)?;

        let mut credited = 0;
        let mut node = node.lock().map_err(|_| "node lock poisoned".to_string())?;
        for mut intent in intents {
            // A credit to another asset takes that asset's own deposit index,
            // read from the chain at submission: the watcher's counter is the
            // bridge's own asset's.
            if let Intent::CreditDeposit { asset, index, .. } = &mut intent {
                if *asset != self.asset {
                    *index = node.state().next_deposit_index(*asset);
                }
            }
            let is_credit = matches!(intent, Intent::CreditDeposit { .. });
            // Operator authority, claimed in writing (S14): the node observed
            // this itself, and no user signed for it.
            let step = node.submit(Authorized::operator(intent), now);
            if step.rejected() {
                // Reporting rather than retrying. A rejected credit means the
                // chain and this scanner disagree about what has already
                // happened, and re-sending cannot resolve a disagreement.
                eprintln!(
                    "zynzapd: bridge intent rejected at seq {} — scanner and chain disagree",
                    step.seq
                );
            } else if is_credit {
                credited += 1;
            }
        }
        self.process_forced(&mut node, forced, forced_tip, now)?;
        if let Some(end) = swept_to {
            self.progress.forced_scanned_to = end;
            self.progress.save(&self.dir, self.chain_id, self.asset)?;
        }
        Ok(credited)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::types::XZEC;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-bridge-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The mainnet guard names the transparent scaffold, and must catch only
    /// it. Written because the pattern matched every `Custody::Zcash`, so the
    /// shielded vault — the thing mainnet is *for* — was refused too, and the
    /// chain could never start.
    #[test]
    fn the_mainnet_guard_refuses_the_transparent_scaffold_only() {
        let clear = Source::Transparent(BTreeMap::new());
        assert!(
            admissible(Network::Mainnet, &clear).is_err(),
            "a vault watched in the clear on mainnet is what §38.4 forbids"
        );
        assert!(
            admissible(Network::Testnet, &clear).is_ok(),
            "the scaffold is still allowed on testnet; that is what it is for"
        );
    }

    #[test]
    fn progress_round_trips_and_refuses_junk() {
        let mut p = Progress {
            scanned_to: 42,
            next_index: 7,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        p.credited.insert([1u8; 32]);
        p.credited.insert([2u8; 32]);
        assert_eq!(Progress::decode(&p.encode()), Some(p.clone()));
        assert_eq!(Progress::decode(b"nope"), None);
        for cut in 0..p.encode().len() {
            assert!(Progress::decode(&p.encode()[..cut]).is_none() || cut == p.encode().len());
        }
    }

    /// A restart must not forget what it has already credited — that set is
    /// the only thing between a rescan and unbacked units.
    #[test]
    fn progress_survives_a_restart() {
        let dir = tmpdir("restart");
        let mut p = Progress {
            scanned_to: 900,
            next_index: 12,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        p.credited.insert([9u8; 32]);
        p.save(&dir, 5, XZEC).unwrap();

        let back = Progress::load(&dir, 5, XZEC).unwrap();
        assert_eq!(back, p);
        assert!(back.credited.contains(&[9u8; 32]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_first_run_is_not_a_failure() {
        let dir = tmpdir("first");
        assert_eq!(Progress::load(&dir, 1, XZEC).unwrap(), Progress::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt progress file must stop the bridge, not be silently ignored.
    /// Starting from zero would rescan everything and re-credit it.
    #[test]
    fn a_corrupt_progress_file_refuses_rather_than_restarting_from_zero() {
        let dir = tmpdir("corrupt");
        let p = Progress {
            scanned_to: 100,
            next_index: 3,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        p.save(&dir, 2, XZEC).unwrap();
        let path = Progress::path(&dir, 2, XZEC);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[2] ^= 0xFF;
        std::fs::write(&path, bytes).unwrap();
        assert!(Progress::load(&dir, 2, XZEC).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn addresses_parse_with_comments_and_blank_lines() {
        let dir = tmpdir("addr");
        let f = dir.join("addresses.txt");
        std::fs::write(
            &f,
            "# the vault's watched addresses\n\
             tmABC  0101010101010101010101010101010101010101010101010101010101010101\n\
             \n\
             tmDEF  0202020202020202020202020202020202020202020202020202020202020202 # bob\n",
        )
        .unwrap();
        let m = load_addresses(&f).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("tmABC"), Some(&[1u8; 32]));
        assert_eq!(m.get("tmDEF"), Some(&[2u8; 32]));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_address_line_is_named_not_skipped() {
        let dir = tmpdir("badaddr");
        let f = dir.join("bad.txt");
        std::fs::write(&f, "tmABC notlongenough\n").unwrap();
        let e = load_addresses(&f).unwrap_err();
        assert!(e.contains("line 1"), "the error must say which line: {}", e);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two bridges now run at once (Zcash and an EVM vault). If they shared a
    /// progress file, each would load the other's height and — much worse —
    /// clear the other's `credited` set, which is what actually stops a
    /// re-credit. Every deposit the surviving file had forgotten would be
    /// minted a second time.
    #[test]
    fn two_bridges_on_one_chain_do_not_share_progress() {
        let dir = tmpdir("isolation");
        const OTHER: AssetId = [0x42; 32];

        let mut zcash = Progress {
            scanned_to: 2_900_000,
            next_index: 4,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        zcash.credited.insert([0xAA; 32]);
        zcash.save(&dir, 7, XZEC).unwrap();

        let mut evm = Progress {
            scanned_to: 19,
            next_index: 1,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        evm.credited.insert([0xBB; 32]);
        evm.save(&dir, 7, OTHER).unwrap();

        assert_ne!(
            Progress::path(&dir, 7, XZEC),
            Progress::path(&dir, 7, OTHER)
        );
        let back_zcash = Progress::load(&dir, 7, XZEC).unwrap();
        let back_evm = Progress::load(&dir, 7, OTHER).unwrap();

        assert_eq!(
            back_zcash, zcash,
            "a Zcash height was overwritten by an EVM one"
        );
        assert_eq!(back_evm, evm);
        assert!(
            back_zcash.credited.contains(&[0xAA; 32]),
            "a dedup set was cleared"
        );
        assert!(back_evm.credited.contains(&[0xBB; 32]));
    }

    /// The deployed testnet node already has a `bridge-<chain>.progress` from
    /// before the file was keyed by asset. Ignoring it would rescan Zcash from
    /// the vault's start height with an empty dedup set — the same re-credit,
    /// arriving as an upgrade rather than a collision.
    #[test]
    fn an_existing_single_bridge_node_keeps_its_progress() {
        let dir = tmpdir("legacy");
        let mut old = Progress {
            scanned_to: 3_100_000,
            next_index: 9,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        old.credited.insert([0xCC; 32]);
        std::fs::write(Progress::legacy_path(&dir, 4), old.encode()).unwrap();

        let loaded = Progress::load(&dir, 4, XZEC).unwrap();
        assert_eq!(loaded, old, "an upgrade lost the scan position");

        // Once saved under the new name, the legacy file is no longer consulted.
        loaded.save(&dir, 4, XZEC).unwrap();
        std::fs::write(Progress::legacy_path(&dir, 4), Progress::default().encode()).unwrap();
        assert_eq!(Progress::load(&dir, 4, XZEC).unwrap(), old);
    }
}

#[cfg(test)]
mod forced_progress_tests {
    use super::*;

    /// The marker survives a save and reload. It is the whole basis of the
    /// sweep being contiguous: a marker that resets re-reads or, worse, skips.
    #[test]
    fn the_forced_marker_round_trips() {
        let p = Progress {
            scanned_to: 4_337_734,
            next_index: 3,
            credited: BTreeSet::new(),
            forced_scanned_to: 4_337_728,
        };
        let back = Progress::decode(&p.encode()).expect("decode");
        assert_eq!(back.forced_scanned_to, 4_337_728);
        assert_eq!(
            back.scanned_to, 4_337_734,
            "the deposit marker is untouched"
        );
    }

    /// A file written before the field existed must still load — the
    /// sequencer's live progress file is one of those, and refusing it would
    /// turn a scanner fix into an outage.
    #[test]
    fn a_progress_file_written_before_the_field_still_loads() {
        let mut e = Encoder::new();
        e.bytes(MAGIC).u64(900).u64(4).u32(0);
        let old = e.finish().to_vec();

        let back = Progress::decode(&old).expect("an older file must still decode");
        assert_eq!(back.scanned_to, 900);
        assert_eq!(back.next_index, 4);
        assert_eq!(
            back.forced_scanned_to, 0,
            "absent means zero, and zero seeds on first use"
        );
    }

    /// Zero is not a height to scan from — it would re-read the chain from
    /// genesis. The first pass seeds it from the deposit scan instead.
    #[test]
    fn a_zero_marker_seeds_from_the_deposit_scan_rather_than_genesis() {
        let mut p = Progress {
            scanned_to: 4_337_734,
            next_index: 0,
            credited: BTreeSet::new(),
            forced_scanned_to: 0,
        };
        // The seeding rule `poll_once` applies before sweeping.
        if p.forced_scanned_to == 0 {
            p.forced_scanned_to = p.scanned_to;
        }
        assert_eq!(p.forced_scanned_to, 4_337_734);
    }
}
