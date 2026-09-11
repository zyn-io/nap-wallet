//! Data availability that outlives the sequencer.
//!
//! For every anchor the chain has, one immutable bundle: the anchor, its
//! certificate, the published leaves, and the intents of the epochs it
//! covers. Written locally, then pushed to any number of mirrors. Nothing in a
//! bundle is trusted for being served — every file is checkable against the
//! anchor id read off Zcash — so a mirror can only fail, never lie, and the
//! cheapest hosting that answers `GET` will do.
//!
//! A mirror outage never holds an anchor back. Finality comes from Zcash; the
//! bundle is what lets others *verify* it, and the publisher retries until
//! every mirror has every file.
//!
//! ```text
//!   chain-<id>/<epoch>/anchor.bin
//!   chain-<id>/<epoch>/certificate.bin
//!   chain-<id>/<epoch>/published.bin
//!   chain-<id>/<epoch>/intents/epoch-<M>.intents
//!   chain-<id>/index            epoch root anchor_id txid height
//! ```

use std::fs;
use std::path::Path;

use zyn::anchor::{Anchor, Certificate};
use zyn::da::Published;

/// Everything a verifier needs for one anchored epoch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Bundle {
    pub anchor: Anchor,
    pub certificate: Certificate,
    pub published: Published,
    /// `(epoch, raw journal file)` for every epoch the anchor covers.
    pub intents: Vec<(u64, Vec<u8>)>,
    pub txid: String,
    pub height: u64,
}

pub fn rel_dir(chain_id: u32, epoch: u64) -> String {
    format!("chain-{}/{}", chain_id, epoch)
}

pub fn index_rel(chain_id: u32) -> String {
    format!("chain-{}/index", chain_id)
}

/// The files of a bundle, as `(relative path, bytes)`.
pub fn files(chain_id: u32, b: &Bundle) -> Vec<(String, Vec<u8>)> {
    let d = rel_dir(chain_id, b.anchor.checkpoint.epoch);
    let mut out = vec![
        (format!("{}/anchor.bin", d), b.anchor.encode()),
        (format!("{}/certificate.bin", d), b.certificate.encode()),
        (format!("{}/published.bin", d), b.published.encode()),
    ];
    for (epoch, bytes) in &b.intents {
        out.push((format!("{}/intents/epoch-{}.intents", d, epoch), bytes.clone()));
    }
    out
}

pub fn index_line(b: &Bundle) -> String {
    format!("{} {} {} {} {}\n", b.anchor.checkpoint.epoch, hex(&b.anchor.checkpoint.state_root), hex(&b.anchor.id()), b.txid, b.height)
}

/// One parsed index line.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IndexEntry {
    pub epoch: u64,
    pub root: [u8; 32],
    pub anchor_id: [u8; 32],
    pub txid: String,
    pub height: u64,
}

pub fn parse_index(s: &str) -> Vec<IndexEntry> {
    s.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            Some(IndexEntry {
                epoch: f.next()?.parse().ok()?,
                root: unhex(f.next()?)?.try_into().ok()?,
                anchor_id: unhex(f.next()?)?.try_into().ok()?,
                txid: f.next()?.to_string(),
                height: f.next()?.parse().ok()?,
            })
        })
        .collect()
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("no parent directory")?;
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!(".{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Write the bundle under `root`, append its index line (once), and return
/// the files so a publisher can push them.
pub fn write_local(root: &Path, chain_id: u32, b: &Bundle) -> Result<Vec<(String, Vec<u8>)>, String> {
    let fs_ = files(chain_id, b);
    for (rel, bytes) in &fs_ {
        write_atomic(&root.join(rel), bytes)?;
    }
    let index = root.join(index_rel(chain_id));
    let existing = fs::read_to_string(&index).unwrap_or_default();
    let mut out = fs_;
    let updated = index_with(&existing, b);
    if updated != existing {
        write_atomic(&index, updated.as_bytes())?;
    }
    out.push((index_rel(chain_id), fs::read(&index).map_err(|e| e.to_string())?));
    Ok(out)
}

/// The index after this bundle is folded into it.
///
/// An anchor is written twice: once at broadcast, where its height is not yet
/// known and goes in as 0, and again on settle carrying the height it
/// confirmed at. The second write has to **replace** the first. Appending only
/// when the epoch is absent — which is what this did — leaves every confirmed
/// anchor published as height 0 forever, so a reader checking the chain sees
/// settlement that looks never to have landed.
///
/// A height already recorded is never overwritten, and a settled entry is
/// never walked back to 0 by a late re-broadcast.
fn index_with(existing: &str, b: &Bundle) -> String {
    let epoch = b.anchor.checkpoint.epoch;
    let fresh = index_line(b);
    let fresh = fresh.trim_end();
    let mut lines: Vec<&str> = Vec::new();
    let mut seen = false;
    for l in existing.lines() {
        if l.split_whitespace().next().and_then(|f| f.parse::<u64>().ok()) != Some(epoch) {
            lines.push(l);
            continue;
        }
        seen = true;
        let mut f = l.split_whitespace().skip(3);
        let known_txid = f.next().unwrap_or("");
        let known_height: u64 = f.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        // Replace when the new entry knows something the old one does not: a
        // height where it had none, or a *different transaction*. The second
        // case is the one that bit us — an anchor whose first transaction
        // expired keeps the dead txid here forever, and the index stops being
        // evidence that the transaction it names ever settled (§50.3).
        let learns_height = known_height == 0 && b.height > 0;
        let new_transaction = !b.txid.is_empty() && known_txid != b.txid;
        lines.push(if learns_height || new_transaction { fresh } else { l });
    }
    if !seen {
        lines.push(fresh);
    }
    if lines.is_empty() { String::new() } else { format!("{}\n", lines.join("\n")) }
}

/// Read a bundle back from disk, as a replica does from its own copy.
pub fn read_local(root: &Path, chain_id: u32, epoch: u64) -> Result<Bundle, String> {
    let d = root.join(rel_dir(chain_id, epoch));
    let rd = |name: &str| fs::read(d.join(name)).map_err(|e| format!("{}: {}", name, e));
    let anchor = Anchor::decode(&rd("anchor.bin")?).ok_or("anchor.bin does not decode")?;
    let certificate = Certificate::decode(&rd("certificate.bin")?).ok_or("certificate.bin does not decode")?;
    let published = Published::decode(&rd("published.bin")?).ok_or("published.bin does not decode")?;
    let mut intents = Vec::new();
    if let Ok(entries) = fs::read_dir(d.join("intents")) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(num) = name.strip_prefix("epoch-").and_then(|n| n.strip_suffix(".intents")) {
                if let Ok(m) = num.parse::<u64>() {
                    intents.push((m, fs::read(e.path()).map_err(|e| e.to_string())?));
                }
            }
        }
    }
    intents.sort_by_key(|(m, _)| *m);
    let index = fs::read_to_string(root.join(index_rel(chain_id))).unwrap_or_default();
    let entry = parse_index(&index).into_iter().find(|e| e.epoch == epoch).ok_or("no index line for the epoch")?;
    Ok(Bundle { anchor, certificate, published, intents, txid: entry.txid, height: entry.height })
}

/// Assemble the bundle for an anchor the chain just confirmed, from what the
/// node holds and the journal on disk.
pub fn bundle_for(
    node: &zyn::node::Node<swapvm::state::SwapState>,
    journal_root: &Path,
    chain_id: u32,
    anchor: &Anchor,
    txid: &str,
    height: u64,
) -> Result<Bundle, String> {
    let published = node
        .publishable()
        .ok_or("the node has no published snapshot for the anchor it just confirmed")?
        .published()
        .map_err(|e| format!("snapshot is malformed: {:?}", e))?;
    if published.root != anchor.checkpoint.state_root {
        return Err("the published snapshot does not open the confirmed anchor's root".into());
    }
    let certificate = node
        .ledger()
        .certificates()
        .iter()
        .find(|c| c.anchor == anchor.id())
        .cloned()
        .unwrap_or_else(|| Certificate::new(anchor.id()));
    let last = anchor.checkpoint.epoch;
    let first = last.saturating_add(1).saturating_sub(anchor.epochs);
    let intents = zyn::journal::files_for(journal_root, chain_id, first..=last).map_err(|e| format!("journal: {}", e))?;
    all_sealed(&intents)?;
    Ok(Bundle { anchor: *anchor, certificate, published, intents, txid: txid.to_string(), height })
}

/// The bundle for an anchor the sequencer just broadcast, before it settles:
/// the anchor, the intents, and the leaves, so signers can verify and endorse
/// while the transaction confirms. Its certificate is whatever has been
/// gathered so far — empty at broadcast, filled by [`bundle_for`] on settle.
pub fn proposed_bundle(
    node: &zyn::node::Node<swapvm::state::SwapState>,
    journal_root: &Path,
    chain_id: u32,
    anchor: &Anchor,
    snapshot: &zyn::da::Snapshot<swapvm::state::SwapState>,
    txid: &str,
) -> Result<Bundle, String> {
    let published = snapshot.published().map_err(|e| format!("snapshot is malformed: {:?}", e))?;
    if published.root != anchor.checkpoint.state_root {
        return Err("the proposed snapshot does not open the anchor's root".into());
    }
    let certificate = node
        .certificate_for(anchor.id())
        .cloned()
        .unwrap_or_else(|| Certificate::new(anchor.id()));
    let last = anchor.checkpoint.epoch;
    let first = last.saturating_add(1).saturating_sub(anchor.epochs);
    let intents = zyn::journal::files_for(journal_root, chain_id, first..=last).map_err(|e| format!("journal: {}", e))?;
    all_sealed(&intents)?;
    Ok(Bundle { anchor: *anchor, certificate, published, intents, txid: txid.to_string(), height: 0 })
}

/// Every epoch an anchor covers must end with its seal.
///
/// The journal is appended to as intents are applied and flushed separately,
/// so reading it can catch an epoch mid-write: the records are there but the
/// `Checkpoint` that closes them is not yet on disk. A bundle published in
/// that state is poison — a verifier replays it, cannot reach the anchored
/// root, and halts; the anchor then never gathers signatures, so the corrected
/// bundle is never written either. That deadlock cost the live chain twenty
/// minutes on 8 Sep 2026 (epoch 2215: 62 bytes published, 96 on disk).
///
/// Refusing here costs one pass, and the next one publishes a whole bundle.
fn all_sealed(files: &[(u64, Vec<u8>)]) -> Result<(), String> {
    use zyn_vm::spec::MicrochainVm;
    for (epoch, raw) in files {
        let f = zyn::journal::read_epoch(raw).map_err(|e| format!("epoch {} is unreadable: {:?}", epoch, e))?;
        let sealed = f
            .records
            .last()
            .and_then(|(_, bytes)| {
                if f.version == 1 {
                    let mut d = zyn_vm::read::Decoder::new(bytes);
                    <swapvm::state::SwapState as MicrochainVm>::decode_intent(&mut d)
                } else {
                    zyn::verify::decode_committed_intent::<swapvm::state::SwapState>(bytes).ok()
                }
            })
            .map(|i| matches!(i, swapvm::tx::Intent::Checkpoint))
            .unwrap_or(false);
        if !sealed {
            return Err(format!(
                "epoch {} is not sealed on disk yet ({} record(s)); publishing it would be a bundle no verifier can reproduce",
                f.epoch,
                f.records.len()
            ));
        }
    }
    Ok(())
}

/// Where bundles go. `url` is a base; files are `PUT` at `url/<rel>`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mirror {
    pub url: String,
    pub token: Option<String>,
}

/// `url[|token],url[|token],…`
pub fn parse_mirrors(spec: &str) -> Vec<Mirror> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| match s.split_once('|') {
            Some((u, t)) => Mirror { url: u.trim_end_matches('/').to_string(), token: Some(t.to_string()) },
            None => Mirror { url: s.trim_end_matches('/').to_string(), token: None },
        })
        .collect()
}

/// Pushes queued files until every mirror has them.
pub struct Publisher {
    mirrors: Vec<Mirror>,
    queue: Vec<(String, Vec<u8>)>,
    agent: ureq::Agent,
    pub pushed: u64,
    pub failures: u32,
}

impl Publisher {
    pub fn new(mirrors: Vec<Mirror>) -> Publisher {
        Publisher {
            mirrors,
            queue: Vec::new(),
            agent: ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(20)).build(),
            pushed: 0,
            failures: 0,
        }
    }

    pub fn mirrors(&self) -> &[Mirror] {
        &self.mirrors
    }

    pub fn queue(&mut self, files: Vec<(String, Vec<u8>)>) {
        for f in files {
            self.queue.retain(|(rel, _)| *rel != f.0);
            self.queue.push(f);
        }
    }

    pub fn pending_len(&self) -> usize {
        self.queue.len()
    }

    fn put(&self, m: &Mirror, rel: &str, bytes: &[u8]) -> Result<(), String> {
        let mut req = self.agent.put(&format!("{}/{}", m.url, rel)).set("Content-Type", "application/octet-stream");
        if let Some(t) = &m.token {
            req = req.set("Authorization", &format!("Bearer {}", t));
        }
        match req.send_bytes(bytes) {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(code, _)) => Err(format!("{} refused {}: HTTP {}", m.url, rel, code)),
            Err(e) => Err(format!("{} unreachable: {}", m.url, e)),
        }
    }

    /// Push everything queued. A file leaves the queue only when **every**
    /// mirror has accepted it. Returns how many files were fully pushed.
    pub fn poll_once(&mut self) -> Result<usize, String> {
        if self.mirrors.is_empty() {
            let n = self.queue.len();
            self.queue.clear();
            return Ok(n);
        }
        let mut done = 0;
        let mut first_err = None;
        let mut remaining = Vec::new();
        for (rel, bytes) in std::mem::take(&mut self.queue) {
            let mut all = true;
            for m in &self.mirrors {
                if let Err(e) = self.put(m, &rel, &bytes) {
                    all = false;
                    first_err.get_or_insert(e);
                }
            }
            if all {
                done += 1;
                self.pushed += 1;
            } else {
                remaining.push((rel, bytes));
            }
        }
        self.queue = remaining;
        match first_err {
            Some(e) if !self.queue.is_empty() => {
                self.failures += 1;
                Err(format!("{} file(s) still queued: {}", self.queue.len(), e))
            }
            _ => {
                self.failures = 0;
                Ok(done)
            }
        }
    }
}

/// A static file server small enough to read in one sitting: `GET` any file
/// under the root, `PUT` any file with the token. What a mirror is.
pub mod http {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    const MAX_BODY: usize = 64 << 20;

    pub fn serve(root: PathBuf, listener: TcpListener, put_token: Option<String>) {
        let cfg = Arc::new((root, put_token));
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let cfg = Arc::clone(&cfg);
            std::thread::spawn(move || {
                let _ = handle(&cfg.0, cfg.1.as_deref(), stream);
            });
        }
    }

    fn respond(s: &mut TcpStream, code: u16, reason: &str, body: &[u8]) -> std::io::Result<()> {
        write!(s, "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", code, reason, body.len())?;
        s.write_all(body)?;
        s.flush()
    }

    /// A relative path that stays under the root: no absolute, no `..`, no empty.
    fn safe(rel: &str) -> Option<PathBuf> {
        let rel = rel.trim_start_matches('/');
        if rel.is_empty() || rel.split('/').any(|c| c.is_empty() || c == "." || c == ".." || c.starts_with('.')) {
            return None;
        }
        Some(PathBuf::from(rel))
    }

    fn handle(root: &Path, token: Option<&str>, mut s: TcpStream) -> std::io::Result<()> {
        s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
        // Read the head up to the blank line.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            let n = s.read(&mut chunk)?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
            if buf.len() > 16 << 10 {
                return respond(&mut s, 431, "Header Too Large", b"");
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut lines = head.lines();
        let request = lines.next().unwrap_or("");
        let mut parts = request.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let mut content_length = 0usize;
        let mut auth = None;
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                match k.trim().to_ascii_lowercase().as_str() {
                    "content-length" => content_length = v.trim().parse().unwrap_or(0),
                    "authorization" => auth = Some(v.trim().to_string()),
                    _ => {}
                }
            }
        }
        let Some(rel) = safe(target.split('?').next().unwrap_or("")) else {
            return respond(&mut s, 400, "Bad Request", b"path");
        };
        match method {
            "GET" | "HEAD" => match std::fs::read(root.join(&rel)) {
                Ok(b) => respond(&mut s, 200, "OK", if method == "HEAD" { &[] } else { &b }),
                Err(_) => respond(&mut s, 404, "Not Found", b""),
            },
            "PUT" => {
                let Some(t) = token else { return respond(&mut s, 405, "Method Not Allowed", b"read-only mirror") };
                if auth.as_deref() != Some(&format!("Bearer {}", t)) {
                    return respond(&mut s, 401, "Unauthorized", b"");
                }
                if content_length > MAX_BODY {
                    return respond(&mut s, 413, "Payload Too Large", b"");
                }
                let mut body = buf[head_end..].to_vec();
                while body.len() < content_length {
                    let n = s.read(&mut chunk)?;
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                if body.len() != content_length {
                    return respond(&mut s, 400, "Bad Request", b"short body");
                }
                match super::write_atomic(&root.join(&rel), &body) {
                    Ok(()) => respond(&mut s, 201, "Created", b""),
                    Err(_) => respond(&mut s, 500, "Internal Server Error", b""),
                }
            }
            _ => respond(&mut s, 405, "Method Not Allowed", b""),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use swapvm::state::SwapState;
    use swapvm::tx::Intent;
    use swapvm::types::XZEC;
    use swapvm::{Fixed, Params};
    use zyn::da::Snapshot;
    use zyn_vm::spec::MicrochainVm;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-publish-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn bundle() -> Bundle {
        let mut s = SwapState::new(4, Params::v1());
        let observed = s.backing_of(XZEC).add(Fixed::whole(10)).unwrap();
        s.apply(1, &Intent::AttestVaultBalance { asset: XZEC, observed });
        let d = Intent::next_deposit(&s, [1u8; 32], XZEC, Fixed::whole(1), [0u8; 32]);
        s.apply(2, &d);
        let r = s.apply(3, &Intent::Checkpoint);
        let cp = SwapState::sealed(&r).unwrap();
        let snap = Snapshot::at_checkpoint(&s, &cp).unwrap();
        let anchor = Anchor { checkpoint: cp, previous_root: [0u8; 32], epochs: 1, actions: 3 };
        Bundle {
            certificate: Certificate::new(anchor.id()),
            anchor,
            published: snap.published().unwrap(),
            intents: vec![(0, b"ZYNJRNL1-fake".to_vec())],
            txid: "ab".repeat(32),
            height: 4_400_000,
        }
    }

    /// An anchor is published twice: at broadcast with no height yet, and on
    /// settle with the height it confirmed at. The second write has to reach
    /// the index, or every settled anchor stays published as height 0 and the
    /// chain looks like nothing ever landed on Zcash.
    #[test]
    fn settling_backfills_the_height_a_broadcast_left_at_zero() {
        let d = tmp("backfill");
        let mut b = bundle();
        let epoch = b.anchor.checkpoint.epoch;

        b.height = 0;
        write_local(&d, 7, &b).unwrap();
        let at_broadcast = parse_index(&fs::read_to_string(d.join(index_rel(7))).unwrap());
        assert_eq!(at_broadcast.len(), 1);
        assert_eq!(at_broadcast[0].height, 0, "a broadcast has no height yet");

        b.height = 4_400_123;
        write_local(&d, 7, &b).unwrap();
        let after = parse_index(&fs::read_to_string(d.join(index_rel(7))).unwrap());
        assert_eq!(after.len(), 1, "settling replaces the entry, it does not add one");
        assert_eq!(after[0].epoch, epoch);
        assert_eq!(after[0].height, 4_400_123, "the confirmed height must reach the index");

        // A late re-broadcast must not walk a settled anchor back to 0.
        b.height = 0;
        b.txid = "ab".repeat(32);
        write_local(&d, 7, &b).unwrap();
        let last = parse_index(&fs::read_to_string(d.join(index_rel(7))).unwrap());
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].height, 4_400_123, "a settled height is never unlearned");
    }

    /// An anchor whose transaction expires is rebuilt under a new txid. The
    /// index has to follow it: left naming the abandoned transaction, it says
    /// an anchor never settled when it did — which is how epoch 4336 looked
    /// like a hole in the chain for days (§50.3).
    #[test]
    fn a_rebuilt_transaction_replaces_the_abandoned_one_in_the_index() {
        let d = tmp("rebuilt");
        let mut b = bundle();

        b.txid = "11".repeat(32);
        b.height = 0;
        write_local(&d, 9, &b).unwrap();
        let first = parse_index(&fs::read_to_string(d.join(index_rel(9))).unwrap());
        assert_eq!(first[0].txid, "11".repeat(32));

        // Expired, rebuilt, and this one confirmed.
        b.txid = "22".repeat(32);
        b.height = 4_400_500;
        write_local(&d, 9, &b).unwrap();
        let after = parse_index(&fs::read_to_string(d.join(index_rel(9))).unwrap());
        assert_eq!(after.len(), 1, "still one row for the epoch");
        assert_eq!(after[0].txid, "22".repeat(32), "the index names the transaction that settled");
        assert_eq!(after[0].height, 4_400_500);
    }

    #[test]
    fn a_bundle_writes_reads_back_and_indexes_once() {
        let root = tmp("local");
        let b = bundle();
        let files = write_local(&root, 4, &b).unwrap();
        assert_eq!(files.len(), 5, "anchor, certificate, published, one intents file, the index");
        assert!(root.join("chain-4/0/anchor.bin").exists());
        assert!(root.join("chain-4/0/intents/epoch-0.intents").exists());
        let back = read_local(&root, 4, 0).unwrap();
        assert_eq!(back, b);
        write_local(&root, 4, &b).unwrap();
        let index = fs::read_to_string(root.join("chain-4/index")).unwrap();
        assert_eq!(parse_index(&index).len(), 1, "writing twice indexes once");
        assert_eq!(parse_index(&index)[0].anchor_id, b.anchor.id());
    }

    #[test]
    fn mirrors_parse_with_and_without_tokens() {
        let m = parse_mirrors("https://a.example/da/|s3cret, http://b:8181 ,,");
        assert_eq!(m, vec![
            Mirror { url: "https://a.example/da".into(), token: Some("s3cret".into()) },
            Mirror { url: "http://b:8181".into(), token: None },
        ]);
    }

    #[test]
    fn a_publisher_pushes_to_a_mirror_the_mirror_serves_it_back_and_refuses_the_rest() {
        let mirror_dir = tmp("mirror");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let md = mirror_dir.clone();
        std::thread::spawn(move || http::serve(md, listener, Some("tok".into())));

        let root = tmp("seq");
        let b = bundle();
        let files = write_local(&root, 4, &b).unwrap();
        let mut p = Publisher::new(parse_mirrors(&format!("http://127.0.0.1:{}|tok", port)));
        p.queue(files.clone());
        assert_eq!(p.poll_once().unwrap(), 5);
        assert_eq!(p.pending_len(), 0);
        for (rel, bytes) in &files {
            let got = ureq::get(&format!("http://127.0.0.1:{}/{}", port, rel)).call().unwrap();
            let mut body = Vec::new();
            got.into_reader().read_to_end(&mut body).unwrap();
            assert_eq!(&body, bytes, "{}", rel);
        }
        assert_eq!(read_local(&mirror_dir, 4, 0).unwrap(), b, "the mirror holds a complete bundle");

        // Wrong token, no token, traversal, missing file. Under a loaded test
        // run a connection can be refused before the server answers; one
        // retry separates that from a wrong status.
        let put = |auth: Option<&str>| {
            for _ in 0..2 {
                let mut req = ureq::put(&format!("http://127.0.0.1:{}/chain-4/x", port));
                if let Some(a) = auth { req = req.set("Authorization", a); }
                match req.send_bytes(b"x") {
                    Err(ureq::Error::Transport(_)) => std::thread::sleep(std::time::Duration::from_millis(50)),
                    other => return other,
                }
            }
            ureq::put(&format!("http://127.0.0.1:{}/chain-4/x", port)).send_bytes(b"x")
        };
        assert!(matches!(put(Some("Bearer nope")), Err(ureq::Error::Status(401, _))));
        assert!(matches!(put(None), Err(ureq::Error::Status(401, _))));
        // A client normalises `..` away, so send the raw request to be sure the
        // server itself refuses to leave its root.
        {
            use std::io::Write;
            let mut raw = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            raw.write_all(b"PUT /../escape HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer tok\r\nContent-Length: 1\r\n\r\nx").unwrap();
            let mut reply = String::new();
            raw.read_to_string(&mut reply).unwrap();
            assert!(reply.starts_with("HTTP/1.1 400"), "{}", reply);
            assert!(!mirror_dir.parent().unwrap().join("escape").exists());
        }
        let r = ureq::get(&format!("http://127.0.0.1:{}/chain-4/9/anchor.bin", port)).call();
        assert!(matches!(r, Err(ureq::Error::Status(404, _))));

        // A mirror that is down keeps the files queued and reports it.
        let mut down = Publisher::new(parse_mirrors("http://127.0.0.1:1|tok"));
        down.queue(files);
        assert!(down.poll_once().is_err());
        assert_eq!(down.pending_len(), 5);
        assert_eq!(down.failures, 1);
    }

}
