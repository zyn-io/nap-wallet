//! The socket.
//!
//! # What is reachable and what is not
//!
//! The wire format documents nine operations, and several of them assert
//! **operator** authority: applying a batch at chosen sequence numbers,
//! checkpointing, restoring a state over the top of a live chain. Those are
//! control-plane operations. They are not exposed here at all — not gated
//! behind a flag, not protected by a token, absent.
//!
//! The reasoning is `zyn::verify::Authorized`, one level out. That type exists
//! so authority has to be *claimed in writing* rather than forgotten; a socket
//! that let a stranger claim `Authority::Operator` would hand the claim back to
//! whoever connects. So the rule here is simple enough to hold in the head:
//!
//! - **Reads** are public. A quote, a status, a snapshot, a proof.
//! - **Writes** require a signature, and the account is *derived* from it.
//! - **Operator authority is not obtainable over the network.**
//!
//! # Framing
//!
//! `swapvm::wire` still defines only application intents. The execution layer
//! wraps those in the generic `ZYNAUTH1` commitment after verification. This
//! socket adds transport framing around the same fields; transport lengths and
//! operation tags never enter the commitment.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use swapvm::state::SwapState;
use swapvm::wire;
use swapvm::Fixed;
use zyn::node::Node;
use zyn::replay::{self, ReplayIndex};
use zyn::verify::{authorize_delegated_intent, authorize_intent, Credential, Delegated};
use zyn_vm::auth::{Authorization, Scheme};
use zyn_vm::commit::Encoder;
use zyn_vm::read::Decoder;
use zyn_vm::session::{AssetLimit, Delegation, MAX_POLICY_ITEMS};
use zyn_vm::spec::MicrochainVm;

/// Submit a signed intent. Not in the original nine: those were written for a
/// control plane that already had authority, and a user does not.
pub const OP_SUBMIT: u8 = 10;
/// An account's published record: balances, exits in flight, credits not yet
/// released. Public — it is the data-availability payload for one account.
pub const OP_ACCOUNT: u8 = 11;
/// An intent carrying several credentials — a co-signed offer.
pub const OP_SUBMIT_MULTI: u8 = 12;
/// A holder tells the operator where their exit goes: the preimage of the
/// destination commitment the chain already holds. Signed by the account.
pub const OP_REVEAL: u8 = 13;
/// Every asset the chain knows: id, symbol, supply, and the pool it is the
/// LP share of. Public, like the pools.
pub const OP_ASSETS: u8 = 14;
/// The caller's open orders — swaps waiting for the seal. Signed: an order
/// is as private as a balance.
pub const OP_ORDERS: u8 = 15;
/// The ZYN launch, public: parameters, clock, graduation, pots.
pub const OP_LAUNCH: u8 = 16;
/// The caller's part in it: contribution, vesting, this epoch's fees. Signed.
pub const OP_LAUNCH_ME: u8 = 17;
/// A signer endorses an anchor it verified: `anchor_id[32] signer[32] sig[64]`.
/// Counted only against a configured signer set; grants no authority.
pub const OP_ENDORSE: u8 = 18;
/// The shielded address an account's deposits should be sent to: `account[32]`.
/// Read-only and unauthenticated — the answer is a function of the account,
/// which the caller already supplied, and the address reveals nothing about
/// the account to anyone who does not already hold the vault's viewing key.
pub const OP_DEPOSIT_ADDRESS: u8 = 19;
/// Every collection: cap, minted, outstanding, pool, phase and the redeem
/// price. Public, and it has to be — the floor is the thing a buyer is
/// trusting, so it is exactly the number that must not require asking us.
pub const OP_COLLECTIONS: u8 = 20;
/// Every resting offer: who placed it, what it gives, what it wants, and when
/// it lapses. Public, and it has to be — an offer nobody can see is one nobody
/// can take, and the order book is the whole point of a resting offer.
pub const OP_OFFERS: u8 = 21;
/// Anchors published so far: `epoch root anchor_id txid height`, newest last.
/// Public: it is the mapping from a Zyn epoch to the Zcash transaction that
/// carries its root, which is the whole claim anyone would want to check.
pub const OP_ANCHORS: u8 = 22;
/// Submit an intent under an owner-issued, expiring session delegation. The
/// complete certificate and both signatures enter the committed journal.
pub const OP_SUBMIT_DELEGATED: u8 = 23;

/// Reveals received over the wire, waiting for a settler to take them.
#[derive(Default)]
pub struct Inbox {
    pub zcash: Vec<crate::settle::ZcashReveal>,
    pub solana: Vec<zyn_bridge::solana::Reveal>,
    /// The lines to append to the reveal files, so a restart keeps them.
    pub lines: Vec<(&'static str, String)>,
}

/// What a signed read covers: `"zyn.read.v1" ‖ chain ‖ account ‖ epoch`.
/// Fresh for [`READ_WINDOW`] epochs, so a captured request cannot be replayed
/// against a later state.
pub const READ_WINDOW: u64 = 100;

/// Refuse a frame larger than this before allocating for it.
const MAX_FRAME: usize = 1 << 20;

pub type Shared = Arc<Mutex<Node<SwapState>>>;

/// What a replica adds to the server: where writes should have gone, and what
/// it has verified so far (`(epoch, height)`), for `OP_STATUS`.
pub struct ReplicaInfo {
    pub sequencer: String,
    pub verified: Arc<Mutex<(Option<u64>, u64)>>,
    /// `(forced intents pending, censored)`.
    pub forced: Arc<Mutex<(u32, u32)>>,
}

/// Leaves per `OP_SNAPSHOT` page by default: 32-byte leaves under a 1 MiB
/// frame with room for the header.
pub const SNAPSHOT_PAGE: u32 = 32_000;

/// Everything the handler is allowed to do to the outside world, so the
/// dispatch itself stays testable without a socket.
pub struct Server {
    /// Component health, written by the poll loop, read by `OP_STATUS`.
    pub health: Arc<Mutex<Vec<crate::alert::Health>>>,
    pub inbox: Arc<Mutex<Inbox>>,
    pub node: Shared,
    pub chain_id: u32,
    /// Wall-clock seconds. Injected because the node takes time as an argument
    /// rather than reading a clock — the same discipline that keeps the VM
    /// replayable.
    pub now: fn() -> u64,
    /// `Some` on a replica: reads are served from verified state, and every
    /// write is refused with the sequencer's address.
    pub replica: Option<ReplicaInfo>,
    /// Signatures already applied: a second submission of one is refused.
    pub replay: Arc<Mutex<ReplayIndex>>,
    /// The deposit-address register and the viewing key to derive from, when
    /// this node custodies a Zcash vault. `None` elsewhere, and the op then
    /// says so rather than inventing an address.
    pub deposits: Option<Arc<Mutex<(crate::deposits::Book, zyn_custody::shielded::VaultKeys)>>>,
    /// Where published bundles and their index live, when this node keeps a
    /// copy. `OP_ANCHORS` reads the index from here — a replica has its own,
    /// which is the point: the mapping from an epoch to the Zcash transaction
    /// carrying its root can be served by something that never sequenced it.
    pub da_dir: Option<std::path::PathBuf>,
}

/// The key a credential is remembered under in the replay index.
pub fn replay_key_of(c: &Credential) -> [u8; 32] {
    match c {
        Credential::Ed25519 { signature, .. } | Credential::Solana { signature, .. } => replay::key(c.scheme().tag(), signature),
        Credential::Evm { signature } => replay::key(c.scheme().tag(), signature),
    }
}

/// Decode one signed submission frame — the bytes after the op and chain id
/// of an `OP_SUBMIT`, and exactly what a forced memo carries:
/// `vm_id[32] ‖ valid_until u64 ‖ scheme u8 ‖ credential ‖ intent`.
pub fn decode_frame(chain_id: u32, frame: &[u8]) -> Result<(Credential, Authorization, swapvm::tx::Intent), &'static str> {
    let mut d = Decoder::new(frame);
    let vm_id = d.array::<32>().map_err(|_| "missing program id")?;
    let valid_until_epoch = d.u64().map_err(|_| "missing expiry")?;
    let tag = d.u8().map_err(|_| "missing scheme")?;
    let scheme = Scheme::from_tag(tag).ok_or("unknown scheme")?;
    let cred = match scheme {
        Scheme::Secp256k1Eip712 => Credential::Evm { signature: d.array::<65>().map_err(|_| "malformed signature")? },
        Scheme::Ed25519 | Scheme::Ed25519Solana => {
            let key = d.array::<32>().map_err(|_| "malformed credential")?;
            let sig = d.array::<64>().map_err(|_| "malformed credential")?;
            match scheme {
                Scheme::Ed25519 => Credential::Ed25519 { key, signature: sig },
                _ => Credential::Solana { key, signature: sig },
            }
        }
    };
    let intent = wire::decode_intent(&mut d).map_err(|_| "malformed intent")?;
    if d.remaining() != 0 {
        return Err("trailing bytes");
    }
    Ok((cred, Authorization { chain_id, vm_id, valid_until_epoch }, intent))
}

pub fn serve(server: Arc<Server>, listener: TcpListener) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let s = Arc::clone(&server);
        // A thread per connection. A single-sequencer devnet has one writer
        // and a handful of readers; an async runtime here would be a
        // dependency bought with nothing.
        std::thread::spawn(move || {
            let _ = handle(&s, stream);
        });
    }
}

fn handle(server: &Server, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return Ok(()); // peer went away; not an error worth logging
        }
        let n = u32::from_be_bytes(len) as usize;
        if n == 0 || n > MAX_FRAME {
            let body = error_frame("frame too large");
            write_frame(&mut stream, &body)?;
            return Ok(());
        }
        let mut buf = vec![0u8; n];
        if stream.read_exact(&mut buf).is_err() {
            return Ok(());
        }
        let out = dispatch(server, &buf);
        write_frame(&mut stream, &out)?;
    }
}

fn write_frame(stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn error_frame(msg: &str) -> Vec<u8> {
    let mut e = Encoder::new();
    e.u8(wire::STATUS_ERR).u16(msg.len() as u16).bytes(msg.as_bytes());
    e.finish().to_vec()
}

fn ok_frame(body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(wire::STATUS_OK);
    out.extend_from_slice(&body);
    out
}

/// Parse one request and produce one response. Never panics on input (**S10**)
/// and never propagates a lock poisoning into a crash loop.
pub fn dispatch(server: &Server, frame: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(frame);
    let Ok(op) = d.u8() else { return error_frame("empty request") };
    let Ok(chain_id) = d.u32() else { return error_frame("missing chain id") };
    if chain_id != server.chain_id {
        return error_frame("wrong chain");
    }

    match op {
        wire::OP_STATUS => with_node(server, |n| {
            let mut body = status_body(n);
            // Appended, so an older client that reads the fixed fields and
            // stops is unaffected.
            let health = server.health.lock().map(|h| h.clone()).unwrap_or_default();
            let mut e = Encoder::new();
            e.u32(health.len() as u32);
            for h in &health {
                let err = h.last_error.clone().unwrap_or_default();
                e.u16(h.name.len() as u16).bytes(h.name.as_bytes()).u64(h.scanned_to).u8(h.down as u8).u32(h.failures).u16(err.len() as u16).bytes(err.as_bytes());
            }
            // Appended after the health list: whether swaps queue for the seal.
            e.u8(n.state().batch_clearing as u8);
            // Appended again: who is answering, and what has been anchored or
            // verified. A sequencer reports its ledger; a replica what it proved.
            match &server.replica {
                None => {
                    e.u8(0).u64(n.ledger().last().map(|a| a.checkpoint.epoch).unwrap_or(0)).u64(0).u32(0).u32(0);
                }
                Some(r) => {
                    let (epoch, height) = r.verified.lock().map(|v| *v).unwrap_or((None, 0));
                    let (pending, censored) = r.forced.lock().map(|v| *v).unwrap_or((0, 0));
                    e.u8(1).u64(epoch.unwrap_or(0)).u64(height).u32(pending).u32(censored);
                }
            }
            body.extend_from_slice(e.finish());
            ok_frame(body)
        }),
        wire::OP_QUOTE => quote(server, &mut d),
        OP_SUBMIT | OP_SUBMIT_MULTI | OP_SUBMIT_DELEGATED | OP_REVEAL
            if server.replica.is_some() =>
        {
            let to = server.replica.as_ref().map(|r| r.sequencer.clone()).unwrap_or_default();
            error_frame(&format!("read-only replica; submit to the sequencer at {}", to))
        }
        OP_SUBMIT => submit(server, &mut d),
        OP_ACCOUNT => match signed_read(server, &mut d) {
            Err(e) => error_frame(e),
            Ok(id) => with_node(server, |n| match zyn_vm::spec::MicrochainVm::account_record(n.state(), &id) {
                Some(record) => ok_frame(record),
                None => error_frame("no such account"),
            }),
        },
        OP_SUBMIT_MULTI => submit_multi(server, &mut d),
        OP_SUBMIT_DELEGATED => submit_delegated(server, &mut d),
        OP_REVEAL => match signed_read(server, &mut d) {
            Err(e) => error_frame(e),
            Ok(id) => reveal(server, &id, &mut d),
        },
        wire::OP_POOLS => with_node(server, |n| ok_frame(pools_body(n))),
        OP_LAUNCH => with_node(server, |n| {
            let s = n.state();
            let mut e = Encoder::new();
            match &s.launch {
                None => { e.u8(0); }
                Some(l) => {
                    use swapvm::launch::*;
                    e.u8(1);
                    swapvm::wire::encode_launch(&mut e, &l.params);
                    e.u64(l.zcash_height).u64(l.graduated_at).u32(l.zyn).u32(l.genesis_pool).fixed(l.minted).u64(l.last_mint_height)
                        .fixed(s.balance(&POT_GENESIS, swapvm::types::XZEC))
                        .fixed(if l.zyn > 0 { s.balance(&POT_LP, l.zyn) } else { Fixed::ZERO })
                        .fixed(if l.zyn > 0 { s.balance(&POT_BRIDGE, l.zyn) } else { Fixed::ZERO })
                        .fixed(if l.zyn > 0 { s.balance(&POT_POL, l.zyn) } else { Fixed::ZERO })
                        .fixed(s.balance(&POT_POL, swapvm::types::XZEC))
                        .fixed(s.balance(&POT_FEES, swapvm::types::XZEC))
                        .fixed(if l.zyn > 0 { s.tokens.get(&l.zyn).map(|t| t.supply).unwrap_or(Fixed::ZERO) } else { Fixed::ZERO })
                        .u32(l.contributions.len() as u32)
                        .fixed(l.contributions.values().fold(Fixed::ZERO, |a, v| a.add(*v).unwrap_or(a)));
                    // Bridged assets on their way to a market of their own.
                    e.u32(l.assets.len() as u32);
                    for (id, a) in &l.assets {
                        e.u32(*id)
                            .fixed(s.balance(&POT_ASSETS, *id))
                            .fixed(a.reference.map(|r| r.price).unwrap_or(Fixed::ZERO))
                            .u64(a.opened_at).u32(a.pool).fixed(a.grant)
                            .u32(a.contributions.len() as u32)
                            .fixed(a.contributions.values().fold(Fixed::ZERO, |x, v| x.add(*v).unwrap_or(x)));
                    }
                    e.fixed(l.params.asset_threshold).u16(l.params.bootstrap_bps);
                }
            }
            ok_frame(e.finish().to_vec())
        }),
        OP_LAUNCH_ME => match signed_read(server, &mut d) {
            Err(e) => error_frame(e),
            Ok(id) => with_node(server, |n| {
                let s = n.state();
                let mut e = Encoder::new();
                match &s.launch {
                    None => { e.u8(0); }
                    Some(l) => {
                        e.u8(1);
                        e.fixed(l.contributions.get(&id).copied().unwrap_or(Fixed::ZERO));
                        e.fixed(l.epoch_bridge_fees.get(&id).copied().unwrap_or(Fixed::ZERO));
                        let v = l.vesting.get(&(id, 0));
                        e.fixed(v.map(|v| v.total).unwrap_or(Fixed::ZERO)).fixed(v.map(|v| v.released).unwrap_or(Fixed::ZERO)).u64(v.map(|v| v.end).unwrap_or(0));
                        // Every market this account helped open: what it put
                        // in, and what is still vesting from the grant.
                        let mine: Vec<_> = l.assets.iter().filter(|(k, a)| a.contributions.contains_key(&id) || l.vesting.contains_key(&(id, **k))).collect();
                        e.u32(mine.len() as u32);
                        for (k, a) in mine {
                            let v = l.vesting.get(&(id, *k));
                            e.u32(*k).fixed(a.contributions.get(&id).copied().unwrap_or(Fixed::ZERO))
                                .fixed(v.map(|v| v.total).unwrap_or(Fixed::ZERO)).fixed(v.map(|v| v.released).unwrap_or(Fixed::ZERO)).u64(v.map(|v| v.end).unwrap_or(0));
                        }
                    }
                }
                ok_frame(e.finish().to_vec())
            }),
        },
        OP_ORDERS => match signed_read(server, &mut d) {
            Err(e) => error_frame(e),
            Ok(id) => with_node(server, |n| {
                let mine: Vec<_> = n.state().orders.iter().filter(|o| o.account == id).collect();
                let mut e = Encoder::new();
                e.u32(mine.len() as u32);
                for o in mine {
                    e.u64(o.seq).u32(o.pool).u32(o.asset_in).fixed(o.amount_in).fixed(o.min_out);
                }
                ok_frame(e.finish().to_vec())
            }),
        },
        OP_ASSETS => with_node(server, |n| {
            let s = n.state();
            let mut e = Encoder::new();
            e.u32(s.tokens.len() as u32);
            for (id, t) in s.tokens.iter() {
                e.u32(*id).bytes(&t.symbol).fixed(t.supply).u32(t.lp_of.unwrap_or(0));
                // What makes an item an item: the content it was minted
                // against, and the collection whose pool backs it. Without
                // these a storefront cannot tell an artwork from a token.
                e.u8(t.content.is_some() as u8).bytes(&t.content.unwrap_or([0u8; 32]));
                e.u32(t.collection.unwrap_or(0));
            }
            ok_frame(e.finish().to_vec())
        }),
        wire::OP_ACCOUNT_PROOF => match signed_read(server, &mut d) {
            Err(e) => error_frame(e),
            Ok(id) => account_proof(server, &id),
        },
        OP_ENDORSE if server.replica.is_some() => error_frame("this is a replica; endorse the sequencer"),
        OP_ENDORSE => endorse(server, &mut d),
        OP_DEPOSIT_ADDRESS => deposit_address(server, &mut d),
        OP_COLLECTIONS => with_node(server, |n| {
            let s = n.state();
            let mut e = Encoder::new();
            e.u32(s.collections.len() as u32);
            for (id, c) in s.collections.iter() {
                e.u32(*id)
                    .bytes(&c.creator)
                    .bytes(&c.symbol)
                    .u32(c.cap)
                    .u32(c.minted)
                    .u32(c.outstanding)
                    .fixed(c.pool)
                    .u16(c.fee_bps)
                    .u8(c.phase.code())
                    // Derived, but sent rather than left to the caller: it is
                    // the number everything else is judged against, and two
                    // implementations of one division is one too many.
                    .fixed(c.redeem_price());
            }
            ok_frame(e.finish().to_vec())
        }),
        OP_OFFERS => with_node(server, |n| {
            let s = n.state();
            let mut e = Encoder::new();
            e.u32(s.offers.len() as u32);
            for (id, o) in s.offers.iter() {
                e.u64(*id)
                    .bytes(&o.maker)
                    .u32(o.offer_asset)
                    .fixed(o.offer_amount)
                    .u32(o.want_asset)
                    .fixed(o.want_amount)
                    .u64(o.expires_at_epoch);
            }
            ok_frame(e.finish().to_vec())
        }),
        OP_ANCHORS => {
            let Some(dir) = server.da_dir.as_ref() else {
                return error_frame("this node keeps no published bundles");
            };
            // Optional limit, appended so an older client that sends none
            // still gets the whole index.
            let limit = d.u32().unwrap_or(0) as usize;
            let path = dir.join(crate::publish::index_rel(server.chain_id));
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            let all = crate::publish::parse_index(&text);
            let from = if limit > 0 && all.len() > limit { all.len() - limit } else { 0 };
            let shown = &all[from..];
            let mut e = Encoder::new();
            e.u32(shown.len() as u32);
            for a in shown {
                e.u64(a.epoch)
                    .bytes(&a.root)
                    .bytes(&a.anchor_id)
                    .u16(a.txid.len() as u16)
                    .bytes(a.txid.as_bytes())
                    .u64(a.height);
            }
            ok_frame(e.finish().to_vec())
        }
        wire::OP_SNAPSHOT => {
            // Optional paging, appended to the request so an older client that
            // sends none gets the first page.
            let offset = d.u32().unwrap_or(0);
            let limit = d.u32().unwrap_or(SNAPSHOT_PAGE).clamp(1, SNAPSHOT_PAGE);
            snapshot(server, offset, limit)
        }

        // Control-plane operations. See the module docs: these assert operator
        // authority, and a socket cannot be the thing that grants it.
        wire::OP_APPLY_BATCH | wire::OP_CHECKPOINT | wire::OP_RESTORE | wire::OP_STATE => {
            error_frame("operator operation, not available over the network")
        }
        _ => error_frame("unknown operation"),
    }
}

/// Record every key; refuse if any was seen. All-or-nothing, so a co-signed
/// intent with one replayed signature records none of them.
fn fresh(server: &Server, keys: &[[u8; 32]], valid_until_epoch: u64) -> bool {
    let Ok(mut r) = server.replay.lock() else { return false };
    let mut probe = r.clone();
    if keys.iter().any(|k| !probe.fresh(*k, valid_until_epoch)) {
        return false;
    }
    *r = probe;
    true
}

fn with_node<F: FnOnce(&mut Node<SwapState>) -> Vec<u8>>(server: &Server, f: F) -> Vec<u8> {
    match server.node.lock() {
        Ok(mut n) => f(&mut n),
        // A poisoned lock means a handler panicked while holding it. The state
        // behind it may be mid-update, so refusing is the only honest answer.
        Err(_) => error_frame("node unavailable"),
    }
}

fn status_body(n: &Node<SwapState>) -> Vec<u8> {
    let s = n.state();
    let mut e = Encoder::new();
    e.u64(s.seq())
        .u64(s.epoch())
        .bytes(&s.state_root())
        .fixed(s.backing_of(swapvm::types::XZEC))
        .u32(s.pools.len() as u32)
        .u32(s.accounts.len() as u32);
    e.finish().to_vec()
}

fn pools_body(n: &Node<SwapState>) -> Vec<u8> {
    let s = n.state();
    let mut e = Encoder::new();
    e.u32(s.pools.len() as u32);
    for (id, p) in s.pools.iter() {
        e.u32(*id)
            .u32(p.asset0)
            .u32(p.asset1)
            .fixed(p.reserve0)
            .fixed(p.reserve1)
            .u16(p.fee_bps)
            // The reference behind the fee, and the fee as charged right now.
            .bool(p.reference.is_some())
            .fixed(p.reference.map(|r| r.price).unwrap_or(Fixed::ZERO))
            .u64(p.reference.map(|r| r.seq).unwrap_or(0))
            .u16(swapvm::vm::effective_fee(p, s.seq(), s.params.reference_staleness));
    }
    e.finish().to_vec()
}

/// `asset_in:u32 count:u32 pool:u32* amount_in:i128`, as documented.
fn quote(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let (Ok(asset_in), Ok(count)) = (d.u32(), d.u32()) else {
        return error_frame("malformed quote");
    };
    if count as usize > wire::MAX_PATH_WIRE {
        return error_frame("path too long");
    }
    let mut path = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Ok(p) = d.u32() else { return error_frame("malformed path") };
        path.push(p);
    }
    let Ok(raw) = d.i128() else { return error_frame("malformed amount") };

    with_node(server, |n| match swapvm::vm::quote(n.state(), asset_in, &path, Fixed(raw)) {
        Err(r) => error_frame(reject_name(r)),
        Ok(q) => {
            let mut e = Encoder::new();
            // Both ends of the range: what solo execution pays, and what a
            // perfectly netted batch would. A router needs the bracket, not a
            // point it cannot rely on.
            e.fixed(q.amount_out)
                .fixed(q.best_case)
                .u32(q.asset_out)
                .u32(q.hops.len() as u32);
            for h in &q.hops {
                e.u32(h.pool)
                    .u32(h.asset_in)
                    .u32(h.asset_out)
                    .fixed(h.amount_in)
                    .fixed(h.amount_out)
                    .fixed(h.fee);
            }
            ok_frame(e.finish().to_vec())
        }
    })
}

/// `vm_id:[32] valid_until:u64 scheme:u8 key* sig* intent`.
///
/// The account is never sent. It is recovered from the signature and the
/// scheme, so a caller cannot name an account they do not control — **S14**.
fn submit(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let Ok(vm_id) = d.array::<32>() else { return error_frame("missing program id") };
    let Ok(valid_until_epoch) = d.u64() else { return error_frame("missing expiry") };
    let Ok(tag) = d.u8() else { return error_frame("missing scheme") };
    let Some(scheme) = Scheme::from_tag(tag) else { return error_frame("unknown scheme") };

    let cred = match scheme {
        Scheme::Secp256k1Eip712 => match d.array::<65>() {
            Ok(sig) => Credential::Evm { signature: sig },
            Err(_) => return error_frame("malformed signature"),
        },
        Scheme::Ed25519 | Scheme::Ed25519Solana => {
            let (Ok(key), Ok(sig)) = (d.array::<32>(), d.array::<64>()) else {
                return error_frame("malformed credential");
            };
            match scheme {
                Scheme::Ed25519 => Credential::Ed25519 { key, signature: sig },
                _ => Credential::Solana { key, signature: sig },
            }
        }
    };

    let Ok(intent) = wire::decode_intent(d) else { return error_frame("malformed intent") };
    let auth =
        Authorization { chain_id: server.chain_id, vm_id, valid_until_epoch };
    let now = (server.now)();

    with_node(server, |n| {
        let authorized = match authorize_intent(std::slice::from_ref(&cred), &auth, intent, n.state()) {
            Ok(a) => a,
            Err(e) => return error_frame(&format!("unauthorised: {:?}", e)),
        };
        if !fresh(server, &[replay_key_of(&cred)], auth.valid_until_epoch) {
            return error_frame("already applied: this signature was seen before (replay)");
        }
        let step = n.submit(authorized, now);
        let mut e = Encoder::new();
        e.u64(step.seq).u64(n.state().epoch()).bytes(&n.state().state_root());
        let receipts = wire::encode_receipts(&step.receipts);
        e.bytes(&receipts);
        ok_frame(e.finish().to_vec())
    })
}

/// A holder's own record, leaf index and path — enough to prove an exit
/// against the anchored root without us, fetched while we are here.
/// `account:32 epoch:u64 scheme:u8 key:32 sig:64` — the holder proves the
/// read is theirs. Ed25519 only for now; a wallet's signed read is the same
/// shape with its own scheme.
fn signed_read(server: &Server, d: &mut Decoder) -> Result<[u8; 32], &'static str> {
    let id = d.array::<32>().map_err(|_| "malformed account")?;
    let epoch = d.u64().map_err(|_| "malformed epoch")?;
    let tag = d.u8().map_err(|_| "malformed scheme")?;
    if Scheme::from_tag(tag) != Some(Scheme::Ed25519) {
        return Err("signed reads accept ed25519 for now");
    }
    let key = d.array::<32>().map_err(|_| "malformed key")?;
    let sig = d.array::<64>().map_err(|_| "malformed signature")?;
    if zyn_vm::auth::account_of(Scheme::Ed25519, &key) != id {
        return Err("the key is not this account's");
    }
    let now = with_epoch(server);
    if epoch > now || now.saturating_sub(epoch) > READ_WINDOW {
        return Err("stale read");
    }
    let msg = read_challenge(server.chain_id, &id, epoch);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "malformed key")?;
    vk.verify_strict(&msg, &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| "bad signature")?;
    Ok(id)
}

/// The bytes a signed read covers.
pub fn read_challenge(chain_id: u32, account: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.bytes(b"zyn.read.v1").u32(chain_id).bytes(account).u64(epoch);
    e.finish().to_vec()
}

fn with_epoch(server: &Server) -> u64 {
    server.node.lock().map(|n| n.state().epoch()).unwrap_or(0)
}

/// `vm_id:32 valid_until:u64 count:u8 (scheme key? sig)* intent` — every
/// party an intent names signs the same bytes; a co-signed offer is one
/// intent with two credentials.
fn submit_multi(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let Ok(vm_id) = d.array::<32>() else { return error_frame("missing program id") };
    let Ok(valid_until_epoch) = d.u64() else { return error_frame("missing expiry") };
    let Ok(count) = d.u8() else { return error_frame("missing credential count") };
    if count == 0 || count > 4 {
        return error_frame("one to four credentials");
    }
    let mut creds = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let Ok(tag) = d.u8() else { return error_frame("missing scheme") };
        let Some(scheme) = Scheme::from_tag(tag) else { return error_frame("unknown scheme") };
        creds.push(match scheme {
            Scheme::Secp256k1Eip712 => match d.array::<65>() {
                Ok(sig) => Credential::Evm { signature: sig },
                Err(_) => return error_frame("malformed signature"),
            },
            Scheme::Ed25519 | Scheme::Ed25519Solana => {
                let (Ok(key), Ok(sig)) = (d.array::<32>(), d.array::<64>()) else {
                    return error_frame("malformed credential");
                };
                match scheme {
                    Scheme::Ed25519 => Credential::Ed25519 { key, signature: sig },
                    _ => Credential::Solana { key, signature: sig },
                }
            }
        });
    }
    let Ok(intent) = wire::decode_intent(d) else { return error_frame("malformed intent") };
    let auth = Authorization { chain_id: server.chain_id, vm_id, valid_until_epoch };
    let now = (server.now)();
    with_node(server, |n| {
        let authorized = match authorize_intent(&creds, &auth, intent, n.state()) {
            Ok(a) => a,
            Err(e) => return error_frame(&format!("unauthorised: {:?}", e)),
        };
        let keys: Vec<[u8; 32]> = creds.iter().map(replay_key_of).collect();
        if !fresh(server, &keys, auth.valid_until_epoch) {
            return error_frame("already applied: a signature here was seen before (replay)");
        }
        let step = n.submit(authorized, now);
        let mut e = Encoder::new();
        e.u64(step.seq).u64(n.state().epoch()).bytes(&n.state().state_root());
        e.bytes(&wire::encode_receipts(&step.receipts));
        ok_frame(e.finish().to_vec())
    })
}

/// `vm_id:32 auth_until:u64 delegation(account key caps policy until)
/// owner_credential session_signature intent`.
fn submit_delegated(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let Ok(vm_id) = d.array::<32>() else {
        return error_frame("missing program id");
    };
    let Ok(valid_until_epoch) = d.u64() else {
        return error_frame("missing intent expiry");
    };
    let (Ok(account), Ok(session_key), Ok(capabilities)) = (
        d.array::<32>(),
        d.array::<32>(),
        d.u32(),
    ) else {
        return error_frame("malformed delegation");
    };
    let mut ids = |name: &'static str| -> Result<Vec<u32>, &'static str> {
        let n = d.u8().map_err(|_| name)? as usize;
        if n > MAX_POLICY_ITEMS { return Err(name); }
        (0..n).map(|_| d.u32().map_err(|_| name)).collect()
    };
    let Ok(allowed_assets) = ids("malformed allowed assets") else { return error_frame("malformed allowed assets") };
    let Ok(allowed_pools) = ids("malformed allowed pools") else { return error_frame("malformed allowed pools") };
    let Ok(limit_count) = d.u8() else { return error_frame("malformed amount limits") };
    if limit_count as usize > MAX_POLICY_ITEMS { return error_frame("too many amount limits"); }
    let mut max_per_action = Vec::with_capacity(limit_count as usize);
    for _ in 0..limit_count {
        let (Ok(asset), Ok(amount)) = (d.u32(), d.fixed()) else { return error_frame("malformed amount limit") };
        max_per_action.push(AssetLimit { asset, amount });
    }
    let (Ok(max_slippage_bps), Ok(valid_from_epoch), Ok(salt), Ok(session_until)) =
        (d.u16(), d.u64(), d.array::<32>(), d.u64())
    else { return error_frame("malformed delegation policy") };
    let Ok(owner_tag) = d.u8() else {
        return error_frame("missing owner scheme");
    };
    let Some(owner_scheme) = Scheme::from_tag(owner_tag) else {
        return error_frame("unknown owner scheme");
    };
    let owner = match owner_scheme {
        Scheme::Secp256k1Eip712 => match d.array::<65>() {
            Ok(signature) => Credential::Evm { signature },
            Err(_) => return error_frame("malformed owner signature"),
        },
        Scheme::Ed25519 | Scheme::Ed25519Solana => {
            let (Ok(key), Ok(signature)) = (d.array::<32>(), d.array::<64>()) else {
                return error_frame("malformed owner credential");
            };
            if owner_scheme == Scheme::Ed25519 {
                Credential::Ed25519 { key, signature }
            } else {
                Credential::Solana { key, signature }
            }
        }
    };
    let Ok(session_signature) = d.array::<64>() else {
        return error_frame("malformed session signature");
    };
    let Ok(intent) = wire::decode_intent(d) else {
        return error_frame("malformed intent");
    };
    if d.remaining() != 0 {
        return error_frame("trailing bytes");
    }

    let auth = Authorization {
        chain_id: server.chain_id,
        vm_id,
        valid_until_epoch,
    };
    let delegated = Delegated {
        delegation: Delegation {
            account,
            session_key,
            capabilities,
            allowed_assets,
            allowed_pools,
            max_per_action,
            max_slippage_bps,
            valid_from_epoch,
            salt,
            valid_until_epoch: session_until,
        },
        owner,
        session_signature,
    };
    let now = (server.now)();

    with_node(server, |node| {
        let authorized = match authorize_delegated_intent::<SwapState>(
            &delegated,
            &auth,
            intent,
            node.state(),
        ) {
            Ok(authorized) => authorized,
            Err(error) => return error_frame(&format!("unauthorised: {:?}", error)),
        };
        let replay_key = replay::key(0xFD, &delegated.session_signature);
        if !fresh(server, &[replay_key], auth.valid_until_epoch) {
            return error_frame("already applied: this session signature was seen before (replay)");
        }
        let step = node.submit(authorized, now);
        let mut e = Encoder::new();
        e.u64(step.seq)
            .u64(node.state().epoch())
            .bytes(&node.state().state_root())
            .bytes(&wire::encode_receipts(&step.receipts));
        ok_frame(e.finish().to_vec())
    })
}

/// After the signed header: `kind:u8 (0 zcash, 1 solana) len:u16 address salt:32`.
///
/// Accepted only if `keccak(kind ‖ address ‖ salt)` is exactly the
/// destination the account bound on-chain — so the channel cannot be used
/// to redirect an exit, only to disclose one the holder already committed.
fn reveal(server: &Server, id: &[u8; 32], d: &mut Decoder) -> Vec<u8> {
    let Ok(kind) = d.u8() else { return error_frame("missing kind") };
    let Ok(len) = d.u16() else { return error_frame("missing address") };
    let Ok(addr) = d.take_bytes(len as usize) else { return error_frame("malformed address") };
    let Ok(salt) = d.array::<32>() else { return error_frame("missing salt") };
    let addr = String::from_utf8_lossy(addr).to_string();
    let bound = match server.node.lock().ok().and_then(|n| n.state().accounts.get(id).and_then(|a| a.binding)) {
        Some(b) => b,
        None => return error_frame("this account has no withdrawal binding"),
    };
    let mut inbox = match server.inbox.lock() {
        Ok(i) => i,
        Err(_) => return error_frame("inbox poisoned"),
    };
    let salt_hex: String = salt.iter().map(|b| format!("{:02x}", b)).collect();
    let id_hex: String = id.iter().map(|b| format!("{:02x}", b)).collect();
    match kind {
        0 => {
            let Some(dest) = crate::settle::parse_destination(&addr, zcash_protocol::consensus::Network::TestNetwork) else {
                return error_frame("not a testnet Zcash address");
            };
            if !bound.admits(crate::settle::zcash_commitment(&dest, &salt)) {
                return error_frame("this address and salt do not match the account's binding");
            }
            inbox.zcash.push(crate::settle::ZcashReveal { account: *id, address: dest, salt });
            inbox.lines.push(("zcash", format!("{} {} {}", id_hex, addr, salt_hex)));
        }
        1 => {
            let Some(pk) = zyn_custody::solana::pubkey(&addr) else { return error_frame("not a Solana address") };
            if !bound.admits(zyn_bridge::solana::commitment(&pk, &salt)) {
                return error_frame("this address and salt do not match the account's binding");
            }
            inbox.solana.push(zyn_bridge::solana::Reveal { account: *id, address: pk, salt });
            inbox.lines.push(("solana", format!("{} {} {}", id_hex, addr, salt_hex)));
        }
        _ => return error_frame("unknown kind"),
    }
    ok_frame(Vec::new())
}

/// A holder's record and path against the **anchored** snapshot — the same
/// rule as `OP_SNAPSHOT`. A proof against live state would open a root that
/// nobody committed, which is a proof of nothing.
/// Fold a signer's endorsement into the pending certificate for an anchor.
/// The node checks the signer is in its set and the signature opens the id;
/// an endorsement that is neither is dropped, not an error.
fn endorse(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let (Ok(anchor_id), Ok(signer), Ok(sig)) = (d.array::<32>(), d.array::<32>(), d.array::<64>()) else {
        return error_frame("malformed endorsement");
    };
    with_node(server, |n| {
        if n.add_endorsement(anchor_id, signer, sig) {
            let mut e = Encoder::new();
            e.u8(1).u8(n.certificate_clears(anchor_id) as u8);
            ok_frame(e.finish().to_vec())
        } else {
            let mut e = Encoder::new();
            e.u8(0).u8(0);
            ok_frame(e.finish().to_vec())
        }
    })
}

/// The address this account should be paid at.
///
/// Issuing is idempotent and the address is a pure function of the account, so
/// this is safe to answer to anyone: the caller had to name the account to ask,
/// and without the vault's viewing key the address says nothing about it.
fn deposit_address(server: &Server, d: &mut Decoder) -> Vec<u8> {
    let Ok(account) = d.array::<32>() else {
        return error_frame("malformed account");
    };
    if account == [0u8; 32] {
        return error_frame("the all-zero account is the vault's own, not a depositor's");
    }
    let Some(deposits) = &server.deposits else {
        return error_frame("this node custodies no Zcash vault, so it has no deposit address to give");
    };
    let mut guard = match deposits.lock() {
        Ok(g) => g,
        Err(_) => return error_frame("deposit register poisoned"),
    };
    let (book, keys) = &mut *guard;
    match book.address_for(keys, &account) {
        Ok(addr) => {
            let mut e = Encoder::new();
            e.u32(addr.len() as u32).bytes(addr.as_bytes());
            ok_frame(e.finish().to_vec())
        }
        Err(e) => error_frame(&format!("cannot issue a deposit address: {}", e)),
    }
}

fn account_proof(server: &Server, id: &[u8; 32]) -> Vec<u8> {
    with_node(server, |n| {
        let Some(snap) = n.publishable() else {
            return error_frame("no anchored snapshot yet — nothing has been committed to Zcash");
        };
        match snap.record_proof(id) {
            Err(_) => error_frame("no such account in the anchored snapshot"),
            Ok((record, index, steps)) => {
                let mut e = Encoder::new();
                e.u32(record.len() as u32).bytes(&record).u32(index).u32(steps.len() as u32);
                for s in &steps {
                    e.u8(s.node_is_right as u8).bytes(&s.sibling);
                }
                // Appended: which anchor this proof belongs to.
                e.u64(snap.epoch).bytes(&snap.root);
                ok_frame(e.finish().to_vec())
            }
        }
    })
}

/// The public data-availability payload: balances, so a holder can prove an
/// exit without us, and deliberately nothing else.
///
/// Serves the **published** snapshot — the one taken at the newest anchored
/// root — and not a fresh snapshot of current state. They are different
/// artefacts and only one of them is useful: a proof is worth something because
/// it opens a root Zcash has seen, and current state has been sealed by nobody.
/// Handing back the live root would give a holder something that verifies
/// against a commitment that does not exist.
///
/// Before the first anchor there is nothing to serve, and saying so is the
/// honest answer. Substituting current state is precisely the bug.
fn snapshot(server: &Server, offset: u32, limit: u32) -> Vec<u8> {
    with_node(server, |n| {
        let Some(snap) = n.publishable() else {
            return error_frame("no anchored snapshot yet — nothing has been committed to Zcash");
        };
        // Leaves, never records: a leaf is `H(record ‖ blind)` and says
        // nothing to anyone but its holder. Anyone can rebuild the root.
        let Ok(published) = snap.published() else { return error_frame("snapshot is malformed") };
        let total = published.leaves.len();
        let start = (offset as usize).min(total);
        let end = start.saturating_add(limit as usize).min(total);
        let mut e = Encoder::new();
        e.u64(published.epoch).bytes(&published.root).u32(published.sections.len() as u32);
        for s in &published.sections {
            e.bytes(s);
        }
        e.u32((end - start) as u32);
        for l in &published.leaves[start..end] {
            e.bytes(l);
        }
        // Appended: the page's place in the whole, so a client knows to ask again.
        e.u32(total as u32).u32(start as u32);
        ok_frame(e.finish().to_vec())
    })
}

/// Rejections cross the wire as names rather than numbers. A caller debugging
/// an integration should not have to hold a code table.
fn reject_name(r: swapvm::tx::Reject) -> &'static str {
    match r {
        swapvm::tx::Reject::NonPositiveAmount => "amount must be positive",
        swapvm::tx::Reject::UnknownPool => "no such pool",
        swapvm::tx::Reject::InvalidPath => "the route does not connect",
        swapvm::tx::Reject::BelowMinimumTrade => "below the pool's minimum trade",
        swapvm::tx::Reject::InsufficientReserves => "the pool cannot fill this",
        swapvm::tx::Reject::InsufficientBalance => "insufficient balance",
        swapvm::tx::Reject::SlippageExceeded => "worse than the limit given",
        other => {
            // Anything unnamed still has to say something true.
            let _ = other;
            "rejected"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::Params;
    use zyn::epoch::Economics;

    fn server() -> Server {
        let node = Node::new(9, Params::v1(), Config::policy_for_test(), Economics::flat(10_000));
        Server { node: Arc::new(Mutex::new(node)), chain_id: 9, now: || 0, health: Arc::new(Mutex::new(Vec::new())), inbox: Arc::new(Mutex::new(Inbox::default())), replica: None, replay: Arc::new(Mutex::new(ReplayIndex::default())), deposits: None, da_dir: None }
    }

    /// A chain with two anchored epochs and forty holders, so a snapshot has
    /// something to page.
    fn anchored_server() -> Server {
        let s = server();
        {
            let mut n = s.node.lock().unwrap();
            let observed = n.state().backing_of(swapvm::types::XZEC).add(Fixed::whole(1_000)).unwrap();
            n.submit_operator(swapvm::tx::Intent::AttestVaultBalance { asset: swapvm::types::XZEC, observed }, 0);
            for i in 0..40u8 {
                let d = swapvm::tx::Intent::next_deposit(n.state(), [i + 1; 32], swapvm::types::XZEC, Fixed::whole(1), [0u8; 32]);
                n.submit_operator(d, 0);
            }
            n.seal_now(1);
            n.anchor_now(1);
        }
        s
    }

    fn body_of(out: &[u8]) -> &[u8] {
        assert_eq!(out[0], wire::STATUS_OK, "{}", String::from_utf8_lossy(&out[3..]));
        &out[1..]
    }

    /// One address per account, stable across calls, and refused where the
    /// node has no vault rather than answered with something invented.
    #[test]
    fn a_deposit_address_is_issued_per_account_and_is_stable() {
        use orchard::keys::{FullViewingKey, SpendingKey};
        let dir = std::env::temp_dir().join(format!("zyn-rpc-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keys = zyn_custody::shielded::VaultKeys::from_full_viewing_key(FullViewingKey::from(
            &SpendingKey::from_bytes([4u8; 32]).unwrap(),
        ));

        // No vault: the op says so instead of inventing an address.
        let mut s = server();
        let out = dispatch(&s, &req(OP_DEPOSIT_ADDRESS, 9, &[1u8; 32]));
        assert_eq!(out[0], wire::STATUS_ERR);

        let book = crate::deposits::Book::open(&dir, 9, zcash_protocol::consensus::NetworkType::Test).unwrap();
        s.deposits = Some(Arc::new(Mutex::new((book, keys.clone()))));

        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let read = |out: Vec<u8>| -> String {
            let mut d = Decoder::new(body_of(&out));
            let n = d.u32().unwrap() as usize;
            String::from_utf8(d.take_bytes(n).unwrap().to_vec()).unwrap()
        };
        let a1 = read(dispatch(&s, &req(OP_DEPOSIT_ADDRESS, 9, &alice)));
        let a2 = read(dispatch(&s, &req(OP_DEPOSIT_ADDRESS, 9, &alice)));
        let b1 = read(dispatch(&s, &req(OP_DEPOSIT_ADDRESS, 9, &bob)));
        assert_eq!(a1, a2, "asking twice gives one address");
        assert_ne!(a1, b1, "each account gets its own");
        assert_eq!(a1, keys.deposit_address(&alice, zcash_protocol::consensus::NetworkType::Test), "and it is the derived one");
        assert_ne!(a1, keys.address(0, zcash_protocol::consensus::NetworkType::Test), "never the vault's own address");

        // The all-zero account is the vault's, not a depositor's.
        let out = dispatch(&s, &req(OP_DEPOSIT_ADDRESS, 9, &[0u8; 32]));
        assert_eq!(out[0], wire::STATUS_ERR);

        // The scanner's register now attributes both accounts' notes.
        let shared = s.deposits.as_ref().unwrap().lock().unwrap().0.shared();
        let m = shared.lock().unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m.get(zyn_custody::shielded::deposit_index(&alice).as_bytes()), Some(&alice));
    }

    #[test]
    fn a_snapshot_pages_and_the_pages_are_the_whole() {
        let s = anchored_server();
        let whole = dispatch(&s, &req(wire::OP_SNAPSHOT, 9, &[]));
        let mut d = Decoder::new(body_of(&whole));
        let (_epoch, root) = (d.u64().unwrap(), d.hash().unwrap());
        let ns = d.u32().unwrap();
        for _ in 0..ns { d.hash().unwrap(); }
        let n = d.u32().unwrap() as usize;
        let mut all = Vec::new();
        for _ in 0..n { all.push(d.hash().unwrap()); }
        assert_eq!(d.u32().unwrap() as usize, n, "total");
        assert_eq!(d.u32().unwrap(), 0, "offset");
        assert!(n >= 40);
        // Now in pages of 7.
        let mut paged = Vec::new();
        let mut offset = 0u32;
        loop {
            let mut e = Encoder::new();
            e.u32(offset).u32(7);
            let out = dispatch(&s, &req(wire::OP_SNAPSHOT, 9, e.finish()));
            let mut d = Decoder::new(body_of(&out));
            d.u64().unwrap();
            assert_eq!(d.hash().unwrap(), root);
            let ns = d.u32().unwrap();
            for _ in 0..ns { d.hash().unwrap(); }
            let k = d.u32().unwrap() as usize;
            for _ in 0..k { paged.push(d.hash().unwrap()); }
            let total = d.u32().unwrap();
            assert_eq!(d.u32().unwrap(), offset);
            offset += k as u32;
            if offset >= total { break; }
        }
        assert_eq!(paged, all, "pages must concatenate to the whole");
    }

    #[test]
    fn a_proof_before_the_first_anchor_is_refused_not_faked() {
        let s = server();
        // OP_ACCOUNT_PROOF needs a signed read; the refusal comes before that
        // matters only if there is a snapshot, so check the handler directly.
        let out = account_proof(&s, &[1u8; 32]);
        assert_eq!(out[0], wire::STATUS_ERR);
        assert!(String::from_utf8_lossy(&out[3..]).contains("no anchored snapshot"));
        let s = anchored_server();
        let out = account_proof(&s, &[1u8; 32]);
        assert_eq!(out[0], wire::STATUS_OK, "an anchored holder gets a proof");
        // And it opens the anchored root, not the live one.
        let anchored = s.node.lock().unwrap().ledger().head_root();
        let mut d = Decoder::new(&out[1..]);
        let len = d.u32().unwrap() as usize;
        let record = d.take_bytes(len).unwrap().to_vec();
        let _index = d.u32().unwrap();
        let n = d.u32().unwrap();
        let mut path = Vec::new();
        for _ in 0..n {
            let right = d.u8().unwrap() != 0;
            path.push(zyn_vm::commit::ProofStep { node_is_right: right, sibling: d.hash().unwrap() });
        }
        assert!(zyn::verify_record::<SwapState>(&record, &path, anchored));
    }

    #[test]
    fn an_endorsement_is_counted_only_from_the_set_and_grants_no_authority() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let node = Node::new(9, Params::v1(), Config::policy_for_test(), Economics::flat(10_000))
            .with_manual_anchoring()
            .with_signers(zyn::anchor::SignerSet::new((1..=3u8).map(|i| SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()).collect(), 2).unwrap());
        let s = Server { node: Arc::new(Mutex::new(node)), chain_id: 9, now: || 0, health: Arc::new(Mutex::new(Vec::new())), inbox: Arc::new(Mutex::new(Inbox::default())), replica: None, replay: Arc::new(Mutex::new(ReplayIndex::default())), deposits: None, da_dir: None };
        let id = [7u8; 32];
        let endorse = |k: &SigningKey| {
            let mut e = Encoder::new();
            e.u8(OP_ENDORSE).u32(9).bytes(&id).bytes(&k.verifying_key().to_bytes()).bytes(&k.sign(&id).to_bytes());
            let out = dispatch(&s, e.finish());
            assert_eq!(out[0], wire::STATUS_OK);
            (out[1] != 0, out[2] != 0)
        };
        // An outsider is not counted.
        assert_eq!(endorse(&SigningKey::from_bytes(&[9u8; 32])), (false, false));
        // A member is counted; two clear the set.
        assert_eq!(endorse(&SigningKey::from_bytes(&[1u8; 32])), (true, false));
        assert_eq!(endorse(&SigningKey::from_bytes(&[2u8; 32])), (true, true));
        // A replica refuses to take endorsements at all.
        let mut rep = Server { node: Arc::new(Mutex::new(Node::new(9, Params::v1(), Config::policy_for_test(), Economics::flat(10_000)))), chain_id: 9, now: || 0, health: Arc::new(Mutex::new(Vec::new())), inbox: Arc::new(Mutex::new(Inbox::default())), replica: None, replay: Arc::new(Mutex::new(ReplayIndex::default())), deposits: None, da_dir: None };
        rep.replica = Some(ReplicaInfo { sequencer: "x".into(), verified: Arc::new(Mutex::new((None, 0))), forced: Arc::new(Mutex::new((0, 0))) });
        let mut e = Encoder::new();
        e.u8(OP_ENDORSE).u32(9).bytes(&id).bytes(&[1u8; 32]).bytes(&[0u8; 64]);
        assert_eq!(dispatch(&rep, e.finish())[0], wire::STATUS_ERR);
    }

    #[test]
    fn a_replica_refuses_writes_and_names_the_sequencer() {
        let mut s = server();
        s.replica = Some(ReplicaInfo { sequencer: "168.119.53.39:8099".into(), verified: Arc::new(Mutex::new((Some(4), 4_400_020))), forced: Arc::new(Mutex::new((0, 0))) });
        for op in [OP_SUBMIT, OP_SUBMIT_MULTI, OP_SUBMIT_DELEGATED, OP_REVEAL] {
            let out = dispatch(&s, &req(op, 9, &[]));
            assert_eq!(out[0], wire::STATUS_ERR);
            assert!(String::from_utf8_lossy(&out[3..]).contains("168.119.53.39:8099"), "op {}", op);
        }
        let out = dispatch(&s, &req(wire::OP_STATUS, 9, &[]));
        let body = body_of(&out);
        // role, anchored epoch, verified height, forced pending, censored: the last 25 bytes.
        let tail = &body[body.len() - 25..];
        assert_eq!(tail[0], 1, "role: replica");
        assert_eq!(u64::from_be_bytes(tail[1..9].try_into().unwrap()), 4);
        assert_eq!(u64::from_be_bytes(tail[9..17].try_into().unwrap()), 4_400_020);
        let seq = anchored_server();
        let out = dispatch(&seq, &req(wire::OP_STATUS, 9, &[]));
        let body = body_of(&out);
        let tail = &body[body.len() - 25..];
        assert_eq!(tail[0], 0, "role: sequencer");
        assert_eq!(u64::from_be_bytes(tail[1..9].try_into().unwrap()), 0, "epoch 0 was the one anchored");
    }

    struct Config;
    impl Config {
        fn policy_for_test() -> zyn::epoch::EpochPolicy {
            zyn::epoch::EpochPolicy {
                intents_per_epoch: 64,
                epochs_per_anchor: 8,
                max_seconds_per_epoch: 0,
                max_seconds_per_anchor: 0,
            }
        }
    }

    fn req(op: u8, chain: u32, body: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new();
        e.u8(op).u32(chain).bytes(body);
        e.finish().to_vec()
    }

    #[test]
    fn a_status_read_needs_no_credential() {
        let s = server();
        let out = dispatch(&s, &req(wire::OP_STATUS, 9, &[]));
        assert_eq!(out[0], wire::STATUS_OK);
    }

    /// The rule the module exists to enforce.
    #[test]
    fn operator_operations_are_not_reachable_over_the_socket() {
        let s = server();
        for op in [wire::OP_APPLY_BATCH, wire::OP_CHECKPOINT, wire::OP_RESTORE, wire::OP_STATE] {
            let out = dispatch(&s, &req(op, 9, &[]));
            assert_eq!(out[0], wire::STATUS_ERR, "op {} was reachable", op);
        }
    }

    #[test]
    fn a_frame_for_another_chain_is_refused() {
        let s = server();
        let out = dispatch(&s, &req(wire::OP_STATUS, 10, &[]));
        assert_eq!(out[0], wire::STATUS_ERR);
    }

    /// **S10**: nothing an attacker can send may abort the process.
    #[test]
    fn malformed_frames_are_refused_rather_than_fatal() {
        let s = server();
        assert_eq!(dispatch(&s, &[])[0], wire::STATUS_ERR);
        assert_eq!(dispatch(&s, &[wire::OP_STATUS])[0], wire::STATUS_ERR);
        assert_eq!(dispatch(&s, &[OP_SUBMIT, 0, 0, 0, 9])[0], wire::STATUS_ERR);
        // Every truncation of a well-formed quote.
        let mut e = Encoder::new();
        e.u8(wire::OP_QUOTE).u32(9).u32(1).u32(1).u32(0).i128(1);
        let full = e.finish().to_vec();
        for cut in 0..full.len() {
            let out = dispatch(&s, &full[..cut]);
            assert!(!out.is_empty(), "truncation at {} produced nothing", cut);
        }
    }

    #[test]
    fn an_unknown_operation_is_named_as_such() {
        let s = server();
        assert_eq!(dispatch(&s, &req(200, 9, &[]))[0], wire::STATUS_ERR);
    }

    use swapvm::tx::Intent;
    use zyn_vm::spec::MicrochainVm;

    fn ed25519_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }
    fn acct_of(k: &ed25519_dalek::SigningKey) -> [u8; 32] {
        zyn_vm::auth::account_of(Scheme::Ed25519, k.verifying_key().as_bytes())
    }
    fn signed_cred(k: &ed25519_dalek::SigningKey, auth: &Authorization, intent: &Intent) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let payload = match zyn_vm::auth::signed_bytes_as::<SwapState>(Scheme::Ed25519, auth, intent) {
            zyn_vm::auth::Signed::Message(m) => m,
            zyn_vm::auth::Signed::Prehash(h) => h.to_vec(),
        };
        let mut e = Encoder::new();
        e.u8(Scheme::Ed25519.tag()).bytes(k.verifying_key().as_bytes()).bytes(&k.sign(&payload).to_bytes());
        e.finish().to_vec()
    }

    #[test]
    fn delegated_submit_allows_swaps_and_refuses_transfers() {
        use ed25519_dalek::Signer;
        use zyn::verify::{Credential, Delegated};
        use zyn_vm::auth::{delegation_bytes_as, Signed};
        use zyn_vm::session::{session_payload, Delegation};

        let s = server();
        let owner_key = ed25519_key(7);
        let session_key = ed25519_key(8);
        let auth = Authorization::for_vm::<SwapState>(9, 0, 20);
        let delegation = Delegation::session(
            acct_of(&owner_key),
            session_key.verifying_key().to_bytes(),
            0,
            20,
        );
        let Signed::Message(owner_payload) =
            delegation_bytes_as::<SwapState>(Scheme::Ed25519, 9, &delegation)
        else {
            unreachable!()
        };
        let owner = Credential::Ed25519 {
            key: owner_key.verifying_key().to_bytes(),
            signature: owner_key.sign(&owner_payload).to_bytes(),
        };
        let sign = |intent: &Intent| Delegated {
            delegation: delegation.clone(),
            owner: owner.clone(),
            session_signature: session_key
                .sign(&session_payload::<SwapState>(
                    &delegation.id(9, &auth.vm_id),
                    &auth,
                    intent,
                ))
                .to_bytes(),
        };

        let swap = Intent::SwapExactIn {
            account: delegation.account,
            asset_in: swapvm::types::XZEC,
            path: vec![1],
            amount_in: Fixed::whole(1),
            min_out: Fixed::ZERO,
        };
        let frame = crate::client::frame_delegated(&auth, &sign(&swap), &swap);
        let out = dispatch(&s, &req(OP_SUBMIT_DELEGATED, 9, &frame));
        assert_eq!(out[0], wire::STATUS_OK, "{}", String::from_utf8_lossy(&out));
        assert_eq!(s.node.lock().unwrap().state().seq(), 1);

        let transfer = Intent::Transfer {
            from: delegation.account,
            to: [0xAA; 32],
            asset: swapvm::types::XZEC,
            amount: Fixed::whole(1),
        };
        let frame = crate::client::frame_delegated(&auth, &sign(&transfer), &transfer);
        let out = dispatch(&s, &req(OP_SUBMIT_DELEGATED, 9, &frame));
        assert_eq!(out[0], wire::STATUS_ERR);
        assert!(String::from_utf8_lossy(&out).contains("OutOfScope"));
        assert_eq!(s.node.lock().unwrap().state().seq(), 1);
    }

    /// The published snapshot is a tree of hashes: no ids, no records.
    #[test]
    fn the_snapshot_publishes_leaves_and_nothing_else() {
        let s = server();
        {
            let mut n = s.node.lock().unwrap();
            let a = acct_of(&ed25519_key(1));
            n.submit_operator(Intent::AttestVaultBalance { asset: swapvm::types::XZEC, observed: Fixed::whole(5) }, 0);
            let idx = n.state().next_deposit_index(swapvm::types::XZEC);
            n.submit_operator(Intent::CreditDeposit { account: a, asset: swapvm::types::XZEC, amount: Fixed::whole(5), index: idx, external_ref: [1u8; 32] }, 0);
            let epoch = n.state().epoch();
            n.submit_operator(Intent::Checkpoint, 0);
            n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
            n.seal_now(1);
            n.anchor_now(1);
        }
        let out = dispatch(&s, &req(wire::OP_SNAPSHOT, 9, &[]));
        assert_eq!(out[0], wire::STATUS_OK, "{:?}", String::from_utf8_lossy(&out[3..]));
        let a = acct_of(&ed25519_key(1));
        assert!(!out.windows(32).any(|w| w == a), "an account id is in the published payload");
        let record = s.node.lock().unwrap().state().account_record(&a).unwrap();
        assert!(!out.windows(record.len()).any(|w| w == record.as_slice()), "a record is in the published payload");
    }

    /// A record is served to its holder and to nobody else.
    /// The mapping from an epoch to the Zcash transaction carrying its root,
    /// served from whatever copy of the index this node keeps — which on a
    /// replica is its own, so the claim can be checked against something that
    /// never sequenced anything.
    #[test]
    fn anchors_map_epochs_to_the_zcash_transactions_that_carry_them() {
        let dir = std::env::temp_dir().join(format!("zyn-anchors-rpc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = server();
        s.da_dir = Some(dir.clone());
        std::fs::create_dir_all(dir.join("chain-9")).unwrap();
        std::fs::write(
            dir.join(crate::publish::index_rel(9)),
            "7 ".to_string()
                + &"aa".repeat(32)
                + " "
                + &"bb".repeat(32)
                + " deadbeefcafe 4331685\n8 "
                + &"cc".repeat(32)
                + " "
                + &"dd".repeat(32)
                + " feedface0001 4331701\n",
        )
        .unwrap();

        let mut e = Encoder::new();
        e.u32(0);
        let b = body_of(&dispatch(&s, &req(OP_ANCHORS, 9, e.finish()))).to_vec();
        let mut d = Decoder::new(&b);
        assert_eq!(d.u32().unwrap(), 2, "both anchors");
        assert_eq!(d.u64().unwrap(), 7);
        assert_eq!(d.array::<32>().unwrap(), [0xaa; 32], "the root that was anchored");
        assert_eq!(d.array::<32>().unwrap(), [0xbb; 32]);
        let n = d.u16().unwrap() as usize;
        assert_eq!(d.take_bytes(n).unwrap(), b"deadbeefcafe", "the Zcash txid");
        assert_eq!(d.u64().unwrap(), 4331685);

        // A limit keeps only the newest, which is what a status strip wants.
        let mut e = Encoder::new();
        e.u32(1);
        let b = body_of(&dispatch(&s, &req(OP_ANCHORS, 9, e.finish()))).to_vec();
        let mut d = Decoder::new(&b);
        assert_eq!(d.u32().unwrap(), 1);
        assert_eq!(d.u64().unwrap(), 8, "the newest, not the oldest");
    }

    /// A node that keeps no bundles says so rather than reporting an empty
    /// history, which would read as "nothing has ever been anchored".
    #[test]
    fn a_node_without_bundles_refuses_to_report_an_empty_anchor_history() {
        let s = server();
        let mut e = Encoder::new();
        e.u32(0);
        let out = dispatch(&s, &req(OP_ANCHORS, 9, e.finish()));
        assert_eq!(out[0], wire::STATUS_ERR);
    }

    #[test]
    fn an_account_read_must_be_signed_by_its_holder() {
        use ed25519_dalek::Signer;
        let s = server();
        let k = ed25519_key(2);
        let a = acct_of(&k);
        s.node.lock().unwrap().submit_operator(Intent::Reblind { account: a, blind: [4u8; 32] }, 0);
        // Bare id: refused.
        assert_eq!(dispatch(&s, &req(OP_ACCOUNT, 9, &a))[0], wire::STATUS_ERR);
        // Signed by the holder: served.
        let epoch = s.node.lock().unwrap().state().epoch();
        let sig = k.sign(&read_challenge(9, &a, epoch)).to_bytes();
        let mut e = Encoder::new();
        e.bytes(&a).u64(epoch).u8(Scheme::Ed25519.tag()).bytes(k.verifying_key().as_bytes()).bytes(&sig);
        let out = dispatch(&s, &req(OP_ACCOUNT, 9, e.finish()));
        assert_eq!(out[0], wire::STATUS_OK, "{:?}", String::from_utf8_lossy(&out[3..]));
        // Signed by someone else for this account: refused.
        let other = ed25519_key(3);
        let sig = other.sign(&read_challenge(9, &a, epoch)).to_bytes();
        let mut e = Encoder::new();
        e.bytes(&a).u64(epoch).u8(Scheme::Ed25519.tag()).bytes(other.verifying_key().as_bytes()).bytes(&sig);
        assert_eq!(dispatch(&s, &req(OP_ACCOUNT, 9, e.finish()))[0], wire::STATUS_ERR);
    }

    /// A whole collection over the wire: the numbers a storefront needs, at
    /// every stage, from the ops a storefront actually has.
    /// The order book has to be readable by anyone, on a node that cannot be
    /// asked to sign anything — that is what lets a storefront or an explorer
    /// show it without being trusted, and it is why the op is unauthenticated.
    #[test]
    fn resting_offers_are_public_over_the_rpc() {
        let s = server();
        let maker = ed25519_key(11);
        let ma = acct_of(&maker);

        let (item, offer) = {
            let mut n = s.node.lock().unwrap();
            n.submit_operator(Intent::AttestVaultBalance { asset: swapvm::types::XZEC, observed: Fixed::whole(100) }, 0);
            let idx = n.state().next_deposit_index(swapvm::types::XZEC);
            n.submit_operator(Intent::CreditDeposit { account: ma, asset: swapvm::types::XZEC, amount: Fixed::whole(100), index: idx, external_ref: [41u8; 32] }, 0);
            let epoch = n.state().epoch();
            n.submit_operator(Intent::Checkpoint, 0);
            n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
            n.submit_operator(Intent::CreateCollection { creator: ma, symbol: swapvm::state::symbol(b"NAP"), cap: 1, fee_bps: 100 }, 0);
            let c = *n.state().collections.keys().next().unwrap();
            n.submit_operator(Intent::AdvanceCollection { creator: ma, collection: c, to: 1 }, 0);
            n.submit_operator(Intent::MintCollectionItem { creator: ma, collection: c, to: ma, symbol: swapvm::state::symbol(b"NAP"), content: [8u8; 32] }, 0);
            let item = n.state().tokens.iter().find(|(_, t)| t.collection == Some(c)).map(|(id, _)| *id).unwrap();
            n.submit_operator(Intent::AdvanceCollection { creator: ma, collection: c, to: 2 }, 0);
            n.submit_operator(Intent::AdvanceCollection { creator: ma, collection: c, to: 3 }, 0);
            let step = n.submit_operator(Intent::PlaceOffer {
                maker: ma,
                offer_asset: item,
                offer_amount: Fixed::ONE,
                want_asset: swapvm::types::XZEC,
                want_amount: Fixed::whole(7),
                expires_at_epoch: 4242,
            }, 0);
            assert!(!step.rejected(), "{:?}", step.receipts);
            let offer = *n.state().offers.keys().next().unwrap();
            (item, offer)
        };

        let b = body_of(&dispatch(&s, &req(OP_OFFERS, 9, &[]))).to_vec();
        let mut d = Decoder::new(&b);
        assert_eq!(d.u32().unwrap(), 1, "one resting offer");
        assert_eq!(d.u64().unwrap(), offer);
        assert_eq!(d.array::<32>().unwrap(), ma);
        assert_eq!(d.u32().unwrap(), item);
        assert_eq!(d.fixed().unwrap(), Fixed::ONE);
        assert_eq!(d.u32().unwrap(), swapvm::types::XZEC);
        assert_eq!(d.fixed().unwrap(), Fixed::whole(7), "the price anyone may take it at");
        assert_eq!(d.u64().unwrap(), 4242);
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn a_collection_reports_its_floor_and_its_items_over_the_rpc() {
        let s = server();
        let creator = ed25519_key(7);
        let buyer = acct_of(&ed25519_key(8));
        let ca = acct_of(&creator);

        // The sale runs and the pool fills, before any item exists.
        let (collection, item) = {
            let mut n = s.node.lock().unwrap();
            n.submit_operator(Intent::AttestVaultBalance { asset: swapvm::types::XZEC, observed: Fixed::whole(100) }, 0);
            let idx = n.state().next_deposit_index(swapvm::types::XZEC);
            n.submit_operator(Intent::CreditDeposit { account: ca, asset: swapvm::types::XZEC, amount: Fixed::whole(100), index: idx, external_ref: [31u8; 32] }, 0);
            let epoch = n.state().epoch();
            n.submit_operator(Intent::Checkpoint, 0);
            n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
            n.submit_operator(Intent::CreateCollection { creator: ca, symbol: swapvm::state::symbol(b"NAP"), cap: 2, fee_bps: 100 }, 0);
            let c = *n.state().collections.keys().next().unwrap();
            n.submit_operator(Intent::FundCollection { from: ca, collection: c, amount: Fixed::whole(20) }, 0);
            n.submit_operator(Intent::AdvanceCollection { creator: ca, collection: c, to: 1 }, 0);
            let step = n.submit_operator(Intent::MintCollectionItem { creator: ca, collection: c, to: buyer, symbol: swapvm::state::symbol(b"NAP"), content: [7u8; 32] }, 0);
            assert!(!step.rejected(), "{:?}", step.receipts);
            let item = n.state().tokens.iter().find(|(_, t)| t.collection == Some(c)).map(|(id, _)| *id).unwrap();
            (c, item)
        };

        let read = |out: Vec<u8>| -> Vec<u8> { body_of(&out).to_vec() };
        let one = |out: Vec<u8>| {
            let b = read(out);
            let mut d = Decoder::new(&b);
            assert_eq!(d.u32().unwrap(), 1, "one collection");
            let id = d.u32().unwrap();
            let _creator = d.array::<32>().unwrap();
            let _sym = d.array::<8>().unwrap();
            let (cap, minted, outstanding) = (d.u32().unwrap(), d.u32().unwrap(), d.u32().unwrap());
            let pool = d.fixed().unwrap();
            let fee_bps = d.u16().unwrap();
            let phase = d.u8().unwrap();
            let redeem = d.fixed().unwrap();
            (id, cap, minted, outstanding, pool, fee_bps, phase, redeem)
        };

        // Mid-sale: the pool is real, the floor is honestly zero.
        let (id, cap, minted, outstanding, pool, fee_bps, phase, redeem) =
            one(dispatch(&s, &req(OP_COLLECTIONS, 9, &[])));
        assert_eq!((id, cap, minted, outstanding), (collection, 2, 1, 1));
        assert_eq!(pool, Fixed::whole(20));
        assert_eq!(fee_bps, 100);
        assert_eq!(phase, 1, "minting");
        assert_eq!(redeem, Fixed::ZERO, "no floor before the market opens");

        // The item is identifiable as one, and names its collection.
        let b = read(dispatch(&s, &req(OP_ASSETS, 9, &[])));
        let mut d = Decoder::new(&b);
        let n = d.u32().unwrap();
        let mut found = None;
        for _ in 0..n {
            let aid = d.u32().unwrap();
            let _sym = d.array::<8>().unwrap();
            let _supply = d.fixed().unwrap();
            let _lp = d.u32().unwrap();
            let has = d.u8().unwrap() != 0;
            let content = d.array::<32>().unwrap();
            let coll = d.u32().unwrap();
            if aid == item {
                found = Some((has, content, coll));
            }
        }
        assert_eq!(found, Some((true, [7u8; 32], collection)), "the item carries its content and collection");

        // The market opens and the floor becomes the whole pool over one item.
        {
            let mut n = s.node.lock().unwrap();
            n.submit_operator(Intent::AdvanceCollection { creator: ca, collection, to: 2 }, 0);
            n.submit_operator(Intent::AdvanceCollection { creator: ca, collection, to: 3 }, 0);
        }
        let (.., phase, redeem) = one(dispatch(&s, &req(OP_COLLECTIONS, 9, &[])));
        assert_eq!(phase, 3, "live");
        assert_eq!(redeem, Fixed::whole(20), "20 over one outstanding item");
    }

    /// A sale: the maker signs the trade, the taker co-signs, one submit.
    #[test]
    fn a_co_signed_offer_trades_an_item_for_zec() {
        let s = server();
        let (maker, taker) = (ed25519_key(5), ed25519_key(6));
        let (ma, ta) = (acct_of(&maker), acct_of(&taker));
        let item;
        {
            let mut n = s.node.lock().unwrap();
            n.submit_operator(Intent::AttestVaultBalance { asset: swapvm::types::XZEC, observed: Fixed::whole(10) }, 0);
            for (i, (who, amt)) in [(ma, 2u64), (ta, 5u64)].into_iter().enumerate() {
                let idx = n.state().next_deposit_index(swapvm::types::XZEC);
                let step = n.submit_operator(Intent::CreditDeposit { account: who, asset: swapvm::types::XZEC, amount: Fixed::whole(amt as i64), index: idx, external_ref: [i as u8 + 10; 32] }, 0);
                assert!(!step.rejected());
            }
            let epoch = n.state().epoch();
            n.submit_operator(Intent::Checkpoint, 0);
            n.submit_operator(Intent::ConfirmAnchor { epoch }, 0);
            let step = n.submit_operator(Intent::MintItem { creator: ma, symbol: swapvm::state::symbol(b"ART"), supply: Fixed::whole(1), bond: Fixed::whole(1), content: [9u8; 32] }, 0);
            assert!(!step.rejected(), "{:?}", step.receipts);
            item = n.state().tokens.iter().find(|(_, t)| t.symbol == swapvm::state::symbol(b"ART")).map(|(id, _)| *id).unwrap();
        }
        let intent = Intent::AcceptOffer { maker: ma, taker: ta, offer_asset: item, offer_amount: Fixed::whole(1), want_asset: swapvm::types::XZEC, want_amount: Fixed::whole(3) };
        let epoch = s.node.lock().unwrap().state().epoch();
        let auth = Authorization::for_vm::<SwapState>(9, epoch, 100);
        // Only the maker's signature: refused.
        let mut e = Encoder::new();
        e.bytes(&auth.vm_id).u64(auth.valid_until_epoch).u8(1).bytes(&signed_cred(&maker, &auth, &intent));
        wire::encode_intent(&mut e, &intent);
        assert_eq!(dispatch(&s, &req(OP_SUBMIT_MULTI, 9, e.finish()))[0], wire::STATUS_ERR);
        // Both: the trade executes.
        let mut e = Encoder::new();
        e.bytes(&auth.vm_id).u64(auth.valid_until_epoch).u8(2).bytes(&signed_cred(&maker, &auth, &intent)).bytes(&signed_cred(&taker, &auth, &intent));
        wire::encode_intent(&mut e, &intent);
        let out = dispatch(&s, &req(OP_SUBMIT_MULTI, 9, e.finish()));
        assert_eq!(out[0], wire::STATUS_OK, "{:?}", String::from_utf8_lossy(&out[3..]));
        let n = s.node.lock().unwrap();
        assert_eq!(n.state().balance(&ta, item), Fixed::whole(1), "the taker holds the item");
        assert_eq!(n.state().balance(&ma, swapvm::types::XZEC), Fixed::whole(4), "the maker was paid 3, having posted a bond of 1 from 2");
    }

    /// The channel discloses, it does not redirect: a reveal is accepted only
    /// if it is the preimage of the destination the account already bound.
    #[test]
    fn a_reveal_must_match_the_accounts_binding() {
        use ed25519_dalek::Signer;
        let s = server();
        let k = ed25519_key(7);
        let a = acct_of(&k);
        let addr = zyn_custody::solana::base58_encode(&[3u8; 32]);
        let salt = [5u8; 32];
        let good = zyn_bridge::solana::commitment(&[3u8; 32], &salt);
        s.node.lock().unwrap().submit_operator(Intent::BindWithdrawal { account: a, destination: good }, 0);
        let epoch = s.node.lock().unwrap().state().epoch();
        let head = |e: &mut Encoder| {
            let sig = k.sign(&read_challenge(9, &a, epoch)).to_bytes();
            e.bytes(&a).u64(epoch).u8(Scheme::Ed25519.tag()).bytes(k.verifying_key().as_bytes()).bytes(&sig);
        };
        let mut e = Encoder::new();
        head(&mut e);
        e.u8(1).u16(addr.len() as u16).bytes(addr.as_bytes()).bytes(&[6u8; 32]);
        assert_eq!(dispatch(&s, &req(OP_REVEAL, 9, e.finish()))[0], wire::STATUS_ERR, "a wrong salt was accepted");
        let mut e = Encoder::new();
        head(&mut e);
        e.u8(1).u16(addr.len() as u16).bytes(addr.as_bytes()).bytes(&salt);
        assert_eq!(dispatch(&s, &req(OP_REVEAL, 9, e.finish()))[0], wire::STATUS_OK);
        let inbox = s.inbox.lock().unwrap();
        assert_eq!(inbox.solana.len(), 1);
        assert_eq!(inbox.lines.len(), 1);
    }
}
