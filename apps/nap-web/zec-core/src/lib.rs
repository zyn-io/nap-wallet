//! Nap's Zcash wallet, for the browser.
//!
//! The desktop wallet (`zynzapd::wallet`) with its socket taken out. Keys,
//! scanning, the note trees and the payout builder are the same
//! `zyn_custody` code the desktop runs; what changes is who does the IO. The
//! desktop asks its block server directly. A browser cannot open a TCP
//! socket, so here the page carries the frames: this crate says what to ask
//! for (`*_request`), the page posts it to the block server's HTTP door, and
//! hands the reply back. Nothing leaves the page but those requests, and none
//! of them names a key or a shielded address.
//!
//! The saved state is the desktop's `ZYNWAL01` format byte for byte, so a
//! state written by one can be read by the other.

use orchard::bundle::BundleVersion;
use orchard::circuit::ProvingKey;
use orchard::keys::{
    FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey,
};
use orchard::ValuePool;
use serde_json::{json, Value};
use zcash_protocol::consensus::{Network, NetworkConstants, Parameters};
use zyn_custody::compact::{self, CompactBlock, Hit};
use zyn_custody::lightd::{decode, request, unwrap_reply, Utxo, NET_MAINNET, NET_TESTNET};
use zyn_custody::notes::{HeldNote, NoteStore};
use zyn_custody::payout::{self, Destination, Envelope, Payment};
use zyn_custody::shielded::VaultKeys;
use zyn_custody::transparent::{self, Receiver};

#[cfg(target_arch = "wasm32")]
mod web;

/// How far behind the tip a block must be before it is scanned. The
/// desktop's figure, so both see the same balance at the same moment.
pub const CONFIRMATIONS: u64 = 3;
const STATE_MAGIC: &[u8; 8] = b"ZYNWAL01";

pub fn network_named(name: &str) -> Result<Network, String> {
    match name {
        "mainnet" => Ok(Network::MainNetwork),
        "testnet" => Ok(Network::TestNetwork),
        other => Err(format!("{other} is not mainnet or testnet")),
    }
}

/// The ZIP-32 Orchard spending key for `account` of a BIP-39 phrase: what
/// desktop Nap derives from the same words (`KeyMaterial::spending_key`).
/// The page seals these 32 bytes; the phrase itself is not kept.
pub fn spending_key_from_phrase(
    phrase: &str,
    passphrase: &str,
    network: Network,
    account: u32,
) -> Result<[u8; 32], String> {
    let words = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.trim())
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let seed = words.to_seed(passphrase);
    let id = zip32::AccountId::try_from(account)
        .map_err(|_| "account must be below 2^31".to_string())?;
    let sk = SpendingKey::from_zip32_seed(&seed, network.coin_type(), id)
        .map_err(|e| format!("cannot derive the Zcash account: {e}"))?;
    Ok(*sk.to_bytes())
}

/// The transparent secret key at BIP-44 `m/44'/coin_type'/account'/0/0` of
/// a BIP-39 phrase: the desktop's receiver (`zynzapd::wallet::receiver`) and
/// the path other Zcash wallets derive from the same words, so funds at this
/// address can always be swept elsewhere. The page seals these 32 bytes
/// beside the Orchard key; the phrase itself is not kept.
pub fn transparent_key_from_phrase(
    phrase: &str,
    passphrase: &str,
    network: Network,
    account: u32,
) -> Result<[u8; 32], String> {
    let words = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.trim())
        .map_err(|e| format!("invalid recovery phrase: {e}"))?;
    let seed = words.to_seed(passphrase);
    let r = Receiver::derive(&network, &seed, account, 0)
        .ok_or("cannot derive the transparent key")?;
    Ok(r.secret().secret_bytes())
}

const NO_TRANSPARENT: &str = "this wallet has no transparent key yet";

/// One thing a sync saw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Received {
        pool: ValuePool,
        zatoshi: u64,
        height: u64,
        txid: [u8; 32],
        memo: String,
    },
    Spent {
        pool: ValuePool,
        zatoshi: u64,
        height: u64,
        txid: [u8; 32],
    },
}

impl Event {
    pub fn json(&self) -> Value {
        match self {
            Event::Received {
                pool,
                zatoshi,
                height,
                txid,
                memo,
            } => json!({"kind": "received", "pool": pool_name(*pool), "zatoshi": zatoshi,
                        "height": height, "txid": txid_hex(txid), "memo": memo}),
            Event::Spent {
                pool,
                zatoshi,
                height,
                txid,
            } => json!({"kind": "spent", "pool": pool_name(*pool), "zatoshi": zatoshi,
                        "height": height, "txid": txid_hex(txid)}),
        }
    }
}

fn pool_name(p: ValuePool) -> &'static str {
    match p {
        ValuePool::Orchard => "orchard",
        ValuePool::Ironwood => "ironwood",
    }
}

/// An output as `txid:index`, the txid as explorers show it.
fn outpoint(u: &Utxo) -> String {
    format!("{}:{}", txid_hex(&u.txid), u.index)
}

/// The txid as explorers show it: byte-reversed hex.
pub fn txid_hex(txid: &[u8; 32]) -> String {
    txid.iter().rev().map(|b| format!("{b:02x}")).collect()
}

/// A memo as text, as the desktop shows it: nothing for "no memo", UTF-8 as
/// typed, anything else as hex.
pub fn memo_text(memo: &[u8]) -> String {
    if memo.first() == Some(&0xF6) || memo.iter().all(|b| *b == 0) {
        return String::new();
    }
    let end = memo.iter().rposition(|b| *b != 0).map(|p| p + 1).unwrap_or(0);
    match std::str::from_utf8(&memo[..end]) {
        Ok(t) if !t.chars().any(|c| c.is_control() && c != '\n') => t.to_string(),
        _ => format!(
            "0x{}",
            memo[..end].iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    }
}

/// Blocks that have been read but not yet applied: the compact hits say
/// which full transactions to fetch, and the blocks wait for them.
struct Pending {
    blocks: Vec<CompactBlock>,
    hits: Vec<Hit>,
    /// Distinct txids with a hit, in block order.
    wanted: Vec<[u8; 32]>,
    fetched: Vec<Option<Vec<u8>>>,
}

pub struct Wallet {
    network: Network,
    sk: SpendingKey,
    fvk: FullViewingKey,
    keys: VaultKeys,
    ivk: PreparedIncomingViewingKey,
    birthday: u64,
    orchard: Option<NoteStore>,
    ironwood: Option<NoteStore>,
    pending: Option<Pending>,
    /// The notes the last built transaction spends, until it is broadcast.
    unsent: Option<(ValuePool, Vec<HeldNote>)>,
    /// Building a proving key takes seconds; keep the ones built.
    proving: Vec<(BundleVersion, ProvingKey)>,
    /// The transparent receiver, when the page has its key.
    transparent: Option<Receiver>,
    /// The outputs the last UTXOS reply listed, less those already being
    /// shielded: exactly what [`Self::build_shield`] sweeps.
    utxos: Vec<Utxo>,
}

impl Wallet {
    pub fn new(spending_key: [u8; 32], network: Network) -> Result<Wallet, String> {
        let sk = Option::<SpendingKey>::from(SpendingKey::from_bytes(spending_key))
            .ok_or("not a valid spending key")?;
        let fvk = FullViewingKey::from(&sk);
        Ok(Wallet {
            network,
            keys: VaultKeys::from_full_viewing_key(fvk.clone()),
            ivk: PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
            sk,
            fvk,
            birthday: 0,
            orchard: None,
            ironwood: None,
            pending: None,
            unsent: None,
            proving: Vec::new(),
            transparent: None,
            utxos: Vec::new(),
        })
    }

    /// Give the wallet its transparent key (from [`transparent_key_from_phrase`]).
    pub fn set_transparent(&mut self, secret: [u8; 32]) -> Result<(), String> {
        self.transparent = Some(Receiver::from_secret(secret).ok_or("not a valid transparent key")?);
        self.utxos.clear();
        Ok(())
    }

    /// The transparent address (`t1…`, or `tm…` on testnet), when there is a key.
    pub fn transparent_address(&self) -> Option<String> {
        self.transparent
            .as_ref()
            .map(|r| r.encoded(self.network.network_type()))
    }

    /// A UTXOS request for this wallet's transparent address. The one request
    /// that names an address (`lightd` explains the cost); it names only this
    /// public one, never the shielded address or a key.
    pub fn utxos_request(&self) -> Result<Vec<u8>, String> {
        Ok(request::utxos(&self.transparent_address().ok_or(NO_TRANSPARENT)?))
    }

    /// Read a UTXOS body. `exclude` lists outpoints (`txid:index`, txid as
    /// explorers show it) a shield already spent that the chain has not mined
    /// yet, so they are neither shown nor swept twice. Returns what is there
    /// and what sweeping it would land, from `transparent::plan`.
    pub fn take_utxos(&mut self, body: &[u8], exclude: &[String]) -> Result<Value, String> {
        self.transparent.as_ref().ok_or(NO_TRANSPARENT)?;
        let mut list = decode::utxos(body).map_err(|e| e.to_string())?;
        list.retain(|u| !exclude.contains(&outpoint(u)));
        let plan = transparent::plan(&list);
        let out = json!({
            "address": self.transparent_address(),
            "total": plan.total,
            "fee": if list.is_empty() { 0 } else { plan.fee },
            "net": if list.is_empty() { 0 } else { plan.net },
            "count": plan.count,
            "utxos": list.iter().map(|u| json!({"outpoint": outpoint(u), "value": u.value, "height": u.height})).collect::<Vec<_>>(),
        });
        self.utxos = list;
        Ok(out)
    }

    /// Build, prove and sign the sweep of every output [`Self::take_utxos`]
    /// last read into one shielded note at this wallet's own address. Slow,
    /// like a payment. Nothing in the note stores changes: the note arrives
    /// through the next sync like any other.
    ///
    /// Into **Ironwood** whenever the branch has it: from NU6.3 the Orchard
    /// value balance cannot go negative, so value cannot enter Orchard at all
    /// and the network refuses a t→Orchard sweep (DECISIONS §45.6). Orchard
    /// is used only under a branch that predates Ironwood.
    pub fn build_shield(&mut self, tip: u64, branch: u32) -> Result<Vec<u8>, String> {
        let receiver = self.transparent.as_ref().ok_or(NO_TRANSPARENT)?;
        if self.utxos.is_empty() {
            return Err("nothing on the transparent address to shield".into());
        }
        let env = Envelope::next(self.network, tip, branch).map_err(|e| e.to_string())?;
        let version = env
            .bundle_version_for(ValuePool::Ironwood)
            .or_else(|_| env.bundle_version_for(ValuePool::Orchard))
            .map_err(|e| e.to_string())?;
        let to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));
        let sealed = transparent::shield(
            &[receiver],
            &self.utxos,
            to,
            &self.fvk,
            &SpendAuthorizingKey::from(&self.sk),
            ovk,
            version,
            &env,
            rand::rngs::OsRng,
        )
        .map_err(|e| format!("cannot shield: {e}"))?;
        Ok(sealed.bytes)
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The unified address, encoded for this wallet's network.
    pub fn address(&self) -> String {
        self.keys.address(0, self.network.network_type())
    }

    pub fn has_state(&self) -> bool {
        self.orchard.is_some() && self.ironwood.is_some()
    }

    pub fn birthday(&self) -> u64 {
        self.birthday
    }

    fn stores(&self) -> Result<(&NoteStore, &NoteStore), String> {
        match (&self.orchard, &self.ironwood) {
            (Some(o), Some(i)) => Ok((o, i)),
            _ => Err("the wallet has no scan state yet".into()),
        }
    }

    fn store_mut(&mut self, pool: ValuePool) -> Result<&mut NoteStore, String> {
        match pool {
            ValuePool::Orchard => self.orchard.as_mut(),
            ValuePool::Ironwood => self.ironwood.as_mut(),
        }
        .ok_or_else(|| "the wallet has no scan state yet".into())
    }

    /// Fresh trees, from the server's tree states at `birthday - 1` (the
    /// bodies of two TREESTATE replies, Orchard then Ironwood).
    pub fn seed(&mut self, birthday: u64, orchard: &[u8], ironwood: &[u8]) -> Result<(), String> {
        let at = birthday.saturating_sub(1);
        let tree = |body: &[u8]| -> Result<NoteStore, String> {
            let (root, frontier) = decode::tree_state(body).map_err(|e| e.to_string())?;
            if frontier.is_empty() {
                // The pool is not active yet: its tree starts empty.
                return Ok(NoteStore::empty_at(at));
            }
            let store = NoteStore::from_frontier(&frontier, at).map_err(|e| format!("{e:?}"))?;
            if store.root_bytes() != Some(root) {
                return Err("the seeded tree does not match the server's root".into());
            }
            Ok(store)
        };
        let o = tree(orchard)?;
        let i = tree(ironwood)?;
        self.birthday = birthday;
        self.orchard = Some(o);
        self.ironwood = Some(i);
        self.pending = None;
        Ok(())
    }

    pub fn synced_to(&self) -> Option<u64> {
        let (o, i) = self.stores().ok()?;
        Some(o.synced_to()?.min(i.synced_to()?))
    }

    /// The first height the next sync asks for.
    pub fn next_height(&self) -> u64 {
        self.synced_to().map(|h| h + 1).unwrap_or(self.birthday)
    }

    /// (orchard, ironwood, in flight) in zatoshi.
    pub fn balance(&self) -> (u64, u64, u64) {
        match self.stores() {
            Ok((o, i)) => (
                o.balance(),
                i.balance(),
                o.in_flight_balance() + i.in_flight_balance(),
            ),
            Err(_) => (0, 0, 0),
        }
    }

    pub fn notes(&self) -> Vec<Value> {
        let mut out = Vec::new();
        if let Ok((o, i)) = self.stores() {
            for (pool, s) in [(ValuePool::Ironwood, i), (ValuePool::Orchard, o)] {
                for h in s.held() {
                    out.push(json!({"pool": pool_name(pool), "zatoshi": h.value(),
                                    "height": h.height, "txid": txid_hex(&h.txid)}));
                }
            }
        }
        out.sort_by_key(|n| std::cmp::Reverse(n["height"].as_u64().unwrap_or(0)));
        out
    }

    pub fn encode_state(&self) -> Result<Vec<u8>, String> {
        let (o, i) = self.stores()?;
        let mut out = STATE_MAGIC.to_vec();
        out.push(if self.network == Network::MainNetwork {
            NET_MAINNET
        } else {
            NET_TESTNET
        });
        out.extend_from_slice(&self.birthday.to_le_bytes());
        for s in [o, i] {
            let enc = s.encode();
            out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
            out.extend_from_slice(&enc);
        }
        Ok(out)
    }

    pub fn load_state(&mut self, b: &[u8]) -> Result<(), String> {
        let bad = || "not a Nap wallet state".to_string();
        if b.get(..8).ok_or_else(bad)? != STATE_MAGIC {
            return Err(bad());
        }
        let net = *b.get(8).ok_or_else(bad)?;
        let want = if self.network == Network::MainNetwork {
            NET_MAINNET
        } else {
            NET_TESTNET
        };
        if net != want {
            return Err("that state belongs to the other network".into());
        }
        let birthday = u64::from_le_bytes(b.get(9..17).ok_or_else(bad)?.try_into().map_err(|_| bad())?);
        let mut at = 17;
        let mut read = || -> Result<NoteStore, String> {
            let n = u32::from_le_bytes(b.get(at..at + 4).ok_or_else(bad)?.try_into().map_err(|_| bad())?)
                as usize;
            at += 4;
            let s = NoteStore::decode(b.get(at..at + n).ok_or_else(bad)?).ok_or_else(bad)?;
            at += n;
            Ok(s)
        };
        let o = read()?;
        let i = read()?;
        self.birthday = birthday;
        self.orchard = Some(o);
        self.ironwood = Some(i);
        self.pending = None;
        Ok(())
    }

    /// Read a BLOCKS reply body. Blocks must start at [`Self::next_height`]
    /// and run in order; anything past `to` is left for later. Returns how
    /// many full transactions to fetch before [`Self::apply`].
    pub fn take_blocks(&mut self, body: &[u8], to: u64) -> Result<usize, String> {
        self.stores()?;
        let mut blocks = decode::blocks(body).map_err(|e| e.to_string())?;
        blocks.retain(|b| b.height <= to);
        let mut expect = self.next_height();
        for b in &blocks {
            if b.height != expect {
                return Err(format!(
                    "the server sent block {} where {} was expected",
                    b.height, expect
                ));
            }
            expect += 1;
        }
        let mut hits = Vec::new();
        let mut wanted: Vec<[u8; 32]> = Vec::new();
        for b in &blocks {
            let found = compact::scan(b, &self.ivk);
            for h in &found {
                if !wanted.contains(&h.txid) {
                    wanted.push(h.txid);
                }
            }
            hits.extend(found.into_iter().map(|h| (b.height, h)));
        }
        let n = wanted.len();
        self.pending = Some(Pending {
            blocks,
            hits: hits.into_iter().map(|(_, h)| h).collect(),
            fetched: vec![None; n],
            wanted,
        });
        Ok(n)
    }

    /// The txid (internal byte order) of the `i`th transaction to fetch.
    pub fn wanted(&self, i: usize) -> Option<[u8; 32]> {
        self.pending.as_ref()?.wanted.get(i).copied()
    }

    /// A TX reply body, for the `i`th wanted transaction.
    pub fn give_transaction(&mut self, i: usize, body: &[u8]) -> Result<(), String> {
        let raw = decode::transaction(body).map_err(|e| e.to_string())?;
        let p = self.pending.as_mut().ok_or("no blocks are waiting")?;
        *p.fetched.get_mut(i).ok_or("no such transaction was asked for")? = Some(raw);
        Ok(())
    }

    /// Apply the waiting blocks: trees, received notes, spends. The desktop
    /// wallet's `scan_block`, block by block.
    pub fn apply(&mut self) -> Result<Vec<Event>, String> {
        let p = self.pending.take().ok_or("no blocks are waiting")?;
        if p.fetched.iter().any(Option::is_none) {
            let missing = p.fetched.iter().filter(|f| f.is_none()).count();
            self.pending = Some(p);
            return Err(format!("{missing} transaction(s) still to fetch"));
        }
        let fvk = self.fvk.clone();
        let mut events = Vec::new();
        for block in &p.blocks {
            let (mut o, mut i) = (
                self.orchard.take().ok_or("no scan state")?,
                self.ironwood.take().ok_or("no scan state")?,
            );
            let r = scan_block(&self.keys, &fvk, block, &p, &mut o, &mut i, &mut events);
            self.orchard = Some(o);
            self.ironwood = Some(i);
            r?;
        }
        Ok(events)
    }

    fn proving_key(&mut self, version: BundleVersion) -> &ProvingKey {
        if let Some(i) = self.proving.iter().position(|(v, _)| *v == version) {
            return &self.proving[i].1;
        }
        self.proving.push((version, payout::proving_key(version)));
        &self.proving.last().expect("just pushed").1
    }

    /// Build, prove and sign one payment on a chain whose tip is `tip`, where
    /// the server says the next block is under consensus branch `branch`.
    /// Refuses when this build would sign for another branch — a network
    /// upgrade it predates. Returns the raw transaction; nothing is spent in
    /// the store until [`Self::confirm_sent`] says the server took it.
    pub fn build_payment(
        &mut self,
        to: &str,
        zatoshi: u64,
        memo: &str,
        tip: u64,
        branch: u32,
    ) -> Result<Vec<u8>, String> {
        let to = payout::parse_destination(to.trim(), self.network).ok_or_else(|| {
            format!(
                "not a {} address",
                if self.network == Network::MainNetwork { "mainnet" } else { "testnet" }
            )
        })?;
        if zatoshi == 0 {
            return Err("amount is zero".into());
        }
        if memo.len() > 512 {
            return Err("memo longer than 512 bytes".into());
        }
        let mut field = [0u8; 512];
        field[..memo.len()].copy_from_slice(memo.as_bytes());
        if memo.is_empty() {
            field[0] = 0xF6;
        }
        let mut payment = Payment::new(to, zatoshi);
        payment.memo = field;
        let env = Envelope::next(self.network, tip, branch).map_err(|e| e.to_string())?;
        let change_to = self.fvk.address_at(0u32, Scope::External);
        let ovk = Some(self.fvk.to_ovk(Scope::External));
        let mut built = None;
        for pool in [ValuePool::Ironwood, ValuePool::Orchard] {
            let Ok(version) = env.bundle_version_for(pool) else {
                continue;
            };
            if matches!(to, Destination::Shielded(_)) && !version.default_flags().cross_address_enabled()
            {
                continue; // Orchard cannot pay a shielded address (NU6.3)
            }
            let store = match pool {
                ValuePool::Orchard => self.orchard.as_ref(),
                ValuePool::Ironwood => self.ironwood.as_ref(),
            }
            .ok_or("the wallet has no scan state yet")?;
            match payout::build(
                store,
                &self.fvk,
                ovk.clone(),
                &[payment.clone()],
                change_to,
                version,
                rand::rngs::OsRng,
            ) {
                Ok(p) => {
                    built = Some((p, version, pool));
                    break;
                }
                Err(payout::PayoutError::Notes(_)) => continue,
                Err(e) => return Err(format!("cannot build: {e}")),
            }
        }
        let Some((mut p, version, pool)) = built else {
            let (o, i, _) = self.balance();
            return Err(format!(
                "no pool can cover {zatoshi} zat (Ironwood {i} zat, Orchard {o} zat; a shielded recipient needs Ironwood)"
            ));
        };
        let sighash = p.sighash(&env).map_err(|e| e.to_string())?;
        p.finalize_io(sighash, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        let pk = self.proving_key(version);
        p.prove(pk, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        let ask = SpendAuthorizingKey::from(&self.sk);
        if payout::sign_with_key(&mut p, sighash, &ask, rand::rngs::OsRng) == 0 {
            return Err("nothing was signed".into());
        }
        let sealed = p.extract(sighash, &env, rand::rngs::OsRng).map_err(|e| e.to_string())?;
        self.unsent = Some((pool, sealed.spent));
        Ok(sealed.bytes)
    }

    /// The server accepted the last built transaction: its notes leave the
    /// store now, and the next sync confirms it from their nullifiers.
    pub fn confirm_sent(&mut self) -> Result<(), String> {
        let (pool, spent) = self.unsent.take().ok_or("nothing is waiting to be sent")?;
        let store = self.store_mut(pool)?;
        for n in &spent {
            store.spend(n.position);
        }
        Ok(())
    }
}

fn scan_block(
    keys: &VaultKeys,
    fvk: &FullViewingKey,
    block: &CompactBlock,
    p: &Pending,
    o: &mut NoteStore,
    i: &mut NoteStore,
    events: &mut Vec<Event>,
) -> Result<(), String> {
    o.begin_block(block.height);
    i.begin_block(block.height);
    for t in &block.txs {
        let hit_here = p.hits.iter().any(|h| h.txid == t.txid && h.tx_index == t.index);
        // The full transaction, only when something in it is ours: that is
        // what turns a compact hit into a spendable note with its memo.
        let full = if hit_here {
            let at = p.wanted.iter().position(|w| *w == t.txid).ok_or("a hit was not fetched")?;
            let raw = p.fetched[at].as_ref().ok_or("a hit was not fetched")?;
            keys.scan_actions_lenient(raw, t.txid, block.height).ok()
        } else {
            None
        };
        let mut ours = full
            .as_ref()
            .map(|s| s.actions.iter().filter(|a| a.ours.is_some()))
            .into_iter()
            .flatten();
        for (pool, list) in [(ValuePool::Orchard, &t.orchard), (ValuePool::Ironwood, &t.ironwood)] {
            let store: &mut NoteStore = match pool {
                ValuePool::Orchard => o,
                ValuePool::Ironwood => i,
            };
            for out in list {
                let act = out.to_action().ok_or("malformed output in a compact block")?;
                if let Some(spent) = store.spend_nullifier(&act.nullifier(), fvk) {
                    events.push(Event::Spent {
                        pool,
                        zatoshi: spent.value(),
                        height: block.height,
                        txid: t.txid,
                    });
                }
                let mine = p.hits.iter().any(|h| {
                    h.txid == t.txid && h.tx_index == t.index && h.pool == pool && h.cmx == out.cmx
                });
                let pos = store.append(&act.cmx(), mine);
                if mine {
                    let a = ours
                        .find(|a| a.pool == pool && a.cmx == act.cmx())
                        .ok_or("a compact hit did not decrypt in the full transaction")?;
                    if let (Some(note), Some(pos)) = (a.ours, pos) {
                        events.push(Event::Received {
                            pool,
                            zatoshi: note.value().inner(),
                            height: block.height,
                            txid: t.txid,
                            memo: a.memo.as_deref().map(memo_text).unwrap_or_default(),
                        });
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

/// Strip a reply's status byte, or read the server's refusal.
pub fn reply_body(reply: &[u8]) -> Result<Vec<u8>, String> {
    unwrap_reply(reply).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The vectors `zynzapd::wallet` pins for the same phrase. If these
    /// drift, the browser shows an empty wallet to someone whose ZEC is
    /// sitting at the address their desktop Nap gave out.
    #[test]
    fn the_browser_derives_the_desktop_spending_keys() {
        assert_eq!(
            hex(&spending_key_from_phrase(WORDS, "", Network::MainNetwork, 0).unwrap()),
            "ba36a915cf195348f4f8bcd584e2635735778190071db2f2af78d80b44a97bcb"
        );
        assert_eq!(
            hex(&spending_key_from_phrase(WORDS, "", Network::TestNetwork, 0).unwrap()),
            "13548ce4ac2ec6cc6b93a8f66f50ddce51e9e156cc084d3cef279873446f1b1b"
        );
    }

    /// The transparent key is BIP-44 `m/44'/coin'/0'/0/0` of the BIP-39 seed:
    /// the same receiver `zyn_custody::transparent::Receiver::derive` gives
    /// desktop Nap for these words. The addresses are pinned so a change to
    /// either side shows here; `tests/zec.test.mjs` checks the same two
    /// against an independent BIP-32 implementation.
    #[test]
    fn the_transparent_key_is_bip44_account_zero_index_zero() {
        let seed = bip39::Mnemonic::parse_in(bip39::Language::English, WORDS).unwrap().to_seed("");
        for (net, addr) in [
            (Network::MainNetwork, MAIN_T),
            (Network::TestNetwork, TEST_T),
        ] {
            let k = transparent_key_from_phrase(WORDS, "", net, 0).unwrap();
            let derived = Receiver::derive(&net, &seed, 0, 0).unwrap();
            assert_eq!(k, derived.secret().secret_bytes());
            let mut w = Wallet::new(spending_key_from_phrase(WORDS, "", net, 0).unwrap(), net).unwrap();
            assert_eq!(w.transparent_address(), None);
            assert!(w.utxos_request().is_err());
            w.set_transparent(k).unwrap();
            assert_eq!(w.transparent_address().as_deref(), Some(addr));
        }
        assert_ne!(
            transparent_key_from_phrase(WORDS, "", Network::MainNetwork, 1).unwrap(),
            transparent_key_from_phrase(WORDS, "", Network::MainNetwork, 0).unwrap(),
            "account 1 is another address"
        );
    }

    const MAIN_T: &str = "t1dUDJ62ANtmebE8drFg7g2MWYwXHQ6Xu3F";
    const TEST_T: &str = "tmBsTi2xWTjUdEXnuTceL7fecEQKeWaPDJd";

    fn p2pkh(addr: &str, net: Network) -> Vec<u8> {
        let a = payout::transparent_address(addr, net).unwrap();
        let zcash_transparent::address::TransparentAddress::PublicKeyHash(h) = a else { panic!() };
        let mut s = vec![0x76, 0xa9, 0x14];
        s.extend_from_slice(&h);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    fn testnet_wallet() -> Wallet {
        let net = Network::TestNetwork;
        let mut w = Wallet::new(spending_key_from_phrase(WORDS, "", net, 0).unwrap(), net).unwrap();
        w.set_transparent(transparent_key_from_phrase(WORDS, "", net, 0).unwrap()).unwrap();
        let mut empty = vec![0u8; 32];
        empty.extend_from_slice(&0u32.to_le_bytes());
        w.seed(4_380_000, &empty, &empty).unwrap();
        w
    }

    /// What is on the address, less what a shield already spent, and what
    /// sweeping it would land: the fee is ZIP-317's for the inputs plus two
    /// padded shielded actions.
    #[test]
    fn utxos_are_planned_and_a_pending_shield_is_left_out() {
        let mut w = testnet_wallet();
        let script = p2pkh(TEST_T, Network::TestNetwork);
        let u = |i: u8, value| Utxo { txid: [i; 32], index: i as u32, value, height: 4_380_010, script: script.clone() };
        let body = unwrap_reply(&zyn_custody::lightd::reply::utxos(&[u(1, 100_000), u(2, 50_000)])).unwrap();
        let all = w.take_utxos(&body, &[]).unwrap();
        assert_eq!(all["total"], 150_000);
        assert_eq!(all["count"], 2);
        assert_eq!(all["fee"], 20_000);
        assert_eq!(all["net"], 130_000);
        let first = all["utxos"][0]["outpoint"].as_str().unwrap().to_string();
        assert_eq!(first, format!("{}:1", "01".repeat(32)));
        let rest = w.take_utxos(&body, &[first]).unwrap();
        assert_eq!(rest["total"], 50_000);
        assert_eq!(rest["fee"], 15_000);
        let none = w.take_utxos(&unwrap_reply(&zyn_custody::lightd::reply::utxos(&[])).unwrap(), &[]).unwrap();
        assert_eq!((none["total"].as_u64(), none["fee"].as_u64(), none["net"].as_u64()), (Some(0), Some(0), Some(0)));
        const NU6_3: u32 = 0x37a5_165b;
        assert!(w.build_shield(4_380_100, NU6_3).unwrap_err().contains("nothing"));
    }

    /// A real sweep: built, proved and signed into one Ironwood note at the
    /// wallet's own address, with the transparent input spent and the fee
    /// left to the miner. Dust the fee would eat is refused before proving.
    #[test]
    fn a_shield_sweeps_into_ironwood_at_our_own_address() {
        use zcash_primitives::transaction::Transaction;
        let mut w = testnet_wallet();
        let script = p2pkh(TEST_T, Network::TestNetwork);
        const NU6_3: u32 = 0x37a5_165b;
        let dust = Utxo { txid: [3; 32], index: 0, value: 9_000, height: 4_380_010, script: script.clone() };
        w.take_utxos(&unwrap_reply(&zyn_custody::lightd::reply::utxos(&[dust])).unwrap(), &[]).unwrap();
        assert!(w.build_shield(4_380_100, NU6_3).unwrap_err().contains("fee"));

        let coin = Utxo { txid: [4; 32], index: 1, value: 100_000, height: 4_380_010, script };
        w.take_utxos(&unwrap_reply(&zyn_custody::lightd::reply::utxos(&[coin])).unwrap(), &[]).unwrap();
        let raw = w.build_shield(4_380_100, NU6_3).unwrap();
        let tx = Transaction::read(&raw[..], zcash_protocol::consensus::BranchId::try_from(NU6_3).unwrap()).unwrap();
        let t = tx.transparent_bundle().expect("a transparent input");
        assert_eq!(t.vin.len(), 1);
        assert!(t.vout.is_empty(), "nothing stays transparent");
        assert!(tx.orchard_bundle().is_none(), "nothing enters Orchard");
        let iw = tx.ironwood_bundle().expect("an Ironwood bundle");
        assert_eq!(i64::from(*iw.value_balance()), -85_000, "100,000 in, 15,000 fee");
        // The note is ours: our own viewing key decrypts it.
        let scanned = w.keys.scan_actions_lenient(&raw, *tx.txid().as_ref(), 4_380_101).unwrap();
        let mine: u64 = scanned.actions.iter().filter_map(|a| a.ours.as_ref()).map(|n| n.value().inner()).sum();
        assert_eq!(mine, 85_000);
    }

    #[test]
    fn addresses_are_encoded_for_their_network() {
        for (net, prefix) in [(Network::MainNetwork, "u1"), (Network::TestNetwork, "utest1")] {
            let sk = spending_key_from_phrase(WORDS, "", net, 0).unwrap();
            let w = Wallet::new(sk, net).unwrap();
            assert!(w.address().starts_with(prefix), "{}", w.address());
        }
    }

    #[test]
    fn a_state_round_trips_in_the_desktop_format() {
        let sk = spending_key_from_phrase(WORDS, "", Network::TestNetwork, 0).unwrap();
        let mut w = Wallet::new(sk, Network::TestNetwork).unwrap();
        // Two "no tree yet" replies: an all-zero root and an empty frontier.
        let mut empty = vec![0u8; 32];
        empty.extend_from_slice(&0u32.to_le_bytes());
        w.seed(4_380_000, &empty, &empty).unwrap();
        let bytes = w.encode_state().unwrap();
        assert_eq!(&bytes[..8], STATE_MAGIC);
        assert_eq!(bytes[8], NET_TESTNET);
        let mut back = Wallet::new(sk, Network::TestNetwork).unwrap();
        back.load_state(&bytes).unwrap();
        assert_eq!(back.birthday(), 4_380_000);
        assert_eq!(back.synced_to(), Some(4_379_999));
        assert_eq!(back.next_height(), 4_380_000);
        let mut other = Wallet::new(sk, Network::MainNetwork).unwrap();
        assert!(other.load_state(&bytes).unwrap_err().contains("other network"));
    }

    #[test]
    fn blocks_must_start_where_the_wallet_stopped() {
        let sk = spending_key_from_phrase(WORDS, "", Network::TestNetwork, 0).unwrap();
        let mut w = Wallet::new(sk, Network::TestNetwork).unwrap();
        let mut empty = vec![0u8; 32];
        empty.extend_from_slice(&0u32.to_le_bytes());
        w.seed(100, &empty, &empty).unwrap();
        let block = |h: u64| CompactBlock { height: h, hash: [0u8; 32], txs: Vec::new() }.encode();
        let reply = |hs: &[u64]| {
            let mut b = (hs.len() as u32).to_le_bytes().to_vec();
            for h in hs {
                let e = block(*h);
                b.extend_from_slice(&(e.len() as u32).to_le_bytes());
                b.extend_from_slice(&e);
            }
            b
        };
        assert!(w.take_blocks(&reply(&[101]), 200).unwrap_err().contains("expected"));
        assert_eq!(w.take_blocks(&reply(&[100, 101, 102]), 101).unwrap(), 0);
        assert!(w.apply().unwrap().is_empty());
        assert_eq!(w.synced_to(), Some(101));
        assert_eq!(w.next_height(), 102);
    }

    #[test]
    fn a_payment_needs_an_address_on_this_network_and_money() {
        let sk = spending_key_from_phrase(WORDS, "", Network::TestNetwork, 0).unwrap();
        let mut w = Wallet::new(sk, Network::TestNetwork).unwrap();
        let mut empty = vec![0u8; 32];
        empty.extend_from_slice(&0u32.to_le_bytes());
        w.seed(4_380_000, &empty, &empty).unwrap();
        let main = Wallet::new(spending_key_from_phrase(WORDS, "", Network::MainNetwork, 0).unwrap(), Network::MainNetwork)
            .unwrap()
            .address();
        const NU6_3: u32 = 0x37a5_165b;
        assert!(w.build_payment(&main, 1000, "", 4_380_100, NU6_3).unwrap_err().contains("testnet"));
        let own = w.address();
        assert!(w.build_payment(&own, 0, "", 4_380_100, NU6_3).unwrap_err().contains("zero"));
        assert!(w.build_payment(&own, 1000, "", 4_380_100, NU6_3).unwrap_err().contains("no pool can cover"));
        assert!(w.confirm_sent().is_err());
    }

    #[test]
    fn a_payment_is_not_signed_for_an_upgrade_this_build_does_not_know() {
        let sk = spending_key_from_phrase(WORDS, "", Network::TestNetwork, 0).unwrap();
        let mut w = Wallet::new(sk, Network::TestNetwork).unwrap();
        let mut empty = vec![0u8; 32];
        empty.extend_from_slice(&0u32.to_le_bytes());
        w.seed(4_380_000, &empty, &empty).unwrap();
        let own = w.address();
        let nu7 = w.build_payment(&own, 1000, "", 4_380_100, payout::NU7_BRANCH_ID).unwrap_err();
        assert!(nu7.contains("NU7") && nu7.contains("Nothing was signed"), "{}", nu7);
        let silent = w.build_payment(&own, 1000, "", 4_380_100, 0).unwrap_err();
        assert!(silent.contains("did not say"), "{}", silent);
        assert!(w.confirm_sent().is_err());
    }
}
