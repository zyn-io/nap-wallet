//! Bitcoin custody: a Taproot vault under FROST(secp256k1, Taproot) (DECISIONS §154).
//!
//! The vault is the group key of a t-of-n ceremony, used as a BIP-341 internal
//! key. Every deposit gets its own address: the same internal key tweaked by a
//! root derived from the depositor's Zyn deposit commitment — Bitcoin wallets
//! cannot attach a memo, so the address *is* the memo. Anyone can recompute an
//! address from the group key and a commitment; only the custodians, together,
//! can spend from it. Change and fee buffer sit at the vault's own key-path
//! address (BIP-86: no script tree).
//!
//! A spend signs each input's BIP-341 sighash with the tweak that input's
//! address was made with (`sign_with_tweak`), aggregated and checked against
//! the output key before it is put in a witness.

use std::collections::BTreeMap;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::{Secp256k1, XOnlyPublicKey};
use bitcoin::secp256k1::{schnorr, Message};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapNodeHash;
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::keys::Tweak;

use crate::ceremony::{Ceremony, CeremonyError, IdentifierFor, ThresholdKeys};
use crate::signing::Session;

/// The Taproot ciphersuite.
pub type Bitcoin = frost::Secp256K1Sha256TR;
pub type Id = IdentifierFor<Bitcoin>;
pub type Keys = ThresholdKeys<Bitcoin>;
pub type PublicPackage = frost_core::keys::PublicKeyPackage<Bitcoin>;
pub type Commitments = frost_core::round1::SigningCommitments<Bitcoin>;
pub type Package = frost_core::SigningPackage<Bitcoin>;
pub type Share = frost_core::round2::SignatureShare<Bitcoin>;

#[derive(Debug)]
pub enum BitcoinError {
    Key,
    Quorum(String),
    Signature,
    Funds(String),
    Chain(String),
}

impl std::fmt::Display for BitcoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BitcoinError::Key => write!(f, "the vault's public package is not a Taproot key"),
            BitcoinError::Quorum(m) => write!(f, "the custodians did not sign: {m}"),
            BitcoinError::Signature => write!(f, "the aggregated signature does not verify"),
            BitcoinError::Funds(m) => write!(f, "{m}"),
            BitcoinError::Chain(m) => write!(f, "{m}"),
        }
    }
}

/// A devnet/signet key in one process (every share on this machine).
pub fn ceremony<R: rand_core::RngCore + rand_core::CryptoRng>(threshold: u16, participants: u16, rng: &mut R) -> Result<BTreeMap<Id, Keys>, CeremonyError> {
    Ceremony::new(threshold, participants)?.run_for::<Bitcoin, R>(rng)
}

/// The vault's internal key: the group key, x-only.
pub fn internal_key(public: &PublicPackage) -> Result<XOnlyPublicKey, BitcoinError> {
    let bytes = public.verifying_key().serialize().map_err(|_| BitcoinError::Key)?;
    XOnlyPublicKey::from_slice(&bytes[bytes.len() - 32..]).map_err(|_| BitcoinError::Key)
}

/// The tweak root a deposit address is made with: BIP-340 tagged hash
/// "Zyn/BtcDeposit" of the deposit commitment. It stands where a script tree's
/// root would, so there is no script path — only the key path, the custodians'.
pub fn deposit_root(commitment: &[u8; 32]) -> [u8; 32] {
    let tag = sha256::Hash::hash(b"Zyn/BtcDeposit");
    let mut e = sha256::Hash::engine();
    e.input(tag.as_ref());
    e.input(tag.as_ref());
    e.input(commitment);
    sha256::Hash::from_engine(e).to_byte_array()
}

/// The address a deposit under `commitment` is paid to.
pub fn deposit_address(public: &PublicPackage, commitment: &[u8; 32], network: Network) -> Result<Address, BitcoinError> {
    let secp = Secp256k1::verification_only();
    Ok(Address::p2tr(&secp, internal_key(public)?, Some(TapNodeHash::from_byte_array(deposit_root(commitment))), network))
}

/// The vault's own address (change, fee buffer): key path only, BIP-86.
pub fn vault_address(public: &PublicPackage, network: Network) -> Result<Address, BitcoinError> {
    let secp = Secp256k1::verification_only();
    Ok(Address::p2tr(&secp, internal_key(public)?, None, network))
}

// ---------------------------------------------------------------------------
// The custodian's side.

pub mod participant {
    use super::*;
    use crate::custodian::{CustodyError, REQUEST_TTL_SECS};

    struct Live {
        message: Vec<u8>,
        root: Option<[u8; 32]>,
        session: Option<Session<Bitcoin>>,
        opened_at: u64,
    }

    /// One Taproot share, and the requests it has open. Like the Solana
    /// participant, it signs the message it committed to and nothing else; the
    /// tweak is fixed at round one too.
    pub struct Participant {
        keys: Keys,
        live: BTreeMap<u64, Live>,
    }

    impl Participant {
        pub fn new(keys: Keys) -> Participant {
            Participant { keys, live: BTreeMap::new() }
        }

        pub fn id(&self) -> Id {
            *self.keys.key_package.identifier()
        }

        pub fn round1<R: rand_core::RngCore + rand_core::CryptoRng>(
            &mut self,
            request_id: u64,
            message: Vec<u8>,
            root: Option<[u8; 32]>,
            now: u64,
            rng: &mut R,
        ) -> Result<Commitments, CustodyError> {
            self.drop_expired(now);
            if self.live.contains_key(&request_id) {
                return Err(CustodyError::AlreadyOpen);
            }
            let s = Session::begin(self.id(), &self.keys, rng);
            let c = s.commitments();
            self.live.insert(request_id, Live { message, root, session: Some(s), opened_at: now });
            Ok(c)
        }

        pub fn round2(&mut self, request_id: u64, package: &Package) -> Result<Share, CustodyError> {
            let mut req = self.live.remove(&request_id).ok_or(CustodyError::NoSuchRequest)?;
            if package.message().as_slice() != req.message.as_slice() {
                return Err(CustodyError::WrongMessage);
            }
            let session = req.session.take().ok_or(CustodyError::NoSuchRequest)?;
            // BIP-341: sign as the output key, tweaked by this input's root
            // (or the key-path-only tweak when there is none).
            let tweaked = Keys {
                key_package: self.keys.key_package.clone().tweak(req.root.as_ref()),
                public_package: self.keys.public_package.clone().tweak(req.root.as_ref()),
            };
            Ok(session.sign(&tweaked, package)?)
        }

        pub fn drop_expired(&mut self, now: u64) {
            self.live.retain(|_, r| now.saturating_sub(r.opened_at) < REQUEST_TTL_SECS);
        }
    }
}

// ---------------------------------------------------------------------------
// The coordinator's side.

/// The Taproot share-holders, wherever they are.
pub trait BitcoinQuorum {
    fn round1(&mut self, request_id: u64, message: &[u8], root: Option<[u8; 32]>) -> BTreeMap<Id, Commitments>;
    fn round2(&mut self, request_id: u64, chosen: &[Id], package: &Package) -> BTreeMap<Id, Share>;
}

/// Shares held in this process — tests and rehearsals.
pub struct LocalBitcoinQuorum {
    pub participants: BTreeMap<Id, participant::Participant>,
    pub now: u64,
}

impl BitcoinQuorum for LocalBitcoinQuorum {
    fn round1(&mut self, request_id: u64, message: &[u8], root: Option<[u8; 32]>) -> BTreeMap<Id, Commitments> {
        let now = self.now;
        self.participants
            .iter_mut()
            .filter_map(|(id, p)| p.round1(request_id, message.to_vec(), root, now, &mut rand::rngs::OsRng).ok().map(|c| (*id, c)))
            .collect()
    }
    fn round2(&mut self, request_id: u64, chosen: &[Id], package: &Package) -> BTreeMap<Id, Share> {
        self.participants
            .iter_mut()
            .filter(|(id, _)| chosen.contains(id))
            .filter_map(|(id, p)| p.round2(request_id, package).ok().map(|s| (*id, s)))
            .collect()
    }
}

/// One BIP-340 signature over `sighash`, by the quorum, for the output key
/// that `root` makes of the vault's internal key. Checked before it is returned.
pub fn sign_digest(quorum: &mut dyn BitcoinQuorum, public: &PublicPackage, threshold: usize, sighash: [u8; 32], root: Option<[u8; 32]>) -> Result<[u8; 64], BitcoinError> {
    let request_id = rand::random::<u64>();
    let commitments = quorum.round1(request_id, &sighash, root);
    if commitments.len() < threshold {
        return Err(BitcoinError::Quorum(format!("{} of {} committed", commitments.len(), threshold)));
    }
    let chosen: BTreeMap<Id, Commitments> = commitments.into_iter().take(threshold).collect();
    let ids: Vec<Id> = chosen.keys().cloned().collect();
    let package = Package::new(chosen, &sighash);
    let shares = quorum.round2(request_id, &ids, &package);
    if shares.len() < threshold {
        return Err(BitcoinError::Quorum(format!("{} of {} shares", shares.len(), threshold)));
    }
    let sig = frost::aggregate_with_tweak(&package, &shares, public, root.as_ref().map(|r| r.as_slice())).map_err(|e| BitcoinError::Quorum(format!("{e:?}")))?;
    let bytes = sig.serialize().map_err(|_| BitcoinError::Signature)?;
    let raw: [u8; 64] = bytes[bytes.len() - 64..].try_into().map_err(|_| BitcoinError::Signature)?;
    // The key the chain will check: the internal key tweaked by `root`.
    let secp = Secp256k1::verification_only();
    let output = internal_key(public)?.add_tweak(&secp, &tap_tweak(&internal_key(public)?, root)).map_err(|_| BitcoinError::Key)?.0;
    let s = schnorr::Signature::from_slice(&raw).map_err(|_| BitcoinError::Signature)?;
    secp.verify_schnorr(&s, &Message::from_digest(sighash), &output).map_err(|_| BitcoinError::Signature)?;
    Ok(raw)
}

fn tap_tweak(internal: &XOnlyPublicKey, root: Option<[u8; 32]>) -> bitcoin::secp256k1::Scalar {
    let t = bitcoin::taproot::TapTweakHash::from_key_and_tweak(*internal, root.map(TapNodeHash::from_byte_array));
    t.to_scalar()
}

// ---------------------------------------------------------------------------
// Spending.

/// A coin the vault holds: where it is, what it is worth, and the root its
/// address was made with (`None` for the vault's own address).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coin {
    pub outpoint: OutPoint,
    pub value: u64,
    pub root: Option<[u8; 32]>,
    pub script: ScriptBuf,
}

/// A payment out: to a script, an amount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pay {
    pub script: ScriptBuf,
    pub value: u64,
}

/// Outputs below this are refused by relays; a payout this small is refused
/// here rather than stuck.
pub const DUST: u64 = 546;
/// A Taproot key-path input's weight, and the rest, for fee estimates (vbytes).
const VB_INPUT: u64 = 58;
const VB_OVERHEAD: u64 = 11;

fn vb_output(script: &ScriptBuf) -> u64 {
    9 + script.len() as u64
}

/// An unsigned spend: coins in, payouts and change out, the fee at `rate`
/// sat/vB. Coins are taken largest first until the payouts and fee are met.
pub fn build(coins: &[Coin], pays: &[Pay], change: &ScriptBuf, rate: u64) -> Result<(Transaction, Vec<Coin>), BitcoinError> {
    if pays.is_empty() {
        return Err(BitcoinError::Funds("nothing to pay".into()));
    }
    if let Some(p) = pays.iter().find(|p| p.value < DUST) {
        return Err(BitcoinError::Funds(format!("a payout of {} sat is below dust", p.value)));
    }
    let want: u64 = pays.iter().map(|p| p.value).sum();
    let mut sorted = coins.to_vec();
    sorted.sort_by(|a, b| b.value.cmp(&a.value));
    let mut taken = Vec::new();
    let mut have = 0u64;
    let outs_vb: u64 = pays.iter().map(|p| vb_output(&p.script)).sum::<u64>() + vb_output(change);
    for c in sorted {
        let fee = rate * (VB_OVERHEAD + VB_INPUT * (taken.len() as u64 + 1) + outs_vb);
        taken.push(c.clone());
        have += c.value;
        if have >= want + fee {
            break;
        }
    }
    let fee = rate * (VB_OVERHEAD + VB_INPUT * taken.len() as u64 + outs_vb);
    if have < want + fee {
        return Err(BitcoinError::Funds(format!("the vault holds {have} sat; paying {want} sat needs {} with the fee", want + fee)));
    }
    let mut output: Vec<TxOut> = pays.iter().map(|p| TxOut { value: Amount::from_sat(p.value), script_pubkey: p.script.clone() }).collect();
    let rest = have - want - fee;
    if rest >= DUST {
        output.push(TxOut { value: Amount::from_sat(rest), script_pubkey: change.clone() });
    }
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: taken.iter().map(|c| TxIn { previous_output: c.outpoint, script_sig: ScriptBuf::new(), sequence: Sequence::ENABLE_RBF_NO_LOCKTIME, witness: Witness::new() }).collect(),
        output,
    };
    Ok((tx, taken))
}

/// Sign every input of `tx` (built by [`build`] from `coins`, in order).
pub fn sign(quorum: &mut dyn BitcoinQuorum, public: &PublicPackage, threshold: usize, mut tx: Transaction, coins: &[Coin]) -> Result<Transaction, BitcoinError> {
    let prevouts: Vec<TxOut> = coins.iter().map(|c| TxOut { value: Amount::from_sat(c.value), script_pubkey: c.script.clone() }).collect();
    let mut sighashes = Vec::new();
    {
        let mut cache = SighashCache::new(&tx);
        for i in 0..coins.len() {
            let h = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default).map_err(|e| BitcoinError::Chain(format!("{e}")))?;
            sighashes.push(h.to_byte_array());
        }
    }
    for (i, (h, c)) in sighashes.into_iter().zip(coins).enumerate() {
        let sig = sign_digest(quorum, public, threshold, h, c.root)?;
        tx.input[i].witness = Witness::from_slice(&[sig.as_slice()]);
    }
    Ok(tx)
}

pub fn txid(tx: &Transaction) -> Txid {
    tx.compute_txid()
}

pub fn raw_hex(tx: &Transaction) -> String {
    bitcoin::consensus::encode::serialize_hex(tx)
}

// ---------------------------------------------------------------------------
// The chain, through an Esplora API (mempool.space / blockstream compatible).

pub struct Esplora {
    base: String,
}

/// An output paying an address, as the explorer reports it.
#[derive(Clone, Debug)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub confirmed_height: Option<u64>,
}

impl Esplora {
    pub fn new(base: &str) -> Esplora {
        Esplora { base: base.trim_end_matches('/').to_string() }
    }

    fn get(&self, path: &str) -> Result<String, BitcoinError> {
        ureq::get(&format!("{}{}", self.base, path))
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .map_err(|e| BitcoinError::Chain(format!("{path}: {e}")))?
            .into_string()
            .map_err(|e| BitcoinError::Chain(format!("{path}: {e}")))
    }

    pub fn tip_height(&self) -> Result<u64, BitcoinError> {
        self.get("/blocks/tip/height")?.trim().parse().map_err(|_| BitcoinError::Chain("tip height".into()))
    }

    /// Unspent outputs at an address, confirmed or not.
    pub fn utxos(&self, address: &Address) -> Result<Vec<Utxo>, BitcoinError> {
        let v: serde_json::Value = serde_json::from_str(&self.get(&format!("/address/{address}/utxo"))?).map_err(|e| BitcoinError::Chain(format!("{e}")))?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|u| {
                        Some(Utxo {
                            txid: u.get("txid")?.as_str()?.parse().ok()?,
                            vout: u.get("vout")?.as_u64()? as u32,
                            value: u.get("value")?.as_u64()?,
                            confirmed_height: u.pointer("/status/block_height").and_then(|h| h.as_u64()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether a transaction is known, and at what height it confirmed.
    pub fn status(&self, txid: &Txid) -> Result<Option<Option<u64>>, BitcoinError> {
        match ureq::get(&format!("{}/tx/{txid}/status", self.base)).timeout(std::time::Duration::from_secs(20)).call() {
            Ok(r) => {
                let v: serde_json::Value = r.into_json().map_err(|e| BitcoinError::Chain(format!("{e}")))?;
                Ok(Some(v.get("block_height").and_then(|h| h.as_u64())))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(BitcoinError::Chain(format!("{e}"))),
        }
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid, BitcoinError> {
        let body = raw_hex(tx);
        let r = ureq::post(&format!("{}/tx", self.base)).timeout(std::time::Duration::from_secs(20)).send_string(&body);
        match r {
            Ok(r) => r.into_string().map_err(|e| BitcoinError::Chain(format!("{e}")))?.trim().parse().map_err(|_| BitcoinError::Chain("broadcast reply".into())),
            Err(ureq::Error::Status(code, r)) => Err(BitcoinError::Chain(format!("broadcast refused ({code}): {}", r.into_string().unwrap_or_default()))),
            Err(e) => Err(BitcoinError::Chain(format!("{e}"))),
        }
    }

    /// A fee rate (sat/vB) for confirmation within about `blocks` blocks.
    pub fn fee_rate(&self, blocks: u32) -> Result<u64, BitcoinError> {
        let v: serde_json::Value = serde_json::from_str(&self.get("/fee-estimates")?).map_err(|e| BitcoinError::Chain(format!("{e}")))?;
        let rate = v.get(blocks.to_string()).and_then(|r| r.as_f64()).unwrap_or(2.0);
        Ok((rate.ceil() as u64).max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quorum() -> (LocalBitcoinQuorum, PublicPackage) {
        let keys = ceremony(2, 3, &mut rand::rngs::OsRng).unwrap();
        let public = keys.values().next().unwrap().public_package.clone();
        let participants = keys.into_iter().map(|(id, k)| (id, participant::Participant::new(k))).collect();
        (LocalBitcoinQuorum { participants, now: 1 }, public)
    }

    #[test]
    fn deposit_addresses_are_the_vault_key_tweaked_by_the_commitment() {
        let (_, public) = quorum();
        let a = deposit_address(&public, &[1; 32], Network::Signet).unwrap();
        let b = deposit_address(&public, &[2; 32], Network::Signet).unwrap();
        assert_ne!(a, b);
        assert_eq!(a, deposit_address(&public, &[1; 32], Network::Signet).unwrap());
        assert!(a.to_string().starts_with("tb1p"));
        assert_ne!(vault_address(&public, Network::Signet).unwrap(), a);
    }

    #[test]
    fn a_spend_from_deposit_and_vault_coins_is_signed_by_two_of_three_and_verifies() {
        let (mut q, public) = quorum();
        let dep = deposit_address(&public, &[9; 32], Network::Signet).unwrap();
        let vault = vault_address(&public, Network::Signet).unwrap();
        let coins = vec![
            Coin { outpoint: OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 }, value: 50_000, root: Some(deposit_root(&[9; 32])), script: dep.script_pubkey() },
            Coin { outpoint: OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 1 }, value: 20_000, root: None, script: vault.script_pubkey() },
        ];
        let to = Pay { script: dep.script_pubkey(), value: 60_000 };
        let (tx, taken) = build(&coins, &[to], &vault.script_pubkey(), 2).unwrap();
        assert_eq!(taken.len(), 2);
        // A participant drops out: two of three still sign.
        let first = *q.participants.keys().next().unwrap();
        q.participants.remove(&first);
        let signed = sign(&mut q, &public, 2, tx, &taken).unwrap();
        // Verify every witness against the prevout's output key, as a node would.
        let prevouts: Vec<TxOut> = taken.iter().map(|c| TxOut { value: Amount::from_sat(c.value), script_pubkey: c.script.clone() }).collect();
        let secp = Secp256k1::verification_only();
        let mut cache = SighashCache::new(&signed);
        for (i, c) in taken.iter().enumerate() {
            let h = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default).unwrap();
            let key = XOnlyPublicKey::from_slice(&c.script.as_bytes()[2..34]).unwrap();
            let sig = schnorr::Signature::from_slice(&signed.input[i].witness[0]).unwrap();
            secp.verify_schnorr(&sig, &Message::from_digest(h.to_byte_array()), &key).unwrap();
        }
    }

    #[test]
    fn spends_refuse_dust_and_shortfalls() {
        let (_, public) = quorum();
        let vault = vault_address(&public, Network::Signet).unwrap();
        let coin = Coin { outpoint: OutPoint { txid: Txid::from_byte_array([3; 32]), vout: 0 }, value: 10_000, root: None, script: vault.script_pubkey() };
        assert!(build(&[coin.clone()], &[Pay { script: vault.script_pubkey(), value: 100 }], &vault.script_pubkey(), 1).is_err());
        assert!(build(&[coin], &[Pay { script: vault.script_pubkey(), value: 20_000 }], &vault.script_pubkey(), 1).is_err());
    }
}
