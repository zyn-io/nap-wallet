//! The intent journal: what a replayer needs that the state blob does not.
//!
//! A [`crate::store::Saved`] state proves *where* execution ended. It cannot
//! show *how* — the VM folds each intent into the epoch's `intent_root` and
//! keeps nothing else, so a saved root is an assertion, not an argument. This
//! journal keeps the argument: every intent the sequencer applied, with the
//! canonical authorization bytes the VM folds into its root, one file per
//! epoch.
//!
//! A replica that holds genesis plus these files reproduces every checkpoint
//! independently and compares it to what was anchored. That comparison is the
//! whole basis for trusting a root read off Zcash, and it is why a record is
//! written **before** the intent is applied: history must never outrun its own
//! evidence.
//!
//! ## Format
//!
//! ```text
//!   journal/chain-<id>/epoch-<N>.intents
//!     "ZYNJRNL2" ‖ chain_id u32 ‖ epoch u64
//!     ( seq u64 ‖ len u32 ‖ bytes )*        bytes == committed authorization + intent
//! ```
//!
//! A file is complete when its last record is the checkpoint intent that sealed
//! the epoch. Version 1 files contain bare VM intents and remain replayable for
//! pre-activation history. A version 1 open epoch must be sealed before an
//! upgraded writer starts; the formats are never mixed in one file.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use zyn_vm::read::Decoder;
use zyn_vm::spec::MicrochainVm;
use zyn_vm::Checkpoint;

const MAGIC_V1: &[u8; 8] = b"ZYNJRNL1";
const MAGIC_V2: &[u8; 8] = b"ZYNJRNL2";
const HEADER_LEN: usize = 8 + 4 + 8;
/// Refuse a single record larger than this before allocating for it.
const MAX_RECORD: usize = 1 << 20;

/// Where a chain's journal lives under a data directory.
pub fn dir_for(root: impl AsRef<Path>, chain_id: u32) -> PathBuf {
    root.as_ref()
        .join("journal")
        .join(format!("chain-{}", chain_id))
}

/// The file for one epoch.
pub fn epoch_path(root: impl AsRef<Path>, chain_id: u32, epoch: u64) -> PathBuf {
    dir_for(root, chain_id).join(format!("epoch-{}.intents", epoch))
}

/// Read the raw files for a range of epochs, in order. A missing epoch is an
/// error: a gap in the journal is a gap in the evidence.
pub fn files_for(
    root: impl AsRef<Path>,
    chain_id: u32,
    epochs: impl IntoIterator<Item = u64>,
) -> std::io::Result<Vec<(u64, Vec<u8>)>> {
    let mut out = Vec::new();
    for e in epochs {
        out.push((e, fs::read(epoch_path(&root, chain_id, e))?));
    }
    Ok(out)
}

/// The append side. One writer per chain; the sequencer owns it.
pub struct Journal {
    dir: PathBuf,
    chain_id: u32,
    open: Option<(u64, BufWriter<File>)>,
}

impl Journal {
    pub fn open(root: impl AsRef<Path>, chain_id: u32) -> std::io::Result<Journal> {
        let dir = dir_for(root, chain_id);
        fs::create_dir_all(&dir)?;
        Ok(Journal {
            dir,
            chain_id,
            open: None,
        })
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Append one intent. Switching epoch closes the previous file durably
    /// first, so an epoch file is never left half-written behind a newer one.
    pub fn record(&mut self, epoch: u64, seq: u64, encoded: &[u8]) -> std::io::Result<()> {
        if encoded.len() > MAX_RECORD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "intent too large",
            ));
        }
        if self.open.as_ref().map(|(e, _)| *e != epoch).unwrap_or(true) {
            self.sync()?;
            let path = self.dir.join(format!("epoch-{}.intents", epoch));
            let mut f = OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(&path)?;
            if f.metadata()?.len() == 0 {
                f.write_all(MAGIC_V2)?;
                f.write_all(&self.chain_id.to_be_bytes())?;
                f.write_all(&epoch.to_be_bytes())?;
            } else {
                let mut magic = [0u8; 8];
                f.read_exact(&mut magic)?;
                if &magic == MAGIC_V1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "legacy journal epoch must be sealed before authorization activation",
                    ));
                }
                if &magic != MAGIC_V2 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "unknown journal version",
                    ));
                }
            }
            self.open = Some((epoch, BufWriter::new(f)));
        }
        let (_, w) = self.open.as_mut().expect("opened above");
        w.write_all(&seq.to_be_bytes())?;
        w.write_all(&(encoded.len() as u32).to_be_bytes())?;
        w.write_all(encoded)?;
        Ok(())
    }

    /// Flush and fsync whatever is open. Called at every seal and on shutdown.
    pub fn sync(&mut self) -> std::io::Result<()> {
        if let Some((_, w)) = self.open.as_mut() {
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        Ok(())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        let _ = self.sync();
    }
}

/// One epoch's records, as read back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EpochFile {
    /// 1 contains a bare application intent; 2 contains committed authority.
    pub version: u8,
    pub chain_id: u32,
    pub epoch: u64,
    /// `(seq, encoded intent)`, strictly increasing by seq.
    pub records: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JournalError {
    NotAJournal,
    Truncated,
    /// Sequence numbers must strictly increase within a file.
    OutOfOrder,
    /// A record longer than the format allows.
    TooLong,
}

/// Parse one epoch file. Every read is bounds-checked; junk is refused, never
/// interpreted.
pub fn read_epoch(b: &[u8]) -> Result<EpochFile, JournalError> {
    if b.len() < HEADER_LEN {
        return Err(JournalError::NotAJournal);
    }
    let version = if &b[..8] == MAGIC_V1 {
        1
    } else if &b[..8] == MAGIC_V2 {
        2
    } else {
        return Err(JournalError::NotAJournal);
    };
    let chain_id = u32::from_be_bytes(b[8..12].try_into().unwrap());
    let epoch = u64::from_be_bytes(b[12..20].try_into().unwrap());
    let mut p = HEADER_LEN;
    let mut records = Vec::new();
    let mut last_seq: Option<u64> = None;
    while p < b.len() {
        if b.len() - p < 12 {
            return Err(JournalError::Truncated);
        }
        let seq = u64::from_be_bytes(b[p..p + 8].try_into().unwrap());
        let len = u32::from_be_bytes(b[p + 8..p + 12].try_into().unwrap()) as usize;
        p += 12;
        if len > MAX_RECORD {
            return Err(JournalError::TooLong);
        }
        if b.len() - p < len {
            return Err(JournalError::Truncated);
        }
        if last_seq.map(|l| seq <= l).unwrap_or(false) {
            return Err(JournalError::OutOfOrder);
        }
        last_seq = Some(seq);
        records.push((seq, b[p..p + len].to_vec()));
        p += len;
    }
    Ok(EpochFile {
        version,
        chain_id,
        epoch,
        records,
    })
}

/// What replay produced: the state at the end, and every checkpoint sealed on
/// the way — the things a verifier compares against an anchor.
#[derive(Clone, Debug)]
pub struct Replayed<V> {
    pub state: V,
    pub checkpoints: Vec<Checkpoint>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReplayError {
    /// The file is for another chain than the state being replayed.
    WrongChain { file: u32, state: u32 },
    /// The file's epoch is not the epoch the state is in.
    EpochMismatch { file: u64, state: u64 },
    /// A sequence number that does not follow the state's.
    SeqGap { expected: u64, got: u64 },
    /// Bytes the VM cannot read as an intent.
    Undecodable { epoch: u64, seq: u64 },
    /// A file that is not the last one ended without sealing its epoch.
    NoSeal { epoch: u64 },
    /// Authorization-aware history cannot be followed by a legacy epoch.
    VersionRollback { epoch: u64 },
    /// A committed authorization or signature did not reproduce.
    Unauthorised {
        epoch: u64,
        seq: u64,
        error: crate::verify::CommittedError,
    },
}

/// Apply every record in order from `start`, collecting the checkpoints.
///
/// The one function a verifier trusts: it is the VM's own `apply`, driven by
/// the VM's own encoding. Nothing here interprets an intent.
pub fn replay<V: MicrochainVm>(start: V, epochs: &[EpochFile]) -> Result<Replayed<V>, ReplayError> {
    let mut state = start;
    let mut checkpoints = Vec::new();
    let n = epochs.len();
    let mut saw_v2 = false;
    for (i, file) in epochs.iter().enumerate() {
        if file.version == 1 && saw_v2 {
            return Err(ReplayError::VersionRollback { epoch: file.epoch });
        }
        saw_v2 |= file.version == 2;
        if file.chain_id != state.chain_id() {
            return Err(ReplayError::WrongChain {
                file: file.chain_id,
                state: state.chain_id(),
            });
        }
        if file.epoch != state.epoch() {
            return Err(ReplayError::EpochMismatch {
                file: file.epoch,
                state: state.epoch(),
            });
        }
        let mut sealed_here = false;
        for (seq, bytes) in &file.records {
            let expected = state.seq() + 1;
            if *seq != expected {
                return Err(ReplayError::SeqGap {
                    expected,
                    got: *seq,
                });
            }
            let receipts = if file.version == 1 {
                let mut d = Decoder::new(bytes);
                let intent = match V::decode_intent(&mut d) {
                    Some(i) if d.remaining() == 0 => i,
                    _ => {
                        return Err(ReplayError::Undecodable {
                            epoch: file.epoch,
                            seq: *seq,
                        })
                    }
                };
                let receipts = state.apply(*seq, &intent);
                receipts
            } else {
                let authorized =
                    crate::verify::decode_authorized::<V>(bytes, &state).map_err(|error| {
                        ReplayError::Unauthorised {
                            epoch: file.epoch,
                            seq: *seq,
                            error,
                        }
                    })?;
                let intent = authorized.into_intent();
                let receipts = state.apply_committed(*seq, &intent, bytes);
                receipts
            };
            if let Some(cp) = V::sealed(&receipts) {
                checkpoints.push(cp);
                sealed_here = true;
            }
        }
        if !sealed_here && i + 1 < n {
            return Err(ReplayError::NoSeal { epoch: file.epoch });
        }
    }
    Ok(Replayed { state, checkpoints })
}

#[cfg(test)]
mod tests {
    use super::*;
    use swapvm::state::SwapState;
    use swapvm::tx::Intent;
    use swapvm::types::XZEC;
    use swapvm::{Fixed, Params};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zyn-journal-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// Run a small history through a journal and the live state together,
    /// returning the state, the checkpoints it sealed, and the journal root.
    fn history(name: &str) -> (SwapState, Vec<Checkpoint>, PathBuf) {
        let root = tmp(name);
        let mut j = Journal::open(&root, 5).unwrap();
        let mut s = SwapState::new(5, Params::v1());
        let observed = s.backing_of(XZEC).add(Fixed::whole(1_000)).unwrap();
        let mut cps = Vec::new();
        type Make = Box<dyn Fn(&SwapState) -> Intent>;
        let script: Vec<Make> = vec![
            Box::new(move |_| Intent::AttestVaultBalance {
                asset: XZEC,
                observed,
            }),
            Box::new(|s| Intent::next_deposit(s, [1u8; 32], XZEC, Fixed::whole(10), [0u8; 32])),
            Box::new(|_| Intent::Checkpoint),
            Box::new(|s| Intent::next_deposit(s, [2u8; 32], XZEC, Fixed::whole(20), [0u8; 32])),
            Box::new(|_| Intent::Checkpoint),
        ];
        for make in script {
            let i = make(&s);
            let seq = s.seq() + 1;
            let authorized = crate::verify::Authorized::operator(i);
            let committed = crate::verify::encode_authorized::<SwapState>(&authorized);
            let i = authorized.into_intent();
            j.record(s.epoch(), seq, &committed).unwrap();
            let r = s.apply_committed(seq, &i, &committed);
            if let Some(cp) = SwapState::sealed(&r) {
                cps.push(cp);
            }
        }
        j.sync().unwrap();
        (s, cps, root)
    }

    fn files(root: &Path, epochs: impl IntoIterator<Item = u64>) -> Vec<EpochFile> {
        files_for(root, 5, epochs)
            .unwrap()
            .into_iter()
            .map(|(_, b)| read_epoch(&b).unwrap())
            .collect()
    }

    #[test]
    fn records_round_trip_and_replay_reproduces_every_checkpoint() {
        let (live, cps, root) = history("roundtrip");
        let epochs = files(&root, [0, 1]);
        assert_eq!(epochs[0].records.len(), 3);
        assert_eq!(epochs[1].records.len(), 2);
        let out = replay(SwapState::new(5, Params::v1()), &epochs).unwrap();
        assert_eq!(
            out.checkpoints, cps,
            "replay must reproduce the sealed checkpoints"
        );
        assert_eq!(out.state.state_root(), live.state_root());
        assert_eq!(cps.len(), 2);
    }

    #[test]
    fn a_tampered_record_does_not_reproduce_the_checkpoint() {
        let (_, cps, root) = history("tamper");
        let mut epochs = files(&root, [0, 1]);
        // The deposit amount lives inside the second record of epoch 0.
        let last = epochs[0].records[1].1.len() - 1;
        epochs[0].records[1].1[last] ^= 0x01;
        match replay(SwapState::new(5, Params::v1()), &epochs) {
            Ok(out) => assert_ne!(
                out.checkpoints[0].state_root, cps[0].state_root,
                "a changed input must change the root"
            ),
            Err(ReplayError::Undecodable { .. }) => {}
            Err(e) => panic!("unexpected {:?}", e),
        }
    }

    #[test]
    fn a_gap_in_sequence_numbers_is_refused() {
        let (_, _, root) = history("gap");
        let mut epochs = files(&root, [0, 1]);
        epochs[0].records.remove(1);
        assert_eq!(
            replay(SwapState::new(5, Params::v1()), &epochs).unwrap_err(),
            ReplayError::SeqGap {
                expected: 2,
                got: 3
            }
        );
    }

    #[test]
    fn an_unsealed_middle_epoch_is_refused_and_a_trailing_open_one_is_not() {
        let (_, _, root) = history("seal");
        let mut epochs = files(&root, [0, 1]);
        epochs[1].records.pop(); // epoch 1 still open: fine as the last file
        assert!(replay(SwapState::new(5, Params::v1()), &epochs).is_ok());
        let mut cut = files(&root, [0, 1]);
        cut[0].records.pop(); // epoch 0 never sealed but epoch 1 follows: not fine
        assert!(matches!(
            replay(SwapState::new(5, Params::v1()), &cut),
            Err(ReplayError::NoSeal { epoch: 0 })
        ));
    }

    #[test]
    fn junk_is_refused_rather_than_read() {
        assert_eq!(read_epoch(b"nope").unwrap_err(), JournalError::NotAJournal);
        let (_, _, root) = history("junk");
        let mut b = fs::read(epoch_path(&root, 5, 0)).unwrap();
        b.truncate(b.len() - 3);
        assert_eq!(read_epoch(&b).unwrap_err(), JournalError::Truncated);
        // Rebuild the file with the second record's seq below the first.
        let o = fs::read(epoch_path(&root, 5, 0)).unwrap();
        let mut file = read_epoch(&o).unwrap();
        file.records[1].0 = 1;
        let mut re = Vec::new();
        re.extend_from_slice(MAGIC_V2);
        re.extend_from_slice(&5u32.to_be_bytes());
        re.extend_from_slice(&0u64.to_be_bytes());
        for (s, b) in &file.records {
            re.extend_from_slice(&s.to_be_bytes());
            re.extend_from_slice(&(b.len() as u32).to_be_bytes());
            re.extend_from_slice(b);
        }
        assert_eq!(read_epoch(&re).unwrap_err(), JournalError::OutOfOrder);
    }

    #[test]
    fn a_reopened_journal_appends_rather_than_overwrites() {
        let root = tmp("reopen");
        {
            let mut j = Journal::open(&root, 5).unwrap();
            j.record(0, 1, b"a").unwrap();
        }
        {
            let mut j = Journal::open(&root, 5).unwrap();
            j.record(0, 2, b"b").unwrap();
        }
        let f = read_epoch(&fs::read(epoch_path(&root, 5, 0)).unwrap()).unwrap();
        assert_eq!(f.records, vec![(1, b"a".to_vec()), (2, b"b".to_vec())]);
    }
}
