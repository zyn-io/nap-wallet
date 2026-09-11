//! `zyn-custodian` — holds one FROST share of a vault key and signs with it
//! on request, without the share ever leaving this machine.
//!
//! A coordinator (the sequencer's settler) drives two rounds; this daemon
//! answers them against its one share. It cannot pay the vault alone — a
//! threshold of custodians must each answer — and it is the piece that turns
//! "all shares in one directory" into "no machine holds a quorum".
//!
//! One daemon may hold a share of the Zcash vault, of the Solana vault, or of
//! both: they are separate ceremonies with separate shares, served over
//! separate ops on the one socket. At least one must be configured.
//!
//! ```text
//!   ZYN_CUSTODY_SHARE         a Zcash share directory: one share-*.bin + public.bin
//!   ZYN_CUSTODY_SOLANA_SHARE  a Solana share directory, same shape
//!   ZYN_CUSTODY_LISTEN        host:port to serve on   (127.0.0.1:8110)
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use zyn_custody::ceremony::{Solana, Zcash};
use zyn_custody::custody_net::Custodian;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Load exactly one share from a directory. More than one would mean this
/// machine could reach a threshold by itself, which is the thing custody is
/// for — so refuse rather than serve it.
fn one_share<C: zyn_custody::frost_core::Ciphersuite>(dir: &PathBuf, what: &str) -> (String, zyn_custody::ceremony::ThresholdKeys<C>) {
    let shares = match zyn_custody::shares::load::<C>(dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zyn-custodian: cannot load the {} share from {}: {}", what, dir.display(), e);
            std::process::exit(1);
        }
    };
    if shares.len() != 1 {
        eprintln!(
            "zyn-custodian: {} holds {} {} shares — a custodian holds exactly one, so no machine ever has a quorum",
            dir.display(),
            shares.len(),
            what
        );
        std::process::exit(1);
    }
    let (id, keys) = shares.into_iter().next().unwrap();
    (AsRef::<[u8]>::as_ref(&id.serialize()).iter().map(|b| format!("{:02x}", b)).collect(), keys)
}

fn main() {
    let zcash_dir = std::env::var("ZYN_CUSTODY_SHARE").ok().map(PathBuf::from);
    let solana_dir = std::env::var("ZYN_CUSTODY_SOLANA_SHARE").ok().map(PathBuf::from);
    if zcash_dir.is_none() && solana_dir.is_none() {
        eprintln!("zyn-custodian: set ZYN_CUSTODY_SHARE and/or ZYN_CUSTODY_SOLANA_SHARE (a directory with one share-*.bin and public.bin)");
        std::process::exit(1);
    }
    let listen = std::env::var("ZYN_CUSTODY_LISTEN").unwrap_or_else(|_| "127.0.0.1:8110".into());

    let mut custodian = Custodian::default();
    let mut held = Vec::new();
    if let Some(dir) = &zcash_dir {
        let (id, keys) = one_share::<Zcash>(dir, "zcash");
        held.push(format!("zcash {}", id));
        custodian.zcash = Some(zyn_custody::custodian::Participant::new(keys));
    }
    if let Some(dir) = &solana_dir {
        let (id, keys) = one_share::<Solana>(dir, "solana");
        held.push(format!("solana {}", id));
        custodian.solana = Some(zyn_custody::custodian::solana::Participant::new(keys));
    }

    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zyn-custodian: cannot bind {}: {}", listen, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "zyn-custodian: share {} serving on {} — it signs a share on request and holds no quorum",
        held.join(", "),
        listen
    );
    zyn_custody::custody_net::serve(Arc::new(Mutex::new(custodian)), listener, now_secs);
}
