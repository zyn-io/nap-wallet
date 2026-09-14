//! `zyn-lightd` — compact blocks for wallets, from a Zebra node.
//!
//! One per network. Reads whole blocks from Zebra, keeps their compact form
//! on disk, and serves ranges of it to any wallet that asks. Understands v6
//! transactions and both shielded pools, which is why it exists (see
//! `zyn_custody::compact`). No keys, no addresses, no accounts: a wallet
//! scans on its own device.
//!
//! ```sh
//! ZYN_LIGHTD_NETWORK=testnet ZYN_LIGHTD_ZEBRA=127.0.0.1:18232 \
//! ZYN_LIGHTD_LISTEN=0.0.0.0:8098 ZYN_LIGHTD_DATA=/var/zyn/lightd zyn-lightd
//! ```

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

use zcash_primitives::block::Block;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network, NetworkUpgrade, Parameters};
use zyn_custody::compact::CompactBlock;
use zyn_custody::lightd::*;
use zyn_custody::zebra::{Network as ZebraNet, Zebra};

struct Server {
    zebra: Zebra,
    network: Network,
    data: PathBuf,
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    let network = match env("ZYN_LIGHTD_NETWORK", "testnet").as_str() {
        "mainnet" => Network::MainNetwork,
        "testnet" => Network::TestNetwork,
        other => {
            eprintln!(
                "zyn-lightd: ZYN_LIGHTD_NETWORK={} is not mainnet or testnet",
                other
            );
            std::process::exit(2)
        }
    };
    let zebra_addr = env("ZYN_LIGHTD_ZEBRA", "127.0.0.1:18232");
    let (host, port) = zebra_addr
        .rsplit_once(':')
        .unwrap_or((&zebra_addr, "18232"));
    let znet = if network == Network::MainNetwork {
        ZebraNet::Mainnet
    } else {
        ZebraNet::Testnet
    };
    let zebra = Zebra::connect_reader(host, port.parse().unwrap_or(18232), None, znet)
        .expect("zebra client");
    let tip = zebra.block_count().unwrap_or_else(|e| {
        eprintln!("zyn-lightd: Zebra at {} not answering: {}", zebra_addr, e);
        std::process::exit(1)
    });
    let data = PathBuf::from(env("ZYN_LIGHTD_DATA", "./lightd-data"));
    std::fs::create_dir_all(&data).expect("data dir");
    let listen = env("ZYN_LIGHTD_LISTEN", "127.0.0.1:8098");
    let listener = TcpListener::bind(&listen).expect("bind");
    eprintln!(
        "zyn-lightd: {:?} via {} at height {}, serving on {}",
        network, zebra_addr, tip, listen
    );
    let server = Arc::new(Server {
        zebra,
        network,
        data,
    });
    for stream in listener.incoming().flatten() {
        let s = Arc::clone(&server);
        std::thread::spawn(move || {
            let _ = handle(&s, stream);
        });
    }
}

fn handle(s: &Server, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    loop {
        let req = match read_frame(&mut stream, 4 << 20) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let reply = dispatch(s, &req);
        write_frame(&mut stream, &reply)?;
    }
}

fn dispatch(s: &Server, req: &[u8]) -> Vec<u8> {
    let request = match Request::decode(req) {
        Ok(r) => r,
        Err(e) => return reply::err(e),
    };
    match request {
        Request::Info => {
            let ci = match s.zebra.chain_info() {
                Ok(c) => c,
                Err(e) => return reply::err(&e.to_string()),
            };
            let branch = u32::from(BranchId::for_height(
                &s.network,
                BlockHeight::from_u32(ci.blocks as u32),
            ));
            reply::info(Info {
                network: if s.network == Network::MainNetwork {
                    NET_MAINNET
                } else {
                    NET_TESTNET
                },
                tip: ci.blocks,
                branch,
                estimated: ci.estimated,
            })
        }
        Request::Blocks { from, count } => {
            let tip = match s.zebra.block_count() {
                Ok(t) => t,
                Err(e) => return reply::err(&e.to_string()),
            };
            let to = (from + count as u64 - 1).min(tip);
            let mut blocks = Vec::new();
            for h in from..=to {
                match compact_block(s, h) {
                    Ok(b) => blocks.push(b),
                    // A short reply is fine; a wrong one is not. The
                    // client asks again from where it stopped.
                    Err(e) => {
                        if blocks.is_empty() {
                            return reply::err(&e);
                        } else {
                            break;
                        }
                    }
                }
            }
            reply::blocks(&blocks)
        }
        Request::Utxos(address) => match s.zebra.address_utxos(&address) {
            Ok(list) => reply::utxos(&list),
            Err(e) => reply::err(&e.to_string()),
        },
        Request::Transaction(txid) => {
            let mut disp = txid;
            disp.reverse();
            let hex: String = disp.iter().map(|b| format!("{:02x}", b)).collect();
            match s.zebra.raw_transaction_bytes(&hex) {
                Ok(raw) => reply::transaction(&raw),
                Err(e) => reply::err(&e.to_string()),
            }
        }
        Request::Send(raw) => {
            let hex: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
            match s.zebra.send_raw_transaction(&hex) {
                Ok(txid) => reply::sent(&txid),
                Err(e) => reply::err(&e.to_string()),
            }
        }
        Request::TreeState { height, pool } => {
            // Below the pool's activation there is no tree to seed from;
            // say so rather than relaying whatever the node answers.
            let upgrade = match pool {
                orchard::ValuePool::Orchard => NetworkUpgrade::Nu5,
                orchard::ValuePool::Ironwood => NetworkUpgrade::Nu6_3,
            };
            let active = s
                .network
                .activation_height(upgrade)
                .map(u32::from)
                .unwrap_or(u32::MAX) as u64;
            if height < active {
                return reply::no_tree();
            }
            match s.zebra.tree_state_of(height, pool) {
                Ok(ts) => reply::tree_state(ts.final_root, &ts.final_state),
                Err(e) => reply::err(&e.to_string()),
            }
        }
    }
}

/// The compact form of one block, from the cache or from Zebra (and then
/// into the cache). Files are grouped a thousand to a directory so the
/// data dir stays listable.
fn compact_block(s: &Server, height: u64) -> Result<Vec<u8>, String> {
    let dir = s.data.join(format!("{}", height / 1000));
    let path = dir.join(format!("{}.cb", height));
    if let Ok(bytes) = std::fs::read(&path) {
        if CompactBlock::decode(&bytes).is_some() {
            return Ok(bytes);
        }
    }
    let raw = s.zebra.raw_block(height).map_err(|e| e.to_string())?;
    let block = Block::read(&raw[..], &s.network)
        .map_err(|e| format!("block {} does not parse: {}", height, e))?;
    let bytes = CompactBlock::from_block(height, &block).encode();
    let _ = std::fs::create_dir_all(&dir);
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &bytes)
        .and_then(|_| std::fs::rename(&tmp, &path))
        .is_err()
    {
        eprintln!("zyn-lightd: could not cache block {}", height);
    }
    Ok(bytes)
}
