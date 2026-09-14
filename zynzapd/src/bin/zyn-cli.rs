//! `zyn-cli` — the smallest client that can move value through a Zyn node.
//!
//! Enough to run the testnet loop by hand: make a key, learn its account and
//! deposit memo, watch the node, bind a withdrawal destination and request an
//! exit. Signs with a local ed25519 key (`Scheme::Ed25519`) over the same
//! payload a wallet would sign, and speaks the node's framed RPC directly.
//!
//! ```text
//!   zyn-cli keygen   <key-file>
//!   zyn-cli account  <key-file>                 -> account id, hex
//!   zyn-cli memo     <key-file>                 -> ZYN1:<hex>, for a Zcash deposit
//!   zyn-cli status   <host:port> <chain-id>
//!   zyn-cli pools    <host:port> <chain-id>
//!   zyn-cli quote    <host:port> <chain-id> <asset-in> <pool[,pool…]> <amount>
//!   zyn-cli create-pool   <host:port> <chain-id> <key-file> <asset-a> <amount-a> <asset-b> <amount-b> [fee-bps]
//!   zyn-cli add-liquidity <host:port> <chain-id> <key-file> <pool> <max0> <max1>
//!   zyn-cli remove-liquidity <host:port> <chain-id> <key-file> <pool> <shares>
//!   zyn-cli swap     <host:port> <chain-id> <key-file> <asset-in> <pool[,pool…]> <amount-in> <min-out>
//!   zyn-cli balance  <host:port> <chain-id> <key-file>            (a signed read: only the holder can see it)
//!   zyn-cli transfer <host:port> <chain-id> <key-file> <to-account-hex> <asset> <amount>
//!   zyn-cli shield   <host:port> <chain-id> <key-file>            (set a fresh blind on the account's published leaf)
//!   zyn-cli mint-item <host:port> <chain-id> <key-file> <symbol> <supply> <bond-zec> <content-hex32>
//!   zyn-cli offer    <host:port> <chain-id> <key-file> <give-asset> <give-amount> <want-asset> <want-amount> <taker-account-hex>
//!                    -> a signed offer, one line, to hand to the taker
//!   zyn-cli accept   <host:port> <chain-id> <key-file> <offer-line>   (co-signs and submits)
//!   zyn-cli bind     <host:port> <chain-id> <key-file> <address> <salt-hex>     (utest1… or tm…)
//!   zyn-cli withdraw <host:port> <chain-id> <key-file> <zec> <address> <salt-hex>
//!   zyn-cli reveal   <key-file> <t-address> <salt-hex>   -> a line for ZYN_ZEBRA_REVEALS
//!   zyn-cli bind-sol     <host:port> <chain-id> <key-file> <solana-address> <salt-hex>
//!   zyn-cli withdraw-sol <host:port> <chain-id> <key-file> <asset-id> <sol> <solana-address> <salt-hex>
//!   zyn-cli withdraw-item <host:port> <chain-id> <key-file> <asset-id> <solana-address> <salt-hex>   (a mirrored NFT back)
//!   zyn-cli reveal-sol   <key-file> <solana-address> <salt-hex>   -> a line for ZYN_SOLANA_REVEALS
//!   zyn-cli reveal-submit <host:port> <chain-id> <key-file> <address> <salt-hex>   (sends it to the node, signed)
//! ```
//!
//! The destination is committed as `keccak(kind ‖ hash160 ‖ salt)`; the node
//! never sees the address. The operator learns it from the reveal line.

use std::io::{Read, Write};
use std::net::TcpStream;

use ed25519_dalek::{Signer, SigningKey};
use swapvm::state::SwapState;
use swapvm::tx::Intent;
use swapvm::types::XZEC;
use swapvm::{wire, Fixed};
use zcash_protocol::consensus::Network;
use zyn_vm::auth::{account_of, signed_bytes_as, Authorization, Scheme, Signed};
use zyn_vm::commit::Encoder;
use zyn_vm::read::Decoder;
use zynzapd::rpc::{read_challenge, OP_ACCOUNT, OP_REVEAL, OP_SUBMIT, OP_SUBMIT_MULTI};
use zynzapd::settle::{parse_destination, zcash_commitment, ZcashDestination};

const ZAT: i128 = 10_000_000_000;

fn die(msg: &str) -> ! {
    eprintln!("zyn-cli: {}", msg);
    std::process::exit(1)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex32(s: &str) -> [u8; 32] {
    if s.len() != 64 {
        die("expected 64 hex characters");
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or_else(|_| die("not hex"));
    }
    out
}
fn key(path: &str) -> SigningKey {
    let bytes =
        std::fs::read(path).unwrap_or_else(|e| die(&format!("cannot read {}: {}", path, e)));
    let seed: [u8; 32] = bytes
        .try_into()
        .unwrap_or_else(|_| die("a key file is 32 bytes"));
    SigningKey::from_bytes(&seed)
}
fn account(k: &SigningKey) -> [u8; 32] {
    account_of(Scheme::Ed25519, k.verifying_key().as_bytes())
}

fn call(addr: &str, frame: &[u8]) -> Vec<u8> {
    let mut s =
        TcpStream::connect(addr).unwrap_or_else(|e| die(&format!("cannot reach {}: {}", addr, e)));
    s.write_all(&(frame.len() as u32).to_be_bytes()).unwrap();
    s.write_all(frame).unwrap();
    let mut len = [0u8; 4];
    s.read_exact(&mut len).unwrap_or_else(|_| die("no reply"));
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body)
        .unwrap_or_else(|_| die("truncated reply"));
    if body.first() == Some(&wire::STATUS_ERR) {
        let n = u16::from_be_bytes([body[1], body[2]]) as usize;
        die(&format!(
            "node refused: {}",
            String::from_utf8_lossy(&body[3..3 + n])
        ));
    }
    body[1..].to_vec()
}

struct Status {
    health: Vec<(String, u64, bool, String)>,
    seq: u64,
    epoch: u64,
    root: [u8; 32],
    backing: Fixed,
    pools: u32,
    accounts: u32,
}

fn status(addr: &str, chain: u32) -> Status {
    let mut e = Encoder::new();
    e.u8(wire::OP_STATUS).u32(chain);
    let body = call(addr, e.finish());
    let mut d = Decoder::new(&body);
    let mut st = Status {
        health: Vec::new(),
        seq: d.u64().unwrap_or_else(|_| die("bad status")),
        epoch: d.u64().unwrap_or_else(|_| die("bad status")),
        root: d.hash().unwrap_or_else(|_| die("bad status")),
        backing: d.fixed().unwrap_or_else(|_| die("bad status")),
        pools: d.u32().unwrap_or_else(|_| die("bad status")),
        accounts: d.u32().unwrap_or_else(|_| die("bad status")),
    };
    if let Ok(n) = d.u32() {
        for _ in 0..n {
            let name = d
                .u16()
                .ok()
                .and_then(|l| d.take_bytes(l as usize).ok())
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default();
            let to = d.u64().unwrap_or(0);
            let down = d.u8().unwrap_or(0) != 0;
            let _fails = d.u32().unwrap_or(0);
            let err = d
                .u16()
                .ok()
                .and_then(|l| d.take_bytes(l as usize).ok())
                .map(|b| String::from_utf8_lossy(b).to_string())
                .unwrap_or_default();
            st.health.push((name, to, down, err));
        }
    }
    st
}

fn submit(addr: &str, chain: u32, k: &SigningKey, intent: Intent) {
    let now = status(addr, chain).epoch;
    let auth = Authorization::for_vm::<SwapState>(chain, now, 100);
    let payload = match signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, &intent) {
        Signed::Message(m) => m,
        Signed::Prehash(h) => h.to_vec(),
    };
    let sig = k.sign(&payload).to_bytes();
    let mut e = Encoder::new();
    e.u8(OP_SUBMIT)
        .u32(chain)
        .bytes(&auth.vm_id)
        .u64(auth.valid_until_epoch)
        .u8(Scheme::Ed25519.tag())
        .bytes(k.verifying_key().as_bytes())
        .bytes(&sig);
    wire::encode_intent(&mut e, &intent);
    let body = call(addr, e.finish());
    let mut d = Decoder::new(&body);
    let seq = d.u64().unwrap_or(0);
    let epoch = d.u64().unwrap_or(0);
    let _root = d.hash().unwrap_or([0; 32]);
    let count = d.u32().unwrap_or(0);
    let first = d.u8().unwrap_or(0);
    if first == 12 {
        let code = d.u8().unwrap_or(0);
        die(&format!("rejected at seq {} (reject code {})", seq, code));
    }
    println!(
        "accepted: seq {} epoch {} ({} receipt(s))",
        seq, epoch, count
    );
}

/// A decimal amount in whole units, e.g. `0.05`, as a `Fixed`.
fn fixed_of(s: &str) -> Fixed {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let whole: i128 = whole.parse().unwrap_or_else(|_| die("amount"));
    if frac.len() > 18 {
        die("at most 18 decimals");
    }
    let frac: i128 = if frac.is_empty() {
        0
    } else {
        format!("{:0<18}", frac)
            .parse()
            .unwrap_or_else(|_| die("amount"))
    };
    Fixed::raw(whole * 1_000_000_000_000_000_000 + frac)
}

fn dest(t: &str, salt: &str) -> ([u8; 32], ZcashDestination) {
    let a = parse_destination(t, Network::TestNetwork)
        .unwrap_or_else(|| die("not a testnet transparent or unified address"));
    (zcash_commitment(&a, &unhex32(salt)), a)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let cmd = a.get(1).map(String::as_str).unwrap_or("");
    match (cmd, a.len()) {
        ("keygen", 3) => {
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            std::fs::write(&a[2], seed).unwrap_or_else(|e| die(&e.to_string()));
            let k = SigningKey::from_bytes(&seed);
            println!("{}", hex(&account(&k)));
        }
        ("account", 3) => println!("{}", hex(&account(&key(&a[2])))),
        ("memo", 3) => println!("{}", zyn_custody::memo::encode_text(&account(&key(&a[2])))),
        ("reveal", 5) => {
            let k = key(&a[2]);
            let (_, addr) = dest(&a[3], &a[4]);
            let _ = addr;
            println!("{} {} {}", hex(&account(&k)), a[3], a[4]);
        }
        ("balance", 5) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let id = account(&k);
            // A read is signed: the node serves a record only to its holder.
            let epoch = status(&a[2], chain).epoch;
            let sig = k.sign(&read_challenge(chain, &id, epoch)).to_bytes();
            let mut e = Encoder::new();
            e.u8(OP_ACCOUNT)
                .u32(chain)
                .bytes(&id)
                .u64(epoch)
                .u8(Scheme::Ed25519.tag())
                .bytes(k.verifying_key().as_bytes())
                .bytes(&sig);
            let body = call(&a[2], e.finish());
            let mut d = Decoder::new(&body);
            let tag = d.take_bytes(17).unwrap_or_else(|_| die("bad record"));
            if tag != b"swapvm.account.v1" {
                die("unexpected record format");
            }
            let _id = d.account().unwrap_or_else(|_| die("bad record"));
            let n = d.u32().unwrap_or_else(|_| die("bad record"));
            println!("account {}", hex(&id));
            for _ in 0..n {
                let (asset, amount) = (d.u32().unwrap_or(0), d.fixed().unwrap_or(Fixed::ZERO));
                println!("  spendable  asset {:<3} {}", asset, amount);
            }
            let n = d.u32().unwrap_or(0);
            for _ in 0..n {
                let (asset, amount, since) = (
                    d.u32().unwrap_or(0),
                    d.fixed().unwrap_or(Fixed::ZERO),
                    d.u64().unwrap_or(0),
                );
                println!(
                    "  exiting    asset {:<3} {}  (requested epoch {})",
                    asset, amount, since
                );
            }
            let n = d.u32().unwrap_or(0);
            for _ in 0..n {
                let (asset, amount, epoch) = (
                    d.u32().unwrap_or(0),
                    d.fixed().unwrap_or(Fixed::ZERO),
                    d.u64().unwrap_or(0),
                );
                println!(
                    "  unreleased asset {:<3} {}  (credited epoch {}, spendable once anchored)",
                    asset, amount, epoch
                );
            }
            if let Ok(dest) = d.hash() {
                let bound = dest != [0u8; 32];
                println!(
                    "  binding    {}",
                    if bound {
                        hex(&dest)
                    } else {
                        "none".to_string()
                    }
                );
                if let Ok(1) = d.u8() {
                    let (pd, since) = (d.hash().unwrap_or([0; 32]), d.u64().unwrap_or(0));
                    println!("  redirect   {} pending since epoch {}", hex(&pd), since);
                }
            }
        }
        ("bind-sol", 7) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let addr =
                zyn_custody::solana::pubkey(&a[5]).unwrap_or_else(|| die("not a Solana address"));
            let destination = zyn_bridge::solana::commitment(&addr, &unhex32(&a[6]));
            submit(
                &a[2],
                chain,
                &k,
                Intent::BindWithdrawal {
                    account: account(&k),
                    destination,
                },
            );
        }
        ("withdraw-sol", 9) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let asset = unhex32(&a[5]);
            let sol: f64 = a[6].parse().unwrap_or_else(|_| die("amount in SOL"));
            let lamports = (sol * 1e9).round() as i128;
            let addr =
                zyn_custody::solana::pubkey(&a[7]).unwrap_or_else(|| die("not a Solana address"));
            let destination = zyn_bridge::solana::commitment(&addr, &unhex32(&a[8]));
            submit(
                &a[2],
                chain,
                &k,
                Intent::RequestWithdrawal {
                    account: account(&k),
                    asset,
                    amount: Fixed::raw(lamports * 1_000_000_000),
                    destination,
                },
            );
        }
        ("withdraw-item", 8) => {
            // One whole unit of a mirrored item, back to its origin chain.
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let asset = unhex32(&a[5]);
            let addr =
                zyn_custody::solana::pubkey(&a[6]).unwrap_or_else(|| die("not a Solana address"));
            let destination = zyn_bridge::solana::commitment(&addr, &unhex32(&a[7]));
            submit(
                &a[2],
                chain,
                &k,
                Intent::RequestWithdrawal {
                    account: account(&k),
                    asset,
                    amount: Fixed::whole(1),
                    destination,
                },
            );
        }
        ("reveal-sol", 5) => {
            let k = key(&a[2]);
            zyn_custody::solana::pubkey(&a[3]).unwrap_or_else(|| die("not a Solana address"));
            println!("{} {} {}", hex(&account(&k)), a[3], a[4]);
        }
        ("pools", 4) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let mut e = Encoder::new();
            e.u8(wire::OP_POOLS).u32(chain);
            let body = call(&a[2], e.finish());
            let mut d = Decoder::new(&body);
            let n = d.u32().unwrap_or(0);
            if n == 0 {
                println!("no pools");
            }
            for _ in 0..n {
                let (id, a0, a1) = (
                    d.array::<32>().unwrap_or([0; 32]),
                    d.array::<32>().unwrap_or([0; 32]),
                    d.array::<32>().unwrap_or([0; 32]),
                );
                let (r0, r1) = (
                    d.fixed().unwrap_or(Fixed::ZERO),
                    d.fixed().unwrap_or(Fixed::ZERO),
                );
                let fee = d.u16().unwrap_or(0);
                let has_ref = d.u8().unwrap_or(0) != 0;
                let (rp, rs, eff) = (
                    d.fixed().unwrap_or(Fixed::ZERO),
                    d.u64().unwrap_or(0),
                    d.u16().unwrap_or(fee),
                );
                println!(
                    "pool {} asset {} : asset {}   reserves {} : {}   fee {} bps{}",
                    hex(&id),
                    hex(&a0),
                    hex(&a1),
                    r0,
                    r1,
                    fee,
                    if has_ref {
                        format!("   reference {} (seq {}), charging {} bps", rp, rs, eff)
                    } else {
                        String::new()
                    }
                );
            }
        }
        ("quote", 7) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let asset_in = unhex32(&a[4]);
            let path: Vec<[u8; 32]> = a[5].split(',').map(unhex32).collect();
            let amount = fixed_of(&a[6]);
            let mut e = Encoder::new();
            e.u8(wire::OP_QUOTE)
                .u32(chain)
                .bytes(&asset_in)
                .u32(path.len() as u32);
            for p in &path {
                e.bytes(p);
            }
            e.i128(amount.0);
            let body = call(&a[2], e.finish());
            let mut d = Decoder::new(&body);
            let out = d.fixed().unwrap_or(Fixed::ZERO);
            let best = d.fixed().unwrap_or(Fixed::ZERO);
            let asset_out = d.array::<32>().unwrap_or([0; 32]);
            println!(
                "{} of asset {} -> {} of asset {}  (best case {}, a perfectly netted batch)",
                amount,
                hex(&asset_in),
                out,
                hex(&asset_out),
                best
            );
        }
        ("create-pool", 9) | ("create-pool", 10) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let asset_a = unhex32(&a[5]);
            let asset_b = unhex32(&a[7]);
            let fee_bps: u16 = a
                .get(9)
                .map(|f| f.parse().unwrap_or_else(|_| die("fee bps")))
                .unwrap_or(30);
            submit(
                &a[2],
                chain,
                &k,
                Intent::CreatePool {
                    creator: account(&k),
                    asset_a,
                    asset_b,
                    amount_a: fixed_of(&a[6]),
                    amount_b: fixed_of(&a[8]),
                    fee_bps,
                },
            );
        }
        ("remove-liquidity", 7) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let pool = unhex32(&a[5]);
            submit(
                &a[2],
                chain,
                &k,
                Intent::RemoveLiquidity {
                    account: account(&k),
                    pool,
                    shares: fixed_of(&a[6]),
                    min0: Fixed::ZERO,
                    min1: Fixed::ZERO,
                },
            );
        }
        ("add-liquidity", 8) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let pool = unhex32(&a[5]);
            submit(
                &a[2],
                chain,
                &k,
                Intent::AddLiquidity {
                    account: account(&k),
                    pool,
                    max0: fixed_of(&a[6]),
                    max1: fixed_of(&a[7]),
                    min_shares: Fixed::ZERO,
                },
            );
        }
        ("swap", 9) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let asset_in = unhex32(&a[5]);
            let path: Vec<[u8; 32]> = a[6].split(',').map(unhex32).collect();
            submit(
                &a[2],
                chain,
                &k,
                Intent::SwapExactIn {
                    account: account(&k),
                    asset_in,
                    path,
                    amount_in: fixed_of(&a[7]),
                    min_out: fixed_of(&a[8]),
                },
            );
        }
        ("transfer", 8) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let asset = unhex32(&a[6]);
            submit(
                &a[2],
                chain,
                &k,
                Intent::Transfer {
                    from: account(&k),
                    to: unhex32(&a[5]),
                    asset,
                    amount: fixed_of(&a[7]),
                },
            );
        }
        ("shield", 5) => {
            use rand::RngCore;
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let mut blind = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut blind);
            submit(
                &a[2],
                chain,
                &k,
                Intent::Reblind {
                    account: account(&k),
                    blind,
                },
            );
            eprintln!("shielded: the published leaf for this account now commits to a secret only it knows");
        }
        ("mint-item", 9) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let symbol = swapvm::state::Symbol::new(a[5].as_bytes())
                .unwrap_or_else(|| die("invalid symbol"));
            let supply: i64 = a[6].parse().unwrap_or_else(|_| die("supply, whole units"));
            submit(
                &a[2],
                chain,
                &k,
                Intent::MintItem {
                    creator: account(&k),
                    symbol,
                    supply: Fixed::whole(supply),
                    bond: fixed_of(&a[7]),
                    content: unhex32(&a[8]),
                },
            );
        }
        ("offer", 10) => {
            // The maker signs the whole trade; the taker adds their signature
            // and submits. Neither can change a field after signing.
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let intent = Intent::AcceptOffer {
                maker: account(&k),
                taker: unhex32(&a[9]),
                offer_asset: unhex32(&a[5]),
                offer_amount: fixed_of(&a[6]),
                want_asset: unhex32(&a[7]),
                want_amount: fixed_of(&a[8]),
            };
            let now = status(&a[2], chain).epoch;
            let auth = Authorization::for_vm::<SwapState>(chain, now, 100);
            let payload = match signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, &intent) {
                Signed::Message(m) => m,
                Signed::Prehash(h) => h.to_vec(),
            };
            let sig = k.sign(&payload).to_bytes();
            let mut e = Encoder::new();
            e.u32(chain)
                .bytes(&auth.vm_id)
                .u64(auth.valid_until_epoch)
                .bytes(k.verifying_key().as_bytes())
                .bytes(&sig);
            wire::encode_intent(&mut e, &intent);
            println!("{}", hex(e.finish()));
        }
        ("accept", 6) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let raw: Vec<u8> = (0..a[5].len() / 2)
                .map(|i| {
                    u8::from_str_radix(&a[5][i * 2..i * 2 + 2], 16)
                        .unwrap_or_else(|_| die("offer line"))
                })
                .collect();
            let mut d = Decoder::new(&raw);
            let offer_chain = d.u32().unwrap_or_else(|_| die("offer line"));
            if offer_chain != chain {
                die("the offer is for another chain");
            }
            let vm_id = d.hash().unwrap_or_else(|_| die("offer line"));
            let valid_until = d.u64().unwrap_or_else(|_| die("offer line"));
            let maker_key = d.array::<32>().unwrap_or_else(|_| die("offer line"));
            let maker_sig = d.array::<64>().unwrap_or_else(|_| die("offer line"));
            let intent =
                wire::decode_intent(&mut d).unwrap_or_else(|_| die("offer line: bad intent"));
            let Intent::AcceptOffer {
                maker,
                taker,
                offer_asset,
                offer_amount,
                want_asset,
                want_amount,
            } = &intent
            else {
                die("not an offer")
            };
            if *taker != account(&k) {
                die("this offer names a different taker");
            }
            eprintln!(
                "offer from {}: they give {} of asset {} for {} of asset {}",
                hex(maker),
                offer_amount,
                hex(offer_asset),
                want_amount,
                hex(want_asset)
            );
            let auth = Authorization {
                chain_id: chain,
                vm_id,
                valid_until_epoch: valid_until,
            };
            let payload = match signed_bytes_as::<SwapState>(Scheme::Ed25519, &auth, &intent) {
                Signed::Message(m) => m,
                Signed::Prehash(h) => h.to_vec(),
            };
            let sig = k.sign(&payload).to_bytes();
            let mut e = Encoder::new();
            e.u8(OP_SUBMIT_MULTI)
                .u32(chain)
                .bytes(&vm_id)
                .u64(valid_until)
                .u8(2)
                .u8(Scheme::Ed25519.tag())
                .bytes(&maker_key)
                .bytes(&maker_sig)
                .u8(Scheme::Ed25519.tag())
                .bytes(k.verifying_key().as_bytes())
                .bytes(&sig);
            wire::encode_intent(&mut e, &intent);
            let body = call(&a[2], e.finish());
            let mut d = Decoder::new(&body);
            let seq = d.u64().unwrap_or(0);
            let _epoch = d.u64().unwrap_or(0);
            let _root = d.hash().unwrap_or([0; 32]);
            let count = d.u32().unwrap_or(0);
            let first = d.u8().unwrap_or(0);
            if first == 12 {
                die(&format!(
                    "rejected at seq {} (reject code {})",
                    seq,
                    d.u8().unwrap_or(0)
                ));
            }
            println!(
                "accepted: seq {} ({} receipt(s)) — the trade is done",
                seq, count
            );
        }
        ("reveal-submit", 7) => {
            // Tell the operator where the bound exit goes — signed, and only
            // accepted if it matches what the chain already holds.
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let id = account(&k);
            let kind: u8 = if zyn_custody::solana::pubkey(&a[5]).is_some()
                && !a[5].starts_with("utest")
                && !a[5].starts_with('t')
            {
                1
            } else {
                0
            };
            let epoch = status(&a[2], chain).epoch;
            let sig = k.sign(&read_challenge(chain, &id, epoch)).to_bytes();
            let mut e = Encoder::new();
            e.u8(OP_REVEAL)
                .u32(chain)
                .bytes(&id)
                .u64(epoch)
                .u8(Scheme::Ed25519.tag())
                .bytes(k.verifying_key().as_bytes())
                .bytes(&sig);
            e.u8(kind)
                .u16(a[5].len() as u16)
                .bytes(a[5].as_bytes())
                .bytes(&unhex32(&a[6]));
            call(&a[2], e.finish());
            println!(
                "reveal accepted: the operator can now pay your exit to {}",
                a[5]
            );
        }
        ("record", 5) | ("record", 6) => {
            // Keep the exit proof: the record and its path to the anchored root.
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let out = a
                .get(5)
                .cloned()
                .unwrap_or_else(|| format!("{}.exit.json", a[4]));
            let node = zynzapd::client::Node::new(&a[2], chain);
            let p = node
                .account_proof(&k)
                .unwrap_or_else(|e| die(&e))
                .unwrap_or_else(|| die("this account has no record in the anchored snapshot"));
            let proof = zynzapd::exitproof::ExitProof {
                chain_id: chain,
                epoch: p.epoch,
                root: p.root,
                record: p.record,
                index: p.index,
                path: p.path,
                fetched_at: now(),
            };
            if !proof.verify() {
                die("the node handed back a proof that does not open its own root — do not trust this node");
            }
            proof
                .save(std::path::Path::new(&out))
                .unwrap_or_else(|e| die(&e));
            println!(
                "exit proof for epoch {} (root {}) kept in {}",
                proof.epoch,
                hex(&proof.root),
                out
            );
        }
        ("exit-proof", 3) => {
            let p = zynzapd::exitproof::ExitProof::load(std::path::Path::new(&a[2]))
                .unwrap_or_else(|| die("not an exit proof file"));
            if !p.verify() {
                die("the proof does not open its root");
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&p.to_json()).unwrap_or_default()
            );
        }
        ("verify-exit", 3) => {
            let p = zynzapd::exitproof::ExitProof::load(std::path::Path::new(&a[2]))
                .unwrap_or_else(|| die("not an exit proof file"));
            if p.verify() {
                println!(
                    "VALID: the record opens root {} (chain {}, epoch {})",
                    hex(&p.root),
                    p.chain_id,
                    p.epoch
                );
                println!("check that this root is the one anchored on Zcash for epoch {}: the anchor's memo id is in chain-{}/index on any mirror", p.epoch, p.chain_id);
            } else {
                println!("INVALID: the record and path do not open the root");
                std::process::exit(1);
            }
        }
        ("force-memo", 9) => {
            // The signed intent as a memo, for any wallet that can pay the vault.
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            if a[5] != "transfer" {
                die("only 'transfer' can be forced from the CLI for now");
            }
            let to = unhex32(&a[6]);
            let asset = unhex32(&a[7]);
            let amount = zynzapd::client::fixed_of(
                a.get(8)
                    .map(String::as_str)
                    .unwrap_or_else(|| die("amount")),
            )
            .unwrap_or_else(|e| die(&e));
            let epoch = status(&a[2], chain).epoch;
            let intent = Intent::Transfer {
                from: account(&k),
                to,
                asset,
                amount,
            };
            let frame = zynzapd::client::frame_submission(&k, chain, epoch, &intent);
            let memo = zyn_custody::memo::encode_forced(&frame)
                .unwrap_or_else(|| die("the signed intent does not fit a memo"));
            println!("memo (hex, 512 bytes):\n{}", hex(&memo));
            println!("pay the vault's deposit address any amount (0.0001 TAZ is enough) with exactly this memo.");
            println!("the note's value is credited to your account; the intent must be applied within 20 blocks of confirmation, or verifiers report censorship.");
        }
        ("status", 4) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let s = status(&a[2], chain);
            println!("seq {}  epoch {}  root {}", s.seq, s.epoch, hex(&s.root));
            println!(
                "ZEC.zy backing {}  pools {}  accounts {}",
                s.backing, s.pools, s.accounts
            );
            for h in &s.health {
                println!(
                    "  {:<16} scanned to {:<12} {}{}",
                    h.0,
                    h.1,
                    if h.2 { "DOWN" } else { "ok" },
                    if h.3.is_empty() {
                        String::new()
                    } else {
                        format!("  — {}", h.3)
                    }
                );
            }
        }
        ("bind", 7) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let (destination, _) = dest(&a[5], &a[6]);
            submit(
                &a[2],
                chain,
                &k,
                Intent::BindWithdrawal {
                    account: account(&k),
                    destination,
                },
            );
        }
        ("withdraw", 8) => {
            let chain: u32 = a[3].parse().unwrap_or_else(|_| die("chain id"));
            let k = key(&a[4]);
            let zec: f64 = a[5]
                .parse()
                .unwrap_or_else(|_| die("amount in ZEC, e.g. 0.01"));
            let zat = (zec * 1e8).round() as i128;
            let (destination, _) = dest(&a[6], &a[7]);
            submit(
                &a[2],
                chain,
                &k,
                Intent::RequestWithdrawal {
                    account: account(&k),
                    asset: XZEC,
                    amount: Fixed::raw(zat * ZAT),
                    destination,
                },
            );
        }
        _ => {
            eprintln!("usage:\n  zyn-cli keygen <key-file>\n  zyn-cli account <key-file>\n  zyn-cli memo <key-file>\n  zyn-cli reveal <key-file> <t-address> <salt-hex>\n  zyn-cli status <host:port> <chain-id>\n  zyn-cli record <host:port> <chain-id> <key-file> [out.json]   keep the exit proof\n  zyn-cli exit-proof <file.json>                                  print it, verified\n  zyn-cli verify-exit <file.json>                                 anyone: check it\n  zyn-cli force-memo <host:port> <chain-id> <key-file> transfer <to-hex> <asset> <amount>   the intent as a memo, for any wallet\n  zyn-cli balance <host:port> <chain-id> <key-file>\n  zyn-cli transfer <host:port> <chain-id> <key-file> <to-account-hex> <asset> <amount>\n  zyn-cli shield <host:port> <chain-id> <key-file>\n  zyn-cli mint-item <host:port> <chain-id> <key-file> <symbol> <supply> <bond-zec> <content-hex32>\n  zyn-cli offer <host:port> <chain-id> <key-file> <give-asset> <give-amount> <want-asset> <want-amount> <taker-account-hex>\n  zyn-cli accept <host:port> <chain-id> <key-file> <offer-line>\n  zyn-cli bind <host:port> <chain-id> <key-file> <t-address> <salt-hex>\n  zyn-cli withdraw <host:port> <chain-id> <key-file> <zec> <t-address> <salt-hex>\n  zyn-cli bind-sol <host:port> <chain-id> <key-file> <solana-address> <salt-hex>\n  zyn-cli withdraw-sol <host:port> <chain-id> <key-file> <asset-id> <sol> <solana-address> <salt-hex>\n  zyn-cli reveal-sol <key-file> <solana-address> <salt-hex>\n  zyn-cli reveal-submit <host:port> <chain-id> <key-file> <address> <salt-hex>\n  zyn-cli pools <host:port> <chain-id>\n  zyn-cli quote <host:port> <chain-id> <asset-in> <pool,..> <amount>\n  zyn-cli create-pool <host:port> <chain-id> <key-file> <asset-a> <amount-a> <asset-b> <amount-b> [fee-bps]\n  zyn-cli add-liquidity <host:port> <chain-id> <key-file> <pool> <max0> <max1>\n  zyn-cli remove-liquidity <host:port> <chain-id> <key-file> <pool> <shares>\n  zyn-cli swap <host:port> <chain-id> <key-file> <asset-in> <pool,..> <amount-in> <min-out>");
            std::process::exit(2);
        }
    }
}
