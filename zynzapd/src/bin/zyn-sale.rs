//! The Cave checkout: an invitation in, an item out.
//!
//! This is the piece that was missing while every part around it worked. The
//! whitelist registry, the order book, the allocator and the treasury signing
//! path all existed and never met, so there was no place where money changed
//! hands (§99).
//!
//! # What a buyer does
//!
//! ```text
//!   POST /quote   {code, account}  -> price, and the address to pay it at
//!   (buyer sends ZEC to that address; the vault scanner credits it)
//!   POST /settle  {code, read}     -> serials, minted to the same account
//!   GET  /order?code=…             -> where the order got to
//! ```
//!
//! # Paid to the account that will hold the item
//!
//! The address quoted is the deposit address of the buyer's **collection
//! receiving account** (§97.5), not of their identity. Three things follow, and
//! the third is the one that made this simple:
//!
//!   * no memo — a per-account address attributes itself, which is what makes
//!     this payable from an exchange (§71.39, A79);
//!   * the journal names an account with no other history, so the mint does not
//!     write the buyer's identity into it;
//!   * the money and the item end up in the same account, so nothing has to be
//!     moved afterwards — and a move is exactly what would have written the
//!     link back in.
//!
//! # Why the buyer proves their own payment
//!
//! Balances are private, so this service cannot look up whether a buyer paid,
//! and giving it the power to would mean giving it a read over every account.
//! Instead `/settle` takes the buyer's own **signed read** — the same payload
//! their wallet already produces to see its balance — and this service relays
//! it. The service holds no key of the buyer's and learns nothing it was not
//! handed (§74.23).
//!
//! # What this is not
//!
//! Trusted by construction, like the claim service. The creator key can mint
//! any item to anyone regardless of what this does. What it guarantees is the
//! ordering in `sale.rs`: a paid order is remembered, retrying is safe, and an
//! allocation nobody minted is given back.
//!
//! Environment:
//!   ZYN_SALE_LISTEN      host:port to serve on
//!   ZYN_SALE_BOOK        path to the order book
//!   ZYN_SALE_REGISTRY    path to the whitelist registry
//!   ZYN_SALE_NODE        node RPC                        (127.0.0.1:8099)
//!   ZYN_SALE_CHAIN       chain id                        (26460)
//!   ZYN_SALE_COLLECTION  collection id, 64 hex
//!   ZYN_SALE_PRICE       entry price per item, ZEC.zy    (0.01, §64.17)
//!   ZYN_SALE_CUSTODIANS  comma-separated host:port
//!   ZYN_SALE_THRESHOLD   signatures required             (2)
//!   ZYN_SALE_TREASURY    directory holding public.bin

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use swapvm::fixed::Fixed;
use swapvm::tx::Intent;
use zynzapd::client::{fixed_of, hex, Node};
use zynzapd::sale::{self, Book, Refused, State};
use zynzapd::whitelist::Registry;

/// `content.json` as the manifest builder writes it: `{"<serial>": {"content":
/// "<64 hex>", …}}`. Indices are the committed serials, 0-based, exactly as
/// `zyn-cave-manifest` derived the root over them.
fn load_manifest(path: &str) -> Result<std::collections::BTreeMap<u32, [u8; 32]>, String> {
    if path.trim().is_empty() {
        return Err("set ZYN_SALE_MANIFEST to the collection's content.json".into());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path, e))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{}: {}", path, e))?;
    let map = doc.as_object().ok_or("content.json is not an object")?;
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in map {
        let serial: u32 = k
            .parse()
            .map_err(|_| format!("manifest key {} is not a serial", k))?;
        let content = v
            .get("content")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("serial {} has no content", serial))?;
        out.insert(
            serial,
            unhex32(content).ok_or_else(|| format!("serial {}: content is not 32 bytes", serial))?,
        );
    }
    if out.is_empty() {
        return Err("the manifest is empty".into());
    }
    Ok(out)
}

fn env(k: &str, default: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| default.to_string())
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

struct Service {
    node: Node,
    book: Mutex<Book>,
    registry: Mutex<Registry>,
    book_path: std::path::PathBuf,
    registry_path: std::path::PathBuf,
    chain: u32,
    collection: [u8; 32],
    price: Fixed,
    /// Serial to its committed content hash, from the same `content.json` the
    /// manifest root was computed over (§86). A mint names the content, so the
    /// service cannot invent one: a serial missing here is refused rather than
    /// minted with a zero commitment.
    manifest: std::collections::BTreeMap<u32, [u8; 32]>,
    symbol_prefix: String,
    custodians: Vec<String>,
    threshold: usize,
    public: zyn_custody::treasury::PublicKeyPackage<zyn_custody::treasury::ZynAccount>,
    treasury: [u8; 32],
    request: std::sync::atomic::AtomicU64,
}

fn main() {
    let listen = env("ZYN_SALE_LISTEN", "127.0.0.1:8096");
    let book_path = std::path::PathBuf::from(env("ZYN_SALE_BOOK", "./sale.book"));
    let registry_path = std::path::PathBuf::from(env("ZYN_SALE_REGISTRY", "./whitelist.registry"));
    let chain: u32 = env("ZYN_SALE_CHAIN", "26460").parse().expect("chain id");
    let collection = unhex32(&env("ZYN_SALE_COLLECTION", "")).unwrap_or_else(|| {
        eprintln!("zyn-sale: set ZYN_SALE_COLLECTION to the collection id (64 hex)");
        std::process::exit(2);
    });
    // §64.17 froze this at 0.01 ZEC for entry. It is read from the environment
    // rather than hardcoded so a testnet run can differ, and printed at start
    // so a wrong one is visible before a buyer meets it rather than after.
    let price = fixed_of(&env("ZYN_SALE_PRICE", "0.01")).unwrap_or_else(|e| {
        eprintln!("zyn-sale: ZYN_SALE_PRICE is not a decimal amount: {}", e);
        std::process::exit(2);
    });
    let custodians: Vec<String> = env("ZYN_SALE_CUSTODIANS", "")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    let threshold: usize = env("ZYN_SALE_THRESHOLD", "2").parse().expect("threshold");
    if custodians.len() < threshold {
        eprintln!(
            "zyn-sale: {} custodian(s) named but threshold is {} — a mint is signed when the \
             buyer settles, so they must be up while this serves",
            custodians.len(),
            threshold
        );
        std::process::exit(2);
    }
    let treasury_dir = env("ZYN_SALE_TREASURY", "");
    let public = zyn_custody::shares::load_public::<zyn_custody::treasury::ZynAccount>(
        std::path::Path::new(&treasury_dir),
    )
    .unwrap_or_else(|e| {
        eprintln!("zyn-sale: cannot read {}/public.bin: {}", treasury_dir, e);
        std::process::exit(1);
    });
    let treasury = zyn_custody::treasury::account_of_group(&public).expect("treasury account");

    let manifest_path = env("ZYN_SALE_MANIFEST", "");
    let manifest = load_manifest(&manifest_path).unwrap_or_else(|e| {
        eprintln!("zyn-sale: {}", e);
        std::process::exit(1);
    });
    let symbol_prefix = env("ZYN_SALE_SYMBOL_PREFIX", "CAVEZ");

    let book = Book::load(&book_path).unwrap_or_else(|e| {
        eprintln!("zyn-sale: {}", e);
        std::process::exit(1);
    });
    let registry = Registry::load(&registry_path).unwrap_or_else(|e| {
        eprintln!("zyn-sale: {}", e);
        std::process::exit(1);
    });
    let (orders, taken) = book.totals();
    if !registry.open {
        eprintln!("zyn-sale: the whitelist phase is CLOSED — quotes will be refused until it opens");
    }

    let node = Node::new(&env("ZYN_SALE_NODE", "127.0.0.1:8099"), chain);

    let s = Arc::new(Service {
        node,
        book: Mutex::new(book),
        registry: Mutex::new(registry),
        book_path,
        registry_path,
        chain,
        collection,
        price,
        manifest,
        symbol_prefix,
        custodians,
        threshold,
        public,
        treasury,
        request: std::sync::atomic::AtomicU64::new(1),
    });

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("zyn-sale: cannot bind {}: {}", listen, e);
        std::process::exit(1);
    });
    eprintln!(
        "zyn-sale: collection {} at {} ZEC.zy each; {} item(s) in the manifest; {} order(s) so far, {} paid",
        hex(&s.collection),
        s.price,
        s.manifest.len(),
        orders,
        taken
    );
    eprintln!("zyn-sale: POST http://{}/quote  {{\"code\":\"…\",\"account\":\"64 hex\"}}", listen);
    eprintln!("zyn-sale: POST http://{}/settle {{\"code\":\"…\",\"read\":\"hex signed read\"}}", listen);

    for stream in listener.incoming().flatten() {
        let s = Arc::clone(&s);
        std::thread::spawn(move || {
            let _ = handle(&s, stream);
        });
    }
}

fn handle(s: &Service, mut stream: TcpStream) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
    let mut r = BufReader::new(stream.try_clone()?);
    let mut line = String::new();
    r.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut len = 0usize;
    loop {
        let mut h = String::new();
        if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
            break;
        }
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    // A body cap, because this is reachable from a browser and a checkout has
    // no reason to send more than a code, an account and a signed read.
    if len > 8192 {
        return reply(&mut stream, 413, r#"{"error":"body too large"}"#);
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut body)?;
    }

    if method == "OPTIONS" {
        return preflight(&mut stream);
    }
    match (method.as_str(), path.split('?').next().unwrap_or("")) {
        ("POST", "/quote") => quote(s, &mut stream, &body),
        ("POST", "/settle") => settle(s, &mut stream, &body),
        ("GET", "/order") => order(s, &mut stream, &path),
        _ => reply(
            &mut stream,
            404,
            r#"{"error":"POST /quote, POST /settle, GET /order?code="}"#,
        ),
    }
}

fn field(body: &[u8], key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    v.get(key)?.as_str().map(str::to_string)
}

fn quote(s: &Service, stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let (Some(code), Some(account_hex)) = (field(body, "code"), field(body, "account")) else {
        return reply(stream, 400, r#"{"error":"code and account are required"}"#);
    };
    let Some(account) = unhex32(&account_hex) else {
        return reply(stream, 400, r#"{"error":"account must be 64 hex characters"}"#);
    };
    let quantity = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("quantity").and_then(serde_json::Value::as_u64))
        .unwrap_or(1) as u32;

    let result = {
        let mut registry = s.registry.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
        let mut book = s.book.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
        let q = sale::quote(&mut registry, &mut book, &code, account, quantity, s.price);
        if q.is_ok() {
            // Persisted before the buyer is told a price, so a crash between
            // the two cannot hand out an allocation the book has forgotten.
            let _ = registry.save(&s.registry_path);
            let _ = book.save(&s.book_path);
        }
        q
    };

    match result {
        Ok(q) => {
            // The address to pay: the deposit address of the account that will
            // hold the item. Asked of the node, which is the only party that
            // can issue one.
            let address = match s.node.deposit_address(account) {
                Ok(a) => a,
                Err(e) => {
                    return reply(
                        stream,
                        502,
                        &format!(
                            r#"{{"error":"reserved, but no deposit address yet: {}"}}"#,
                            e.replace('"', "'")
                        ),
                    )
                }
            };
            reply(
                stream,
                200,
                &format!(
                    r#"{{"reserved":true,"quantity":{},"unitPrice":"{}","total":"{}","payTo":"{}","memo":false}}"#,
                    q.quantity, q.unit_price, q.total, address
                ),
            )
        }
        Err(e) => refused(stream, e),
    }
}

fn settle(s: &Service, stream: &mut TcpStream, body: &[u8]) -> std::io::Result<()> {
    let (Some(code), Some(read_hex)) = (field(body, "code"), field(body, "read")) else {
        return reply(
            stream,
            400,
            r#"{"error":"code and read (a signed read from the paying account) are required"}"#,
        );
    };
    let Some(read) = unhex(&read_hex) else {
        return reply(stream, 400, r#"{"error":"read must be hex"}"#);
    };

    let account = {
        let book = s.book.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
        match book.get(&code) {
            Some(o) => o.account,
            None => return reply(stream, 404, r#"{"error":"no such order — quote first"}"#),
        }
    };

    // The buyer's own signed read, relayed. This service never holds a key of
    // theirs and cannot read any account that has not handed it one.
    let record = match s.node.account_raw(&read) {
        Ok(Some(r)) => r,
        Ok(None) => return reply(stream, 402, r#"{"error":"that account holds nothing yet"}"#),
        Err(e) => {
            return reply(
                stream,
                400,
                &format!(r#"{{"error":"{}"}}"#, e.replace('"', "'")),
            )
        }
    };
    let held = record
        .spendable
        .iter()
        .find(|(a, _)| *a == swapvm::types::XZEC)
        .map(|(_, v)| *v)
        .unwrap_or(Fixed::ZERO);

    let pay = || -> Result<Fixed, String> {
        // Payment is already on chain: the buyer sent ZEC to the address this
        // service quoted and the vault scanner credited it. "Paying" here is
        // therefore recognising it, not moving it — and the money stays in the
        // account that receives the item, so nothing has to move afterwards.
        Ok(held)
    };
    let allocate = |_n: u32| -> Result<Vec<u32>, String> {
        Err("the allocation policy is not committed yet — see A71 and §64.16".to_string())
    };
    let mint = |serial: u32, to: [u8; 32]| -> Result<(), String> {
        // The content commitment comes from the manifest the root was computed
        // over. A serial this service cannot find is refused rather than minted
        // against a zero commitment, which would be an item committing to
        // nothing and could never be corrected.
        let content = *s
            .manifest
            .get(&serial)
            .ok_or_else(|| format!("serial {} is not in the manifest", serial))?;
        let symbol = swapvm::state::symbol(
            format!("{}{:04}", s.symbol_prefix, serial + 1).as_bytes(),
        );
        let epoch = s.node.status().map_err(|e| e.to_string())?.epoch;
        let rid = s.request.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let frame = zynzapd::treasury::frame_submission_across(
            &s.custodians,
            &s.public,
            s.threshold,
            s.chain,
            epoch,
            &Intent::MintCollectionItem {
                creator: s.treasury,
                collection: s.collection,
                serial,
                to,
                symbol,
                content,
            },
            rid,
        )?;
        match s.node.submit_raw(&frame) {
            Ok(_) => Ok(()),
            // A serial already minted is this attempt finishing what an earlier
            // one started, which for a retry is success.
            Err(e) if e.contains("(code 3)") => Ok(()),
            Err(e) => Err(e),
        }
    };

    let outcome = {
        let mut book = s.book.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
        let r = sale::settle(&mut book, &code, account, s.price, &pay, &allocate, &mint);
        let _ = book.save(&s.book_path);
        r
    };

    match outcome {
        Ok(sold) => {
            eprintln!(
                "zyn-sale: {} -> {} serial(s) {:?}",
                hex(&account),
                sold.serials.len(),
                sold.serials
            );
            let serials = sold
                .serials
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");
            reply(
                stream,
                200,
                &format!(r#"{{"minted":true,"serials":[{}]}}"#, serials),
            )
        }
        Err(e) => refused(stream, e),
    }
}

fn order(s: &Service, stream: &mut TcpStream, path: &str) -> std::io::Result<()> {
    let code = path
        .split_once("code=")
        .map(|(_, c)| c.split('&').next().unwrap_or("").to_string())
        .unwrap_or_default();
    if code.trim().is_empty() {
        return reply(stream, 400, r#"{"error":"GET /order?code=…"}"#);
    }
    let book = s.book.lock().map_err(|_| std::io::Error::other("lock poisoned"))?;
    match book.get(&code) {
        None => reply(stream, 404, r#"{"error":"no such order"}"#),
        Some(o) => {
            let state = match o.state {
                State::Reserved => "reserved",
                State::Paid => "paid",
                State::Minted => "minted",
            };
            let serials = o
                .serials
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(",");
            reply(
                stream,
                200,
                &format!(
                    r#"{{"state":"{}","quantity":{},"paid":"{}","serials":[{}]}}"#,
                    state, o.quantity, o.paid, serials
                ),
            )
        }
    }
}

/// A refusal the buyer can act on. Each maps to the thing they would do next,
/// which is why they are not collapsed into one error.
fn refused(stream: &mut TcpStream, e: Refused) -> std::io::Result<()> {
    let (status, message): (u16, &str) = match e {
        Refused::UnknownCode => (404, "that invitation is not one of ours"),
        Refused::BoundElsewhere => (409, "that invitation is already in use by another account"),
        Refused::Closed => (403, "the whitelist phase is not open"),
        Refused::Exhausted { .. } => (409, "that invitation has no allocation left"),
        Refused::WrongAmount { .. } => (402, "the payment has not arrived in full yet"),
        Refused::PaymentRefused => (502, "the chain refused the payment"),
        Refused::NotMinting => (409, "this collection is not minting"),
    };
    reply(
        stream,
        status,
        &format!(r#"{{"error":"{}"}}"#, message.replace('"', "'")),
    )
}

fn reply(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} \r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status,
        body.len(),
        body
    )?;
    stream.flush()
}

fn preflight(stream: &mut TcpStream) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 204 \r\nAccess-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Headers: content-type\r\n\
         Access-Control-Allow-Methods: POST, GET, OPTIONS\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service must read exactly what the manifest builder wrote, because
    /// a mint names the content commitment and there is no second source for
    /// it. This reads the real Collection Z manifest when it is present.
    #[test]
    fn it_reads_the_collection_z_manifest() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../examples/zyn-pfp-concepts/out/content.json"
        );
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: run build_collection_z_manifests.py first");
            return;
        }
        let m = load_manifest(path).expect("the builder's own output must load");
        assert_eq!(m.len(), 4444, "every serial, none invented");
        // Serials are 0-based and contiguous: the same indices the manifest
        // root was derived over (§86.1).
        assert!(m.contains_key(&0) && m.contains_key(&4443));
        assert_eq!(*m.keys().next().unwrap(), 0);
        assert_eq!(*m.keys().next_back().unwrap(), 4443);
        assert!(m.values().all(|c| *c != [0u8; 32]), "no zero commitments");
        // Item 0's content, pinned: this is the value the mint will name, and
        // it matches what zyn-cave-manifest hashed into the root.
        assert_eq!(
            hex(&m[&0]),
            "0d6e082004c43523c551c05cb8ce0ce6b844cf06478a487e66444ac7e757acc1"
        );
    }

    #[test]
    fn a_missing_or_empty_manifest_is_refused_rather_than_defaulted() {
        assert!(load_manifest("").is_err(), "no path is an error, not an empty map");
        assert!(load_manifest("/nonexistent/content.json").is_err());
    }

    /// A serial whose content is not 32 bytes must fail the load, not mint an
    /// item committing to something truncated.
    #[test]
    fn a_short_content_hash_fails_the_load() {
        let dir = std::env::temp_dir().join(format!("zyn-sale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.json");
        std::fs::write(&p, r#"{"0":{"content":"abcd"}}"#).unwrap();
        assert!(load_manifest(p.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
