//! Hand out the 333, one claim code at a time.
//!
//! A claim code is an operator promise (§74.5). This service is trusted by
//! construction — the creator key can move any item regardless of what it does
//! — so it is not, and must not be presented as, trustless. What it does offer
//! is that a claim is *idempotent* and *binds once*: retrying is safe, and a
//! code that has been redeemed will not redeem again to a different account.
//!
//! Environment:
//!   ZYN_CLAIM_LISTEN     host:port to serve on          (127.0.0.1:8099 is the node)
//!   ZYN_CLAIM_BOOK       path to the claim book
//!   ZYN_CLAIM_NODE       node RPC                       (127.0.0.1:8099)
//!   ZYN_CLAIM_CHAIN      chain id                       (26460)
//!   ZYN_CLAIM_CUSTODIANS comma-separated host:port, at least `threshold`
//!   ZYN_CLAIM_THRESHOLD  signatures required            (2)
//!   ZYN_CLAIM_TREASURY   directory holding public.bin
//!   ZYN_CLAIM_COLLECTION collection id, 64 hex
//!
//! Usage:
//!   zyn-claim issue <first> <last>   print codes for a serial range, once
//!   zyn-claim serve                  accept claims
//!
//! The custodians must be reachable while this serves, because a transfer is
//! signed at claim time: the signature commits to the recipient's account, and
//! nobody knows that until they say so. Bring them up for the event and take
//! them down after.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use swapvm::tx::Intent;
use zynzapd::claim::{resolve, Book, Granted, Outcome};
use zynzapd::client::Node;

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// A code with enough entropy that guessing is not a strategy, in an alphabet
/// that survives being read aloud and typed on a phone: no look-alikes.
fn fresh_code(rng: &mut impl rand::RngCore) -> String {
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut bytes = [0u8; 20];
    rng.fill_bytes(&mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect();
    // Grouped for reading off paper.
    format!(
        "{}-{}-{}-{}",
        &body[0..5],
        &body[5..10],
        &body[10..15],
        &body[15..20]
    )
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let book_path = PathBuf::from(env("ZYN_CLAIM_BOOK", ""));
    if book_path.as_os_str().is_empty() {
        eprintln!("zyn-claim: set ZYN_CLAIM_BOOK to the claim book's path");
        std::process::exit(2);
    }

    match mode.as_str() {
        "issue" => issue(&book_path),
        "serve" => serve(&book_path),
        _ => {
            eprintln!("usage: zyn-claim issue <first> <last> | zyn-claim serve");
            std::process::exit(2);
        }
    }
}

fn issue(book_path: &std::path::Path) {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let (first, last) = match args.as_slice() {
        [a, b] => (
            a.parse::<u32>().unwrap_or(0),
            b.parse::<u32>().unwrap_or(0),
        ),
        _ => {
            eprintln!("usage: zyn-claim issue <first> <last>   (collector numbers, 1-333)");
            std::process::exit(2);
        }
    };
    if first == 0 || last < first || last > 333 {
        eprintln!("zyn-claim: serials run 1 to 333, first <= last");
        std::process::exit(2);
    }

    let mut book = if book_path.exists() {
        Book::load(book_path).unwrap_or_else(|e| {
            eprintln!("zyn-claim: {}", e);
            std::process::exit(1);
        })
    } else {
        Book::new()
    };
    let already: std::collections::BTreeSet<u32> =
        book.entries.values().map(|e| e.serial).collect();

    let mut rng = rand::rngs::OsRng;
    let mut issued = 0usize;
    // Printed once, to this terminal, and never stored: the book keeps only a
    // fingerprint, so a code that is lost here is lost for good and must be
    // reissued as a new one.
    println!("# serial\tcode");
    for n in first..=last {
        if already.contains(&n) {
            eprintln!("zyn-claim: MOLE{:03} already has a code — skipping", n);
            continue;
        }
        let code = fresh_code(&mut rng);
        book.issue(n, &code);
        println!("MOLE{:03}\t{}", n, code);
        issued += 1;
    }
    book.set_path(book_path.to_path_buf());
    if let Err(e) = book.persist() {
        eprintln!("zyn-claim: could not save the book: {}", e);
        std::process::exit(1);
    }
    eprintln!(
        "zyn-claim: {} code(s) issued into {} — the codes above are not stored and cannot be recovered",
        issued,
        book_path.display()
    );
}

struct Serving {
    book: std::sync::Mutex<Book>,
    node: Node,
    chain: u32,
    collection: [u8; 32],
    treasury: [u8; 32],
    public: zyn_custody::treasury::PublicKeyPackage<zyn_custody::treasury::ZynAccount>,
    custodians: Vec<String>,
    threshold: usize,
    request: std::sync::atomic::AtomicU64,
}

fn serve(book_path: &std::path::Path) {
    let chain: u32 = env("ZYN_CLAIM_CHAIN", "26460").parse().expect("chain id");
    let treasury_dir = env("ZYN_CLAIM_TREASURY", "");
    let collection = unhex32(&env("ZYN_CLAIM_COLLECTION", "")).unwrap_or_else(|| {
        eprintln!("zyn-claim: set ZYN_CLAIM_COLLECTION to the collection id (64 hex)");
        std::process::exit(2);
    });
    let custodians: Vec<String> = env("ZYN_CLAIM_CUSTODIANS", "")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    let threshold: usize = env("ZYN_CLAIM_THRESHOLD", "2").parse().expect("threshold");
    if custodians.len() < threshold {
        eprintln!(
            "zyn-claim: {} custodian(s) named but threshold is {} — a claim is signed when it \
             arrives, so they must be up while this serves",
            custodians.len(),
            threshold
        );
        std::process::exit(2);
    }

    let public = zyn_custody::shares::load_public::<zyn_custody::treasury::ZynAccount>(
        std::path::Path::new(&treasury_dir),
    )
    .unwrap_or_else(|e| {
        eprintln!("zyn-claim: cannot read {}/public.bin: {}", treasury_dir, e);
        std::process::exit(1);
    });
    let treasury = zyn_custody::treasury::account_of_group(&public).expect("treasury account");

    let book = Book::load(book_path).unwrap_or_else(|e| {
        eprintln!("zyn-claim: {}", e);
        std::process::exit(1);
    });
    let unclaimed = book.entries.values().filter(|e| e.claimed_by.is_none()).count();

    let node = env("ZYN_CLAIM_NODE", "127.0.0.1:8099");
    let listen = env("ZYN_CLAIM_LISTEN", "127.0.0.1:8099");
    let s = std::sync::Arc::new(Serving {
        book: std::sync::Mutex::new(book),
        node: Node::new(&node, chain),
        chain,
        collection,
        treasury,
        public,
        custodians: custodians.clone(),
        threshold,
        request: std::sync::atomic::AtomicU64::new(1),
    });

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("zyn-claim: cannot bind {}: {}", listen, e);
        std::process::exit(1);
    });
    eprintln!(
        "zyn-claim: chain {} collection {} — {} code(s) outstanding",
        chain,
        hex(&collection),
        unclaimed
    );
    eprintln!("zyn-claim: treasury {}", hex(&treasury));
    eprintln!("zyn-claim: signing through {:?}, threshold {}", custodians, threshold);
    eprintln!("zyn-claim: POST http://{}/claim  {{\"code\":\"…\",\"account\":\"64 hex\"}}", listen);

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let s = std::sync::Arc::clone(&s);
        std::thread::spawn(move || {
            let _ = handle(&s, stream);
        });
    }
}

fn handle(s: &Serving, mut stream: TcpStream) -> std::io::Result<()> {
    let Some((method, path, body)) = read_request(&mut stream) else {
        return reply(&mut stream, 400, r#"{"error":"bad request"}"#);
    };
    if method == "OPTIONS" {
        return reply(&mut stream, 204, "");
    }
    if method != "POST" || path != "/claim" {
        return reply(&mut stream, 404, r#"{"error":"POST /claim"}"#);
    }

    let text = String::from_utf8_lossy(&body);
    let code = field(&text, "code").unwrap_or_default();
    let account_hex = field(&text, "account").unwrap_or_default();
    let Some(account) = unhex32(&account_hex) else {
        return reply(
            &mut stream,
            400,
            r#"{"error":"account must be 64 hex characters"}"#,
        );
    };
    if code.trim().is_empty() {
        return reply(&mut stream, 400, r#"{"error":"a code is required"}"#);
    }

    let grant = |_serial: u32, asset: [u8; 32], to: [u8; 32]| -> Result<Granted, String> {
        let epoch = s.node.status().map_err(|e| e.to_string())?.epoch;
        let rid = s
            .request
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let frame = zynzapd::treasury::frame_submission_across(
            &s.custodians,
            &s.public,
            s.threshold,
            s.chain,
            epoch,
            &Intent::Transfer {
                from: s.treasury,
                to,
                asset,
                amount: swapvm::fixed::Fixed::ONE,
            },
            rid,
        )?;
        match s.node.submit_raw(&frame) {
            Ok(_) => Ok(Granted::Moved),
            // The item is unique, so "insufficient balance" can only mean it
            // already left on an earlier attempt. For a claim that is success.
            Err(e) if zynzapd::claim::is_already_gone(&e) => Ok(Granted::AlreadyGone),
            Err(e) => Err(e),
        }
    };

    let outcome = {
        let mut book = s.book.lock().map_err(|_| {
            std::io::Error::other("claim book lock poisoned")
        })?;
        resolve(&mut book, &code, account, s.collection, &grant)
    };

    match outcome {
        Ok(Outcome::Granted { serial, asset }) => {
            eprintln!("zyn-claim: MOLE{:03} -> {}", serial, hex(&account));
            reply(
                &mut stream,
                200,
                &format!(
                    r#"{{"ok":true,"serial":{},"symbol":"MOLE{:03}","asset":"{}"}}"#,
                    serial,
                    serial,
                    hex(&asset)
                ),
            )
        }
        Ok(Outcome::AlreadyBound { serial }) => reply(
            &mut stream,
            409,
            &format!(
                r#"{{"ok":false,"error":"this code has already been claimed by another account","serial":{}}}"#,
                serial
            ),
        ),
        Ok(Outcome::Unknown) => reply(
            &mut stream,
            404,
            r#"{"ok":false,"error":"no such code"}"#,
        ),
        Err(e) => {
            eprintln!("zyn-claim: claim failed: {}", e);
            reply(
                &mut stream,
                500,
                &format!(r#"{{"ok":false,"error":{}}}"#, json_string(&e)),
            )
        }
    }
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Pull one string field out of a small JSON object without a parser.
fn field(text: &str, name: &str) -> Option<String> {
    let key = format!("\"{}\"", name);
    let at = text.find(&key)? + key.len();
    let rest = &text[at..];
    let colon = rest.find(':')? + 1;
    let rest = &rest[colon..];
    let q1 = rest.find('"')? + 1;
    let mut out = String::new();
    let mut chars = rest[q1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => out.push(chars.next()?),
            c => out.push(c),
        }
    }
    None
}

fn read_request(s: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 16 << 10 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut len = 0usize;
    for l in lines {
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    // A claim is a code and an account. Anything larger is not one.
    if len > 4096 {
        return None;
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Some((method, path, body))
}

fn reply(s: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\nConnection: close\r\n\r\n",
        status,
        reason,
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body.as_bytes())?;
    s.flush()
}
