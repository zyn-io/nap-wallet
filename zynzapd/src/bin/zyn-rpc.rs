//! `zyn-rpc` — the chain over JSON-RPC 2.0, the way every other chain is read.
//!
//! The node's own socket speaks a binary framing whose payload *is* the epoch
//! commitment, so it cannot grow a transport concern and cannot be reached
//! from a browser. This is the public face: ordinary JSON-RPC over HTTP, which
//! sits behind nginx on 443, proxies like anything else, and answers `curl`.
//! Binary stays the peer protocol — replicas, signers and the mirror keep it.
//!
//! Two rules shape the method table.
//!
//! **A write carries bytes, not fields.** A signed intent commits to an exact
//! encoding. `zyn_sendRawIntent` therefore takes the submission frame as hex
//! and relays it untouched; re-encoding JSON fields into wire bytes here would
//! either break signatures or invent a malleability surface. Bitcoin's
//! `sendrawtransaction` and Solana's `sendTransaction` are the same shape for
//! the same reason.
//!
//! **A signed read stays signed.** `OP_ACCOUNT` derives the account from the
//! signature, which is what stops a stranger reading someone's balance. So
//! `zyn_account` takes a pre-signed read payload, not an account id. Exposing
//! a bare id would quietly turn a private read into a public lookup.
//!
//! ```text
//!   ZYN_RPC_LISTEN     HTTP                       (127.0.0.1:8099 is the node;
//!                                                  this defaults to :8095)
//!   ZYN_RPC_NODE       node RPC to relay to       (127.0.0.1:8100, a replica)
//!   ZYN_CHAIN_ID       the chain                  (11)
//!   ZYN_RPC_ORIGIN     Access-Control-Allow-Origin (*)
//! ```
//!
//! This process holds no key and cannot sign. Everything that needs authority
//! arrives already signed, or is refused by the node behind it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use serde_json::{json, Value};
use zynzapd::client::{hex, CurveView, Node};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

/// JSON-RPC reserves -32768..-32000. Application errors live in the
/// implementation-defined band the spec sets aside at -32000..-32099.
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
/// The node refused, or could not be reached. The message is the node's.
const NODE_ERROR: i64 = -32000;

fn main() {
    let listen = env("ZYN_RPC_LISTEN", "127.0.0.1:8095");
    let node_addr = env("ZYN_RPC_NODE", "127.0.0.1:8100");
    let chain: u32 = env("ZYN_CHAIN_ID", "11").parse().unwrap_or(11);
    let origin = env("ZYN_RPC_ORIGIN", "*");

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| {
        eprintln!("zyn-rpc: cannot bind {}: {}", listen, e);
        std::process::exit(1)
    });
    eprintln!(
        "zyn-rpc: chain {} relaying {} — POST http://{}/",
        chain, node_addr, listen
    );
    let cfg = Arc::new(Cfg {
        node: node_addr,
        chain,
        origin,
    });
    for stream in listener.incoming().flatten() {
        let cfg = Arc::clone(&cfg);
        std::thread::spawn(move || {
            let _ = handle(&cfg, stream);
        });
    }
}

struct Cfg {
    node: String,
    chain: u32,
    origin: String,
}

fn handle(cfg: &Cfg, mut s: TcpStream) -> std::io::Result<()> {
    let Some((method, body)) = read_request(&mut s) else {
        return Ok(());
    };
    let cors = format!(
        "Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Headers: Content-Type\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\nVary: Origin\r\n",
        cfg.origin
    );
    match method.as_str() {
        "OPTIONS" => respond(&mut s, "204 No Content", "text/plain", &cors, b""),
        // A browser opening the URL should learn what it is rather than see a
        // parse error for a request it never meant to make.
        "GET" => respond(
            &mut s,
            "200 OK",
            "application/json",
            &cors,
            discovery(cfg).to_string().as_bytes(),
        ),
        "POST" => {
            let out = dispatch_body(cfg, &body);
            let bytes = match out {
                Some(v) => v.to_string().into_bytes(),
                // A batch of only notifications gets no body, per the spec.
                None => Vec::new(),
            };
            let status = if bytes.is_empty() {
                "204 No Content"
            } else {
                "200 OK"
            };
            respond(&mut s, status, "application/json", &cors, &bytes)
        }
        _ => respond(
            &mut s,
            "405 Method Not Allowed",
            "text/plain",
            &cors,
            b"POST JSON-RPC here",
        ),
    }
}

fn discovery(cfg: &Cfg) -> Value {
    json!({
        "name": "zyn-rpc",
        "protocol": "JSON-RPC 2.0 over HTTP POST",
        "chain": cfg.chain,
        "methods": [
            "zyn_status", "zyn_pools", "zyn_assets", "zyn_curves", "zyn_curve", "zyn_curveQuote", "zyn_quote", "zyn_anchors",
            "zyn_offers", "zyn_offer", "zyn_collections", "zyn_collection",
            "zyn_account", "zyn_sendRawIntent"
        ],
        "notes": {
            "zyn_sendRawIntent": "hex submission frame, relayed byte for byte; the signature commits to it",
            "zyn_account": "hex pre-signed read payload — the account is derived from the signature, never from a parameter"
        }
    })
}

/// One request or a batch, per the JSON-RPC 2.0 spec. `None` means every
/// member was a notification and nothing should be written back.
fn dispatch_body(cfg: &Cfg, body: &[u8]) -> Option<Value> {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return Some(err_obj(Value::Null, PARSE_ERROR, &e.to_string())),
    };
    match parsed {
        Value::Array(items) if items.is_empty() => {
            Some(err_obj(Value::Null, INVALID_REQUEST, "empty batch"))
        }
        Value::Array(items) => {
            let out: Vec<Value> = items
                .into_iter()
                .filter_map(|it| dispatch_one(cfg, it))
                .collect();
            if out.is_empty() {
                None
            } else {
                Some(Value::Array(out))
            }
        }
        one => dispatch_one(cfg, one),
    }
}

fn dispatch_one(cfg: &Cfg, req: Value) -> Option<Value> {
    let id = req.get("id").cloned();
    // A request with no id is a notification: it is served, and answered with
    // nothing at all — including when it fails.
    let notify = id.is_none();
    let id = id.unwrap_or(Value::Null);

    if req.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return (!notify).then(|| err_obj(id, INVALID_REQUEST, "jsonrpc must be \"2.0\""));
    }
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return (!notify).then(|| err_obj(id, INVALID_REQUEST, "no method"));
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    let out = call(cfg, method, &params);
    if notify {
        return None;
    }
    Some(match out {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, msg)) => err_obj(id, code, &msg),
    })
}

fn err_obj(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Positional or named parameters, both allowed by the spec.
fn param<'a>(p: &'a Value, i: usize, name: &str) -> Option<&'a Value> {
    match p {
        Value::Array(a) => a.get(i),
        Value::Object(o) => o.get(name),
        _ => None,
    }
}

fn want_str(p: &Value, i: usize, name: &str) -> Result<String, (i64, String)> {
    param(p, i, name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| (INVALID_PARAMS, format!("{} must be a string", name)))
}

fn want_u64(p: &Value, i: usize, name: &str) -> Result<u64, (i64, String)> {
    param(p, i, name)
        .and_then(Value::as_u64)
        .ok_or_else(|| (INVALID_PARAMS, format!("{} must be a number", name)))
}

fn unhex(s: &str, what: &str) -> Result<Vec<u8>, (i64, String)> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err((
            INVALID_PARAMS,
            format!("{}: odd number of hex digits", what),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| (INVALID_PARAMS, format!("{}: not hex", what)))
        })
        .collect()
}

/// A decimal amount in whole units, e.g. `0.05`. The CLI has this too, but its
/// version exits the process on bad input, which is not a thing a server may
/// do with a stranger's parameter.
fn fixed_of(s: &str) -> Result<zyn_vm::fixed::Fixed, (i64, String)> {
    let bad = |why: &str| (INVALID_PARAMS, format!("amount: {}", why));
    let s = s.trim();
    if s.starts_with('-') {
        return Err(bad("must not be negative"));
    }
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    if frac.len() > 18 {
        return Err(bad("at most 18 decimals"));
    }
    if whole.is_empty() && frac.is_empty() {
        return Err(bad("empty"));
    }
    let whole: i128 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| bad("not a decimal"))?
    };
    let frac: i128 = if frac.is_empty() {
        0
    } else {
        format!("{:0<18}", frac)
            .parse()
            .map_err(|_| bad("not a decimal"))?
    };
    whole
        .checked_mul(1_000_000_000_000_000_000)
        .and_then(|w| w.checked_add(frac))
        .map(zyn_vm::fixed::Fixed::raw)
        .ok_or_else(|| bad("too large"))
}

fn node_err<T>(r: Result<T, String>) -> Result<T, (i64, String)> {
    r.map_err(|e| (NODE_ERROR, e))
}

fn want_id(p: &Value, i: usize, name: &str) -> Result<[u8; 32], (i64, String)> {
    let value = want_str(p, i, name)?;
    zynzapd::client::unhex32(&value).map_err(|e| (INVALID_PARAMS, format!("{name}: {e}")))
}

fn curve_json(c: &CurveView) -> Value {
    json!({
        "asset": hex(&c.asset), "creator": hex(&c.creator), "symbol": c.symbol,
        "displayName": c.display_name, "metadataHash": hex(&c.metadata_hash),
        "feeBps": c.fee_bps, "sold": c.sold.to_string(), "curveReserve": c.curve_reserve.to_string(), "marketZec": c.market_zec.to_string(),
        "creatorFees": c.creator_fees.to_string(), "graduationFees": c.graduation_fees.to_string(),
        "graduatedTokenLiquidity": c.graduated_token_liquidity.to_string(),
        "graduatedZecLiquidity": c.graduated_zec_liquidity.to_string(),
        "graduationOverflow": c.graduation_overflow.to_string(),
        "graduatedLockedLp": c.graduated_locked_lp.to_string(),
        "zecPerToken": c.marginal_price.to_string(),
        "marginalPrice": c.marginal_price.to_string(), "graduated": c.pool.is_some(),
        "pool": c.pool.map(|p| hex(&p)),
    })
}

fn call(cfg: &Cfg, method: &str, p: &Value) -> Result<Value, (i64, String)> {
    let n = Node::new(&cfg.node, cfg.chain);
    match method {
        "zyn_status" => {
            let s = node_err(n.status())?;
            Ok(json!({
                "chain": cfg.chain,
                "role": if s.role == 1 { "replica" } else { "sequencer" },
                "seq": s.seq, "epoch": s.epoch, "root": hex(&s.root),
                "backing": s.backing.to_string(),
                "pools": s.pools, "accounts": s.accounts,
                "clearing": s.clearing,
                "anchored_epoch": s.anchored_epoch,
                "verified_height": s.verified_height,
                "forced_pending": s.forced_pending,
                "censored": s.censored,
                "health": s.health.iter().map(|h| json!({
                    "name": h.name, "scanned_to": h.scanned_to, "down": h.down, "error": h.error
                })).collect::<Vec<_>>(),
            }))
        }
        "zyn_pools" => {
            let v = node_err(n.pools())?;
            Ok(json!(v.iter().map(|x| json!({
                "id": hex(&x.id),
                "asset0": hex(&x.asset0), "asset1": hex(&x.asset1),
                "reserve0": x.reserve0.to_string(), "reserve1": x.reserve1.to_string(),
                "fee_bps": x.fee_bps, "effective_fee_bps": x.effective_fee_bps,
                "reference": x.reference.map(|(px, seq)| json!({ "price": px.to_string(), "seq": seq })),
            })).collect::<Vec<_>>()))
        }
        "zyn_assets" => {
            let v = node_err(n.assets())?;
            Ok(json!(v
                .iter()
                .map(|a| json!({
                    "id": hex(&a.id), "symbol": a.symbol, "supply": a.supply.to_string(),
                    "lp_of": a.lp_of.map(|v| hex(&v)), "collection": a.collection.map(|v| hex(&v)),
                    "content": a.content.map(|c| hex(&c)),
                }))
                .collect::<Vec<_>>()))
        }
        "zyn_curves" => {
            let v = node_err(n.curves())?;
            Ok(json!(v.iter().map(curve_json).collect::<Vec<_>>()))
        }
        "zyn_curve" => {
            let asset = want_id(p, 0, "asset")?;
            Ok(node_err(n.curve(asset))?
                .as_ref()
                .map(curve_json)
                .unwrap_or(Value::Null))
        }
        "zyn_curveQuote" => {
            let asset = want_id(p, 0, "asset")?;
            let side = want_str(p, 1, "side")?;
            let buy = match side.as_str() {
                "buy" => true,
                "sell" => false,
                _ => return Err((INVALID_PARAMS, "side must be buy or sell".into())),
            };
            let tokens = fixed_of(&want_str(p, 2, "tokens")?)?;
            let q = node_err(n.curve_quote(buy, asset, tokens))?;
            Ok(json!({
                "side": side, "asset": hex(&asset), "tokens": tokens.to_string(),
                "principal": q.principal.to_string(), "fee": q.fee.to_string(),
                "settlement": q.settlement.to_string(), "soldAfter": q.sold_after.to_string(),
                "priceAfter": q.price_after.to_string(), "graduates": q.graduates,
            }))
        }
        "zyn_quote" => {
            let asset_in = want_id(p, 0, "assetIn")?;
            let path: Vec<[u8; 32]> = param(p, 1, "path")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    (
                        INVALID_PARAMS,
                        "path must be an array of pool ids".to_string(),
                    )
                })?
                .iter()
                .map(|v| {
                    v.as_str()
                        .ok_or_else(|| (INVALID_PARAMS, "pool id must be hex".to_string()))
                        .and_then(|s| zynzapd::client::unhex32(s).map_err(|e| (INVALID_PARAMS, e)))
                })
                .collect::<Result<_, _>>()?;
            let amount = fixed_of(&want_str(p, 2, "amount")?)?;
            let q = node_err(n.quote(asset_in, &path, amount))?;
            Ok(json!({
                "out": q.amount_out.to_string(), "bestCase": q.best_case.to_string(), "assetOut": hex(&q.asset_out),
                "hops": q.hops.iter().map(|h| json!({
                    "pool": hex(&h.pool), "assetIn": hex(&h.asset_in), "assetOut": hex(&h.asset_out),
                    "amountIn": h.amount_in.to_string(), "amountOut": h.amount_out.to_string(),
                    "feeAsset": hex(&h.fee_asset), "fee": h.fee.to_string(),
                    "poolFee": h.pool_fee.to_string(), "protocolFee": h.protocol_fee.to_string(),
                    "creatorFee": h.creator_fee.to_string(), "polFee": h.pol_fee.to_string(),
                })).collect::<Vec<_>>()
            }))
        }
        "zyn_anchors" => {
            let limit = param(p, 0, "limit")
                .and_then(Value::as_u64)
                .unwrap_or(100)
                .min(10_000) as u32;
            let v = node_err(n.anchors(limit))?;
            Ok(json!(v
                .iter()
                .map(|a| json!({
                    "epoch": a.epoch, "root": hex(&a.root), "anchorId": hex(&a.anchor_id),
                    "txid": a.txid,
                    // 0 is "broadcast, not yet seen confirmed" — not block zero.
                    "height": if a.height == 0 { Value::Null } else { json!(a.height) },
                }))
                .collect::<Vec<_>>()))
        }
        "zyn_offers" => {
            let v = node_err(n.offers())?;
            Ok(json!(v.iter().map(offer_json).collect::<Vec<_>>()))
        }
        "zyn_offer" => {
            let id = want_u64(p, 0, "id")?;
            Ok(node_err(n.offer(id))?
                .as_ref()
                .map(offer_json)
                .unwrap_or(Value::Null))
        }
        "zyn_collections" => {
            let v = node_err(n.collections())?;
            Ok(json!(v.iter().map(collection_json).collect::<Vec<_>>()))
        }
        "zyn_collection" => {
            let id = want_id(p, 0, "id")?;
            Ok(node_err(n.collection(id))?
                .as_ref()
                .map(collection_json)
                .unwrap_or(Value::Null))
        }
        // Signed, and stays signed: the account is derived from the signature
        // inside this payload, never from a parameter.
        "zyn_account" => {
            let payload = unhex(&want_str(p, 0, "signedRead")?, "signedRead")?;
            let r = node_err(n.account_raw(&payload))?;
            Ok(match r {
                None => Value::Null,
                Some(r) => json!({
                    "spendable": r.spendable.iter().map(|(a, v)| json!({ "asset": hex(a), "amount": v.to_string() })).collect::<Vec<_>>(),
                    "exiting": r.exiting.iter().map(|(a, v, e)| json!({ "asset": hex(a), "amount": v.to_string(), "epoch": e })).collect::<Vec<_>>(),
                    "unreleased": r.unreleased.iter().map(|(a, v, e)| json!({ "asset": hex(a), "amount": v.to_string(), "epoch": e })).collect::<Vec<_>>(),
                    "binding": r.binding.map(|b| hex(&b)),
                    "redirect": r.redirect.map(|(d, e)| json!({ "to": hex(&d), "epoch": e })),
                }),
            })
        }
        // Relayed byte for byte. See the module note.
        "zyn_sendRawIntent" => {
            let frame = unhex(&want_str(p, 0, "frame")?, "frame")?;
            if frame.is_empty() {
                return Err((INVALID_PARAMS, "frame is empty".into()));
            }
            let a = node_err(n.submit_raw(&frame))?;
            Ok(json!({
                "seq": a.seq, "epoch": a.epoch, "receipts": a.receipts, "queued": a.queued,
                "swapped": a.swapped.map(|(i, o)| json!({ "in": i.to_string(), "out": o.to_string() })),
                "liquidity": a.liquidity.map(|(x, y, sh)| json!({ "amount0": x.to_string(), "amount1": y.to_string(), "shares": sh.to_string() })),
            }))
        }
        _ => Err((METHOD_NOT_FOUND, format!("no method {}", method))),
    }
}

fn offer_json(o: &zynzapd::client::OfferView) -> Value {
    json!({
        "id": o.id, "maker": hex(&o.maker),
        "offerAsset": hex(&o.offer_asset), "offerAmount": o.offer_amount.to_string(),
        "wantAsset": hex(&o.want_asset), "wantAmount": o.want_amount.to_string(),
        "expiresAtEpoch": o.expires_at_epoch,
    })
}

fn collection_json(c: &zynzapd::client::CollectionView) -> Value {
    json!({
        "id": hex(&c.id), "creator": hex(&c.creator), "symbol": c.symbol,
        "cap": c.cap, "minted": c.minted, "outstanding": c.outstanding,
        "pool": c.pool.to_string(), "feeBps": c.fee_bps,
        "phase": c.phase, "phaseName": c.phase_name(),
    })
}

fn read_request(s: &mut TcpStream) -> Option<(String, Vec<u8>)> {
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
        if buf.len() > 64 << 10 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let method = lines.next()?.split_whitespace().next()?.to_string();
    let mut len = 0usize;
    for l in lines {
        if let Some(v) = l.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    // A relayed intent is small; anything this size is not one.
    if len > 1 << 20 {
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
    Some((method, body))
}

fn respond(
    s: &mut TcpStream,
    status: &str,
    ctype: &str,
    extra: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n{}Connection: close\r\n\r\n",
        status,
        ctype,
        body.len(),
        extra
    )?;
    s.write_all(body)?;
    s.flush()
}
