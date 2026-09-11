//! `zynscan` — the chain, checkable by someone who does not trust us.
//!
//! Serves the anchor index over HTTP: every Zyn epoch, the state root it
//! sealed, and the Zcash transaction that carries it. "Settled in batches on
//! Zcash" is a claim; this is the page that lets a reader follow it to a
//! transaction they can look up in an explorer we do not run.
//!
//! Point it at a **replica** (§40.2). A replica verified the chain from Zcash
//! and mirrors alone and sequenced nothing, so what it serves is an argument
//! about decentralisation rather than a view of our own claims. It will read
//! a sequencer just as happily, and says on the page which one it got.
//!
//! ```text
//!   ZYN_SCAN_LISTEN    HTTP, read-only            (0.0.0.0:8090)
//!   ZYN_SCAN_NODE      node RPC to read           (127.0.0.1:8100, a replica)
//!   ZYN_CHAIN_ID       the chain                  (11)
//!   ZYN_SCAN_LIMIT     anchors to show            (200)
//!   ZYN_SCAN_REFRESH   seconds between reads      (15)
//!   ZYN_SCAN_EXPLORER  Zcash explorer tx base URL
//! ```
//!
//! Nothing here can write: no key is loaded and no submit path exists. The
//! node is read on a timer rather than per request, so a page that gets
//! attention cannot turn into load on the chain behind it.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use zynzapd::client::{hex, AnchorView, Node, Status};

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

/// What the last read of the node produced. Served to every visitor until the
/// next one lands, so the node sees one reader however many people look.
#[derive(Default)]
struct Snapshot {
    status: Option<Status>,
    anchors: Vec<AnchorView>,
    /// Why the last read failed, if it did. Shown rather than swallowed: a
    /// scan that silently serves stale data is worse than one that says so.
    error: Option<String>,
    at: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn main() {
    let listen = env("ZYN_SCAN_LISTEN", "0.0.0.0:8090");
    let addr = env("ZYN_SCAN_NODE", "127.0.0.1:8100");
    let chain: u32 = env("ZYN_CHAIN_ID", "11").parse().unwrap_or(11);
    let limit: u32 = env("ZYN_SCAN_LIMIT", "200").parse().unwrap_or(200);
    let refresh: u64 = env("ZYN_SCAN_REFRESH", "15").parse().unwrap_or(15).max(2);
    let explorer = env("ZYN_SCAN_EXPLORER", "https://testnet.zcashexplorer.app/transactions/");

    let snap = Arc::new(Mutex::new(Snapshot::default()));
    {
        let (snap, addr) = (Arc::clone(&snap), addr.clone());
        std::thread::spawn(move || loop {
            let node = Node::new(&addr, chain);
            let got = node.status().and_then(|s| node.anchors(limit).map(|a| (s, a)));
            if let Ok(mut w) = snap.lock() {
                match got {
                    Ok((s, mut a)) => {
                        // Newest first: a reader wants the most recent
                        // settlement, not the chain's first one.
                        a.sort_by(|x, y| y.epoch.cmp(&x.epoch));
                        *w = Snapshot { status: Some(s), anchors: a, error: None, at: now() };
                    }
                    // Keep what was last proved and say the read failed. The
                    // page then shows real anchors and an honest banner.
                    Err(e) => { w.error = Some(e); }
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(refresh));
        });
    }

    let listener = TcpListener::bind(&listen).unwrap_or_else(|e| { eprintln!("zynscan: cannot bind {}: {}", listen, e); std::process::exit(1) });
    eprintln!("zynscan: chain {} reading {} — http://{}/", chain, addr, listen);
    let cfg = Arc::new((chain, addr, explorer));
    for stream in listener.incoming().flatten() {
        let (snap, cfg) = (Arc::clone(&snap), Arc::clone(&cfg));
        std::thread::spawn(move || { let _ = handle(&snap, &cfg, stream); });
    }
}

fn read_path(s: &mut TcpStream) -> Option<String> {
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 { return None }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break }
        // A read-only GET server needs no body at all; anything this long is
        // not a request we serve.
        if buf.len() > 8 << 10 { return None }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let mut req = head.lines().next()?.split_whitespace();
    let method = req.next()?;
    if method != "GET" && method != "HEAD" { return None }
    Some(req.next()?.to_string())
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        s,
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n\
         Access-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        status, ctype, body.len()
    )?;
    s.write_all(body)?;
    s.flush()
}

fn handle(snap: &Arc<Mutex<Snapshot>>, cfg: &Arc<(u32, String, String)>, mut s: TcpStream) -> std::io::Result<()> {
    let Some(path) = read_path(&mut s) else { return Ok(()) };
    let route = path.split('?').next().unwrap_or("/");
    let (chain, node, explorer) = (cfg.0, cfg.1.as_str(), cfg.2.as_str());
    let g = snap.lock().map_err(|_| std::io::Error::other("poisoned"))?;
    match route {
        "/healthz" => respond(&mut s, "200 OK", "text/plain", if g.status.is_some() { b"ok" } else { b"no data" }),
        "/api/status" => respond(&mut s, "200 OK", "application/json", status_json(&g, chain, node).as_bytes()),
        "/api/anchors" => respond(&mut s, "200 OK", "application/json", anchors_json(&g).as_bytes()),
        "/" => respond(&mut s, "200 OK", "text/html; charset=utf-8", page(&g, chain, node, explorer).as_bytes()),
        _ => respond(&mut s, "404 Not Found", "text/plain", b"not found"),
    }
}

fn status_json(g: &Snapshot, chain: u32, node: &str) -> String {
    let Some(st) = g.status.as_ref() else {
        return format!(r#"{{"chain":{},"reading":"{}","ready":false,"error":{}}}"#, chain, esc_json(node), g.error.as_deref().map(esc_quoted).unwrap_or_else(|| "null".into()));
    };
    format!(
        r#"{{"chain":{},"reading":"{}","ready":true,"role":"{}","seq":{},"epoch":{},"root":"{}","anchored_epoch":{},"verified_height":{},"forced_pending":{},"censored":{},"accounts":{},"pools":{},"fetched_at":{},"error":{}}}"#,
        chain, esc_json(node), if st.role == 1 { "replica" } else { "sequencer" },
        st.seq, st.epoch, hex(&st.root), st.anchored_epoch, st.verified_height,
        st.forced_pending, st.censored, st.accounts, st.pools, g.at,
        g.error.as_deref().map(esc_quoted).unwrap_or_else(|| "null".into())
    )
}

fn anchors_json(g: &Snapshot) -> String {
    let rows: Vec<String> = g.anchors.iter().map(|a| format!(
        r#"{{"epoch":{},"root":"{}","anchor_id":"{}","txid":"{}","height":{}}}"#,
        a.epoch, hex(&a.root), hex(&a.anchor_id), esc_json(&a.txid), a.height
    )).collect();
    format!(r#"{{"anchors":[{}]}}"#, rows.join(","))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
/// JSON string body: the values here are hex, hostnames and node error text,
/// so quotes and backslashes are the whole risk.
fn esc_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', " ")
}
fn esc_quoted(s: &str) -> String {
    format!("\"{}\"", esc_json(s))
}
fn short(s: &str, n: usize) -> String {
    if s.len() > 2 * n { format!("{}…{}", &s[..n], &s[s.len() - 6..]) } else { s.to_string() }
}

fn page(g: &Snapshot, chain: u32, node: &str, explorer: &str) -> String {
    let (role, head) = match g.status.as_ref() {
        Some(st) => (
            if st.role == 1 { "a verifying replica" } else { "the sequencer" },
            format!(
                r#"<div class="grid">
      <div class="stat"><span class="k">Chain</span><span class="v num">{chain}</span></div>
      <div class="stat"><span class="k">Epoch</span><span class="v num">{epoch}</span></div>
      <div class="stat"><span class="k">Last anchored epoch</span><span class="v num">{anch}</span></div>
      <div class="stat"><span class="k">Anchors listed</span><span class="v num">{n}</span></div>
    </div>"#,
                chain = chain, epoch = st.epoch, anch = st.anchored_epoch, n = g.anchors.len()
            ),
        ),
        None => ("a node", format!(r#"<div class="grid"><div class="stat"><span class="k">Chain</span><span class="v num">{}</span></div></div>"#, chain)),
    };

    let banner = match (g.status.as_ref(), g.error.as_deref()) {
        (_, Some(e)) => format!(r#"<p class="warn">The last read of the node failed: {}. Anything below is what was last proved, not what is true now.</p>"#, esc(e)),
        (None, None) => r#"<p class="warn">Waiting for the first read of the node.</p>"#.to_string(),
        _ => String::new(),
    };

    let rows = if g.anchors.is_empty() {
        r#"<tr><td colspan="4" class="empty">No anchors served. A node holding no bundles refuses rather than reporting an empty chain, so this means it has none — not that nothing was ever settled.</td></tr>"#.to_string()
    } else {
        g.anchors.iter().map(|a| {
            let txid = esc(&a.txid);
            format!(
                r#"<tr><td class="num">{epoch}</td><td class="mono" title="{root}">{root_s}</td>
       <td class="mono"><a href="{ex}{txid}" target="_blank" rel="noopener noreferrer" title="{txid}">{txid_s}</a></td>
       <td class="num">{height}</td></tr>"#,
                epoch = a.epoch,
                root = hex(&a.root), root_s = short(&hex(&a.root), 10),
                ex = esc(explorer), txid = txid, txid_s = short(&txid, 10),
                // The index carries 0 for an anchor whose transaction has been
                // broadcast but not yet seen confirmed. Printing that as a
                // height claims it settled in block zero.
                height = if a.height == 0 { "<span class=\"pending\">broadcast</span>".to_string() } else { a.height.to_string() },
            )
        }).collect::<Vec<_>>().join("\n")
    };

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>zynscan</title>
<style>
:root {{
  --bg:#f7f4ea; --surface:#fff; --line:#d8d5c9; --ink:#202326; --ink-2:#555b5d; --ink-3:#7c807f;
  --accent:#0e6f6e; --gold:#a87509; --record:#6b7385; --warn:#b5651d;
  --sans:"IBM Plex Sans",system-ui,-apple-system,"Segoe UI",sans-serif;
  --mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
  color-scheme: light dark;
}}
@media (prefers-color-scheme: dark) {{ :root {{
  --bg:#151718; --surface:#202326; --line:#414649; --ink:#f7f4ea; --ink-2:#c7c8c2; --ink-3:#919694;
  --accent:#50bdb6; --gold:#e0a51b; --record:#abb0b2; --warn:#e6934a;
}} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 var(--sans); }}
.wrap {{ max-width:1000px; margin:0 auto; padding:28px 18px 64px }}
h1 {{ margin:0 0 2px; font-size:25px; letter-spacing:-.02em }}
h1 span {{ color:var(--gold) }}
.lede {{ margin:0 0 22px; color:var(--ink-2); max-width:66ch }}
.card {{ background:var(--surface); border:1px solid var(--line); border-radius:14px; padding:16px 18px; margin-bottom:20px }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px }}
.stat {{ display:flex; flex-direction:column; gap:2px }}
.k {{ font-size:11.5px; letter-spacing:.07em; text-transform:uppercase; color:var(--ink-3) }}
.v {{ font-size:21px; font-weight:600 }}
.num {{ font-family:var(--mono); font-variant-numeric:tabular-nums }}
.mono {{ font-family:var(--mono); font-size:13px }}
.src {{ margin:10px 0 0; padding-top:10px; border-top:1px solid var(--line); font-size:13px; color:var(--record) }}
.src code {{ font-family:var(--mono) }}
.scroll {{ overflow-x:auto }}
table {{ width:100%; border-collapse:collapse; min-width:640px }}
th {{ text-align:left; font-size:11.5px; letter-spacing:.07em; text-transform:uppercase; color:var(--ink-3); font-weight:500; padding:0 12px 9px 0; border-bottom:1px solid var(--line) }}
td {{ padding:9px 12px 9px 0; border-bottom:1px solid var(--line); vertical-align:baseline }}
td.num, th.r {{ text-align:right }}
td:first-child, th:first-child {{ text-align:left; width:1%; white-space:nowrap; padding-right:28px }}
tbody td:last-child, thead th:last-child {{ padding-right:0 }}
td.num {{ color:var(--ink-2) }}
a {{ color:var(--accent) }}
a:focus-visible, summary:focus-visible {{ outline:2px solid var(--accent); outline-offset:2px }}
.empty {{ color:var(--ink-3); padding:18px 0; font-size:13.5px }}
.pending {{ font-family:var(--sans); font-size:12px; color:var(--ink-3) }}
.warn {{ margin:0 0 20px; padding:11px 14px; border-radius:10px; font-size:13.5px;
  color:var(--warn); border:1px solid currentColor; background:transparent }}
footer {{ margin-top:26px; font-size:12.5px; color:var(--ink-3) }}
</style></head>
<body><div class="wrap">
  <h1>zyn<span>scan</span></h1>
  <p class="lede">Every Zyn epoch is sealed to a state root, and that root is written into a Zcash
  transaction. Each row below is one of those: follow the transaction into a block explorer
  we do not run, and the settlement claim checks out without taking our word for it.</p>
  {banner}
  <div class="card">
    {head}
    <p class="src">Read from {role} at <code>{node}</code>, {age}s ago.
    This page cannot write: it holds no key and serves no submit route.</p>
  </div>
  <div class="card">
    <div class="scroll"><table>
      <thead><tr><th>Epoch</th><th>State root</th><th>Zcash transaction</th><th class="r">Height</th></tr></thead>
      <tbody>
{rows}
      </tbody>
    </table></div>
  </div>
  <footer>Also as JSON: <a href="/api/anchors">/api/anchors</a> · <a href="/api/status">/api/status</a></footer>
</div></body></html>"#,
        banner = banner,
        head = head,
        role = role,
        node = esc(node),
        age = now().saturating_sub(g.at.max(1)).min(99_999),
        rows = rows,
    )
}
