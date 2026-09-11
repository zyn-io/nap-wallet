//! `nap-wallet` — Nap Wallet as a local process with a page on loopback.
//!
//! Serves `zynzapd::app` over loopback HTTP: the page at `/`, the API under
//! `/api/`. Keys never leave the process. A browser extension may call the
//! API too (its origin is `chrome-extension://…`), which is why the server
//! answers CORS preflights for extension origins and no others.
//!
//! ```text
//!   ZYN_APP_DIR     ~/.zyn/app          keys and state
//!   ZYN_APP_WALLET  $ZYN_APP_DIR/wallet the Zcash recovery record (+ .state)
//!   ZYN_APP_KEY     $ZYN_APP_DIR/zyn.key the Zyn account key
//!   ZYN_LIGHTD      168.119.53.39:8098   compact-block server
//!   ZYN_NODE        168.119.53.39:8099   Zyn node RPC
//!   ZYN_CHAIN       11
//!   ZYN_VAULT       utest1h6sf…x2t407    the vault's deposit address
//!   ZYN_APP_LISTEN  127.0.0.1:8977
//!   ZYN_AGENT_LISTEN 127.0.0.1:8978  restricted agent API only
//!   ZYN_AGENT_TOKEN random secret shared with `nap-agent`
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};
use zynzapd::app::{api, App, Config};
use zynzapd::client::{account, hex};
use zynzapd::wallet::network_name;

const UI: &str = include_str!("../../ui/index.html");
const NAP_MARK: &[u8] = include_bytes!("../../ui/nap-mark.png");
const BRICOLAGE_GROTESQUE: &[u8] = include_bytes!("../../ui/fonts/BricolageGrotesque.ttf");
const IBM_PLEX_SANS: &[u8] = include_bytes!("../../ui/fonts/IBMPlexSans.ttf");
const IBM_PLEX_MONO_REGULAR: &[u8] = include_bytes!("../../ui/fonts/IBMPlexMono-Regular.ttf");
const IBM_PLEX_MONO_MEDIUM: &[u8] = include_bytes!("../../ui/fonts/IBMPlexMono-Medium.ttf");
/// ZynZap, the AMM front, served from the same origin so it can call the
/// API directly (hosted elsewhere it goes through the extension provider).
const ZYNZAP: &str = include_str!("../../../apps/zynzap/index.html");

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn main() {
    let dir = PathBuf::from(env("ZYN_APP_DIR", &format!("{}/.zyn/app", env("HOME", "."))));
    let cfg = Config::in_dir(dir);
    let listen = env("ZYN_APP_LISTEN", "127.0.0.1:8977");
    let agent_listen = env("ZYN_AGENT_LISTEN", "127.0.0.1:8978");
    let agent_token = env("ZYN_AGENT_TOKEN", "");
    if agent_token.len() < 32 {
        eprintln!("nap-wallet: ZYN_AGENT_TOKEN must contain at least 32 characters");
        std::process::exit(1);
    }
    let app = Arc::new(App::open(&cfg).unwrap_or_else(|e| { eprintln!("nap-wallet: {}", e); std::process::exit(1) }));
    {
        let w = app.wallet.lock().unwrap();
        eprintln!("nap-wallet: {} wallet {}  account {}  node {} chain {}", network_name(w.network()), w.address(), hex(&account(&app.key)), cfg.node, cfg.chain);
    }
    let agent_listener = TcpListener::bind(&agent_listen).expect("bind agent API");
    let agent_app = Arc::clone(&app);
    let agent_secret = Arc::new(agent_token);
    let agent_secret_for_thread = Arc::clone(&agent_secret);
    std::thread::spawn(move || {
        for stream in agent_listener.incoming().flatten() {
            let app = Arc::clone(&agent_app);
            let secret = Arc::clone(&agent_secret_for_thread);
            std::thread::spawn(move || { let _ = handle(&app, stream, true, &secret); });
        }
    });
    let listener = TcpListener::bind(&listen).expect("bind wallet UI");
    eprintln!("nap-wallet: open http://{}/", listen);
    eprintln!("nap-wallet: restricted agent API on {}", agent_listen);
    for stream in listener.incoming().flatten() {
        let app = Arc::clone(&app);
        let secret = Arc::clone(&agent_secret);
        std::thread::spawn(move || { let _ = handle(&app, stream, false, &secret); });
    }
}

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    same_origin: bool,
    origin: Option<String>,
    agent_token: Option<String>,
}

fn read_request(s: &mut TcpStream) -> Option<Request> {
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 { return None }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break p + 4 }
        if buf.len() > 64 << 10 { return None }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let mut req = lines.next()?.split_whitespace();
    let method = req.next()?.to_string();
    let path = req.next()?.split('?').next()?.to_string();
    let mut len = 0usize;
    let mut same_origin = false;
    let mut origin = None;
    let mut agent_token = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else { continue };
        match k.trim().to_ascii_lowercase().as_str() {
            "content-length" => len = v.trim().parse().unwrap_or(0),
            "x-zyn" => same_origin = true,
            "origin" => origin = Some(v.trim().to_string()),
            "x-nap-agent-token" => agent_token = Some(v.trim().to_string()),
            _ => {}
        }
    }
    if len > 1 << 20 { return None }
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 { break }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Some(Request { method, path, body, same_origin, origin, agent_token })
}

/// An extension is the only cross-origin caller we answer.
fn cors(origin: &Option<String>) -> String {
    match origin {
        Some(o) if o.starts_with("chrome-extension://") || o.starts_with("moz-extension://") || o.starts_with("safari-web-extension://") => {
            format!("Access-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Headers: Content-Type, X-Zyn\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nVary: Origin\r\n", o)
        }
        _ => String::new(),
    }
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, extra: &str, body: &[u8]) -> std::io::Result<()> {
    write!(s, "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{}Connection: close\r\n\r\n", status, ctype, body.len(), extra)?;
    s.write_all(body)?;
    s.flush()
}

fn agent_route_allowed(method: &str, path: &str) -> bool {
    matches!((method, path),
        ("GET", "/api/agent/status")
            | ("GET", "/api/agent/portfolio")
            | ("GET", "/api/agent/assets")
            | ("GET", "/api/agent/pools")
            | ("GET", "/api/agent/offers")
            | ("GET", "/api/agent/anchors")
            | ("GET", "/api/agent/mandates")
            | ("POST", "/api/agent/quote")
            | ("POST", "/api/agent/draft-swap")
            | ("POST", "/api/agent/check-swap")
            | ("POST", "/api/agent/execute-swap")
            | ("POST", "/api/agent/action")
            | ("POST", "/api/agent/pause")
            | ("POST", "/api/agent/close")
    )
}

fn static_asset(path: &str) -> Option<(&'static str, &'static [u8])> {
    match path {
        "/nap-mark.png" => Some(("image/png", NAP_MARK)),
        "/fonts/BricolageGrotesque.ttf" => Some(("font/ttf", BRICOLAGE_GROTESQUE)),
        "/fonts/IBMPlexSans.ttf" => Some(("font/ttf", IBM_PLEX_SANS)),
        "/fonts/IBMPlexMono-Regular.ttf" => Some(("font/ttf", IBM_PLEX_MONO_REGULAR)),
        "/fonts/IBMPlexMono-Medium.ttf" => Some(("font/ttf", IBM_PLEX_MONO_MEDIUM)),
        _ => None,
    }
}

fn handle(app: &Arc<App>, mut s: TcpStream, agent_only: bool, agent_secret: &str) -> std::io::Result<()> {
    let Some(req) = read_request(&mut s) else { return Ok(()) };
    if agent_only {
        if !agent_route_allowed(&req.method, &req.path) {
            return respond(&mut s, "404 Not Found", "text/plain", "", b"not available on the agent service");
        }
        if req.agent_token.as_deref() != Some(agent_secret) {
            return respond(&mut s, "403 Forbidden", "text/plain", "", b"invalid agent token");
        }
    }
    let cors = cors(&req.origin);
    if req.method == "OPTIONS" {
        return respond(&mut s, "204 No Content", "text/plain", &cors, b"");
    }
    if req.method == "GET" && req.path == "/" {
        return respond(&mut s, "200 OK", "text/html; charset=utf-8", "", UI.as_bytes());
    }
    if req.method == "GET" {
        if let Some((content_type, body)) = static_asset(&req.path) {
            return respond(&mut s, "200 OK", content_type, "", body);
        }
    }
    if req.method == "GET" && (req.path == "/zynzap" || req.path == "/zynzap/") {
        return respond(&mut s, "200 OK", "text/html; charset=utf-8", "", ZYNZAP.as_bytes());
    }
    if !req.path.starts_with("/api/") {
        return respond(&mut s, "404 Not Found", "text/plain", "", b"not here");
    }
    if !agent_only && req.method == "POST" && !req.same_origin {
        // Only the page (or an extension, after a preflight) can set a
        // custom header; a cross-site form cannot.
        return respond(&mut s, "403 Forbidden", "text/plain", &cors, b"missing X-Zyn header");
    }
    let input: Value = if req.body.is_empty() { json!({}) } else { serde_json::from_slice(&req.body).unwrap_or(json!({})) };
    let (status, body) = match api(app, &req.method, &req.path, &input) {
        Ok(v) => ("200 OK", v),
        Err(e) => { app.note(format!("error: {}", e)); ("400 Bad Request", json!({ "error": e })) }
    };
    respond(&mut s, status, "application/json", &cors, body.to_string().as_bytes())
}

#[cfg(test)]
mod agent_boundary_tests {
    use super::{agent_route_allowed, static_asset, UI};

    #[test]
    fn the_agent_listener_has_no_wallet_or_mandate_creation_escape_hatch() {
        for (method, path) in [
            ("POST", "/api/export"),
            ("POST", "/api/import"),
            ("POST", "/api/send"),
            ("POST", "/api/withdraw"),
            ("POST", "/api/transfer"),
            ("POST", "/api/bind"),
            ("POST", "/api/settings"),
            ("POST", "/api/agent/mandates"),
            ("POST", "/api/raw"),
        ] {
            assert!(!agent_route_allowed(method, path), "{method} {path} escaped the allowlist");
        }
        assert!(agent_route_allowed("POST", "/api/agent/execute-swap"));
        assert!(agent_route_allowed("POST", "/api/agent/pause"));
    }

    #[test]
    fn the_wallet_ui_loads_fonts_only_from_its_own_origin() {
        assert!(!UI.contains("fonts.googleapis.com"));
        assert!(!UI.contains("fonts.gstatic.com"));
        for path in [
            "/fonts/BricolageGrotesque.ttf",
            "/fonts/IBMPlexSans.ttf",
            "/fonts/IBMPlexMono-Regular.ttf",
            "/fonts/IBMPlexMono-Medium.ttf",
        ] {
            let (content_type, body) = static_asset(path).expect("font route");
            assert_eq!(content_type, "font/ttf");
            assert!(body.len() > 100_000, "{path} is not the bundled font");
        }
    }
}
