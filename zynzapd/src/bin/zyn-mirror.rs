//! `zyn-mirror` — a data-availability mirror: serves bundles over HTTP `GET`,
//! accepts them over `PUT` with a bearer token. Point a sequencer's
//! `ZYN_DA_MIRRORS` at it and a replica's `ZYN_DA_MIRRORS` at it too.
//!
//! ```text
//!   ZYN_MIRROR_DIR      where bundles live          (./zyn-mirror)
//!   ZYN_MIRROR_LISTEN   host:port                   (127.0.0.1:8181)
//!   ZYN_MIRROR_TOKEN    bearer token for PUT; unset = read-only
//! ```

fn main() {
    let dir = std::env::var("ZYN_MIRROR_DIR").unwrap_or_else(|_| "./zyn-mirror".into());
    let listen = std::env::var("ZYN_MIRROR_LISTEN").unwrap_or_else(|_| "127.0.0.1:8181".into());
    let token = std::env::var("ZYN_MIRROR_TOKEN").ok().filter(|t| !t.is_empty());
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("zyn-mirror: cannot create {}: {}", dir, e);
        std::process::exit(1);
    }
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("zyn-mirror: cannot bind {}: {}", listen, e);
            std::process::exit(1);
        }
    };
    eprintln!(
        "zyn-mirror: serving {} on {} ({})",
        dir,
        listen,
        if token.is_some() { "PUT enabled with token" } else { "read-only" }
    );
    zynzapd::publish::http::serve(dir.into(), listener, token);
}
