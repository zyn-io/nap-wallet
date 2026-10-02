//! Nap Wallet on a phone: the wallet's own pages (apps/nap-web, built with
//! `--mode mobile`) in the platform's web view — the wallet on nap.zyn-network.com:
//! keys made and sealed on the device, chain reads and signed frames to Nap's
//! server. Two native pieces are exposed to those pages: `napvault` (the kept
//! wallet's password behind Face ID / fingerprint, §151) and `napbrowser`
//! (sites in a web view of their own, their requests approved here, §152).
//!
//! The wallet's own view never leaves the app's pages: any navigation or new
//! window to somewhere else opens in the Nap browser instead, so a linked page
//! can never draw inside the wallet.

use tauri::webview::{NewWindowFeatures, NewWindowResponse};
use tauri::{AppHandle, Runtime, Url, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_napbrowser::{NapbrowserExt, OpenRequest};

/// Hand a link to the Nap browser. Never inline: the platform asks about a
/// navigation on its UI thread, and the browser opens on that same thread, so
/// waiting for it there would freeze the app (it did, on Android).
fn open_in_browser<R: Runtime>(app: &AppHandle<R>, url: &Url) {
    if !matches!(url.scheme(), "https" | "http") {
        return;
    }
    let (app, url) = (app.clone(), url.to_string());
    std::thread::spawn(move || {
        let _ = app.napbrowser().open(OpenRequest { url });
    });
}

/// The app's own pages: `tauri://localhost` on iOS, `http(s)://tauri.localhost` on Android.
fn is_app(url: &Url) -> bool {
    matches!(url.scheme(), "tauri" | "http" | "https") && url.host_str() == Some(if url.scheme() == "tauri" { "localhost" } else { "tauri.localhost" })
        || url.scheme() == "about"
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_napvault::init())
        .plugin(tauri_plugin_napbrowser::init())
        .setup(|app| {
            let (nav, popup) = (app.handle().clone(), app.handle().clone());
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Nap Wallet")
                .on_navigation(move |url| {
                    if is_app(url) {
                        return true;
                    }
                    open_in_browser(&nav, url);
                    false
                })
                .on_new_window(move |url: Url, _: NewWindowFeatures| {
                    open_in_browser(&popup, &url);
                    NewWindowResponse::Deny
                })
                .build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Nap Wallet could not start");
}
