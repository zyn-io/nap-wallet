//! The Nap browser (DECISIONS §152): sites open in a web view of their own,
//! beside the wallet — not in it. Each https page gets Nap's provider
//! (`nap:announceProvider`, `window.zyn`) and its requests reach the wallet's
//! page as `request` events, named by the origin the platform reports for the
//! main frame, never one the page claims. The wallet answers with `respond`
//! and asks the holder with `approve`, a native sheet over the site.
//!
//! The site's web view has no Tauri IPC and no access to the wallet's origin,
//! storage or the `napvault` plugin: its one door is the provider bridge.
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

pub use models::*;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

mod commands;
mod error;
mod models;

pub use error::{Error, Result};

#[cfg(desktop)]
use desktop::Napbrowser;
#[cfg(mobile)]
use mobile::Napbrowser;

pub trait NapbrowserExt<R: Runtime> {
    fn napbrowser(&self) -> &Napbrowser<R>;
}

impl<R: Runtime, T: Manager<R>> crate::NapbrowserExt<R> for T {
    fn napbrowser(&self) -> &Napbrowser<R> {
        self.state::<Napbrowser<R>>().inner()
    }
}

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("napbrowser")
        .invoke_handler(tauri::generate_handler![commands::open, commands::close, commands::respond, commands::approve])
        .setup(|app, api| {
            #[cfg(mobile)]
            let b = mobile::init(app, api)?;
            #[cfg(desktop)]
            let b = desktop::init(app, api)?;
            app.manage(b);
            Ok(())
        })
        .build()
}
