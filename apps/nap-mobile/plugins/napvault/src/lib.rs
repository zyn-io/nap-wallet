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
use desktop::Napvault;
#[cfg(mobile)]
use mobile::Napvault;

/// Face ID / fingerprint unlock for Nap's kept wallet (DECISIONS §151): one
/// secret — the kept wallet's password — held by the Keychain (iOS) or the
/// Android Keystore, released only to the enrolled biometrics of this device.
///
/// Extensions to [`tauri::App`], [`tauri::AppHandle`] and [`tauri::Window`] to access the napvault APIs.
pub trait NapvaultExt<R: Runtime> {
  fn napvault(&self) -> &Napvault<R>;
}

impl<R: Runtime, T: Manager<R>> crate::NapvaultExt<R> for T {
  fn napvault(&self) -> &Napvault<R> {
    self.state::<Napvault<R>>().inner()
  }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
  Builder::new("napvault")
    .invoke_handler(tauri::generate_handler![commands::status, commands::store, commands::unlock, commands::forget])
    .setup(|app, api| {
      #[cfg(mobile)]
      let napvault = mobile::init(app, api)?;
      #[cfg(desktop)]
      let napvault = desktop::init(app, api)?;
      app.manage(napvault);
      Ok(())
    })
    .build()
}
