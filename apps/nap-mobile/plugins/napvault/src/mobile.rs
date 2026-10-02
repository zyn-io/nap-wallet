use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_napvault);

pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Napvault<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("win.cavebro.napvault", "NapVaultPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_napvault)?;
    Ok(Napvault(handle))
}

/// The Keychain (iOS) or Keystore (Android) behind biometrics.
pub struct Napvault<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Napvault<R> {
    pub fn status(&self) -> crate::Result<Status> {
        self.0.run_mobile_plugin("status", ()).map_err(Into::into)
    }
    pub fn store(&self, payload: StoreRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin::<serde_json::Value>("store", payload).map(|_| ()).map_err(Into::into)
    }
    pub fn unlock(&self, payload: UnlockRequest) -> crate::Result<Unlocked> {
        self.0.run_mobile_plugin("unlock", payload).map_err(Into::into)
    }
    pub fn forget(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin::<serde_json::Value>("forget", ()).map(|_| ()).map_err(Into::into)
    }
}
