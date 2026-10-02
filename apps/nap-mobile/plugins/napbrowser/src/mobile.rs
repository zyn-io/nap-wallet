use serde::de::DeserializeOwned;
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_napbrowser);

pub fn init<R: Runtime, C: DeserializeOwned>(_app: &AppHandle<R>, api: PluginApi<R, C>) -> crate::Result<Napbrowser<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("win.cavebro.napbrowser", "NapBrowserPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_napbrowser)?;
    Ok(Napbrowser(handle))
}

pub struct Napbrowser<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> Napbrowser<R> {
    pub fn open(&self, payload: OpenRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin::<serde_json::Value>("open", payload).map(|_| ()).map_err(Into::into)
    }
    pub fn close(&self) -> crate::Result<()> {
        self.0.run_mobile_plugin::<serde_json::Value>("close", ()).map(|_| ()).map_err(Into::into)
    }
    pub fn respond(&self, payload: RespondRequest) -> crate::Result<()> {
        self.0.run_mobile_plugin::<serde_json::Value>("respond", payload).map(|_| ()).map_err(Into::into)
    }
    pub fn approve(&self, payload: ApproveRequest) -> crate::Result<Approved> {
        self.0.run_mobile_plugin("approve", payload).map_err(Into::into)
    }
}
