use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(app: &AppHandle<R>, _api: PluginApi<R, C>) -> crate::Result<Napvault<R>> {
    Ok(Napvault(app.clone()))
}

/// A desktop window of the phone app has no biometric store: it says so.
pub struct Napvault<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

impl<R: Runtime> Napvault<R> {
    pub fn status(&self) -> crate::Result<Status> {
        Ok(Status { available: false, kind: "none".into(), stored: false })
    }
    pub fn store(&self, _: StoreRequest) -> crate::Result<()> {
        Err(crate::Error::Unavailable)
    }
    pub fn unlock(&self, _: UnlockRequest) -> crate::Result<Unlocked> {
        Err(crate::Error::Unavailable)
    }
    pub fn forget(&self) -> crate::Result<()> {
        Ok(())
    }
}
