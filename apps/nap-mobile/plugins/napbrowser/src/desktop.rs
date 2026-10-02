use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(app: &AppHandle<R>, _api: PluginApi<R, C>) -> crate::Result<Napbrowser<R>> {
    Ok(Napbrowser(app.clone()))
}

/// The browser is a phone feature; a desktop window of the app says so.
pub struct Napbrowser<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

impl<R: Runtime> Napbrowser<R> {
    pub fn open(&self, _: OpenRequest) -> crate::Result<()> {
        Err(crate::Error::Unavailable)
    }
    pub fn close(&self) -> crate::Result<()> {
        Ok(())
    }
    pub fn respond(&self, _: RespondRequest) -> crate::Result<()> {
        Ok(())
    }
    pub fn approve(&self, _: ApproveRequest) -> crate::Result<Approved> {
        Ok(Approved { approved: false })
    }
}
