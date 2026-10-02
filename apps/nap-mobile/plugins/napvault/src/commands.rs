use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::NapvaultExt;
use crate::Result;

#[command]
pub(crate) async fn status<R: Runtime>(app: AppHandle<R>) -> Result<Status> {
    app.napvault().status()
}

#[command]
pub(crate) async fn store<R: Runtime>(app: AppHandle<R>, secret: String) -> Result<()> {
    app.napvault().store(StoreRequest { secret })
}

#[command]
pub(crate) async fn unlock<R: Runtime>(app: AppHandle<R>, reason: String) -> Result<Unlocked> {
    app.napvault().unlock(UnlockRequest { reason })
}

#[command]
pub(crate) async fn forget<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.napvault().forget()
}
