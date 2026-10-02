use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::NapbrowserExt;
use crate::Result;

#[command]
pub(crate) async fn open<R: Runtime>(app: AppHandle<R>, url: String) -> Result<()> {
    app.napbrowser().open(OpenRequest { url })
}

#[command]
pub(crate) async fn close<R: Runtime>(app: AppHandle<R>) -> Result<()> {
    app.napbrowser().close()
}

#[command]
pub(crate) async fn respond<R: Runtime>(app: AppHandle<R>, id: u64, json: String) -> Result<()> {
    app.napbrowser().respond(RespondRequest { id, json })
}

#[command]
pub(crate) async fn approve<R: Runtime>(app: AppHandle<R>, kicker: String, title: String, rows: Vec<Vec<String>>, note: String, danger: bool) -> Result<Approved> {
    app.napbrowser().approve(ApproveRequest { kicker, title, rows, note, danger })
}
