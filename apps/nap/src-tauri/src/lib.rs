//! The desktop and mobile shell. Same page, same `zynzapd::app` API as the
//! loopback server — carried by Tauri's `invoke` instead of HTTP, so nothing
//! listens on a port and the keys live in the platform's app-data directory.

use std::sync::{Arc, OnceLock};

use serde_json::{json, Value};
use tauri::Manager;
use zynzapd::app::{api, App, Config};

struct Shared {
    app: OnceLock<Result<Arc<App>, String>>,
    dir: std::path::PathBuf,
}

impl Shared {
    /// Opening the wallet reaches the block server, so it happens on first
    /// use rather than at launch, and a failure is reported to the page
    /// instead of killing the window.
    fn app(&self) -> Result<Arc<App>, String> {
        self.app.get_or_init(|| App::open(&Config::in_dir(self.dir.clone())).map(Arc::new)).clone()
    }
}

#[tauri::command]
async fn api_call(state: tauri::State<'_, Arc<Shared>>, method: String, path: String, input: Value) -> Result<Value, String> {
    let shared = Arc::clone(&state);
    // Proving takes a minute; never on the UI thread.
    tauri::async_runtime::spawn_blocking(move || {
        let app = shared.app()?;
        match api(&app, &method, &path, &input) {
            Ok(v) => Ok(v),
            Err(e) => { app.note(format!("error: {}", e)); Ok(json!({ "error": e })) }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
            app.manage(Arc::new(Shared { app: OnceLock::new(), dir }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![api_call])
        .run(tauri::generate_context!())
        .expect("error while running Nap Wallet");
}
