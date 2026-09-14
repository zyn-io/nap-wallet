use std::path::{Path, PathBuf};

/// Stage the page the daemon serves into `frontendDist`.
///
/// `tauri::generate_context!` reads `frontendDist` at **compile** time, and
/// cargo does not run `tauri.conf.json`'s `beforeBuildCommand`. Because
/// `apps/nap/dist/` is generated and therefore gitignored, a clean clone could
/// not build or even `cargo check` this crate at all — it failed with
/// "`frontendDist` is set to `../dist` but this path doesn't exist".
///
/// `build-ui.mjs` does the same copy for the Tauri CLI. Doing it here as well
/// costs nothing, needs no node and no network, and means the workspace builds
/// from a fresh checkout.
fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let ui = root.join("../../../zynzapd/ui");
    let dist = root.join("../dist");

    if ui.is_dir() {
        let _ = std::fs::create_dir_all(&dist);
        copy(&ui.join("index.html"), &dist.join("index.html"));
        copy(&ui.join("nap-mark.png"), &dist.join("nap-mark.png"));
        copy_dir(&ui.join("fonts"), &dist.join("fonts"));
        println!("cargo:rerun-if-changed={}", ui.display());
    }
    tauri_build::build()
}

fn copy(from: &Path, to: &Path) {
    if from.is_file() {
        let _ = std::fs::copy(from, to);
    }
}

fn copy_dir(from: &Path, to: &Path) {
    let Ok(entries) = std::fs::read_dir(from) else { return };
    let _ = std::fs::create_dir_all(to);
    for e in entries.flatten() {
        let path = e.path();
        if path.is_file() {
            copy(&path, &to.join(e.file_name()));
        }
    }
}
