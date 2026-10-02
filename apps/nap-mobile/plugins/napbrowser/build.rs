const COMMANDS: &[&str] = &["open", "close", "respond", "approve", "registerListener", "removeListener"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).android_path("android").ios_path("ios").build();
}
