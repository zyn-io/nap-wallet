const COMMANDS: &[&str] = &["status", "store", "unlock", "forget"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).android_path("android").ios_path("ios").build();
}
