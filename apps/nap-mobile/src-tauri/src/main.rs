// A desktop window of the same app, for working on it without a phone.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nap_mobile_lib::run()
}
