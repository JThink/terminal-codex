// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(code) = tauri_app_lib::ssh_askpass_exit_code_if_requested() {
        std::process::exit(code);
    }
    tauri_app_lib::run()
}
