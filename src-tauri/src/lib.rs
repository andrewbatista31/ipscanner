mod commands;
mod scanner;

use scanner::engine::ScannerState;
use std::sync::Arc;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(ScannerState::default()))
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::cancel_scan,
            commands::rescan_host,
            commands::get_local_subnet,
            commands::export_xlsx,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
