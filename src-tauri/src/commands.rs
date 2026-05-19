use crate::scanner::engine::{self, ScannerState};
use crate::scanner::types::{ScanOptions, ScanRequest};
use std::sync::Arc;
use tauri::{AppHandle, State};
use uuid::Uuid;

#[tauri::command]
pub fn start_scan(
    app: AppHandle,
    state: State<'_, Arc<ScannerState>>,
    targets: String,
    options: Option<ScanOptions>,
) -> Result<Uuid, String> {
    let options = options.unwrap_or_default();
    let req = ScanRequest { targets, options };
    engine::start_scan(state.inner().clone(), app, req)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, Arc<ScannerState>>, scan_id: Uuid) -> bool {
    state.inner().cancel(scan_id)
}
