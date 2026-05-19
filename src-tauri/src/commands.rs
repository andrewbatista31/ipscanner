use crate::scanner::engine::{self, ScannerState};
use crate::scanner::types::{Liveness, ScanOptions, ScanRequest, ScanResult};
use rust_xlsxwriter::{Color, Format, FormatBorder, Workbook};
use std::path::PathBuf;
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

#[tauri::command]
pub async fn export_xlsx(path: PathBuf, results: Vec<ScanResult>) -> Result<(), String> {
    let mut wb = Workbook::new();
    let sheet = wb.add_worksheet().set_name("Scan results").map_err(s)?;

    let header_fmt = Format::new()
        .set_bold()
        .set_background_color(Color::RGB(0x1F_2A_44))
        .set_font_color(Color::White)
        .set_border(FormatBorder::Thin);
    let alive_fmt = Format::new().set_font_color(Color::RGB(0x10_7C_3F));
    let dead_fmt = Format::new().set_font_color(Color::RGB(0x99_99_99));

    let headers = [
        "IP",
        "Status",
        "RTT (ms)",
        "Hostname",
        "NetBIOS name",
        "Workgroup",
        "Open ports",
    ];
    for (i, h) in headers.iter().enumerate() {
        sheet
            .write_string_with_format(0, i as u16, *h, &header_fmt)
            .map_err(s)?;
    }

    for (row_idx, r) in results.iter().enumerate() {
        let row = (row_idx + 1) as u32;
        sheet.write_string(row, 0, r.ip.to_string()).map_err(s)?;
        let status_fmt = match r.liveness {
            Liveness::Alive => &alive_fmt,
            _ => &dead_fmt,
        };
        let status_text = match r.liveness {
            Liveness::Alive => "alive",
            Liveness::Dead => "dead",
            Liveness::Unknown => "unknown",
        };
        sheet
            .write_string_with_format(row, 1, status_text, status_fmt)
            .map_err(s)?;
        if let Some(rtt) = r.rtt_ms {
            sheet.write_number(row, 2, rtt as f64).map_err(s)?;
        }
        if let Some(h) = &r.hostname {
            sheet.write_string(row, 3, h).map_err(s)?;
        }
        if let Some(nb) = &r.netbios {
            sheet.write_string(row, 4, &nb.name).map_err(s)?;
            if let Some(wg) = &nb.workgroup {
                sheet.write_string(row, 5, wg).map_err(s)?;
            }
        }
        if !r.open_ports.is_empty() {
            let ports = r
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            sheet.write_string(row, 6, &ports).map_err(s)?;
        }
    }

    sheet.autofit();
    sheet.set_freeze_panes(1, 0).map_err(s)?;
    wb.save(&path).map_err(s)?;
    Ok(())
}

fn s<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}
