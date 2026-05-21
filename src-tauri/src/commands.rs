use crate::scanner::engine::{self, ScannerState};
use crate::scanner::subnet;
use crate::scanner::types::{Liveness, ScanOptions, ScanRequest, ScanResult};
use rust_xlsxwriter::{Color, Format, FormatBorder, Workbook};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, State};
use tokio_util::sync::CancellationToken;
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

/// Rescan a single host using the supplied options. Returns the fresh
/// `ScanResult` directly instead of streaming events.
#[tauri::command]
pub async fn rescan_host(ip: String, options: Option<ScanOptions>) -> Result<ScanResult, String> {
    let addr: Ipv4Addr = ip.parse().map_err(|_| format!("invalid IP: {ip}"))?;
    let mut opts = options.unwrap_or_default();
    // The single-host rescan should always return a row even if dead, so the
    // UI can replace the row in place. Otherwise a dead rescan would just
    // silently disappear.
    opts.include_dead = true;
    let token = CancellationToken::new();
    Ok(engine::scan_one(addr, Uuid::nil(), &opts, &token).await)
}

/// Detect the local IPv4 subnet on the active network interface, returned
/// as a CIDR string (e.g. "192.168.1.0/24"). Used to populate the Targets
/// field with a sensible default on first launch.
#[tauri::command]
pub fn get_local_subnet() -> Option<String> {
    subnet::detect()
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
        "Device type",
        "RTT (ms)",
        "Hostname",
        "NetBIOS name",
        "Workgroup",
        "MAC",
        "Vendor",
        "HTTP title",
        "HTTP server",
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
        if let Some(dt) = r.device_type {
            sheet
                .write_string(row, 2, format!("{dt:?}").to_lowercase())
                .map_err(s)?;
        }
        if let Some(rtt) = r.rtt_ms {
            sheet.write_number(row, 3, rtt as f64).map_err(s)?;
        }
        if let Some(h) = &r.hostname {
            sheet.write_string(row, 4, h).map_err(s)?;
        }
        if let Some(nb) = &r.netbios {
            sheet.write_string(row, 5, &nb.name).map_err(s)?;
            if let Some(wg) = &nb.workgroup {
                sheet.write_string(row, 6, wg).map_err(s)?;
            }
        }
        if let Some(m) = &r.mac {
            sheet.write_string(row, 7, &m.mac).map_err(s)?;
            if let Some(v) = &m.vendor {
                sheet.write_string(row, 8, v).map_err(s)?;
            }
        }
        if let Some(b) = &r.http_banner {
            if let Some(t) = &b.title {
                sheet.write_string(row, 9, t).map_err(s)?;
            }
            if let Some(srv) = &b.server {
                sheet.write_string(row, 10, srv).map_err(s)?;
            }
        }
        if !r.open_ports.is_empty() {
            let ports = r
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            sheet.write_string(row, 11, &ports).map_err(s)?;
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
