use crate::scanner::fetchers::{dns, netbios, ping, port};
use crate::scanner::range;
use crate::scanner::types::*;
use futures::stream::{FuturesUnordered, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Default)]
pub struct ScannerState {
    active: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl ScannerState {
    pub fn cancel(&self, id: Uuid) -> bool {
        if let Some(tok) = self.active.lock().get(&id) {
            tok.cancel();
            true
        } else {
            false
        }
    }
}

pub fn start_scan(
    state: Arc<ScannerState>,
    app: AppHandle,
    req: ScanRequest,
) -> Result<Uuid, String> {
    let targets = range::parse_targets(&req.targets)?;
    let total = targets.len();
    let scan_id = Uuid::new_v4();
    let token = CancellationToken::new();
    state.active.lock().insert(scan_id, token.clone());

    // Notify the UI that the scan is starting.
    let _ = app.emit("scan-started", ScanStarted { scan_id, total });

    let opts = Arc::new(req.options);
    let app_clone = app.clone();
    let state_clone = state.clone();
    // Tauri commands run on the main thread, which is NOT a Tokio runtime, so
    // we spawn onto Tauri's managed Tokio runtime. Inside the task, ordinary
    // tokio::spawn / tokio::net / tokio::time calls work normally because we
    // are then in a Tokio context.
    tauri::async_runtime::spawn(async move {
        let cancelled = run_scan(app_clone.clone(), scan_id, targets, opts, token.clone()).await;
        state_clone.active.lock().remove(&scan_id);
        let _ = app_clone.emit("scan-complete", ScanComplete { scan_id, cancelled });
    });

    Ok(scan_id)
}

async fn run_scan(
    app: AppHandle,
    scan_id: Uuid,
    targets: Vec<Ipv4Addr>,
    opts: Arc<ScanOptions>,
    token: CancellationToken,
) -> bool {
    let total = targets.len();
    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let mut tasks: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();

    for ip in targets {
        let permit_sem = sem.clone();
        let opts = opts.clone();
        let app = app.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit_sem.acquire_owned().await.ok();
            if token.is_cancelled() {
                return;
            }
            let result = scan_one(ip, scan_id, &opts, &token).await;
            if !opts.include_dead && result.liveness == Liveness::Dead {
                return;
            }
            let _ = app.emit("scan-result", &result);
        }));
    }

    let mut completed = 0usize;
    let mut last_progress = std::time::Instant::now();
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                // Drop remaining task handles — workers will see the token and exit.
                return true;
            }
            next = tasks.next() => {
                match next {
                    Some(_) => {
                        completed += 1;
                        if last_progress.elapsed() > Duration::from_millis(100) || completed == total {
                            last_progress = std::time::Instant::now();
                            let _ = app.emit("scan-progress", ScanProgress { scan_id, completed, total });
                        }
                    }
                    None => break,
                }
            }
        }
    }
    false
}

async fn scan_one(
    ip: Ipv4Addr,
    scan_id: Uuid,
    opts: &ScanOptions,
    token: &CancellationToken,
) -> ScanResult {
    let ping_to = Duration::from_millis(opts.ping_timeout_ms as u64);
    let port_to = Duration::from_millis(opts.port_timeout_ms as u64);
    let netbios_to = Duration::from_millis(opts.netbios_timeout_ms as u64);

    let rtt = if opts.ping {
        tokio::select! {
            _ = token.cancelled() => None,
            r = ping::ping(ip, ping_to) => r,
        }
    } else {
        None
    };

    let liveness = if opts.ping {
        if rtt.is_some() {
            Liveness::Alive
        } else {
            Liveness::Dead
        }
    } else {
        Liveness::Unknown
    };

    // If ping says dead, skip the rest unless the user wants dead hosts too.
    let do_followup = liveness != Liveness::Dead || opts.include_dead || !opts.ping;

    // Run follow-up fetchers concurrently — they all use the network independently.
    let hostname_fut = async {
        if opts.resolve_hostname && do_followup {
            dns::reverse_lookup(ip).await
        } else {
            None
        }
    };
    let netbios_fut = async {
        if opts.netbios && do_followup {
            netbios::query(ip, netbios_to).await
        } else {
            None
        }
    };
    let ports_fut = async {
        if !opts.ports.is_empty() && do_followup {
            port::probe_ports(ip, &opts.ports, port_to).await
        } else {
            Vec::new()
        }
    };

    let (hostname, nb, open_ports) = tokio::select! {
        _ = token.cancelled() => (None, None, Vec::new()),
        out = async { tokio::join!(hostname_fut, netbios_fut, ports_fut) } => out,
    };

    ScanResult {
        scan_id,
        ip,
        liveness,
        rtt_ms: rtt,
        hostname,
        netbios: nb,
        open_ports,
    }
}
