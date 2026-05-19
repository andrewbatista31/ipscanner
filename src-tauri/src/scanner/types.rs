use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    pub ping: bool,
    pub resolve_hostname: bool,
    pub ports: Vec<u16>,
    pub ping_timeout_ms: u32,
    pub port_timeout_ms: u32,
    pub concurrency: usize,
    pub include_dead: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            ping: true,
            resolve_hostname: true,
            ports: vec![],
            ping_timeout_ms: 1000,
            port_timeout_ms: 500,
            concurrency: 100,
            include_dead: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: String,
    pub options: ScanOptions,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Liveness {
    Alive,
    Dead,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: Uuid,
    pub ip: Ipv4Addr,
    pub liveness: Liveness,
    pub rtt_ms: Option<u32>,
    pub hostname: Option<String>,
    pub open_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanProgress {
    pub scan_id: Uuid,
    pub completed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStarted {
    pub scan_id: Uuid,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanComplete {
    pub scan_id: Uuid,
    pub cancelled: bool,
}
