use crate::scanner::oui;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacInfo {
    pub mac: String,
    pub vendor: Option<String>,
}

/// Resolve the MAC address for an IPv4 host on the local subnet using the
/// Windows `SendARP` IP Helper API. This actively issues an ARP request if
/// the address is not already cached, so it will populate the cache itself
/// and works even on a cold scan. Requires no elevated privileges.
///
/// Returns `None` if the host is off-subnet, unreachable, or did not reply
/// to ARP.
pub async fn query(addr: Ipv4Addr) -> Option<MacInfo> {
    tokio::task::spawn_blocking(move || query_blocking(addr))
        .await
        .ok()
        .flatten()
}

fn query_blocking(addr: Ipv4Addr) -> Option<MacInfo> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

    // Win32 expects the destination IP as a 32-bit value in network byte order.
    let dest: u32 = u32::from_ne_bytes(addr.octets());
    let mut mac = [0u8; 8];
    let mut mac_len: u32 = mac.len() as u32;
    // SAFETY: SendARP fills up to mac_len bytes of `mac`, then writes back the
    // actual length into `mac_len`. Pointers are valid for the call's duration.
    let result = unsafe { SendARP(dest, 0, mac.as_mut_ptr().cast(), &mut mac_len) };
    if result != 0 || mac_len != 6 {
        return None;
    }
    let mac_str = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    let vendor = oui::vendor_for(&mac_str).map(str::to_string);
    Some(MacInfo {
        mac: mac_str,
        vendor,
    })
}
