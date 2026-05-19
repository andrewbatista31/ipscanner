use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use winping::{AsyncPinger, Buffer};

/// Send a single ICMP echo to `addr` and return the round-trip time in
/// milliseconds, or `None` if the host did not reply within `timeout`.
///
/// Uses the Windows `IcmpSendEcho` API (via the `winping` crate), which does
/// not require elevated privileges.
pub async fn ping(addr: Ipv4Addr, timeout: Duration) -> Option<u32> {
    let mut pinger = AsyncPinger::new();
    pinger.set_timeout(timeout.as_millis() as u32);
    let buffer = Buffer::new();
    match pinger.send(IpAddr::V4(addr), buffer).await.result {
        Ok(rtt) => Some(rtt),
        Err(_) => None,
    }
}
