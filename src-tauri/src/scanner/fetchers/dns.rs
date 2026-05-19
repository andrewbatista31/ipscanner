use std::net::{IpAddr, Ipv4Addr};

/// Reverse-DNS lookup. Returns `None` if no PTR record exists or the lookup
/// fails for any reason.
pub async fn reverse_lookup(addr: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        dns_lookup::lookup_addr(&IpAddr::V4(addr))
            .ok()
            .filter(|n| !n.is_empty() && n != &addr.to_string())
    })
    .await
    .ok()
    .flatten()
}
