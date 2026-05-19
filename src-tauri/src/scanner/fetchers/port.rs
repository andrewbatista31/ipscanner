use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::TcpStream;

/// Attempt a TCP connect to `addr:port` with `timeout`. Returns true on a
/// successful 3-way handshake, false otherwise.
pub async fn probe_port(addr: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    let socket: SocketAddr = SocketAddr::V4(SocketAddrV4::new(addr, port));
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect(socket)).await,
        Ok(Ok(_))
    )
}

/// Probe a list of ports concurrently and return the ones that responded.
pub async fn probe_ports(addr: Ipv4Addr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    use futures::stream::{FuturesUnordered, StreamExt};
    let mut futs: FuturesUnordered<_> = ports
        .iter()
        .map(|&p| async move {
            if probe_port(addr, p, timeout).await {
                Some(p)
            } else {
                None
            }
        })
        .collect();
    let mut open = Vec::new();
    while let Some(r) = futs.next().await {
        if let Some(p) = r {
            open.push(p);
        }
    }
    open.sort_unstable();
    open
}
