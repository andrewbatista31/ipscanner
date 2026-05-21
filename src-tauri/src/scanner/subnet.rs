use std::net::Ipv4Addr;

/// Detect the local IPv4 subnet in CIDR notation by reading the active
/// network interface(s). Returns the first non-loopback IPv4 interface
/// whose prefix length is in the [/8, /30] range. Used to populate the
/// "Targets" textbox with a sensible default on app launch.
pub fn detect() -> Option<String> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    let mut candidates: Vec<_> = ifaces
        .into_iter()
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !v4.ip.is_link_local() => {
                let prefix = u32::from_be_bytes(v4.netmask.octets()).count_ones() as u8;
                if (8..=30).contains(&prefix) {
                    let network = u32::from_be_bytes(v4.ip.octets())
                        & u32::from_be_bytes(v4.netmask.octets());
                    Some((iface.name, Ipv4Addr::from(network.to_be_bytes()), prefix))
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect();

    // Sort: prefer interfaces with the smallest network (most-specific prefix)
    // and a name that doesn't look like a virtual adapter.
    candidates.sort_by_key(|(name, _, prefix)| {
        let virtual_pen = if name.to_ascii_lowercase().contains("virtual")
            || name.to_ascii_lowercase().contains("vmware")
            || name.to_ascii_lowercase().contains("hyper-v")
        {
            1
        } else {
            0
        };
        (virtual_pen, std::cmp::Reverse(*prefix))
    });

    candidates
        .into_iter()
        .next()
        .map(|(_, net, prefix)| format!("{net}/{prefix}"))
}
