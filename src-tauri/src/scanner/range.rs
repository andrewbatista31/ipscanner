use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

/// Parses a target string into a list of IPv4 addresses.
///
/// Accepted syntaxes (comma or newline separated):
///   192.168.1.5              single host
///   192.168.1.0/24           CIDR
///   192.168.1.10-50          short range (last octet)
///   192.168.1.10-192.168.2.5 explicit range
pub fn parse_targets(input: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for token in input
        .split([',', '\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some((start, end)) = token.split_once('-') {
            let start_ip: Ipv4Addr = start
                .trim()
                .parse()
                .map_err(|_| format!("invalid range start: {start}"))?;
            let end_trim = end.trim();
            let end_ip: Ipv4Addr = if end_trim.contains('.') {
                end_trim
                    .parse()
                    .map_err(|_| format!("invalid range end: {end_trim}"))?
            } else {
                let last: u8 = end_trim
                    .parse()
                    .map_err(|_| format!("invalid range end: {end_trim}"))?;
                let o = start_ip.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            };
            let s: u32 = start_ip.into();
            let e: u32 = end_ip.into();
            if e < s {
                return Err(format!("range end before start: {token}"));
            }
            if e - s > 1_000_000 {
                return Err(format!("range too large (>1M hosts): {token}"));
            }
            for i in s..=e {
                out.push(Ipv4Addr::from(i));
            }
        } else if token.contains('/') {
            let net: Ipv4Net = token
                .parse()
                .map_err(|e: ipnet::AddrParseError| format!("invalid CIDR {token}: {e}"))?;
            if net.prefix_len() < 8 {
                return Err(format!("CIDR too large (prefix must be >= 8): {token}"));
            }
            for ip in net.hosts() {
                out.push(ip);
            }
        } else {
            let ip: Ipv4Addr = token.parse().map_err(|_| format!("invalid IP: {token}"))?;
            out.push(ip);
        }
    }
    if out.is_empty() {
        return Err("no targets provided".into());
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ip() {
        let r = parse_targets("10.0.0.1").unwrap();
        assert_eq!(r, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn parses_cidr_24() {
        let r = parse_targets("192.168.1.0/24").unwrap();
        assert_eq!(r.len(), 254); // /24 excludes network + broadcast
    }

    #[test]
    fn parses_short_range() {
        let r = parse_targets("192.168.1.5-7").unwrap();
        assert_eq!(
            r,
            vec![
                Ipv4Addr::new(192, 168, 1, 5),
                Ipv4Addr::new(192, 168, 1, 6),
                Ipv4Addr::new(192, 168, 1, 7),
            ]
        );
    }

    #[test]
    fn parses_explicit_range() {
        let r = parse_targets("10.0.0.254-10.0.1.2").unwrap();
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn dedups_and_sorts() {
        let r = parse_targets("10.0.0.2, 10.0.0.1, 10.0.0.2").unwrap();
        assert_eq!(
            r,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn rejects_huge_range() {
        assert!(parse_targets("10.0.0.0/4").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_targets("   ").is_err());
    }
}
