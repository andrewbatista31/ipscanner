use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetbiosInfo {
    pub name: String,
    pub workgroup: Option<String>,
}

// NBSTAT (Node Status) query: a fixed 50-byte UDP packet sent to port 137.
// QName is the wildcard "*" encoded as 32 ASCII chars ("CKAA...AA") plus the
// 0x20 length prefix and 0x00 terminator. QType=0x0021 (NBSTAT), QClass=0x0001.
const NBSTAT_QUERY: [u8; 50] = [
    0x12, 0x34, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C', b'K',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
    0x00, 0x00, 0x21, 0x00, 0x01,
];

pub async fn query(addr: Ipv4Addr, timeout: Duration) -> Option<NetbiosInfo> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect((addr, 137)).await.ok()?;
    socket.send(&NBSTAT_QUERY).await.ok()?;
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    parse_nbstat_reply(&buf[..n])
}

fn parse_nbstat_reply(data: &[u8]) -> Option<NetbiosInfo> {
    if data.len() < 13 {
        return None;
    }
    let mut pos = 12;
    // Skip the answer record's NAME field. Most responders use DNS compression
    // (0xC0 0x0C) but a literal name is also valid.
    if data[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < data.len() && data[pos] != 0 {
            let label_len = data[pos] as usize;
            pos += 1 + label_len;
        }
        pos += 1;
    }
    // type(2) + class(2) + ttl(4) + rdlength(2)
    pos += 10;
    if pos >= data.len() {
        return None;
    }
    let num_names = data[pos] as usize;
    pos += 1;

    let mut computer_name: Option<String> = None;
    let mut workgroup: Option<String> = None;

    for _ in 0..num_names {
        if pos + 18 > data.len() {
            break;
        }
        let raw = &data[pos..pos + 15];
        let suffix = data[pos + 15];
        let flag_hi = data[pos + 16];
        let is_group = (flag_hi & 0x80) != 0;

        let name = String::from_utf8_lossy(raw).trim_end().to_string();
        if name.is_empty() {
            pos += 18;
            continue;
        }

        // Suffix 0x00 unique = workstation/computer name.
        // Suffix 0x00 group or 0x1E = workgroup.
        if suffix == 0x00 && !is_group && computer_name.is_none() {
            computer_name = Some(name);
        } else if ((suffix == 0x00 && is_group) || suffix == 0x1E) && workgroup.is_none() {
            workgroup = Some(name);
        }
        pos += 18;
    }

    computer_name.map(|name| NetbiosInfo { name, workgroup })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_typical_reply() {
        // Hand-built minimal NBSTAT response: header + compressed name pointer
        // + type/class/ttl/rdlength + 2 names (PC-NAME unique 0x00, WORKGROUP group 0x00)
        let mut data = vec![
            0x12, 0x34, // ID
            0x84, 0x00, // flags (response, authoritative)
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // counts
            0xC0, 0x0C, // name pointer
            0x00, 0x21, 0x00, 0x01, // type, class
            0x00, 0x00, 0x00, 0x00, // ttl
            0x00, 0x00, // rdlength (we won't validate)
            0x02, // 2 names
        ];
        // Name 1: "PC-NAME        " (15 bytes), suffix 0x00, flags 0x0400 (unique)
        let mut name1 = b"PC-NAME        ".to_vec();
        data.append(&mut name1);
        data.extend_from_slice(&[0x00, 0x04, 0x00]);
        // Name 2: "WORKGROUP      " (15 bytes), suffix 0x00, flags 0x8400 (group)
        let mut name2 = b"WORKGROUP      ".to_vec();
        data.append(&mut name2);
        data.extend_from_slice(&[0x00, 0x84, 0x00]);

        let info = parse_nbstat_reply(&data).expect("should parse");
        assert_eq!(info.name, "PC-NAME");
        assert_eq!(info.workgroup.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn returns_none_for_garbage() {
        assert!(parse_nbstat_reply(&[]).is_none());
        assert!(parse_nbstat_reply(&[0u8; 5]).is_none());
    }
}
