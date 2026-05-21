use crate::scanner::fetchers::http::HttpBanner;
use crate::scanner::fetchers::netbios::NetbiosInfo;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceType {
    Router,
    Switch,
    AccessPoint,
    Server,
    Workstation,
    Printer,
    Camera,
    Iot,
    Vm,
    Mobile,
    Unknown,
}

/// Heuristic device-type guess. Synthesizes vendor (from MAC OUI), open
/// ports, HTTP banner, and NetBIOS presence into a single label. Banner
/// matches win, then vendor matches, then port/NetBIOS heuristics.
pub fn guess(
    vendor: Option<&str>,
    open_ports: &[u16],
    banner: Option<&HttpBanner>,
    netbios: Option<&NetbiosInfo>,
) -> DeviceType {
    // 1. Banner-driven: most specific signal we have.
    if let Some(b) = banner {
        let hay = format!(
            "{} {}",
            b.server.as_deref().unwrap_or(""),
            b.title.as_deref().unwrap_or("")
        )
        .to_ascii_lowercase();

        let matches = |needles: &[&str]| needles.iter().any(|n| hay.contains(n));

        if matches(&["camera", "axis", "hikvision", "dahua", "ip-cam", "nvr", "dvr"]) {
            return DeviceType::Camera;
        }
        if matches(&[
            "printer", "laserjet", "officejet", "deskjet", "color laserjet",
            "imagerunner", "workcentre", "phaser", "brother", "epson stylus",
            "ricoh aficio", "kyocera", "lexmark",
        ]) {
            return DeviceType::Printer;
        }
        if matches(&["unifi", "ruckus", "aerohive", "extreme wireless"])
            || matches(&["access point", "wireless ap"])
        {
            return DeviceType::AccessPoint;
        }
        if matches(&["catalyst", "procurve", "aruba", "comware"])
            || matches(&["switch login", "switch management"])
        {
            return DeviceType::Switch;
        }
        if matches(&["sonicwall", "fortigate", "pfsense", "opnsense", "mikrotik", "edgerouter", "router"])
            || hay.contains("gateway")
        {
            return DeviceType::Router;
        }
        if matches(&["synology", "qnap", "truenas", "freenas", "ilo", "idrac", "imm", "openmediavault"]) {
            return DeviceType::Server;
        }
    }

    // 2. Vendor-driven.
    if let Some(v) = vendor {
        let vl = v.to_ascii_lowercase();
        if vl.contains("vmware")
            || vl.contains("hyper-v")
            || vl.contains("virtualbox")
            || vl.contains("parallels")
        {
            return DeviceType::Vm;
        }
        if vl.contains("axis") || vl.contains("hikvision") || vl.contains("dahua") {
            return DeviceType::Camera;
        }
        if vl.contains("hp-printer")
            || vl.contains("brother")
            || vl.contains("epson")
            || vl.contains("ricoh")
            || vl.contains("canon")
            || vl.contains("xerox")
            || vl.contains("toshiba")
        {
            return DeviceType::Printer;
        }
        if vl.contains("ubiquiti")
            || vl.contains("aruba")
            || vl.contains("meraki")
            || vl.contains("ruckus")
        {
            return DeviceType::AccessPoint;
        }
        if vl.contains("cisco") || vl.contains("juniper") || vl.contains("netgear") {
            return DeviceType::Switch;
        }
        if vl.contains("synology") || vl.contains("qnap") {
            return DeviceType::Server;
        }
        if vl.contains("nest") || vl.contains("ring") || vl.contains("philips-hue") {
            return DeviceType::Iot;
        }
        if vl.contains("raspberry-pi") {
            return DeviceType::Server;
        }
    }

    // 3. Port + NetBIOS heuristics.
    if open_ports.contains(&9100) || open_ports.contains(&631) {
        return DeviceType::Printer;
    }
    if open_ports.contains(&3389) {
        return DeviceType::Workstation; // RDP usually = Windows desktop
    }
    if netbios.is_some() {
        return DeviceType::Workstation;
    }
    if open_ports.contains(&22) {
        return DeviceType::Server;
    }
    if open_ports.contains(&80) || open_ports.contains(&443) {
        // Has web UI but we don't recognize it. Default to "server" rather
        // than "workstation" since random workstations rarely serve HTTP.
        return DeviceType::Server;
    }

    DeviceType::Unknown
}
