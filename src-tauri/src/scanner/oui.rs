// Curated OUI → vendor lookup table.
//
// This is intentionally a hand-picked subset of the IEEE OUI registry, focused
// on vendors common in IT/helpdesk environments (enterprise network gear,
// hypervisors, common workstation/printer/camera brands, popular IoT). It
// will not catch every device but trades comprehensiveness for binary size.
// Add entries as needed.

/// Look up the manufacturer for a MAC address (any common format: aa:bb:cc:..,
/// aa-bb-cc-.., or aabbcc..). Returns the vendor name if the OUI is known.
pub fn vendor_for(mac: &str) -> Option<&'static str> {
    let cleaned: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if cleaned.len() < 6 {
        return None;
    }
    let prefix = &cleaned[..6];
    OUI_MAP
        .iter()
        .find_map(|&(p, v)| if p == prefix { Some(v) } else { None })
}

#[rustfmt::skip]
static OUI_MAP: &[(&str, &str)] = &[
    // Hypervisors / virtualization
    ("000c29", "VMware"), ("005056", "VMware"), ("001c14", "VMware"),
    ("000569", "VMware"), ("000e0c", "VMware"),
    ("080027", "VirtualBox"),
    ("00155d", "Microsoft Hyper-V"), ("000d3a", "Microsoft"),
    ("001dd8", "Microsoft"),
    ("001c42", "Parallels"),
    // Apple
    ("0017f2", "Apple"), ("0021e9", "Apple"), ("002241", "Apple"),
    ("002332", "Apple"), ("002500", "Apple"), ("002608", "Apple"),
    ("00264a", "Apple"), ("0c74c2", "Apple"), ("3c0754", "Apple"),
    ("3c15c2", "Apple"), ("5c95ae", "Apple"), ("70cd60", "Apple"),
    ("78a3e4", "Apple"), ("88c663", "Apple"), ("a4b197", "Apple"),
    ("ace4b5", "Apple"), ("b8c75d", "Apple"), ("d49a20", "Apple"),
    ("dc2b61", "Apple"), ("e0acf1", "Apple"), ("f0dbe2", "Apple"),
    // Cisco (incl. Linksys/Meraki)
    ("0001c7", "Cisco"), ("0007ec", "Cisco"), ("000bbe", "Cisco"),
    ("000c30", "Cisco"), ("000e08", "Cisco"), ("000ed7", "Cisco"),
    ("0011bb", "Cisco"), ("00146a", "Cisco"), ("0017df", "Cisco"),
    ("001a2f", "Cisco"), ("001bd4", "Cisco"), ("001ef7", "Cisco"),
    ("0021a0", "Cisco"), ("0022bd", "Cisco"), ("0023ac", "Cisco"),
    ("0024c4", "Cisco"), ("002608", "Cisco"), ("0026cb", "Cisco"),
    ("00583b", "Cisco"), ("64a0e7", "Cisco"), ("6c41f7", "Cisco"),
    ("e0acf1", "Cisco"), ("3417eb", "Cisco-Meraki"), ("e0cb1d", "Cisco-Meraki"),
    ("002584", "Cisco-Linksys"), ("000fcb", "Cisco-Linksys"),
    // HPE / Aruba
    ("001f29", "HPE"), ("002264", "HPE"), ("0030c1", "HPE"),
    ("0080a1", "HPE"), ("3c4a92", "HPE"), ("78acc0", "HPE"),
    ("9c8e99", "HPE"), ("a45d36", "HPE"), ("ec9a74", "HPE"),
    ("0024a8", "HPE-Aruba"), ("6c0b84", "HPE-Aruba"),
    ("80e828", "HPE-Aruba"), ("84d47e", "HPE-Aruba"),
    // Dell
    ("00065b", "Dell"), ("00086b", "Dell"), ("000874", "Dell"),
    ("000bdb", "Dell"), ("000d56", "Dell"), ("000f1f", "Dell"),
    ("00115b", "Dell"), ("00188b", "Dell"), ("0019b9", "Dell"),
    ("001ec9", "Dell"), ("001fa0", "Dell"), ("002219", "Dell"),
    ("00248c", "Dell"), ("0026b9", "Dell"), ("18a99b", "Dell"),
    ("a41f72", "Dell"), ("b083fe", "Dell"), ("d067e5", "Dell"),
    ("d4ae52", "Dell"), ("ec2280", "Dell"), ("f48e38", "Dell"),
    // Ubiquiti
    ("0418d6", "Ubiquiti"), ("245a4c", "Ubiquiti"), ("245afc", "Ubiquiti"),
    ("44d9e7", "Ubiquiti"), ("687251", "Ubiquiti"), ("802aa8", "Ubiquiti"),
    ("80f5ac", "Ubiquiti"), ("9c0571", "Ubiquiti"), ("ac8bf9", "Ubiquiti"),
    ("acf7f3", "Ubiquiti"), ("b4fbe4", "Ubiquiti"), ("dc9fdb", "Ubiquiti"),
    ("f09fc2", "Ubiquiti"), ("fcec4d", "Ubiquiti"),
    // Lenovo
    ("002590", "Lenovo"), ("002564", "Lenovo"), ("0050ba", "Lenovo"),
    ("3c970e", "Lenovo"), ("385a98", "Lenovo"), ("6c0b84", "Lenovo"),
    ("aceff5", "Lenovo"), ("e0db55", "Lenovo"), ("e8b1fc", "Lenovo"),
    // Intel
    ("000423", "Intel"), ("001b21", "Intel"), ("0028f8", "Intel"),
    ("28d244", "Intel"), ("44850e", "Intel"), ("acfdce", "Intel"),
    // Printers
    ("000d4b", "HP-Printer"), ("0017a4", "HP-Printer"),
    ("001b78", "HP-Printer"), ("002655", "HP-Printer"),
    ("002721", "HP-Printer"), ("3c4a92", "HP-Printer"),
    ("9c8e99", "HP-Printer"), ("dca5d4", "HP-Printer"),
    ("000aa3", "Brother"), ("00cd4f", "Brother"), ("a4ce62", "Brother"),
    ("000bbd", "Toshiba"), ("002608", "Toshiba"),
    ("000048", "Seiko-Epson"), ("0014e5", "Seiko-Epson"),
    ("0026ab", "Seiko-Epson"), ("a4ee57", "Seiko-Epson"),
    ("000067", "Ricoh"), ("000acd", "Ricoh"), ("002673", "Ricoh"),
    ("000085", "Canon"), ("00bb3a", "Canon"), ("9c93e4", "Canon"),
    ("00065b", "Xerox"), ("0014c2", "Xerox"),
    // Cameras / NVRs
    ("000408", "Axis-Communications"), ("00408c", "Axis-Communications"),
    ("acea5a", "Axis-Communications"), ("b8a44f", "Axis-Communications"),
    ("8c69e0", "Axis-Communications"),
    ("8c00fc", "Hikvision"), ("28572b", "Hikvision"), ("4ce670", "Hikvision"),
    ("4c11bf", "Hikvision"), ("c0561d", "Hikvision"), ("f4b7e2", "Hikvision"),
    ("c0817", "Dahua"), ("3c8112", "Dahua"), ("9c14638", "Dahua"),
    ("4c8b3", "Dahua"),
    // Storage / NAS
    ("00113217", "Synology"), ("00113272", "Synology"),
    ("0011d8", "Synology"), ("180373", "Synology"),
    ("245ebe", "Synology"), ("00084d", "QNAP"), ("245ebe", "QNAP"),
    // Network gear (other)
    ("00146c", "Netgear"), ("a040a0", "Netgear"), ("c40415", "Netgear"),
    ("4c60de", "Netgear"), ("9c3dcf", "Netgear"),
    ("000fea", "GIGABYTE"),
    ("00185e", "TP-Link"), ("8c1645", "TP-Link"), ("60e327", "TP-Link"),
    ("ec086b", "TP-Link"), ("48ba4e", "TP-Link"), ("9c5322", "TP-Link"),
    ("0050ba", "D-Link"), ("002195", "D-Link"), ("e406e2", "D-Link"),
    ("002418", "D-Link"),
    // Samsung
    ("00120e", "Samsung"), ("00161b", "Samsung"), ("0023ab", "Samsung"),
    ("100c24", "Samsung"), ("8c1ab9", "Samsung"), ("a4f4c2", "Samsung"),
    ("dc7144", "Samsung"),
    // Sony
    ("000f4b", "Sony"), ("38e0fb", "Sony"), ("78f878", "Sony"),
    // Google / Nest / Amazon / IoT
    ("3c5ab4", "Google"), ("a4773b", "Google"), ("e4f4c6", "Google"),
    ("18b430", "Nest"),
    ("44650d", "Amazon"), ("4c5e0c", "Amazon"), ("84d6d0", "Amazon"),
    ("e8b6c8", "Amazon"), ("d4f7d2", "Amazon-Ring"), ("ac63be", "Amazon"),
    ("1865f1", "Philips-Hue"), ("00179a", "Philips-Hue"),
    // ASUS / ASRock / motherboards
    ("00b362", "ASUS"), ("60a44c", "ASUS"), ("ac220b", "ASUS"),
    ("002618", "ASUS"), ("d850e6", "ASUS"), ("e0cb4e", "ASRock"),
    // Raspberry Pi
    ("b827eb", "Raspberry-Pi"), ("dca632", "Raspberry-Pi"),
    ("e45f01", "Raspberry-Pi"), ("28cdc1", "Raspberry-Pi"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_vmware() {
        assert_eq!(vendor_for("00:50:56:12:34:56"), Some("VMware"));
        assert_eq!(vendor_for("00-50-56-12-34-56"), Some("VMware"));
        assert_eq!(vendor_for("005056123456"), Some("VMware"));
    }

    #[test]
    fn finds_ubiquiti() {
        assert_eq!(vendor_for("ac:8b:f9:de:ad:be"), Some("Ubiquiti"));
    }

    #[test]
    fn unknown_oui() {
        assert_eq!(vendor_for("ff:ff:ff:00:00:00"), None);
    }

    #[test]
    fn malformed_input() {
        assert_eq!(vendor_for("xyz"), None);
        assert_eq!(vendor_for(""), None);
    }
}
