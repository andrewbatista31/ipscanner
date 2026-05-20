# ipscanner

A modern Windows rewrite of [Angry IP Scanner](https://angryip.org/) — same core idea (sweep a range of IPs, see what's alive), but with a fast Rust backend, a streaming UI, native Excel export, and clickable hostnames that open devices straight in your browser.

Built with [Tauri 2](https://tauri.app/) + [SvelteKit](https://svelte.dev/) + [Tailwind CSS v4](https://tailwindcss.com/), in [Rust](https://www.rust-lang.org/).

## Download

Grab the latest installer from the **[Releases page](https://github.com/andrewbatista31/ipscanner/releases/latest)**:

| File | Use it if |
|---|---|
| `ipscanner_x.y.z_x64-setup.exe` | You want the normal installer (adds a Start menu shortcut, ~2 MB) |
| `ipscanner_x.y.z_x64_en-US.msi` | Your IT department deploys software via SCCM / group policy |
| `ipscanner_x.y.z_x64-portable.exe` | You want a single `.exe` you can drop on a USB stick — no install |

Windows will show a SmartScreen warning on first launch since the binary is not code-signed. Click **More info** → **Run anyway**.

Requires **WebView2 Runtime**, which is preinstalled on Windows 11 and most modern Windows 10 builds. If missing, the installer will offer to fetch it.

## Features

- **Range syntax** — single IPs (`10.0.0.1`), CIDR (`192.168.1.0/24`), short ranges (`10.0.0.5-50`), explicit ranges (`10.0.0.254-10.0.1.5`), or any mix separated by commas / newlines.
- **ICMP ping** — Windows `IcmpSendEcho` API, no admin required.
- **Reverse DNS** — system resolver lookup for `.in-addr.arpa` PTR records.
- **NetBIOS** — UDP/137 NBSTAT query returns the workstation name and workgroup for any Windows host that has it enabled.
- **TCP port probing** — pick from presets (Common, Web, Top 20) or specify custom ports.
- **Live results** — rows stream in as each host completes; progress bar, alive count, elapsed time always visible.
- **Clickable IPs** — for alive hosts, click the IP to open the device in your default browser. URL is picked smart: https on port 443/8443, http on 80/8080, defaulting to `http://<ip>`.
- **Native Excel export** — writes a real `.xlsx` (styled header, frozen top row, autofit columns) via [`rust_xlsxwriter`](https://crates.io/crates/rust_xlsxwriter). No CSV-blob shenanigans.
- **Filter & cancel** — text filter across IP/hostname/NetBIOS/ports, plus a Stop button that cleanly cancels in-flight workers.
- **Configurable concurrency and timeouts** — defaults work for /24-sized scans, knobs for everything else.

## Building from source

Prerequisites:
- Rust (stable) via [rustup](https://rustup.rs)
- Node.js LTS (v20+)
- Microsoft Visual Studio Build Tools (C++ workload)
- WebView2 Runtime (preinstalled on Windows 11)

```powershell
git clone https://github.com/andrewbatista31/ipscanner
cd ipscanner
npm install
npm run tauri dev          # live-reload dev build
npm run tauri build        # release build + installers (NSIS, MSI)
```

Release artifacts land in `src-tauri/target/release/bundle/`.

## Project layout

```
src/                       Svelte frontend (routes, app.css)
src-tauri/
  src/
    lib.rs                 Tauri entry + plugin registration
    commands.rs            Tauri command surface (start_scan, cancel_scan, export_xlsx)
    scanner/
      engine.rs            Worker pool, cancellation, event emission
      range.rs             Target parser (CIDR / range / list)
      types.rs             ScanOptions / ScanResult / event payloads
      fetchers/
        ping.rs            Windows ICMP via winping
        dns.rs             Reverse DNS via dns-lookup
        netbios.rs         Raw UDP NBSTAT query + reply parser
        port.rs            TCP connect probe with timeout
```

## Roadmap

- [ ] mDNS / Bonjour service discovery (Apple devices, IoT, modern printers)
- [ ] SNMP fetcher (switches, APs, business printers, UPSes)
- [ ] Sortable result columns
- [ ] Saved range presets
- [ ] Auto-detect local subnet on launch
- [ ] Code signing (kill the SmartScreen warning)
- [ ] Auto-updater
