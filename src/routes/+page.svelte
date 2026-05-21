<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { save } from "@tauri-apps/plugin-dialog";
  import { openUrl } from "@tauri-apps/plugin-opener";
  import { onMount, onDestroy } from "svelte";

  type Liveness = "alive" | "dead" | "unknown";
  type NetbiosInfo = { name: string; workgroup: string | null };
  type ScanResult = {
    scan_id: string;
    ip: string;
    liveness: Liveness;
    rtt_ms: number | null;
    hostname: string | null;
    netbios: NetbiosInfo | null;
    open_ports: number[];
  };
  type ScanProgress = { scan_id: string; completed: number; total: number };
  type ScanStarted = { scan_id: string; total: number };
  type ScanComplete = { scan_id: string; cancelled: boolean };

  const PORT_PRESETS: Record<string, number[]> = {
    "None": [],
    "Common": [22, 80, 443, 3389],
    "Web": [80, 443, 8080, 8443, 3000, 5000, 8000, 8888],
    "Top 20": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080],
  };

  // Port → category mapping for colored chips
  const PORT_CATEGORY: Record<number, { label: string; color: string }> = {
    21:   { label: "FTP",     color: "var(--color-port-file)" },
    22:   { label: "SSH",     color: "var(--color-port-remote)" },
    23:   { label: "Telnet",  color: "var(--color-port-remote)" },
    25:   { label: "SMTP",    color: "var(--color-port-mail)" },
    53:   { label: "DNS",     color: "var(--color-port-dns)" },
    67:   { label: "DHCP",    color: "var(--color-port-dns)" },
    80:   { label: "HTTP",    color: "var(--color-port-web)" },
    110:  { label: "POP3",    color: "var(--color-port-mail)" },
    139:  { label: "SMB",     color: "var(--color-port-file)" },
    143:  { label: "IMAP",    color: "var(--color-port-mail)" },
    161:  { label: "SNMP",    color: "var(--color-port-dns)" },
    389:  { label: "LDAP",    color: "var(--color-port-remote)" },
    443:  { label: "HTTPS",   color: "var(--color-port-web)" },
    445:  { label: "SMB",     color: "var(--color-port-file)" },
    465:  { label: "SMTPS",   color: "var(--color-port-mail)" },
    587:  { label: "SMTP",    color: "var(--color-port-mail)" },
    636:  { label: "LDAPS",   color: "var(--color-port-remote)" },
    993:  { label: "IMAPS",   color: "var(--color-port-mail)" },
    995:  { label: "POP3S",   color: "var(--color-port-mail)" },
    1433: { label: "MSSQL",   color: "var(--color-port-db)" },
    1521: { label: "Oracle",  color: "var(--color-port-db)" },
    3306: { label: "MySQL",   color: "var(--color-port-db)" },
    3389: { label: "RDP",     color: "var(--color-port-remote)" },
    5000: { label: "HTTP",    color: "var(--color-port-web)" },
    5432: { label: "PgSQL",   color: "var(--color-port-db)" },
    5900: { label: "VNC",     color: "var(--color-port-remote)" },
    6379: { label: "Redis",   color: "var(--color-port-db)" },
    8000: { label: "HTTP",    color: "var(--color-port-web)" },
    8080: { label: "HTTP",    color: "var(--color-port-web)" },
    8443: { label: "HTTPS",   color: "var(--color-port-web)" },
    8888: { label: "HTTP",    color: "var(--color-port-web)" },
    27017:{ label: "Mongo",   color: "var(--color-port-db)" },
  };

  function portMeta(p: number) {
    return PORT_CATEGORY[p] ?? { label: "", color: "var(--color-port-other)" };
  }

  // --- State ---
  let targets = $state("192.168.1.0/24");
  let portPreset = $state("None");
  let customPorts = $state("");
  let doPing = $state(true);
  let doDns = $state(true);
  let doNetbios = $state(true);
  let includeDead = $state(false);
  let concurrency = $state(100);
  let pingTimeout = $state(1000);
  let portTimeout = $state(500);
  let netbiosTimeout = $state(1000);

  let scanId = $state<string | null>(null);
  let results = $state<ScanResult[]>([]);
  let completed = $state(0);
  let total = $state(0);
  let elapsedMs = $state(0);
  let startedAt = 0;
  let elapsedTimer: ReturnType<typeof setInterval> | null = null;
  let error = $state<string | null>(null);
  let unlisteners: UnlistenFn[] = [];
  let filter = $state("");

  // --- Saved target ranges (persisted in localStorage) ---
  type SavedRange = { name: string; value: string };
  const SAVED_RANGES_KEY = "ipscanner.savedRanges.v1";
  let savedRanges = $state<SavedRange[]>([]);

  function persistSaved() {
    try {
      localStorage.setItem(SAVED_RANGES_KEY, JSON.stringify(savedRanges));
    } catch {}
  }
  function loadSavedFromStorage() {
    try {
      const raw = localStorage.getItem(SAVED_RANGES_KEY);
      if (raw) savedRanges = JSON.parse(raw);
    } catch {}
  }
  function saveCurrentRange() {
    const current = targets.trim();
    if (!current) return;
    const suggested = current.split(/[\n,]/)[0].trim().slice(0, 40);
    const name = window.prompt("Save this range as:", suggested);
    if (!name || !name.trim()) return;
    savedRanges = [...savedRanges, { name: name.trim(), value: current }];
    persistSaved();
  }
  function applySaved(r: SavedRange) {
    targets = r.value;
  }
  function deleteSaved(idx: number, ev: MouseEvent) {
    ev.stopPropagation();
    savedRanges = savedRanges.filter((_, i) => i !== idx);
    persistSaved();
  }

  // --- Sort state ---
  type SortKey = "ip" | "status" | "rtt" | "hostname" | "netbios" | "ports";
  let sortKey = $state<SortKey | null>(null);
  let sortDir = $state<"asc" | "desc">("asc");

  function ipToNum(ip: string): number {
    const o = ip.split(".").map((x) => parseInt(x, 10));
    return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
  }
  function livenessRank(l: Liveness): number {
    return l === "alive" ? 0 : l === "unknown" ? 1 : 2;
  }
  function compareBy(a: ScanResult, b: ScanResult, key: SortKey): number {
    switch (key) {
      case "ip":       return ipToNum(a.ip) - ipToNum(b.ip);
      case "status":   return livenessRank(a.liveness) - livenessRank(b.liveness);
      case "rtt":      return (a.rtt_ms ?? Infinity) - (b.rtt_ms ?? Infinity);
      case "hostname": return (a.hostname ?? "").localeCompare(b.hostname ?? "");
      case "netbios":  return (a.netbios?.name ?? "").localeCompare(b.netbios?.name ?? "");
      case "ports":    return b.open_ports.length - a.open_ports.length;
    }
  }
  function clickHeader(key: SortKey) {
    if (sortKey === key) {
      if (sortDir === "asc") sortDir = "desc";
      else { sortKey = null; sortDir = "asc"; }
    } else {
      sortKey = key;
      sortDir = "asc";
    }
  }

  const isScanning = $derived(scanId !== null);
  const aliveCount = $derived(results.filter((r) => r.liveness === "alive").length);
  const pctComplete = $derived(total > 0 ? Math.round((completed / total) * 100) : 0);
  const filteredResults = $derived(
    filter.trim()
      ? results.filter((r) => {
          const f = filter.toLowerCase();
          return (
            r.ip.includes(filter) ||
            (r.hostname ?? "").toLowerCase().includes(f) ||
            (r.netbios?.name ?? "").toLowerCase().includes(f) ||
            (r.netbios?.workgroup ?? "").toLowerCase().includes(f) ||
            r.open_ports.some((p) => String(p).includes(filter))
          );
        })
      : results,
  );

  // Sorted view: when sortKey is null we preserve insertion order (alive
  // hosts naturally come first when dead are filtered, since they emit
  // sooner). Once the user clicks a column header we sort by that key.
  const displayedResults = $derived.by(() => {
    const key = sortKey;
    if (!key) return filteredResults;
    const sorted = [...filteredResults].sort((a, b) => compareBy(a, b, key));
    return sortDir === "desc" ? sorted.reverse() : sorted;
  });

  function parsePorts(): number[] {
    const preset = PORT_PRESETS[portPreset] ?? [];
    const custom = customPorts
      .split(/[,\s]+/)
      .map((s) => parseInt(s, 10))
      .filter((n) => Number.isFinite(n) && n > 0 && n < 65536);
    return Array.from(new Set([...preset, ...custom])).sort((a, b) => a - b);
  }

  async function startScan() {
    error = null;
    results = [];
    completed = 0;
    total = 0;
    startedAt = performance.now();
    elapsedMs = 0;
    if (elapsedTimer) clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      elapsedMs = performance.now() - startedAt;
    }, 100);

    try {
      const id = await invoke<string>("start_scan", {
        targets,
        options: {
          ping: doPing,
          resolve_hostname: doDns,
          netbios: doNetbios,
          ports: parsePorts(),
          ping_timeout_ms: pingTimeout,
          port_timeout_ms: portTimeout,
          netbios_timeout_ms: netbiosTimeout,
          concurrency,
          include_dead: includeDead,
        },
      });
      scanId = id;
    } catch (e) {
      error = String(e);
      if (elapsedTimer) clearInterval(elapsedTimer);
    }
  }

  async function stopScan() {
    if (!scanId) return;
    await invoke("cancel_scan", { scanId });
  }

  async function exportXlsx() {
    error = null;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    try {
      const path = await save({
        defaultPath: `scan-${stamp}.xlsx`,
        filters: [{ name: "Excel workbook", extensions: ["xlsx"] }],
      });
      if (!path) return;
      await invoke("export_xlsx", { path, results: displayedResults });
    } catch (e) {
      error = `Export failed: ${e}`;
    }
  }

  function urlFor(r: ScanResult): string {
    const ports = r.open_ports;
    if (ports.includes(443)) return `https://${r.ip}`;
    if (ports.includes(80)) return `http://${r.ip}`;
    if (ports.includes(8443)) return `https://${r.ip}:8443`;
    if (ports.includes(8080)) return `http://${r.ip}:8080`;
    return `http://${r.ip}`;
  }

  async function openIp(r: ScanResult) {
    try {
      await openUrl(urlFor(r));
    } catch (e) {
      error = `Failed to open URL: ${e}`;
    }
  }

  onMount(async () => {
    loadSavedFromStorage();
    unlisteners.push(
      await listen<ScanStarted>("scan-started", (e) => {
        total = e.payload.total;
      }),
    );
    unlisteners.push(
      await listen<ScanResult>("scan-result", (e) => {
        results.push(e.payload);
      }),
    );
    unlisteners.push(
      await listen<ScanProgress>("scan-progress", (e) => {
        completed = e.payload.completed;
      }),
    );
    unlisteners.push(
      await listen<ScanComplete>("scan-complete", (_e) => {
        if (elapsedTimer) {
          clearInterval(elapsedTimer);
          elapsedTimer = null;
        }
        elapsedMs = performance.now() - startedAt;
        scanId = null;
      }),
    );
  });

  onDestroy(() => {
    unlisteners.forEach((u) => u());
    if (elapsedTimer) clearInterval(elapsedTimer);
  });

  function fmtElapsed(ms: number): string {
    const s = Math.floor(ms / 1000);
    const m = Math.floor(s / 60);
    return `${m}:${String(s % 60).padStart(2, "0")}`;
  }
</script>

<svelte:head>
  <title>ipscanner</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin="anonymous" />
  <link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap"
    rel="stylesheet"
  />
</svelte:head>

<div class="grid h-screen grid-cols-[320px_1fr] grid-rows-[1fr] overflow-hidden">
  <!-- ============ SIDEBAR ============ -->
  <aside class="flex flex-col overflow-hidden border-r border-[var(--color-border)] bg-[var(--color-panel)]">
    <!-- Brand -->
    <header class="flex items-center gap-3 border-b border-[var(--color-border)] px-5 py-4">
      <div class="relative">
        <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-[var(--color-accent-soft)]">
          <!-- radar/network icon -->
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-accent)]">
            <circle cx="12" cy="12" r="9"></circle>
            <circle cx="12" cy="12" r="5"></circle>
            <circle cx="12" cy="12" r="1.5" fill="currentColor"></circle>
            <line x1="12" y1="3" x2="12" y2="6"></line>
            <line x1="12" y1="18" x2="12" y2="21"></line>
            <line x1="3" y1="12" x2="6" y2="12"></line>
            <line x1="18" y1="12" x2="21" y2="12"></line>
          </svg>
        </div>
      </div>
      <div class="flex-1">
        <div class="font-semibold leading-tight">ipscanner</div>
        <div class="font-mono text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">v0.2.1</div>
      </div>
    </header>

    <!-- Scrollable controls -->
    <div class="flex-1 space-y-6 overflow-y-auto p-5">
      <!-- Targets -->
      <section class="space-y-2">
        <div class="flex items-center justify-between">
          <label for="targets" class="text-xs font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Targets</label>
          <span class="font-mono text-[10px] text-[var(--color-text-muted)]">CIDR · range · list</span>
        </div>
        <textarea
          id="targets"
          bind:value={targets}
          rows="3"
          class="input-base w-full resize-none"
          placeholder="192.168.1.0/24"
          disabled={isScanning}
        ></textarea>

        <!-- Saved ranges -->
        <div class="flex flex-wrap items-center gap-1.5 pt-1">
          {#each savedRanges as r, i (r.name + i)}
            <div class="group/chip inline-flex items-stretch rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] text-[11px] transition hover:border-[var(--color-accent)] hover:bg-[var(--color-accent-soft)]">
              <button
                type="button"
                onclick={() => applySaved(r)}
                class="flex items-center gap-1 px-2 py-1 transition hover:text-[var(--color-accent-bright)]"
                title={r.value}
                disabled={isScanning}
              >
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-text-muted)] group-hover/chip:text-[var(--color-accent)]">
                  <polygon points="12 2 15 8.5 22 9.3 17 14 18.2 21 12 17.8 5.8 21 7 14 2 9.3 9 8.5 12 2"/>
                </svg>
                <span class="max-w-[100px] truncate">{r.name}</span>
              </button>
              <button
                type="button"
                onclick={(e) => deleteSaved(i, e)}
                title="Delete preset"
                class="hidden items-center justify-center pr-1.5 pl-0.5 text-[var(--color-text-muted)] hover:text-[var(--color-danger)] group-hover/chip:flex"
              >
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
              </button>
            </div>
          {/each}
          <button
            type="button"
            onclick={saveCurrentRange}
            disabled={isScanning || !targets.trim()}
            class="inline-flex items-center gap-1 rounded-md border border-dashed border-[var(--color-border-bright)] px-2 py-1 text-[11px] text-[var(--color-text-dim)] transition hover:border-[var(--color-accent)] hover:text-[var(--color-accent)] disabled:opacity-40"
            title="Save the current target range as a preset"
          >
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Save current
          </button>
        </div>
      </section>

      <!-- Ports -->
      <section class="space-y-2">
        <label for="port-preset" class="text-xs font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Port scan</label>
        <select id="port-preset" bind:value={portPreset} class="input-base w-full" disabled={isScanning}>
          {#each Object.keys(PORT_PRESETS) as p}
            <option value={p}>{p}{PORT_PRESETS[p].length > 0 ? ` (${PORT_PRESETS[p].length})` : ""}</option>
          {/each}
        </select>
        <input
          type="text"
          bind:value={customPorts}
          class="input-base w-full"
          placeholder="extra ports (e.g. 8000, 9090)"
          disabled={isScanning}
        />
      </section>

      <!-- Identification toggles -->
      <section class="space-y-1">
        <div class="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Identification</div>
        <label class="toggle-row">
          <span>ICMP ping</span>
          <input type="checkbox" class="check" bind:checked={doPing} disabled={isScanning} />
        </label>
        <label class="toggle-row">
          <span>Reverse DNS</span>
          <input type="checkbox" class="check" bind:checked={doDns} disabled={isScanning} />
        </label>
        <label class="toggle-row">
          <span>NetBIOS</span>
          <input type="checkbox" class="check" bind:checked={doNetbios} disabled={isScanning} />
        </label>
        <label class="toggle-row">
          <span>Show dead hosts</span>
          <input type="checkbox" class="check" bind:checked={includeDead} disabled={isScanning} />
        </label>
      </section>

      <!-- Advanced -->
      <section class="space-y-3">
        <div class="text-xs font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Advanced</div>
        <div class="grid grid-cols-2 gap-3">
          <label class="space-y-1">
            <span class="text-[11px] text-[var(--color-text-dim)]">Concurrency</span>
            <input type="number" bind:value={concurrency} min="1" max="1000" class="input-base w-full" disabled={isScanning} />
          </label>
          <label class="space-y-1">
            <span class="text-[11px] text-[var(--color-text-dim)]">Ping ms</span>
            <input type="number" bind:value={pingTimeout} min="100" max="10000" step="100" class="input-base w-full" disabled={isScanning} />
          </label>
          <label class="space-y-1">
            <span class="text-[11px] text-[var(--color-text-dim)]">Port ms</span>
            <input type="number" bind:value={portTimeout} min="100" max="10000" step="100" class="input-base w-full" disabled={isScanning} />
          </label>
          <label class="space-y-1">
            <span class="text-[11px] text-[var(--color-text-dim)]">NetBIOS ms</span>
            <input type="number" bind:value={netbiosTimeout} min="100" max="10000" step="100" class="input-base w-full" disabled={isScanning} />
          </label>
        </div>
      </section>
    </div>

    <!-- Bottom action -->
    <div class="border-t border-[var(--color-border)] p-5">
      {#if isScanning}
        <button
          onclick={stopScan}
          class="group relative flex w-full items-center justify-center gap-2 rounded-md bg-[var(--color-danger-bg)] py-2.5 font-medium text-[var(--color-danger)] transition hover:bg-[var(--color-danger)] hover:text-white"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>
          Stop scan
        </button>
      {:else}
        <button
          onclick={startScan}
          class="group relative flex w-full items-center justify-center gap-2 rounded-md bg-[var(--color-accent)] py-2.5 font-medium text-[#06121a] shadow-[0_0_24px_var(--color-accent-glow)] transition hover:bg-[var(--color-accent-bright)]"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
          Start scan
        </button>
      {/if}
    </div>
  </aside>

  <!-- ============ MAIN ============ -->
  <main class="flex min-w-0 flex-col overflow-hidden">
    <!-- Top status bar -->
    <header class="flex items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-panel)]/60 px-6 py-3 backdrop-blur">
      <div class="flex items-center gap-2.5">
        <div class="relative flex h-2 w-2 items-center justify-center">
          {#if isScanning}
            <span class="pulse-ring absolute inline-block h-2 w-2 rounded-full bg-[var(--color-accent)]"></span>
            <span class="inline-block h-2 w-2 rounded-full bg-[var(--color-accent)]"></span>
          {:else}
            <span class="inline-block h-2 w-2 rounded-full bg-[var(--color-text-muted)]"></span>
          {/if}
        </div>
        <span class="text-sm text-[var(--color-text-dim)]">
          {#if isScanning}
            Scanning <span class="font-mono text-[var(--color-text)]">{targets.split(/[\n,]/)[0].trim()}</span>...
          {:else if results.length > 0}
            Scan complete · <span class="font-mono text-[var(--color-text)]">{aliveCount}</span> alive
          {:else}
            Ready
          {/if}
        </span>
      </div>
      <div class="font-mono text-xs text-[var(--color-text-muted)]">{new Date().toLocaleDateString()}</div>
    </header>

    <!-- Stat cards -->
    <div class="grid grid-cols-4 gap-3 px-6 py-4">
      <div class="lift rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
        <div class="flex items-center justify-between">
          <div class="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Scanned</div>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-text-muted)]">
            <path d="M21 21l-4.35-4.35"/><circle cx="11" cy="11" r="7"/>
          </svg>
        </div>
        <div class="mt-2 font-mono text-2xl font-semibold tabular-nums">
          {completed}<span class="text-[var(--color-text-muted)]">/{total || "—"}</span>
        </div>
      </div>

      <div class="lift rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
        <div class="flex items-center justify-between">
          <div class="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Alive</div>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-up)]">
            <polyline points="3 12 9 12 12 5 15 19 18 12 21 12"/>
          </svg>
        </div>
        <div class="mt-2 font-mono text-2xl font-semibold tabular-nums text-[var(--color-up)]">{aliveCount}</div>
      </div>

      <div class="lift rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
        <div class="flex items-center justify-between">
          <div class="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Elapsed</div>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-text-muted)]">
            <circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>
          </svg>
        </div>
        <div class="mt-2 font-mono text-2xl font-semibold tabular-nums">{fmtElapsed(elapsedMs)}</div>
      </div>

      <div class="lift rounded-lg border border-[var(--color-border)] bg-[var(--color-panel)] p-4">
        <div class="flex items-center justify-between">
          <div class="text-[11px] font-medium uppercase tracking-wider text-[var(--color-text-dim)]">Progress</div>
          <span class="font-mono text-xs text-[var(--color-text-muted)]">{pctComplete}%</span>
        </div>
        <div class="mt-3 h-1.5 overflow-hidden rounded-full bg-[var(--color-panel-3)]">
          <div
            class="relative h-full bg-[var(--color-accent)] transition-all duration-300"
            style="width: {pctComplete}%"
          >
            {#if isScanning}
              <div class="shimmer absolute inset-0"></div>
            {/if}
          </div>
        </div>
      </div>
    </div>

    {#if error}
      <div class="mx-6 mb-3 flex items-start gap-2 rounded-md border border-[var(--color-danger)]/30 bg-[var(--color-danger-bg)] px-3 py-2 text-sm text-[var(--color-danger)]">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="mt-0.5 flex-none">
          <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12" y2="16"/>
        </svg>
        <span class="font-mono text-xs">{error}</span>
      </div>
    {/if}

    <!-- Toolbar -->
    <div class="flex items-center gap-2 border-y border-[var(--color-border)] bg-[var(--color-panel)]/40 px-6 py-2.5">
      <div class="relative flex-1">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--color-text-muted)]">
          <path d="M21 21l-4.35-4.35"/><circle cx="11" cy="11" r="7"/>
        </svg>
        <input
          type="text"
          bind:value={filter}
          placeholder="Filter by IP, hostname, NetBIOS, port..."
          class="input-base w-full pl-8 font-sans"
        />
      </div>
      <span class="font-mono text-xs text-[var(--color-text-muted)]">
        {filteredResults.length}{filteredResults.length !== results.length ? ` of ${results.length}` : ""} {results.length === 1 ? "row" : "rows"}
      </span>
      <button
        onclick={exportXlsx}
        disabled={results.length === 0}
        class="flex items-center gap-1.5 rounded-md border border-[var(--color-border)] bg-[var(--color-panel-2)] px-3 py-1.5 text-sm transition hover:border-[var(--color-border-bright)] hover:bg-[var(--color-panel-3)] disabled:opacity-40"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
        </svg>
        Export Excel
      </button>
    </div>

    <!-- Results table -->
    <div class="min-h-0 flex-1 overflow-auto">
      {#if displayedResults.length === 0}
        <div class="flex h-full flex-col items-center justify-center gap-4 text-center">
          <div class="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--color-accent-soft)]">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" class="text-[var(--color-accent)]">
              <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/>
            </svg>
          </div>
          <div class="text-sm text-[var(--color-text-dim)]">
            {#if isScanning}
              Scanning <span class="font-mono text-[var(--color-text)]">{targets.split(/[\n,]/)[0].trim()}</span>...
            {:else if results.length === 0}
              <div class="font-medium text-[var(--color-text)]">No results yet</div>
              <div class="mt-1 text-xs">Enter a range and hit <span class="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 font-mono text-[var(--color-accent)]">Start scan</span></div>
            {:else}
              No results match the filter.
            {/if}
          </div>
        </div>
      {:else}
        <table class="w-full text-sm">
          <thead class="sticky top-0 z-10 bg-[var(--color-panel)] text-[10px] font-medium uppercase tracking-wider text-[var(--color-text-dim)] backdrop-blur">
            <tr class="border-b border-[var(--color-border)]">
              {#snippet sortableTh(key: SortKey, label: string, align: "left" | "right" = "left", extra = "")}
                <th class="px-3 py-2.5 {align === 'right' ? 'text-right' : 'text-left'} {extra}">
                  <button
                    type="button"
                    onclick={() => clickHeader(key)}
                    class="inline-flex items-center gap-1 {align === 'right' ? 'flex-row-reverse' : ''} text-[10px] font-medium uppercase tracking-wider transition hover:text-[var(--color-text)] {sortKey === key ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-dim)]'}"
                  >
                    <span>{label}</span>
                    {#if sortKey === key}
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        {#if sortDir === "asc"}<polyline points="18 15 12 9 6 15"/>{:else}<polyline points="6 9 12 15 18 9"/>{/if}
                      </svg>
                    {:else}
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-30">
                        <polyline points="8 9 12 5 16 9"/><polyline points="16 15 12 19 8 15"/>
                      </svg>
                    {/if}
                  </button>
                </th>
              {/snippet}
              {@render sortableTh("ip", "IP address", "left", "pl-6")}
              {@render sortableTh("status", "Status")}
              {@render sortableTh("rtt", "RTT", "right")}
              {@render sortableTh("hostname", "Hostname")}
              {@render sortableTh("netbios", "NetBIOS")}
              {@render sortableTh("ports", "Open ports")}
            </tr>
          </thead>
          <tbody class="font-mono">
            {#each displayedResults as r (r.ip)}
              <tr class="group border-b border-[var(--color-border)]/40 transition-colors hover:bg-[var(--color-panel-2)]">
                <td class="px-6 py-2">
                  {#if r.liveness === "alive"}
                    <button
                      type="button"
                      onclick={() => openIp(r)}
                      title="Open {urlFor(r)} in browser"
                      class="inline-flex items-center gap-1 text-[var(--color-accent)] transition hover:text-[var(--color-accent-bright)]"
                    >
                      <span>{r.ip}</span>
                      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 transition-opacity group-hover:opacity-100">
                        <path d="M7 17 17 7"/><path d="M7 7h10v10"/>
                      </svg>
                    </button>
                  {:else}
                    <span class="text-[var(--color-text-muted)]">{r.ip}</span>
                  {/if}
                </td>
                <td class="px-3 py-2">
                  {#if r.liveness === "alive"}
                    <span class="inline-flex items-center gap-1.5 rounded-full bg-[var(--color-up-bg)] px-2 py-0.5 text-[11px] font-medium text-[var(--color-up)]">
                      <span class="h-1.5 w-1.5 rounded-full bg-[var(--color-up)]"></span>
                      Alive
                    </span>
                  {:else if r.liveness === "dead"}
                    <span class="text-[11px] text-[var(--color-text-muted)]">Dead</span>
                  {:else}
                    <span class="text-[11px] text-[var(--color-warning)]">Unknown</span>
                  {/if}
                </td>
                <td class="px-3 py-2 text-right text-[var(--color-text-dim)] tabular-nums">{r.rtt_ms != null ? `${r.rtt_ms} ms` : "—"}</td>
                <td class="px-3 py-2 text-[var(--color-text)]">{r.hostname ?? "—"}</td>
                <td class="px-3 py-2">
                  {#if r.netbios}
                    <span class="text-[var(--color-text)]">{r.netbios.name}</span>
                    {#if r.netbios.workgroup}
                      <span class="ml-1.5 text-[11px] text-[var(--color-text-muted)]">/ {r.netbios.workgroup}</span>
                    {/if}
                  {:else}
                    <span class="text-[var(--color-text-muted)]">—</span>
                  {/if}
                </td>
                <td class="px-3 py-2">
                  {#if r.open_ports.length > 0}
                    <div class="flex flex-wrap gap-1">
                      {#each r.open_ports as p}
                        {@const meta = portMeta(p)}
                        <span
                          class="inline-flex items-baseline gap-1 rounded border px-1.5 py-0.5 text-[10px]"
                          style="color: {meta.color}; border-color: {meta.color}33; background: {meta.color}10;"
                          title={meta.label ? `${meta.label} (${p})` : `Port ${p}`}
                        >
                          <span class="font-mono font-medium">{p}</span>
                          {#if meta.label}<span class="font-sans text-[9px] uppercase opacity-70">{meta.label}</span>{/if}
                        </span>
                      {/each}
                    </div>
                  {:else}
                    <span class="text-[var(--color-text-muted)]">—</span>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </main>
</div>
