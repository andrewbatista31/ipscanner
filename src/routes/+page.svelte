<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
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
    "Common (22,80,443,3389)": [22, 80, 443, 3389],
    "Web (80,443,8080,8443)": [80, 443, 8080, 8443],
    "Top 20": [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080],
  };

  let targets = $state("192.168.1.0/24");
  let portPreset = $state("None");
  let customPorts = $state("");
  let includeDead = $state(false);
  let doNetbios = $state(true);
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

  const isScanning = $derived(scanId !== null && completed < total);
  const aliveCount = $derived(results.filter((r) => r.liveness === "alive").length);
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
          ping: true,
          resolve_hostname: true,
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

  function exportCsv() {
    const header = "ip,liveness,rtt_ms,hostname,netbios_name,workgroup,open_ports";
    const rows = filteredResults.map(
      (r) =>
        `${r.ip},${r.liveness},${r.rtt_ms ?? ""},${r.hostname ?? ""},${r.netbios?.name ?? ""},${r.netbios?.workgroup ?? ""},${r.open_ports.join(" ")}`,
    );
    const blob = new Blob([header + "\n" + rows.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${new Date().toISOString().replace(/[:.]/g, "-")}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  onMount(async () => {
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
    return `${m}:${String(s % 60).padStart(2, "0")}.${String(Math.floor(ms % 1000 / 100))}`;
  }
</script>

<svelte:head>
  <title>ipscanner</title>
</svelte:head>

<div class="flex h-screen flex-col">
  <!-- Header -->
  <header class="border-b border-[var(--color-border)] bg-[var(--color-panel)] px-4 py-3">
    <div class="flex items-center gap-3">
      <div class="flex items-center gap-2 font-mono text-sm text-[var(--color-text-dim)]">
        <span class="inline-block h-2 w-2 rounded-full" class:bg-emerald-400={isScanning} class:bg-zinc-600={!isScanning}></span>
        ipscanner
      </div>
      <div class="flex flex-1 items-center gap-2">
        <input
          type="text"
          bind:value={targets}
          placeholder="192.168.1.0/24 or 10.0.0.1-50 or comma list"
          class="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1.5 font-mono text-sm outline-none placeholder:text-[var(--color-text-dim)] focus:border-[var(--color-accent)]"
          disabled={isScanning}
          onkeydown={(e) => e.key === "Enter" && !isScanning && startScan()}
        />
        <select
          bind:value={portPreset}
          class="rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1.5 text-sm outline-none focus:border-[var(--color-accent)]"
          disabled={isScanning}
        >
          {#each Object.keys(PORT_PRESETS) as p}
            <option value={p}>{p}</option>
          {/each}
        </select>
        {#if isScanning}
          <button
            onclick={stopScan}
            class="rounded-md bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-500"
          >Stop</button>
        {:else}
          <button
            onclick={startScan}
            class="rounded-md bg-[var(--color-accent)] px-4 py-1.5 text-sm font-medium text-white hover:bg-[var(--color-accent-hover)]"
          >Start scan</button>
        {/if}
      </div>
    </div>

    <!-- Options row -->
    <div class="mt-2 flex flex-wrap items-center gap-4 text-xs text-[var(--color-text-dim)]">
      <label class="flex items-center gap-1.5">
        <input type="checkbox" bind:checked={includeDead} disabled={isScanning} />
        Show dead hosts
      </label>
      <label class="flex items-center gap-1.5">
        <input type="checkbox" bind:checked={doNetbios} disabled={isScanning} />
        NetBIOS
      </label>
      <label class="flex items-center gap-1.5">
        Concurrency
        <input type="number" bind:value={concurrency} min="1" max="1000" disabled={isScanning}
          class="w-16 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-right font-mono" />
      </label>
      <label class="flex items-center gap-1.5">
        Ping timeout
        <input type="number" bind:value={pingTimeout} min="100" max="10000" step="100" disabled={isScanning}
          class="w-20 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-right font-mono" /> ms
      </label>
      <label class="flex items-center gap-1.5">
        Port timeout
        <input type="number" bind:value={portTimeout} min="100" max="10000" step="100" disabled={isScanning}
          class="w-20 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-right font-mono" /> ms
      </label>
      <label class="flex items-center gap-1.5">
        NetBIOS timeout
        <input type="number" bind:value={netbiosTimeout} min="100" max="10000" step="100" disabled={isScanning}
          class="w-20 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-1.5 py-0.5 text-right font-mono" /> ms
      </label>
      <label class="flex flex-1 items-center gap-1.5">
        Extra ports
        <input type="text" bind:value={customPorts} placeholder="e.g. 8000, 9000-9010"
          disabled={isScanning}
          class="flex-1 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-0.5 font-mono" />
      </label>
    </div>
  </header>

  <!-- Stats strip -->
  <div class="flex items-center gap-6 border-b border-[var(--color-border)] bg-[var(--color-panel-2)] px-4 py-2 font-mono text-xs">
    <div><span class="text-[var(--color-text-dim)]">Progress</span> <span class="ml-1">{completed} / {total}</span></div>
    <div><span class="text-[var(--color-text-dim)]">Alive</span> <span class="ml-1 text-emerald-400">{aliveCount}</span></div>
    <div><span class="text-[var(--color-text-dim)]">Elapsed</span> <span class="ml-1">{fmtElapsed(elapsedMs)}</span></div>
    {#if total > 0}
      <div class="ml-auto flex items-center gap-2">
        <div class="h-1.5 w-48 overflow-hidden rounded-full bg-[var(--color-border)]">
          <div class="h-full bg-[var(--color-accent)] transition-all" style="width: {(completed / total) * 100}%"></div>
        </div>
        <span class="w-10 text-right text-[var(--color-text-dim)]">{Math.round((completed / total) * 100)}%</span>
      </div>
    {/if}
  </div>

  {#if error}
    <div class="border-b border-red-800/50 bg-red-950/50 px-4 py-2 font-mono text-xs text-red-300">{error}</div>
  {/if}

  <!-- Filter + export -->
  <div class="flex items-center gap-2 border-b border-[var(--color-border)] bg-[var(--color-panel)] px-4 py-2">
    <input
      type="text"
      bind:value={filter}
      placeholder="Filter results..."
      class="flex-1 rounded-md border border-[var(--color-border)] bg-[var(--color-bg)] px-3 py-1 text-sm outline-none focus:border-[var(--color-accent)]"
    />
    <button
      onclick={exportCsv}
      disabled={results.length === 0}
      class="rounded-md border border-[var(--color-border)] px-3 py-1 text-sm hover:bg-[var(--color-panel-2)] disabled:opacity-40"
    >Export CSV</button>
  </div>

  <!-- Results table -->
  <div class="flex-1 overflow-auto">
    {#if filteredResults.length === 0}
      <div class="flex h-full items-center justify-center text-sm text-[var(--color-text-dim)]">
        {#if isScanning}
          Scanning {targets}...
        {:else}
          {results.length === 0 ? "No results yet. Enter a range and click Start scan." : "No results match the filter."}
        {/if}
      </div>
    {:else}
      <table class="w-full font-mono text-sm">
        <thead class="sticky top-0 bg-[var(--color-panel-2)] text-xs uppercase tracking-wider text-[var(--color-text-dim)]">
          <tr>
            <th class="px-4 py-2 text-left">IP</th>
            <th class="px-4 py-2 text-left">Status</th>
            <th class="px-4 py-2 text-right">RTT</th>
            <th class="px-4 py-2 text-left">Hostname</th>
            <th class="px-4 py-2 text-left">NetBIOS</th>
            <th class="px-4 py-2 text-left">Open ports</th>
          </tr>
        </thead>
        <tbody>
          {#each filteredResults as r (r.ip)}
            <tr class="border-b border-[var(--color-border)]/50 hover:bg-[var(--color-panel-2)]">
              <td class="px-4 py-1.5">{r.ip}</td>
              <td class="px-4 py-1.5">
                {#if r.liveness === "alive"}
                  <span class="inline-flex items-center gap-1.5 text-emerald-400">
                    <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>alive
                  </span>
                {:else if r.liveness === "dead"}
                  <span class="text-[var(--color-text-dim)]">dead</span>
                {:else}
                  <span class="text-amber-400">?</span>
                {/if}
              </td>
              <td class="px-4 py-1.5 text-right text-[var(--color-text-dim)]">{r.rtt_ms != null ? `${r.rtt_ms} ms` : "—"}</td>
              <td class="px-4 py-1.5 text-[var(--color-text-dim)]">{r.hostname ?? "—"}</td>
              <td class="px-4 py-1.5">
                {#if r.netbios}
                  <span>{r.netbios.name}</span>
                  {#if r.netbios.workgroup}
                    <span class="ml-1.5 text-xs text-[var(--color-text-dim)]">/ {r.netbios.workgroup}</span>
                  {/if}
                {:else}
                  <span class="text-[var(--color-text-dim)]">—</span>
                {/if}
              </td>
              <td class="px-4 py-1.5">
                {#if r.open_ports.length > 0}
                  <div class="flex flex-wrap gap-1">
                    {#each r.open_ports as p}
                      <span class="rounded bg-[var(--color-panel-2)] px-1.5 py-0.5 text-xs">{p}</span>
                    {/each}
                  </div>
                {:else}
                  <span class="text-[var(--color-text-dim)]">—</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>
