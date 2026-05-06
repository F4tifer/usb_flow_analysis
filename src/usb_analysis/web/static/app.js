import { FlowView } from "/static/flow.js";
import { FlowDetailPanel } from "/static/detail.js";
import { FlowTimeline } from "/static/timeline.js";

const q = (id) => document.getElementById(id);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

// ============================================================
// State
// ============================================================
const state = {
  captureId: null,
  captureIds: [],
  loaded: {
    overview: false,
    packets: false,
    stream: false,
    flow: false,
    errors: false,
    sessions: false,
    deep: false,
  },
  navHistory: [],
  navIndex: -1,
  suppressHistoryPush: false,
};

// ============================================================
// Helpers
// ============================================================
function optionalInt(elId) {
  const raw = q(elId).value.trim();
  if (!raw.length) return undefined;
  const v = Number.parseInt(raw, 10);
  return Number.isFinite(v) ? v : undefined;
}

function qs(obj) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || v === "") continue;
    u.set(k, String(v));
  }
  return "?" + u.toString();
}

function baseQuery() {
  const path = q("pathBox").value.trim();
  return qs({
    path: path || undefined,
    capture_id: state.captureId ?? undefined,
    capture_ids: state.captureIds.length ? state.captureIds.join(",") : undefined,
    bus: optionalInt("fBus"),
    device: optionalInt("fDev"),
    endpoint: optionalInt("fEp"),
  });
}

function flowQuery() {
  const runRaw = Number.parseInt(q("flowRun").value, 10);
  const direction = q("flowDirection").value || "";
  const parts = [
    baseQuery(),
    "&min_severity=" + encodeURIComponent(q("flowSeverity").value),
  ];
  if (direction) parts.push("&direction=" + encodeURIComponent(direction));
  if (Number.isFinite(runRaw)) parts.push(`&run=${runRaw}`);
  return parts.join("");
}

function hasCapture() {
  return !!(state.captureId || state.captureIds.length || q("pathBox").value.trim());
}

function fmtDuration(secs) {
  if (secs == null) return "—";
  if (secs < 1) return `${(secs * 1000).toFixed(0)} ms`;
  if (secs < 60) return `${secs.toFixed(2)} s`;
  const m = Math.floor(secs / 60);
  const s = secs - m * 60;
  return `${m}m ${s.toFixed(1)}s`;
}

function fmtTs(secs) {
  if (secs == null) return "—";
  return new Date(secs * 1000).toISOString().replace("T", " ").replace("Z", "");
}

function showToast(msg, kind = "info") {
  const el = q("toast");
  el.textContent = msg;
  el.className = `toast toast-${kind}`;
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.hidden = true; }, 3500);
}

function toastError(err) {
  console.error(err);
  showToast(String(err?.message || err), "error");
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  let res;
  try {
    res = await fetch(url, { signal: controller.signal });
  } catch (err) {
    if (err?.name === "AbortError") {
      throw new Error(`Timeout při volání API: ${url}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json();
}

function setStatus(kind, text) {
  const dot = q("captureStatus").querySelector(".status-dot");
  const txt = q("captureStatus").querySelector(".status-text");
  dot.className = "status-dot status-" + kind;
  txt.textContent = text;
}

// ============================================================
// Loading overlay (refcounted so concurrent operations stack)
// ============================================================
let loadingDepth = 0;
let loadingWatchdogTimer = null;
const LOADING_WATCHDOG_MS = 30000;

function resetLoadingWatchdog() {
  if (loadingWatchdogTimer) clearTimeout(loadingWatchdogTimer);
  loadingWatchdogTimer = null;
}

function armLoadingWatchdog() {
  resetLoadingWatchdog();
  loadingWatchdogTimer = setTimeout(() => {
    if (loadingDepth <= 0) return;
    loadingDepth = 0;
    const overlay = q("loadingOverlay");
    overlay.hidden = true;
    overlay.style.display = "none";
    showToast("Načítání trvalo příliš dlouho. Zkontrolujte API/server logy.", "error");
  }, LOADING_WATCHDOG_MS);
}

function showLoading(title, detail) {
  loadingDepth += 1;
  q("loadingTitle").textContent = title || "Načítám…";
  q("loadingDetail").textContent = detail || "";
  const overlay = q("loadingOverlay");
  overlay.hidden = false;
  overlay.style.display = "";
  armLoadingWatchdog();
}

function updateLoadingDetail(detail) {
  q("loadingDetail").textContent = detail || "";
}

function hideLoading() {
  loadingDepth = Math.max(0, loadingDepth - 1);
  const overlay = q("loadingOverlay");
  if (loadingDepth === 0) {
    overlay.hidden = true;
    overlay.style.display = "none";
    resetLoadingWatchdog();
  } else {
    armLoadingWatchdog();
  }
}

async function withLoading(title, fn, detail) {
  showLoading(title, detail);
  try {
    return await fn();
  } finally {
    hideLoading();
  }
}

// ============================================================
// Flow primitives (initialised lazily on first flow tab visit)
// ============================================================
let flowView = null;
let detailPanel = null;
let timeline = null;

function ensureFlowComponents() {
  if (flowView) return;
  detailPanel = new FlowDetailPanel();
  flowView = new FlowView({
    viewportId: "flowVirtualViewport",
    innerId: "flowVirtualInner",
    statsId: "flowStats",
    detailPanel,
    queryProvider: flowQuery,
  });
  timeline = new FlowTimeline("flowTimeline");
  detailPanel.setBaseQueryProvider(baseQuery);
  detailPanel.onJumpToSeq = (seq) => jumpToSeq(seq).catch(toastError);

  timeline.onSelectBucket = (idx, total) => {
    const approxSeq = Math.floor((idx / total) * Math.max(1, flowView.total));
    flowView.reload({ from_seq: Math.max(1, approxSeq) }).catch(toastError);
  };

  flowView.onSelectionChanged = (event) => {
    if (!state.suppressHistoryPush) pushHistory(event.seq);
    if (!event?.ts || !timeline?.buckets?.length) return;
    const ts0 = timeline.buckets[0].ts;
    const ts1 = timeline.buckets[timeline.buckets.length - 1].ts;
    if (ts1 <= ts0) return;
    const rel = (event.ts - ts0) / (ts1 - ts0);
    const canvas = q("flowTimeline");
    const ctx = canvas.getContext("2d");
    timeline.draw();
    const x = Math.max(0, Math.min(canvas.width - 1, rel * canvas.width));
    ctx.strokeStyle = "#f8fafc";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  };
}

// ============================================================
// History (flow seq navigation)
// ============================================================
function updateHistoryButtons() {
  q("flowBack").disabled = state.navIndex <= 0;
  q("flowForward").disabled = state.navIndex < 0 || state.navIndex >= state.navHistory.length - 1;
}

function pushHistory(seq) {
  if (!Number.isFinite(seq)) return;
  if (state.navHistory[state.navIndex] === seq) return;
  state.navHistory = state.navHistory.slice(0, state.navIndex + 1);
  state.navHistory.push(seq);
  state.navIndex = state.navHistory.length - 1;
  updateHistoryButtons();
}

async function jumpToSeq(seq, { fromHistory = false } = {}) {
  ensureFlowComponents();
  await activateTab("flow");
  state.suppressHistoryPush = true;
  try {
    await flowView.focusSeq(seq);
    if (!fromHistory) pushHistory(seq);
  } finally {
    state.suppressHistoryPush = false;
  }
}

async function historyBack() {
  if (state.navIndex <= 0) return;
  state.navIndex -= 1;
  updateHistoryButtons();
  await jumpToSeq(state.navHistory[state.navIndex], { fromHistory: true });
}

async function historyForward() {
  if (state.navIndex >= state.navHistory.length - 1) return;
  state.navIndex += 1;
  updateHistoryButtons();
  await jumpToSeq(state.navHistory[state.navIndex], { fromHistory: true });
}

// ============================================================
// Upload
// ============================================================
async function uploadFiles(files) {
  const list = Array.from(files || []);
  if (!list.length) return;
  const total = list.reduce((s, f) => s + (f.size || 0), 0);
  const sizeStr = total ? ` · ${(total / 1024 / 1024).toFixed(1)} MB` : "";
  const detail = list.length === 1
    ? `${list[0].name}${sizeStr}`
    : `${list.length} souborů${sizeStr}`;

  await withLoading("Nahrávám PCAP", async () => {
    setStatus("loading", `Nahrávám ${list.length} soubor(ů)…`);
    const fd = new FormData();
    if (list.length === 1) {
      fd.append("file", list[0]);
      const res = await fetch("/api/upload", { method: "POST", body: fd });
      if (!res.ok) {
        setStatus("error", "Upload selhal");
        throw new Error(await res.text());
      }
      const data = await res.json();
      state.captureId = data.capture_id;
      state.captureIds = [];
      setStatus("ready", data.filename || "capture nahrán");
    } else {
      for (const f of list) fd.append("files", f);
      const res = await fetch("/api/upload-multi", { method: "POST", body: fd });
      if (!res.ok) {
        setStatus("error", "Upload selhal");
        throw new Error(await res.text());
      }
      const data = await res.json();
      state.captureIds = data.capture_ids || [];
      state.captureId = state.captureIds[0] ?? null;
      setStatus("ready", `${state.captureIds.length} captures nahráno`);
    }
    q("pathBox").value = "";
    invalidateLoaded();
    updateLoadingDetail("Analyzuji obsah…");
    await loadCurrentTab();
  }, detail);
}

function invalidateLoaded() {
  for (const k of Object.keys(state.loaded)) state.loaded[k] = false;
  q("overviewEmpty").hidden = hasCapture();
  q("overviewContent").hidden = !hasCapture();
}

// ============================================================
// Tab switching
// ============================================================
async function activateTab(name) {
  $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.panel === name));
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  await loadTab(name);
}

async function loadCurrentTab() {
  const active = $$(".tab.active")[0]?.dataset.tab || "overview";
  // Force reload regardless of cache (filters / capture changed).
  state.loaded[active] = false;
  await loadTab(active, { force: true });
}

const TAB_LOADERS = {
  // Keep overview non-blocking so startup never gets trapped behind modal loading.
  overview: { fn: loadOverview, title: "", detail: "" },
  packets:  { fn: loadPackets,  title: "Načítám pakety",  detail: "" },
  stream:   { fn: loadStream,   title: "Načítám stream",  detail: "ASCII překlad bulk komunikace" },
  flow:     { fn: loadFlow,     title: "Analyzuji flow",  detail: "Build flow stream + causal + detectors" },
  errors:   { fn: loadErrors,   title: "Načítám chyby",   detail: "" },
  sessions: { fn: loadSessions, title: "Načítám sessions a runy", detail: "" },
  export:   { fn: () => { setupExport(); }, title: "", detail: "" },
  // Help is static HTML, doesn't need a capture or any fetch.
  help:     { fn: () => {}, title: "", detail: "" },
};

async function loadTab(name, { force = false } = {}) {
  if (!hasCapture() && name !== "overview" && name !== "export" && name !== "help") return;
  if (state.loaded[name] && !force) return;
  const loader = TAB_LOADERS[name];
  if (!loader) {
    state.loaded[name] = true;
    return;
  }
  try {
    if (loader.title) {
      await withLoading(loader.title, () => loader.fn(), loader.detail);
    } else {
      await loader.fn();
    }
    state.loaded[name] = true;
  } catch (err) {
    toastError(err);
  }
}

// ============================================================
// Overview
// ============================================================
async function loadOverview() {
  if (!hasCapture()) {
    q("overviewEmpty").hidden = false;
    q("overviewContent").hidden = true;
    return;
  }
  q("overviewEmpty").hidden = true;
  q("overviewContent").hidden = false;

  const summary = await fetchJson("/api/summary" + baseQuery());
  q("mPackets").textContent = (summary.total_packets || 0).toLocaleString();
  q("mDuration").textContent = fmtDuration(summary.duration_s);
  q("timeInfo").innerHTML = `
    <div>Start: <code>${fmtTs(summary.time_start)}</code></div>
    <div>End:   <code>${fmtTs(summary.time_end)}</code></div>
  `;

  const devEl = q("overviewDevices");
  devEl.innerHTML = (summary.devices || [])
    .map((d) => `<span class="device-chip">bus ${d.bus} / dev ${d.device}</span>`)
    .join("") || `<span class="muted">žádná zařízení</span>`;

  q("overviewXfer").innerHTML = renderDist(summary.transfer_types || {});
  q("overviewEvents").innerHTML = renderDist(summary.event_types || {});
  q("mRuns").textContent = "…";
  q("mCritical").textContent = "…";
  q("mWarning").textContent = "…";
  q("mSessions").textContent = "…";
  q("badgeCritical").textContent = "…";
  q("badgeWarning").textContent = "…";
  q("badgeInfo").textContent = "…";
  q("severitySummary").hidden = false;

  // Heavy derived metrics are loaded in background to keep overview responsive.
  void loadOverviewDerivedMetrics();
}

async function loadOverviewDerivedMetrics() {
  if (!hasCapture()) return;

  // Single batched fetch for runs + errors + sessions data.
  const sessionsByKey = new Map();
  let runCount = 0;
  let critical = 0, warning = 0, info = 0;

  try {
    const [runs, errs, fsHead] = await Promise.all([
      fetchJson("/api/flow/runs" + baseQuery()),
      fetchJson("/api/flow/errors" + baseQuery() + "&min_severity=info"),
      fetchJson("/api/flow/stream" + baseQuery() + "&min_severity=info&page_size=1"),
    ]);
    runCount = (runs.rows || []).length;
    const errRows = errs.rows || [];
    critical = errRows.filter((r) => r.severity === "critical").length;
    warning  = errRows.filter((r) => r.severity === "warning").length;
    info     = errRows.filter((r) => r.severity === "info").length;

    const totalEvents = fsHead.total || 0;
    if (totalEvents > 0) {
      const fsAll = await fetchJson("/api/flow/stream" + baseQuery()
        + "&min_severity=info&page_size=" + Math.min(totalEvents, 2000));
      for (const ev of fsAll.events || []) {
        const k = ev.device_session;
        if (!sessionsByKey.has(k)) {
          sessionsByKey.set(k, {
            session_index: k,
            bus_id: ev.bus_id,
            device_address: ev.device_address,
            device_serial: ev.device_serial || null,
            start_seq: ev.seq,
            end_seq: ev.seq,
          });
        } else {
          const s = sessionsByKey.get(k);
          s.end_seq = ev.seq;
          if (ev.device_serial && !s.device_serial) s.device_serial = ev.device_serial;
        }
      }
    }
  } catch (err) {
    console.warn("Overview metrics partial failure:", err);
  }

  q("mRuns").textContent = runCount || "—";
  q("mCritical").textContent = critical;
  q("mWarning").textContent = warning;
  q("mSessions").textContent = sessionsByKey.size || "—";

  q("badgeCritical").textContent = critical;
  q("badgeWarning").textContent = warning;
  q("badgeInfo").textContent = info;
  q("severitySummary").hidden = false;

  renderSidebarSessions([...sessionsByKey.values()]);
}

function renderDist(obj) {
  const entries = Object.entries(obj).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 1;
  if (!entries.length) return `<div class="muted">žádné</div>`;
  return entries
    .map(([k, v]) => `
      <div class="dist-bar">
        <div>${k}</div>
        <div class="dist-bar-track"><div class="dist-bar-fill" style="width:${(v / max) * 100}%"></div></div>
        <div class="dist-bar-value">${v.toLocaleString()}</div>
      </div>
    `).join("");
}

function renderSidebarSessions(sessions) {
  const wrap = q("sessionsSection");
  const list = q("sessionsList");
  if (!sessions.length) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  list.innerHTML = sessions.map((s) => `
    <div class="session-pill" data-seq="${s.start_seq}">
      <div><span class="session-id">#${s.session_index}</span> bus ${s.bus_id}/dev ${s.device_address}</div>
      <div class="session-meta">SN: ${s.device_serial || "?"} · seq ${s.start_seq}–${s.end_seq}</div>
    </div>
  `).join("");
  $$(".session-pill", list).forEach((el) => {
    el.onclick = () => jumpToSeq(parseInt(el.dataset.seq, 10)).catch(toastError);
  });
}

// ============================================================
// Packets
// ============================================================
async function loadPackets() {
  if (!hasCapture()) return;
  const offset = parseInt(q("fOff").value, 10) || 0;
  const lim = parseInt(q("fLim").value, 10) || 50;
  const data = await fetchJson("/api/packets" + baseQuery() + `&offset=${offset}&limit=${lim}`);
  const body = q("rowsBody");
  body.innerHTML = "";
  let firstRow = null;
  for (const row of data.rows || []) {
    const tr = document.createElement("tr");
    tr.onclick = () => {
      $$("#rowsBody tr.selected").forEach((el) => el.classList.remove("selected"));
      tr.classList.add("selected");
      q("detailOut").textContent = JSON.stringify(row, null, 2);
    };
    tr.innerHTML = `
      <td>${row.ordinal}</td>
      <td>${(row.pcap_ts || 0).toFixed(6)}</td>
      <td>${row.urb_id}</td>
      <td>${row.event ?? ""}</td>
      <td>${row.transfer_type}</td>
      <td>${row.bus_id}</td>
      <td>${row.device_address}</td>
      <td>${row.endpoint}</td>
      <td>${(row.payload_hex || "").slice(0, 40)}${(row.payload_hex || "").length > 40 ? "…" : ""}</td>
      <td>${row.trezor ? `${row.trezor.frame}:${row.trezor.message_type_id ?? ""}:${row.trezor.protobuf?.message_name ?? ""}` : ""}</td>
    `;
    body.append(tr);
    if (!firstRow) firstRow = tr;
  }
  if (firstRow) firstRow.click();
}

// ============================================================
// Stream
// ============================================================
async function loadStream() {
  if (!hasCapture()) return;
  const data = await fetchJson("/api/stream" + baseQuery() + "&offset=0&limit=2000");
  q("streamOut").textContent = (data.rows || [])
    .map((r) => `${r.speaker === "host" ? "host  →" : "device ←"} ${r.line}`)
    .join("\n") || "(stream je prázdný)";
}

// ============================================================
// Flow
// ============================================================
async function loadFlow() {
  if (!hasCapture()) return;
  ensureFlowComponents();
  await flowView.reload();
  await timeline.load(baseQuery());
  state.navHistory = [];
  state.navIndex = -1;
  updateHistoryButtons();
  if (flowView.events.length) {
    await flowView.selectIndex(0);
    pushHistory(flowView.events[0].seq);
  }
}

// ============================================================
// Errors
// ============================================================
async function loadErrors() {
  if (!hasCapture()) return;
  const sev = q("errSeverity").value;
  const layer = q("errLayer").value;
  const url = "/api/flow/errors" + baseQuery()
    + "&min_severity=" + encodeURIComponent(sev)
    + (layer ? "&layer=" + encodeURIComponent(layer) : "");
  const data = await fetchJson(url);
  const rows = data.rows || [];
  const body = q("errorsBody");
  body.innerHTML = "";
  q("errorsEmpty").textContent = rows.length ? "" : "Žádné chyby pro zvolené filtry.";
  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.className = `sev-${e.severity}`;
    const seq = e.linked_flow_events?.[0] ?? "";
    tr.innerHTML = `
      <td>${seq}</td>
      <td>${e.layer}</td>
      <td>${e.severity}</td>
      <td>${e.event_type}</td>
      <td>${escapeHtml(e.description)}</td>
      <td>${fmtTs(e.ts)}</td>
      <td>${(e.causal_hints || []).map(escapeHtml).join("<br/>")}</td>
    `;
    if (Number.isFinite(seq)) {
      tr.onclick = () => jumpToSeq(seq).catch(toastError);
    }
    body.append(tr);
  }
}

// ============================================================
// Sessions / Runs
// ============================================================
async function loadSessions() {
  if (!hasCapture()) return;
  // Build sessions from flow events.
  const fs = await fetchJson("/api/flow/stream" + baseQuery() + "&min_severity=info&page_size=1");
  const total = fs.total || 0;
  const sessions = new Map();
  if (total > 0) {
    const data = await fetchJson("/api/flow/stream" + baseQuery() + "&min_severity=info&page_size=" + Math.min(total, 1000));
    for (const ev of data.events || []) {
      const k = ev.device_session;
      if (!sessions.has(k)) {
        sessions.set(k, {
          session_index: k,
          bus_id: ev.bus_id,
          device_address: ev.device_address,
          device_serial: ev.device_serial || null,
          start_seq: ev.seq,
          end_seq: ev.seq,
          ts_start: ev.ts,
          ts_end: ev.ts,
          event_count: 0,
        });
      }
      const s = sessions.get(k);
      s.end_seq = ev.seq;
      s.ts_end = ev.ts;
      s.event_count += 1;
      if (ev.device_serial && !s.device_serial) s.device_serial = ev.device_serial;
    }
  }
  const sBody = q("sessionsTableBody");
  sBody.innerHTML = "";
  for (const s of sessions.values()) {
    const tr = document.createElement("tr");
    const dur = fmtDuration(s.ts_end - s.ts_start);
    tr.innerHTML = `
      <td>${s.session_index}</td>
      <td>${s.bus_id}</td>
      <td>${s.device_address}</td>
      <td>${s.device_serial || "?"}</td>
      <td>${s.start_seq}</td>
      <td>${s.end_seq}</td>
      <td>${s.event_count}</td>
      <td>${fmtTs(s.ts_start)}</td>
      <td>${dur}</td>
    `;
    tr.onclick = () => jumpToSeq(s.start_seq).catch(toastError);
    sBody.append(tr);
  }

  // Runs
  const runs = await fetchJson("/api/flow/runs" + baseQuery());
  const rBody = q("runsBody");
  rBody.innerHTML = "";
  for (const r of runs.rows || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.run_index}</td>
      <td>${r.start_seq}</td>
      <td>${r.end_seq}</td>
      <td>${r.cmd_count}</td>
      <td>${r.error_count}</td>
      <td>${fmtDuration((r.duration_ms || 0) / 1000)}</td>
      <td>${(r.completeness_pct || 0).toFixed(0)} %</td>
    `;
    tr.onclick = () => jumpToSeq(r.start_seq).catch(toastError);
    rBody.append(tr);
  }
}

// ============================================================
// Deep
// ============================================================
async function loadDeep() {
  if (!hasCapture()) return showToast("Nahrajte PCAP nejdřív.", "warning");

  await withLoading("Hluboká analýza", async () => {
    setStatus("loading", "Spouštím hloubkovou analýzu…");
    try {
      const path = q("pathBox").value.trim();
      const baseQ = qs({
        path: path || undefined,
        capture_id: state.captureId ?? undefined,
        capture_ids: state.captureIds.length ? state.captureIds.join(",") : undefined,
      });
      updateLoadingDetail("Segmentace + scoring + mining pravidel");
      const [summary, findings, rules] = await Promise.all([
        fetchJson("/api/deep/summary" + baseQ),
        fetchJson("/api/deep/findings" + baseQ + "&limit=50"),
        fetchJson("/api/deep/rules" + baseQ + "&limit=50"),
      ]);
      q("deepSummaryOut").textContent = JSON.stringify(summary, null, 2);

      const fBody = q("deepFindingsBody");
      fBody.innerHTML = "";
      for (const f of findings.rows || []) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${f.score?.toFixed?.(2) ?? f.score}</td>
          <td>${f.segment?.cmd_name || ""}</td>
          <td>${f.segment?.outcome || ""}</td>
          <td>${f.segment?.run_index ?? ""}</td>
          <td>${f.segment?.latency_ms?.toFixed?.(1) ?? ""} ms</td>
          <td>${(f.reasons || []).join(", ")}</td>
        `;
        fBody.append(tr);
      }
      const rBody = q("deepRulesBody");
      rBody.innerHTML = "";
      for (const r of rules.rows || []) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${r.rule_id}</td>
          <td>${(r.confidence || 0).toFixed(2)}</td>
          <td>${r.support}</td>
          <td>${escapeHtml(r.description || "")}</td>
          <td>${escapeHtml(r.suggested_action || "")}</td>
        `;
        rBody.append(tr);
      }
      state.loaded.deep = true;
      setStatus("ready", "Deep analýza hotová");
    } catch (err) {
      setStatus("error", "Deep selhala");
      throw err;
    }
  }, "(může chvíli trvat)");
}

// ============================================================
// Export
// ============================================================
function setupExport() {
  const wire = (id, endpoint) => {
    const el = q(id);
    if (!hasCapture()) {
      el.classList.add("disabled");
      el.removeAttribute("href");
    } else {
      el.classList.remove("disabled");
      el.href = endpoint + baseQuery();
    }
  };
  wire("exportJson", "/api/export/json");
  wire("exportCsv", "/api/export/csv");
  wire("exportHtml", "/api/export/html");
  wire("exportJunit", "/api/export/junit");
}

// ============================================================
// Misc helpers
// ============================================================
function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

// ============================================================
// Wiring — DOMContentLoaded
// ============================================================
function wireUpload() {
  const inp = q("upload");
  inp.addEventListener("change", (e) => e.target.files?.length && uploadFiles(e.target.files).catch(toastError));

  const zone = q("uploadZone");
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => {
    e.preventDefault();
    zone.classList.add("dragover");
  }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => {
    e.preventDefault();
    zone.classList.remove("dragover");
  }));
  zone.addEventListener("drop", (e) => {
    if (e.dataTransfer?.files?.length) uploadFiles(e.dataTransfer.files).catch(toastError);
  });
}

function wireTabs() {
  $$(".tab").forEach((btn) => btn.addEventListener("click", () => activateTab(btn.dataset.tab)));
  // Hash routing
  const initial = (location.hash || "#overview").slice(1);
  if ($$(`.tab[data-tab="${initial}"]`).length) activateTab(initial);
  else activateTab("overview");
}

function wireFilters() {
  q("btnLoadPath").addEventListener("click", () => {
    state.captureId = null;
    state.captureIds = [];
    invalidateLoaded();
    setStatus("ready", "Použita lokální cesta");
    loadCurrentTab().catch(toastError);
  });
  q("btnApplyFilters").addEventListener("click", () => {
    invalidateLoaded();
    loadCurrentTab().catch(toastError);
  });
  q("btnClearFilters").addEventListener("click", () => {
    q("fBus").value = "";
    q("fDev").value = "";
    q("fEp").value = "";
    invalidateLoaded();
    loadCurrentTab().catch(toastError);
  });
}

function wirePackets() {
  q("btnRefresh").addEventListener("click", () => loadPackets().catch(toastError));
  q("btnNext").addEventListener("click", () => {
    const lim = parseInt(q("fLim").value, 10) || 50;
    q("fOff").value = String((parseInt(q("fOff").value, 10) || 0) + lim);
    loadPackets().catch(toastError);
  });
  q("btnPrev").addEventListener("click", () => {
    const lim = parseInt(q("fLim").value, 10) || 50;
    q("fOff").value = String(Math.max(0, (parseInt(q("fOff").value, 10) || 0) - lim));
    loadPackets().catch(toastError);
  });
}

function wireStream() {
  q("btnStream").addEventListener("click", () => loadStream().catch(toastError));
}

function wireFlow() {
  q("btnFlow").addEventListener("click", () => loadFlow().catch(toastError));
  q("flowSeverity").addEventListener("change", () => loadFlow().catch(toastError));
  q("flowDirection").addEventListener("change", () => loadFlow().catch(toastError));
  q("flowRun").addEventListener("change", () => loadFlow().catch(toastError));
  q("flowSearch").addEventListener("change", async () => {
    const term = q("flowSearch").value.trim();
    ensureFlowComponents();
    if (!term) return loadFlow().catch(toastError);
    await withLoading(`Hledám "${term}"`, async () => {
      const data = await fetchJson(`/api/flow/search${baseQuery()}&q=${encodeURIComponent(term)}&limit=1000`);
      flowView.events = data.rows || [];
      flowView.total = flowView.events.length;
      flowView.selectedIndex = -1;
      flowView.lastSelectedPairSeq = null;
      flowView.inner.style.height = `${flowView.total * 28}px`;
      flowView.active.clear();
      flowView.inner.innerHTML = "";
      await flowView.renderVirtual();
      state.navHistory = [];
      state.navIndex = -1;
      updateHistoryButtons();
      if (flowView.events.length) {
        await flowView.selectIndex(0);
        pushHistory(flowView.events[0].seq);
      }
    }).catch(toastError);
  });
  q("flowBack").addEventListener("click", () => historyBack().catch(toastError));
  q("flowForward").addEventListener("click", () => historyForward().catch(toastError));
}

function wireErrors() {
  q("btnLoadErrors").addEventListener("click", () => loadErrors().catch(toastError));
  q("errSeverity").addEventListener("change", () => loadErrors().catch(toastError));
  q("errLayer").addEventListener("change", () => loadErrors().catch(toastError));
}

function wireSessions() {
  q("btnLoadSessions").addEventListener("click", () => loadSessions().catch(toastError));
}

function wireDeep() {
  q("btnDeep").addEventListener("click", () => loadDeep().catch(toastError));
}

function wireKeyboard() {
  window.addEventListener("keydown", async (ev) => {
    if (ev.target && ["INPUT", "TEXTAREA", "SELECT"].includes(ev.target.tagName)) return;
    if (ev.altKey && ev.key === "ArrowLeft") { ev.preventDefault(); await historyBack(); }
    else if (ev.altKey && ev.key === "ArrowRight") { ev.preventDefault(); await historyForward(); }
    else if (/^[1-9]$/.test(ev.key) && !ev.metaKey && !ev.ctrlKey) {
      const idx = parseInt(ev.key, 10) - 1;
      const tab = $$(".tab")[idx];
      if (tab) { ev.preventDefault(); activateTab(tab.dataset.tab); }
    }
    else if (flowView && q("flow")?.classList?.contains?.("active")) {
      // ignored — flow view registers its own
    }
    if (!flowView) return;
    const flowActive = $$(".tab.active")[0]?.dataset.tab === "flow";
    if (!flowActive) return;
    if (ev.key === "ArrowDown") { ev.preventDefault(); await flowView.moveSelection(1); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); await flowView.moveSelection(-1); }
    else if (ev.key === "PageDown") { ev.preventDefault(); await flowView.moveSelection(20); }
    else if (ev.key === "PageUp") { ev.preventDefault(); await flowView.moveSelection(-20); }
    else if (ev.key.toLowerCase() === "p") {
      ev.preventDefault();
      const cur = flowView.events[flowView.selectedIndex];
      if (cur?.paired_seq) await jumpToSeq(cur.paired_seq);
    }
  });
}

// ============================================================
// Boot
// ============================================================
function boot() {
  wireUpload();
  wireTabs();
  wireFilters();
  wirePackets();
  wireStream();
  wireFlow();
  wireErrors();
  wireSessions();
  wireDeep();
  wireKeyboard();
  setStatus("empty", "Žádný capture nenahrán");
}

window.addEventListener("unhandledrejection", () => {
  loadingDepth = 0;
  resetLoadingWatchdog();
  const overlay = q("loadingOverlay");
  if (overlay) {
    overlay.hidden = true;
    overlay.style.display = "none";
  }
});

window.addEventListener("error", () => {
  loadingDepth = 0;
  resetLoadingWatchdog();
  const overlay = q("loadingOverlay");
  if (overlay) {
    overlay.hidden = true;
    overlay.style.display = "none";
  }
});

boot();
