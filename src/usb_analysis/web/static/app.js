import { FlowView } from "/static/flow.js";
import { FlowDetailPanel } from "/static/detail.js";
import { FlowTimeline } from "/static/timeline.js";
import {
  applyTranslations,
  getLanguage,
  initI18n,
  onLanguageChange,
  setLanguage,
  t,
} from "/static/i18n.js";

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
  if (err?.captureLost) return;       // already handled by handleCaptureLost
  showToast(String(err?.message || err), "error");
}

// Per-endpoint timeout heuristic. Building a flow-stream from a large PCAP
// (50 MB / 30k events) routinely takes 30–90 s on first call (no cache yet);
// the previous 20 s blanket timeout was killing legitimate analyses. Fast
// endpoints (info, packets, summary on small files) keep a tight bound so a
// truly hung server still surfaces as an error instead of hanging forever.
const _DEFAULT_TIMEOUT_MS = 30_000;
const _SLOW_TIMEOUT_MS    = 600_000;   // 10 minutes
const _SLOW_PATH_RE = /^\/api\/(flow\/(stream|errors|runs|run\/|sessions|context|event|search|completeness|timeline)|deep\/|aggregate|summary)/;

function _timeoutFor(url) {
  try {
    const path = new URL(url, location.origin).pathname;
    if (_SLOW_PATH_RE.test(path)) return _SLOW_TIMEOUT_MS;
  } catch {}
  return _DEFAULT_TIMEOUT_MS;
}

async function fetchJson(url, opts = {}) {
  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? _timeoutFor(url);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, { signal: controller.signal });
  } catch (err) {
    if (err?.name === "AbortError") {
      const secs = (timeoutMs / 1000).toFixed(0);
      throw new Error(`Timeout při volání API (${secs}s): ${url}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const text = await res.text();
    // Server forgot our capture (e.g. process was restarted and the persisted
    // state file is empty). Reset the client and tell the user to re-upload.
    if (res.status === 404 && CAPTURE_LOST_RE.test(text)) {
      // Pass the captureId that was active when the failing request was
      // issued — if the user re-uploaded between request and response, the
      // current captureId differs and we must NOT reset the fresh state.
      handleCaptureLost(state.captureId, state.captureIds.slice());
      const e = new Error("Capture vypršel — server ho už nezná. Nahrajte PCAP znovu.");
      e.captureLost = true;
      throw e;
    }
    throw new Error(`${res.status}: ${text.slice(0, 200)}`);
  }
  return res.json();
}

// Contract with the server: any 404 whose body matches this regex means the
// referenced capture_id is no longer registered. Server-side string lives in
// app.py:_resolve_capture_id ("Unknown capture id: ...").
const CAPTURE_LOST_RE = /Unknown capture id/;

let _captureLostNotified = false;
function handleCaptureLost(failingCaptureId, failingCaptureIds) {
  // Skip the reset entirely if state already moved on — a stale in-flight
  // request finishing after a successful re-upload must not wipe the new
  // valid captureId.
  const stateUnchanged =
    failingCaptureId === state.captureId &&
    failingCaptureIds.length === state.captureIds.length &&
    failingCaptureIds.every((id, i) => id === state.captureIds[i]);
  if (!stateUnchanged) return;
  if (_captureLostNotified) {
    state.captureId = null;
    state.captureIds = [];
    return;
  }
  _captureLostNotified = true;
  state.captureId = null;
  state.captureIds = [];
  for (const k of Object.keys(state.loaded)) state.loaded[k] = false;
  q("pathBox").value = "";
  setStatus("error", t("status.error"));
  showToast(t("toast.capture_lost"), "warning");
  q("severitySummary").hidden = true;
  q("sessionsSection").hidden = true;
  q("overviewEmpty").hidden = false;
  q("overviewContent").hidden = true;
  // Allow future failures (after re-upload) to notify again.
  setTimeout(() => { _captureLostNotified = false; }, 5000);
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
    showToast(t("loading.watchdog") || "Loading is taking too long. Check API / server logs.", "error");
  }, LOADING_WATCHDOG_MS);
}

function showLoading(title, detail) {
  loadingDepth += 1;
  q("loadingTitle").textContent = title || t("loading.default");
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
  detailPanel.contentLocalizer = localizeContent;
  _updateDetailLabels();
  onLanguageChange(_updateDetailLabels);
  // Live progress in the loading modal during full-stream fetch.
  flowView.onProgress = (loaded, total) => {
    updateLoadingDetail(t("loading.events_progress", {
      loaded: loaded.toLocaleString(),
      total: total.toLocaleString(),
    }));
  };
  // Localised "shown X / Y" label above the viewport.
  flowView.statsFormatter = ({ loaded, total }) =>
    t("flow.stats_format", { loaded: loaded.toLocaleString(), total: total.toLocaleString() });
  // Translate the canonical English `event.content` strings produced by the
  // analyzer into the current UI language.
  flowView.contentLocalizer = localizeContent;

  timeline.onSelectBucket = (idx) => {
    const bucket = timeline.buckets[idx];
    if (!bucket || !flowView.events.length) return;
    // Find the first event whose timestamp is at or beyond the bucket's start.
    // Events are sorted by ts so binary search is overkill — linear is fine.
    let target = null;
    for (const ev of flowView.events) {
      if (ev.ts >= bucket.ts) { target = ev; break; }
    }
    if (!target) target = flowView.events[flowView.events.length - 1];
    flowView.focusSeq(target.seq).catch(toastError);
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
  const fileLabel = list.length === 1 ? list[0].name : `${list.length} files`;
  const detail = `${fileLabel}${sizeStr}`;

  await withLoading(t("loading.uploading"), async () => {
    setStatus("loading", t("status.uploading"));
    const fd = new FormData();
    if (list.length === 1) {
      fd.append("file", list[0]);
      const res = await fetch("/api/upload", { method: "POST", body: fd });
      if (!res.ok) {
        setStatus("error", t("toast.upload_failed"));
        throw new Error(await res.text());
      }
      const data = await res.json();
      state.captureId = data.capture_id;
      state.captureIds = [];
      setStatus("ready", data.filename || t("status.ready"));
    } else {
      for (const f of list) fd.append("files", f);
      const res = await fetch("/api/upload-multi", { method: "POST", body: fd });
      if (!res.ok) {
        setStatus("error", t("toast.upload_failed"));
        throw new Error(await res.text());
      }
      const data = await res.json();
      state.captureIds = data.capture_ids || [];
      state.captureId = state.captureIds[0] ?? null;
      setStatus("ready", t("toast.captures_uploaded", { n: state.captureIds.length }));
    }
    q("pathBox").value = "";
    invalidateLoaded();
    updateLoadingDetail(t("loading.analyzing"));
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

// TAB_LOADERS use translation *keys* for the loading-overlay title/detail
// so the displayed text follows the current language at the time the tab is
// activated (not the time the table was built at module load).
const TAB_LOADERS = {
  // Keep overview non-blocking so startup never gets trapped behind modal loading.
  overview: { fn: loadOverview, titleKey: "", detailKey: "" },
  packets:  { fn: loadPackets,  titleKey: "loading.packets", detailKey: "" },
  stream:   { fn: loadStream,   titleKey: "loading.stream",  detailKey: "loading.stream_detail" },
  flow:     { fn: loadFlow,     titleKey: "loading.flow_title", detailKey: "loading.flow_detail" },
  errors:   { fn: loadErrors,   titleKey: "loading.errors",  detailKey: "" },
  sessions: { fn: loadSessions, titleKey: "loading.sessions", detailKey: "" },
  // Deep is deliberately not auto-run on tab switch — segmentation + scoring +
  // rule mining is heavy. User must click the "Run deep analysis" button. We
  // still register a no-op loader so loadTab() doesn't silently mark it loaded.
  deep:     { fn: () => {}, titleKey: "", detailKey: "" },
  export:   { fn: () => { setupExport(); }, titleKey: "", detailKey: "" },
  // Help is static HTML, doesn't need a capture or any fetch.
  help:     { fn: () => {}, titleKey: "", detailKey: "" },
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
    if (loader.titleKey) {
      const title = t(loader.titleKey);
      const detail = loader.detailKey ? t(loader.detailKey) : "";
      await withLoading(title, () => loader.fn(), detail);
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

  // Animated loaders so the user sees the metrics are *being computed*, not
  // broken. CSS @keyframes + middle <span> implement a 3-dot pulse.
  const metricLoader = `<span class="metric-loading"><span></span></span>`;
  const badgeLoader = `<span class="badge-loading"><span></span></span>`;
  q("mRuns").innerHTML = metricLoader;
  q("mCritical").innerHTML = metricLoader;
  q("mWarning").innerHTML = metricLoader;
  q("mSessions").innerHTML = metricLoader;
  q("badgeCritical").innerHTML = badgeLoader;
  q("badgeWarning").innerHTML = badgeLoader;
  q("badgeInfo").innerHTML = badgeLoader;
  q("severitySummary").hidden = false;

  // Sidebar sessions: show skeleton placeholders that shimmer until real data arrives.
  const sessionsList = q("sessionsList");
  const sessionsWrap = q("sessionsSection");
  if (sessionsList && sessionsWrap) {
    sessionsWrap.hidden = false;
    sessionsList.innerHTML = `
      <div class="session-skeleton"><div class="session-skeleton-line"></div><div class="session-skeleton-line short"></div></div>
      <div class="session-skeleton"><div class="session-skeleton-line"></div><div class="session-skeleton-line short"></div></div>
    `;
  }

  // Heavy derived metrics are loaded in background to keep overview responsive.
  void loadOverviewDerivedMetrics();
}

async function loadOverviewDerivedMetrics() {
  if (!hasCapture()) return;

  let sessions = [];
  let runCount = 0;
  let critical = 0, warning = 0, info = 0;
  let failed = false;

  try {
    // Fire each request independently — a slow /api/flow/sessions shouldn't
    // hold up the runs/errors metrics. Each result fills in its own widget
    // as soon as it arrives so the user sees progressive completion.
    const runsP = fetchJson("/api/flow/runs" + baseQuery())
      .then((runs) => {
        runCount = (runs.rows || []).length;
        q("mRuns").textContent = runCount || "—";
      })
      .catch((err) => { console.warn("runs:", err); failed = true; q("mRuns").textContent = "—"; });

    const errsP = fetchJson("/api/flow/errors" + baseQuery() + "&min_severity=info")
      .then((errs) => {
        const errRows = errs.rows || [];
        critical = errRows.filter((r) => r.severity === "critical").length;
        warning  = errRows.filter((r) => r.severity === "warning").length;
        info     = errRows.filter((r) => r.severity === "info").length;
        q("mCritical").textContent = critical;
        q("mWarning").textContent = warning;
        q("badgeCritical").textContent = critical;
        q("badgeWarning").textContent = warning;
        q("badgeInfo").textContent = info;
      })
      .catch((err) => {
        console.warn("errors:", err); failed = true;
        q("mCritical").textContent = "—";
        q("mWarning").textContent = "—";
        q("badgeCritical").textContent = "—";
        q("badgeWarning").textContent = "—";
        q("badgeInfo").textContent = "—";
      });

    const sessP = fetchJson("/api/flow/sessions" + baseQuery())
      .then((sess) => {
        sessions = sess.rows || [];
        q("mSessions").textContent = sessions.length || "—";
        renderSidebarSessions(sessions);
      })
      .catch((err) => {
        console.warn("sessions:", err); failed = true;
        q("mSessions").textContent = "—";
        const list = q("sessionsList");
        if (list) list.innerHTML = `<div class="muted">Sessions se nepodařilo načíst.</div>`;
      });

    await Promise.allSettled([runsP, errsP, sessP]);
  } catch (err) {
    console.warn("Overview metrics partial failure:", err);
    failed = true;
  }

  if (failed) showToast(t("toast.partial_metrics"), "warning");
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
  const dutLabelOf = (s) => {
    const dutCount = (s.dut_serials || []).length;
    if (dutCount === 0) return t("sessions.pill_no_dut");
    if (dutCount === 1) return escapeHtml(s.dut_serials[0]);
    return t("sessions.pill_many_duts", { n: dutCount });
  };
  list.innerHTML = sessions.map((s) => `
      <div class="session-pill" data-seq="${s.start_seq}">
        <div><span class="session-id">#${s.session_index}</span> ${escapeHtml(t("sidebar.bus"))} ${s.bus_id}/${escapeHtml(t("sidebar.device"))} ${s.device_address}</div>
        <div class="session-meta">${escapeHtml(t("sessions.pill_dut"))}: ${dutLabelOf(s)} · ${escapeHtml(t("sessions.pill_tester"))}: ${escapeHtml(s.tester_serial || "?")}</div>
        <div class="session-meta">seq ${s.start_seq}–${s.end_seq} · ${s.event_count} ${escapeHtml(t("sessions.pill_events"))}</div>
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
  q("errorsEmpty").textContent = rows.length ? "" : t("errors.no_match");
  for (const e of rows) {
    const tr = document.createElement("tr");
    tr.className = `sev-${e.severity}`;
    const seq = e.linked_flow_events?.[0] ?? "";
    // Detector description is canonical-EN ("Latency 32ms on …", "Missing CRC on …");
    // causal hints likewise. Functions return the raw text on no-match so
    // chaining is safe.
    const desc = localizeContent(localizeDetectorDesc(e.description || ""));
    const hints = (e.causal_hints || []).map((h) => escapeHtml(localizeContent(h))).join("<br/>");
    tr.innerHTML = `
      <td>${seq}</td>
      <td>${e.layer}</td>
      <td>${e.severity}</td>
      <td>${e.event_type}</td>
      <td>${escapeHtml(desc)}</td>
      <td>${fmtTs(e.ts)}</td>
      <td>${hints}</td>
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
// Cached payloads for the Sessions tab so the search input can re-render
// without going back to the server on every keystroke.
let _sessionsData = [];
let _runsData = [];

async function loadSessions() {
  if (!hasCapture()) return;
  // Authoritative list straight from the flow analyzer; includes every
  // (bus, device_address) transition regardless of severity filter.
  const [sessData, runsData] = await Promise.all([
    fetchJson("/api/flow/sessions" + baseQuery()),
    fetchJson("/api/flow/runs" + baseQuery()),
  ]);
  _sessionsData = sessData.rows || [];
  _runsData = runsData.rows || [];
  applySessionsFilter();
}

function _makeDutMatcher(term) {
  /**
   * Build a matcher for the DUT-SN search box. **Case-sensitive** — serial
   * numbers are tightly tied to their casing in the protocol, so D736D92D
   * and d736d92d must not collide. Plain substring match by default; if the
   * input is wrapped in slashes (`/regex/`) it's treated as a case-sensitive
   * regex. Bad regex falls back to substring so the user never sees an error.
   */
  if (!term) {
    return {
      empty: true,
      test: () => true,
      highlight: (s) => escapeHtml(s ?? ""),
    };
  }
  let re = null;
  if (term.length > 2 && term.startsWith("/") && term.endsWith("/")) {
    // `g` only — no `i`. Case sensitivity is intentional.
    try { re = new RegExp(term.slice(1, -1), "g"); } catch { re = null; }
  }

  const test = (s) => {
    const v = String(s ?? "");
    if (!v) return false;
    if (re) { re.lastIndex = 0; return re.test(v); }
    return v.includes(term);
  };

  const highlight = (s) => {
    const v = String(s ?? "");
    if (!v) return "";
    if (re) {
      let out = "", last = 0;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(v))) {
        out += escapeHtml(v.slice(last, m.index));
        out += `<mark>${escapeHtml(m[0])}</mark>`;
        last = m.index + m[0].length;
        if (m[0].length === 0) re.lastIndex += 1;
      }
      out += escapeHtml(v.slice(last));
      return out;
    }
    let out = "", i = 0;
    while (true) {
      const idx = v.indexOf(term, i);
      if (idx < 0) { out += escapeHtml(v.slice(i)); break; }
      out += escapeHtml(v.slice(i, idx))
           + `<mark>${escapeHtml(v.slice(idx, idx + term.length))}</mark>`;
      i = idx + term.length;
    }
    return out;
  };

  return { empty: false, test, highlight };
}

function applySessionsFilter() {
  const term = q("sessionsSearch").value.trim();
  const matcher = _makeDutMatcher(term);

  const matchedSessions = matcher.empty
    ? _sessionsData
    : _sessionsData.filter((s) => (s.dut_serials || []).some((d) => matcher.test(d)));

  const matchedRuns = matcher.empty
    ? _runsData
    : _runsData.filter((r) => matcher.test(r.dut_serial || ""));

  // Render Sessions
  const sBody = q("sessionsTableBody");
  sBody.innerHTML = "";
  for (const s of matchedSessions) {
    const tr = document.createElement("tr");
    const dur = fmtDuration(s.ts_end - s.ts_start);
    const dutsRaw = s.dut_serials || [];
    const duts = dutsRaw.length
      ? dutsRaw.map((d) => matcher.highlight(d)).join(", ")
      : "—";
    tr.innerHTML = `
      <td>${s.session_index}</td>
      <td>${s.bus_id}</td>
      <td>${s.device_address}</td>
      <td>${escapeHtml(s.tester_serial || "—")}</td>
      <td>${duts}</td>
      <td>${s.start_seq}</td>
      <td>${s.end_seq}</td>
      <td>${s.event_count}</td>
      <td>${fmtTs(s.ts_start)}</td>
      <td>${dur}</td>
    `;
    tr.onclick = () => jumpToSeq(s.start_seq).catch(toastError);
    sBody.append(tr);
  }
  if (!matchedSessions.length) {
    sBody.innerHTML = `<tr><td colspan="10" class="muted" style="text-align:center;padding:1rem">${escapeHtml(t("sessions.empty_sessions"))}</td></tr>`;
  }

  // Render Runs
  const rBody = q("runsBody");
  rBody.innerHTML = "";
  for (const r of matchedRuns) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.run_index}</td>
      <td>${r.dut_serial ? matcher.highlight(r.dut_serial) : "—"}</td>
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
  if (!matchedRuns.length) {
    rBody.innerHTML = `<tr><td colspan="8" class="muted" style="text-align:center;padding:1rem">${escapeHtml(t("sessions.empty_runs"))}</td></tr>`;
  }

  // Match info
  const info = q("sessionsMatchInfo");
  if (matcher.empty) {
    info.textContent = t("sessions.count_format_empty", {
      sessions: _sessionsData.length,
      runs: _runsData.length,
    });
  } else {
    info.textContent = t("sessions.count_format_match", {
      ms: matchedSessions.length,
      ts: _sessionsData.length,
      mr: matchedRuns.length,
      tr: _runsData.length,
    });
  }
}

// ============================================================
// Deep
// ============================================================
// Canonical → localised translator for server-side strings that contain
// variable parts (cmd names, byte counts, …). The patterns must match the
// strings produced by flow_builder.py / causal.py / detectors.py exactly,
// so updating those files requires updating this function too.
function localizeContent(raw) {
  if (!raw) return raw;
  // 1. Causal hints — fixed prefixes that may be embedded in event.content
  //    (timeline meta rows) or stand alone in causal_hints array.
  let m;
  m = raw.match(/^Timeout on '([^']+)' just before the error may have corrupted device state\.$/);
  if (m) return t("causal.timeout_before_error", { cmd: m[1] });
  if (raw === "USB error preceded the problem — possible DN/DP physical-layer fault.")
    return t("causal.usb_error_before");
  if (raw === "An incomplete segment earlier may have caused a domino effect.")
    return t("causal.incomplete_segment_before");
  if (raw === "A reconnect preceded the problem — the device may have gone through a reset.")
    return t("causal.reconnect_before");
  if (raw === "Previous ERROR suggests an error chain.")
    return t("causal.error_chain");

  // 2. Flow event content
  m = raw.match(/^Incomplete segment \(([^)]+)\) — chunked, device change$/);
  if (m) return t("content.incomplete_chunked_device_change", { cmd: m[1] });
  m = raw.match(/^Incomplete segment \(([^)]+)\) — device change$/);
  if (m) return t("content.incomplete_device_change", { cmd: m[1] });
  m = raw.match(/^Incomplete segment after (.+)$/);
  if (m) return t("content.incomplete_after", { cmd: m[1] });
  m = raw.match(/^New command before previous was closed: (.+)$/);
  if (m) return t("content.incomplete_new_cmd", { cmd: m[1] });
  m = raw.match(/^Device change: bus (\d+)\/dev (\d+) \(tester (\S+)\) — previous tester: (\S+)$/);
  if (m) return t("content.device_change_full", { bus: m[1], dev: m[2], tester: m[3], prev: m[4] });
  m = raw.match(/^Device change: bus (\d+)\/dev (\d+) \(tester (\S+)\)$/);
  if (m) return t("content.device_change_new_only", { bus: m[1], dev: m[2], tester: m[3] });
  m = raw.match(/^Device change: bus (\d+)\/dev (\d+) — previous tester: (\S+)$/);
  if (m) return t("content.device_change_prev_only", { bus: m[1], dev: m[2], prev: m[3] });
  m = raw.match(/^Device change: bus (\d+)\/dev (\d+)$/);
  if (m) return t("content.device_change_bare", { bus: m[1], dev: m[2] });
  m = raw.match(/^URB (\S+) submit without complete$/);
  if (m) return t("content.urb_no_complete", { urb: m[1] });
  m = raw.match(/^Timeout ([\d.]+)ms on (.+)$/);
  if (m) return t("content.timeout_on", { ms: m[1], cmd: m[2] });
  if (raw === "Reconnect after a longer gap")
    return t("content.reconnect_after_gap");
  // Chunked-awaiting suffix appears tail of `display_content`. Replace inline.
  if (raw.endsWith("[chunked, awaiting…]")) {
    return raw.slice(0, -"[chunked, awaiting…]".length) + t("content.chunked_awaiting_suffix");
  }
  return raw;
}

// Detector ErrorEvent.description — server emits English.
function localizeDetectorDesc(raw) {
  if (!raw) return raw;
  if (raw === "Device reconnect") return t("detector.device_reconnect");
  let m;
  m = raw.match(/^Missing CRC on (.+)$/);
  if (m) return t("detector.missing_crc", { cmd: m[1] });
  m = raw.match(/^CRC mismatch on (.+)$/);
  if (m) return t("detector.crc_mismatch", { cmd: m[1] });
  m = raw.match(/^Latency ([\d.]+)ms on (.+)$/);
  if (m) return t("detector.timing", { ms: m[1], cmd: m[2] });
  m = raw.match(/^Suspiciously low latency ([\d.]+)ms on (.+)$/);
  if (m) return t("detector.timing_low", { ms: m[1], cmd: m[2] });
  // ERROR / status / app_error etc. pass through — they're protocol-level text
  // that should stay verbatim (`ERROR invalid-crc "..."`, `USB status=...`).
  return raw;
}

// Map a canonical English anomaly-finding reason (emitted by scorer.py) to a
// localised string. Returns the original text when no translation matches.
function localizeReason(raw) {
  if (!raw) return "";
  if (raw === "unknown command for baseline") return t("reason.unknown_command");
  if (raw === "unusual run position") return t("reason.unusual_run_position");
  if (raw === "response line count spike") return t("reason.response_line_count_spike");
  if (raw === "high anomaly score") return t("reason.high_anomaly");
  if (raw.startsWith("unexpected outcome")) {
    const tail = raw.slice("unexpected outcome".length).trim();
    return t("reason.unexpected_outcome") + (tail ? " " + tail : "");
  }
  const m = raw.match(/^latency spike \(([^)]+)\)$/);
  if (m) return t("reason.latency_spike", { mad: m[1] });
  return raw;
}

async function loadDeep() {
  if (!hasCapture()) return showToast(t("toast.upload_no_pcap"), "warning");

  await withLoading(t("loading.deep"), async () => {
    setStatus("loading", t("status.deep_running"));
    try {
      const path = q("pathBox").value.trim();
      const baseQ = qs({
        path: path || undefined,
        capture_id: state.captureId ?? undefined,
        capture_ids: state.captureIds.length ? state.captureIds.join(",") : undefined,
      });
      updateLoadingDetail(t("loading.deep_progress"));
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
          <td>${escapeHtml((f.reasons || []).map(localizeReason).join(", "))}</td>
        `;
        fBody.append(tr);
      }
      const rBody = q("deepRulesBody");
      rBody.innerHTML = "";
      for (const r of rules.rows || []) {
        const tr = document.createElement("tr");
        const ruleKey = `rule.${r.rule_id}`;
        // Server sends canonical EN description; UI replaces via `rule.<id>`
        // lookup. Missing keys fall through to the server text.
        const ruleDesc = t(ruleKey);
        const description = ruleDesc !== ruleKey ? ruleDesc : (r.description || "");
        const actionKey = `action.${r.suggested_action}`;
        const actionLocal = t(actionKey);
        const action = actionLocal !== actionKey ? actionLocal : (r.suggested_action || "");
        tr.innerHTML = `
          <td>${escapeHtml(r.rule_id)}</td>
          <td>${(r.confidence || 0).toFixed(2)}</td>
          <td>${r.support}</td>
          <td>${escapeHtml(description)}</td>
          <td>${escapeHtml(action)}</td>
        `;
        rBody.append(tr);
      }
      // Intentionally don't lock `state.loaded.deep` — user may want to re-run
      // after changing filters or upload, so each button click should re-fetch.
      setStatus("ready", t("status.deep_done"));
    } catch (err) {
      setStatus("error", t("status.deep_failed"));
      throw err;
    }
  }, t("loading.deep_detail"));
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
    setStatus("ready", t("toast.using_path"));
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
    await withLoading(t("loading.search", { term }), async () => {
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

  // Jump-to-seq: number input + button. Enter inside the input triggers it too.
  const doJump = async () => {
    const raw = q("flowJumpSeq").value.trim();
    const seq = Number.parseInt(raw, 10);
    if (!Number.isFinite(seq) || seq < 1) {
      showToast(t("toast.invalid_seq"), "warning");
      return;
    }
    ensureFlowComponents();
    if (!flowView.events.length) {
      // Make sure flow data is loaded before searching for the seq.
      await loadFlow();
    }
    await withLoading(t("loading.jump", { seq }), async () => {
      await jumpToSeq(seq);
      const found = flowView.events.find((e) => e.seq === seq);
      if (!found) showToast(t("toast.seq_not_in_filter", { seq }), "warning");
    });
  };
  q("btnFlowJump").addEventListener("click", () => doJump().catch(toastError));
  q("flowJumpSeq").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      doJump().catch(toastError);
    }
  });
}

function wireErrors() {
  q("btnLoadErrors").addEventListener("click", () => loadErrors().catch(toastError));
  q("errSeverity").addEventListener("change", () => loadErrors().catch(toastError));
  q("errLayer").addEventListener("change", () => loadErrors().catch(toastError));
}

function _debounce(fn, ms) {
  let t = null;
  return function (...args) {
    if (t) clearTimeout(t);
    t = setTimeout(() => { t = null; fn.apply(this, args); }, ms);
  };
}

function wireSessions() {
  q("btnLoadSessions").addEventListener("click", () => loadSessions().catch(toastError));
  // Live filter — re-renders cached data after a brief idle period. Debounce
  // keeps typing snappy with 1000+ sessions where DOM rebuild per keystroke
  // would otherwise stall the input.
  const debouncedFilter = _debounce(() => {
    try { applySessionsFilter(); } catch (err) { toastError(err); }
  }, 80);
  q("sessionsSearch").addEventListener("input", debouncedFilter);
  q("btnSessionsClear").addEventListener("click", () => {
    q("sessionsSearch").value = "";
    applySessionsFilter();
  });
}

function wireDeep() {
  q("btnDeep").addEventListener("click", () => loadDeep().catch(toastError));
}

// ============================================================
// About modal
// ============================================================
function fmtBytes(n) {
  if (n == null) return "—";
  if (n >= 1024 * 1024 * 1024) return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

async function showAbout() {
  const overlay = q("aboutOverlay");
  const body = q("aboutBody");
  body.innerHTML = `<div class="muted">${escapeHtml(t("about.loading"))}</div>`;
  overlay.hidden = false;

  try {
    const info = await fetchJson("/api/info");
    const cfg = info.config || {};
    const rt = info.runtime || {};
    body.innerHTML = `
      <div>
        <span class="about-version-pill">${escapeHtml(info.name)} v${escapeHtml(info.version)}</span>
      </div>
      <p class="about-description">${escapeHtml(info.description || "")}</p>

      <div class="about-section">
        <h3>${escapeHtml(t("about.environment"))}</h3>
        <dl class="about-grid">
          <dt>${escapeHtml(t("about.python"))}</dt><dd>${escapeHtml(info.python || "?")}</dd>
          <dt>${escapeHtml(t("about.platform"))}</dt><dd>${escapeHtml(info.platform || "?")}</dd>
        </dl>
      </div>

      <div class="about-section">
        <h3>${escapeHtml(t("about.upload_limits"))}</h3>
        <dl class="about-grid">
          <dt>${escapeHtml(t("about.per_file"))}</dt><dd>${fmtBytes(cfg.max_upload_bytes)}</dd>
          <dt>${escapeHtml(t("about.files_at_once"))}</dt><dd>${cfg.max_upload_files ?? "?"}</dd>
          <dt>${escapeHtml(t("about.total_at_once"))}</dt><dd>${fmtBytes(cfg.max_upload_total_bytes)}</dd>
          <dt>${escapeHtml(t("about.flow_cache"))}</dt><dd>${cfg.flow_cache_max_entries ?? "?"} ${escapeHtml(t("about.flow_cache_unit"))}</dd>
          <dt>${escapeHtml(t("about.state_dir"))}</dt><dd>${escapeHtml(cfg.state_dir || "?")}</dd>
        </dl>
      </div>

      <div class="about-section">
        <h3>${escapeHtml(t("about.runtime"))}</h3>
        <dl class="about-grid">
          <dt>${escapeHtml(t("about.captures_loaded"))}</dt><dd>${rt.captures_loaded ?? 0}</dd>
          <dt>${escapeHtml(t("about.flow_cache_size"))}</dt><dd>${rt.flow_cache_size ?? 0}</dd>
        </dl>
      </div>
    `;
  } catch (err) {
    body.innerHTML = `<div class="muted">${escapeHtml(t("about.load_failed", { msg: err.message }))}</div>`;
  }
}

function hideAbout() {
  q("aboutOverlay").hidden = true;
}

function wireAbout() {
  q("brandButton").addEventListener("click", () => showAbout().catch(toastError));
  q("aboutClose").addEventListener("click", hideAbout);
  q("aboutOverlay").addEventListener("click", (ev) => {
    // Click on backdrop (not the card) closes the modal.
    if (ev.target.id === "aboutOverlay") hideAbout();
  });
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && !q("aboutOverlay").hidden) {
      ev.preventDefault();
      hideAbout();
    }
  });
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
    else if (ev.key.toLowerCase() === "g") {
      ev.preventDefault();
      const inp = q("flowJumpSeq");
      inp.focus();
      inp.select();
    }
  });
}

function _updateDetailLabels() {
  if (!detailPanel) return;
  detailPanel.labels = {
    loading: t("flow.causal_loading"),
    error: t("flow.causal_error"),
    empty: t("flow.causal_empty"),
  };
}

function _updateLangSwitchUI() {
  const cur = getLanguage();
  for (const btn of $$(".lang-option")) {
    btn.classList.toggle("active", btn.dataset.lang === cur);
    btn.setAttribute("aria-pressed", btn.dataset.lang === cur ? "true" : "false");
  }
}

function wireLanguage() {
  for (const btn of $$(".lang-option")) {
    btn.addEventListener("click", () => {
      const lang = btn.dataset.lang;
      setLanguage(lang);
    });
  }
  _updateLangSwitchUI();
  // After every language switch: re-render anything that doesn't live in
  // [data-i18n] attributes (sidebar session pills, flow stats, sessions
  // match counter, capture-status text, deep tables — those are rebuilt
  // when the relevant data is re-fetched, so we also refresh the status text
  // explicitly here).
  onLanguageChange(() => {
    _updateLangSwitchUI();
    // Capture-status text is set imperatively in JS — re-apply it via the
    // last-known status kind. We track it on the element itself.
    const dot = q("captureStatus").querySelector(".status-dot");
    const txt = q("captureStatus").querySelector(".status-text");
    const kindClass = [...dot.classList].find((c) => c.startsWith("status-") && c !== "status-dot");
    const kind = kindClass ? kindClass.slice("status-".length) : "empty";
    const statusKey = {
      empty: "status.empty",
      loading: "status.loading",
      ready: "status.ready",
      error: "status.error",
    }[kind];
    if (statusKey) txt.textContent = t(statusKey);
    // Re-render sessions sidebar if data is loaded.
    if (_sessionsData.length) renderSidebarSessions(_sessionsData);
    if (_sessionsData.length || _runsData.length) applySessionsFilter();
    // Re-render flow stats label + viewport rows if loaded.
    if (flowView && flowView.events.length) {
      flowView.stats.textContent = flowView.statsFormatter({
        loaded: flowView.events.length,
        total: flowView.total,
      });
      // Drop active row DOM so renderVirtual rebuilds them with the new
      // contentLocalizer. inner.innerHTML cleared, active map cleared.
      flowView.active.clear();
      flowView.inner.innerHTML = "";
      flowView.renderVirtual();
      // Refresh detail JSON (active selection) — its content is JSON-stringified
      // and may include localised fields next time user clicks. The static
      // JSON dump itself is server-generated raw event so it intentionally
      // stays in English (acts as machine-readable detail).
    }
  });
}

// ============================================================
// Boot
// ============================================================
function boot() {
  initI18n();
  wireUpload();
  wireTabs();
  wireFilters();
  wirePackets();
  wireStream();
  wireFlow();
  wireErrors();
  wireSessions();
  wireDeep();
  wireAbout();
  wireLanguage();
  wireKeyboard();
  setStatus("empty", t("status.empty"));
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
