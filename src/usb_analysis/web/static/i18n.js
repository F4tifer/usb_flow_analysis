/**
 * Tiny i18n module — supports Czech (cs) and English (en).
 *
 * Behaviour:
 *  - First visit: pick language from `localStorage` if set, else from
 *    `navigator.languages` (cs/sk → "cs", anything else → "en"). Browser
 *    setting wins over geographic guessing.
 *  - User toggle is persisted to localStorage so next visit honours choice.
 *  - `t(key)` returns the translated string; falls back to the key itself
 *    so a missing translation is visible at a glance during development.
 *  - `applyTranslations()` walks the DOM and updates:
 *       [data-i18n]              → textContent
 *       [data-i18n-html]         → innerHTML (use sparingly, only for trusted authored content)
 *       [data-i18n-placeholder]  → placeholder attribute
 *       [data-i18n-title]        → title attribute
 *       [data-i18n-aria-label]   → aria-label attribute
 *       [data-i18n-block="cs"]   → hidden unless current lang is cs
 *       [data-i18n-block="en"]   → hidden unless current lang is en
 *
 *  Listeners can subscribe via `onLanguageChange(fn)` to re-render dynamic
 *  content (e.g. table rows built in JS).
 */

export const SUPPORTED_LANGS = ["cs", "en"];
const STORAGE_KEY = "usb-analysis-lang";

const TRANSLATIONS = {
  cs: {
    // ───────── Header / app chrome ─────────
    "app.title": "USB Analysis",
    "app.about_tooltip": "O aplikaci",
    "app.lang_switch_tooltip": "Přepnout jazyk",
    "status.empty": "Žádný capture nenahrán",
    "status.uploading": "Nahrávám…",
    "status.loading": "Načítám…",
    "status.ready": "Capture připraven",
    "status.error": "Capture nedostupný — nahrajte znovu",
    "status.deep_running": "Spouštím hloubkovou analýzu…",
    "status.deep_done": "Deep analýza hotová",
    "status.deep_failed": "Deep selhala",
    "badge.critical_title": "Kritické události",
    "badge.warning_title": "Varování",
    "badge.info_title": "Informativní události",

    // ───────── Sidebar ─────────
    "sidebar.source": "Zdroj",
    "sidebar.upload_button": "Nahrát PCAP soubory",
    "sidebar.upload_hint": "nebo přetáhni sem",
    "sidebar.path_summary": "Lokální cesta na serveru",
    "sidebar.path_placeholder": "/cesta/trace.pcap00",
    "sidebar.path_load": "Načíst",
    "sidebar.filters": "Filtry",
    "sidebar.filters_tooltip": "Filtry se aplikují na pakety i flow",
    "sidebar.bus": "bus",
    "sidebar.device": "device",
    "sidebar.endpoint": "endpoint",
    "sidebar.filter_apply": "Aplikovat filtry",
    "sidebar.filter_clear": "Vymazat filtry",
    "sidebar.device_sessions": "Device sessions",
    "sidebar.shortcuts": "Klávesové zkratky",
    "sidebar.shortcut_move": "pohyb ve flow",
    "sidebar.shortcut_jump": "rychlý skok",
    "sidebar.shortcut_paired": "skok na párovanou událost",
    "sidebar.shortcut_goto": "skok na seq číslo",
    "sidebar.shortcut_history": "historie",
    "sidebar.shortcut_tabs": "přepnutí záložky",

    // ───────── Tabs ─────────
    "tab.overview": "Přehled",
    "tab.packets": "Pakety",
    "tab.stream": "Stream",
    "tab.stream_suffix": "(ASCII)",
    "tab.flow": "Flow analyzer",
    "tab.errors": "Errors",
    "tab.sessions": "Sessions",
    "tab.deep": "Deep analysis",
    "tab.export": "Export",
    "tab.help": "Nápověda",

    // ───────── Overview ─────────
    "overview.empty_title": "Začněte nahráním PCAP souboru",
    "overview.empty_hint": "Použijte nahrávací tlačítko vlevo nebo přetáhněte soubor sem.",
    "metric.packets": "Pakety",
    "metric.duration": "Doba trvání",
    "metric.sessions": "Sessions",
    "metric.runs": "Runs",
    "metric.critical": "Critical",
    "metric.warning": "Warning",
    "overview.time_window": "Časové okno",
    "overview.devices": "Zařízení",
    "overview.devices_empty": "žádná zařízení",
    "overview.distribution": "Rozdělení přenosů a událostí",
    "overview.transfer_types": "Transfer types",
    "overview.event_types": "Event types",
    "overview.dist_empty": "žádné",
    "overview.time_start": "Start",
    "overview.time_end": "End",

    // ───────── Packets ─────────
    "packets.offset": "offset",
    "packets.limit": "limit",
    "packets.load": "Načíst",
    "packets.prev": "← stránka",
    "packets.next": "stránka →",
    "packets.detail_title": "Detail paketu",
    "packets.detail_placeholder": "Vyber řádek…",
    "packets.col.ev": "ev",
    "packets.col.xfer": "xfer",
    "packets.col.payload": "payload",
    "packets.col.trezor": "trezor",

    // ───────── Stream ─────────
    "stream.load": "Načíst stream",
    "stream.hint": "Wireshark-like „Follow stream“ — ASCII překlad bulk komunikace",
    "stream.placeholder": "Klikni na „Načíst stream“…",
    "stream.empty": "(stream je prázdný)",

    // ───────── Flow analyzer ─────────
    "flow.severity": "Severity",
    "flow.severity.all": "ALL (vše)",
    "flow.severity.info": "info+",
    "flow.severity.warning": "warning+",
    "flow.severity.critical": "critical",
    "flow.direction": "Direction",
    "flow.direction.all": "vše",
    "flow.run": "Run",
    "flow.run_placeholder": "vše",
    "flow.search": "Search",
    "flow.search_placeholder": "ERROR, DN/DP…",
    "flow.jump_label": "Skoč na #",
    "flow.jump_placeholder": "např. 423",
    "flow.jump_tooltip": "Skoč na konkrétní seq číslo události (Enter)",
    "flow.jump_button_tooltip": "Skoč na zadané seq",
    "flow.back_tooltip": "Zpět (Alt+←)",
    "flow.forward_tooltip": "Vpřed (Alt+→)",
    "flow.load": "Načíst",
    "flow.legend.internal": "INTERNAL",
    "flow.legend.warning": "warning",
    "flow.legend.critical": "critical",
    "flow.detail_title": "Detail události",
    "flow.causal_title": "Kauzální kontext",
    "flow.causal_empty": "Bez kauzálních kandidátů.",
    "flow.causal_loading": "Načítám kontext...",
    "flow.causal_error": "Kontext se nepodařilo načíst.",
    "flow.timeline_hint": "Klikni do timelinu pro skok na úsek.",
    "flow.stats_format": "zobrazeno {loaded} / {total}",

    // ───────── Errors ─────────
    "errors.min_severity": "Min severity",
    "errors.layer": "Layer",
    "errors.layer.all": "vše",
    "errors.layer.transport": "transport",
    "errors.layer.connection": "connection",
    "errors.layer.protocol": "protocol",
    "errors.layer.application": "application",
    "errors.layer.timing": "timing",
    "errors.load": "Načíst chyby",
    "errors.empty_hint": "Klikni na „Načíst chyby“ po nahrání capture.",
    "errors.no_match": "Žádné chyby pro zvolené filtry.",
    "errors.col.layer": "layer",
    "errors.col.severity": "severity",
    "errors.col.type": "type",
    "errors.col.description": "description",
    "errors.col.causal": "causal hints",

    // ───────── Sessions ─────────
    "sessions.load": "Načíst sessions a runy",
    "sessions.search_label": "Hledat DUT SN",
    "sessions.search_case_note": "(case-sensitive)",
    "sessions.search_placeholder": "část SN nebo /regex/ — rozlišuje velikost písmen",
    "sessions.search_clear_tooltip": "Vymazat hledání",
    "sessions.usb_sessions": "USB sessions",
    "sessions.usb_sessions_sub": "(per bus/device)",
    "sessions.usb_sessions_hint": "Hranice = změna (bus, device_address). Tester serial je z `OK …` odpovědí, DUT serials z `checked-otp-device-sn-write`.",
    "sessions.test_runs": "Test runs",
    "sessions.test_runs_sub": "(jednotlivé HW kusy)",
    "sessions.test_runs_hint": "Každý run programuje jeden DUT. DUT SN = první argument příkazu `checked-otp-device-sn-write` v daném runu.",
    "sessions.col.tester_sn": "tester SN",
    "sessions.col.dut_sn": "DUT SN(s)",
    "sessions.col.dut_sn_single": "DUT SN",
    "sessions.col.start_seq": "start seq",
    "sessions.col.end_seq": "end seq",
    "sessions.col.events": "events",
    "sessions.col.start_ts": "start ts",
    "sessions.col.duration": "doba",
    "sessions.col.run": "run",
    "sessions.col.cmds": "cmds",
    "sessions.col.errors_short": "errors",
    "sessions.col.completeness": "completeness",
    "sessions.empty_sessions": "Žádná session neobsahuje hledaný DUT SN.",
    "sessions.empty_runs": "Žádný run neobsahuje hledaný DUT SN.",
    "sessions.count_format_empty": "{sessions} sessions · {runs} runů",
    "sessions.count_format_match": "{ms}/{ts} sessions · {mr}/{tr} runů odpovídá",
    "sessions.pill_dut": "DUT",
    "sessions.pill_tester": "tester",
    "sessions.pill_events": "eventů",
    "sessions.pill_no_dut": "—",
    "sessions.pill_many_duts": "{n} DUTs",
    "sessions.no_sessions_match": "Žádná session neobsahuje hledaný DUT SN.",

    // ───────── Deep ─────────
    "deep.run_button": "Spustit hloubkovou analýzu",
    "deep.hint": "Segmentace, baseline scoring, mining pravidel",
    "deep.summary": "Souhrn",
    "deep.findings": "Top anomálie",
    "deep.rules": "Návrhy pravidel",
    "deep.col.score": "score",
    "deep.col.cmd": "cmd",
    "deep.col.outcome": "outcome",
    "deep.col.run": "run",
    "deep.col.latency": "latency",
    "deep.col.reasons": "reasons",
    "deep.col.rule": "rule",
    "deep.col.conf": "conf",
    "deep.col.support": "support",
    "deep.col.popis": "popis",
    "deep.col.akce": "akce",

    // Rule descriptions (Deep analysis → Rule candidates). The server sends
    // canonical English text + the rule_id; UI replaces description via
    // `rule.<rule_id>` lookup. Suggested actions translated via `action.*`.
    "rule.incomplete-segment-timeout": "Příkazy bez finální OK/ERROR odpovědi.",
    "rule.error-outside-crc-enable": "ERROR mimo očekávaný command crc-enable.",
    "rule.retry-storm": "Stejný command opakován v sousedních segmentech.",
    "rule.high-score-anomaly-cluster": "Shluk segmentů s vysokým anomaly score.",
    "action.investigate": "prošetřit",
    "action.alert": "upozornit",

    // Anomaly-finding reasons (Deep analysis → Top anomalies). Server emits
    // canonical English strings (scorer.py); UI translates via key match.
    "reason.unknown_command": "neznámý příkaz v baseline",
    "reason.unexpected_outcome": "neočekávaný outcome",
    "reason.latency_spike": "vyšší latence ({mad} MAD)",
    "reason.unusual_run_position": "neobvyklá pozice v runu",
    "reason.response_line_count_spike": "neobvyklý počet řádků odpovědi",
    "reason.high_anomaly": "vysoké anomaly skóre",

    // Causal hints — server emits canonical English (causal.py); UI maps the
    // exact strings via these keys. Patterns with `{cmd}` are interpolated.
    "causal.timeout_before_error": "Timeout na příkazu '{cmd}' těsně před chybou mohl rozbít stav zařízení.",
    "causal.usb_error_before": "USB chyba předcházela problému — možné DN/DP selhání fyzické vrstvy.",
    "causal.incomplete_segment_before": "Nedokončený segment dříve mohl způsobit dominový efekt.",
    "causal.reconnect_before": "Reconnect předcházel problému — zařízení mohlo projít resetem.",
    "causal.error_chain": "Předchozí ERROR naznačuje řetězení chyb.",

    // Flow event content — server emits canonical English; UI maps via regex.
    // Parameter placeholders: {cmd} command name, {ms} milliseconds, {urb} urb id,
    // {bus}/{dev} bus/device, {tester} tester serial, {prev} previous serial.
    "content.incomplete_chunked_device_change": "Nedokončený segment ({cmd}) — chunked, změna zařízení",
    "content.incomplete_device_change": "Nedokončený segment ({cmd}) — změna zařízení",
    "content.incomplete_after": "Nedokončený segment po {cmd}",
    "content.incomplete_new_cmd": "Nový příkaz před uzavřením předchozího: {cmd}",
    "content.device_change_full": "Změna zařízení: bus {bus}/dev {dev} (tester {tester}) — předchozí tester: {prev}",
    "content.device_change_new_only": "Změna zařízení: bus {bus}/dev {dev} (tester {tester})",
    "content.device_change_prev_only": "Změna zařízení: bus {bus}/dev {dev} — předchozí tester: {prev}",
    "content.device_change_bare": "Změna zařízení: bus {bus}/dev {dev}",
    "content.urb_no_complete": "URB {urb} submit bez complete",
    "content.timeout_on": "Timeout {ms}ms na {cmd}",
    "content.reconnect_after_gap": "Reconnect po delší mezeře",
    "content.chunked_awaiting_suffix": "[chunked, čekám…]",

    // Detector messages (ErrorEvent.description) — server EN canonical.
    "detector.device_reconnect": "Detekován reconnect zařízení",
    "detector.missing_crc": "Chybí CRC u {cmd}",
    "detector.crc_mismatch": "CRC mismatch u {cmd}",
    "detector.timing": "Latence {ms}ms u {cmd}",
    "detector.timing_low": "Podezřele nízká latence {ms}ms u {cmd}",

    // ───────── Export ─────────
    "export.title": "Stáhnout flow analýzu",
    "export.hint": "Stáhne se aktuálně nahraný capture (a všechny jeho sessions).",
    "export.json_desc": "Kompletní stream + stats + sessions",
    "export.csv_desc": "Tabulka eventů pro spreadsheet",
    "export.html_desc": "Standalone náhled pro sdílení",
    "export.junit_desc": "CI integrace (Jenkins, GitLab…)",

    // ───────── About modal ─────────
    "about.title": "O aplikaci",
    "about.environment": "Prostředí",
    "about.python": "Python",
    "about.platform": "Platforma",
    "about.upload_limits": "Limity uploadu",
    "about.per_file": "Per soubor",
    "about.files_at_once": "Souborů najednou",
    "about.total_at_once": "Celkem najednou",
    "about.flow_cache": "Flow cache",
    "about.flow_cache_unit": "záznamů (LRU)",
    "about.state_dir": "State dir",
    "about.runtime": "Aktuální stav",
    "about.captures_loaded": "Captures v paměti",
    "about.flow_cache_size": "Cachované flow",
    "about.close": "Zavřít",
    "about.loading": "Načítám…",
    "about.load_failed": "Nepodařilo se načíst info: {msg}",

    // ───────── Loading overlay ─────────
    "loading.default": "Načítám…",
    "loading.uploading": "Nahrávám PCAP",
    "loading.analyzing": "Analyzuji obsah…",
    "loading.deep": "Hluboká analýza",
    "loading.deep_detail": "(může chvíli trvat)",
    "loading.deep_progress": "Segmentace + scoring + mining pravidel",
    "loading.search": "Hledám \"{term}\"",
    "loading.jump": "Skok na seq #{seq}",
    "loading.events_progress": "{loaded} / {total} eventů",
    "loading.flow_title": "Analyzuji flow",
    "loading.flow_detail": "Build flow stream + causal + detectors",
    "loading.packets": "Načítám pakety",
    "loading.stream": "Načítám stream",
    "loading.stream_detail": "ASCII překlad bulk komunikace",
    "loading.errors": "Načítám chyby",
    "loading.sessions": "Načítám sessions a runy",
    "loading.overview": "Načítám přehled",
    "loading.overview_detail": "Souhrn, sessions, severity counts",

    // ───────── Toasts / errors ─────────
    "toast.invalid_seq": "Zadej platné seq číslo (kladné celé)",
    "toast.seq_not_in_filter": "Seq #{seq} mimo aktuální filtr/rozsah",
    "toast.capture_lost": "Server ztratil aktuální capture (pravděpodobně po restartu). Nahrajte PCAP znovu.",
    "toast.upload_failed": "Upload selhal",
    "toast.capture_expired": "Capture vypršel — server ho už nezná. Nahrajte PCAP znovu.",
    "toast.upload_no_pcap": "Nahrajte PCAP nejdřív.",
    "toast.partial_metrics": "Některé metriky se nepodařilo načíst — viz konzole.",
    "toast.api_timeout": "Timeout při volání API ({secs}s): {url}",
    "toast.using_path": "Použita lokální cesta",
    "toast.captures_uploaded": "{n} captures nahráno",

    // ───────── Misc ─────────
    "misc.no_devices": "žádná zařízení",
    "misc.unknown": "?",
    "misc.dash": "—",
    "misc.bytes": "B",
    "misc.kb": "KB",
    "misc.mb": "MB",
    "misc.gb": "GB",
    "misc.ms": "ms",
    "misc.sec": "s",
  },

  en: {
    // ───────── Header / app chrome ─────────
    "app.title": "USB Analysis",
    "app.about_tooltip": "About the application",
    "app.lang_switch_tooltip": "Switch language",
    "status.empty": "No capture loaded",
    "status.uploading": "Uploading…",
    "status.loading": "Loading…",
    "status.ready": "Capture ready",
    "status.error": "Capture unavailable — please re-upload",
    "status.deep_running": "Running deep analysis…",
    "status.deep_done": "Deep analysis done",
    "status.deep_failed": "Deep analysis failed",
    "badge.critical_title": "Critical events",
    "badge.warning_title": "Warnings",
    "badge.info_title": "Info events",

    // ───────── Sidebar ─────────
    "sidebar.source": "Source",
    "sidebar.upload_button": "Upload PCAP files",
    "sidebar.upload_hint": "or drop them here",
    "sidebar.path_summary": "Local path on the server",
    "sidebar.path_placeholder": "/path/to/trace.pcap00",
    "sidebar.path_load": "Load",
    "sidebar.filters": "Filters",
    "sidebar.filters_tooltip": "Filters apply to packets and flow",
    "sidebar.bus": "bus",
    "sidebar.device": "device",
    "sidebar.endpoint": "endpoint",
    "sidebar.filter_apply": "Apply filters",
    "sidebar.filter_clear": "Clear filters",
    "sidebar.device_sessions": "Device sessions",
    "sidebar.shortcuts": "Keyboard shortcuts",
    "sidebar.shortcut_move": "move within flow",
    "sidebar.shortcut_jump": "fast jump",
    "sidebar.shortcut_paired": "jump to paired event",
    "sidebar.shortcut_goto": "go to seq number",
    "sidebar.shortcut_history": "history",
    "sidebar.shortcut_tabs": "switch tab",

    // ───────── Tabs ─────────
    "tab.overview": "Overview",
    "tab.packets": "Packets",
    "tab.stream": "Stream",
    "tab.stream_suffix": "(ASCII)",
    "tab.flow": "Flow analyzer",
    "tab.errors": "Errors",
    "tab.sessions": "Sessions",
    "tab.deep": "Deep analysis",
    "tab.export": "Export",
    "tab.help": "Help",

    // ───────── Overview ─────────
    "overview.empty_title": "Start by uploading a PCAP file",
    "overview.empty_hint": "Use the upload button on the left or drop a file here.",
    "metric.packets": "Packets",
    "metric.duration": "Duration",
    "metric.sessions": "Sessions",
    "metric.runs": "Runs",
    "metric.critical": "Critical",
    "metric.warning": "Warning",
    "overview.time_window": "Time window",
    "overview.devices": "Devices",
    "overview.devices_empty": "no devices",
    "overview.distribution": "Transfer / event distribution",
    "overview.transfer_types": "Transfer types",
    "overview.event_types": "Event types",
    "overview.dist_empty": "none",
    "overview.time_start": "Start",
    "overview.time_end": "End",

    // ───────── Packets ─────────
    "packets.offset": "offset",
    "packets.limit": "limit",
    "packets.load": "Load",
    "packets.prev": "← page",
    "packets.next": "page →",
    "packets.detail_title": "Packet detail",
    "packets.detail_placeholder": "Select a row…",
    "packets.col.ev": "ev",
    "packets.col.xfer": "xfer",
    "packets.col.payload": "payload",
    "packets.col.trezor": "trezor",

    // ───────── Stream ─────────
    "stream.load": "Load stream",
    "stream.hint": "Wireshark-like \"Follow stream\" — ASCII translation of bulk communication",
    "stream.placeholder": "Click \"Load stream\"…",
    "stream.empty": "(stream is empty)",

    // ───────── Flow analyzer ─────────
    "flow.severity": "Severity",
    "flow.severity.all": "ALL",
    "flow.severity.info": "info+",
    "flow.severity.warning": "warning+",
    "flow.severity.critical": "critical",
    "flow.direction": "Direction",
    "flow.direction.all": "all",
    "flow.run": "Run",
    "flow.run_placeholder": "all",
    "flow.search": "Search",
    "flow.search_placeholder": "ERROR, DN/DP…",
    "flow.jump_label": "Go to #",
    "flow.jump_placeholder": "e.g. 423",
    "flow.jump_tooltip": "Jump to a specific seq number (Enter)",
    "flow.jump_button_tooltip": "Jump to entered seq",
    "flow.back_tooltip": "Back (Alt+←)",
    "flow.forward_tooltip": "Forward (Alt+→)",
    "flow.load": "Load",
    "flow.legend.internal": "INTERNAL",
    "flow.legend.warning": "warning",
    "flow.legend.critical": "critical",
    "flow.detail_title": "Event detail",
    "flow.causal_title": "Causal context",
    "flow.causal_empty": "No causal candidates.",
    "flow.causal_loading": "Loading context...",
    "flow.causal_error": "Could not load context.",
    "flow.timeline_hint": "Click into the timeline to jump to a time slice.",
    "flow.stats_format": "shown {loaded} / {total}",

    // ───────── Errors ─────────
    "errors.min_severity": "Min severity",
    "errors.layer": "Layer",
    "errors.layer.all": "all",
    "errors.layer.transport": "transport",
    "errors.layer.connection": "connection",
    "errors.layer.protocol": "protocol",
    "errors.layer.application": "application",
    "errors.layer.timing": "timing",
    "errors.load": "Load errors",
    "errors.empty_hint": "Click \"Load errors\" once a capture is uploaded.",
    "errors.no_match": "No errors match the selected filters.",
    "errors.col.layer": "layer",
    "errors.col.severity": "severity",
    "errors.col.type": "type",
    "errors.col.description": "description",
    "errors.col.causal": "causal hints",

    // ───────── Sessions ─────────
    "sessions.load": "Load sessions and runs",
    "sessions.search_label": "Search DUT SN",
    "sessions.search_case_note": "(case-sensitive)",
    "sessions.search_placeholder": "SN substring or /regex/ — case-sensitive",
    "sessions.search_clear_tooltip": "Clear search",
    "sessions.usb_sessions": "USB sessions",
    "sessions.usb_sessions_sub": "(per bus/device)",
    "sessions.usb_sessions_hint": "Boundary = change of (bus, device_address). Tester serial comes from `OK …` responses, DUT serials from `checked-otp-device-sn-write`.",
    "sessions.test_runs": "Test runs",
    "sessions.test_runs_sub": "(individual HW units)",
    "sessions.test_runs_hint": "Each run programs one DUT. DUT SN = first argument of `checked-otp-device-sn-write` in that run.",
    "sessions.col.tester_sn": "tester SN",
    "sessions.col.dut_sn": "DUT SN(s)",
    "sessions.col.dut_sn_single": "DUT SN",
    "sessions.col.start_seq": "start seq",
    "sessions.col.end_seq": "end seq",
    "sessions.col.events": "events",
    "sessions.col.start_ts": "start ts",
    "sessions.col.duration": "duration",
    "sessions.col.run": "run",
    "sessions.col.cmds": "cmds",
    "sessions.col.errors_short": "errors",
    "sessions.col.completeness": "completeness",
    "sessions.empty_sessions": "No session contains the searched DUT SN.",
    "sessions.empty_runs": "No run contains the searched DUT SN.",
    "sessions.count_format_empty": "{sessions} sessions · {runs} runs",
    "sessions.count_format_match": "{ms}/{ts} sessions · {mr}/{tr} runs match",
    "sessions.pill_dut": "DUT",
    "sessions.pill_tester": "tester",
    "sessions.pill_events": "events",
    "sessions.pill_no_dut": "—",
    "sessions.pill_many_duts": "{n} DUTs",
    "sessions.no_sessions_match": "No session contains the searched DUT SN.",

    // ───────── Deep ─────────
    "deep.run_button": "Run deep analysis",
    "deep.hint": "Segmentation, baseline scoring, rule mining",
    "deep.summary": "Summary",
    "deep.findings": "Top anomalies",
    "deep.rules": "Rule candidates",
    "deep.col.score": "score",
    "deep.col.cmd": "cmd",
    "deep.col.outcome": "outcome",
    "deep.col.run": "run",
    "deep.col.latency": "latency",
    "deep.col.reasons": "reasons",
    "deep.col.rule": "rule",
    "deep.col.conf": "conf",
    "deep.col.support": "support",
    "deep.col.popis": "description",
    "deep.col.akce": "action",

    // Rule descriptions / suggested actions (EN).
    "rule.incomplete-segment-timeout": "Commands without a final OK/ERROR response.",
    "rule.error-outside-crc-enable": "ERROR outside the expected crc-enable command.",
    "rule.retry-storm": "Same command repeated in adjacent segments.",
    "rule.high-score-anomaly-cluster": "Cluster of segments with a high anomaly score.",
    "action.investigate": "investigate",
    "action.alert": "alert",

    // Anomaly-finding reasons (EN — server already emits English here).
    "reason.unknown_command": "unknown command for baseline",
    "reason.unexpected_outcome": "unexpected outcome",
    "reason.latency_spike": "latency spike ({mad} MAD)",
    "reason.unusual_run_position": "unusual run position",
    "reason.response_line_count_spike": "response line count spike",
    "reason.high_anomaly": "high anomaly score",

    // Causal hints (EN canonical, server emits these as-is).
    "causal.timeout_before_error": "Timeout on '{cmd}' just before the error may have corrupted device state.",
    "causal.usb_error_before": "USB error preceded the problem — possible DN/DP physical-layer fault.",
    "causal.incomplete_segment_before": "An incomplete segment earlier may have caused a domino effect.",
    "causal.reconnect_before": "A reconnect preceded the problem — the device may have gone through a reset.",
    "causal.error_chain": "Previous ERROR suggests an error chain.",

    // Flow event content templates (EN canonical).
    "content.incomplete_chunked_device_change": "Incomplete segment ({cmd}) — chunked, device change",
    "content.incomplete_device_change": "Incomplete segment ({cmd}) — device change",
    "content.incomplete_after": "Incomplete segment after {cmd}",
    "content.incomplete_new_cmd": "New command before previous was closed: {cmd}",
    "content.device_change_full": "Device change: bus {bus}/dev {dev} (tester {tester}) — previous tester: {prev}",
    "content.device_change_new_only": "Device change: bus {bus}/dev {dev} (tester {tester})",
    "content.device_change_prev_only": "Device change: bus {bus}/dev {dev} — previous tester: {prev}",
    "content.device_change_bare": "Device change: bus {bus}/dev {dev}",
    "content.urb_no_complete": "URB {urb} submit without complete",
    "content.timeout_on": "Timeout {ms}ms on {cmd}",
    "content.reconnect_after_gap": "Reconnect after a longer gap",
    "content.chunked_awaiting_suffix": "[chunked, awaiting…]",

    // Detector messages (ErrorEvent.description).
    "detector.device_reconnect": "Device reconnect",
    "detector.missing_crc": "Missing CRC on {cmd}",
    "detector.crc_mismatch": "CRC mismatch on {cmd}",
    "detector.timing": "Latency {ms}ms on {cmd}",
    "detector.timing_low": "Suspiciously low latency {ms}ms on {cmd}",

    // ───────── Export ─────────
    "export.title": "Download flow analysis",
    "export.hint": "Exports the currently loaded capture (and all of its sessions).",
    "export.json_desc": "Complete stream + stats + sessions",
    "export.csv_desc": "Event table for spreadsheets",
    "export.html_desc": "Standalone preview for sharing",
    "export.junit_desc": "CI integration (Jenkins, GitLab…)",

    // ───────── About modal ─────────
    "about.title": "About the application",
    "about.environment": "Environment",
    "about.python": "Python",
    "about.platform": "Platform",
    "about.upload_limits": "Upload limits",
    "about.per_file": "Per file",
    "about.files_at_once": "Files at once",
    "about.total_at_once": "Total at once",
    "about.flow_cache": "Flow cache",
    "about.flow_cache_unit": "entries (LRU)",
    "about.state_dir": "State dir",
    "about.runtime": "Runtime",
    "about.captures_loaded": "Captures in memory",
    "about.flow_cache_size": "Cached flows",
    "about.close": "Close",
    "about.loading": "Loading…",
    "about.load_failed": "Failed to load info: {msg}",

    // ───────── Loading overlay ─────────
    "loading.default": "Loading…",
    "loading.uploading": "Uploading PCAP",
    "loading.analyzing": "Analyzing content…",
    "loading.deep": "Deep analysis",
    "loading.deep_detail": "(may take a while)",
    "loading.deep_progress": "Segmentation + scoring + rule mining",
    "loading.search": "Searching \"{term}\"",
    "loading.jump": "Jump to seq #{seq}",
    "loading.events_progress": "{loaded} / {total} events",
    "loading.flow_title": "Analyzing flow",
    "loading.flow_detail": "Build flow stream + causal + detectors",
    "loading.packets": "Loading packets",
    "loading.stream": "Loading stream",
    "loading.stream_detail": "ASCII translation of bulk communication",
    "loading.errors": "Loading errors",
    "loading.sessions": "Loading sessions and runs",
    "loading.overview": "Loading overview",
    "loading.overview_detail": "Summary, sessions, severity counts",

    // ───────── Toasts / errors ─────────
    "toast.invalid_seq": "Enter a valid seq number (positive integer)",
    "toast.seq_not_in_filter": "Seq #{seq} is outside the current filter/range",
    "toast.capture_lost": "Server lost the current capture (likely after a restart). Please re-upload.",
    "toast.upload_failed": "Upload failed",
    "toast.capture_expired": "Capture expired — server no longer knows it. Please re-upload.",
    "toast.upload_no_pcap": "Upload a PCAP first.",
    "toast.partial_metrics": "Some metrics could not be loaded — see console.",
    "toast.api_timeout": "API timeout ({secs}s): {url}",
    "toast.using_path": "Using local path",
    "toast.captures_uploaded": "{n} captures uploaded",

    // ───────── Misc ─────────
    "misc.no_devices": "no devices",
    "misc.unknown": "?",
    "misc.dash": "—",
    "misc.bytes": "B",
    "misc.kb": "KB",
    "misc.mb": "MB",
    "misc.gb": "GB",
    "misc.ms": "ms",
    "misc.sec": "s",
  },
};

let _lang = "en";
const _listeners = [];

export function detectLanguage() {
  const stored = (() => { try { return localStorage.getItem(STORAGE_KEY); } catch { return null; } })();
  if (stored && SUPPORTED_LANGS.includes(stored)) return stored;
  const candidates = navigator.languages?.length ? navigator.languages : [navigator.language || "en"];
  for (const cand of candidates) {
    const lc = (cand || "").toLowerCase();
    if (lc.startsWith("cs") || lc.startsWith("sk")) return "cs";
    if (lc.startsWith("en")) return "en";
  }
  return "en";
}

export function getLanguage() {
  return _lang;
}

export function setLanguage(lang) {
  if (!SUPPORTED_LANGS.includes(lang) || lang === _lang) return;
  _lang = lang;
  try { localStorage.setItem(STORAGE_KEY, lang); } catch {}
  document.documentElement.lang = lang;
  applyTranslations();
  for (const fn of _listeners) {
    try { fn(lang); } catch (err) { console.error(err); }
  }
}

export function onLanguageChange(fn) {
  _listeners.push(fn);
  return () => {
    const i = _listeners.indexOf(fn);
    if (i >= 0) _listeners.splice(i, 1);
  };
}

export function t(key, params) {
  let s = TRANSLATIONS[_lang]?.[key];
  if (s == null) s = TRANSLATIONS.en[key] ?? key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
}

export function applyTranslations() {
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of document.querySelectorAll("[data-i18n-html]")) {
    el.innerHTML = t(el.dataset.i18nHtml);
  }
  for (const el of document.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  for (const el of document.querySelectorAll("[data-i18n-title]")) {
    el.title = t(el.dataset.i18nTitle);
  }
  for (const el of document.querySelectorAll("[data-i18n-aria-label]")) {
    el.setAttribute("aria-label", t(el.dataset.i18nAriaLabel));
  }
  for (const el of document.querySelectorAll("[data-i18n-block]")) {
    el.hidden = el.dataset.i18nBlock !== _lang;
  }
}

export function initI18n() {
  _lang = detectLanguage();
  document.documentElement.lang = _lang;
  applyTranslations();
}
