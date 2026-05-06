"""FastAPI app: summarize and paginated packet view."""

from __future__ import annotations

import os
import re as _re
import tempfile
import threading
import uuid
from collections import Counter, OrderedDict
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from usb_analysis.analysis.aggregator import aggregate_directory, aggregation_to_dict
from usb_analysis.analysis.causal import enrich_causal
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.detectors import detect_errors, errors_to_dict
from usb_analysis.analysis.engine import analyze_path
from usb_analysis.analysis.exporter import export_csv, export_html_report, export_json, export_junit_xml
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import iter_usb_packets
from usb_analysis.filters import matches
from usb_analysis.models import event_type_char, transfer_type_name
from usb_analysis.pipeline import ensure_mmap_link, iter_mmap_packets
from usb_analysis.flow_timeline import build_flow_timeline
from usb_analysis.serialization import packet_record
from usb_analysis.stream_text import build_text_stream
from usb_analysis.summary import build_summary
from usb_analysis.trezor import TrezorDecoder

HERE = Path(__file__).resolve().parent
STATIC_DIR = HERE / "static"

# Maximum upload size per file (bytes). Configurable via env var.
MAX_UPLOAD_BYTES = int(os.environ.get("USB_ANALYSIS_MAX_UPLOAD_BYTES", str(512 * 1024 * 1024)))
# Maximum number of cached flow analyses (LRU).
FLOW_CACHE_MAX_ENTRIES = int(os.environ.get("USB_ANALYSIS_FLOW_CACHE_MAX", "16"))
# Allowed character set for capture/device identifiers.
_DEVICE_ID_RE = _re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

CAPTURE_IDS: dict[str, Path] = {}
FLOW_CACHE: "OrderedDict[str, dict]" = OrderedDict()
SUPPRESSED_EVENT_TYPES: dict[str, str] = {}
_state_lock = threading.Lock()

app = FastAPI(title="usb-analysis")


def _safe_device_id(device: str) -> str:
    if not _DEVICE_ID_RE.match(device):
        raise HTTPException(status_code=400, detail="Invalid device identifier")
    return device


def _event_dict(e) -> dict:
    """Serialize a slots-based FlowEvent for JSON response."""
    return asdict(e)


def _flow_cache_key(paths: list[Path]) -> str:
    return "|".join(str(p) for p in paths)


def _get_flow_analysis(paths: list[Path]) -> dict:
    key = _flow_cache_key(paths)
    with _state_lock:
        if key in FLOW_CACHE:
            FLOW_CACHE.move_to_end(key)
            return FLOW_CACHE[key]
    cfg = AnalysisConfig()
    packets = list(iter_usb_packets(paths))
    stream = build_flow_stream(packets, cfg)
    enrich_causal(stream, cfg)
    errors = detect_errors(stream, cfg)
    payload = {"stream": stream, "errors": errors}
    with _state_lock:
        FLOW_CACHE[key] = payload
        FLOW_CACHE.move_to_end(key)
        while len(FLOW_CACHE) > FLOW_CACHE_MAX_ENTRIES:
            FLOW_CACHE.popitem(last=False)
    return payload


def _nonempty_query(s: str | None) -> str | None:
    if s is None:
        return None
    stripped = s.strip()
    return stripped if stripped else None


EMPTY_SUMMARY: dict[str, object] = {
    "capture_required": True,
    "path": None,
    "total_packets": 0,
    "time_start": None,
    "time_end": None,
    "duration_s": None,
    "devices": [],
    "transfer_types": {},
    "event_types": {},
}


def _resolve_capture_id(capture_id: str) -> Path:
    try:
        return CAPTURE_IDS[capture_id]
    except KeyError as e:
        raise HTTPException(status_code=404, detail=f"Unknown capture id: {capture_id}") from e


def resolve_captures(path: str | None, capture_id: str | None, capture_ids: str | None) -> list[Path]:
    paths: list[Path] = []
    if capture_ids:
        for cid in [x.strip() for x in capture_ids.split(",") if x.strip()]:
            paths.append(_resolve_capture_id(cid))
    if capture_id:
        paths.append(_resolve_capture_id(capture_id))
    if path:
        p = Path(path).expanduser().resolve(strict=False)
        if not p.is_file():
            raise HTTPException(status_code=404, detail=f"File not found: {p}")
        paths.append(p)
    if not paths:
        raise HTTPException(status_code=400, detail='Provide capture_id, capture_ids, or path')
    # de-duplicate while preserving order
    out: list[Path] = []
    seen = set()
    for p in paths:
        key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def resolve_capture(path: str | None, capture_id: str | None) -> Path:
    # backward-compatible helper where single capture is required
    caps = resolve_captures(path, capture_id, None)
    return caps[0]


def _ensure_all_mmap(paths: list[Path]) -> None:
    for p in paths:
        ensure_mmap_link(p)


def _build_summary_multi(
    paths: list[Path],
    *,
    bus: int | None,
    device: int | None,
    endpoint: int | None,
) -> dict:
    if len(paths) == 1:
        return build_summary(paths[0], bus=bus, device=device, endpoint=endpoint)

    total = 0
    devices: set[tuple[int, int]] = set()
    xfer_c: Counter[int] = Counter()
    event_c: Counter[str] = Counter()
    t_start = None
    t_end = None
    for p in paths:
        for pkt in iter_mmap_packets(p):
            if not matches(pkt, bus=bus, device=device, endpoint=endpoint):
                continue
            total += 1
            h = pkt.header
            devices.add((h.bus_id, h.device_address))
            xfer_c[h.transfer_type] += 1
            event_c[event_type_char(h.event_type) or f"0x{h.event_type:02x}"] += 1
            ts = pkt.pcap_ts_sec + pkt.pcap_ts_usec / 1_000_000.0
            t_start = ts if t_start is None or ts < t_start else t_start
            t_end = ts if t_end is None or ts > t_end else t_end
    return {
        "path": ",".join(str(p) for p in paths),
        "files_count": len(paths),
        "total_packets": total,
        "time_start": t_start,
        "time_end": t_end,
        "duration_s": (t_end - t_start) if t_start is not None and t_end is not None else None,
        "devices": [{"bus": b, "device": d} for b, d in sorted(devices)],
        "transfer_types": {transfer_type_name(k): v for k, v in sorted(xfer_c.items())},
        "event_types": dict(event_c),
    }


def _deep_result(path: str | None, capture_id: str | None, capture_ids: str | None) -> dict:
    pcs = resolve_captures(path, capture_id, capture_ids)
    _ensure_all_mmap(pcs)
    cfg = AnalysisConfig()
    return analyze_path(pcs, cfg=cfg, update_baseline=False)


@app.get("/api/summary")
def api_summary(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    bus: int | None = Query(default=None),
    device: int | None = Query(default=None),
    endpoint: int | None = Query(default=None),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return EMPTY_SUMMARY
    caps = resolve_captures(p, cid, cids)
    _ensure_all_mmap(caps)
    try:
        return _build_summary_multi(caps, bus=bus, device=device, endpoint=endpoint)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid or truncated PCAP: {e}") from e


@app.get("/api/packets")
def api_packets(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=500),
    bus: int | None = Query(default=None),
    device: int | None = Query(default=None),
    endpoint: int | None = Query(default=None),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {
            "capture_required": True,
            "offset": offset,
            "limit": limit,
            "returned": 0,
            "rows": [],
        }
    caps = resolve_captures(p, cid, cids)
    _ensure_all_mmap(caps)
    items: list[dict] = []
    shown = scanned = 0
    decoder = TrezorDecoder()

    try:
        for pcap in caps:
            for pkt in iter_mmap_packets(pcap):
                if not matches(pkt, bus=bus, device=device, endpoint=endpoint):
                    continue
                trezor = decoder.decode_packet(pkt)
                if scanned < offset:
                    scanned += 1
                    continue
                if shown >= limit:
                    break
                items.append(packet_record(pkt, trezor_decoded=trezor))
                shown += 1
                scanned += 1
            if shown >= limit:
                break
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid or truncated PCAP: {e}") from e

    return {"offset": offset, "limit": limit, "returned": len(items), "rows": items}


@app.get("/api/stream")
def api_stream(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    bus: int | None = Query(default=None),
    device: int | None = Query(default=None),
    endpoint: int | None = Query(default=None),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True, "offset": offset, "limit": limit, "returned": 0, "rows": []}

    caps = resolve_captures(p, cid, cids)
    _ensure_all_mmap(caps)
    selected = []
    for pcap in caps:
        for pkt in iter_mmap_packets(pcap):
            if matches(pkt, bus=bus, device=device, endpoint=endpoint):
                selected.append(pkt)
    rows = build_text_stream(selected)
    sliced = rows[offset : offset + limit]
    return {"offset": offset, "limit": limit, "returned": len(sliced), "rows": sliced}


@app.get("/api/flow")
def api_flow(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=5000),
    bus: int | None = Query(default=None),
    device: int | None = Query(default=None),
    endpoint: int | None = Query(default=None),
    gap_threshold_s: float = Query(
        default=2.0,
        ge=0.0,
        le=3600.0,
        description="Insert a gap row when pcap time between consecutive URBs exceeds this (0 disables).",
    ),
    bulk_only: bool = Query(default=False, description="Only Bulk transfers"),
):
    """Chronological USB flow with host↔device direction and optional long-idle gaps."""
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True, "offset": offset, "limit": limit, "returned": 0, "rows": []}

    caps = resolve_captures(p, cid, cids)
    _ensure_all_mmap(caps)
    selected: list = []
    try:
        for pcap in caps:
            for pkt in iter_mmap_packets(pcap):
                if matches(pkt, bus=bus, device=device, endpoint=endpoint):
                    selected.append(pkt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid or truncated PCAP: {e}") from e

    timeline = build_flow_timeline(
        selected, gap_threshold_s=gap_threshold_s, bulk_only=bulk_only
    )
    sliced = timeline[offset : offset + limit]
    return {
        "offset": offset,
        "limit": limit,
        "returned": len(sliced),
        "total_entries": len(timeline),
        "gap_threshold_s": gap_threshold_s,
        "bulk_only": bulk_only,
        "rows": sliced,
    }


@app.get("/api/flow/stream")
def api_flow_stream(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
    min_severity: str = Query(default="info"),
    direction: str | None = Query(default=None),
    event_class: str | None = Query(default=None),
    cmd_name: str | None = Query(default=None),
    from_seq: int = Query(default=1, ge=1),
    to_seq: int | None = Query(default=None, ge=1),
    run: int | None = Query(default=None, ge=0),
    # Accept the raw string so an empty value (legacy clients sending
    # `has_causal_hints=`) does not 422 the request — we coerce ourselves below.
    has_causal_hints: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=1, le=1000),
):
    causal_filter: bool | None
    raw = (has_causal_hints or "").strip().lower()
    if raw in {"true", "1", "yes"}:
        causal_filter = True
    elif raw in {"false", "0", "no"}:
        causal_filter = False
    else:
        causal_filter = None
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True, "events": [], "total": 0, "page": page, "stats": {}}
    caps = resolve_captures(p, cid, cids)
    data = _get_flow_analysis(caps)
    stream = data["stream"]
    sev_rank = {"ok": 0, "info": 1, "warning": 2, "critical": 3, "suppressed": -1}
    min_rank = sev_rank.get(min_severity, 1)
    events = []
    for e in stream.events:
        event_type = e.event_class
        sev = e.severity
        if event_type in SUPPRESSED_EVENT_TYPES:
            sev = "suppressed"
        if e.seq < from_seq:
            continue
        if to_seq is not None and e.seq > to_seq:
            continue
        if run is not None and e.run_index != run:
            continue
        if direction and e.direction != direction:
            continue
        if event_class and e.event_class != event_class:
            continue
        if cmd_name and (e.cmd_name or "") != cmd_name:
            continue
        if causal_filter is True and not e.causal_hints:
            continue
        if causal_filter is False and e.causal_hints:
            continue
        if sev_rank.get(sev, 0) < min_rank:
            continue
        row = _event_dict(e)
        row["severity"] = sev
        if sev == "suppressed":
            row["suppression_reason"] = SUPPRESSED_EVENT_TYPES[event_type]
        events.append(row)
    total = len(events)
    off = (page - 1) * page_size
    rows = events[off : off + page_size]
    return {"events": rows, "total": total, "page": page, "stats": asdict(stream.stats)}


@app.get("/api/flow/event/{seq}")
def api_flow_event(
    seq: int,
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    for e in stream.events:
        if e.seq == seq:
            return _event_dict(e)
    raise HTTPException(status_code=404, detail=f"Flow event {seq} not found")


@app.get("/api/flow/context/{seq}")
def api_flow_context(
    seq: int,
    before: int = Query(default=10, ge=0, le=500),
    after: int = Query(default=5, ge=0, le=500),
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    idx = next((i for i, e in enumerate(stream.events) if e.seq == seq), None)
    if idx is None:
        raise HTTPException(status_code=404, detail=f"Flow event {seq} not found")
    target = stream.events[idx]
    ctx = stream.events[max(0, idx - before) : idx + after + 1]
    causal = [e for e in stream.events if e.seq in target.causal_window]
    return {
        "target": _event_dict(target),
        "context": [_event_dict(e) for e in ctx],
        "causal_window": [_event_dict(e) for e in causal],
    }


@app.get("/api/flow/errors")
def api_flow_errors(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
    layer: str | None = Query(default=None),
    min_severity: str = Query(default="warning"),
    run: int | None = Query(default=None, ge=0),
):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    data = _get_flow_analysis(caps)
    errors = data["errors"]
    sev_rank = {"info": 1, "warning": 2, "critical": 3}
    min_rank = sev_rank.get(min_severity, 2)
    out = []
    stream = data["stream"]
    seq_to_run = {e.seq: e.run_index for e in stream.events}
    for e in errors:
        if layer and e.layer != layer:
            continue
        if sev_rank.get(e.severity, 1) < min_rank:
            continue
        if run is not None and not any(seq_to_run.get(s) == run for s in e.linked_flow_events):
            continue
        out.append(e)
    return {"rows": errors_to_dict(out), "returned": len(out)}


@app.get("/api/flow/runs")
def api_flow_runs(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    runs: dict[int, dict] = {}
    for e in stream.events:
        r = runs.setdefault(
            e.run_index,
            {
                "run_index": e.run_index,
                "start_seq": e.seq,
                "end_seq": e.seq,
                "ts_start": e.ts,
                "ts_end": e.ts,
                "cmd_count": 0,
                "error_count": 0,
            },
        )
        r["end_seq"] = e.seq
        r["ts_end"] = e.ts
        if e.event_class in {"command", "crc_probe"}:
            r["cmd_count"] += 1
        if e.severity in {"warning", "critical"}:
            r["error_count"] += 1
    rows = []
    for r in sorted(runs.values(), key=lambda x: x["run_index"]):
        dur = (r["ts_end"] - r["ts_start"]) * 1000.0
        comp = 100.0 if r["error_count"] == 0 else max(0.0, 100.0 - min(100.0, r["error_count"] * 10.0))
        rows.append({**r, "duration_ms": dur, "completeness_pct": comp})
    return {"rows": rows, "returned": len(rows)}


@app.get("/api/flow/run/{n}")
def api_flow_run(n: int, path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    rows = [_event_dict(e) for e in stream.events if e.run_index == n]
    return {"rows": rows, "returned": len(rows), "run_index": n}


@app.get("/api/flow/timeline")
def api_flow_timeline(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None), buckets: int = Query(default=120, ge=10, le=2000)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    if not stream.events:
        return {"buckets": []}
    ts0 = stream.events[0].ts
    ts1 = stream.events[-1].ts
    span = max(1e-9, ts1 - ts0)
    out = [{"ts": ts0 + span * i / buckets, "ok_count": 0, "warn_count": 0, "error_count": 0, "reconnect": 0} for i in range(buckets)]
    for e in stream.events:
        idx = min(buckets - 1, int((e.ts - ts0) / span * buckets))
        if e.severity == "critical":
            out[idx]["error_count"] += 1
        elif e.severity == "warning":
            out[idx]["warn_count"] += 1
        else:
            out[idx]["ok_count"] += 1
        if e.event_class == "reconnect":
            out[idx]["reconnect"] += 1
    return {"buckets": out}


@app.get("/api/flow/search")
def api_flow_search(
    q: str,
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    needle = q.lower()
    rows = [_event_dict(e) for e in stream.events if needle in (e.content or "").lower()][:limit]
    return {"rows": rows, "returned": len(rows)}


@app.get("/api/flow/completeness")
def api_flow_completeness(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    stream = _get_flow_analysis(caps)["stream"]
    return {"rows": stream.stats.run_completeness, "returned": len(stream.stats.run_completeness)}


@app.get("/api/aggregate")
def api_aggregate(path: str):
    report = aggregate_directory(path)
    return aggregation_to_dict(report)


@app.post("/api/flow/suppress")
def api_flow_suppress(payload: dict):
    event_type = str(payload.get("event_type", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    if not event_type:
        raise HTTPException(status_code=400, detail="event_type is required")
    SUPPRESSED_EVENT_TYPES[event_type] = reason or "manual suppression"
    return {"ok": True, "suppressed": SUPPRESSED_EVENT_TYPES}


@app.get("/api/baseline/{device}")
def api_baseline_get(device: str):
    safe = _safe_device_id(device)
    p = Path(f"~/.usb_analysis/{safe}.baseline.json").expanduser().resolve()
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"Baseline not found for {safe}")
    import json

    return json.loads(p.read_text(encoding="utf-8"))


@app.post("/api/baseline/{device}/update")
def api_baseline_update(
    device: str,
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None),
):
    safe = _safe_device_id(device)
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True}
    data = _deep_result(p, cid, cids)
    import json

    out = Path(f"~/.usb_analysis/{safe}.baseline.json").expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data.get("baseline") or {}, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(out)}


def _cleanup_temp(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


@app.get("/api/export/json")
def api_export_json(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    data = _get_flow_analysis(caps)
    fd, name = tempfile.mkstemp(prefix="usb-flow-", suffix=".json")
    os.close(fd)
    export_json(data["stream"], name)
    return FileResponse(name, filename="usb-flow.json", background=BackgroundTask(_cleanup_temp, name))


@app.get("/api/export/csv")
def api_export_csv(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    data = _get_flow_analysis(caps)
    fd, name = tempfile.mkstemp(prefix="usb-flow-", suffix=".csv")
    os.close(fd)
    export_csv(data["stream"], name)
    return FileResponse(name, filename="usb-flow.csv", background=BackgroundTask(_cleanup_temp, name))


@app.get("/api/export/html")
def api_export_html(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    data = _get_flow_analysis(caps)
    fd, name = tempfile.mkstemp(prefix="usb-flow-", suffix=".html")
    os.close(fd)
    export_html_report(data["stream"], data["errors"], None, name)
    return FileResponse(name, filename="usb-flow.html", background=BackgroundTask(_cleanup_temp, name))


@app.get("/api/export/junit")
def api_export_junit(path: str | None = Query(default=None), capture_id: str | None = Query(default=None), capture_ids: str | None = Query(default=None)):
    caps = resolve_captures(_nonempty_query(path), _nonempty_query(capture_id), _nonempty_query(capture_ids))
    data = _get_flow_analysis(caps)
    fd, name = tempfile.mkstemp(prefix="usb-flow-", suffix=".xml")
    os.close(fd)
    export_junit_xml(data["stream"], data["errors"], name)
    return FileResponse(name, filename="usb-flow-junit.xml", background=BackgroundTask(_cleanup_temp, name))


@app.get("/api/deep/summary")
def api_deep_summary(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True}
    data = _deep_result(p, cid, cids)
    return {
        "files": data["files"],
        "segments_count": data["segments_count"],
        "features_count": data["features_count"],
        "findings_count": len(data["findings"]),
        "rules_count": len(data["rules"]),
        "device_serial": (data.get("baseline") or {}).get("device_serial"),
    }


@app.get("/api/deep/findings")
def api_deep_findings(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=2000),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True, "rows": [], "returned": 0}
    data = _deep_result(p, cid, cids)
    rows = data["findings"][offset : offset + limit]
    return {"offset": offset, "limit": limit, "returned": len(rows), "rows": rows}


@app.get("/api/deep/rules")
def api_deep_rules(
    path: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    capture_ids: str | None = Query(default=None, description="Comma-separated capture IDs"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=2000),
):
    p = _nonempty_query(path)
    cid = _nonempty_query(capture_id)
    cids = _nonempty_query(capture_ids)
    if not p and not cid and not cids:
        return {"capture_required": True, "rows": [], "returned": 0}
    data = _deep_result(p, cid, cids)
    rows = data["rules"][offset : offset + limit]
    return {"offset": offset, "limit": limit, "returned": len(rows), "rows": rows}


def _store_upload(file: UploadFile) -> Path:
    """Stream upload to a temp file, enforcing MAX_UPLOAD_BYTES."""
    fd, name = tempfile.mkstemp(prefix="usbpcap-", suffix=".pcap")
    os.close(fd)
    dest = Path(name)
    written = 0
    try:
        with dest.open("wb") as sink:
            while True:
                chunk = file.file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Upload exceeds {MAX_UPLOAD_BYTES} bytes",
                    )
                sink.write(chunk)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
    return dest


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    dest = _store_upload(file)
    try:
        ensure_mmap_link(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Not a LINUX USB MMAPPED PCAP")
    uid = str(uuid.uuid4())
    with _state_lock:
        CAPTURE_IDS[uid] = dest
    return {"capture_id": uid, "filename": file.filename, "stored_path": str(dest)}


@app.post("/api/upload-multi")
async def api_upload_multi(files: list[UploadFile] = File(...)):
    ids: list[str] = []
    names: list[str] = []
    for file in files:
        try:
            dest = _store_upload(file)
        except HTTPException:
            raise
        try:
            ensure_mmap_link(dest)
        except Exception:
            dest.unlink(missing_ok=True)
            continue
        uid = str(uuid.uuid4())
        with _state_lock:
            CAPTURE_IDS[uid] = dest
        ids.append(uid)
        names.append(file.filename or uid)
    if not ids:
        raise HTTPException(status_code=400, detail="No valid LINUX USB MMAPPED captures in upload")
    return {"capture_ids": ids, "filenames": names}


@app.get("/")
def spa_index():
    index = STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=500, detail=f"Missing static bundle: {index}")
    return FileResponse(index)


if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="asset")
