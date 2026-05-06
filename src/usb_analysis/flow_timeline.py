"""Chronological USB flow: host↔device direction, urb events, optional gap markers."""

from __future__ import annotations

from typing import Any

from usb_analysis.models import EVENT_COMPLETE, EVENT_ERROR, EVENT_SUBMIT, event_type_char, transfer_type_name
from usb_analysis.pcap import pcap_wall_ts_sec
from usb_analysis.stream_text import to_printable_ascii as _to_printable_ascii


def _status_hint(status: int, event_type: int) -> str:
    if event_type == EVENT_ERROR:
        return "error"
    if status == 0:
        return "ok"
    if status < 0:
        return "errno"
    return "nonzero"


def _header_is_in(h: Any) -> bool:
    if hasattr(h, "is_in_transfer"):
        return bool(h.is_in_transfer)
    ep = int(getattr(h, "endpoint_number", 0))
    return (ep & 0x80) != 0


def _header_endpoint_index(h: Any) -> int:
    if hasattr(h, "endpoint_index"):
        return int(h.endpoint_index)
    return int(getattr(h, "endpoint_number", 0)) & 0x7F


def _protocol_highlights(text: str) -> list[str]:
    """Heuristic tags for protocol strings (e.g. user-mentioned DN/DP)."""
    t = text.upper()
    out: list[str] = []
    if "DN/" in t or " DN" in t or t.startswith("DN"):
        out.append("dn_token")
    if "DP/" in t or " DP" in t or t.startswith("DP"):
        out.append("dp_token")
    return out


def _payload_lines(payload: bytes, *, max_line_len: int = 512) -> tuple[list[str], str | None]:
    if not payload:
        return [], None
    ascii_text = _to_printable_ascii(payload)
    if not ascii_text.strip():
        return [], None
    lines: list[str] = []
    for raw in ascii_text.splitlines():
        line = raw.rstrip("\r")
        if len(line) > max_line_len:
            line = line[:max_line_len] + "…"
        if line:
            lines.append(line)
    preview = lines[0] if lines else None
    return lines, preview


def build_flow_timeline(
    packets: list[Any],
    *,
    gap_threshold_s: float = 2.0,
    bulk_only: bool = False,
) -> list[dict[str, Any]]:
    """Build ordered timeline rows: URB events and optional `kind: gap` rows.

    Direction is from the test host perspective: OUT (host→device) vs IN (device→host).
    """
    rows: list[dict[str, Any]] = []
    prev_ts: float | None = None
    prev_ord: int | None = None

    for pkt in packets:
        h = pkt.header
        if bulk_only and h.transfer_type != 3:
            continue

        ts = pcap_wall_ts_sec(pkt.pcap_ts_sec, pkt.pcap_ts_usec)
        if prev_ts is not None and gap_threshold_s > 0 and (ts - prev_ts) >= gap_threshold_s:
            rows.append(
                {
                    "kind": "gap",
                    "pcap_ts": prev_ts,
                    "gap_s": round(ts - prev_ts, 6),
                    "after_ordinal": prev_ord,
                    "before_ordinal": pkt.ordinal,
                    "label": "prodleva mezi URB (možný timeout / nečinnost sběrnice)",
                }
            )

        ev = event_type_char(h.event_type)
        is_in = _header_is_in(h)
        direction = "from_device" if is_in else "to_device"
        label = "device→TESTER" if is_in else "TESTER→device"
        lines, preview = _payload_lines(pkt.payload)
        highlights: list[str] = []
        for ln in lines[:8]:
            highlights.extend(_protocol_highlights(ln))
        highlights = list(dict.fromkeys(highlights))

        row: dict[str, Any] = {
            "kind": "urb",
            "pcap_ts": ts,
            "ordinal": pkt.ordinal,
            "direction": direction,
            "label": label,
            "event": ev,
            "transfer_type": transfer_type_name(h.transfer_type),
            "urb_id": hex(h.urb_id),
            "status": h.status,
            "status_hint": _status_hint(h.status, h.event_type),
            "endpoint": int(getattr(h, "endpoint_number", 0)),
            "endpoint_index": _header_endpoint_index(h),
            "is_in": is_in,
            "payload_len": len(pkt.payload),
            "payload_preview": preview,
            "payload_lines": lines,
            "highlights": highlights,
            "note": pkt.truncation_note or "",
        }
        if h.event_type == EVENT_SUBMIT:
            row["phase"] = "submit"
        elif h.event_type == EVENT_COMPLETE:
            row["phase"] = "complete"
        elif h.event_type == EVENT_ERROR:
            row["phase"] = "error"
        else:
            row["phase"] = "other"

        rows.append(row)
        prev_ts = ts
        prev_ord = pkt.ordinal

    return rows
