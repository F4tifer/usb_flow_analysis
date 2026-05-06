"""One-pass PCAP statistics."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from usb_analysis.models import event_type_char, transfer_type_name
from usb_analysis.filters import matches
from usb_analysis.pipeline import iter_mmap_packets
from usb_analysis.pcap import pcap_wall_ts_sec


def build_summary(
    path: Path | str,
    *,
    bus: int | None = None,
    device: int | None = None,
    endpoint: int | None = None,
) -> dict[str, Any]:
    path = Path(path)
    xfer_c: Counter[int] = Counter()
    event_c: Counter[str] = Counter()
    total = 0
    first_ts: float | None = None
    last_ts: float | None = None
    devices: set[tuple[int, int]] = set()

    for pkt in iter_mmap_packets(path):
        if not matches(pkt, bus=bus, device=device, endpoint=endpoint):
            continue
        total += 1
        h = pkt.header
        xfer_c[h.transfer_type] += 1
        ev = event_type_char(h.event_type) or f"0x{h.event_type:02x}"
        event_c[ev] += 1
        devices.add((h.bus_id, h.device_address))
        wall = pcap_wall_ts_sec(pkt.pcap_ts_sec, pkt.pcap_ts_usec)
        if first_ts is None or wall < first_ts:
            first_ts = wall
        if last_ts is None or wall > last_ts:
            last_ts = wall

    xfer_named = {transfer_type_name(k): v for k, v in sorted(xfer_c.items())}
    dev_list = [{"bus": b, "device": d} for b, d in sorted(devices)]

    return {
        "path": str(path.resolve()),
        "total_packets": total,
        "time_start": first_ts,
        "time_end": last_ts,
        "duration_s": (last_ts - first_ts) if first_ts is not None and last_ts is not None else None,
        "devices": dev_list,
        "transfer_types": xfer_named,
        "event_types": dict(event_c),
    }
