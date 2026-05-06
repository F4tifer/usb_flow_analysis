"""Streaming usbmon parser yielding normalized UsbPacket rows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Literal

from usb_analysis.pcap import iter_pcap_packets
from usb_analysis.pipeline import ensure_mmap_link
from usb_analysis.usb_mmap import parse_mapped_packet_body

# Matches "*.pcap", "*.pcap00", "*.pcap123", etc.
_PCAP_NAME_RE = re.compile(r"\.pcap(\d+)?$", re.IGNORECASE)


def is_pcap_file(p: Path) -> bool:
    return p.is_file() and bool(_PCAP_NAME_RE.search(p.name))


def collect_pcap_files(path_or_dir: Path | str | list[Path] | tuple[Path, ...]) -> list[Path]:
    """Return sorted list of pcap files from a path, directory, or explicit list."""
    if isinstance(path_or_dir, (list, tuple)):
        out: list[Path] = []
        for item in path_or_dir:
            p = Path(item).expanduser().resolve()
            if p.is_file():
                out.append(p)
        return sorted(set(out))
    p = Path(path_or_dir).expanduser().resolve()
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(x for x in p.iterdir() if is_pcap_file(x))
    return []


@dataclass(slots=True)
class UsbPacket:
    urb_id: int
    event: Literal["S", "C", "E"]
    xfer_type: Literal["control", "interrupt", "bulk", "iso"]
    ep: int
    direction: Literal["IN", "OUT"]
    ts: float
    status: int
    orig_length: int
    payload: bytes
    is_truncated: bool
    source_file: str
    bus_id: int = 0
    device_address: int = 0


_XFER_MAP = {0: "iso", 1: "interrupt", 2: "control", 3: "bulk"}


def _iter_packets_one(path: Path) -> Iterator[UsbPacket]:
    ensure_mmap_link(path)
    for ord_, ts_sec, ts_usec, caplen, orig_len, body in iter_pcap_packets(path):
        parsed = parse_mapped_packet_body(
            body,
            ordinal=ord_,
            pcap_ts_sec=ts_sec,
            pcap_ts_usec=ts_usec,
            caplen=caplen,
            origlen=orig_len,
        )
        h = parsed.header
        ev = chr(h.event_type) if 32 <= h.event_type < 127 else "?"
        if ev not in {"S", "C", "E"}:
            continue
        xfer = _XFER_MAP.get(h.transfer_type, "bulk")
        direction = "IN" if h.is_in_transfer else "OUT"
        ts = parsed.pcap_ts_sec + parsed.pcap_ts_usec / 1_000_000.0
        payload = parsed.payload
        yield UsbPacket(
            urb_id=h.urb_id,
            event=ev,
            xfer_type=xfer,
            ep=h.endpoint_index,
            direction=direction,
            ts=ts,
            status=h.status,
            orig_length=h.urb_total_len,
            payload=payload,
            is_truncated=(h.urb_total_len > len(payload) and len(payload) > 0),
            source_file=str(path),
            bus_id=h.bus_id,
            device_address=h.device_address,
        )


def iter_usb_packets(path_or_files: str | Path | list[Path]) -> Iterator[UsbPacket]:
    """Yield packets from one pcap, directory, or explicit file list."""
    files = collect_pcap_files(path_or_files)
    for f in files:
        yield from _iter_packets_one(f)
