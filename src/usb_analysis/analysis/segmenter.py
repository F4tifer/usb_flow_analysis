"""Segment USB command/response communication into semantic blocks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.models import EVENT_COMPLETE, EVENT_SUBMIT, ParsedPacket
from usb_analysis.pcap import pcap_wall_ts_sec
from usb_analysis.pipeline import iter_mmap_packets

FINAL_RE = re.compile(r"^(OK(?:\s+NO)?|ERROR)\b")
SERIAL_RE = re.compile(r"OK(?:\s+NO)?\s+([0-9A-F]{8})")
CRC_RE = re.compile(r"\b([0-9A-F]{8})$")


@dataclass(slots=True)
class Segment:
    run_index: int
    cmd_raw: str
    cmd_name: str
    cmd_args: list[str]
    cmd_crc: str | None
    progress_lines: list[str]
    response_lines: list[str]
    final_response: str
    outcome: Literal["OK", "OK_NO", "ERROR", "TIMEOUT", "UNKNOWN"]
    device_serial: str | None
    ts_cmd: float
    ts_resp: float
    latency_ms: float
    payload_bytes_out: int
    payload_bytes_in: int
    source_file: str


@dataclass
class _OpenSegment:
    run_index: int
    cmd_raw: str
    cmd_name: str
    cmd_args: list[str]
    cmd_crc: str | None
    ts_cmd: float
    payload_bytes_out: int
    response_lines: list[str] = field(default_factory=list)
    progress_lines: list[str] = field(default_factory=list)
    payload_bytes_in: int = 0


def _decode_lines(payload: bytes) -> list[str]:
    text = payload.decode("ascii", errors="ignore")
    text = text.replace("\x00", "")
    lines: list[str] = []
    for line in text.splitlines():
        cleaned = line.strip()
        if cleaned:
            lines.append(cleaned)
    return lines


def _parse_cmd_line(line: str) -> tuple[str, list[str], str | None]:
    toks = line.strip().split()
    if not toks:
        return "", [], None
    cmd_name = toks[0]
    cmd_crc = None
    args = toks[1:]
    if args:
        m = CRC_RE.search(args[-1])
        if m and len(args[-1]) == 8:
            cmd_crc = m.group(1)
            args = args[:-1]
    return cmd_name, args, cmd_crc


def _outcome(final_response: str) -> Literal["OK", "OK_NO", "ERROR", "TIMEOUT", "UNKNOWN"]:
    if final_response.startswith("ERROR"):
        return "ERROR"
    if final_response.startswith("OK NO"):
        return "OK_NO"
    if final_response.startswith("OK"):
        return "OK"
    if final_response == "TIMEOUT":
        return "TIMEOUT"
    return "UNKNOWN"


def _close_segment(open_seg: _OpenSegment, *, ts_resp: float, source_file: str) -> Segment:
    final_response = open_seg.response_lines[-1] if open_seg.response_lines else "TIMEOUT"
    out = _outcome(final_response)
    serial = None
    if out in ("OK", "OK_NO"):
        m = SERIAL_RE.search(final_response)
        if m:
            serial = m.group(1)
    return Segment(
        run_index=open_seg.run_index,
        cmd_raw=open_seg.cmd_raw,
        cmd_name=open_seg.cmd_name,
        cmd_args=open_seg.cmd_args,
        cmd_crc=open_seg.cmd_crc,
        progress_lines=list(open_seg.progress_lines),
        response_lines=list(open_seg.response_lines),
        final_response=final_response,
        outcome=out,
        device_serial=serial,
        ts_cmd=open_seg.ts_cmd,
        ts_resp=ts_resp,
        latency_ms=max(0.0, (ts_resp - open_seg.ts_cmd) * 1000.0),
        payload_bytes_out=open_seg.payload_bytes_out,
        payload_bytes_in=open_seg.payload_bytes_in,
        source_file=source_file,
    )


def segment_packets(
    packets: list[ParsedPacket], *, source_file: str, cfg: AnalysisConfig | None = None
) -> list[Segment]:
    cfg = cfg or AnalysisConfig()
    segs: list[Segment] = []
    open_seg: _OpenSegment | None = None
    run_index = 0

    for pkt in packets:
        h = pkt.header
        if h.transfer_type != 3 or h.endpoint_index != 1:
            continue
        if not pkt.payload:
            continue
        ts = pcap_wall_ts_sec(pkt.pcap_ts_sec, pkt.pcap_ts_usec)
        lines = _decode_lines(pkt.payload)
        if not lines:
            continue

        if (not h.is_in_transfer) and h.event_type == EVENT_SUBMIT:
            if open_seg is not None:
                segs.append(_close_segment(open_seg, ts_resp=ts, source_file=source_file))
            cmd_raw = " ".join(lines)
            cmd_name, cmd_args, cmd_crc = _parse_cmd_line(lines[0])
            if cmd_name == "ping":
                run_index = 0
            run_index += 1
            open_seg = _OpenSegment(
                run_index=run_index,
                cmd_raw=cmd_raw,
                cmd_name=cmd_name,
                cmd_args=cmd_args,
                cmd_crc=cmd_crc,
                ts_cmd=ts,
                payload_bytes_out=len(pkt.payload),
            )
            continue

        if h.is_in_transfer and h.event_type == EVENT_COMPLETE and open_seg is not None:
            open_seg.payload_bytes_in += len(pkt.payload)
            for line in lines:
                if line.startswith(cfg.progress_prefix):
                    open_seg.progress_lines.append(line)
                open_seg.response_lines.append(line)
                if FINAL_RE.match(line) is not None:
                    segs.append(_close_segment(open_seg, ts_resp=ts, source_file=source_file))
                    open_seg = None
                    break
                if len(open_seg.response_lines) >= cfg.max_segment_lines:
                    segs.append(_close_segment(open_seg, ts_resp=ts, source_file=source_file))
                    open_seg = None
                    break

    if open_seg is not None:
        if packets:
            last_pkt = packets[-1]
            last_ts = pcap_wall_ts_sec(last_pkt.pcap_ts_sec, last_pkt.pcap_ts_usec)
        else:
            last_ts = open_seg.ts_cmd
        segs.append(_close_segment(open_seg, ts_resp=last_ts, source_file=source_file))
    return segs


def segment_file(path: Path | str, *, cfg: AnalysisConfig | None = None) -> list[Segment]:
    p = Path(path)
    packets = list(iter_mmap_packets(p))
    return segment_packets(packets, source_file=str(p), cfg=cfg)

