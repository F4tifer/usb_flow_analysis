"""Feature extraction for segmented USB command-response blocks."""

from __future__ import annotations

from dataclasses import dataclass

from usb_analysis.analysis.segmenter import Segment


@dataclass(slots=True)
class SegmentFeatures:
    cmd_name: str
    device_serial: str | None
    outcome: str
    crc_present: bool
    latency_ms: float
    resp_line_count: int
    payload_out_bytes: int
    payload_in_bytes: int
    run_position: int
    prev_cmd_name: str | None
    run_outcome_so_far: str


def build_features(segments: list[Segment]) -> list[SegmentFeatures]:
    feats: list[SegmentFeatures] = []
    seen_error = False
    prev_cmd: str | None = None
    last_run_pos = 0
    for s in segments:
        if s.run_index <= last_run_pos:
            seen_error = False
            prev_cmd = None
        last_run_pos = s.run_index
        if s.outcome in ("ERROR", "OK_NO"):
            seen_error = True
        run_status = "has_errors" if seen_error else "OK_only"
        feats.append(
            SegmentFeatures(
                cmd_name=s.cmd_name,
                device_serial=s.device_serial,
                outcome=s.outcome,
                crc_present=s.cmd_crc is not None,
                latency_ms=s.latency_ms,
                resp_line_count=len(s.response_lines),
                payload_out_bytes=s.payload_bytes_out,
                payload_in_bytes=s.payload_bytes_in,
                run_position=s.run_index,
                prev_cmd_name=prev_cmd,
                run_outcome_so_far=run_status,
            )
        )
        prev_cmd = s.cmd_name
    return feats

