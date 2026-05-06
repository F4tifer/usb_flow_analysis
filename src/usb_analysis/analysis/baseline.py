"""Baseline profile learning for USB command-response segments."""

from __future__ import annotations

import statistics
from dataclasses import dataclass

from usb_analysis.analysis.segmenter import Segment


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "std": 0.0, "median": 0.0, "mad": 0.0}
    mean = statistics.fmean(values)
    std = statistics.pstdev(values) if len(values) > 1 else 0.0
    med = statistics.median(values)
    mad = statistics.median([abs(v - med) for v in values]) if len(values) > 1 else 0.0
    return {"mean": mean, "std": std, "median": med, "mad": mad}


@dataclass(slots=True)
class CommandProfile:
    cmd_name: str
    sample_count: int
    outcome_distribution: dict[str, int]
    latency_stats: dict[str, float]
    resp_line_count_stats: dict[str, float]
    payload_in_stats: dict[str, float]
    expected_at_positions: list[int]


@dataclass(slots=True)
class DeviceBaseline:
    schema_version: int
    device_serial: str
    sample_count: int
    commands: dict[str, CommandProfile]
    known_expected_outliers: list[str]


def _expected_rules() -> list[str]:
    return [
        "crc-enable->ERROR:invalid-crc",
        "checked-optiga-lock-check->OK_NO",
        "checked-tropic-lock-check->OK_NO",
    ]


def build_device_baseline(
    segments: list[Segment], *, schema_version: int = 1, device_serial: str = "unknown"
) -> DeviceBaseline:
    by_cmd: dict[str, list[Segment]] = {}
    for s in segments:
        by_cmd.setdefault(s.cmd_name or "UNKNOWN", []).append(s)

    commands: dict[str, CommandProfile] = {}
    for cmd, segs in by_cmd.items():
        outcome_dist: dict[str, int] = {}
        lat = []
        line_cnt = []
        pin = []
        pos = []
        for s in segs:
            outcome_dist[s.outcome] = outcome_dist.get(s.outcome, 0) + 1
            lat.append(s.latency_ms)
            line_cnt.append(float(len(s.response_lines)))
            pin.append(float(s.payload_bytes_in))
            pos.append(s.run_index)
        commands[cmd] = CommandProfile(
            cmd_name=cmd,
            sample_count=len(segs),
            outcome_distribution=outcome_dist,
            latency_stats=_stats(lat),
            resp_line_count_stats=_stats(line_cnt),
            payload_in_stats=_stats(pin),
            expected_at_positions=sorted(set(pos)),
        )

    return DeviceBaseline(
        schema_version=schema_version,
        device_serial=device_serial,
        sample_count=len(segments),
        commands=commands,
        known_expected_outliers=_expected_rules(),
    )

