"""Persistence and incremental baseline updates."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from usb_analysis.analysis.baseline import CommandProfile, DeviceBaseline, build_device_baseline
from usb_analysis.analysis.segmenter import Segment


def save_baseline(profile: DeviceBaseline, path: Path | str) -> None:
    p = Path(path).expanduser().resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        json.dump(asdict(profile), f, ensure_ascii=False, indent=2)


def load_baseline(path: Path | str) -> DeviceBaseline:
    p = Path(path).expanduser().resolve()
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    commands = {
        k: CommandProfile(
            cmd_name=v["cmd_name"],
            sample_count=v["sample_count"],
            outcome_distribution=v["outcome_distribution"],
            latency_stats=v["latency_stats"],
            resp_line_count_stats=v["resp_line_count_stats"],
            payload_in_stats=v["payload_in_stats"],
            expected_at_positions=v["expected_at_positions"],
        )
        for k, v in data["commands"].items()
    }
    return DeviceBaseline(
        schema_version=data["schema_version"],
        device_serial=data["device_serial"],
        sample_count=data["sample_count"],
        commands=commands,
        known_expected_outliers=data.get("known_expected_outliers", []),
    )


def _merge_stats(old: dict[str, float], old_n: int, new: dict[str, float], new_n: int) -> dict[str, float]:
    """Pool two stat dicts. Mean is sample-weighted; std is pooled population stdev.

    Median/MAD cannot be exactly merged from summary stats, so we keep the more
    sample-rich side as a best-effort estimate.
    """
    total = old_n + new_n
    if total <= 0:
        return dict(new)
    om, nm = old.get("mean", 0.0), new.get("mean", 0.0)
    os_, ns = old.get("std", 0.0), new.get("std", 0.0)
    mean = (om * old_n + nm * new_n) / total
    var = (old_n * (os_ ** 2 + (om - mean) ** 2) + new_n * (ns ** 2 + (nm - mean) ** 2)) / total
    base = old if old_n >= new_n else new
    return {
        "mean": mean,
        "std": var ** 0.5,
        "median": base.get("median", 0.0),
        "mad": base.get("mad", 0.0),
    }


def merge_baseline(existing: DeviceBaseline, new_segments: list[Segment]) -> DeviceBaseline:
    """Combine an existing baseline with stats from new_segments.

    Rebuilds command profiles for cmds present in `new_segments` and pools their
    distributions with whatever was previously stored. Commands only seen in the
    existing baseline are carried over unchanged.
    """
    if not new_segments:
        return existing
    serial = next((s.device_serial for s in new_segments if s.device_serial), existing.device_serial)
    fresh = build_device_baseline(
        new_segments, schema_version=existing.schema_version, device_serial=serial or "unknown"
    )
    for cmd, prof in existing.commands.items():
        if cmd not in fresh.commands:
            fresh.commands[cmd] = prof
            continue
        merged = fresh.commands[cmd]
        merged.latency_stats = _merge_stats(prof.latency_stats, prof.sample_count, merged.latency_stats, merged.sample_count)
        merged.resp_line_count_stats = _merge_stats(
            prof.resp_line_count_stats, prof.sample_count, merged.resp_line_count_stats, merged.sample_count
        )
        merged.payload_in_stats = _merge_stats(
            prof.payload_in_stats, prof.sample_count, merged.payload_in_stats, merged.sample_count
        )
        merged.sample_count += prof.sample_count
        for k, v in prof.outcome_distribution.items():
            merged.outcome_distribution[k] = merged.outcome_distribution.get(k, 0) + v
        merged.expected_at_positions = sorted(set(merged.expected_at_positions + prof.expected_at_positions))
    fresh.sample_count += existing.sample_count
    return fresh

