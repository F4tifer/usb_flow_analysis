"""Multi-file aggregation for flow analysis."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import statistics

from usb_analysis.analysis.causal import enrich_causal
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.detectors import detect_errors
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import iter_usb_packets


@dataclass(slots=True)
class TesterStats:
    tester_id: str
    device_serial: str | None
    run_count: int
    error_counts: dict[str, int]
    reconnect_count: int
    avg_run_duration_ms: float | None


@dataclass(slots=True)
class AggregationReport:
    tester_stats: list[TesterStats]
    error_heatmap: dict[str, dict[str, int]]
    outlier_testers: list[str]
    outlier_devices: list[str]
    cross_run_timing: dict[str, list[float]]
    timing_drift: dict[str, str]


def detect_timing_drift(cross_run_timing: dict[str, list[float]], window: int = 10) -> dict[str, str]:
    out: dict[str, str] = {}
    for cmd, vals in cross_run_timing.items():
        if len(vals) < max(3, window):
            out[cmd] = 'stable'
            continue
        head = statistics.fmean(vals[:window])
        tail = statistics.fmean(vals[-window:])
        if head <= 0:
            out[cmd] = 'stable'
            continue
        ratio = (tail - head) / head
        if ratio > 0.2:
            out[cmd] = 'critical'
        elif ratio > 0.05:
            out[cmd] = 'warning'
        else:
            out[cmd] = 'stable'
    return out


def build_error_heatmap(tester_stats: list[TesterStats]) -> dict[str, dict[str, int]]:
    return {t.tester_id: dict(t.error_counts) for t in tester_stats}


def aggregate_directory(directory: str, glob_pattern: str = '*.pcap*', config: AnalysisConfig | None = None, baseline_dir: str | None = None) -> AggregationReport:
    cfg = config or AnalysisConfig()
    root = Path(directory).expanduser().resolve()
    files = sorted(x for x in root.glob(glob_pattern) if x.is_file())
    tester_stats: list[TesterStats] = []
    cross_run_timing: dict[str, list[float]] = {}

    for f in files:
        packets = list(iter_usb_packets(f))
        stream = build_flow_stream(packets, cfg)
        enrich_causal(stream, cfg)
        errs = detect_errors(stream, cfg)
        counts: dict[str, int] = {}
        for e in errs:
            counts[e.event_type] = counts.get(e.event_type, 0) + 1
        reconnect_count = sum(1 for e in stream.events if e.event_class == 'reconnect')
        avg_run_ms = (stream.total_duration_s * 1000.0 / stream.stats.run_count) if stream.stats.run_count > 0 else None
        tester_stats.append(TesterStats(
            tester_id=f.name,
            device_serial=stream.device_serial,
            run_count=stream.stats.run_count,
            error_counts=counts,
            reconnect_count=reconnect_count,
            avg_run_duration_ms=avg_run_ms,
        ))
        for e in stream.events:
            if e.latency_ms is not None and e.cmd_name:
                cross_run_timing.setdefault(e.cmd_name, []).append(e.latency_ms)

    totals = [sum(t.error_counts.values()) for t in tester_stats]
    mean = statistics.fmean(totals) if totals else 0.0
    std = statistics.pstdev(totals) if len(totals) > 1 else 0.0
    # A tester is an outlier when its error total exceeds the cohort mean and is at
    # least 2σ above; with a single outlier among low-noise testers σ is small but
    # the gap is the meaningful signal, so we also require strictly more errors than
    # the mean.
    threshold = mean + 2 * std
    outlier_testers = [
        t.tester_id
        for t in tester_stats
        if sum(t.error_counts.values()) > mean and sum(t.error_counts.values()) >= threshold
    ]
    outlier_devices = sorted({t.device_serial for t in tester_stats if t.device_serial and t.tester_id in outlier_testers})

    return AggregationReport(
        tester_stats=tester_stats,
        error_heatmap=build_error_heatmap(tester_stats),
        outlier_testers=outlier_testers,
        outlier_devices=outlier_devices,
        cross_run_timing=cross_run_timing,
        timing_drift=detect_timing_drift(cross_run_timing),
    )


def aggregation_to_dict(report: AggregationReport) -> dict:
    return {
        'tester_stats': [asdict(t) for t in report.tester_stats],
        'error_heatmap': report.error_heatmap,
        'outlier_testers': report.outlier_testers,
        'outlier_devices': report.outlier_devices,
        'cross_run_timing': report.cross_run_timing,
        'timing_drift': report.timing_drift,
    }
