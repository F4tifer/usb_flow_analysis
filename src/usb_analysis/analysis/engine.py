"""High-level orchestration for deep USB analysis."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from usb_analysis.analysis.baseline import DeviceBaseline, build_device_baseline
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.features import build_features
from usb_analysis.analysis.parser import collect_pcap_files
from usb_analysis.analysis.rules import RuleCandidate, mine_rule_candidates
from usb_analysis.analysis.scorer import AnomalyFinding, score_segments
from usb_analysis.analysis.segmenter import Segment, segment_file
from usb_analysis.analysis.store import load_baseline, merge_baseline, save_baseline


def _collect_files(path_or_dir: Path | str | list[Path] | tuple[Path, ...]) -> list[Path]:
    return collect_pcap_files(path_or_dir)


def analyze_path(
    path_or_dir: Path | str | list[Path] | tuple[Path, ...],
    *,
    cfg: AnalysisConfig | None = None,
    update_baseline: bool = False,
) -> dict:
    cfg = cfg or AnalysisConfig()
    files = _collect_files(path_or_dir)
    if not files:
        return {
            "files": [],
            "segments_count": 0,
            "features_count": 0,
            "findings": [],
            "rules": [],
            "baseline": None,
        }

    segments: list[Segment] = []
    for f in files:
        segments.extend(segment_file(f, cfg=cfg))
    features = build_features(segments)
    serial = next((s.device_serial for s in segments if s.device_serial), "unknown")

    baseline_path = cfg.baseline_path_resolved
    if update_baseline and baseline_path.exists():
        baseline = merge_baseline(load_baseline(baseline_path), segments)
    else:
        baseline = build_device_baseline(segments, schema_version=cfg.baseline_schema_version, device_serial=serial)

    findings: list[AnomalyFinding] = score_segments(segments, baseline, cfg=cfg)
    rules: list[RuleCandidate] = mine_rule_candidates(segments, findings)

    if update_baseline:
        save_baseline(baseline, baseline_path)

    return {
        "files": [str(f) for f in files],
        "segments_count": len(segments),
        "features_count": len(features),
        "baseline": _baseline_to_dict(baseline),
        "findings": [_finding_to_dict(f) for f in findings],
        "rules": [_rule_to_dict(r) for r in rules],
    }


def _segment_to_brief(seg: Segment) -> dict:
    return {
        "cmd_name": seg.cmd_name,
        "cmd_raw": seg.cmd_raw,
        "outcome": seg.outcome,
        "final_response": seg.final_response,
        "run_index": seg.run_index,
        "latency_ms": seg.latency_ms,
        "source_file": seg.source_file,
    }


def _finding_to_dict(f: AnomalyFinding) -> dict:
    return {
        "score": f.score,
        "reasons": f.reasons,
        "evidence": f.evidence,
        "segment": _segment_to_brief(f.segment),
    }


def _rule_to_dict(r: RuleCandidate) -> dict:
    return {
        "rule_id": r.rule_id,
        "description": r.description,
        "confidence": r.confidence,
        "support": r.support,
        "suggested_action": r.suggested_action,
        "examples": [_segment_to_brief(s) for s in r.example_segments],
    }


def _baseline_to_dict(b: DeviceBaseline) -> dict:
    return asdict(b)

