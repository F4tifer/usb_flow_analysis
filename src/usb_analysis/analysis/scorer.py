"""Anomaly scoring against learned baseline."""

from __future__ import annotations

from dataclasses import dataclass

from usb_analysis.analysis.baseline import DeviceBaseline
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.segmenter import Segment


@dataclass(slots=True)
class AnomalyFinding:
    segment: Segment
    score: float
    reasons: list[str]
    evidence: dict


def _is_expected_outlier(s: Segment, baseline: DeviceBaseline) -> bool:
    line = s.final_response
    if s.cmd_name == "crc-enable" and "invalid-crc" in line:
        return True
    if s.cmd_name in ("checked-optiga-lock-check", "checked-tropic-lock-check") and s.outcome == "OK_NO":
        return True
    marker = f"{s.cmd_name}->{s.outcome}"
    return any(r.startswith(marker) for r in baseline.known_expected_outliers)


def score_segments(
    segments: list[Segment], baseline: DeviceBaseline, *, cfg: AnalysisConfig | None = None
) -> list[AnomalyFinding]:
    cfg = cfg or AnalysisConfig()
    out: list[AnomalyFinding] = []

    for s in segments:
        reasons: list[str] = []
        score = 0.0
        prof = baseline.commands.get(s.cmd_name or "UNKNOWN")

        if prof is None:
            score += 0.6
            reasons.append("unknown command for baseline")
        else:
            if s.outcome not in prof.outcome_distribution and not _is_expected_outlier(s, baseline):
                score += 0.4
                reasons.append(f"unexpected outcome {s.outcome}")

            mad = max(prof.latency_stats.get("mad", 0.0), 1e-9)
            med = prof.latency_stats.get("median", 0.0)
            z_like = abs(s.latency_ms - med) / mad
            if z_like > cfg.latency_z_threshold:
                score += min(0.3, 0.05 * z_like)
                reasons.append(f"latency spike ({z_like:.2f} MAD)")

            expected = prof.expected_at_positions
            if expected and s.run_index not in expected:
                score += 0.1
                reasons.append("unusual run position")

            max_lines = prof.resp_line_count_stats.get("median", 0.0) + 3 * max(
                prof.resp_line_count_stats.get("mad", 0.0), 1.0
            )
            if len(s.response_lines) > max_lines:
                score += 0.2
                reasons.append("response line count spike")

        score = max(0.0, min(1.0, score))
        if score >= cfg.anomaly_score_threshold:
            out.append(
                AnomalyFinding(
                    segment=s,
                    score=score,
                    reasons=reasons or ["high anomaly score"],
                    evidence={
                        "cmd_name": s.cmd_name,
                        "outcome": s.outcome,
                        "latency_ms": s.latency_ms,
                        "run_index": s.run_index,
                        "final_response": s.final_response,
                    },
                )
            )
    return sorted(out, key=lambda x: x.score, reverse=True)

