"""Rule candidate mining from repeated anomalies and protocol patterns."""

from __future__ import annotations

from dataclasses import dataclass

from usb_analysis.analysis.scorer import AnomalyFinding
from usb_analysis.analysis.segmenter import Segment


@dataclass(slots=True)
class RuleCandidate:
    rule_id: str
    description: str
    confidence: float
    support: int
    example_segments: list[Segment]
    suggested_action: str


def mine_rule_candidates(segments: list[Segment], findings: list[AnomalyFinding]) -> list[RuleCandidate]:
    rules: list[RuleCandidate] = []
    if not segments:
        return rules

    # Note on language: rule descriptions are canonical English. The UI
    # resolves a localised label via `t("rule." + rule_id)` keyed on the
    # rule_id; CLI and other non-UI consumers see English text by default.

    # Missing final responses (TIMEOUT)
    timeouts = [s for s in segments if s.outcome == "TIMEOUT"]
    if timeouts:
        rules.append(
            RuleCandidate(
                rule_id="incomplete-segment-timeout",
                description="Commands without a final OK/ERROR response.",
                confidence=min(1.0, len(timeouts) / max(1, len(segments))),
                support=len(timeouts),
                example_segments=timeouts[:3],
                suggested_action="investigate",
            )
        )

    # Error outside crc-enable
    bad_crc_context = [s for s in segments if s.outcome == "ERROR" and s.cmd_name != "crc-enable"]
    if bad_crc_context:
        rules.append(
            RuleCandidate(
                rule_id="error-outside-crc-enable",
                description="ERROR outside the expected crc-enable command.",
                confidence=min(1.0, len(bad_crc_context) / max(1, len(segments))),
                support=len(bad_crc_context),
                example_segments=bad_crc_context[:3],
                suggested_action="alert",
            )
        )

    # Retry storms (same command repeating in short sequence)
    repeats = []
    for i in range(1, len(segments)):
        if segments[i].cmd_name and segments[i].cmd_name == segments[i - 1].cmd_name:
            repeats.append(segments[i])
    if repeats:
        rules.append(
            RuleCandidate(
                rule_id="retry-storm",
                description="Same command repeated in adjacent segments.",
                confidence=min(1.0, len(repeats) / max(1, len(segments))),
                support=len(repeats),
                example_segments=repeats[:3],
                suggested_action="investigate",
            )
        )

    # High-score anomaly aggregation
    if findings:
        rules.append(
            RuleCandidate(
                rule_id="high-score-anomaly-cluster",
                description="Cluster of segments with a high anomaly score.",
                confidence=min(1.0, len(findings) / max(1, len(segments))),
                support=len(findings),
                example_segments=[f.segment for f in findings[:3]],
                suggested_action="investigate",
            )
        )
    return rules

