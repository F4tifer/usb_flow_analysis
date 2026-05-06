from usb_analysis.analysis.rules import mine_rule_candidates
from usb_analysis.analysis.scorer import AnomalyFinding
from usb_analysis.analysis.segmenter import Segment


def _seg(cmd, outcome, idx):
    return Segment(
        run_index=idx,
        cmd_raw=cmd,
        cmd_name=cmd,
        cmd_args=[],
        cmd_crc=None,
        progress_lines=[],
        response_lines=[outcome],
        final_response=outcome,
        outcome=outcome,
        device_serial="D736D92D",
        ts_cmd=1.0,
        ts_resp=1.1,
        latency_ms=100.0,
        payload_bytes_out=8,
        payload_bytes_in=8,
        source_file="x",
    )


def test_rule_mining_detects_error_context():
    segs = [_seg("crc-enable", "ERROR", 1), _seg("checked-x", "ERROR", 2), _seg("checked-x", "ERROR", 3)]
    findings = [AnomalyFinding(segment=segs[1], score=0.9, reasons=["x"], evidence={})]
    rules = mine_rule_candidates(segs, findings)
    ids = {r.rule_id for r in rules}
    assert "error-outside-crc-enable" in ids
    assert "retry-storm" in ids

