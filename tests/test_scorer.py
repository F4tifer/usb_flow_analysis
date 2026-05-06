from usb_analysis.analysis.baseline import build_device_baseline
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.scorer import score_segments
from usb_analysis.analysis.segmenter import Segment


def _seg(cmd, outcome, lat, idx):
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
        ts_resp=1.0 + lat / 1000.0,
        latency_ms=lat,
        payload_bytes_out=10,
        payload_bytes_in=10,
        source_file="x",
    )


def test_scorer_flags_unexpected_outcome():
    train = [_seg("ping", "OK", 10, 1), _seg("ping", "OK", 11, 1), _seg("ping", "OK", 9, 1)]
    baseline = build_device_baseline(train, device_serial="D736D92D")
    cfg = AnalysisConfig(anomaly_score_threshold=0.1)
    findings = score_segments([_seg("ping", "ERROR", 10, 1)], baseline, cfg=cfg)
    assert findings
    assert findings[0].segment.outcome == "ERROR"


def _seg_with_response(cmd, outcome, lat, idx, final_response):
    s = _seg(cmd, outcome, lat, idx)
    return type(s)(
        run_index=s.run_index,
        cmd_raw=s.cmd_raw,
        cmd_name=s.cmd_name,
        cmd_args=s.cmd_args,
        cmd_crc=s.cmd_crc,
        progress_lines=s.progress_lines,
        response_lines=[final_response],
        final_response=final_response,
        outcome=s.outcome,
        device_serial=s.device_serial,
        ts_cmd=s.ts_cmd,
        ts_resp=s.ts_resp,
        latency_ms=s.latency_ms,
        payload_bytes_out=s.payload_bytes_out,
        payload_bytes_in=s.payload_bytes_in,
        source_file=s.source_file,
    )


def test_scorer_does_not_flag_expected_crc_enable_invalid_crc():
    """crc-enable returning ERROR invalid-crc is a known probe outcome, not an anomaly."""
    # Train baseline so prof is known but only OK is observed, then verify ERROR is whitelisted.
    train = [_seg_with_response("crc-enable", "OK", 5, 1, "OK D736D92D")] * 5
    baseline = build_device_baseline(train, device_serial="D736D92D")
    cfg = AnalysisConfig(anomaly_score_threshold=0.5)
    seg = _seg_with_response("crc-enable", "ERROR", 5, 1, 'ERROR invalid-crc "CRC missing"')
    findings = score_segments([seg], baseline, cfg=cfg)
    crc_findings = [f for f in findings if f.segment.cmd_name == "crc-enable"]
    # Without the whitelist, an unknown-outcome ERROR would add 0.4. The whitelist
    # suppresses that, so any remaining score must come from other signals (e.g. latency).
    for f in crc_findings:
        assert "unexpected outcome" not in " ".join(f.reasons)


def test_scorer_does_not_flag_expected_lock_check_ok_no():
    """checked-optiga-lock-check returning OK_NO is a normal pre-lock state."""
    train = [_seg_with_response("checked-optiga-lock-check", "OK", 5, 1, "OK D736D92D")] * 5
    baseline = build_device_baseline(train, device_serial="D736D92D")
    cfg = AnalysisConfig(anomaly_score_threshold=0.5)
    seg = _seg_with_response("checked-optiga-lock-check", "OK_NO", 5, 1, "OK NO D736D92D")
    findings = score_segments([seg], baseline, cfg=cfg)
    matching = [f for f in findings if f.segment.cmd_name == "checked-optiga-lock-check"]
    for f in matching:
        assert "unexpected outcome" not in " ".join(f.reasons)

