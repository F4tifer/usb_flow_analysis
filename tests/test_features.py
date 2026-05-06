from usb_analysis.analysis.features import build_features
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
        outcome=outcome if outcome in ("OK", "OK_NO", "ERROR") else "UNKNOWN",
        device_serial=None,
        ts_cmd=1.0,
        ts_resp=1.1,
        latency_ms=100.0,
        payload_bytes_out=10,
        payload_bytes_in=12,
        source_file="x",
    )


def test_features_context_progression():
    segs = [_seg("ping", "OK", 1), _seg("cmd2", "ERROR", 2)]
    feats = build_features(segs)
    assert feats[0].prev_cmd_name is None
    assert feats[1].prev_cmd_name == "ping"
    assert feats[1].run_outcome_so_far == "has_errors"

