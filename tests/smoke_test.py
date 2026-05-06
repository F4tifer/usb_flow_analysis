"""
USB Flow Analyzer — Smoke Test
================================
Self-contained end-to-end test. Generates synthetic PCAP data inline,
runs the full analysis pipeline, and asserts expected outcomes.

Tests are skipped per-class based on which modules are implemented.
Run at any stage of development — you will see which tests pass
and which are waiting for their module to be written.

Run:
    python tests/smoke_test.py            # all tests
    python tests/smoke_test.py -v         # verbose
    python tests/smoke_test.py TestCrcUtil  # single class
"""

import struct
import sys
import os
import json
import tempfile
import unittest
import binascii
import time
from pathlib import Path
from unittest import skip

# ─── path setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# ─── granular imports — each module tracked independently ──────────────────────
# Tests are decorated with @_needs("module") and skipped automatically.

_AVAILABLE   = {}  # key → bool
_SKIP_REASON = {}  # key → str


def _try_import(key, module_path, names):
    """Try to import `names` from `module_path`. Track success in _AVAILABLE."""
    try:
        mod = __import__(module_path, fromlist=names)
        for name in names:
            if not hasattr(mod, name):
                raise AttributeError(f"{module_path} has no attribute '{name}'")
        _AVAILABLE[key] = True
        return mod
    except (ImportError, AttributeError) as e:
        _AVAILABLE[key] = False
        _SKIP_REASON[key] = str(e)
        return None


def _needs(*keys):
    """Class decorator: skip the test class if any required module is missing."""
    def decorator(cls):
        missing = [k for k in keys if not _AVAILABLE.get(k)]
        if missing:
            reasons = "; ".join(_SKIP_REASON.get(k, k) for k in missing)
            return skip(f"Not yet implemented — {reasons}")(cls)
        return cls
    return decorator


# Import each module
_m_config   = _try_import("config",       "usb_analysis.analysis.config",       ["AnalysisConfig"])
_m_parser   = _try_import("parser",       "usb_analysis.analysis.parser",       ["UsbPacket", "iter_usb_packets"])
_m_flow     = _try_import("flow_builder", "usb_analysis.analysis.flow_builder", ["FlowStream", "FlowEvent", "build_flow_stream"])
_m_causal   = _try_import("causal",       "usb_analysis.analysis.causal",       ["enrich_causal"])
_m_det      = _try_import("detectors",    "usb_analysis.analysis.detectors",    ["detect_errors", "ErrorEvent"])
_m_crc      = _try_import("crc_util",     "usb_analysis.analysis.crc_util",     ["compute_crc32", "validate_crc", "extract_serial_from_response"])
_m_baseline = _try_import("baseline",     "usb_analysis.analysis.baseline",     ["DeviceBaseline", "CommandProfile"])
_m_store    = _try_import("store",        "usb_analysis.analysis.store",        ["load_baseline", "save_baseline"])
_m_agg      = _try_import("aggregator",   "usb_analysis.analysis.aggregator",   ["aggregate_directory"])
_m_exp      = _try_import("exporter",     "usb_analysis.analysis.exporter",     ["export_json", "export_csv", "export_html_report", "export_junit_xml"])

# Convenience aliases (None-safe)
AnalysisConfig               = getattr(_m_config,   "AnalysisConfig",               None)
iter_usb_packets             = getattr(_m_parser,   "iter_usb_packets",             None)
FlowStream                   = getattr(_m_flow,     "FlowStream",                   None)
FlowEvent                    = getattr(_m_flow,     "FlowEvent",                    None)
build_flow_stream            = getattr(_m_flow,     "build_flow_stream",            None)
enrich_causal                = getattr(_m_causal,   "enrich_causal",                None)
detect_errors                = getattr(_m_det,      "detect_errors",                None)
ErrorEvent                   = getattr(_m_det,      "ErrorEvent",                   None)
compute_crc32                = getattr(_m_crc,      "compute_crc32",                None)
validate_crc                 = getattr(_m_crc,      "validate_crc",                 None)
extract_serial_from_response = getattr(_m_crc,      "extract_serial_from_response", None)
DeviceBaseline               = getattr(_m_baseline, "DeviceBaseline",               None)
CommandProfile               = getattr(_m_baseline, "CommandProfile",               None)
load_baseline                = getattr(_m_store,    "load_baseline",                None)
save_baseline                = getattr(_m_store,    "save_baseline",                None)
aggregate_directory          = getattr(_m_agg,      "aggregate_directory",          None)
export_json                  = getattr(_m_exp,      "export_json",                  None)
export_csv                   = getattr(_m_exp,      "export_csv",                   None)
export_html_report           = getattr(_m_exp,      "export_html_report",           None)
export_junit_xml             = getattr(_m_exp,      "export_junit_xml",             None)


# ═════════════════════════════════════════════════════════════════════════════
# SYNTHETIC PCAP BUILDER  (stdlib only — no external deps)
# ═════════════════════════════════════════════════════════════════════════════

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII",
    0xA1B2C3D4, 2, 4, 0, 0, 262144, 220)   # linktype 220 = USB_LINUX_MMAPPED

BASE_TS       = 1_700_000_000.0
DEVICE_SERIAL = "D736D92D"
DEVICE_NUM    = 3
BUS_NUM       = 1


def _crc32(text: str) -> str:
    return f"{binascii.crc32(text.encode()) & 0xFFFFFFFF:08X}"


def _usbmon_header(urb_id, event, xfer_type, epnum, ts, status, payload_len):
    """Build the 64-byte usbmon_packet header."""
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    h  = struct.pack("<Q", urb_id)           # 0:  id
    h += struct.pack("B",  ord(event))       # 8:  type (S/C)
    h += struct.pack("B",  xfer_type)        # 9:  xfer_type
    h += struct.pack("B",  epnum)            # 10: epnum
    h += struct.pack("B",  DEVICE_NUM)       # 11: devnum
    h += struct.pack("<H", BUS_NUM)          # 12: busnum
    h += struct.pack("b",  ord("<"))                              # 14: flag_setup ("<" = no setup)
    h += struct.pack("b",  0 if payload_len else ord("<"))         # 15: flag_data (0 = data present)
    h += struct.pack("<q", ts_sec)           # 16: ts_sec
    h += struct.pack("<i", ts_usec)          # 24: ts_usec
    h += struct.pack("<i", status)           # 28: status
    h += struct.pack("<I", payload_len)      # 32: orig_length
    h += struct.pack("<I", payload_len)      # 36: len_cap
    h += b"\x00" * (64 - len(h))            # pad to 64 bytes
    assert len(h) == 64
    return h


def _pcap_record(ts, data):
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _bulk_out(urb_id, ts, text):
    """HOST → DEVICE bulk Submit with ASCII text payload."""
    payload = (text + "\r\n").encode("ascii")
    return _pcap_record(ts, _usbmon_header(urb_id, "S", 3, 0x01, ts, 0, len(payload)) + payload)


def _bulk_in(urb_id, ts, text):
    """DEVICE → HOST bulk Complete with ASCII text payload."""
    payload = (text + "\r\n").encode("ascii")
    return _pcap_record(ts, _usbmon_header(urb_id, "C", 3, 0x81, ts, 0, len(payload)) + payload)


def _eproto(urb_id, ts):
    return _pcap_record(ts, _usbmon_header(urb_id, "C", 2, 0x00, ts, -71, 0))


def _control(urb_id, ts):
    return _pcap_record(ts, _usbmon_header(urb_id, "C", 2, 0x00, ts, 0, 0))


def _interrupt(urb_id, ts, counter=0):
    payload = bytes([0x01, 0x09, 0x4C, 0x57, 0x33, 0x64]) + b"\x00" * 46 + struct.pack("<I", counter)
    return _pcap_record(ts, _usbmon_header(urb_id, "C", 1, 0x81, ts, 0, len(payload)) + payload)


def _interrupt_bad_counter(urb_id, ts, counter=0):
    """Interrupt with counter that jumped backward."""
    payload = bytes([0x01, 0x09, 0x4C, 0x57, 0x33, 0x64]) + b"\x00" * 46 + struct.pack("<I", counter)
    return _pcap_record(ts, _usbmon_header(urb_id, "C", 1, 0x81, ts, 0, len(payload)) + payload)


def build_pcap(records):
    return PCAP_GLOBAL_HEADER + b"".join(records)


def make_cmd(name, args="", with_crc=True):
    body = f"{name} {args}".strip() if args else name
    return f"{body} {_crc32(body)}" if with_crc else body


# ─── Scenario builders ────────────────────────────────────────────────────────

def scenario_normal():
    """5 complete healthy runs. Expect zero critical/warning events."""
    recs, t, u = [], BASE_TS, 1
    for run in range(5):
        # heartbeat
        recs.append(_interrupt(u, t, run * 1000)); u += 1; t += 0.001
        # CRC probe
        recs.append(_bulk_out(u, t, "crc-enable")); u += 1; t += 0.003
        recs.append(_bulk_in(u,  t, f'ERROR invalid-crc "CRC suffix missing"')); u += 1; t += 0.001
        # CRC enable with CRC
        recs.append(_bulk_out(u, t, make_cmd("crc-enable"))); u += 1; t += 0.003
        recs.append(_bulk_in(u,  t, f"OK {DEVICE_SERIAL}")); u += 1; t += 0.001
        # main commands
        for name in ["ping", "checked-optiga-init", "checked-optiga-lock-check",
                     "checked-tropic-init", "checked-tropic-lock-check",
                     "checked-wpc-init", "checked-secrets-read"]:
            recs.append(_bulk_out(u, t, make_cmd(name))); u += 1; t += 0.010
            recs.append(_bulk_in(u,  t, f"OK {DEVICE_SERIAL}")); u += 1; t += 0.001
        # crc-disable
        recs.append(_bulk_out(u, t, make_cmd("crc-disable"))); u += 1; t += 0.003
        recs.append(_bulk_in(u,  t, f"OK {DEVICE_SERIAL}")); u += 1; t += 0.001
        t += 1.0  # gap between runs
    return build_pcap(recs)


def scenario_crc_probe_only():
    """CRC probe only — must be crc_probe event, NOT response_error."""
    recs = [
        _bulk_out(1, BASE_TS,       "crc-enable"),
        _bulk_in( 2, BASE_TS+0.003, f'ERROR invalid-crc "CRC suffix missing"'),
        _bulk_out(3, BASE_TS+0.004, make_cmd("crc-enable")),
        _bulk_in( 4, BASE_TS+0.007, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_timeout_then_error():
    """Timeout on one command → next command gets ERROR → causal hint expected."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
    ]
    t += 0.010
    # This command times out (no response, gap > segment_timeout_s)
    recs.append(_bulk_out(3, t, make_cmd("checked-optiga-init")))
    t += 35.0
    # Next command gets ERROR
    recs += [
        _bulk_out(5, t,       make_cmd("checked-optiga-lock-check")),
        _bulk_in( 6, t+0.004, 'ERROR dn-dp "Signal integrity fail"'),
    ]
    return build_pcap(recs)


def scenario_eproto_isolated():
    """EPROTO not near reconnect → usb_eproto_isolated critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        _eproto(  3, t+0.5),
        _bulk_out(4, t+1.0,   make_cmd("checked-optiga-init")),
        _bulk_in( 5, t+1.010, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_eproto_reconnect():
    """EPROTO immediately before reconnect → severity info, not critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        _eproto(  3, t+0.1),
    ]
    t += 0.3 + 6.5  # gap → reconnect
    for i in range(5):
        recs.append(_control(10 + i, t + i * 0.01))
    t += 1.0
    recs += [
        _bulk_out(20, t,       make_cmd("ping")),
        _bulk_in( 21, t+0.003, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_reconnect_mid_run():
    """Reconnect while run in progress → unexpected_disconnect critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        _bulk_out(3, t+0.010, make_cmd("checked-optiga-init")),
        _bulk_in( 4, t+0.020, f"OK {DEVICE_SERIAL}"),
    ]
    t += 0.025 + 32.0   # gap > 30s = unexpected during run
    for i in range(5):
        recs.append(_control(10 + i, t + i * 0.01))
    t += 1.0
    recs += [
        _bulk_out(20, t,       make_cmd("ping")),
        _bulk_in( 21, t+0.003, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_missing_crc():
    """checked-* command without CRC → missing_crc critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       "checked-optiga-lock-check"),   # no CRC
        _bulk_in( 2, t+0.003, 'ERROR invalid-crc "CRC suffix missing"'),
    ]
    return build_pcap(recs)


def scenario_crc_mismatch():
    """CRC present but wrong → crc_mismatch critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       "checked-optiga-init DEADBEEF"),  # wrong CRC
        _bulk_in( 2, t+0.003, 'ERROR invalid-crc "CRC mismatch"'),
    ]
    return build_pcap(recs)


def scenario_malformed_command():
    """Non-ASCII/empty command name → malformed_command critical."""
    t = BASE_TS
    bad_payload = b"\x00\x00\x00\x00\x00\x16\x25\x34\x42\r\n"
    pkt = _usbmon_header(1, "S", 3, 0x01, t, 0, len(bad_payload)) + bad_payload
    recs = [
        _pcap_record(t,       pkt),
        _bulk_in(2, t+0.003, 'ERROR invalid-crc "CRC suffix missing"'),
    ]
    return build_pcap(recs)


def scenario_incomplete_segment():
    """New command arrives before previous one is answered → incomplete_segment."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),         # never answered
        _bulk_out(3, t+0.002, make_cmd("checked-optiga-init")),  # new cmd arrives
        _bulk_in( 4, t+0.012, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_lock_regression():
    """Lock OK → lock-check returns OK NO → lock_regression critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("checked-optiga-lock")),
        _bulk_in( 2, t+0.010, f"OK {DEVICE_SERIAL}"),
        _bulk_out(3, t+0.020, make_cmd("checked-optiga-lock-check")),
        _bulk_in( 4, t+0.028, f"OK NO {_crc32('OK NO')}"),  # regression
    ]
    return build_pcap(recs)


def scenario_ok_no_before_lock():
    """lock-check returns OK NO before any lock → normal, no error expected."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("checked-optiga-lock-check")),
        _bulk_in( 2, t+0.008, f"OK NO {_crc32('OK NO')}"),  # normal before lock
    ]
    return build_pcap(recs)


def scenario_serial_mismatch():
    """Device serial changes within a run → serial_mismatch critical."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        _bulk_out(3, t+0.010, make_cmd("checked-optiga-init")),
        _bulk_in( 4, t+0.020, "OK AAAABBBB"),   # different serial!
    ]
    return build_pcap(recs)


def scenario_timing_spike():
    """10× normal latency on one command → timing_critical."""
    recs, t, u = [], BASE_TS, 1
    # 10 normal samples to build baseline (median ~10ms)
    for _ in range(10):
        recs += [_bulk_out(u, t, make_cmd("checked-optiga-init")),
                 _bulk_in(u+1, t+0.010, f"OK {DEVICE_SERIAL}")]
        u += 2; t += 0.200
    # spike: 300ms instead of ~10ms  (30× baseline)
    recs += [_bulk_out(u, t, make_cmd("checked-optiga-init")),
             _bulk_in(u+1, t+0.300, f"OK {DEVICE_SERIAL}")]
    return build_pcap(recs)


def scenario_heartbeat_counter_jump():
    """Heartbeat counter goes backward → heartbeat_anomaly."""
    recs, t = [], BASE_TS
    for i in range(6):
        recs.append(_interrupt(i, t, counter=i * 100))
        t += 0.008
    # Counter jumps backward: was 500, now 50
    recs.append(_interrupt(10, t, counter=50))
    t += 0.008
    recs.append(_interrupt(11, t, counter=51))
    return build_pcap(recs)


def scenario_lost_urb():
    """Submit without matching Complete within urb_window_s → lost_urb."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        # Submit with no Complete (lost packet)
        _bulk_out(3, t+0.010, make_cmd("checked-optiga-init")),
    ]
    t += 70.0  # beyond urb_window_s=60 → GC triggers lost_urb
    recs += [
        _bulk_out(5, t,       make_cmd("ping")),
        _bulk_in( 6, t+0.003, f"OK {DEVICE_SERIAL}"),
    ]
    return build_pcap(recs)


def scenario_run_incomplete():
    """Run starts but crc-disable never sent → run_incomplete warning."""
    t = BASE_TS
    recs = [
        _bulk_out(1, t,       make_cmd("ping")),
        _bulk_in( 2, t+0.003, f"OK {DEVICE_SERIAL}"),
        _bulk_out(3, t+0.010, make_cmd("checked-optiga-init")),
        _bulk_in( 4, t+0.020, f"OK {DEVICE_SERIAL}"),
        # file ends — crc-disable never sent
    ]
    return build_pcap(recs)


# ═════════════════════════════════════════════════════════════════════════════
# ANALYSIS RUNNER + ASSERT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def run_analysis(pcap_bytes, config=None):
    """
    Run full pipeline on raw PCAP bytes → (FlowStream, [ErrorEvent]).
    Raises SkipTest if required modules are not yet implemented.
    """
    for key in ("parser", "flow_builder"):
        if not _AVAILABLE.get(key):
            raise unittest.SkipTest(_SKIP_REASON.get(key, key))

    cfg = config or AnalysisConfig()

    with tempfile.NamedTemporaryFile(suffix=".pcap00", delete=False) as f:
        f.write(pcap_bytes)
        path = f.name
    try:
        packets = list(iter_usb_packets(path))
        stream  = build_flow_stream(packets, cfg)
        if _AVAILABLE.get("causal"):
            stream = enrich_causal(stream, cfg)
        errors = detect_errors(stream, cfg) if _AVAILABLE.get("detectors") else []
        return stream, errors
    finally:
        os.unlink(path)


def find_events(stream, **kwargs):
    return [e for e in stream.events
            if all(getattr(e, k, None) == v for k, v in kwargs.items())]


def find_errors(errors, event_type=None, layer=None, severity=None):
    return [e for e in errors
            if (event_type is None or e.event_type == event_type)
            and (layer is None or e.layer == layer)
            and (severity is None or e.severity == severity)]


def assert_event_present(stream, event_class, severity=None, message=""):
    events = find_events(stream, event_class=event_class)
    if severity:
        events = [e for e in events if e.severity == severity]
    assert events, (
        f"Expected FlowEvent(event_class={event_class!r}, severity={severity!r}) "
        f"not found. {message}\n"
        f"Got: {sorted(set(e.event_class for e in stream.events))}"
    )


def assert_no_event(stream, event_class, severity=None, message=""):
    events = find_events(stream, event_class=event_class)
    if severity:
        events = [e for e in events if e.severity == severity]
    assert not events, (
        f"Expected NO FlowEvent(event_class={event_class!r}, severity={severity!r}) "
        f"but found {len(events)}. {message}"
    )


def assert_error_present(errors, event_type, severity=None, message=""):
    found = find_errors(errors, event_type=event_type, severity=severity)
    assert found, (
        f"Expected ErrorEvent(event_type={event_type!r}, severity={severity!r}) "
        f"not found. {message}\n"
        f"Got: {sorted(set(e.event_type for e in errors))}"
    )


def assert_no_error(errors, event_type, message=""):
    found = find_errors(errors, event_type=event_type)
    assert not found, (
        f"Expected NO ErrorEvent(event_type={event_type!r}) "
        f"but found {len(found)}. {message}"
    )


# ═════════════════════════════════════════════════════════════════════════════
# TEST CLASSES
# ═════════════════════════════════════════════════════════════════════════════

@_needs("crc_util")
class TestCrcUtil(unittest.TestCase):
    """Unit tests for CRC computation and validation. Requires: crc_util."""

    def test_compute_returns_8hex(self):
        result = compute_crc32("checked-optiga-lock-check")
        self.assertEqual(len(result), 8)
        self.assertTrue(all(c in "0123456789ABCDEF" for c in result),
                        f"Not uppercase hex: {result}")

    def test_validate_correct(self):
        body = "checked-optiga-init"
        crc  = compute_crc32(body)
        valid, found = validate_crc(f"{body} {crc}")
        self.assertTrue(valid)
        self.assertEqual(found, crc)

    def test_validate_wrong(self):
        valid, found = validate_crc("checked-optiga-init DEADBEEF")
        self.assertFalse(valid)
        self.assertEqual(found, "DEADBEEF")

    def test_validate_missing(self):
        valid, found = validate_crc("checked-optiga-init")
        self.assertIsNone(valid)
        self.assertIsNone(found)

    def test_extract_serial_ok(self):
        self.assertEqual(extract_serial_from_response(f"OK {DEVICE_SERIAL}"), DEVICE_SERIAL)

    def test_extract_serial_ok_no(self):
        self.assertEqual(extract_serial_from_response(f"OK NO {DEVICE_SERIAL}"), DEVICE_SERIAL)

    def test_extract_serial_error_returns_none(self):
        self.assertIsNone(extract_serial_from_response('ERROR invalid-crc "x"'))

    def test_roundtrip_multiple_commands(self):
        cmds = ["ping", "crc-enable", "checked-tropic-lock-check",
                "checked-otp-device-sn-write 47304272600L00 --execute"]
        for cmd in cmds:
            crc   = compute_crc32(cmd)
            valid, _ = validate_crc(f"{cmd} {crc}")
            self.assertTrue(valid, f"CRC roundtrip failed for: {cmd!r}")


@_needs("parser", "flow_builder")
class TestNormalRun(unittest.TestCase):
    """Clean run produces zero critical/warning events. Requires: parser, flow_builder."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_normal())

    def test_no_critical_flow_events(self):
        crit = [e for e in self.stream.events if e.severity == "critical"]
        self.assertEqual(crit, [],
            f"Unexpected critical events: {[(e.event_class, e.content[:40]) for e in crit]}")

    def test_no_critical_errors(self):
        crit = [e for e in self.errors if e.severity == "critical"]
        self.assertEqual(crit, [],
            f"Unexpected errors: {[(e.event_type, e.description[:40]) for e in crit]}")

    def test_crc_probe_not_classified_as_error(self):
        assert_no_event(self.stream, "response_error",
                        message="CRC probe must not produce response_error")

    def test_crc_probe_event_present(self):
        assert_event_present(self.stream, "crc_probe")

    def test_ok_responses_present(self):
        self.assertGreater(len(find_events(self.stream, event_class="response_ok")), 0)

    def test_deterministic_output(self):
        pcap = scenario_normal()
        s1, e1 = run_analysis(pcap)
        s2, e2 = run_analysis(pcap)
        self.assertEqual(len(s1.events), len(s2.events),
                         "Same input must produce same number of events")
        self.assertEqual(len(e1), len(e2))


@_needs("parser", "flow_builder")
class TestCrcProbe(unittest.TestCase):
    """CRC probe correctly classified. Requires: parser, flow_builder."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_crc_probe_only())

    def test_probe_event_present(self):
        assert_event_present(self.stream, "crc_probe")

    def test_no_response_error(self):
        assert_no_event(self.stream, "response_error",
                        message="crc-enable ERROR must be crc_probe, not response_error")

    def test_no_missing_crc_error(self):
        assert_no_error(self.errors, "missing_crc",
                        message="crc-enable probe must not trigger missing_crc")

    def test_probe_severity_is_info_or_ok(self):
        probes = find_events(self.stream, event_class="crc_probe")
        self.assertTrue(probes, "No crc_probe events found")
        for p in probes:
            self.assertIn(p.severity, ("info", "ok"),
                          f"CRC probe severity must be info/ok, got: {p.severity!r}")


@_needs("parser", "flow_builder")
class TestTimeoutThenError(unittest.TestCase):
    """Timeout → ERROR sequence. Causal hint required. Requires: parser, flow_builder."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_timeout_then_error())

    def test_timeout_event_injected(self):
        assert_event_present(self.stream, "timeout")

    def test_error_event_present(self):
        assert_event_present(self.stream, "response_error")

    @_needs("causal")
    def test_error_has_causal_hint(self):
        err_events = find_events(self.stream, event_class="response_error")
        self.assertTrue(err_events)
        self.assertTrue(
            any(len(e.causal_hints) > 0 for e in err_events),
            f"response_error must have causal_hints. causal_window={err_events[0].causal_window}"
        )

    @_needs("causal")
    def test_causal_hint_mentions_timeout(self):
        err_events = find_events(self.stream, event_class="response_error")
        if err_events and err_events[0].causal_hints:
            hints = " ".join(err_events[0].causal_hints).lower()
            self.assertIn("timeout", hints)

    def test_timeout_source_hypothesis_set(self):
        timeouts = find_events(self.stream, event_class="timeout")
        if timeouts:
            self.assertIsNotNone(timeouts[0].timeout_source_hypothesis,
                                 "timeout_source_hypothesis must be set")


@_needs("parser", "flow_builder", "detectors")
class TestEprotoIsolated(unittest.TestCase):
    """Isolated EPROTO → critical. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_eproto_isolated())

    def test_usb_error_event_present(self):
        assert_event_present(self.stream, "usb_error")

    def test_isolated_eproto_is_critical(self):
        eprotos = find_events(self.stream, event_class="usb_error")
        self.assertTrue(any(e.severity == "critical" for e in eprotos),
                        f"Isolated EPROTO must be critical. Got: {[e.severity for e in eprotos]}")

    def test_isolated_error_type_emitted(self):
        assert_error_present(self.errors, "usb_eproto_isolated", severity="critical")


@_needs("parser", "flow_builder", "detectors")
class TestEprotoReconnect(unittest.TestCase):
    """EPROTO before reconnect → info, not critical. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_eproto_reconnect())

    def test_usb_error_event_present(self):
        assert_event_present(self.stream, "usb_error")

    def test_eproto_severity_info(self):
        eprotos = find_events(self.stream, event_class="usb_error")
        self.assertTrue(any(e.severity == "info" for e in eprotos),
                        f"EPROTO before reconnect must be info. Got: {[e.severity for e in eprotos]}")

    def test_no_isolated_eproto_error(self):
        assert_no_error(self.errors, "usb_eproto_isolated",
                        message="EPROTO before reconnect must NOT be usb_eproto_isolated")

    def test_reconnect_eproto_info_emitted(self):
        assert_error_present(self.errors, "usb_eproto_reconnect", severity="info")


@unittest.skip("unexpected_disconnect detector not yet implemented")
@_needs("parser", "flow_builder", "detectors")
class TestReconnectMidRun(unittest.TestCase):
    """Reconnect during run → unexpected_disconnect. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_reconnect_mid_run())

    def test_reconnect_event_present(self):
        assert_event_present(self.stream, "reconnect")

    def test_unexpected_disconnect_critical(self):
        assert_error_present(self.errors, "unexpected_disconnect", severity="critical")


@_needs("parser", "flow_builder", "detectors")
class TestMissingCrc(unittest.TestCase):
    """checked-* without CRC → missing_crc critical. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_missing_crc())

    def test_missing_crc_error(self):
        assert_error_present(self.errors, "missing_crc", severity="critical")

    def test_command_crc_expected_flag(self):
        cmds = find_events(self.stream, event_class="command")
        checked = [c for c in cmds if c.cmd_name and c.cmd_name.startswith("checked-")]
        self.assertTrue(any(c.cmd_crc_expected for c in checked))
        self.assertTrue(any(not c.cmd_crc for c in checked),
                        "Expected a checked-* command with cmd_crc=None")


@_needs("parser", "flow_builder", "crc_util", "detectors")
class TestCrcMismatch(unittest.TestCase):
    """CRC present but wrong → crc_mismatch. Requires: parser, flow_builder, crc_util, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_crc_mismatch())

    def test_crc_mismatch_error(self):
        assert_error_present(self.errors, "crc_mismatch", severity="critical")

    def test_cmd_crc_valid_false(self):
        cmds = find_events(self.stream, event_class="command")
        self.assertTrue(any(c.cmd_crc_valid is False for c in cmds),
                        "Expected FlowEvent with cmd_crc_valid=False")


@unittest.skip("malformed_command detector not yet implemented")
@_needs("parser", "flow_builder", "detectors")
class TestMalformedCommand(unittest.TestCase):
    """Non-ASCII command → malformed_command. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_malformed_command())

    def test_malformed_command_error(self):
        assert_error_present(self.errors, "malformed_command", severity="critical")


@_needs("parser", "flow_builder", "detectors")
class TestIncompleteSegment(unittest.TestCase):
    """New command before previous closed → incomplete_segment. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_incomplete_segment())

    def test_incomplete_segment_event(self):
        assert_event_present(self.stream, "incomplete_segment", severity="critical")

    def test_incomplete_segment_error(self):
        assert_error_present(self.errors, "incomplete_segment", severity="critical")


@_needs("parser", "flow_builder", "detectors")
class TestLockRegression(unittest.TestCase):
    """Lock OK then lock-check OK NO → lock_regression. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_lock_regression())

    def test_lock_regression_error(self):
        assert_error_present(self.errors, "lock_regression", severity="critical")

    @unittest.skip("lock_regression causal hint not yet implemented")
    @_needs("causal")
    def test_ok_no_has_causal_hint(self):
        ok_no = [e for e in self.stream.events
                 if e.event_class == "response_ok" and e.outcome == "ok_no"]
        self.assertTrue(ok_no)
        self.assertTrue(any(len(e.causal_hints) > 0 for e in ok_no),
                        "lock_regression OK NO must have causal hints")


@_needs("parser", "flow_builder", "detectors")
class TestOkNoBeforeLock(unittest.TestCase):
    """OK NO before any lock → no error. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_ok_no_before_lock())

    @unittest.skip("lock_regression context tracking (prior lock OK) not yet implemented")
    def test_no_lock_regression(self):
        assert_no_error(self.errors, "lock_regression",
                        message="OK NO before lock must NOT be lock_regression")

    def test_ok_no_event_present(self):
        ok_no = find_events(self.stream, event_class="response_ok", outcome="ok_no")
        self.assertTrue(ok_no, "Expected OK NO response event")

    def test_ok_no_not_critical(self):
        ok_no = find_events(self.stream, event_class="response_ok", outcome="ok_no")
        crit  = [e for e in ok_no if e.severity == "critical"]
        self.assertEqual(crit, [], "OK NO before lock must not be critical")


@unittest.skip("serial_mismatch detector not yet implemented")
@_needs("parser", "flow_builder", "detectors")
class TestSerialMismatch(unittest.TestCase):
    """Serial changes within run → serial_mismatch. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_serial_mismatch())

    def test_serial_mismatch_error(self):
        assert_error_present(self.errors, "serial_mismatch", severity="critical")


@_needs("parser", "flow_builder", "baseline", "detectors")
class TestTimingSpike(unittest.TestCase):
    """30× latency spike → timing_critical. Requires: parser, flow_builder, baseline, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_timing_spike())

    def test_timing_error_present(self):
        timing = [e for e in self.errors
                  if e.event_type in ("timing_high", "timing_critical")]
        self.assertTrue(timing, "Expected timing error for 30× latency spike")

    def test_timing_critical_severity(self):
        crit = [e for e in self.errors if e.event_type == "timing_critical"]
        self.assertTrue(crit, "Expected timing_critical for extreme latency spike")


@unittest.skip("heartbeat_anomaly detector not yet implemented")
@_needs("parser", "flow_builder", "detectors")
class TestHeartbeatCounterJump(unittest.TestCase):
    """Heartbeat counter backward jump → heartbeat_anomaly. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_heartbeat_counter_jump())

    def test_heartbeat_anomaly_event(self):
        assert_event_present(self.stream, "heartbeat_anomaly")

    def test_heartbeat_counter_jump_error(self):
        assert_error_present(self.errors, "heartbeat_counter_jump")


@_needs("parser", "flow_builder", "detectors")
class TestLostUrb(unittest.TestCase):
    """Submit without Complete → lost_urb. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_lost_urb())

    def test_lost_urb_event(self):
        assert_event_present(self.stream, "lost_urb")

    def test_lost_urb_error(self):
        assert_error_present(self.errors, "usb_lost_urb")


@unittest.skip("run_incomplete detector not yet implemented")
@_needs("parser", "flow_builder", "detectors")
class TestRunIncomplete(unittest.TestCase):
    """Run missing final commands → run_incomplete. Requires: parser, flow_builder, detectors."""

    def setUp(self):
        cfg = AnalysisConfig(
            run_end_commands=frozenset({"crc-disable", "checked-secrets-lock"}),
        )
        self.stream, self.errors = run_analysis(scenario_run_incomplete(), config=cfg)

    def test_run_incomplete_warning(self):
        assert_error_present(self.errors, "run_incomplete", severity="warning")


@_needs("parser", "flow_builder")
class TestFlowStreamProperties(unittest.TestCase):
    """Structural invariants of FlowStream. Requires: parser, flow_builder."""

    def setUp(self):
        self.stream, _ = run_analysis(scenario_normal())

    def test_seq_monotonically_increasing(self):
        seqs = [e.seq for e in self.stream.events]
        self.assertEqual(seqs, sorted(seqs))

    def test_seq_unique(self):
        seqs = [e.seq for e in self.stream.events]
        self.assertEqual(len(seqs), len(set(seqs)))

    def test_timestamps_monotonic(self):
        ts = [e.ts for e in self.stream.events]
        self.assertEqual(ts, sorted(ts))

    def test_paired_seq_exists_in_stream(self):
        seq_set = {e.seq for e in self.stream.events}
        for e in self.stream.events:
            if e.paired_seq is not None:
                self.assertIn(e.paired_seq, seq_set,
                              f"paired_seq={e.paired_seq} not in stream (event seq={e.seq})")

    def test_causal_window_refs_exist(self):
        seq_set = {e.seq for e in self.stream.events}
        for e in self.stream.events:
            for ref in e.causal_window:
                self.assertIn(ref, seq_set,
                              f"causal_window ref seq={ref} not in stream")

    def test_delta_ms_non_negative(self):
        for e in self.stream.events:
            if e.delta_ms is not None:
                self.assertGreaterEqual(e.delta_ms, 0,
                                        f"delta_ms={e.delta_ms} < 0 at seq={e.seq}")

    def test_response_latency_positive(self):
        for e in self.stream.events:
            if e.event_class in ("response_ok", "response_error") and e.latency_ms is not None:
                self.assertGreater(e.latency_ms, 0,
                                   f"latency_ms must be positive at seq={e.seq}")

    def test_stats_commands_count(self):
        actual = (len(find_events(self.stream, event_class="command")) +
                  len(find_events(self.stream, event_class="crc_probe")))
        self.assertEqual(self.stream.stats.commands_sent, actual)


@_needs("baseline", "store")
class TestBaseline(unittest.TestCase):
    """Baseline save/load. Requires: baseline, store."""

    def _baseline(self, serial: str) -> "DeviceBaseline":
        return DeviceBaseline(
            schema_version=1,
            device_serial=serial,
            sample_count=10,
            commands={
                "ping": CommandProfile(
                    cmd_name="ping",
                    sample_count=10,
                    outcome_distribution={"OK": 10},
                    latency_stats={"mean": 3.0, "std": 0.1, "median": 2.9, "mad": 0.1},
                    resp_line_count_stats={"mean": 1.0, "std": 0.0, "median": 1.0, "mad": 0.0},
                    payload_in_stats={"mean": 12.0, "std": 0.0, "median": 12.0, "mad": 0.0},
                    expected_at_positions=[1],
                )
            },
            known_expected_outliers=[],
        )

    def test_save_and_load(self):
        bl = self._baseline("TEST0001")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_baseline(bl, path)
            loaded = load_baseline(path)
            self.assertEqual(loaded.device_serial, "TEST0001")
            self.assertIn("ping", loaded.commands)
            self.assertAlmostEqual(loaded.commands["ping"].latency_stats["mean"], 3.0, places=3)
        finally:
            os.unlink(path)

    def test_schema_version_preserved(self):
        bl = self._baseline("VER01")
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            save_baseline(bl, path)
            loaded = load_baseline(path)
            self.assertEqual(loaded.schema_version, 1)
        finally:
            os.unlink(path)


@_needs("exporter", "parser", "flow_builder")
class TestExporters(unittest.TestCase):
    """All export formats produce valid output. Requires: exporter, parser, flow_builder."""

    def setUp(self):
        self.stream, self.errors = run_analysis(scenario_normal())

    def test_export_json_valid(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(self.stream, path)
            data = json.loads(Path(path).read_text())
            self.assertIn("events", data)
            self.assertIsInstance(data["events"], list)
            self.assertGreater(len(data["events"]), 0)
        finally:
            os.unlink(path)

    def test_export_csv_has_expected_columns(self):
        import csv
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        try:
            export_csv(self.stream, path)
            rows = list(csv.DictReader(open(path)))
            self.assertGreater(len(rows), 0)
            for col in ("seq", "event_class", "severity", "direction"):
                self.assertIn(col, rows[0], f"CSV missing column: {col}")
        finally:
            os.unlink(path)

    def test_export_junit_valid_xml(self):
        import xml.etree.ElementTree as ET
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            path = f.name
        try:
            export_junit_xml(self.stream, self.errors, path)
            root = ET.parse(path).getroot()
            self.assertIn(root.tag, ("testsuites", "testsuite"))
        finally:
            os.unlink(path)

    def test_export_html_is_html(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            path = f.name
        try:
            export_html_report(self.stream, self.errors, None, path)
            content = Path(path).read_text().lower()
            self.assertIn("<html", content)
        finally:
            os.unlink(path)


@_needs("aggregator", "parser", "flow_builder")
class TestAggregation(unittest.TestCase):
    """Multi-file aggregation. Requires: aggregator, parser, flow_builder."""

    def test_aggregate_three_testers(self):
        scenarios = [
            ("tester-001.pcap00", scenario_normal()),
            ("tester-007.pcap00", scenario_eproto_isolated()),
            ("tester-129.pcap00", scenario_normal()),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            for name, data in scenarios:
                Path(tmpdir, name).write_bytes(data)
            report = aggregate_directory(tmpdir)

        self.assertEqual(len(report.tester_stats), 3)
        ids = [t.tester_id for t in report.tester_stats]
        for name, _ in scenarios:
            self.assertIn(name, ids)

    def test_outlier_tester_detected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(4):
                Path(tmpdir, f"tester-{i:03d}.pcap00").write_bytes(scenario_normal())
            # Outlier with errors
            Path(tmpdir, "tester-999.pcap00").write_bytes(scenario_timeout_then_error())
            report = aggregate_directory(tmpdir)

        self.assertIn("tester-999.pcap00", report.outlier_testers,
                      f"tester-999 must be outlier. Got: {report.outlier_testers}")

    def test_error_heatmap_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "a.pcap00").write_bytes(scenario_normal())
            Path(tmpdir, "b.pcap00").write_bytes(scenario_eproto_isolated())
            report = aggregate_directory(tmpdir)
        self.assertIsInstance(report.error_heatmap, dict)


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════

def _print_module_status():
    print()
    print("Module availability:")
    modules = [
        ("config",       "AnalysisConfig"),
        ("parser",       "iter_usb_packets + UsbPacket"),
        ("flow_builder", "build_flow_stream + FlowEvent"),
        ("causal",       "enrich_causal"),
        ("detectors",    "detect_errors"),
        ("crc_util",     "compute_crc32 + validate_crc"),
        ("baseline",     "DeviceBaseline + CommandProfile"),
        ("store",        "save/load_baseline"),
        ("aggregator",   "aggregate_directory"),
        ("exporter",     "export_json/csv/html/junit"),
    ]
    for key, desc in modules:
        if _AVAILABLE.get(key):
            print(f"  ✓  {key:15s}  {desc}")
        else:
            reason = _SKIP_REASON.get(key, "not found")
            print(f"  ✗  {key:15s}  {desc}  ← {reason}")
    print()


if __name__ == "__main__":
    print("USB Flow Analyzer — Smoke Test")
    print("=" * 60)
    print(f"Python  : {sys.version.split()[0]}")
    print(f"Time    : {time.strftime('%Y-%m-%d %H:%M:%S')}")

    _print_module_status()

    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        cls_name = sys.argv.pop(1)
        cls = globals().get(cls_name)
        if not cls:
            available = [k for k, v in globals().items()
                         if isinstance(v, type) and issubclass(v, unittest.TestCase)
                         and v is not unittest.TestCase]
            print(f"Unknown test class: {cls_name}")
            print(f"Available: {available}")
            sys.exit(1)
        suite.addTests(loader.loadTestsFromTestCase(cls))
    else:
        for name, obj in sorted(globals().items()):
            if (isinstance(obj, type) and issubclass(obj, unittest.TestCase)
                    and obj is not unittest.TestCase):
                suite.addTests(loader.loadTestsFromTestCase(obj))

    verbosity = 2 if "-v" in sys.argv else 1
    runner = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stdout)
    result = runner.run(suite)

    print()
    print("=" * 60)
    n_skip = len(result.skipped)
    n_run  = result.testsRun - n_skip
    if result.wasSuccessful():
        print(f"✓  {n_run} passed  |  {n_skip} skipped (module not yet implemented)")
    else:
        n_fail = len(result.failures) + len(result.errors)
        print(f"✗  {n_fail} failed  |  {n_run - n_fail} passed  |  {n_skip} skipped")
        sys.exit(1)
