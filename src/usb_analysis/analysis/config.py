"""Central config for deep USB analysis + flow analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class AnalysisConfig:
    segment_end_prefixes: tuple[str, ...] = ("OK", "ERROR")
    progress_prefix: str = "#"
    line_encoding: str = "ascii"
    max_segment_lines: int = 50

    min_samples_for_ml: int = 20
    anomaly_score_threshold: float = 0.5
    latency_z_threshold: float = 3.0

    baseline_path: str = "~/.usb_analysis/baseline.json"
    baseline_schema_version: int = 1

    stream_chunk_size: int = 65536
    usbmon_header_size: int = 64

    # Flow builder
    segment_timeout_s: float = 30.0
    segment_max_resp_bytes: int = 65536
    run_end_commands: frozenset[str] = frozenset({"crc-disable", "checked-secrets-lock"})
    run_start_commands: frozenset[str] = frozenset({"ping"})

    # Timeout / causal
    timeout_warning_ms: float = 500.0
    timeout_critical_multiplier: float = 5.0
    causal_window_size: int = 10
    causal_suspect_classes: frozenset[str] = frozenset(
        {"timeout", "response_error", "usb_error", "incomplete_segment", "reconnect", "lost_urb"}
    )

    # USB / reconnect / heartbeat
    ignored_usb_status: frozenset[int] = frozenset({0, -2, -115})
    error_usb_status: frozenset[int] = frozenset({-71})
    # Window in which a USB EPROTO event is correlated with a subsequent reconnect.
    # Reconnects often appear several seconds after the last bulk activity, so the
    # window must be wide enough to span typical reset durations.
    reconnect_eproto_window_s: float = 10.0
    reconnect_gap_s: float = 5.0
    unexpected_gap_s: float = 30.0
    heartbeat_dropout_ms: float = 500.0
    heartbeat_dead_s: float = 60.0

    # Protocol
    crc_required_prefix: str = "checked-"
    known_no_crc_commands: frozenset[str] = frozenset({"ping", "crc-enable", "crc-disable"})
    crc_probe_commands: frozenset[str] = frozenset({"crc-enable", "crc-disable"})
    # Commands whose first argument carries the *DUT* (device-under-test) serial
    # number — independent from `OK <SN>` responses (which are the tester's
    # internal serial). Tracking the DUT serial lets us identify each physical
    # piece of hardware across runs in one capture.
    device_sn_write_commands: frozenset[str] = frozenset({"checked-otp-device-sn-write"})

    # Timing
    timing_mad_multiplier: float = 5.0
    timing_critical_multiplier: float = 15.0
    timing_min_samples: int = 10
    timing_suspiciously_low_ratio: float = 0.5

    # URB tracking
    urb_window_s: float = 60.0

    # Heartbeat payload parsing
    heartbeat_model_offset: int = 2
    heartbeat_model_len: int = 4
    heartbeat_counter_offset: int = 52

    expected_command_sequence: list[str] = field(default_factory=list)
    multi_file_glob: str = "*.pcap*"

    @property
    def baseline_path_resolved(self) -> Path:
        return Path(self.baseline_path).expanduser().resolve()

