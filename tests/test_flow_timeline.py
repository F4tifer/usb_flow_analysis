"""Tests for USB flow timeline (direction + gaps)."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from usb_analysis.flow_timeline import build_flow_timeline
from usb_analysis.models import EVENT_COMPLETE, EVENT_SUBMIT
from usb_analysis.pipeline import iter_mmap_packets

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_mmap.pcap"


def _hdr(**kwargs):
    defaults = dict(
        urb_id=1,
        event_type=EVENT_SUBMIT,
        transfer_type=3,
        endpoint_number=1,
        device_address=2,
        bus_id=1,
        setup_flag=1,
        data_flag=1,
        ts_sec=0,
        ts_usec=0,
        status=0,
        urb_total_len=0,
        data_presence_len=0,
        union_payload=b"",
        interval_frames=0,
        start_frame=0,
        xfer_flags=0,
        ndesc=0,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_gap_inserted_when_threshold_exceeded():
    p1 = SimpleNamespace(
        ordinal=1,
        pcap_ts_sec=0,
        pcap_ts_usec=0,
        payload=b"hello\n",
        truncation_note=None,
        header=_hdr(event_type=EVENT_SUBMIT),
    )
    p2 = SimpleNamespace(
        ordinal=2,
        pcap_ts_sec=10,
        pcap_ts_usec=0,
        payload=b"world\n",
        truncation_note=None,
        header=_hdr(event_type=EVENT_COMPLETE),
    )
    rows = build_flow_timeline([p1, p2], gap_threshold_s=2.0)
    assert len(rows) == 3
    assert rows[0]["kind"] == "urb"
    assert rows[1]["kind"] == "gap"
    assert rows[1]["gap_s"] == pytest.approx(10.0)
    assert rows[2]["kind"] == "urb"


def test_gap_disabled_when_threshold_zero():
    p1 = SimpleNamespace(
        ordinal=1,
        pcap_ts_sec=0,
        pcap_ts_usec=0,
        payload=b"",
        truncation_note=None,
        header=_hdr(),
    )
    p2 = SimpleNamespace(
        ordinal=2,
        pcap_ts_sec=100,
        pcap_ts_usec=0,
        payload=b"",
        truncation_note=None,
        header=_hdr(),
    )
    rows = build_flow_timeline([p1, p2], gap_threshold_s=0)
    assert len(rows) == 2
    assert all(r["kind"] == "urb" for r in rows)


def test_direction_labels():
    out = SimpleNamespace(
        ordinal=0,
        pcap_ts_sec=0,
        pcap_ts_usec=0,
        payload=b"x",
        truncation_note=None,
        header=_hdr(endpoint_number=1, transfer_type=3),
    )
    inn = SimpleNamespace(
        ordinal=1,
        pcap_ts_sec=0,
        pcap_ts_usec=1,
        payload=b"y",
        truncation_note=None,
        header=_hdr(endpoint_number=0x81, transfer_type=3),
    )
    rows = build_flow_timeline([out, inn], gap_threshold_s=99)
    assert rows[0]["direction"] == "to_device"
    assert rows[0]["label"] == "TESTER→device"
    assert rows[1]["direction"] == "from_device"
    assert rows[1]["label"] == "device→TESTER"


def test_bulk_only_filters():
    bulk = SimpleNamespace(
        ordinal=0,
        pcap_ts_sec=1,
        pcap_ts_usec=0,
        payload=b"",
        truncation_note=None,
        header=_hdr(transfer_type=3),
    )
    ctl = SimpleNamespace(
        ordinal=1,
        pcap_ts_sec=2,
        pcap_ts_usec=0,
        payload=b"",
        truncation_note=None,
        header=_hdr(transfer_type=2),
    )
    rows = build_flow_timeline([bulk, ctl], gap_threshold_s=0, bulk_only=True)
    assert len(rows) == 1
    assert rows[0]["ordinal"] == 0


def test_dn_dp_highlights():
    pkt = SimpleNamespace(
        ordinal=0,
        pcap_ts_sec=0,
        pcap_ts_usec=0,
        payload=b"ERR DN/timeout\n",
        truncation_note=None,
        header=_hdr(),
    )
    rows = build_flow_timeline([pkt], gap_threshold_s=0)
    assert "dn_token" in rows[0]["highlights"]


def test_fixture_single_urb_row():
    rows = list(iter_mmap_packets(FIXTURE))
    assert len(rows) == 1
    assert rows[0].header.transfer_type == 1  # Interrupt
    timeline = build_flow_timeline(rows, gap_threshold_s=0)
    assert len(timeline) == 1
    assert timeline[0]["kind"] == "urb"
    assert timeline[0]["transfer_type"] == "Interrupt"
    assert timeline[0]["urb_id"] == hex(rows[0].header.urb_id)
