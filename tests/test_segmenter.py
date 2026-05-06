from types import SimpleNamespace

from usb_analysis.analysis.segmenter import segment_packets
from usb_analysis.models import EVENT_COMPLETE, EVENT_SUBMIT


def _pkt(*, is_in, event, payload, ordinal):
    header = SimpleNamespace(transfer_type=3, endpoint_index=1, is_in_transfer=is_in, event_type=event)
    return SimpleNamespace(
        header=header,
        payload=payload,
        ordinal=ordinal,
        pcap_ts_sec=1000 + ordinal,
        pcap_ts_usec=0,
    )


def test_segmenter_command_response_boundary():
    packets = [
        _pkt(is_in=False, event=EVENT_SUBMIT, payload=b"ping\r\n", ordinal=1),
        _pkt(is_in=True, event=EVENT_COMPLETE, payload=b"OK D736D92D\r\n", ordinal=2),
        _pkt(is_in=False, event=EVENT_SUBMIT, payload=b"crc-enable\r\n", ordinal=3),
        _pkt(
            is_in=True,
            event=EVENT_COMPLETE,
            payload=b'ERROR invalid-crc "CRC suffix missing"\r\n',
            ordinal=4,
        ),
    ]
    segs = segment_packets(packets, source_file="synthetic")
    assert len(segs) == 2
    assert segs[0].cmd_name == "ping"
    assert segs[0].outcome == "OK"
    assert segs[0].device_serial == "D736D92D"
    assert segs[1].cmd_name == "crc-enable"
    assert segs[1].outcome == "ERROR"


def test_segmenter_unfinished_segment_marked_timeout():
    """Last command without a response must close as TIMEOUT, not be dropped."""
    packets = [
        _pkt(is_in=False, event=EVENT_SUBMIT, payload=b"ping\r\n", ordinal=1),
        _pkt(is_in=True, event=EVENT_COMPLETE, payload=b"OK D736D92D\r\n", ordinal=2),
        _pkt(is_in=False, event=EVENT_SUBMIT, payload=b"checked-init\r\n", ordinal=3),
    ]
    segs = segment_packets(packets, source_file="synthetic")
    assert len(segs) == 2
    assert segs[1].cmd_name == "checked-init"
    assert segs[1].outcome == "TIMEOUT"
    # ts_resp must use the last packet's wall-clock time, not pcap_ts_sec only.
    assert segs[1].ts_resp == packets[-1].pcap_ts_sec + packets[-1].pcap_ts_usec / 1_000_000.0


def test_segmenter_empty_input():
    assert segment_packets([], source_file="empty") == []

