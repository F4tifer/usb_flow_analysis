import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from usb_analysis.pipeline import iter_mmap_packets, peek_pcap_globals
from usb_analysis.stream_text import build_text_stream
from usb_analysis.trezor import TrezorDecoder
from trezorlib import mapping, messages


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_mmap.pcap"
# Optional large sample for local regression checks. Override via env var.
_TREZOR_PATH = os.environ.get("USB_ANALYSIS_LARGE_SAMPLE")
TREZOR = Path(_TREZOR_PATH) if _TREZOR_PATH else None


def test_fixture_accepts_mmap_linktype():
    glob = peek_pcap_globals(FIXTURE)
    assert glob.network == 220


def test_one_packet_decode():
    rows = list(iter_mmap_packets(FIXTURE))
    assert len(rows) == 1
    pkt = rows[0]
    assert pkt.caplen == 64
    assert pkt.header.transfer_type == 1  # interrupt in sample trace
    assert pkt.header.bus_id >= 1


@pytest.mark.skipif(
    TREZOR is None or not TREZOR.is_file(),
    reason="Set USB_ANALYSIS_LARGE_SAMPLE to a Trezor pcap path to enable",
)
def test_large_sample_reads_first_bulk():
    for pkt in iter_mmap_packets(TREZOR):
        if pkt.header.transfer_type == 3:  # bulk
            assert pkt.ordinal >= 0
            assert isinstance(pkt.payload, bytes)
            break


def test_wrong_linktype_errors(tmp_path):
    junk = Path(tmp_path / "bad.pcap")
    # Minimal LE micro pcap globals with ethernet link instead of usb
    junk.write_bytes(bytes.fromhex("d4c3b2a102000400000000000000000040c0030001000000"))
    with pytest.raises(RuntimeError):
        next(iter_mmap_packets(junk))


def test_trezor_decoder_start_and_continuation():
    dec = TrezorDecoder()
    hdr = SimpleNamespace(bus_id=1, device_address=3, endpoint_index=1, is_in_transfer=True)

    # report-id 0x3f + "##" + type 17 + len 6 + first 3 bytes
    p1 = SimpleNamespace(header=hdr, payload=bytes.fromhex("3f2323001100000006616263"))
    d1 = dec.decode_packet(p1)
    assert d1 is not None
    assert d1["frame"] == "start"
    assert d1["message_type_id"] == 17
    assert d1["is_complete"] is False

    # continuation with remaining 3 bytes
    p2 = SimpleNamespace(header=hdr, payload=b"def")
    d2 = dec.decode_packet(p2)
    assert d2 is not None
    assert d2["frame"] == "continuation"
    assert d2["is_complete"] is True
    assert d2["collected_len"] == 6


def test_trezor_decoder_protobuf_layer():
    dec = TrezorDecoder()
    hdr = SimpleNamespace(bus_id=1, device_address=3, endpoint_index=1, is_in_transfer=True)

    msg_type, msg_bytes = mapping.DEFAULT_MAPPING.encode(messages.Initialize())
    frame = b"##" + msg_type.to_bytes(2, "big") + len(msg_bytes).to_bytes(4, "big") + msg_bytes
    pkt = SimpleNamespace(header=hdr, payload=b"\x3f" + frame)
    out = dec.decode_packet(pkt)

    assert out is not None
    assert out["is_complete"] is True
    assert out["protobuf"]["decoder"] == "trezorlib"
    assert out["protobuf"]["message_name"] == "Initialize"


def test_trezor_decoder_raw_fallback():
    dec = TrezorDecoder()
    hdr = SimpleNamespace(bus_id=2, device_address=4, endpoint_index=1, is_in_transfer=True)
    out = dec.decode_packet(SimpleNamespace(header=hdr, payload=bytes.fromhex("01094c57336400")))
    assert out is not None
    assert out["frame"] == "raw_report"
    assert out["report_id"] == 0x01
    assert out["report_tag"] == 0x09


def test_build_text_stream_lines():
    hdr_host = SimpleNamespace(is_in_transfer=False)
    hdr_dev = SimpleNamespace(is_in_transfer=True)
    p1 = SimpleNamespace(header=hdr_host, payload=b"ping\r\n", ordinal=1)
    p2 = SimpleNamespace(header=hdr_dev, payload=b"OK\r\n", ordinal=2)
    rows = build_text_stream([p1, p2])
    assert rows[0]["speaker"] == "host"
    assert rows[0]["line"] == "ping"
    assert rows[1]["speaker"] == "device"
    assert rows[1]["line"] == "OK"
