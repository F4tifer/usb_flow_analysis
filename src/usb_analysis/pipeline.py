"""High-level iterator over PCAP with USB mmap decoding."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from usb_analysis.models import DLT_USB_LINUX_MMAPPED, ParsedPacket
from usb_analysis.pcap import iter_pcap_packets, read_global_header
from usb_analysis.usb_mmap import parse_mapped_packet_body


def peek_pcap_globals(path: Path | str):
    """Return PCAP global header (`PcapGlobals`)."""
    path = Path(path)
    with path.open("rb") as f:
        return read_global_header(f)


def ensure_mmap_link(path: Path | str) -> None:
    g = peek_pcap_globals(path)
    if g.network != DLT_USB_LINUX_MMAPPED:
        raise RuntimeError(
            f"Expected PCAP link type {DLT_USB_LINUX_MMAPPED} (USB_LINUX_MMAPPED), got {g.network}"
        )


def iter_mmap_packets(path: Path | str) -> Iterator[ParsedPacket]:
    """Yield parsed packets from a PCAP with LINKTYPE_USB_LINUX_MMAPPED."""
    path = Path(path)
    ensure_mmap_link(path)

    for ordinal, ts_sec, ts_usec, caplen, orig_len, body in iter_pcap_packets(path):
        pkt: ParsedPacket = parse_mapped_packet_body(
            body,
            ordinal=ordinal,
            pcap_ts_sec=ts_sec,
            pcap_ts_usec=ts_usec,
            caplen=caplen,
            origlen=orig_len,
        )
        yield pkt
