"""Data models for Linux USB mmap capture parsing."""

from __future__ import annotations

from dataclasses import dataclass, field


# LINKTYPE_USB_LINUX_MMAPPED (see libpcap)
DLT_USB_LINUX_MMAPPED = 220


USB_MAPPED_HDR_LEN = 64

# Isoch descriptor size in mmap trace (matches Wireshark wiretap / kernel alignment)
LINUX_USB_ISO_DESC_LEN = 24

_TRANSFER_NAMES = ("Isochronous", "Interrupt", "Control", "Bulk")


def transfer_type_name(tt: int) -> str:
    if 0 <= tt < len(_TRANSFER_NAMES):
        return _TRANSFER_NAMES[tt]
    return f"Unknown({tt})"


EVENT_SUBMIT = ord("S")
EVENT_COMPLETE = ord("C")
EVENT_ERROR = ord("E")


def event_type_char(b: int) -> str | None:
    if 32 <= b < 127:
        return chr(b)
    return None


@dataclass(frozen=True, slots=True)
class UsbMappedHeader:
    """Parsed `pcap_usb_header_mmapped` (little-endian)."""

    urb_id: int
    event_type: int  # ASCII: S / C / E / …
    transfer_type: int
    endpoint_number: int  # raw: MSB = IN if set (linux usb convention)
    device_address: int
    bus_id: int
    setup_flag: int
    data_flag: int
    ts_sec: int
    ts_usec: int
    status: int
    urb_total_len: int
    data_presence_len: int
    union_payload: bytes
    interval_frames: int
    start_frame: int
    xfer_flags: int
    ndesc: int

    @property
    def endpoint_index(self) -> int:
        return self.endpoint_number & 0x7F

    @property
    def is_in_transfer(self) -> bool:
        return (self.endpoint_number & 0x80) != 0


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    """One PCAP packet with decoded USB mmap layer."""

    ordinal: int
    pcap_ts_sec: int
    pcap_ts_usec: int
    caplen: int
    origlen: int
    header: UsbMappedHeader
    iso_descriptors_blob: bytes
    setup_packet: bytes | None
    payload: bytes
    truncation_note: str | None = None
