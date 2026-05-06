"""Decode LINKTYPE_USB_LINUX_MMAPPED link-layer payload."""

from __future__ import annotations

import struct

from usb_analysis.models import (
    LINUX_USB_ISO_DESC_LEN,
    USB_MAPPED_HDR_LEN,
    ParsedPacket,
    UsbMappedHeader,
)

# Packed layout mirrors libpcap `pcap_usb_header_mmapped` (little-endian).
_HDR_FMT = "<QBBBBHbb qii II 8s iiiI"


def decode_usb_mapped_header(blob: bytes) -> UsbMappedHeader:
    if len(blob) < USB_MAPPED_HDR_LEN:
        raise ValueError("USB mmap header truncated")
    (
        urb_id,
        et,
        tt,
        ep,
        da,
        bus,
        sf,
        df,
        ts_sec,
        ts_usec,
        status,
        urb_total,
        data_len,
        uni,
        iv,
        stf,
        xf,
        nd,
    ) = struct.unpack_from(_HDR_FMT, blob, 0)

    union_bytes = uni if isinstance(uni, (bytes, bytearray)) else bytes(uni)

    return UsbMappedHeader(
        urb_id=int(urb_id),
        event_type=int(et),
        transfer_type=int(tt),
        endpoint_number=int(ep),
        device_address=int(da),
        bus_id=int(bus),
        setup_flag=int(sf),
        data_flag=int(df),
        ts_sec=int(ts_sec),
        ts_usec=int(ts_usec),
        status=int(status),
        urb_total_len=int(urb_total),
        data_presence_len=int(data_len),
        union_payload=bytes(union_bytes),
        interval_frames=int(iv),
        start_frame=int(stf),
        xfer_flags=int(xf),
        ndesc=int(nd),
    )


def _slice_after_header(
    cap_body: bytes, hdr: UsbMappedHeader
) -> tuple[bytes, bytes | None, bytes, str | None]:
    """Split cap_body (link payload after 64 B header) into iso blob, setup, data."""
    off = 0
    note: str | None = None

    iso_blob = b""
    if hdr.ndesc > 0:
        need = hdr.ndesc * LINUX_USB_ISO_DESC_LEN
        take = min(need, len(cap_body) - off)
        if take < need:
            note = f"iso_desc_truncated(want {need}, have {take})"
        iso_blob = cap_body[off : off + take]
        off += take

    setup: bytes | None = None
    if hdr.transfer_type == 2 and hdr.setup_flag == 0 and len(cap_body) - off >= 8:
        setup = cap_body[off : off + 8]
        off += 8

    payload = b""
    if hdr.data_flag == 0:
        payload = memoryview(cap_body)[off:].tobytes()
        claim = hdr.data_presence_len
        if claim and len(payload) < claim and note is None:
            note = f"payload_short_claim_{claim}_cap_{len(payload)}"

    return iso_blob, setup, payload, note


def parse_mapped_packet_body(
    cap_body: bytes, *, ordinal: int, pcap_ts_sec: int, pcap_ts_usec: int, caplen: int, origlen: int
) -> ParsedPacket:
    """Parse full link-layer buffer (cap body) for LINUX USB MMAPPED."""
    hdr = decode_usb_mapped_header(cap_body[:USB_MAPPED_HDR_LEN])
    rest = cap_body[USB_MAPPED_HDR_LEN:]
    iso_blob, setup, payload, note = _slice_after_header(rest, hdr)

    return ParsedPacket(
        ordinal=ordinal,
        pcap_ts_sec=pcap_ts_sec,
        pcap_ts_usec=pcap_ts_usec,
        caplen=caplen,
        origlen=origlen,
        header=hdr,
        iso_descriptors_blob=iso_blob,
        setup_packet=setup,
        payload=payload,
        truncation_note=note,
    )
