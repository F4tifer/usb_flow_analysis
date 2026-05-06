"""Serialize parsed packets for API/CLI/export."""

from __future__ import annotations

from typing import Any

from usb_analysis.models import event_type_char, transfer_type_name
from usb_analysis.pcap import pcap_wall_ts_sec


def packet_record(pkt: Any, trezor_decoded: dict[str, Any] | None = None) -> dict[str, Any]:
    h = pkt.header
    row = {
        "ordinal": pkt.ordinal,
        "pcap_ts": pcap_wall_ts_sec(pkt.pcap_ts_sec, pkt.pcap_ts_usec),
        "kernel_ts_sec": h.ts_sec,
        "kernel_ts_usec": h.ts_usec,
        "urb_id": hex(h.urb_id),
        "event": event_type_char(h.event_type),
        "transfer_type": transfer_type_name(h.transfer_type),
        "bus_id": h.bus_id,
        "device_address": h.device_address,
        "endpoint": h.endpoint_number,
        "endpoint_index": h.endpoint_index,
        "is_in": h.is_in_transfer,
        "status": h.status,
        "caplen": pkt.caplen,
        "origlen": pkt.origlen,
        "payload_hex": pkt.payload.hex(),
        "payload_len": len(pkt.payload),
        "setup_hex": pkt.setup_packet.hex() if pkt.setup_packet else "",
        "note": pkt.truncation_note or "",
    }
    if trezor_decoded is not None:
        row["trezor"] = trezor_decoded
    return row
