"""Packet filter helpers."""

from __future__ import annotations

from usb_analysis.models import ParsedPacket


def matches(pkt: ParsedPacket, *, bus: int | None, device: int | None, endpoint: int | None) -> bool:
    h = pkt.header
    if bus is not None and h.bus_id != bus:
        return False
    if device is not None and h.device_address != device:
        return False
    if endpoint is not None:
        if (h.endpoint_number & 0x7F) != (endpoint & 0x7F):
            return False
    return True
