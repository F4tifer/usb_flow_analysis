"""CRC helpers for text protocol lines."""

from __future__ import annotations

import binascii
import re

CRC_PATTERN = re.compile(r"\b([0-9A-Fa-f]{8})\s*$")


def strip_crc_suffix(text: str) -> str:
    return CRC_PATTERN.sub("", text).rstrip()


def compute_crc32(text: str) -> str:
    body = strip_crc_suffix(text)
    # The protocol uses ASCII only. latin-1 gives a deterministic 1:1 byte mapping
    # for any non-ASCII content so the CRC reflects the actual bytes on the wire.
    crc = binascii.crc32(body.encode("latin-1", errors="replace")) & 0xFFFFFFFF
    return f"{crc:08X}"


def validate_crc(raw_line: str) -> tuple[bool | None, str | None]:
    m = CRC_PATTERN.search(raw_line.rstrip())
    if not m:
        return None, None
    found = m.group(1).upper()
    body = raw_line[: m.start()].rstrip()
    expected = compute_crc32(body)
    return found == expected, found


def extract_serial_from_response(response_line: str) -> str | None:
    m = re.match(r"OK(?:\s+NO)?\s+([0-9A-Fa-f]{8})\s*$", response_line.strip())
    return m.group(1).upper() if m else None
