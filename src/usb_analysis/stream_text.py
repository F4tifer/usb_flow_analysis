"""USB packet-to-text stream extraction (Wireshark follow-stream style)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class _Buffer:
    text: str = ""


def _speaker(pkt: Any) -> str:
    return "device" if pkt.header.is_in_transfer else "host"


def to_printable_ascii(payload: bytes) -> str:
    chars: list[str] = []
    for b in payload:
        if b in (9, 10, 13) or 32 <= b <= 126:
            chars.append(chr(b))
    return "".join(chars)


_to_printable_ascii = to_printable_ascii


def _looks_meaningful(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    prefixes = (
        "#",
        "checked-",
        "OK",
        "ping",
        "crc-",
        "WPC",
        "Updating",
        "Testing",
        "Writing",
        "Bytes",
        "Locking",
        "Trezor",
    )
    if s.startswith(prefixes):
        return True
    tokens = s.split()
    if len(tokens) < 2:
        return False
    letters = sum(ch.isalpha() for ch in s)
    return letters >= 3 and any(len(tok) >= 3 for tok in tokens)


def build_text_stream(
    packets: list[Any],
    *,
    include_empty_lines: bool = False,
    meaningful_only: bool = True,
) -> list[dict[str, Any]]:
    """Return line-oriented stream entries from packet payloads."""
    buffers: dict[str, _Buffer] = {"host": _Buffer(), "device": _Buffer()}
    out: list[dict[str, Any]] = []

    for pkt in packets:
        payload = pkt.payload
        if not payload:
            continue
        speaker = _speaker(pkt)
        chunk = _to_printable_ascii(payload)
        if not chunk:
            continue

        buf = buffers[speaker]
        buf.text += chunk

        while "\n" in buf.text:
            line, rest = buf.text.split("\n", 1)
            buf.text = rest
            line = line.rstrip("\r")
            if (line or include_empty_lines) and (not meaningful_only or _looks_meaningful(line)):
                out.append(
                    {
                        "ordinal": pkt.ordinal,
                        "speaker": speaker,
                        "line": line,
                    }
                )

    # Flush tails without newline.
    for speaker, buf in buffers.items():
        tail = buf.text.rstrip("\r")
        if tail:
            out.append({"ordinal": None, "speaker": speaker, "line": tail, "tail": True})

    return out
