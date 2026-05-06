"""Best-effort Trezor HID framing decoder."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

try:
    from trezorlib import mapping as trezor_mapping
except Exception:  # pragma: no cover - optional dependency fallback
    trezor_mapping = None


def _stream_key(pkt: Any) -> tuple[int, int, int, bool]:
    h = pkt.header
    return (h.bus_id, h.device_address, h.endpoint_index, h.is_in_transfer)


def _strip_report_id(payload: bytes) -> bytes:
    # Trezor on HID often uses 64-byte report with report id 0x3F in traces.
    if payload and payload[0] == 0x3F:
        return payload[1:]
    return payload


@dataclass(slots=True)
class _State:
    msg_type: int
    total_len: int
    collected: bytes


class TrezorDecoder:
    """Decode Trezor-style HID framing and reassemble multi-packet messages."""

    def __init__(self) -> None:
        self._states: dict[tuple[int, int, int, bool], _State] = {}
        self._mapping = trezor_mapping.DEFAULT_MAPPING if trezor_mapping else None

    def _decode_message(self, message_type_id: int, message_bytes: bytes) -> dict[str, Any]:
        if self._mapping is None:
            return {"decoder": "unavailable", "reason": "install trezor"}
        try:
            msg = self._mapping.decode(message_type_id, message_bytes)
            fields = {}
            for k, v in msg.__dict__.items():
                if k.startswith("_") or v is None:
                    continue
                fields[k] = v
            return {
                "decoder": "trezorlib",
                "message_name": msg.__class__.__name__,
                "fields": fields,
            }
        except Exception as e:
            return {"decoder": "trezorlib", "decode_error": str(e)}

    def decode_packet(self, pkt: Any) -> dict[str, Any] | None:
        payload = pkt.payload
        if not payload:
            return None

        key = _stream_key(pkt)
        core = _strip_report_id(payload)
        if not core:
            return None

        # Start frame: "##" + type(2B big-endian) + len(4B big-endian) + data
        if core.startswith(b"##") and len(core) >= 8:
            msg_type = struct.unpack(">H", core[2:4])[0]
            total_len = struct.unpack(">I", core[4:8])[0]
            chunk = core[8:]
            truncated_chunk = chunk[:total_len]
            self._states[key] = _State(msg_type=msg_type, total_len=total_len, collected=truncated_chunk)
            done = len(truncated_chunk) >= total_len
            out = {
                "trezor_detected": True,
                "frame": "start",
                "message_type_id": msg_type,
                "message_total_len": total_len,
                "chunk_len": len(chunk),
                "collected_len": len(truncated_chunk),
                "is_complete": done,
                "message_hex_preview": truncated_chunk[:48].hex(),
            }
            if done:
                out["protobuf"] = self._decode_message(msg_type, truncated_chunk)
                self._states.pop(key, None)
            return out

        # Continuation frame for currently open stream.
        if key in self._states:
            st = self._states[key]
            remain = max(0, st.total_len - len(st.collected))
            chunk = core[:remain]
            st.collected += chunk
            done = len(st.collected) >= st.total_len
            out = {
                "trezor_detected": True,
                "frame": "continuation",
                "message_type_id": st.msg_type,
                "message_total_len": st.total_len,
                "chunk_len": len(chunk),
                "collected_len": len(st.collected),
                "is_complete": done,
                "message_hex_preview": st.collected[:48].hex(),
            }
            if done:
                out["protobuf"] = self._decode_message(st.msg_type, st.collected)
                self._states.pop(key, None)
            return out

        # Fallback: expose an interpreted raw report so UI/export has "second layer"
        # even when the payload doesn't use "##" protobuf framing.
        tag = core[1] if len(core) > 1 else None
        body = core[2:] if len(core) > 2 else b""
        return {
            "trezor_detected": True,
            "frame": "raw_report",
            "report_id": core[0],
            "report_tag": tag,
            "report_len": len(core),
            "body_hex_preview": body[:48].hex(),
            "is_complete": True,
        }
