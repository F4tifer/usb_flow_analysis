"""Minimal PCAP reader (streaming)."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator


PCAP_MAGIC_LE = 0xA1B2C3D4
GLOBAL_HDR_FMT = "<IHHiIII"  # 24 bytes
PKT_HDR_FMT = "<IIII"  # 16 bytes


@dataclass(frozen=True, slots=True)
class PcapGlobals:
    snaplen: int
    network: int  # datalink


def read_global_header(f: BinaryIO) -> PcapGlobals:
    raw = f.read(24)
    if len(raw) < 24:
        raise ValueError("Not a PCAP file (too short)")
    magic, vmaj, vmin, thiszone, sigfigs, snaplen, network = struct.unpack(GLOBAL_HDR_FMT, raw)
    # Little-endian PCAP microsecond timestamps use magic 0xA1B2C3D4 on-disk pattern d4c3b2a1 when read LE.
    if magic != PCAP_MAGIC_LE:
        raise ValueError(f"Unsupported PCAP magic or endianness: {magic:#010x} (want LE 0xa1b2c3d4)")

    return PcapGlobals(int(snaplen), int(network))


def iter_pcap_packets(
    path: Path,
) -> Iterator[tuple[int, int, int, int, int, bytes]]:
    """Yield tuples: (ordinal, tv_sec, tv_usec, caplen, orig_len, body). Ordinal is zero-based.

    The function is intentionally tolerant to a truncated tail packet (common with
    split/partial captures). In that case, it stops iteration instead of raising.
    """
    path = Path(path)
    ordinal = 0
    with path.open("rb") as f:
        _g = read_global_header(f)

        while True:
            hdr = f.read(16)
            if len(hdr) == 0:
                break
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(PKT_HDR_FMT, hdr)
            body = f.read(incl_len)
            if len(body) != incl_len:
                break

            yield (
                ordinal,
                int(ts_sec),
                int(ts_usec),
                int(incl_len),
                int(orig_len),
                body,
            )
            ordinal += 1


def pcap_wall_ts_sec(sec: int, usec: int) -> float:
    return sec + usec / 1_000_000.0
