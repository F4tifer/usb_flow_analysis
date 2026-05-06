"""Synthetic PCAP generator placeholder for CI-safe fixtures."""

from __future__ import annotations

from pathlib import Path


def generate_placeholder(path: Path) -> None:
    # This fixture intentionally stores small deterministic bytes and is not
    # used by runtime parser tests directly. It documents synthetic-data flow.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"SYNTHETIC_PCAP_PLACEHOLDER")


if __name__ == "__main__":
    generate_placeholder(Path(__file__).with_name("synthetic_placeholder.bin"))
