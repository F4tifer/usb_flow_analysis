"""CLI entry (`usb-analyze`)."""

from __future__ import annotations

import contextlib
import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from usb_analysis.filters import matches
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.engine import analyze_path
from usb_analysis.analysis.causal import enrich_causal
from usb_analysis.analysis.detectors import detect_errors
from usb_analysis.analysis.exporter import export_csv, export_html_report, export_json, export_junit_xml
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import iter_usb_packets
from usb_analysis.models import event_type_char, transfer_type_name
from usb_analysis.pipeline import ensure_mmap_link, iter_mmap_packets
from usb_analysis.pcap import pcap_wall_ts_sec
from usb_analysis.serialization import packet_record
from usb_analysis.stream_text import build_text_stream
from usb_analysis.summary import build_summary
from usb_analysis.trezor import TrezorDecoder

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


def _hex_preview(blob: bytes, max_len: int = 24) -> str:
    slice_ = blob[:max_len].hex()
    if len(blob) > max_len:
        return slice_ + "…"
    return slice_


def _csv_safe_row(row: dict) -> dict:
    out = dict(row)
    trezor = out.pop("trezor", None)
    if isinstance(trezor, dict):
        out["trezor_frame"] = trezor.get("frame")
        out["trezor_message_type_id"] = trezor.get("message_type_id")
        out["trezor_message_total_len"] = trezor.get("message_total_len")
        out["trezor_collected_len"] = trezor.get("collected_len")
        out["trezor_is_complete"] = trezor.get("is_complete")
    else:
        out["trezor_frame"] = ""
        out["trezor_message_type_id"] = ""
        out["trezor_message_total_len"] = ""
        out["trezor_collected_len"] = ""
        out["trezor_is_complete"] = ""
    return out


@app.command()
def info(
    path: Annotated[Path, typer.Argument(help="Path to .pcap with LINKTYPE_USB_LINUX_MMAPPED")],
    bus: Annotated[int | None, typer.Option(help="Filter bus")] = None,
    device: Annotated[int | None, typer.Option(help="Filter USB device address")] = None,
    endpoint: Annotated[int | None, typer.Option(help="Filter endpoint (low 7 bits match)")] = None,
) -> None:
    """Print aggregate statistics."""
    ensure_mmap_link(path)
    data = build_summary(path, bus=bus, device=device, endpoint=endpoint)
    console.rule("[bold]USB PCAP summary[/bold]")
    console.print("[cyan]path[/cyan]:", data["path"])
    console.print("[cyan]total_packets[/cyan]:", data["total_packets"])
    if data["total_packets"]:
        console.print("[cyan]time_start[/cyan]:", data["time_start"])
        console.print("[cyan]time_end[/cyan]:", data["time_end"])
        console.print("[cyan]duration_s[/cyan]:", f"{data['duration_s']:.6f}")

    tbl = Table(title="devices (bus / address)")
    tbl.add_column("bus")
    tbl.add_column("addr")
    for d in data["devices"]:
        tbl.add_row(str(d["bus"]), str(d["device"]))
    console.print(tbl)

    console.print("[cyan]transfer_types[/cyan]:", data["transfer_types"])
    console.print("[cyan]event_types[/cyan]:", data["event_types"])


@app.command("dump")
def dump_packets(
    path: Annotated[Path, typer.Argument(help="PCAP path")],
    skip: Annotated[int, typer.Option(help="Skip this many filtered rows")] = 0,
    limit: Annotated[int | None, typer.Option(help="Max filtered rows")] = None,
    bus: Annotated[int | None, typer.Option()] = None,
    device: Annotated[int | None, typer.Option()] = None,
    endpoint: Annotated[int | None, typer.Option()] = None,
) -> None:
    """Dump decoded packets as a table."""
    ensure_mmap_link(path)
    emitted = 0
    scanned = 0

    tbl = Table(
        "ordinal",
        "pcap_ts",
        "urb_id",
        "event",
        "xfer",
        "bus",
        "dev",
        "ep_raw",
        "IN?",
        "caplen",
        "payload(len)",
        "hex(payload)",
        "trezor",
        show_lines=True,
    )

    decoder = TrezorDecoder()
    for pkt in iter_mmap_packets(path):
        if not matches(pkt, bus=bus, device=device, endpoint=endpoint):
            continue
        trezor = decoder.decode_packet(pkt)
        if scanned < skip:
            scanned += 1
            continue
        if limit is not None and emitted >= limit:
            break
        h = pkt.header
        ts = pcap_wall_ts_sec(pkt.pcap_ts_sec, pkt.pcap_ts_usec)
        evt = event_type_char(h.event_type) or f"x{h.event_type:02x}"
        tbl.add_row(
            str(pkt.ordinal),
            f"{ts:.6f}",
            f"{h.urb_id:#018x}",
            evt,
            transfer_type_name(h.transfer_type),
            str(h.bus_id),
            str(h.device_address),
            str(h.endpoint_number),
            "Y" if h.is_in_transfer else "N",
            str(pkt.caplen),
            str(len(pkt.payload)),
            _hex_preview(pkt.payload),
            ""
            if not trezor
            else (
                f"{trezor.get('frame')}:{trezor.get('message_type_id')}:"
                f"{(trezor.get('protobuf') or {}).get('message_name','')}"
            ),
        )
        emitted += 1
        scanned += 1

    console.print(tbl)
    console.print(f"[dim]shown {emitted} packet(s)[/dim]")


@app.command("export")
def export_rows(
    path: Annotated[Path, typer.Argument(help="PCAP path")],
    format: Annotated[str, typer.Option("--format", help="Output format")] = "jsonl",
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to file")] = None,
    skip: Annotated[int, typer.Option(help="Skip filtered rows")] = 0,
    limit: Annotated[int | None, typer.Option(help="Max filtered rows")] = None,
    bus: Annotated[int | None, typer.Option()] = None,
    device: Annotated[int | None, typer.Option()] = None,
    endpoint: Annotated[int | None, typer.Option()] = None,
) -> None:
    """Export filtered packets to JSON Lines or CSV."""
    ensure_mmap_link(path)
    fmt = format.lower().strip()
    if fmt not in {"jsonl", "csv"}:
        raise typer.BadParameter("--format must be jsonl or csv")

    use_stdout = output is None
    fout_cm = contextlib.nullcontext(sys.stdout) if use_stdout else Path(output).open("w", encoding="utf-8")

    with fout_cm as fout:
        emitted = scanned = 0
        wrote_header = False
        csv_writer: csv.DictWriter | None = None
        decoder = TrezorDecoder()

        for pkt in iter_mmap_packets(path):
            if not matches(pkt, bus=bus, device=device, endpoint=endpoint):
                continue
            trezor = decoder.decode_packet(pkt)
            if scanned < skip:
                scanned += 1
                continue
            if limit is not None and emitted >= limit:
                break

            row = packet_record(pkt, trezor_decoded=trezor)
            if fmt == "jsonl":
                fout.write(json.dumps(row, ensure_ascii=False) + "\n")
            else:
                row = _csv_safe_row(row)
                if not wrote_header:
                    csv_writer = csv.DictWriter(fout, fieldnames=list(row.keys()))
                    csv_writer.writeheader()
                    wrote_header = True
                assert csv_writer is not None
                csv_writer.writerow(row)

            emitted += 1
            scanned += 1


@app.command("stream")
def stream_log(
    path: Annotated[Path, typer.Argument(help="PCAP path")],
    limit: Annotated[int | None, typer.Option(help="Max stream lines")] = None,
    bus: Annotated[int | None, typer.Option()] = None,
    device: Annotated[int | None, typer.Option()] = None,
    endpoint: Annotated[int | None, typer.Option()] = None,
) -> None:
    """Render Follow-Stream-like ASCII communication (host/device lines)."""
    ensure_mmap_link(path)
    selected = []
    for pkt in iter_mmap_packets(path):
        if matches(pkt, bus=bus, device=device, endpoint=endpoint):
            selected.append(pkt)

    lines = build_text_stream(selected)
    if limit is not None:
        lines = lines[:limit]

    for item in lines:
        who = item["speaker"]
        line = item["line"]
        if who == "host":
            console.print(f"[cyan]host[/cyan]   {line}")
        else:
            console.print(f"[magenta]device[/magenta] {line}")


@app.command("deep-analyze")
def deep_analyze(
    path_or_dir: Annotated[Path, typer.Argument(help="PCAP file or directory")],
    baseline: Annotated[Path | None, typer.Option(help="Path to baseline JSON")] = None,
    update_baseline: Annotated[bool, typer.Option(help="Persist/update baseline")] = False,
) -> None:
    """Run deep anomaly analysis over USB command/response communication."""
    cfg = AnalysisConfig()
    if baseline is not None:
        cfg.baseline_path = str(baseline)
    data = analyze_path(path_or_dir, cfg=cfg, update_baseline=update_baseline)

    console.rule("[bold]Deep USB analysis[/bold]")
    console.print("[cyan]files[/cyan]:", len(data["files"]))
    console.print("[cyan]segments[/cyan]:", data["segments_count"])
    console.print("[cyan]findings[/cyan]:", len(data["findings"]))
    console.print("[cyan]rules[/cyan]:", len(data["rules"]))

    if data["findings"]:
        t = Table(title="Top anomalies")
        t.add_column("score")
        t.add_column("cmd")
        t.add_column("outcome")
        t.add_column("reason")
        for f in data["findings"][:20]:
            seg = f["segment"]
            t.add_row(
                f"{f['score']:.2f}",
                seg["cmd_name"],
                seg["outcome"],
                "; ".join(f["reasons"])[:90],
            )
        console.print(t)

    if data["rules"]:
        t = Table(title="Rule candidates")
        t.add_column("rule_id")
        t.add_column("conf")
        t.add_column("support")
        t.add_column("desc")
        for r in data["rules"][:20]:
            t.add_row(r["rule_id"], f"{r['confidence']:.2f}", str(r["support"]), r["description"])
        console.print(t)


@app.command("flow")
def flow(
    path_or_dir: Annotated[Path, typer.Argument(help="PCAP file or directory")],
    min_severity: Annotated[str, typer.Option(help="info|warning|critical")] = "warning",
    hide_probes: Annotated[bool, typer.Option(help="Hide crc_probe events")] = False,
    hide_ok: Annotated[bool, typer.Option(help="Show only non-ok events")] = False,
    from_seq: Annotated[int, typer.Option(help="Start from sequence")] = 1,
    run: Annotated[int | None, typer.Option(help="Show only run index")] = None,
    causal_only: Annotated[bool, typer.Option(help="Only events with causal hints")] = False,
    format: Annotated[str, typer.Option("--format", help="text|json|csv")] = "text",
    out: Annotated[Path | None, typer.Option(help="Output file path")] = None,
    export_html: Annotated[Path | None, typer.Option(help="Write HTML report")] = None,
    export_junit: Annotated[Path | None, typer.Option(help="Write JUnit XML")] = None,
) -> None:
    cfg = AnalysisConfig()
    packets = list(iter_usb_packets(path_or_dir))
    stream = build_flow_stream(packets, cfg)
    stream = enrich_causal(stream, cfg)
    errors = detect_errors(stream, cfg)

    sev_rank = {"ok": 0, "info": 1, "warning": 2, "critical": 3, "suppressed": -1}
    min_rank = sev_rank.get(min_severity, 2)
    events = []
    for e in stream.events:
        if e.seq < from_seq:
            continue
        if run is not None and e.run_index != run:
            continue
        if hide_probes and e.event_class == "crc_probe":
            continue
        if hide_ok and e.severity == "ok":
            continue
        if causal_only and not e.causal_hints:
            continue
        if sev_rank.get(e.severity, 0) < min_rank:
            continue
        events.append(e)

    if export_html:
        export_html_report(stream, errors, None, str(export_html))
    if export_junit:
        export_junit_xml(stream, errors, str(export_junit))

    fmt = format.lower()
    if fmt == "json":
        target = out or Path("-")
        if str(target) == "-":
            console.print_json(
                data=json.dumps(
                    {
                        "device_serial": stream.device_serial,
                        "stats": asdict(stream.stats),
                        "events": [asdict(e) for e in events],
                    },
                    ensure_ascii=False,
                    default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else None,
                )
            )
        else:
            clone = type(stream)(
                events=events,
                device_serial=stream.device_serial,
                source_files=stream.source_files,
                total_duration_s=stream.total_duration_s,
                stats=stream.stats,
            )
            export_json(clone, str(target))
        return
    if fmt == "csv":
        target = out or Path("flow.csv")
        clone = type(stream)(
            events=events,
            device_serial=stream.device_serial,
            source_files=stream.source_files,
            total_duration_s=stream.total_duration_s,
            stats=stream.stats,
        )
        export_csv(clone, str(target))
        console.print(f"[green]CSV exported:[/green] {target}")
        return

    console.rule("[bold]USB Flow[/bold]")
    sessions = stream.device_sessions
    session_count = len(sessions)
    console.print(
        f"Sessions: [cyan]{session_count}[/cyan] | Runs: {stream.stats.run_count} | "
        f"Duration: {stream.total_duration_s:.2f}s | "
        f"Critical: {sum(1 for x in errors if x.severity=='critical')}"
    )
    if session_count > 1:
        for s in sessions:
            console.print(
                f"  [dim]session {s.session_index}: bus {s.bus_id}/dev {s.device_address} "
                f"serial=[cyan]{s.device_serial or 'unknown'}[/cyan] "
                f"events {s.start_seq}–{s.end_seq} ({s.event_count})[/dim]"
            )
    elif sessions:
        s = sessions[0]
        console.print(
            f"Device: bus {s.bus_id}/dev {s.device_address} "
            f"serial=[cyan]{s.device_serial or 'unknown'}[/cyan]"
        )

    last_session = -1
    for e in events:
        if e.device_session != last_session and session_count > 1:
            sess = next((s for s in sessions if s.session_index == e.device_session), None)
            if sess is not None:
                console.rule(
                    f"[bold green]Device session {sess.session_index}[/bold green] "
                    f"bus {sess.bus_id}/dev {sess.device_address} "
                    f"serial={sess.device_serial or 'unknown'} "
                    f"(events {sess.start_seq}–{sess.end_seq})"
                )
            last_session = e.device_session
        arrow = "──►" if e.direction == "HOST→DEV" else ("◄──" if e.direction == "DEV→HOST" else " • ")
        color = "red" if e.severity == "critical" else ("yellow" if e.severity == "warning" else "white")
        lat = "" if e.latency_ms is None else f" {e.latency_ms:7.1f}ms"
        # Compact device tag so a row stays self-describing even outside its
        # session header (useful when piping through grep / less -S).
        dev_tag = f"[dim][b{e.bus_id}/d{e.device_address}{('|' + e.device_serial) if e.device_serial else ''}][/dim] "
        # Indent continuation chunks; mark chunked parent with a chain glyph.
        if e.event_class == "command_chunk":
            console.print(
                f"[dim]{e.seq:5d} {lat:>10}     {dev_tag}{e.content} [{e.event_class}][/dim]"
            )
            continue
        chunk_mark = " ⛓" if e.is_chunked else ""
        console.print(
            f"[{color}]{e.seq:5d} {lat:>10} {arrow}[/{color}] "
            f"{dev_tag}[{color}]{e.content}{chunk_mark} [{e.event_class}][/{color}]"
        )
        for hint, conf in zip(e.causal_hints, e.causal_confidence):
            console.print(f"       [dim]Kauzální hypotéza ({conf}): {hint}[/dim]")
