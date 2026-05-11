"""Build chronological FlowStream from UsbPacket stream."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.crc_util import extract_serial_from_response, validate_crc
from usb_analysis.analysis.parser import UsbPacket


# Pre-compiled to keep session builder out of crc_util's regex re-compile path.
import re as _re
_OK_SERIAL_RE = _re.compile(r"^OK(?:\s+NO)?\s+([0-9A-Fa-f]{8})\s*$")


@dataclass(slots=True)
class FlowEvent:
    seq: int
    ts: float
    ts_relative_ms: float
    delta_ms: float
    direction: Literal["HOST→DEV", "DEV→HOST", "INTERNAL"]
    layer: Literal["bulk", "control", "interrupt", "meta"]
    event_class: str
    content: str
    cmd_name: str | None = None
    cmd_args: list[str] = field(default_factory=list)
    cmd_crc: str | None = None
    cmd_crc_expected: bool = False
    cmd_crc_valid: bool | None = None
    device_serial: str | None = None
    raw_payload: bytes = b""
    outcome: str = "none"
    paired_seq: int | None = None
    latency_ms: float | None = None
    causal_window: list[int] = field(default_factory=list)
    causal_hints: list[str] = field(default_factory=list)
    causal_confidence: list[str] = field(default_factory=list)
    is_causal_suspect: bool = False
    timeout_source_hypothesis: str | None = None
    run_index: int = 0
    run_seq: int = 0
    expected_at_run_seq: int | None = None
    is_unexpected_command: bool = False
    is_out_of_order: bool = False
    severity: Literal["ok", "info", "warning", "critical", "suppressed"] = "ok"
    source_file: str = ""
    # Identity of the USB device that produced (or received) this event. Carried
    # on every row so consumers can group / filter by physical device when a
    # capture spans bus reassignments or multiple devices.
    bus_id: int = 0
    device_address: int = 0
    device_session: int = 0
    # Chunking metadata for commands that span multiple bulk OUT submits because
    # the payload exceeded the endpoint's max packet size. is_chunked=True on the
    # parent command event; chunk_count counts only the continuation packets
    # (so 3 means 1 parent + 3 continuations = 4 packets total).
    is_chunked: bool = False
    chunk_count: int = 0


@dataclass(slots=True)
class FlowStats:
    total_events: int = 0
    commands_sent: int = 0
    responses_ok: int = 0
    responses_ok_no: int = 0
    responses_error: int = 0
    timeouts: int = 0
    reconnects: int = 0
    usb_errors: int = 0
    lost_urbs: int = 0
    incomplete_segments: int = 0
    crc_mismatches: int = 0
    causal_chains: int = 0
    run_count: int = 0
    chunked_commands: int = 0
    run_completeness: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class DeviceSession:
    """Continuous span of events that belonged to one (bus, device_address)."""

    session_index: int
    bus_id: int
    device_address: int
    device_serial: str | None
    start_seq: int
    end_seq: int
    ts_start: float
    ts_end: float
    event_count: int
    # Tester-side serial (from `OK <SN>` responses) — typically the USB-port /
    # programming station ID, identical across all runs of a capture.
    tester_serial: str | None = None
    # All distinct DUT serials seen during this session (extracted from
    # `checked-otp-device-sn-write <SN>` commands). Each entry is one physical
    # piece of hardware that was programmed in this session.
    dut_serials: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FlowStream:
    events: list[FlowEvent]
    device_serial: str | None
    source_files: list[str]
    total_duration_s: float
    stats: FlowStats
    device_sessions: list[DeviceSession] = field(default_factory=list)
    # run_index → DUT serial captured during that run (from `checked-otp-device-sn-write`).
    # Allows the runs table and per-run UI to identify which physical HW was tested.
    dut_serial_by_run: dict[int, str] = field(default_factory=dict)


def _split_lines(buf: bytes) -> tuple[list[bytes], bytes]:
    lines = []
    while True:
        idx = -1
        for sep in (b"\n", b"\r"):
            i = buf.find(sep)
            if i >= 0 and (idx < 0 or i < idx):
                idx = i
        if idx < 0:
            break
        lines.append(buf[:idx])
        buf = buf[idx + 1 :]
    return lines, buf


def _command_parts(text: str) -> tuple[str, list[str], str | None]:
    parts = text.split()
    if not parts:
        return "", [], None
    cmd = parts[0]
    crc = None
    if len(parts) > 1 and len(parts[-1]) == 8 and all(c in '0123456789abcdefABCDEF' for c in parts[-1]):
        crc = parts[-1]
        args = parts[1:-1]
    else:
        args = parts[1:]
    return cmd, args, crc


def build_flow_stream(packets: list[UsbPacket], cfg: AnalysisConfig | None = None) -> FlowStream:
    cfg = cfg or AnalysisConfig()
    if not packets:
        return FlowStream(
            events=[], device_serial=None, source_files=[], total_duration_s=0.0,
            stats=FlowStats(), device_sessions=[],
        )

    packets = sorted(packets, key=lambda p: p.ts)
    events: list[FlowEvent] = []
    stats = FlowStats()
    source_files: list[str] = []
    last_ts = packets[0].ts
    run_start = packets[0].ts
    run_index = 0
    run_seq = 0
    open_urbs: dict[int, float] = {}
    last_bulk_ts: float | None = None

    cur_cmd: FlowEvent | None = None
    resp_buf = b""
    segment_open = False
    # Chunking state: when a command's bulk OUT payload doesn't end with a CR/LF,
    # subsequent OUT submits are appended into out_buf as continuation chunks
    # rather than being mis-detected as new commands.
    out_buf = b""
    awaiting_chunks = False
    chunk_count = 0
    # Tester serials come from `OK <SN>` responses — typically the USB-port /
    # programming station ID, constant across all runs of a capture.
    tester_serial_by_device: dict[tuple[int, int], str] = {}
    # DUT (device-under-test) serial is *written* by the tester via the
    # `checked-otp-device-sn-write <SN>` command. This is the unique identity
    # of each physical piece of hardware being programmed; it changes per run.
    cur_dut_serial: str | None = None
    dut_serial_by_run: dict[int, str] = {}
    cur_device: tuple[int, int] = (packets[0].bus_id, packets[0].device_address)
    device_session_index = 0

    def serial() -> str | None:
        # DUT serial wins over tester serial — it's the user-meaningful identity.
        return cur_dut_serial or tester_serial_by_device.get(cur_device)

    def emit(**kwargs) -> FlowEvent:
        nonlocal last_ts
        seq = len(events) + 1
        ts = kwargs.get('ts', last_ts)
        e = FlowEvent(
            seq=seq,
            ts=ts,
            ts_relative_ms=(ts - run_start) * 1000.0,
            delta_ms=(ts - last_ts) * 1000.0,
            run_index=run_index,
            run_seq=run_seq,
            source_file=kwargs.get('source_file', ''),
            bus_id=kwargs.get('bus_id', cur_device[0]),
            device_address=kwargs.get('device_address', cur_device[1]),
            device_session=kwargs.get('device_session', device_session_index),
            **{k: v for k, v in kwargs.items()
               if k not in {'ts', 'source_file', 'bus_id', 'device_address', 'device_session'}},
        )
        last_ts = ts
        events.append(e)
        stats.total_events += 1
        return e

    for p in packets:
        if p.source_file not in source_files:
            source_files.append(p.source_file)

        # Detect transition between physical USB devices. A capture that spans a
        # bus reassignment, a different USB port, or simply two different DUTs
        # will have different (bus_id, device_address) tuples — emit a meta
        # event so consumers can split the timeline into device sessions.
        pkt_device = (p.bus_id, p.device_address)
        if pkt_device != cur_device:
            prev_serial = tester_serial_by_device.get(cur_device)
            new_serial = tester_serial_by_device.get(pkt_device)
            # If the previous device had an open chunked command (or any
            # open segment), the response from the old device will never come
            # — surface that as incomplete_segment so the parent command isn't
            # silently truncated on the timeline.
            if segment_open and cur_cmd is not None:
                ie = emit(ts=p.ts, direction='INTERNAL', layer='meta',
                          event_class='incomplete_segment',
                          content=(
                              f'Incomplete segment ({cur_cmd.cmd_name}) — '
                              + ('chunked, ' if cur_cmd.is_chunked else '')
                              + 'device change'
                          ),
                          cmd_name=cur_cmd.cmd_name,
                          severity='critical', outcome='incomplete',
                          source_file=p.source_file)
                cur_cmd.paired_seq = ie.seq
                stats.incomplete_segments += 1
            device_session_index += 1
            cur_device = pkt_device
            # DUT serial belongs to the *current* programming run on the
            # previous tester; a new USB session means a new physical setup,
            # so clear it.
            cur_dut_serial = None
            emit(
                ts=p.ts, direction='INTERNAL', layer='meta', event_class='device_change',
                content=(
                    f'Device change: bus {cur_device[0]}/dev {cur_device[1]}'
                    + (f' (tester {new_serial})' if new_serial else '')
                    + (f' — previous tester: {prev_serial}' if prev_serial else '')
                ),
                severity='info', outcome='device_change',
                device_serial=new_serial,
                source_file=p.source_file,
            )
            # New device session resets command-segment state — a half-open URB
            # from the previous device should not be paired with the new one.
            cur_cmd = None
            segment_open = False
            resp_buf = b''
            out_buf = b''
            awaiting_chunks = False
            chunk_count = 0
            run_index = 0
            run_seq = 0
            run_start = p.ts

        # URB tracking
        if p.event == 'S':
            open_urbs[p.urb_id] = p.ts
        elif p.event == 'C':
            open_urbs.pop(p.urb_id, None)
        expired = [u for u, ts in open_urbs.items() if p.ts - ts > cfg.urb_window_s]
        for u in expired:
            emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='lost_urb',
                 content=f'URB {u} submit without complete', severity='warning', outcome='lost_urb', source_file=p.source_file)
            stats.lost_urbs += 1
            open_urbs.pop(u, None)

        # Timeout for the open segment must be checked before reconnect, because a
        # large bulk gap can satisfy both conditions and timeout is more informative
        # when a command was still awaiting a response.
        if segment_open and cur_cmd is not None and (p.ts - cur_cmd.ts) > cfg.segment_timeout_s:
            tms = (p.ts - cur_cmd.ts) * 1000.0
            critical_ms = cfg.timeout_warning_ms * cfg.timeout_critical_multiplier
            sev = 'critical' if tms >= critical_ms else 'warning'
            te = emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='timeout',
                      content=f'Timeout {tms:.1f}ms on {cur_cmd.cmd_name}', cmd_name=cur_cmd.cmd_name,
                      severity=sev, outcome='timeout', latency_ms=tms, source_file=p.source_file)
            cur_cmd.paired_seq = te.seq
            stats.timeouts += 1
            segment_open = False
            cur_cmd = None
            resp_buf = b''
            out_buf = b''
            awaiting_chunks = False
            chunk_count = 0

        if p.xfer_type == 'bulk':
            if last_bulk_ts is not None and p.ts - last_bulk_ts > cfg.reconnect_gap_s:
                emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='reconnect', content='Reconnect after a longer gap',
                     severity='info', outcome='reconnect', source_file=p.source_file)
                stats.reconnects += 1
                if segment_open and cur_cmd is not None:
                    emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='incomplete_segment',
                         content=f'Incomplete segment after {cur_cmd.cmd_name}', cmd_name=cur_cmd.cmd_name,
                         severity='critical', outcome='incomplete', source_file=p.source_file)
                    stats.incomplete_segments += 1
                    segment_open = False
                    cur_cmd = None
                    out_buf = b''
                    awaiting_chunks = False
                    chunk_count = 0
            last_bulk_ts = p.ts

        if p.status in cfg.error_usb_status or p.is_truncated:
            emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='usb_error',
                 content=f'USB status={p.status}, truncated={p.is_truncated}', severity='warning', outcome='usb_error',
                 source_file=p.source_file)
            stats.usb_errors += 1

        if p.xfer_type == 'bulk' and p.event == 'S' and p.direction == 'OUT' and p.payload:
            # Continuation chunk of a previous command whose first packet did
            # not end with a line terminator. Append, emit a low-severity meta
            # row so the user can see chunking on the timeline, and finalize
            # the parent command once a CR/LF arrives.
            if segment_open and cur_cmd is not None and awaiting_chunks:
                out_buf += p.payload
                chunk_count += 1
                cur_cmd.chunk_count = chunk_count
                preview = p.payload[:48].decode('ascii', errors='replace').rstrip()
                emit(ts=p.ts, direction='HOST→DEV', layer='bulk',
                     event_class='command_chunk',
                     content=f'[chunk #{chunk_count}, +{len(p.payload)} B] {preview}…',
                     cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                     severity='ok', outcome='chunk', source_file=p.source_file)
                if p.payload.endswith((b'\n', b'\r')):
                    full_text = out_buf.decode('ascii', errors='replace').rstrip()
                    cmd, args, crc = _command_parts(full_text)
                    cur_cmd.cmd_name = cmd
                    cur_cmd.cmd_args = args
                    cur_cmd.cmd_crc = crc
                    crc_expected = cmd.startswith(cfg.crc_required_prefix)
                    crc_valid, _ = validate_crc(full_text)
                    cur_cmd.cmd_crc_expected = crc_expected
                    cur_cmd.cmd_crc_valid = crc_valid
                    # Re-derive command-sequence flags now that the *full* cmd
                    # name is known — the truncated first-chunk name would have
                    # been parsed as an unknown / unexpected command otherwise.
                    if cfg.expected_command_sequence:
                        try:
                            cur_cmd.expected_at_run_seq = cfg.expected_command_sequence.index(cmd)
                        except ValueError:
                            cur_cmd.expected_at_run_seq = None
                        cur_cmd.is_unexpected_command = cur_cmd.expected_at_run_seq is None
                        cur_cmd.is_out_of_order = (
                            cur_cmd.expected_at_run_seq is not None
                            and abs(cur_cmd.expected_at_run_seq - cur_cmd.run_seq) > 2
                        )
                    # DUT serial extraction also has to wait for the full cmd:
                    # the truncated first chunk wouldn't match `device_sn_write_commands`.
                    if cmd in cfg.device_sn_write_commands and args:
                        cur_dut_serial = args[0]
                        dut_serial_by_run[cur_cmd.run_index] = cur_dut_serial
                        cur_cmd.device_serial = serial()
                    summary = full_text[:160] + ('…' if len(full_text) > 160 else '')
                    cur_cmd.content = f'{summary}  [chunked: {chunk_count + 1} pkts, {len(out_buf)} B]'
                    if crc_expected and crc is None:
                        cur_cmd.severity = 'critical'
                    elif crc_valid is False:
                        cur_cmd.severity = 'warning'
                        stats.crc_mismatches += 1
                    awaiting_chunks = False
                    out_buf = b''
                    chunk_count = 0
                continue

            if segment_open and cur_cmd is not None:
                ie = emit(ts=p.ts, direction='INTERNAL', layer='meta', event_class='incomplete_segment',
                          content=f'New command before previous was closed: {cur_cmd.cmd_name}', cmd_name=cur_cmd.cmd_name,
                          severity='critical', outcome='incomplete', source_file=p.source_file)
                cur_cmd.paired_seq = ie.seq
                stats.incomplete_segments += 1
            raw_text = p.payload.decode('ascii', errors='replace').strip()
            cmd, args, crc = _command_parts(raw_text)
            is_complete_line = p.payload.endswith((b'\n', b'\r'))
            crc_expected = cmd.startswith(cfg.crc_required_prefix)
            # Defer CRC validation when the payload is incomplete — the real CRC
            # is at the end of the *full* command which arrives in later chunks.
            crc_valid: bool | None = None
            if is_complete_line:
                crc_valid, _ = validate_crc(raw_text)
            is_probe = cmd in cfg.crc_probe_commands and crc is None and is_complete_line
            expected_pos = None
            is_unexpected = False
            is_ooo = False
            if cfg.expected_command_sequence:
                try:
                    expected_pos = cfg.expected_command_sequence.index(cmd)
                except ValueError:
                    expected_pos = None
                is_unexpected = expected_pos is None
                is_ooo = expected_pos is not None and abs(expected_pos - run_seq) > 2
            if cmd in cfg.run_start_commands and run_seq > 5:
                run_index += 1
                run_seq = 0
                run_start = p.ts

            sev = 'ok'
            if is_complete_line:
                if crc_expected and crc is None:
                    sev = 'critical'
                elif crc_valid is False:
                    sev = 'warning'
                    stats.crc_mismatches += 1
            # Detect DUT-serial-write commands: the first argument is the unique
            # identity of the physical hardware being programmed. From here on,
            # subsequent events are tagged with this DUT serial.
            if is_complete_line and cmd in cfg.device_sn_write_commands and args:
                cur_dut_serial = args[0]
                dut_serial_by_run[run_index] = cur_dut_serial
            display_content = raw_text if is_complete_line else f'{raw_text[:160]}{"…" if len(raw_text) > 160 else ""}  [chunked, awaiting…]'
            ev = emit(ts=p.ts, direction='HOST→DEV', layer='bulk',
                      event_class='crc_probe' if is_probe else 'command',
                      content=display_content, cmd_name=cmd, cmd_args=args, cmd_crc=crc,
                      cmd_crc_expected=crc_expected, cmd_crc_valid=crc_valid,
                      expected_at_run_seq=expected_pos, is_unexpected_command=is_unexpected,
                      is_out_of_order=is_ooo, severity=sev, source_file=p.source_file,
                      device_serial=serial(),
                      is_chunked=not is_complete_line)
            cur_cmd = ev
            segment_open = True
            resp_buf = b''
            run_seq += 1
            stats.commands_sent += 1
            if is_complete_line:
                awaiting_chunks = False
                out_buf = b''
                chunk_count = 0
            else:
                awaiting_chunks = True
                out_buf = p.payload
                chunk_count = 0
                stats.chunked_commands += 1
            continue

        if p.xfer_type == 'bulk' and p.event == 'C' and p.direction == 'IN' and p.payload and segment_open and cur_cmd is not None:
            resp_buf += p.payload
            if len(resp_buf) > cfg.segment_max_resp_bytes:
                # Truncate at the next newline so we never split mid-line.
                tail = resp_buf[-cfg.segment_max_resp_bytes:]
                first_nl = -1
                for sep in (b"\n", b"\r"):
                    i = tail.find(sep)
                    if i >= 0 and (first_nl < 0 or i < first_nl):
                        first_nl = i
                resp_buf = tail[first_nl + 1 :] if first_nl >= 0 else b""
            lines, resp_buf = _split_lines(resp_buf)
            for raw in lines:
                txt = raw.decode('ascii', errors='replace').strip()
                if not txt:
                    continue
                latency = (p.ts - cur_cmd.ts) * 1000.0
                if txt.startswith('#'):
                    emit(ts=p.ts, direction='DEV→HOST', layer='bulk', event_class='response_progress',
                         content=txt, cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                         latency_ms=latency, severity='info', source_file=p.source_file)
                    continue
                if txt.startswith('OK NO'):
                    parsed_serial = extract_serial_from_response(txt)
                    if parsed_serial:
                        tester_serial_by_device[cur_device] = parsed_serial
                    outcome = 'probe_active' if cur_cmd.event_class == 'crc_probe' else 'ok_no'
                    sev = 'info' if cur_cmd.event_class == 'crc_probe' else 'warning'
                    resp_ev = emit(ts=p.ts, direction='DEV→HOST', layer='bulk', event_class='response_ok',
                                   content=txt, cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                                   latency_ms=latency, device_serial=serial(), outcome=outcome, severity=sev,
                                   source_file=p.source_file)
                    cur_cmd.paired_seq = resp_ev.seq
                    segment_open = False
                    stats.responses_ok_no += 1
                    break
                if txt.startswith('OK'):
                    parsed_serial = extract_serial_from_response(txt)
                    if parsed_serial:
                        tester_serial_by_device[cur_device] = parsed_serial
                    outcome = 'probe_activated' if cur_cmd.event_class == 'crc_probe' else 'ok'
                    sev = 'info' if cur_cmd.event_class == 'crc_probe' else 'ok'
                    resp_ev = emit(ts=p.ts, direction='DEV→HOST', layer='bulk', event_class='response_ok',
                                   content=txt, cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                                   latency_ms=latency, device_serial=serial(), outcome=outcome, severity=sev,
                                   source_file=p.source_file)
                    cur_cmd.paired_seq = resp_ev.seq
                    segment_open = False
                    stats.responses_ok += 1
                    if cur_cmd.cmd_name in cfg.run_end_commands:
                        stats.run_completeness.append({'run_index': run_index, 'completed': True})
                    break
                if txt.startswith('ERROR'):
                    crc_probe_error = cur_cmd.event_class == 'crc_probe' and 'invalid-crc' in txt.lower()
                    if crc_probe_error:
                        cur_cmd.outcome = 'probe_active'
                        cur_cmd.severity = 'info'
                        cur_cmd.content = '[CRC probe → already active]'
                        segment_open = False
                        break
                    resp_ev = emit(ts=p.ts, direction='DEV→HOST', layer='bulk', event_class='response_error',
                                   content=txt, cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                                   latency_ms=latency, outcome='error', severity='critical', source_file=p.source_file)
                    cur_cmd.paired_seq = resp_ev.seq
                    segment_open = False
                    stats.responses_error += 1
                    break
                emit(ts=p.ts, direction='DEV→HOST', layer='bulk', event_class='response_data',
                     content=txt[:200], cmd_name=cur_cmd.cmd_name, paired_seq=cur_cmd.seq,
                     latency_ms=latency, severity='info', source_file=p.source_file)

    stats.run_count = (run_index + 1) if events else 0
    total_duration = packets[-1].ts - packets[0].ts

    # Materialise device_sessions from the stream so consumers don't have to
    # re-scan events to find boundaries. Each session records:
    #   • device_serial  – best identity (DUT preferred, tester fallback)
    #   • tester_serial  – the OK-response (port) serial
    #   • dut_serials    – every DUT serial seen, in order encountered
    sessions: list[DeviceSession] = []

    def _build_sessions() -> None:
        if not events:
            return
        cur = {
            "idx": events[0].device_session,
            "bus": events[0].bus_id,
            "dev": events[0].device_address,
            "start_seq": events[0].seq,
            "ts_start": events[0].ts,
            "count": 0,
            "last_seq": events[0].seq,
            "last_ts": events[0].ts,
            "last_serial": None,
            "tester": None,
            "duts": [],
        }

        def flush() -> None:
            sessions.append(DeviceSession(
                session_index=cur["idx"],
                bus_id=cur["bus"],
                device_address=cur["dev"],
                device_serial=cur["last_serial"],
                start_seq=cur["start_seq"],
                end_seq=cur["last_seq"],
                ts_start=cur["ts_start"],
                ts_end=cur["last_ts"],
                event_count=cur["count"],
                tester_serial=cur["tester"],
                dut_serials=list(cur["duts"]),
            ))

        for ev in events:
            if ev.device_session != cur["idx"]:
                flush()
                cur = {
                    "idx": ev.device_session, "bus": ev.bus_id, "dev": ev.device_address,
                    "start_seq": ev.seq, "ts_start": ev.ts, "count": 0,
                    "last_seq": ev.seq, "last_ts": ev.ts,
                    "last_serial": None, "tester": None, "duts": [],
                }
            cur["count"] += 1
            cur["last_seq"] = ev.seq
            cur["last_ts"] = ev.ts
            # Detect DUT-write events to keep the session's dut_serials list ordered.
            if ev.event_class == "command" and ev.cmd_name in cfg.device_sn_write_commands and ev.cmd_args:
                dut = ev.cmd_args[0]
                if dut and dut not in cur["duts"]:
                    cur["duts"].append(dut)
            # Tester serial = value parsed straight from `OK <SN>` content,
            # *regardless* of whether a DUT has been written. This way two
            # captures with the same tester but different DUT-write order
            # both expose the tester ID consistently.
            if ev.event_class == "response_ok" and not cur["tester"]:
                m = _OK_SERIAL_RE.match((ev.content or "").strip())
                if m:
                    cur["tester"] = m.group(1).upper()
            if ev.device_serial:
                cur["last_serial"] = ev.device_serial
        flush()

    _build_sessions()

    last_serial = sessions[-1].device_serial if sessions else None
    return FlowStream(
        events=events,
        device_serial=last_serial,
        source_files=source_files,
        total_duration_s=total_duration,
        stats=stats,
        device_sessions=sessions,
        dut_serial_by_run=dut_serial_by_run,
    )
