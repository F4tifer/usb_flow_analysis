"""Cross-event detectors producing ErrorEvent rows."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Literal

from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.flow_builder import FlowStream


@dataclass(slots=True)
class ErrorEvent:
    layer: Literal['transport', 'connection', 'protocol', 'application', 'timing']
    severity: Literal['critical', 'warning', 'info']
    event_type: str
    description: str
    ts: float
    evidence: dict
    linked_flow_events: list[int]
    causal_hints: list[str]
    source_file: str


def detect_errors(stream: FlowStream, cfg: AnalysisConfig | None = None) -> list[ErrorEvent]:
    cfg = cfg or AnalysisConfig()
    out: list[ErrorEvent] = []
    by_seq = {e.seq: e for e in stream.events}

    for e in stream.events:
        if e.event_class == 'usb_error':
            near_reconnect = any(abs(r.ts - e.ts) <= cfg.reconnect_eproto_window_s for r in stream.events if r.event_class == 'reconnect')
            et = 'usb_eproto_reconnect' if near_reconnect else 'usb_eproto_isolated'
            sev = 'info' if near_reconnect else 'critical'
            # Reflect the classified severity back onto the source FlowEvent so UI
            # filters and downstream consumers see the final verdict.
            e.severity = sev
            out.append(ErrorEvent('transport', sev, et, e.content, e.ts, {'status': e.content}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'lost_urb':
            out.append(ErrorEvent('transport', 'warning', 'usb_lost_urb', e.content, e.ts, {}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'reconnect':
            out.append(ErrorEvent('connection', 'info', 'device_reconnect', 'Device reconnect', e.ts, {}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'timeout':
            out.append(ErrorEvent('protocol', 'critical', 'segment_timeout', e.content, e.ts, {'hypothesis': e.timeout_source_hypothesis}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'incomplete_segment':
            out.append(ErrorEvent('protocol', 'critical', 'incomplete_segment', e.content, e.ts, {}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'command' and e.cmd_crc_expected and e.cmd_crc is None:
            out.append(ErrorEvent('protocol', 'critical', 'missing_crc', f'Missing CRC on {e.cmd_name}', e.ts, {}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'command' and e.cmd_crc_valid is False:
            out.append(ErrorEvent('protocol', 'critical', 'crc_mismatch', f'CRC mismatch on {e.cmd_name}', e.ts, {}, [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'response_error':
            out.append(ErrorEvent('application', 'critical', 'app_error', e.content, e.ts, {'cmd_name': e.cmd_name}, [e.seq, e.paired_seq] if e.paired_seq else [e.seq], e.causal_hints, e.source_file))
        elif e.event_class == 'response_ok' and e.outcome == 'ok_no':
            et = 'lock_regression' if (e.cmd_name or '').endswith('lock-check') else 'unexpected_ok_no'
            sev = 'critical' if et == 'lock_regression' else 'warning'
            out.append(ErrorEvent('application', sev, et, e.content, e.ts, {'cmd_name': e.cmd_name}, [e.seq], e.causal_hints, e.source_file))

    # timing detector
    by_cmd: dict[str, list] = {}
    for e in stream.events:
        if e.event_class in {'response_ok', 'response_error'} and e.cmd_name and e.latency_ms is not None:
            by_cmd.setdefault(e.cmd_name, []).append(e.latency_ms)
    import statistics
    med_mad: dict[str, tuple[float, float, float]] = {}
    for cmd, vals in by_cmd.items():
        if len(vals) < cfg.timing_min_samples:
            continue
        med = statistics.median(vals)
        mad = statistics.median([abs(v - med) for v in vals]) or 1.0
        mn = min(vals)
        med_mad[cmd] = (med, mad, mn)

    for e in stream.events:
        if e.cmd_name in med_mad and e.latency_ms is not None:
            med, mad, mn = med_mad[e.cmd_name]
            if e.latency_ms > med + cfg.timing_critical_multiplier * mad:
                out.append(ErrorEvent('timing', 'critical', 'timing_critical', f'Latency {e.latency_ms:.1f}ms on {e.cmd_name}', e.ts, {'median': med, 'mad': mad}, [e.seq], e.causal_hints, e.source_file))
            elif e.latency_ms > med + cfg.timing_mad_multiplier * mad:
                out.append(ErrorEvent('timing', 'warning', 'timing_high', f'Latency {e.latency_ms:.1f}ms on {e.cmd_name}', e.ts, {'median': med, 'mad': mad}, [e.seq], e.causal_hints, e.source_file))
            elif e.latency_ms < mn * cfg.timing_suspiciously_low_ratio:
                out.append(ErrorEvent('timing', 'warning', 'timing_suspiciously_low', f'Suspiciously low latency {e.latency_ms:.1f}ms on {e.cmd_name}', e.ts, {'min': mn}, [e.seq], e.causal_hints, e.source_file))

    return out


def errors_to_dict(errors: list[ErrorEvent]) -> list[dict]:
    return [asdict(e) for e in errors]
