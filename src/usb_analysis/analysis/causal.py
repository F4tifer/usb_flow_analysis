"""Causal enrichment for flow events."""

from __future__ import annotations

from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.flow_builder import FlowStream


def _find(window, cls):
    for e in reversed(window):
        if e.event_class == cls:
            return e
    return None


def _classify_timeout(window) -> str:
    if any(e.event_class == 'usb_error' for e in window):
        return 'usb_physical'
    if any(e.event_class == 'lost_urb' for e in window):
        return 'lost_packet'
    if any(e.event_class in {'reconnect', 'heartbeat_dropout'} for e in window):
        return 'device_reset'
    if any(e.event_class == 'response_progress' for e in window):
        return 'device_busy'
    return 'unknown'


def enrich_causal(stream: FlowStream, config: AnalysisConfig | None = None) -> FlowStream:
    cfg = config or AnalysisConfig()
    events = stream.events
    idx_by_seq = {e.seq: i for i, e in enumerate(events)}

    for i, event in enumerate(events):
        if event.severity not in ('warning', 'critical'):
            continue

        window = []
        j = i - 1
        while j >= 0 and len(window) < cfg.causal_window_size:
            e = events[j]
            if e.event_class in cfg.causal_suspect_classes or e.severity != 'ok':
                window.insert(0, e)
            j -= 1

        event.causal_window = [e.seq for e in window]

        if event.event_class in {'response_error', 'incomplete_segment'} and any(e.event_class == 'timeout' for e in window):
            t = _find(window, 'timeout')
            event.causal_hints.append(
                f"Timeout na '{t.cmd_name or 'unknown'}' těsně před chybou mohl rozbít stav zařízení."
            )
            event.causal_confidence.append('high')
        if event.event_class in {'response_error', 'timeout'} and any(e.event_class == 'usb_error' for e in window):
            event.causal_hints.append('USB chyba předcházela problému, možné DN/DP selhání fyzické vrstvy.')
            event.causal_confidence.append('medium')
        if event.event_class in {'response_error', 'timeout'} and any(e.event_class == 'incomplete_segment' for e in window):
            event.causal_hints.append('Nedokončený segment před tímto bodem mohl způsobit dominový efekt.')
            event.causal_confidence.append('high')
        if event.event_class in {'response_error', 'timeout', 'incomplete_segment'} and any(e.event_class == 'reconnect' for e in window):
            event.causal_hints.append('Reconnect předcházel problému, zařízení mohlo projít resetem.')
            event.causal_confidence.append('high')
        if event.event_class == 'response_error' and any(e.event_class == 'response_error' for e in window):
            event.causal_hints.append('Předchozí ERROR naznačuje řetězení chyb.')
            event.causal_confidence.append('medium')

        if event.causal_hints:
            stream.stats.causal_chains += 1
            for suspect in window:
                if suspect.event_class in cfg.causal_suspect_classes:
                    events[idx_by_seq[suspect.seq]].is_causal_suspect = True

        if event.event_class == 'timeout':
            event.timeout_source_hypothesis = _classify_timeout(window)

    return stream
