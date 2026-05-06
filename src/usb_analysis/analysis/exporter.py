"""Export helpers for flow streams."""

from __future__ import annotations

import csv
import html
import json
from dataclasses import asdict
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, ElementTree

from usb_analysis.analysis.aggregator import AggregationReport, aggregation_to_dict
from usb_analysis.analysis.detectors import ErrorEvent, errors_to_dict
from usb_analysis.analysis.flow_builder import FlowStream


def _json_default(o):
    if isinstance(o, (bytes, bytearray)):
        return o.hex()
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def export_json(stream: FlowStream, path: str, pretty: bool = True) -> None:
    data = {
        'device_serial': stream.device_serial,
        'device_sessions': [asdict(s) for s in stream.device_sessions],
        'source_files': stream.source_files,
        'total_duration_s': stream.total_duration_s,
        'stats': asdict(stream.stats),
        'events': [asdict(e) for e in stream.events],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(data, ensure_ascii=False, indent=2 if pretty else None, default=_json_default),
        encoding='utf-8',
    )


def export_csv(stream: FlowStream, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    cols = [
        'seq', 'ts', 'ts_relative_ms', 'delta_ms', 'direction', 'event_class',
        'cmd_name', 'outcome', 'severity', 'latency_ms', 'causal_hints',
        'bus_id', 'device_address', 'device_session', 'device_serial',
        'source_file',
    ]
    with p.open('w', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for e in stream.events:
            w.writerow({
                'seq': e.seq,
                'ts': e.ts,
                'ts_relative_ms': e.ts_relative_ms,
                'delta_ms': e.delta_ms,
                'direction': e.direction,
                'event_class': e.event_class,
                'cmd_name': e.cmd_name or '',
                'outcome': e.outcome,
                'severity': e.severity,
                'latency_ms': '' if e.latency_ms is None else f'{e.latency_ms:.3f}',
                'causal_hints': ' | '.join(e.causal_hints),
                'bus_id': e.bus_id,
                'device_address': e.device_address,
                'device_session': e.device_session,
                'device_serial': e.device_serial or '',
                'source_file': e.source_file,
            })


def export_html_report(stream: FlowStream, errors: list[ErrorEvent], agg: AggregationReport | None, path: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    errs = errors_to_dict(errors)
    agg_dict = aggregation_to_dict(agg) if agg else None
    esc = html.escape
    rows = ''.join(
        f"<tr><td>{e.seq}</td><td>{esc(e.event_class)}</td><td>{esc(e.direction)}</td><td>{esc(e.severity)}</td><td>{esc(e.content or '')}</td></tr>"
        for e in stream.events[:5000]
    )
    err_rows = ''.join(
        f"<tr><td>{esc(e['event_type'])}</td><td>{esc(e['severity'])}</td><td>{esc(e['description'])}</td></tr>"
        for e in errs
    )
    serial = esc(stream.device_serial or 'unknown')
    agg_text = esc(json.dumps(agg_dict, ensure_ascii=False, indent=2)) if agg_dict else ''
    html_doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>USB Flow Report</title>
<style>body{{font-family:system-ui}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px;font-size:12px}}</style>
</head><body>
<h1>USB Flow Report</h1>
<p>Device: {serial} | Events: {len(stream.events)} | Duration: {stream.total_duration_s:.3f}s</p>
<h2>Errors</h2><table><tr><th>Type</th><th>Severity</th><th>Description</th></tr>{err_rows}</table>
<h2>Flow (first 5000 events)</h2><table><tr><th>seq</th><th>class</th><th>dir</th><th>severity</th><th>content</th></tr>{rows}</table>
<pre id='agg'>{agg_text}</pre>
</body></html>"""
    p.write_text(html_doc, encoding='utf-8')


def export_junit_xml(stream: FlowStream, errors: list[ErrorEvent], path: str) -> None:
    root = Element('testsuite', name='usb-flow', tests=str(max(stream.stats.run_count, 1)))
    run_count = max(stream.stats.run_count, 1)
    for run in range(run_count):
        case = SubElement(root, 'testcase', classname='usb.flow', name=f'run_{run}')
        critical = [e for e in errors if e.severity == 'critical' and any((ev.run_index == run) for ev in stream.events if ev.seq in e.linked_flow_events)]
        if critical:
            msg = "\n".join(f"{e.event_type}: {e.description}" for e in critical)
            SubElement(case, 'failure', message='critical issues').text = msg
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    ElementTree(root).write(p, encoding='utf-8', xml_declaration=True)
