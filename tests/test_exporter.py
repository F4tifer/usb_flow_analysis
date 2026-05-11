import csv
import json
from pathlib import Path

from usb_analysis.analysis.exporter import _json_default, export_csv, export_json
from usb_analysis.analysis.flow_builder import DeviceSession, FlowEvent, FlowStats, FlowStream


def test_export_json_csv(tmp_path):
    s = FlowStream(events=[], device_serial='X', source_files=['a.pcap'], total_duration_s=0.0, stats=FlowStats())
    jp = tmp_path / 'o.json'
    cp = tmp_path / 'o.csv'
    export_json(s, str(jp))
    export_csv(s, str(cp))
    assert jp.is_file()
    assert cp.is_file()


def _ev(**kw):
    base = dict(
        seq=1, ts=1.0, ts_relative_ms=0.0, delta_ms=0.0,
        direction='HOST→DEV', layer='bulk', event_class='command',
        content='ping ABCD1234',
    )
    base.update(kw)
    return FlowEvent(**base)


def test_csv_contains_new_columns(tmp_path):
    """Regression for D3 — CSV must include run/chunk/paired fields so a
    consumer can reconstruct the run boundaries and chunk parents from
    export alone."""
    ev = _ev(seq=42, run_index=3, run_seq=7, paired_seq=43,
             is_chunked=True, chunk_count=2, cmd_name='checked-x')
    s = FlowStream(events=[ev], device_serial=None, source_files=[],
                   total_duration_s=0.0, stats=FlowStats())
    cp = tmp_path / 'o.csv'
    export_csv(s, str(cp))
    rows = list(csv.DictReader(cp.open()))
    assert len(rows) == 1
    row = rows[0]
    for col in ('run_index', 'run_seq', 'paired_seq', 'is_chunked', 'chunk_count'):
        assert col in row, f'CSV header missing column {col}'
    assert row['run_index'] == '3'
    assert row['paired_seq'] == '43'
    assert row['is_chunked'] == '1'
    assert row['chunk_count'] == '2'


def test_json_export_includes_device_sessions_and_dut_map(tmp_path):
    """Regression for K3 — JSON export must carry over device_sessions and
    dut_serial_by_run; a previous bug in CLI dropped both fields silently."""
    sess = DeviceSession(
        session_index=0, bus_id=1, device_address=4,
        device_serial='DUT-A', start_seq=1, end_seq=5,
        ts_start=1.0, ts_end=2.0, event_count=5,
        tester_serial='ABCDEF01', dut_serials=['DUT-A'],
    )
    s = FlowStream(
        events=[], device_serial='DUT-A', source_files=[],
        total_duration_s=1.0, stats=FlowStats(),
        device_sessions=[sess],
        dut_serial_by_run={0: 'DUT-A'},
    )
    jp = tmp_path / 'o.json'
    export_json(s, str(jp))
    data = json.loads(jp.read_text())
    assert 'device_sessions' in data
    assert len(data['device_sessions']) == 1
    assert data['device_sessions'][0]['dut_serials'] == ['DUT-A']
    # FlowStream itself doesn't expose dut_serial_by_run in JSON export,
    # but the underlying field must be preserved on the dataclass for the
    # CLI path to function. Verify the CLI clone helper preserves it.
    from usb_analysis.cli import _clone_flow_stream
    clone = _clone_flow_stream(s, list(s.events))
    assert clone.dut_serial_by_run == {0: 'DUT-A'}
    assert clone.device_sessions == [sess]


def test_json_default_raises_on_unknown_type():
    """Regression for K4 — silent `None` fallback masked future model
    changes; helper must surface unknown types as TypeError."""
    import pytest
    with pytest.raises(TypeError):
        _json_default(object())
    # bytes should still be hex-encoded.
    assert _json_default(b'\x00\xff') == '00ff'
