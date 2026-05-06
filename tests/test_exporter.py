from pathlib import Path

from usb_analysis.analysis.exporter import export_csv, export_json
from usb_analysis.analysis.flow_builder import FlowStream, FlowStats


def test_export_json_csv(tmp_path):
    s = FlowStream(events=[], device_serial='X', source_files=['a.pcap'], total_duration_s=0.0, stats=FlowStats())
    jp = tmp_path / 'o.json'
    cp = tmp_path / 'o.csv'
    export_json(s, str(jp))
    export_csv(s, str(cp))
    assert jp.is_file()
    assert cp.is_file()
