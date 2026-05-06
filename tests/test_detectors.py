from usb_analysis.analysis.causal import enrich_causal
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.detectors import detect_errors
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import UsbPacket


def test_detect_app_error():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap'),
        UsbPacket(1,'C','bulk',1,'IN',1.1,0,10,b'ERROR fail\n',False,'a.pcap'),
    ]
    stream = enrich_causal(build_flow_stream(pkts, AnalysisConfig()), AnalysisConfig())
    errors = detect_errors(stream, AnalysisConfig())
    assert any(e.event_type == 'app_error' for e in errors)
