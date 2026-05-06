from usb_analysis.analysis.causal import enrich_causal
from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import UsbPacket


def test_timeout_hint_before_error():
    pkts = [
        # First command sent but never answered → timeout will be injected.
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'checked-cmd ABCD1234\n',False,'a.pcap'),
        # Second command, paired complete uses the matching urb_id.
        UsbPacket(2,'S','bulk',1,'OUT',40.0,0,10,b'checked-next 11111111\n',False,'a.pcap'),
        UsbPacket(2,'C','bulk',1,'IN',40.01,0,10,b'ERROR bad\n',False,'a.pcap'),
    ]
    stream = enrich_causal(build_flow_stream(pkts, AnalysisConfig()), AnalysisConfig())
    errs = [e for e in stream.events if e.event_class == 'response_error']
    assert errs
    assert errs[0].causal_hints
    # Window must include either the timeout or the prior incomplete segment.
    causal_classes = {stream.events[s - 1].event_class for s in errs[0].causal_window}
    assert causal_classes & {'timeout', 'incomplete_segment'}
