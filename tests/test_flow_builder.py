from usb_analysis.analysis.config import AnalysisConfig
from usb_analysis.analysis.flow_builder import build_flow_stream
from usb_analysis.analysis.parser import UsbPacket


def test_command_response_pair():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap'),
        UsbPacket(1,'C','bulk',1,'IN',1.01,0,10,b'OK D736D92D\n',False,'a.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    assert len(stream.events) == 2
    assert stream.events[0].event_class in {'command','crc_probe'}
    assert stream.events[1].event_class == 'response_ok'
    assert stream.events[0].paired_seq == stream.events[1].seq


def test_empty_input_returns_empty_stream():
    stream = build_flow_stream([], AnalysisConfig())
    assert stream.events == []
    assert stream.stats.run_count == 0
    assert stream.total_duration_s == 0.0


def test_timeout_emitted_when_no_response():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'checked-init ABCD1234\n',False,'a.pcap'),
        # 35s gap and another command of the same urb stream — segment_timeout_s=30s.
        UsbPacket(2,'S','bulk',1,'OUT',36.0,0,10,b'checked-next 11111111\n',False,'a.pcap'),
        UsbPacket(2,'C','bulk',1,'IN',36.01,0,10,b'OK D736D92D\n',False,'a.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    timeouts = [e for e in stream.events if e.event_class == 'timeout']
    assert timeouts, "expected a timeout event for the unanswered first command"
    assert stream.stats.timeouts >= 1


def test_incomplete_segment_when_new_command_before_response():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap'),
        # A second command arrives before the first one has any response.
        UsbPacket(2,'S','bulk',1,'OUT',1.002,0,10,b'checked-init ABCD1234\n',False,'a.pcap'),
        UsbPacket(2,'C','bulk',1,'IN',1.012,0,10,b'OK D736D92D\n',False,'a.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    incomplete = [e for e in stream.events if e.event_class == 'incomplete_segment']
    assert incomplete


def test_reconnect_emitted_on_long_bulk_gap():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap'),
        UsbPacket(1,'C','bulk',1,'IN',1.01,0,10,b'OK D736D92D\n',False,'a.pcap'),
        # 10s gap > reconnect_gap_s=5s.
        UsbPacket(2,'S','bulk',1,'OUT',12.0,0,10,b'ping\n',False,'a.pcap'),
        UsbPacket(2,'C','bulk',1,'IN',12.01,0,10,b'OK D736D92D\n',False,'a.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    reconnects = [e for e in stream.events if e.event_class == 'reconnect']
    assert reconnects
    assert stream.stats.reconnects >= 1


def test_multi_source_files_tracked():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap'),
        UsbPacket(1,'C','bulk',1,'IN',1.01,0,10,b'OK D736D92D\n',False,'a.pcap'),
        UsbPacket(2,'S','bulk',1,'OUT',2.0,0,10,b'ping\n',False,'b.pcap'),
        UsbPacket(2,'C','bulk',1,'IN',2.01,0,10,b'OK D736D92D\n',False,'b.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    assert set(stream.source_files) == {'a.pcap', 'b.pcap'}


def test_device_change_emits_session_boundary():
    """Two devices in one capture must produce a device_change event and two sessions."""
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap',bus_id=1,device_address=5),
        UsbPacket(1,'C','bulk',1,'IN',1.01,0,10,b'OK D736D92D\n',False,'a.pcap',bus_id=1,device_address=5),
        # Different device address — should be detected as a new session.
        UsbPacket(2,'S','bulk',1,'OUT',2.0,0,10,b'ping\n',False,'a.pcap',bus_id=1,device_address=6),
        UsbPacket(2,'C','bulk',1,'IN',2.01,0,10,b'OK AAAABBBB\n',False,'a.pcap',bus_id=1,device_address=6),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    changes = [e for e in stream.events if e.event_class == 'device_change']
    assert len(changes) == 1
    assert len(stream.device_sessions) == 2
    s0, s1 = stream.device_sessions
    assert (s0.bus_id, s0.device_address) == (1, 5)
    assert (s1.bus_id, s1.device_address) == (1, 6)
    assert s0.device_serial == 'D736D92D'
    assert s1.device_serial == 'AAAABBBB'
    # Every event carries device identity.
    assert all(e.bus_id in (1,) for e in stream.events)
    assert {e.device_session for e in stream.events} == {0, 1}


def test_chunked_command_does_not_emit_incomplete_segment():
    """Long ASCII command split across multiple bulk OUT submits — must be
    recognized as one chunked command, not as a series of `incomplete_segment`
    errors. The protocol uses CR/LF terminator, so absence of CR/LF on a
    submit's payload means the next submit is a continuation."""
    long_arg = "30820fdf30820655a003020102020868b00bcafebabedeadbeef" * 10
    chunk1 = b'checked-secrets-certdev-write ' + long_arg[:200].encode()        # no newline
    chunk2 = long_arg[200:400].encode()                                         # no newline
    chunk3 = long_arg[400:].encode() + b' ABCD1234\r\n'                         # terminator
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,    0, len(chunk1), chunk1, False, 'a.pcap'),
        UsbPacket(2,'S','bulk',1,'OUT',1.0015, 0, len(chunk2), chunk2, False, 'a.pcap'),
        UsbPacket(3,'S','bulk',1,'OUT',1.0030, 0, len(chunk3), chunk3, False, 'a.pcap'),
        UsbPacket(3,'C','bulk',1,'IN', 1.0050, 0, 14,           b'OK D736D92D\r\n', False, 'a.pcap'),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    incomplete = [e for e in stream.events if e.event_class == 'incomplete_segment']
    assert not incomplete, f'unexpected incomplete_segment events: {[e.content for e in incomplete]}'
    commands = [e for e in stream.events if e.event_class == 'command']
    assert len(commands) == 1, 'chunked command must collapse to a single command event'
    parent = commands[0]
    assert parent.is_chunked is True
    assert parent.chunk_count == 2
    assert parent.cmd_name == 'checked-secrets-certdev-write'
    chunks = [e for e in stream.events if e.event_class == 'command_chunk']
    assert len(chunks) == 2
    assert all(e.severity == 'ok' for e in chunks)
    assert stream.stats.chunked_commands == 1
    # The response still pairs with the parent command.
    response = [e for e in stream.events if e.event_class == 'response_ok']
    assert response and response[0].paired_seq == parent.seq


def test_single_device_one_session():
    pkts = [
        UsbPacket(1,'S','bulk',1,'OUT',1.0,0,10,b'ping\n',False,'a.pcap',bus_id=1,device_address=5),
        UsbPacket(1,'C','bulk',1,'IN',1.01,0,10,b'OK D736D92D\n',False,'a.pcap',bus_id=1,device_address=5),
    ]
    stream = build_flow_stream(pkts, AnalysisConfig())
    assert len(stream.device_sessions) == 1
    assert not [e for e in stream.events if e.event_class == 'device_change']
