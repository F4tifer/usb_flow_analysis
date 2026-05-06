from usb_analysis.analysis.aggregator import detect_timing_drift


def test_detect_timing_drift_stable():
    # 1% drift, well below the 5% warning threshold.
    d = detect_timing_drift({'cmd': [100] * 10 + [101] * 10}, window=5)
    assert d['cmd'] == 'stable'


def test_detect_timing_drift_warning():
    # Tail mean ≈ 10.6% higher than head — between 5% and 20%.
    d = detect_timing_drift({'cmd': [10] * 10 + [11] * 10}, window=10)
    assert d['cmd'] == 'warning'


def test_detect_timing_drift_critical():
    # Tail mean is 50% higher than head — well above 20%.
    d = detect_timing_drift({'cmd': [10] * 10 + [15] * 10}, window=10)
    assert d['cmd'] == 'critical'


def test_detect_timing_drift_insufficient_samples():
    d = detect_timing_drift({'cmd': [10, 20]}, window=5)
    assert d['cmd'] == 'stable'
