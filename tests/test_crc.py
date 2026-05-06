from usb_analysis.analysis.crc_util import compute_crc32, strip_crc_suffix, validate_crc


def test_crc_roundtrip():
    txt = 'checked-optiga-init'
    crc = compute_crc32(txt)
    ok, found = validate_crc(f'{txt} {crc}')
    assert ok is True
    assert found == crc
    assert strip_crc_suffix(f'{txt} {crc}') == txt
