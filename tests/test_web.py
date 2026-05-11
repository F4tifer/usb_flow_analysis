"""End-to-end tests for the FastAPI web app — guards against slots / serialization regressions."""

from __future__ import annotations

import binascii
import struct
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from usb_analysis.web.app import CAPTURE_IDS, app


def _hdr(urb_id, event, xfer, ep, ts_sec, ts_usec, status, plen):
    h = struct.pack("<Q", urb_id)
    h += struct.pack("B", ord(event))
    h += struct.pack("B", xfer)
    h += struct.pack("B", ep)
    h += struct.pack("B", 3)
    h += struct.pack("<H", 1)
    h += struct.pack("b", ord("<"))
    h += struct.pack("b", 0 if plen else ord("<"))
    h += struct.pack("<q", ts_sec)
    h += struct.pack("<i", ts_usec)
    h += struct.pack("<i", status)
    h += struct.pack("<I", plen)
    h += struct.pack("<I", plen)
    h += b"\x00" * (64 - len(h))
    return h


def _rec(ts_sec, ts_usec, body):
    return struct.pack("<IIII", ts_sec, ts_usec, len(body), len(body)) + body


def _build_capture() -> Path:
    """Two ping/OK pairs at +0s and +1s — enough to exercise event serialization."""
    glob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 220)
    ping = b"ping " + f"{binascii.crc32(b'ping') & 0xFFFFFFFF:08X}".encode() + b"\r\n"
    ok = b"OK D736D92D\r\n"
    records = [
        _rec(1, 0, _hdr(1, "S", 3, 0x01, 1, 0, 0, len(ping)) + ping),
        _rec(1, 10000, _hdr(1, "C", 3, 0x81, 1, 10000, 0, len(ok)) + ok),
        _rec(2, 0, _hdr(2, "S", 3, 0x01, 2, 0, 0, len(ping)) + ping),
        _rec(2, 10000, _hdr(2, "C", 3, 0x81, 2, 10000, 0, len(ok)) + ok),
    ]
    f = tempfile.NamedTemporaryFile(suffix=".pcap00", delete=False)
    f.write(glob + b"".join(records))
    f.close()
    return Path(f.name)


@pytest.fixture
def capture_id():
    path = _build_capture()
    cid = "pytest-capture"
    CAPTURE_IDS[cid] = path
    yield cid
    CAPTURE_IDS.pop(cid, None)
    path.unlink(missing_ok=True)


@pytest.fixture
def client():
    return TestClient(app)


def test_summary_endpoint_no_capture(client):
    r = client.get("/api/summary")
    assert r.status_code == 200
    assert r.json()["capture_required"] is True


def test_summary_endpoint_with_capture(client, capture_id):
    r = client.get(f"/api/summary?capture_id={capture_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["total_packets"] == 4
    assert any(d["bus"] == 1 for d in body["devices"])


def test_flow_stream_returns_200_and_serializable_events(client, capture_id):
    """Regression: FlowStats / FlowEvent are slots dataclasses without __dict__."""
    r = client.get(f"/api/flow/stream?capture_id={capture_id}&min_severity=ok")
    assert r.status_code == 200
    body = r.json()
    assert "events" in body
    assert isinstance(body["stats"], dict)
    # Stats dict must include the actual FlowStats fields, not be empty.
    assert "total_events" in body["stats"]
    if body["events"]:
        ev = body["events"][0]
        assert "bus_id" in ev
        assert "device_session" in ev


def test_flow_stream_accepts_empty_has_causal_hints(client):
    """Legacy clients sending `has_causal_hints=` (empty) must not 422."""
    r = client.get("/api/flow/stream?has_causal_hints=")
    assert r.status_code == 200


def test_flow_event_endpoint(client, capture_id):
    r = client.get(f"/api/flow/event/1?capture_id={capture_id}")
    assert r.status_code == 200
    assert r.json()["seq"] == 1


def test_flow_run_endpoint(client, capture_id):
    r = client.get(f"/api/flow/run/0?capture_id={capture_id}")
    assert r.status_code == 200
    assert "rows" in r.json()


def test_flow_sessions_endpoint(client, capture_id):
    """Sessions endpoint must return all device_sessions, regardless of severity."""
    r = client.get(f"/api/flow/sessions?capture_id={capture_id}")
    assert r.status_code == 200
    body = r.json()
    assert "rows" in body
    rows = body["rows"]
    # Synthetic capture has at least one device session.
    assert len(rows) >= 1
    s = rows[0]
    for required in ("session_index", "bus_id", "device_address", "start_seq", "end_seq", "event_count"):
        assert required in s, f"missing field {required}"


def test_flow_search_endpoint(client, capture_id):
    r = client.get(f"/api/flow/search?capture_id={capture_id}&q=ping")
    assert r.status_code == 200
    assert isinstance(r.json()["rows"], list)


def test_baseline_rejects_traversal_strings(client):
    """Path traversal payload must never reach the filesystem layer.

    The route is `/api/baseline/{device}` so URL-encoded slashes either get
    rejected at routing (404) or by our own validator (400). Either way, the
    request must not 200.
    """
    for payload in ("..%2F..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd", "evil%00name"):
        r = client.get(f"/api/baseline/{payload}")
        assert r.status_code in (400, 404), f"{payload} returned {r.status_code}"


def test_baseline_rejects_disallowed_chars(client):
    # Spaces, colons, etc. are not in the allowed regex.
    r = client.get("/api/baseline/foo bar")
    assert r.status_code == 400


def test_static_js_modules_parse_as_esm(client):
    """Regression — every shipped /static/*.js file must be valid ECMAScript
    Module source. Unescaped quotes inside a string literal once shipped
    silently broke the whole UI (uploads, help, i18n switcher) because the
    browser failed to load `i18n.js`. This guards against that class of bug.

    We rely on the host having Node.js available; CI without Node should
    skip rather than fail.
    """
    import shutil, subprocess, tempfile
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    targets = ["app.js", "i18n.js", "flow.js", "detail.js", "timeline.js"]
    for name in targets:
        r = client.get(f"/static/{name}")
        assert r.status_code == 200, f"{name} not served"
        with tempfile.NamedTemporaryFile(suffix=".mjs", delete=False, mode="w", encoding="utf-8") as f:
            f.write(r.text)
            path = f.name
        try:
            res = subprocess.run([node, "--check", path], capture_output=True, text=True, timeout=15)
            assert res.returncode == 0, f"{name} failed ESM parse:\n{res.stderr}"
        finally:
            import os
            os.unlink(path)


def test_unknown_capture_id_returns_404(client):
    """Stale capture IDs (e.g. left over after server restart) must 404 with
    the exact message the JS recovery handler looks for."""
    r = client.get("/api/summary?capture_id=does-not-exist")
    assert r.status_code == 404
    assert "Unknown capture id" in r.text


def test_capture_index_persistence(tmp_path, monkeypatch):
    """Persisted capture map should survive an in-process reset."""
    import importlib
    from usb_analysis.web import app as app_mod

    # Use a fresh state dir so we don't pollute the shared one.
    monkeypatch.setenv("USB_ANALYSIS_STATE_DIR", str(tmp_path))
    importlib.reload(app_mod)

    fake_pcap = tmp_path / "fake.pcap00"
    fake_pcap.write_bytes(b"\xd4\xc3\xb2\xa1")  # at least exists
    app_mod.CAPTURE_IDS["abc-123"] = fake_pcap
    app_mod._save_capture_index()

    # Simulate restart: clear in-memory map and reload from disk.
    app_mod.CAPTURE_IDS.clear()
    app_mod._load_capture_index()
    assert "abc-123" in app_mod.CAPTURE_IDS
    assert app_mod.CAPTURE_IDS["abc-123"] == fake_pcap

    # Stale entry whose file no longer exists should be dropped on reload.
    app_mod.CAPTURE_IDS.clear()
    fake_pcap.unlink()
    app_mod._load_capture_index()
    assert "abc-123" not in app_mod.CAPTURE_IDS
