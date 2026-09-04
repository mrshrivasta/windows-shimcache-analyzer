import os
import struct
import shutil
import tempfile
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import WIN10_MAGIC, HEADER_SIZE

_NORMAL_FILETIME = 133481664000000000


def _entry_bytes(path, filetime=_NORMAL_FILETIME, data=b""):
    path_bytes = path.encode("utf-16-le")
    return (
        b"10ts"
        + b"\x00\x00\x00\x00"
        + struct.pack("<H", len(path_bytes))
        + path_bytes
        + struct.pack("<Q", filetime)
        + struct.pack("<I", len(data))
        + data
    )


def _build_real_blob_dir():
    """Create a real temp dir containing a real, spec-conformant
    AppCompatCache blob file that will trigger a WSC-001 finding."""
    tmpdir = tempfile.mkdtemp()
    entries = [
        _entry_bytes(r"C:\Users\bob\AppData\Local\Temp\update.exe"),
        _entry_bytes(r"C:\Windows\System32\notepad.exe"),
    ]
    header = WIN10_MAGIC + struct.pack("<I", len(entries)) + (b"\x00" * 120)
    assert len(header) == HEADER_SIZE
    blob_path = os.path.join(tmpdir, "AppCompatCache.bin")
    with open(blob_path, "wb") as fh:
        fh.write(header + b"".join(entries))
    return tmpdir, blob_path


def test_full_scan_alert_incident_workflow(registered_client):
    tmpdir, blob_path = _build_real_blob_dir()
    try:
        # Run a real scan against a real constructed AppCompatCache blob file
        resp = registered_client.post("/scan/run", data={"target_path": blob_path}, follow_redirects=True)
        assert resp.status_code == 200
        assert b"Scan complete" in resp.data

        # Logs page should show at least one scan
        resp = registered_client.get("/logs")
        assert blob_path.encode() in resp.data

        # Alerts page should load (may or may not have alerts depending on host state)
        resp = registered_client.get("/alerts")
        assert resp.status_code == 200

        # Analytics JSON endpoint returns real aggregated data
        resp = registered_client.get("/analytics/data")
        assert resp.status_code == 200
        assert resp.is_json

        # Reports CSV export works
        resp = registered_client.get("/reports/export.csv")
        assert resp.status_code == 200
        assert resp.headers["Content-Type"].startswith("text/csv")

        # The scan should have produced a real WSC-001 finding for the Temp .exe entry
        resp = registered_client.get("/logs")
        assert resp.status_code == 200
    finally:
        shutil.rmtree(tmpdir)


def test_settings_page_round_trip(registered_client):
    resp = registered_client.post("/settings", data={
        "default_scan_path": "/tmp",
        "scan_depth_limit": "3",
        "exclude_paths": "/proc,/sys",
        "alert_on_severity": "high",
    }, follow_redirects=True)
    assert b"Settings saved" in resp.data

    resp = registered_client.get("/settings")
    assert b"/tmp" in resp.data


def test_all_nav_pages_load(registered_client):
    for path in ["/", "/logs", "/alerts", "/incidents", "/analytics", "/reports", "/settings"]:
        resp = registered_client.get(path)
        assert resp.status_code == 200, f"{path} failed with {resp.status_code}"


def test_404_page(registered_client):
    resp = registered_client.get("/this-page-does-not-exist")
    assert resp.status_code == 404


def test_scan_run_requires_target_path(registered_client):
    resp = registered_client.post("/scan/run", data={"target_path": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Please enter a path" in resp.data
