"""Tests for the Security Engine and Detection Rules — the rule tests use
synthetic context dicts, and the engine tests BUILD REAL, SPEC-CONFORMANT
Windows 10 AppCompatCache blob bytes from scratch with struct.pack, write
them to a real temp .bin file, and run the actual ScanEngine against it
(no mocking of the binary parser)."""
import os
import struct
import tempfile
import shutil
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine, filetime_to_datetime, WIN10_MAGIC, HEADER_SIZE
from app.detection_rules import (
    rule_suspicious_execution_location,
    rule_extension_spoofing,
    rule_zeroed_timestamp,
    rule_duplicate_basename_multiple_paths,
    rule_random_staging_directory,
    rule_unrecognized_format,
)


# ---------------------------------------------------------------------------
# Real binary blob builder helpers
# ---------------------------------------------------------------------------

def _entry_bytes(path, filetime=0, data=b""):
    """Build one real, spec-conformant Windows 10 AppCompatCache entry."""
    path_bytes = path.encode("utf-16-le")
    return (
        b"10ts"
        + b"\x00\x00\x00\x00"                       # unknown/padding
        + struct.pack("<H", len(path_bytes))         # PathLength
        + path_bytes                                  # Path (UTF-16LE)
        + struct.pack("<Q", filetime)                 # LastModifiedFILETIME
        + struct.pack("<I", len(data))                 # DataSize
        + data                                          # insertion-flag data
    )


def _build_blob(entries):
    """Build a real Windows 10 AppCompatCache header + entries blob."""
    header = WIN10_MAGIC + struct.pack("<I", len(entries)) + (b"\x00" * 120)
    assert len(header) == HEADER_SIZE
    body = b"".join(_entry_bytes(*e) if isinstance(e, tuple) else _entry_bytes(e) for e in entries)
    return header + body


def _write_blob(tmpdir, filename, entries):
    path = os.path.join(tmpdir, filename)
    with open(path, "wb") as fh:
        fh.write(_build_blob(entries))
    return path


# A real, non-zero Windows FILETIME (2024-01-01 UTC) used for "normal" entries.
_NORMAL_FILETIME = 133481664000000000


# ---------------------------------------------------------------------------
# Rule-level unit tests (synthetic context dicts)
# ---------------------------------------------------------------------------

def test_rule_suspicious_execution_location_temp_exe():
    ctx = {"path": r"C:\Users\bob\AppData\Local\Temp\update.exe", "all_paths": []}
    result = rule_suspicious_execution_location(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-001"
    assert result["severity"] == "high"


def test_rule_suspicious_execution_location_downloads():
    ctx = {"path": r"C:\Users\bob\Downloads\invoice.exe", "all_paths": []}
    result = rule_suspicious_execution_location(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-001"


def test_rule_suspicious_execution_location_clean_path():
    ctx = {"path": r"C:\Program Files\Vendor\app.exe", "all_paths": []}
    assert rule_suspicious_execution_location(ctx) is None


def test_rule_extension_spoofing_detected():
    ctx = {"path": r"C:\Users\bob\Downloads\invoice.pdf.exe", "all_paths": []}
    result = rule_extension_spoofing(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-002"


def test_rule_extension_spoofing_clean():
    ctx = {"path": r"C:\Program Files\Vendor\app.exe", "all_paths": []}
    assert rule_extension_spoofing(ctx) is None


def test_rule_zeroed_timestamp_detected():
    ctx = {"path": r"C:\Windows\System32\cmd.exe", "last_modified_raw": 0, "unrecognized_format": False}
    result = rule_zeroed_timestamp(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-003"


def test_rule_zeroed_timestamp_clean():
    ctx = {"path": r"C:\Windows\System32\cmd.exe", "last_modified_raw": _NORMAL_FILETIME, "unrecognized_format": False}
    assert rule_zeroed_timestamp(ctx) is None


def test_rule_duplicate_basename_multiple_paths_detected():
    ctx = {
        "path": r"C:\Users\bob\AppData\Local\Temp\svchost.exe",
        "all_paths": [r"C:\Windows\System32\svchost.exe", r"C:\Users\bob\AppData\Local\Temp\svchost.exe"],
    }
    result = rule_duplicate_basename_multiple_paths(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-004"


def test_rule_duplicate_basename_multiple_paths_clean():
    ctx = {"path": r"C:\Windows\System32\cmd.exe", "all_paths": [r"C:\Windows\System32\cmd.exe"]}
    assert rule_duplicate_basename_multiple_paths(ctx) is None


def test_rule_random_staging_directory_detected():
    ctx = {"path": r"C:\Users\bob\AppData\Local\a8f3c9d2\payload.exe", "all_paths": []}
    result = rule_random_staging_directory(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-005"


def test_rule_random_staging_directory_clean():
    ctx = {"path": r"C:\Program Files\Vendor\app.exe", "all_paths": []}
    assert rule_random_staging_directory(ctx) is None


def test_rule_unrecognized_format_detected():
    ctx = {"unrecognized_format": True, "blob_path": "/tmp/weird.bin"}
    result = rule_unrecognized_format(ctx)
    assert result is not None
    assert result["rule_id"] == "WSC-006"


def test_rule_unrecognized_format_clean():
    ctx = {"unrecognized_format": False, "blob_path": "/tmp/normal.bin"}
    assert rule_unrecognized_format(ctx) is None


def test_filetime_to_datetime_zero_is_epoch():
    dt = filetime_to_datetime(0)
    assert dt.year == 1601 and dt.month == 1 and dt.day == 1


def test_filetime_to_datetime_real_value():
    dt = filetime_to_datetime(_NORMAL_FILETIME)
    assert isinstance(dt, datetime)
    assert dt.year in (2023, 2024)


# ---------------------------------------------------------------------------
# Engine-level tests — REAL bytes, REAL temp .bin file, REAL ScanEngine
# ---------------------------------------------------------------------------

def test_engine_parses_real_blob_and_detects_temp_exe():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Users\bob\AppData\Local\Temp\svchost.exe", _NORMAL_FILETIME),
            (r"C:\Windows\System32\notepad.exe", _NORMAL_FILETIME),
        ])
        engine = ScanEngine(blob)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert result["errors_count"] == 0
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-001" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_extension_spoofing():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Users\bob\Downloads\invoice.pdf.exe", _NORMAL_FILETIME),
        ])
        engine = ScanEngine(blob)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-002" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_zeroed_timestamp():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Windows\System32\cmd.exe", 0),
        ])
        engine = ScanEngine(blob)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-003" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_detects_duplicate_basename_across_paths():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Windows\System32\svchost.exe", _NORMAL_FILETIME),
            (r"C:\Users\bob\AppData\Local\Temp\svchost.exe", _NORMAL_FILETIME),
        ])
        engine = ScanEngine(blob)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-004" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_parses_multiple_real_entries_together():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Users\bob\AppData\Local\Temp\update.exe", _NORMAL_FILETIME),
            (r"C:\Users\bob\Downloads\invoice.pdf.exe", _NORMAL_FILETIME),
            (r"C:\Windows\System32\svchost.exe", _NORMAL_FILETIME),
            (r"C:\Users\bob\AppData\Local\Temp\svchost.exe", 0),
        ])
        engine = ScanEngine(blob)
        result = engine.run()

        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert {"WSC-001", "WSC-002", "WSC-003", "WSC-004"}.issubset(rule_ids)
    finally:
        shutil.rmtree(tmpdir)


def test_engine_clean_blob_produces_no_findings():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Windows\System32\notepad.exe", _NORMAL_FILETIME),
            (r"C:\Program Files\Vendor\app.exe", _NORMAL_FILETIME),
        ])
        engine = ScanEngine(blob)
        result = engine.run()
        assert result["findings"] == []
        assert result["files_scanned"] == 1
    finally:
        shutil.rmtree(tmpdir)


def test_engine_unrecognized_magic_reports_finding_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        bad_path = os.path.join(tmpdir, "old_format.bin")
        with open(bad_path, "wb") as fh:
            fh.write(b"\xFF\xFF\xFF\xFF" + b"\x00" * 40)

        engine = ScanEngine(bad_path)
        result = engine.run()

        assert result["files_scanned"] == 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-006" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_truncated_blob_does_not_crash():
    tmpdir = tempfile.mkdtemp()
    try:
        truncated_path = os.path.join(tmpdir, "truncated.bin")
        header = WIN10_MAGIC + struct.pack("<I", 5) + (b"\x00" * 120)
        # Claim 5 entries but supply zero — the parser must stop cleanly.
        with open(truncated_path, "wb") as fh:
            fh.write(header)

        engine = ScanEngine(truncated_path)
        result = engine.run()

        assert result["files_scanned"] == 1
        assert isinstance(result["findings"], list)
    finally:
        shutil.rmtree(tmpdir)


def test_engine_walks_directory_of_blob_files():
    tmpdir = tempfile.mkdtemp()
    try:
        _write_blob(tmpdir, "host1.bin", [(r"C:\Users\bob\AppData\Local\Temp\a.exe", _NORMAL_FILETIME)])
        _write_blob(tmpdir, "host2.bin", [(r"C:\Windows\System32\b.exe", _NORMAL_FILETIME)])

        engine = ScanEngine(tmpdir, max_depth=2)
        result = engine.run()

        assert result["files_scanned"] == 2
        assert result["dirs_scanned"] >= 1
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-001" in rule_ids
    finally:
        shutil.rmtree(tmpdir)


def test_engine_random_staging_directory_end_to_end():
    tmpdir = tempfile.mkdtemp()
    try:
        blob = _write_blob(tmpdir, "cache.bin", [
            (r"C:\Users\bob\AppData\Local\a8f3c9d2\payload.exe", _NORMAL_FILETIME),
        ])
        engine = ScanEngine(blob)
        result = engine.run()
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "WSC-005" in rule_ids
    finally:
        shutil.rmtree(tmpdir)
