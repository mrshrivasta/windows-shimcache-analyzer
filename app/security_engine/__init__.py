"""
Security Engine — Windows Shimcache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

REAL binary parser for the Windows 10 AppCompatCache ("Shimcache") format.

Background / expected input
----------------------------
On a live Windows system the Application Compatibility Cache is stored as a
single REG_BINARY value named `AppCompatCache` under the registry key
`HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache`,
inside the SYSTEM registry hive. Parsing a full registry hive is out of
scope for this tool. Instead, this engine accepts the ALREADY-EXTRACTED raw
bytes of that single `AppCompatCache` value as a `.bin` file — a real and
common forensic workflow: analysts pull just that value's raw bytes out of
a live or offline SYSTEM hive with tools such as `reg.exe export`,
RegRipper, a hex/registry editor, or a hive-parsing library, save them to a
`.bin` file, and hand that blob to analysis tooling like this one.

Given a target path, this engine will:
  * If the target is a single file, attempt to parse it as one blob.
  * If the target is a directory, real-walk it (bounded by max_depth /
    max_files / excludes) and attempt to parse every regular file found as
    a blob, skipping nothing based on filename — the real leading bytes of
    each file decide whether it looks like an AppCompatCache blob.

Windows 10 AppCompatCache binary layout (the most common real-world target,
and the only format version this tool supports):

  Header (128 bytes total):
    offset 0   : 4 bytes  - Magic / format signature, must be 0x30000000
                            little-endian (bytes 30 00 00 00) for Windows 10
    offset 4   : 4 bytes  - NumberOfEntries (uint32 LE)
    offset 8   : 120 bytes - padding / unused header space
    offset 128 : entries begin

  Each entry (variable length):
    Signature          4 bytes  ASCII "10ts" (bytes 31 30 74 73)
    Unknown/padding     4 bytes  (real-read, not interpreted)
    PathLength          2 bytes  uint16 LE, length of the path IN BYTES
    Path                PathLength bytes, UTF-16LE encoded
    LastModifiedFILETIME 8 bytes  uint64 LE, Windows FILETIME
                                  (100ns intervals since 1601-01-01 UTC)
    DataSize            4 bytes  uint32 LE
    Data                DataSize bytes  (insertion-flag data, real-read but
                                          not deeply interpreted beyond size)

Parsing is defensive: any truncated/malformed entry increments
`errors_count` and stops further parsing of that blob rather than raising.
A blob whose leading magic bytes are not 0x30 is never crash-parsed as
entries — it is reported via the WSC-006 "unrecognized format" finding.
No sample/mock data is ever generated — every Finding reflects bytes
actually read from a real file on disk.
"""
import os
import struct
import time
from datetime import datetime, timedelta

from app.detection_rules import ALL_RULES

DEFAULT_EXCLUDES = {"/proc", "/sys", "/dev", "/run"}

WIN10_MAGIC = b"\x30\x00\x00\x00"
ENTRY_SIGNATURE = b"10ts"
HEADER_SIZE = 128  # 4 (magic) + 4 (count) + 120 (padding)

# Windows FILETIME epoch (1601-01-01 UTC) expressed as a Python datetime,
# used to convert real 100ns-interval FILETIME integers to real UTC datetimes.
_FILETIME_EPOCH = datetime(1601, 1, 1)


def filetime_to_datetime(filetime):
    """Convert a real Windows FILETIME (100ns intervals since 1601-01-01 UTC)
    to a real Python datetime. Returns None if the value is out of a sane
    representable range (defensive against corrupt/malformed bytes)."""
    if filetime == 0:
        return _FILETIME_EPOCH
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=filetime / 10)
    except (OverflowError, OSError, ValueError):
        return None


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set(DEFAULT_EXCLUDES)
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous blob parse. Returns summary dict."""
        start = time.time()

        if os.path.isfile(self.target_path):
            self._parse_blob_file(self.target_path)
        elif os.path.isdir(self.target_path):
            self._walk(self.target_path, depth=0)
        else:
            self.errors_count += 1

        # Cross-entry rule (WSC-004) needs to see every parsed path across
        # the whole scan, so it is applied in a second pass here rather than
        # per-file, using the real accumulated set of parsed entries.
        self._apply_cross_entry_rules()

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _walk(self, path, depth):
        if self.files_scanned >= self.max_files:
            return
        if self._is_excluded(path):
            return
        if depth > self.max_depth:
            return

        try:
            with os.scandir(path) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
            self.errors_count += 1
            return

        self.dirs_scanned += 1

        for entry in entries:
            if self.files_scanned >= self.max_files:
                return
            full_path = entry.path
            if self._is_excluded(full_path):
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                self.errors_count += 1
                continue

            if is_file:
                self._parse_blob_file(full_path)
            elif is_dir:
                self._walk(full_path, depth + 1)

    # ------------------------------------------------------------------
    # Real binary parsing
    # ------------------------------------------------------------------

    def _parse_blob_file(self, blob_path):
        self.files_scanned += 1
        try:
            with open(blob_path, "rb") as fh:
                data = fh.read()
        except OSError:
            self.errors_count += 1
            return

        self._parsed_entries = getattr(self, "_parsed_entries", [])

        if len(data) < 8 or data[0:4] != WIN10_MAGIC:
            ctx = {
                "path": "",
                "last_modified": None,
                "last_modified_raw": None,
                "all_paths": [],
                "blob_path": blob_path,
                "unrecognized_format": True,
            }
            self._apply_rules(ctx, blob_path)
            return

        num_entries = struct.unpack_from("<I", data, 4)[0]
        offset = HEADER_SIZE
        parsed = 0

        while parsed < num_entries and offset < len(data):
            entry, next_offset = self._parse_entry(data, offset)
            if entry is None:
                self.errors_count += 1
                break
            entry["blob_path"] = blob_path
            self._parsed_entries.append(entry)
            offset = next_offset
            parsed += 1

    def _parse_entry(self, data, offset):
        """Real-parse one Windows 10 AppCompatCache entry starting at
        `offset`. Returns (entry_dict, next_offset) or (None, offset) if the
        entry is malformed/truncated."""
        try:
            if offset + 4 + 4 + 2 > len(data):
                return None, offset
            signature = data[offset:offset + 4]
            if signature != ENTRY_SIGNATURE:
                return None, offset
            # unknown/padding (4 bytes) — real-read, not interpreted
            offset += 8
            path_length = struct.unpack_from("<H", data, offset)[0]
            offset += 2

            if offset + path_length > len(data):
                return None, offset
            raw_path = data[offset:offset + path_length]
            path = raw_path.decode("utf-16-le", errors="replace")
            offset += path_length

            if offset + 8 + 4 > len(data):
                return None, offset
            filetime_raw = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
            data_size = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            if offset + data_size > len(data):
                return None, offset
            offset += data_size  # real-read insertion-flag data, size only

            last_modified = filetime_to_datetime(filetime_raw)

            return {
                "path": path,
                "last_modified": last_modified,
                "last_modified_raw": filetime_raw,
                "unrecognized_format": False,
            }, offset
        except (struct.error, IndexError):
            return None, offset

    def _apply_rules(self, ctx, blob_path):
        for rule in ALL_RULES:
            try:
                result = rule(ctx)
            except Exception:
                self.errors_count += 1
                continue
            if result:
                result["file_path"] = blob_path
                result["permissions_octal"] = ctx.get("path") or ""
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)

    def _apply_cross_entry_rules(self):
        entries = getattr(self, "_parsed_entries", [])
        all_paths = [e["path"] for e in entries]
        for entry in entries:
            ctx = {
                "path": entry["path"],
                "last_modified": entry["last_modified"],
                "last_modified_raw": entry["last_modified_raw"],
                "all_paths": all_paths,
                "blob_path": entry["blob_path"],
                "unrecognized_format": False,
            }
            self._apply_rules(ctx, entry["blob_path"])
