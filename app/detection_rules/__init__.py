"""
Detection Rules — Windows Shimcache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL, already-parsed AppCompatCache ("Shimcache") entry
(a dict produced by app.security_engine.ScanEngine while decoding the real
binary blob) and returns a Finding dict if a forensically-relevant condition
is met. Rules are pure functions of a "context" dict so they can be unit
tested with synthetic data as well as exercised end-to-end against real
parsed bytes.

Context dict shape (built by the engine for every parsed entry):
    {
        "path": str,               # real cached path string from the entry
        "last_modified": datetime | None,  # real decoded FILETIME (UTC) or None
        "last_modified_raw": int,  # raw 8-byte FILETIME integer (0 == epoch/zeroed)
        "all_paths": list[str],    # every real path parsed in this scan (for cross-entry rules)
        "blob_path": str,          # path to the .bin file this entry came from
        "unrecognized_format": bool,  # True only for the WSC-006 file-level pseudo-entry
    }
"""
import os
import re

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SUSPICIOUS_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".ps1", ".cpl")
SUSPICIOUS_LOCATIONS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
)

DOUBLE_EXTENSION_PATTERNS = (".pdf.exe", ".doc.scr", ".jpg.exe", ".txt.vbs")

# 8+ char alphanumeric/hex-looking folder segment with no vowel-bearing
# dictionary-word structure — a heuristic for randomly-generated staging
# directory names (e.g. "a8f3c9d2", "0f1e2d3c4b").
RANDOM_DIR_RE = re.compile(r"\\([a-f0-9]{8,}|[a-z0-9]{10,})\\")


def _basename(path):
    return path.replace("/", "\\").rsplit("\\", 1)[-1]


def rule_suspicious_execution_location(ctx):
    """WSC-001: The cached path points to a location classic malware
    frequently executes from (Temp, Public, ProgramData, or Downloads)
    combined with an executable-class extension — a strong real-world
    malware-execution-location signature seen across commodity malware
    and living-off-the-land tooling."""
    path = ctx.get("path") or ""
    lowered = path.lower()
    _, ext = os.path.splitext(lowered)
    if ext not in SUSPICIOUS_EXTENSIONS:
        return None
    if any(loc in lowered for loc in SUSPICIOUS_LOCATIONS):
        return _finding(
            "WSC-001", "Suspicious Execution Location", SEVERITY_HIGH,
            f"Shimcache entry '{path}' was executed from a classic malware "
            f"staging location (Temp/Public/ProgramData) with an executable "
            f"extension ({ext}).",
        )
    if "\\downloads\\" in lowered:
        return _finding(
            "WSC-001", "Suspicious Execution Location", SEVERITY_HIGH,
            f"Shimcache entry '{path}' was executed directly from a "
            f"Downloads folder with an executable extension ({ext}).",
        )
    return None


def rule_extension_spoofing(ctx):
    """WSC-002: The cached path uses a double-extension / extension-spoofing
    pattern (e.g. invoice.pdf.exe) — a real disguised-executable indicator
    commonly used in phishing-delivered payloads to trick users relying on
    Explorer's default hidden-extensions setting."""
    path = ctx.get("path") or ""
    lowered = path.lower()
    for pattern in DOUBLE_EXTENSION_PATTERNS:
        if lowered.endswith(pattern):
            return _finding(
                "WSC-002", "Extension Spoofing / Double Extension", SEVERITY_MEDIUM,
                f"Shimcache entry '{path}' uses a disguised double extension "
                f"({pattern}) commonly used to trick users into running "
                f"executables that appear to be documents or media.",
            )
    return None


def rule_zeroed_timestamp(ctx):
    """WSC-003: The entry's LastModifiedFILETIME is exactly zero (which
    decodes to the Windows FILETIME epoch, 1601-01-01 UTC). Real cached
    entries normally carry the real last-modified time of the file at the
    time it was cached; a zeroed value is an anomaly that can indicate
    timestomping, hive/tooling corruption, or an unusual filesystem state
    worth reviewing."""
    if ctx.get("unrecognized_format"):
        return None
    if ctx.get("last_modified_raw") == 0:
        path = ctx.get("path") or ""
        return _finding(
            "WSC-003", "Zeroed / Epoch Last-Modified Timestamp", SEVERITY_LOW,
            f"Shimcache entry '{path}' has a zeroed LastModifiedFILETIME "
            f"(decodes to the 1601-01-01 epoch) — an anomaly worth "
            f"reviewing rather than a real observed modification time.",
        )
    return None


def rule_duplicate_basename_multiple_paths(ctx):
    """WSC-004: Two or more real parsed entries in this scan share the exact
    same filename but were executed from different full paths — evidence of
    the same-named binary running from multiple real locations, a common
    lateral-movement/persistence pattern (e.g. svchost.exe running from a
    non-System32 path alongside the legitimate one)."""
    path = ctx.get("path") or ""
    all_paths = ctx.get("all_paths") or []
    if not path:
        return None
    my_base = _basename(path).lower()
    sibling_paths = {p for p in all_paths if _basename(p).lower() == my_base and p != path}
    if sibling_paths:
        others = ", ".join(sorted(sibling_paths)[:3])
        return _finding(
            "WSC-004", "Duplicate Filename Across Multiple Paths", SEVERITY_MEDIUM,
            f"Shimcache entry '{path}' shares its filename with {len(sibling_paths)} "
            f"other cached path(s) executed from different locations ({others}) — "
            f"possible lateral movement or persistence via a same-named binary.",
        )
    return None


def rule_random_staging_directory(ctx):
    """WSC-005: The cached path passes through a short, random-looking
    directory segment (8+ hex/alphanumeric characters, no dictionary-word
    structure) combined with an executable extension — a heuristic for
    malware-created staging/drop folders (e.g. \\AppData\\Local\\a8f3c9d2\\)."""
    path = ctx.get("path") or ""
    lowered = path.lower()
    _, ext = os.path.splitext(lowered)
    if ext not in SUSPICIOUS_EXTENSIONS:
        return None
    if RANDOM_DIR_RE.search(lowered):
        return _finding(
            "WSC-005", "Random-Looking Staging Directory", SEVERITY_LOW,
            f"Shimcache entry '{path}' references a short, random-looking "
            f"directory segment combined with an executable extension — "
            f"a heuristic pattern for malware-created staging folders.",
        )
    return None


def rule_unrecognized_format(ctx):
    """WSC-006: The blob file's leading magic bytes did not match the
    expected Windows 10 AppCompatCache signature (0x30). This is not a
    crash — it is reported as a parse-note so analysts know the file is
    either a different Shimcache format version (unsupported by this tool)
    or not an AppCompatCache blob at all."""
    if ctx.get("unrecognized_format"):
        blob_path = ctx.get("blob_path") or ""
        return _finding(
            "WSC-006", "Unrecognized AppCompatCache Format", SEVERITY_LOW,
            f"'{blob_path}' does not start with the expected Windows 10 "
            f"AppCompatCache magic (0x30). This tool only parses the "
            f"Windows 10 format; the file may be a different OS version's "
            f"Shimcache format or not an AppCompatCache blob at all.",
        )
    return None


def _finding(rule_id, rule_name, severity, description):
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "description": description,
    }


ALL_RULES = [
    rule_suspicious_execution_location,
    rule_extension_spoofing,
    rule_zeroed_timestamp,
    rule_duplicate_basename_multiple_paths,
    rule_random_staging_directory,
    rule_unrecognized_format,
]
