# Windows Shimcache Analyzer

**A real, no-mock-data Windows AppCompatCache (Shimcache) binary parser — CLI + Web App, for digital-forensics execution-evidence analysis.**
Real-parses an already-extracted, Windows 10-format `AppCompatCache` registry-value blob byte-for-byte and flags suspicious execution locations, extension-spoofed filenames, zeroed/epoch timestamps, duplicate filenames executed from multiple paths, and random-looking staging directories.

Developed by **Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)

---

## ⚠️ Disclaimer

This software is provided **strictly for educational, digital-forensics, and defensive-security purposes**, and is offered **"AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED**, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

- **Authorized use only.** Only analyze systems, media, artifact extracts, or files that you own or for which you have explicit, documented authorization to investigate. Analyzing artifacts extracted from systems without authorization may violate computer-crime laws (e.g. the Computer Fraud and Abuse Act, the UK Computer Misuse Act, or equivalent legislation in your jurisdiction), evidentiary/chain-of-custody rules, and organizational policy.
- **No liability.** The author, **Karanam Shrivasta**, and any contributors, accept **no responsibility or liability whatsoever** for any direct, indirect, incidental, special, or consequential damages — including data loss, misinterpretation of evidence, or legal consequences — arising from the use, misuse, or inability to use this software.
- **Not a substitute for certified forensic tools or expert testimony.** This tool is **not a substitute** for validated, court-recognized forensic suites (e.g. EnCase, X-Ways, Magnet AXIOM), a certified forensic examiner, or expert testimony. Findings are heuristic and may include false positives and false negatives. Always corroborate Shimcache evidence with other artifacts (Prefetch, event logs, MFT timestamps, etc.) before drawing conclusions.
- **No guaranteed detection.** Absence of findings does **not** mean a system is clean. AppCompatCache itself has well-documented forensic limitations — an entry records that a path was *referenced* (not necessarily *executed*), cache entries can be evicted (LRU), and this tool only parses the Windows 10 blob format.
- **Read-only by design.** The Security Engine only reads bytes from the blob file you point it at — it never writes to, modifies, or deletes the input file. Verify this yourself by reading `app/security_engine/__init__.py` before running it on anything important.
- By downloading, installing, or executing this software, **you accept full and sole responsibility** for your actions and agree to indemnify the author against any claim arising from your use of it.

If you are unsure whether you are authorized to analyze a given artifact, **do not run this tool against it.**

---

## Input format — read this before use

The Application Compatibility Cache ("Shimcache") is normally stored as a single **REG_BINARY** registry value named `AppCompatCache`, under the key:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

Parsing an entire live/offline registry hive is **out of scope** for this tool. Instead, this analyzer expects the **already-extracted raw bytes of that single `AppCompatCache` value** as a `.bin` file. This is a real, common step in a forensic workflow — analysts typically pull just that value out with tools such as:

- `reg.exe export` against the relevant key, then extracting the value's binary payload
- RegRipper (or a similar registry-hive parsing library) targeting the `AppCompatCache` value
- A hex/registry editor, saving the value's raw bytes to disk

Once you have that `.bin` file, point this tool at it (or at a directory containing one or more such files) and it will real-parse the actual bytes.

**Format support:** this tool supports **only the Windows 10 AppCompatCache format** (identified by the leading magic bytes `30 00 00 00`). This is the most common real-world target and is the only version implemented — earlier/later Windows AppCompatCache layouts (XP, Vista/7, 8/8.1, and future revisions) are **not** parsed; a blob that doesn't start with the Windows 10 magic is reported as an "unrecognized format" finding (WSC-006) rather than misparsed or silently ignored.

---

## Who should use this project

- Digital forensics analysts and incident responders reviewing Shimcache evidence for execution artifacts during an investigation.
- Malware analysts correlating cached execution paths with known staging/drop-folder and extension-spoofing patterns.
- DFIR students and self-learners studying the Windows AppCompatCache binary format and its forensic value.
- Anyone who has legitimately extracted an `AppCompatCache` blob (from a system/media they own or are authorized to investigate) and wants a fast, transparent first pass over it.

## Why use this project

- **Real data only** — every finding comes from bytes actually parsed out of the blob file you provide with `struct`. Nothing is mocked, sampled, or fabricated, in the CLI or the web app.
- **Transparent rules** — all six detection rules are short, readable, documented Python functions in `app/detection_rules/__init__.py`. Nothing is a black box.
- **Two interfaces, one engine** — the CLI (for terminals/CI/scripted triage) and the web app (for case dashboards/teams) both call the exact same `ScanEngine`, so results are always consistent.
- **Full workflow, not just a parser** — findings flow into Alerts, Alerts can be escalated into tracked Incidents, and everything rolls up into Analytics charts and CSV Reports.
- **Free and auditable** — pure Python + Flask + SQLite, no paid services, no telemetry, no external API calls at parse time.

---

## Architecture

```
windows-shimcache-analyzer/
├── app/
│   ├── auth/                 # Authentication (register/login/logout, Flask-Login, hashed passwords)
│   ├── dashboard/            # Dashboard page + "run scan" action
│   ├── security_engine/      # Core real AppCompatCache binary parser (struct-based)
│   ├── detection_rules/      # 6 documented detection rules (WSC-001..006)
│   ├── logs/                 # Scan history = audit log (Logs page)
│   ├── alerts/                # Alert generation from findings + Alerts page
│   ├── incident_management/  # Incident workflow (open -> investigating -> resolved -> closed)
│   ├── analytics/            # Real DB aggregation feeding Chart.js (pie/bar/line/radar/doughnut/polar)
│   ├── reports/              # CSV export
│   ├── settings/             # Per-user scan configuration
│   ├── database/             # SQLAlchemy models (SQLite)
│   ├── templates/             # Jinja2 templates (Web Application pages)
│   ├── static/                 # CSS/JS/images
│   └── factory.py            # create_app() — wires every module together
├── cli/
│   └── main.py                # Standalone CLI (argparse): scan, rules
├── tests/                     # pytest suite — real spec-conformant blob bytes built with struct.pack
├── run.py                     # Web Application entrypoint
├── requirements.txt
└── README.md                  # You are here
```

### Pages (Web Application — 9 total, minimum requirement of 6 exceeded)
1. **Login** — `/login`
2. **Register** — `/register`
3. **Dashboard** — `/` (stat tiles + run-scan form + recent scans)
4. **Logs** — `/logs` and `/logs/<id>` (full scan history + per-scan findings)
5. **Alerts** — `/alerts` (acknowledge / escalate to incident)
6. **Incident Management** — `/incidents` (status workflow)
7. **Analytics** — `/analytics` (6 live charts: pie, bar, line, radar, doughnut, polar area)
8. **Reports** — `/reports` (CSV export, all scans or per-scan)
9. **Settings** — `/settings` (default path, walk depth, exclusions, alert threshold)

---

## Detection Rules

| ID | Name | Severity | What it checks |
|----|------|----------|-----------------|
| WSC-001 | Suspicious Execution Location | High | Cached path in Temp/Public/ProgramData/Downloads combined with an executable-class extension (`.exe`, `.dll`, `.scr`, `.bat`, `.ps1`, `.cpl`) — classic malware-execution-location signature |
| WSC-002 | Extension Spoofing / Double Extension | Medium | Cached path uses a disguised double extension (`.pdf.exe`, `.doc.scr`, `.jpg.exe`, `.txt.vbs`) |
| WSC-003 | Zeroed / Epoch Last-Modified Timestamp | Low | Entry's LastModifiedFILETIME decodes to exactly the 1601-01-01 epoch — a real anomaly |
| WSC-004 | Duplicate Filename Across Multiple Paths | Medium | Two or more parsed entries share the exact same filename but different full paths — possible lateral movement/persistence |
| WSC-005 | Random-Looking Staging Directory | Low | Cached path passes through a short, random-looking (hex/alphanumeric) directory segment plus an executable extension — heuristic for malware staging folders |
| WSC-006 | Unrecognized AppCompatCache Format | Low / Info | The blob's leading magic bytes did not match the Windows 10 signature (`0x30`) — reported as a parse-note, never a crash |

---

## The real Windows 10 AppCompatCache binary layout this tool parses

```
Header (128 bytes):
  offset 0   : 4 bytes   Magic            (must be 30 00 00 00 for Windows 10)
  offset 4   : 4 bytes   NumberOfEntries  (uint32 LE)
  offset 8   : 120 bytes padding / unused

Each entry (variable length), repeated NumberOfEntries times:
  Signature             4 bytes   ASCII "10ts" (31 30 74 73)
  Unknown/padding       4 bytes
  PathLength            2 bytes   uint16 LE (length of Path IN BYTES)
  Path                  PathLength bytes, UTF-16LE
  LastModifiedFILETIME  8 bytes   uint64 LE (100ns intervals since 1601-01-01 UTC)
  DataSize              4 bytes   uint32 LE
  Data                  DataSize bytes  (insertion-flag data; size read, not deeply interpreted)
```

Malformed or truncated bytes anywhere in a blob are handled defensively: parsing of that blob stops, `errors_count` is incremented, and the tool moves on — it never crashes on a bad file.

---

## Setup & Run

### Requirements
- Python 3.9+
- Works on any OS Python runs on — the tool parses bytes from a file, it does not require Windows.

### Install

```bash
git clone <this-repository-url>
cd windows-shimcache-analyzer
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
```

### Run the Web Application

```bash
python3 run.py
# then open http://127.0.0.1:5000
```

Environment variables (optional):

```bash
WSA_SECRET_KEY=change-me   # Flask session secret — set this in production
PORT=5000                  # port to listen on
FLASK_DEBUG=1               # enable the debug reloader (development only)
```

Register an account on first run — accounts and all scan data live in a local SQLite file at `instance/shimcache.db`.

### Run the CLI

```bash
python3 cli/main.py scan /path/to/AppCompatCache.bin
python3 cli/main.py scan /path/to/AppCompatCache.bin --json
python3 cli/main.py scan /path/to/blobs_dir --csv findings.csv
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings are detected (useful as a CI/triage gate) and `0` if the blob is clean.

### Run the tests

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m pytest tests/ -v
```

All 34 tests pass. The engine-level tests build **real, spec-conformant Windows 10 AppCompatCache bytes from scratch with `struct.pack`** (correct magic, entry count, and encoded entries), write them to a real temp `.bin` file, and run the actual `ScanEngine` against them — nothing is mocked.

---

## FAQ (for search & answer engines)

**What does the Windows Shimcache Analyzer check?**
It real-parses an already-extracted Windows 10 AppCompatCache (Shimcache) binary blob and flags suspicious execution locations, extension-spoofed filenames, zeroed/epoch timestamps, duplicate filenames across multiple paths, random-looking staging directories, and unrecognized blob formats — using bytes actually read from the file, never sample data.

**Where do I get an AppCompatCache `.bin` file?**
Export the `AppCompatCache` REG_BINARY value from `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (live or from an offline SYSTEM hive) using `reg.exe export`, RegRipper, or a registry/hex editor, and save its raw bytes to a `.bin` file.

**Does it parse the full registry hive?**
No. It only parses an already-extracted `AppCompatCache` value blob. Full hive parsing is out of scope for this tool.

**Which Shimcache format versions are supported?**
Only the Windows 10 format (leading magic `0x30`). Other OS versions' AppCompatCache layouts are not supported and are reported as an "unrecognized format" finding rather than misparsed.

**Who should use it?**
Digital forensics analysts, incident responders, and security students working with AppCompatCache blobs extracted from systems or media they own or are explicitly authorized to investigate.

**Is it a replacement for certified forensic tools?**
No. It is an educational and productivity aid only — see the Disclaimer section above.

**Does it modify my files?**
No. It only reads the bytes of the blob file you point it at. It never writes to, deletes, or changes the input file.

---

## License & Attribution

Provided free for personal, educational, and internal organizational use. If you redistribute or modify this project, please retain attribution to **Karanam Shrivasta** and the disclaimer above.

**Developed by Karanam Shrivasta**
GitHub: [https://github.com/mrshrivasta](https://github.com/mrshrivasta) · LinkedIn: [https://www.linkedin.com/in/karanam-shrivasta](https://www.linkedin.com/in/karanam-shrivasta)
