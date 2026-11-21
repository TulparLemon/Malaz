# Usage, CLI Reference & Optional Feeds

## 1. Desktop GUI Workflow

Launch the desktop interface via `Malaz.exe`, `start.bat`, or `python -m malaz`:

1. **Drop or Select Files/Folders:** Drag suspicious files or directories onto the main window.
2. **Inspect Verdicts & Engine Strip:** Each scanned item displays:
   - Traffic-light risk badge (`GREEN` 0–19, `YELLOW` 20–49, `RED` 50–100), marked *(unvollständig / incomplete)* whenever any content-bearing stage could not run,
   - Per-engine status chips (`Defender`, `ClamAV`, `YARA`: clean / threat / unchecked),
   - Score breakdown (`src/malaz/gui/score_breakdown.py`) and plain-language explanation + recommended next step.
3. **Safe Email Preview:** For `.eml` and `.msg` files, open the dedicated plain-text mail panel (`src/malaz/gui/mail_panel.py`) to inspect sender/reply-to mismatches, authentication headers, defanged URLs (`hxxp://`), and recursively scanned attachments without rendering untrusted HTML or remote images.
4. **Export Reports:** Save self-contained HTML5 or PDF triage reports, or export batch results as sanitized CSV/JSON.

### The *"Optionen…"* Dialog

All opt-in switches live behind the **Optionen…** button in the bottom status bar (`src/malaz/gui/options_dialog.py`) and apply consistently to both GUI and `--cli` runs:

| Category | Toggle | Effect | Default |
| :--- | :--- | :--- | :--- |
| **Network** | Update ClamAV on startup | Runs `freshclam` when signatures are stale | **Off** |
| **Network** | Refresh blocklists on startup | Downloads configured public hash/URL/domain/CIDR feeds if older than `FEEDS_AUTO_UPDATE_MIN_AGE_DAYS` (1 day) | **Off** |
| **Network** | Check SPF/DMARC via DNS | Queries system DNS resolver for sender domain SPF/DMARC/DKIM records during `.eml`/`.msg` scans | **Off** |
| **Analysis** | Capability analysis (slow) | Runs local `capa` binary on executables | **Off** |

---

### What Malaz Can and Cannot Verify (and the `.eml` Path)

| Question | What Malaz Checks | Recommended Workflow |
| :--- | :--- | :--- |
| **"Does this file contain malware, scripts, or hidden actions?"** | Static pipelines (`PDF`, Office macros/DDE/XLM, archives, executables, images) + local Defender/ClamAV/YARA + structural `/URI` link extraction against local blocklists | Scan the file directly in GUI or `--cli` |
| **"Is this email sender genuine or is it phishing?"** | Header authentication (`SPF`/`DKIM`/`DMARC`), display-name & `Reply-To` spoofing, defanged body links, and recursive attachment triage | **Save and scan the full `.eml` or `.msg` email**, not just the extracted PDF attachment |
| **"Is this brand-new invoice domain trustworthy?"** | Local blocklists match known malicious URLs/domains/IPs offline; unknown domains remain `GREEN` with a visible defanged `PDF_LINK` note | Verify unexpected payment requests or links via a second channel (phone/known portal) |

---

## 2. Command-Line Interface (`--cli` & Diagnostics)

```bat
:: Scan a single file and write an HTML report
python -m malaz --cli C:\Samples\invoice.pdf --report report.html

:: Scan directories and files recursively (up to config.MAX_BATCH_FILES = 5000)
python -m malaz --cli C:\DropFolder C:\Samples\archive.zip --report batch.html

:: Purely static scan (disables Windows Defender & ClamAV; preserves forensic samples)
python -m malaz --cli C:\Samples\suspect.docm --static-only --report static.html

:: Show local engine, Defender, and privilege status (offline)
python -m malaz --status

:: Show offline ClamAV database version & age
python -m malaz --clamav-status

:: Explicit opt-in online ClamAV version check (64-byte range request to database.clamav.net)
python -m malaz --clamav-update-check

:: Batch corpus evaluation mode (writes CSV/JSON metrics)
python -m malaz --evaluate C:\Corpus --static-only --csv results.csv
```

### CLI Exit Codes

When scanning multiple files or archives with children, `--cli` returns the highest-severity exit code across all inspected items:

| Exit Code | Meaning |
| :---: | :--- |
| `0` | All inspected files are `GREEN` and complete |
| `1` | CLI usage error or unhandled fatal runtime failure |
| `2` | At least one file (or archive child) scored `RED` (`>= 50`) |
| `3` | Highest verdict is `YELLOW` (`20–49`) or scan was incomplete/errored |

---

## 3. Custom & Optional YARA Rules

- **Bundled First-Party Rules:** `rules/yara/malaz_default.yar`, `rules/yara/malaz_extended.yar`, and `rules/yara/malaz_unix.yar` (`GPL-3.0-or-later`).
- **Adding Custom Rules:** Place `.yar` files in `rules/yara/`. Whenever you edit a bundled `.yar` file that has a precompiled `.yarc` companion, recompile with `--force` so the updated source takes effect:

```bat
python scripts/compile_yara.py --force
```

### Opt-In External YARA Feeds (User-Fetched Only)

Malaz never bundles third-party YARA rules in releases (`scripts/check_release.py` enforces this). Users can fetch two independent upstream rule sets onto their own machine; each feed owns a separate directory and enforces bounded streaming ZIP decompression (`64 MiB` cap):

1. **ReversingLabs YARA Rules (MIT)** → `rules/yara/external/` (via the GUI *"YARA-Regeln nachladen"* action / `src/malaz/core/yara_update.py`).
2. **Neo23x0 `signature-base` (DRL 1.1 + per-rule licenses)** → `rules/yara/signature_base/`:

```bat
scripts\update_signature_base.bat
python scripts/update_signature_base.py --status
```

---

## 4. Offline Threat-Intel Blocklists & Feed Manifests

Malaz supports completely offline hash, URL, domain, and CIDR matching:

- **Tracked format example:** `rules/hashes/blocklist.sha256` (curated format documentation / EICAR hash).
- **User-imported feeds (stored outside Git under `%LocalAppData%\Malaz\hashes\`):**
  - File SHA-256 blocklist (`blocklist.sha256`): hits trigger a `CRITICAL` anchor (`50`, `RED`).
  - Defanged/hashed URL blocklist (`urls.sha256`): stores **only SHA-256 hashes** of malicious URLs (never live URLs on disk, avoiding AV false alarms on feed files); hits trigger `MAIL_LINK_REPUTATION` (`HIGH` / `30`) with zero network traffic.
  - Domain (`domains.txt`) and IP/CIDR (`netze.txt`) lists.

```bat
:: Import SHA-256 file hashes from any local text/CSV/JSON export
python scripts/import_blocklist.py local_hashes.txt --dry-run
python scripts/import_blocklist.py local_hashes.txt

:: Import malicious URLs as SHA-256 hashes (offline link reputation)
python scripts/import_blocklist.py urlhaus_urls.txt --urls

:: Verify local feed ages and HMAC-SHA256 integrity manifest
python scripts/verify_feeds.py
```

Every feed import writes atomically (`src/malaz/core/atomicwrite.py`) with byte-exact rollback on failure and records file sizes and SHA-256 digests in `%LocalAppData%\Malaz\hashes\feeds\feed-manifest.json` (protected by a local HMAC key to detect truncation or accidental corruption). For air-gapped machines, copy `%LocalAppData%\Malaz\hashes\`, `rules\yara\external\bundle.yarc`, and the ClamAV DB folder via USB and run `python scripts/verify_feeds.py`.

---

## 5. Diagnostic Logs

- **Source / CLI / Developer Mode:** Logs write to `%LOCALAPPDATA%\Malaz\logs\malaz.log` (overridable via `MALAZ_LOG_DIR`), never polluting the current working directory.
- **Portable Standalone `Malaz.exe`:** Writes `malaz.log` next to `Malaz.exe`.
- **Log Privacy (`src/malaz/core/log_privacy.py`):** File paths in log files are automatically pseudonymized at the handler sink (e.g., `<datei:3f2a1b9c.pdf>`) so diagnostic logs can be shared without leaking sensitive filenames or user directory paths.
