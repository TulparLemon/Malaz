# Security Model & Self-Protection

> **Design Premise:** Malaz parses untrusted, potentially weaponized files. The analyzer itself must never become an attack vector, leak user files to external services, or disguise an failed/skipped check as a clean result.

---

## 1. Offline-by-Default & Complete Opt-In Network Inventory

By default, Malaz opens **zero network sockets** during startup, file scanning, YARA evaluation, or report export. There are no accounts, no telemetry, no crash uploads, and no cloud APIs.

Every network capability in the codebase is **disabled by default** and restricted to explicit user actions:

| Opt-In Path | Module | Outbound Data | When Triggered | Default |
| :--- | :--- | :--- | :--- | :---: |
| **ClamAV `freshclam`** | `src/malaz/analysis/clamav_update.py` | Downloads signed `.cvd`/`.cld` databases (zero user file data) | Manual script/button or *"Update ClamAV on startup"* toggle | **Off** |
| **Public Blocklist Refresh** | `src/malaz/core/feeds.py` | Downloads public hash/URL/domain/CIDR lists over allowlisted `https://` URLs (URL feeds hashed on the fly in 64 KB chunks without writing live URLs to disk) | Manual *"Datenbanken nachladen"* dialog or startup toggle | **Off** |
| **`--clamav-update-check`** | `src/malaz/analysis/clamav_status.py` | Single 64-byte HTTP Range request to `database.clamav.net` | Explicit `--clamav-update-check` CLI flag only | **Off** |
| **ReversingLabs YARA Update** | `src/malaz/core/yara_update.py` | Downloads rule ZIP from `codeload.github.com` | Manual GUI update button only | **Off** |
| **`signature-base` YARA Update** | `src/malaz/core/yara_signature_base.py` | Downloads rule ZIP from `codeload.github.com` | Manual `scripts/update_signature_base.bat` / `.py` run | **Off** |
| **Mail URL Reputation** | `src/malaz/core/url_reputation.py` | **SHA-256 hash of URL only** (fragments stripped; private/loopback/link-local/intranet hosts never queried) to a user-configured `https://` endpoint | Only when user configures an endpoint **and** enables `URL_REPUTATION_ENABLED` | **Off** |
| **Mail DNS SPF/DMARC** | `src/malaz/core/dns_auth.py` | Queries system DNS resolver (`Resolve-DnsName`) for sender domain SPF/DMARC/DKIM TXT records (no mail body/attachments; DNSSEC/DKIM crypto signatures not verified) | Only when *"SPF/DMARC über DNS prüfen"* toggle is enabled | **Off** |

*(Note: Local URL blocklist matching against `%LocalAppData%\Malaz\hashes\urls.sha256` is 100% offline and independent of `URL_REPUTATION_ENABLED`.)*

---

## 2. The Completeness Invariant (*"Unchecked Is Never Clean"*)

When a stage cannot inspect file bytes, Malaz never silently emits `GREEN`:

| Failure Class | Indicator(s) | Weight | Verdict Impact |
| :--- | :--- | :---: | :--- |
| **Optional external tool absent (no bytes hidden)** | `AV_SKIPPED`, `CLAMAV_SKIPPED`, `CAPA_SKIPPED`, `DIE_SKIPPED`, `MAIL_REPUTATION_WARN`, `OFFICE_LIB_MISSING` (general) | `0` | Visible in Engine Strip, detail pane, and report |
| **XLM macro parser missing on Excel macro formats** | `OFFICE_LIB_MISSING` (on `.xls`, `.xlsm`, `.xlsb`) | **`25`** | Forces at least **`YELLOW`** (`> SCORE_GREEN_MAX = 19`) |
| **PDF structure / action-graph parse warning** | `PDF_PARSE_WARN` | **`20`** | Forces at least **`YELLOW`** |
| **PDF structural link cap reached** | `PDF_LINK_CAPPED` | **`0`** | Marks result *incomplete* (`_INCOMPLETE_RULES` in `src/malaz/models.py`, GUI `Ungeprüft`, CLI exit code `3`) |
| **Unchecked content due to missing parser, error, or size cap** | `PDF_LIB_MISSING`, `PDF_JS_PARSE_WARN`, `YARA_SCAN_ERROR`, `YARA_LOAD_ERROR`, `CLAMAV_SIZE_LIMIT`, `ARCH_7Z_MISSING` (`20`), `CORE_READ_TRUNCATED` (`20`), `CORE_LIMIT`, `CORE_ERROR` | **`20–25`** | Forces at least **`YELLOW`** + marks result *incomplete* (`_INCOMPLETE_RULES` in `src/malaz/models.py`, CLI exit code `3`) |

---

## 3. Archive, Decompression & Parser Hardening

### Path Traversal & Unsafe Archive Member Names (`src/malaz/security/safe_extract.py`)
- **Zip-Slip vs. Benign OS Name Incompatibilities:** `unsafe_name_reason()` distinguishes true path escapes (`..\..\evil.dll`, drive letters, trailing Windows dots/spaces like `.. `), scored as **`ARCH_ZIPSLIP` (`CRITICAL` / `50`, `RED` anchor)**, from non-traversal Windows device/ADS names (`CON.txt`, `file:stream`) scored as **`ARCH_UNSAFE_NAME` (`LOW` / `5`)**.
- **In-Memory Content Inspection of Unsafe Names:** `ZIP` and `TAR` iterators still scan the payload bytes of unsafe-named entries in memory rather than skipping them, closing name-based detection bypasses.
- **OneNote `.one` Scope Boundary:** Static `FileDataStoreObject` extraction (`src/malaz/core/onenote_extract.py`) unpacks plaintext embedded attachments under the standard entry/size/depth budgets and marks corrupt/truncated objects as incomplete (`ONENOTE_OBJ_ERROR`). Password-encrypted OneNote sections do not expose plaintext `FileDataStoreObject` payloads and are a known static-analysis boundary.
- **Symlink & NTFS Junction Containment:** Symlinks/reparse points are never followed during extraction or YARA directory cleanup.
- **Bounded Streaming ZIP Reads (`read_zip_member_bounded`):** Both archive inspection and opt-in YARA feed updaters read streams via a cloned `ZipInfo` descriptor (`max_bytes + 1`) with manual CRC-32 verification and cumulative `64 MiB` budget accounting before skipping oversized entries, defeating forged `file_size == 0` ZIP headers.

### Resource & DoS Limits (`src/malaz/config.py`)

| Constant | Default | Purpose |
| :--- | :---: | :--- |
| `MAX_FILE_SIZE` | `2 GB` | Hard upper file size ceiling (`CORE_LIMIT` above) |
| `MAX_READ_SIZE` / `MAX_LARGE_FILE_SIZE` | `64 MB` | Switch point from in-memory buffer to chunked `FileSource` streaming |
| `MAX_LARGE_PREFIX_SIZE` | `8 MB` | Bounded prefix passed to deep buffer parsers on `> 64 MB` files |
| `MAX_FILE_SCAN_SECONDS` | `120 s` | Per-file wall-clock budget (`CORE_TIME_BUDGET` on expiry) |
| `MAX_UNCOMPRESSED_SIZE` | `4 GB` | Cumulative archive extraction ceiling |
| `MAX_EXTRACTED_FILE_SIZE` | `512 MB` | Single archive member extraction ceiling |
| `MAX_ARCHIVE_ENTRIES` / `MAX_ARCHIVE_DEPTH` | `10,000` / `5` | Central-directory pre-check & nested archive recursion cap |
| `MAX_FORMULA_CELLS` / `MAX_FORMULA_MEMBER_SIZE` | `250,000` / `64 MB` | `.xlsx` XML & formula scan caps |
| `MAX_QR_FILE_BYTES` / `MAX_QR_PIXELS` / `MAX_PDF_QR_DECODED_BYTES` | `16 MiB` / `16 MP` / `64 MiB` | Offline QR/MicroQR (`zxing-cpp`) image, Data-URI & PDF filter-bomb caps (`QR_SCAN_INCOMPLETE` fail-closed) |

---

## 4. Subprocess Isolation & Local `clamd` Trade-Offs

- **Zero Shell Execution:** The codebase contains zero `eval`/`exec` calls and zero `shell=True` subprocess invocations. External binaries (`MpCmdRun.exe`, `clamscan.exe`, `clamdscan.exe`, `7z.exe`, `diec.exe`, `capa.exe`, `powershell.exe` with an isolated `PSModulePath` environment for read-only `Get-MpComputerStatus`, `Get-AuthenticodeSignature`, and opt-in `Resolve-DnsName`) are resolved exclusively via fixed installation paths or `src/malaz/core/toolpath.py::which_absolute` (which ignores relative CWD entries) and receive file paths as single literal `argv` elements under hard timeouts.
- **Windows Defender Remediation Policy:** By default (`config.AV_DISABLE_REMEDIATION = False`), on-demand Defender scans allow remediation so threats on end-user systems are neutralized. Analysts preserving samples must use an isolated VM and pass `--static-only` (or set `AV_DISABLE_REMEDIATION = True`).
- **Local `clamd` Daemon (`127.0.0.1:3310`):** On Windows, ClamAV's `clamd` supports only unauthenticated TCP sockets. When Malaz generates a user-local `clamd.conf`, it binds strictly to loopback (`TCPAddr 127.0.0.1`) and sets `EnableShutdownCommand no` and `EnableReloadCommand no` so local processes cannot remotely disable the engine.

---

## 5. Output Sanitization, Atomic Writes & Log Privacy

- **HTML5 & PDF Reports (`src/malaz/security/escaping.py`):** Every untrusted string (filenames, VBA snippets, PDF metadata, EXIF, YARA matches, mail headers) passes through `html.escape(..., quote=True)` and Bidi/invisible-character masking (`U+202E` RLO, zero-width chars). Reports embed zero JavaScript and zero external assets, and defang extracted URLs (`hxxp://`).
- **CSV Formula Injection Protection (`src/malaz/reporting/export.py`):** `safe_cell()` prefixes cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with a single quote to prevent spreadsheet formula execution (`CWE-1236`).
- **Atomic Feed Updates (`src/malaz/core/atomicwrite.py`):** Concurrent blocklist updates use normalized per-path locks (`path_lock`), `fsync` + `os.replace`, and full snapshot rollback so concurrent scans never read truncated or empty lists.
- **Log Privacy (`src/malaz/core/log_privacy.py`):** Diagnostic file logs (`%LOCALAPPDATA%\Malaz\logs\malaz.log`) hash all detected file and user paths at the logging sink (`<datei:3f2a1b9c.pdf>`) and never record mail bodies or attachment contents. QR-code indicator details (`src/malaz/core/qr_scan.py`) redact Wi-Fi passwords (`WIFI:...;P:`), TOTP/migration secrets (`otpauth://`, `otpauth-migration://`), URL credentials, and sensitive query/fragment tokens before emission.
- **Offline QR/MicroQR Scope & Explicit Non-Goals (`src/malaz/core/qr_scan.py`, `src/malaz/pipelines/pdf_qr.py`):** Scans raster images (`PNG`/`JPEG`/`GIF`/`BMP`/`WebP`/`TIFF`), PDF raster `/XObject /Image` (incl. inherited `/Resources`, `/Annots/AP`, `/Form`, `/Pattern`, `/SMask`/`/Mask`), email attachments/unnamed inline images, and HTML/SVG/EML `data:image/` URIs strictly offline via `zxing-cpp`. Explicit non-goals (not rasterized): vector-path QR codes (SVG `<path>`/`<rect>`, PDF vector drawing ops), HTML `<table>`/CSS-grid QR codes, tiled multi-image QR codes, `.ico`, `.msg` HTML Data-URIs, and PDF `BI`/`ID` inline images (reported fail-closed as `QR_SCAN_INCOMPLETE`).
