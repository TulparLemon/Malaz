# Changelog

All notable changes to **Malaz** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Security-relevant changes are marked with **SECURITY**.

## [Unreleased]

## [1.3.0] - 2026-11-27

### Added
- **Modern Phishing & Container Format Detection (`DET-001`):**
  - Added `WebContentPipeline` (`src/malaz/pipelines/web_pipeline.py`) with linear HTML5/XML scanning for **HTML smuggling** (`Blob`/`createObjectURL`/Base64-embedded PE/ZIP/ISO payloads), CHM ActiveX execution, offline credential forms, meta-refresh redirects, and active **SVG** scripts/phishing (`WEB_PARSE_LIMIT` completeness cap).
  - Added static **Microsoft OneNote (`.one`)** `FileDataStoreObject` extraction (`src/malaz/core/onenote_extract.py`) with recursive child scanning and explicit parse-error markers (`ONENOTE_PARSE_ERROR`, `ONENOTE_OBJ_ERROR`).
  - Added magic-byte detection and `7-Zip` container routing for **CHM**, **VHDX**, **NTFS**, and **FAT** disk images plus 13 additional risky archive/attachment types with full DE/EN/TR localization.
- **Offline QR & MicroQR Quishing Analysis (`DET-002`):**
  - Added 100% offline QR/MicroQR decoding (`src/malaz/core/qr_scan.py`, `src/malaz/pipelines/pdf_qr.py`, Apache-2.0 `zxing-cpp==3.2.0`) across raster images (`PNG`/`JPEG`/`GIF`/`BMP`/`WebP`/`TIFF`), PDF `/XObject /Image`, `/Annots/AP`, `/Form`, `/Pattern`, and `/SMask`/`/Mask` (with decompression/dimension bomb guards), fail-closed `QR_SCAN_INCOMPLETE` detection for PDF inline `BI`/`ID` images, email attachments, and HTML/SVG/EML `data:image/` payloads.
  - Evaluates decoded QR URLs offline against local blocklists, shorteners, credential/punycode patterns, and dangerous URI schemes with linear O(N) secret redaction and `QR_SCAN_INCOMPLETE` completeness reporting.
- **Deep Static Script Deobfuscation (`DET-003`):**
  - Added 100% stdlib, strictly linear O(N), zero-execution static deobfuscators (`src/malaz/core/script_deobf.py`, `src/malaz/core/js_deobf.py`) wired into `generic_pipeline.py`, `pdf_javascript.py`, and `web_pipeline.py`:
    - **PowerShell:** backtick state machine, `[char[]]`/`[int[]]` decoding, string concatenation, safe `-f` format evaluation, Base64 + bounded GZip/Raw-Deflate decompression, and deduplicated encoded-command extraction.
    - **Windows Batch:** caret (`^`) state machine, `set` variable/substring slicing, and replacement resolution with self-reference protection.
    - **JavaScript:** ES6 `\u{...}` escapes, shared array-join merging (including `.reverse().join()`), single-level string tables, and inline `atob()` decoding (`GEN_SCRIPT_DEOBFUSCATED`, `GEN_DEOBF_LIMIT`).
- **Automated Isolated Malware Lab (`LAB-001`):**
  - Added zero-unpack 64 KiB streaming host ingest (`scripts/lab_ingest.py`) for password-protected ZIPs (AES-256 & ZipCrypto) with atomic rollback, header-spoof/Zip-Slip/symlink/junction/`zlib`/`lzma` guards, and SHA-256 manifest self-validation.
  - Added hardened Windows Sandbox orchestration (`scripts/run_lab_sandbox.ps1`, `scripts/sandbox_inner.ps1`, `scripts/lab_guard.ps1 -SandboxGuest`) with XML-DOM `.wsb` generation, `7z l -slt` pre-extract checks, SHA-256 chain of custody, and a strictly read-only, idempotent post-exit output filter (`FindFirstStreamW` NTFS ADS checks, 0 NUL bytes, strict schema/hash checks, `-VerifyOutputOnly`, `-DryRun`).
  - Added split-filtered regression comparison (`scripts/lab_compare.py`), fail-closed OPSEC leak guard (`src/malaz/lab/opsec.py`), `scripts/triage_misses.py --split`, and operational documentation (`docs/LAB_WORKFLOW.md`).
- **Community Templates & CI-Verified Benchmarks (`TRUST-001`):**
  - Added GitHub issue/PR templates (`.github/ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md`) and deterministic 5-corpus benchmark verification (`docs/BENCHMARKS.md`, 555 benchmark fixtures via `scripts/run_corpus.py --check-doc`; 560 golden-snapshot fixtures across 45 file types).

### Changed
- **Modularized Core & Pipeline Hotspots (`ARCH-001`):** Split `core/eml_analysis.py` (`core/eml_parser.py`), `pipelines/pdf_pipeline.py` (`pdf_streams.py`, `pdf_links.py`, `pdf_javascript.py`), and `core/dispatcher.py` (`core/container_dispatch.py`) with zero behavior change, enforced by a fail-closed facade DAG gate in `scripts/arch_gate.py`.
- Removed 7 verified unused functions/classes and their unused imports across `src/malaz/`.

### Security
- **SECURITY:** Added top-level and nested Unicode BiDi/RLO filename spoofing detection (`GEN_BIDI_NAME`, `CRITICAL`/50) via pure ASCII `ord()` checks (`U+202A..U+202E`, `U+2066..U+2069`) on both `ctx.path.name` and the extracted container display-path leaf while preserving genuine Arabic/Hebrew filenames (`0.0%` benign false positives).
- **SECURITY:** Registered 8 missing incomplete/limit/timeout indicators (`PE_LIB_MISSING`, `PE_SECTION_ENTROPY_LIMIT`, `PE_SECTION_PARSE_WARN`, `PE_TLS_PARSE_WARN`, `PE_IMPORT_PARSE_WARN`, `HEIC_BOX_LIMIT`, `OFFICE_REL_TRUNCATED`, `OFFICE_XLM_TIMEOUT`) in `models._INCOMPLETE_RULES` with full DE/EN/TR parity.
- **SECURITY:** Hardened `security/safe_extract.py` to reject embedded NUL bytes (`REASON_NUL` in `ATTACK_REASONS`) and aligned `core/yara_signature_base.py` to enforce `is_safe_member_name()` matching `core/yara_update.py`.

## [1.2.0] - 2026-11-21

### Added
- **Trilingual UI & Report Localization (`UI-006`, DE / EN / TR / System):** Zero-dependency localization catalog (`src/malaz/i18n.py`, `src/malaz/i18n_catalog.py`, `src/malaz/i18n_catalog_tr.py`) covering **German (`Deutsch`)**, **English (`English`)**, and idiomatic **Turkish (`Türkçe`)** across the entire desktop GUI, 240+ canonical rule findings, and HTML/PDF reports. Supports automatic Windows LCID detection (`System`), live language switching in **Options → Language**, and ephemeral `--lang {system,de,en,tr}` CLI overrides while keeping JSON/CSV exports 100% machine-invariant and preserving the completeness invariant (`Ungeprüft` / `Unchecked` / `Taranamadı`) in all languages.
- **Reproducible Showcase Asset Generator (`scripts/make_showcase_assets.py`):** Regenerates the English README screenshots (`docs/assets/malaz-{ui,overview,light,options}.png`) and animated walkthrough (`docs/assets/malaz-demo.gif`) deterministically from the real PySide6 application.
- **PDF structural link analysis (`PDF-001`):** Extracts `/URI` targets structurally via the bounded action-graph walk (including compressed `/ObjStm` streams and UTF-16BE/LE strings without BOM), strips C0 control characters, filters format namespaces, and checks links offline against local URL/domain/IP blocklists (`PDF_LINK`, `BINARY_IOC_BLOCKED`, `PDF_LINK_CAPPED`).
- Documented the `.eml`/`.msg` workflow for sender/phishing verification and `--lang` usage in `docs/USAGE.md`.

### Fixed
- Fixed `_EngineCapsule.set_engines()` not showing dynamically created engine badges after background `_EngineProbe` completion on an already-visible window.
- Adjusted sidebar status filter chip spacing/stretch so labels (`Alle` / `All` / `Tümü` and `OK`) render without horizontal clipping in all languages.

### Changed
- Tightened `RiskLevel.GREEN.advice` so clean static results never promise safety ("bedenkenlos") and explicitly remind users that sender authenticity and business content still require verification.

## [1.1.0] - 2026-11-18

### Changed
- Reworked the PySide6 desktop GUI ("Klare Fläche v2"): token-based dark/light/system themes (`src/malaz/design_tokens.py`), zero hardcoded hex values in GUI modules, resizable master-detail layout with nested container tree, 3 uniform engine cards, custom risk ring, structured analyst datasheet (IOCs + thin single-line SHA-256), integrated Options & Auto-Update view (including session-only static-only mode), and synchronized bottom footers with safe Explorer reveal (`SHOpenFolderAndSelectItems`).
- Added automatic display and High-DPI scaling adaptation (`HighDpiScaleFactorRoundingPolicy.PassThrough`, `QScreen.availableGeometry()` clamping for main window and dialogs, `screenChanged` re-clamping, and compact responsive layout below 1080 px).

## [1.0.0] — 2026-11-05

Initial public open-source release under **`GPL-3.0-or-later`**.

### Added
- **Desktop GUI & CLI (`PySide6`):** Dark-theme drag-and-drop triage window, per-engine verdict chips (`Defender`, `ClamAV`, `YARA`), score breakdown, safe plain-text `.eml`/`.msg` viewer, headless `--cli` / recursive folder batch scanner, `--static-only` forensic sample-preservation mode, and `--status` diagnostics.
- **Format-Aware Static Pipelines:**
  - **PDF (`pipelines/pdf_pipeline.py`):** Keyword triage, `pikepdf`/qpdf stream & incremental-save analysis, bounded action-graph traversal (`/OpenAction`, `/AA`, `/Launch`), static JS deobfuscation (`core/js_deobf.py`), and invisible-text forensics.
  - **Office (`pipelines/office_pipeline.py`):** OLE/OOXML macro & auto-exec detection (`oletools`), VBA stomping (`pcodedmp`), encoded string extraction, DDE links, Excel 4.0 (`XLM`) deobfuscation (`XLMMacroDeobfuscator`), `.xlsx` formula checks (`openpyxl`), and external OOXML template/relationship detection (`core/ooxml_rels.py`).
  - **Email (`pipelines/eml_pipeline.py`):** `.eml` and `.msg` header spoofing/phishing analysis, optional DNS SPF/DMARC lookup, local & opt-in SHA-256 URL reputation, and bounded recursive attachment scanning.
  - **Executables (`pipelines/pe_pipeline.py`, `elf_pipeline.py`, `macho_pipeline.py`):** PE/ELF/Mach-O structural inspection, Authenticode metadata, RWX/overlay checks, and optional local **Detect It Easy** (`diec.exe`) and **capa** integration.
  - **Images & Containers (`pipelines/image_pipeline.py`, `archive_pipeline.py`, `generic_pipeline.py`):** Magic-byte mismatch detection, PNG/JPEG trailer checks, HEIC/AVIF box validation, recursive `ZIP`/`TAR`/`GZIP`/`BZIP2`/`XZ` and optional `7-Zip` (`7z`/`RAR`/`CAB`/`ISO`) extraction, bundled YARA rules (`malaz_default.yar`, `malaz_extended.yar`, `malaz_unix.yar`), `.lnk`/`.rtf`/`.swf` inspection, and local SHA-256/URL/domain/CIDR blocklists with HMAC-verified local feed manifests.
- **Large-File Streaming (up to 2 GB):** Full in-memory buffer up to 64 MB; chunked 8 MB `FileSource` streaming above 64 MB with explicit partial-inspection indicators (`CORE_READ_TRUNCATED`).
- **Reporting & Exports:** Self-contained, JavaScript-free HTML5 and PDF triage reports plus CSV/JSON batch exports.
- **Packaging, CI & Verification:** PEP 621 / PEP 639 `pyproject.toml`, Nuitka standalone build (`scripts/build_nuitka.bat`), CycloneDX 1.5 runtime SBOM generator (`scripts/make_sbom.py`), OpenPGP checksum signing (`scripts/sign_sums.py`), 12-step deterministic CI gate (`scripts/ci_gate.py`), 558-file golden snapshot, and 30/30 mutation test verification (`scripts/check_tests_bite.py`).

### Security
- **SECURITY:** Enforced the completeness invariant (*"unchecked is never clean"*) across parser errors, missing optional libraries, archive budgets, and AV size/time limits (`SCORE_GREEN_MAX = 19` floor, `ANCHOR_CRITICAL_SCORE = 50`).
- **SECURITY:** Hardened `ZIP`, `TAR`, `XZ`, `7-Zip`, and opt-in YARA feed updaters (`read_zip_member_bounded`, 64 MiB cumulative decompression cap) against Zip-Slip, NTFS junctions, trailing-slash directory spoofing, forged `file_size == 0` headers, and dictionary/PAX memory bombs.
- **SECURITY:** Restricted `subprocess` execution to `shell=False` with absolute binary resolution (`core/toolpath.py::which_absolute`), sanitized HTML/PDF/CSV/Bidi outputs against XSS and formula injection, and isolated runtime logs under `%LOCALAPPDATA%\Malaz\logs\malaz.log` with filename hashing (`core/log_privacy.py`).
