# Changelog

All notable changes to **Malaz** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Security-relevant changes are marked with **SECURITY**.

## [Unreleased]

### Added
- **PDF structural link analysis (`PDF-001`):** Extracts `/URI` targets structurally via the bounded action-graph walk (including compressed `/ObjStm` streams and UTF-16BE/LE strings without BOM), strips C0 control characters, filters format namespaces, and checks links offline against local URL/domain/IP blocklists (`PDF_LINK`, `BINARY_IOC_BLOCKED`, `PDF_LINK_CAPPED`).
- Documented the `.eml`/`.msg` workflow for sender/phishing verification in `docs/USAGE.md`.

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
