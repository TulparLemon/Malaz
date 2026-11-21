# System Architecture, Pipelines & Risk Scoring

## 1. Strict 7-Layer Architecture

Malaz is structured into seven unidirectional layers communicated via typed dataclasses in `src/malaz/models.py`. `scripts/arch_gate.py` enforces these import boundaries on every commit and CI run:

```text
gui/            PySide6 desktop interface (main_window, mail_panel, options_dialog, feeds_dialog)
  │
  ▼
workers/        QRunnable + QThreadPool async bridge (up to MAX_SCAN_WORKERS = 3 parallel files)
  │
  ▼
reporting/      Self-contained HTML5, PDF (QPdfWriter), CSV, and JSON report exporters
  │
  ▼
analysis/       Optional external OS-process adapters (Defender, ClamAV/clamd, DIE, capa, EDR)
  │
  ▼
pipelines/      Purely static format analyzers: analyze(AnalysisContext) -> list[Indicator]
  │
  ▼
core/           Dispatcher, magic bytes, scoring, bounded archives, YARA, FileSource, blocklists
  │
  ▼
security/       Foundational limits, Zip-Slip/junction guards, HTML/CSV/Bidi escaping
```

*(Lower layers `security`, `core`, `pipelines`, `analysis`, and `reporting` never import `gui` or `workers`; only `reporting/pdf_report.py` imports `PySide6.QtCore`/`QtGui` for headless PDF rendering.)*

### Core Data Models (`src/malaz/models.py`)

| Model | Role |
| :--- | :--- |
| `Severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `RiskLevel` | `GREEN` (`0–19`), `YELLOW` (`20–49`), `RED` (`50–100`) |
| `Indicator` | Single finding: `rule_id`, `title`, `detail`, `severity`, `weight`, `category`, `source` |
| `AnalysisContext` | Pipeline input: path, in-memory bytes or `FileSource`, magic-detected type, size, deadline, recursion depth |
| `EngineVerdict` | Per-engine status (`threat`, `clean`, `skipped`, `error`, `off`) displayed alongside the score |
| `ScanResult` | File hashes, size, indicators, final score, `RiskLevel`, `StageTiming` list, `engine_verdicts`, child results |

---

## 2. Format Identification & Static Pipelines

`src/malaz/core/dispatcher.py` identifies files by **magic bytes** (`src/malaz/core/magic.py`), including prefixed-ZIP EOCD recovery and prefixed-PDF header recovery within the first 1,024 bytes, preventing extension spoofing (`GEN_FORMAT_MISMATCH`). No pipeline ever executes inspected code.

| Pipeline | Module | Static Inspection Stages |
| :--- | :--- | :--- |
| **PDF** | `src/malaz/pipelines/pdf_pipeline.py` | 1. Fast keyword triage (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, `/AA`, `/EmbeddedFile`, `/ObjStm`).<br>2. `pikepdf`/qpdf XREF, object-stream, incremental-save, bounded structural action-graph traversal, and `/Annots -> /A -> /URI` link extraction (including UTF-16 without BOM) checked against local blocklists (`PDF_LINK`, `BINARY_IOC_BLOCKED`, `PDF_LINK_CAPPED`).<br>3. Static JS decoding (`src/malaz/core/js_deobf.py`: `\xNN`, `\uNNNN`, `unescape`, `String.fromCharCode`, string concat; emits `PDF_JS_DEOBFUSCATED` at **HIGH/50** with auto-open or **MEDIUM/30** without).<br>4. Content-stream layout forensics (`PDF_INVISIBLE_TEXT` render mode `3 Tr`, `PDF_COLOR_ON_COLOR`). |
| **Office** | `src/malaz/pipelines/office_pipeline.py` | 1. OLE/VBA macro & auto-exec triage (`oletools`).<br>2. VBA stomping detection (`pcodedmp` P-code vs. source mismatch).<br>3. Macro hex/Base64/Dridex string decoding.<br>4. DDE command-link inspection (`msodde`).<br>5. Excel 4.0 (`XLM`) macro emulation (`XLMMacroDeobfuscator`).<br>6. `.xlsx` cell formula inspection (`openpyxl`) & external OOXML relationship/template injection (`src/malaz/core/ooxml_rels.py` → `OFFICE_REMOTE_TEMPLATE`). |
| **Email** | `src/malaz/pipelines/eml_pipeline.py` | `.eml` and `.msg` parsing (`src/malaz/core/eml_analysis.py`), header/From/Reply-To spoofing, authentication results, optional DNS SPF/DMARC check, local/opt-in SHA-256 URL reputation (`MAIL_LINK_REPUTATION`), and recursive attachment scanning under strict MIME byte budgets. |
| **Executables** | `src/malaz/pipelines/pe_pipeline.py`, `elf_pipeline.py`, `macho_pipeline.py` | `pefile` header/import/section/Authenticode/overlay/RWX analysis, ELF and Mach-O structural parsing, plus parallelized optional `diec.exe` (with SHA-256 result cache and signed-PE skip optimization) and opt-in `capa`. |
| **Images** | `src/malaz/pipelines/image_pipeline.py` | Magic-byte vs. extension verification, trailing data past PNG `IEND` / JPEG `EOI`, HEIC/AVIF ISO-BMFF box validation, SVG script detection, and Pillow EXIF inspection. |
| **Archives** | `src/malaz/pipelines/archive_pipeline.py` | Bounded in-process `ZIP` and `TAR`/`GZIP`/`BZIP2`/`XZ` iteration (`src/malaz/core/archive.py`) plus isolated temp extraction via `7-Zip` (`src/malaz/core/sevenzip.py`) for `7z`, `RAR`, `CAB`, and `ISO` (including standard malware-share password list `rules/passwords/zip_passwords.txt`). |
| **Generic** | `src/malaz/pipelines/generic_pipeline.py` | NumPy Shannon entropy, bundled + optional YARA rules (`src/malaz/core/yara_engine.py`), SHA-256/domain/IP/filename IOC lists, PowerShell/script deobfuscation (`GEN_PS_ENCODED`, `GEN_SUSPICIOUS_STRINGS`), Windows `.lnk` parser (`src/malaz/core/lnk.py`), `.rtf`, and `.swf` (bounded LZMA). |

---

## 3. Large-File Streaming (64 MB – 2 GB)

To prevent out-of-memory crashes while still inspecting large installers, ISOs, and archives up to `MAX_FILE_SIZE = 2 GB`:

- **<= 64 MB (`MAX_READ_SIZE`):** Read into memory once and passed to all applicable pipelines.
- **> 64 MB up to 2 GB (`src/malaz/core/filesource.py`):**
  - Full-file streaming in **8 MB chunks** for SHA-256 hashing, Shannon entropy, path-based YARA scanning, and raw-byte IOC extraction.
  - Direct file-path access for `ZIP`, `PDF` (`pikepdf`), Windows Defender, and ClamAV (with explicit `CLAMAV_SIZE_LIMIT` detection above ClamAV's 100 MB cap).
  - Bounded **8 MB prefix** (`MAX_LARGE_PREFIX_SIZE`) for deep buffer-oriented parsers, accompanied by a visible `CORE_READ_TRUNCATED` indicator (`weight = 20`, `YELLOW`) whenever a stage saw only the prefix.

---

## 4. Multi-Layer Risk Scoring (`src/malaz/core/scoring.py`)

`compute_score()` aggregates indicators deterministically in seven steps:

1. **Effective Weight:** Use `indicator.weight` if set; otherwise fall back to severity base weights (`INFO = 0`, `LOW = 5`, `MEDIUM = 15`, `HIGH = 30`, `CRITICAL = 50`).
2. **Per-Rule Deduplication:** Repeated instances of the same `rule_id` count **once** at their highest effective weight.
3. **Additive Raw Score:** Sum the deduplicated weights across all distinct `rule_id`s (`raw`).
4. **AV Clean Discount:** Subtract `4` points per verified clean AV engine vote (`AV_CLEAN`, `CLAMAV_CLEAN`, `EXT_<TAG>_CLEAN`), capped at `8` points total. Skipped or errored engines (`AV_SKIPPED`, `CLAMAV_SKIPPED`) grant **zero** discount.
5. **Green Floor (`SCORE_GREEN_MAX = 19`):** If `raw > 19`, the discounted score cannot drop below `20` (`YELLOW`); clean AV votes never erase a substantive static warning or incomplete-scan indicator.
6. **Critical Anchor (`ANCHOR_CRITICAL_SCORE = 50`):** Any `CRITICAL` indicator (e.g., `CLAMAV_THREAT`, `PDF_KW_Launch`, `ARCH_ZIPSLIP`, AutoExec + shell macro, SHA-256 blocklist hit) forces `score >= 50` (`RED`).
7. **Cap:** Clamp final score to `[0, 100]`.

For archives and emails with attachments, parent items inherit elevated child risk while keeping per-item breakdowns transparent in GUI, CLI, HTML, PDF, CSV, and JSON outputs.

---

## 5. Measured Performance Highlights

Measured statically (`Dispatcher()` without external AV subprocesses) across a **1,922-file / 43-type** multi-format benchmark corpus ([`scripts/benchmark.py`](../scripts/benchmark.py)):

- **Throughput:** 1,922 files scanned in **283.1 s** (**147 ms/file** mean, 0 crashes).
- **Typical Median (`p50`) Latency:** `3–9 ms` for `PNG`/`JSON`/`LNK`/`SWF`/`ZIP`/`TAR`/`GZIP`, `18 ms` for `PDF`, `47–88 ms` for `DOC`/`DOCX`/`XLSX`, `287 ms` warm for `PE` (`notepad.exe`).
- **ClamAV Daemon Speedup:** Persistent loopback `clamd` reduces ClamAV scan overhead from **18.8 s** (`clamscan` cold DB load) to **41 ms** per file (~455× faster).
