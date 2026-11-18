# Installation, Optional Engines & Building from Source

## 1. System Requirements

- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Privileges:** Standard user account (**administrator privileges are never required**).
- **Source Mode Only:** Python 3.11 – 3.14 (CI tests run on Python 3.12).
- **Nuitka Native Build Only:** No pre-installed C compiler required; `scripts\build_nuitka.bat` passes `--assume-yes-for-downloads` so Nuitka automatically fetches MinGW-w64 on first build if neither MSVC nor MinGW is installed.

---

## 2. Portable Standalone Release (Recommended for End Users)

1. Download `Malaz-1.0.0.zip` alongside `SHA256SUMS-1.0.0.txt`, `SHA256SUMS-1.0.0.txt.asc`, and [RELEASE-SIGNING-KEY.asc](RELEASE-SIGNING-KEY.asc).
2. Verify the PGP signature and SHA-256 checksum ([VERIFYING_RELEASES.md](VERIFYING_RELEASES.md)).
3. Extract the folder to any writable directory (local drive, network share, or USB stick) and run `Malaz.exe` from inside that folder.
4. **Optional Windows Explorer Context Menu (`HKCU`, no admin rights):**
   - Register *"Mit Malaz prüfen"*: run `scripts\register_explorer_menu.bat` (or from inside the portable folder).
   - Remove: run `scripts\unregister_explorer_menu.bat`.

---

## 3. Developer / Source Installation

```bat
git clone https://github.com/TulparLemon/Malaz.git
cd Malaz

python -m venv .venv
.venv\Scripts\activate

python -m pip install -r requirements.txt
python -m pip install --no-build-isolation --no-deps -e .
```

All heavy parser libraries (`pikepdf`, `oletools`, `XLMMacroDeobfuscator`, `openpyxl`, `Pillow`, `pefile`, `yara-python`) are loaded defensively: if an optional library is absent in a custom source environment, Malaz stays runnable and emits an explicit `*_LIB_MISSING` / `*_SKIPPED` indicator rather than silently passing unchecked content.

### Running the Test & Quality Suite

```bat
python -m pip install -r requirements-dev.txt
python -m pytest -q --basetemp=.pytest-tmp\local
```

> **Locked `%TEMP%` on migrated Windows profiles:** If `pytest` fails with `PermissionError: [WinError 5]` inside `%TEMP%\pytest-of-<user>`, always pass `--basetemp=.pytest-tmp\local` (the repository CI and `scripts/run_tests.bat` do this automatically).

Full 12-step local quality gate (identical to [../.github/workflows/ci.yml](../.github/workflows/ci.yml), including `pytest --cov-fail-under=70`, **30/30 mutations** via `scripts/check_tests_bite.py`, `558`-file golden snapshot via `scripts/make_golden_snapshot.py --check`, golden UI images via `scripts/make_golden_images.py --check`, `scripts/check_doc_claims.py`, and `scripts/check_duplicate_logic.py`):

```bat
python scripts/ci_gate.py
```

---

## 4. Optional External Engines (Never Bundled)

Malaz invokes external scanners strictly as separate OS processes (`shell=False`) when installed on the host. If a binary is absent, Malaz degrades gracefully and surfaces the skipped state in the UI and report.

| Engine | Purpose | Default Lookup Paths (`src/malaz/config.py`) | Notes |
| :--- | :--- | :--- | :--- |
| **Windows Defender** (`MpCmdRun.exe`) | On-demand AV scan | Built into Windows 10/11 | Active remediation enabled by default (`AV_DISABLE_REMEDIATION = False`); use `--static-only` to preserve samples |
| **ClamAV** (`clamscan.exe` / `clamdscan.exe`) | Independent open-source second AV engine | `C:\Program Files\ClamAV` or `PATH`; DB under `%LocalAppData%\ClamAV\db` | Detection-only (`--remove` is never passed). If `clamdscan` is installed, Malaz auto-starts a local loopback `clamd` (`127.0.0.1:3310`) cutting per-file AV latency from ~19 s to ~40 ms (`scripts/start_clamd.bat` / `scripts/stop_clamd.bat`) |
| **7-Zip CLI** (`7z.exe` / `7zz.exe`) | Recursive extraction of `RAR`, `7z`, `CAB`, and `ISO` archives | `C:\Program Files\7-Zip\7z.exe` or `PATH` | Without 7-Zip, those containers receive `ARCH_7Z_MISSING` (`YELLOW` / weight 20) instead of a false `GREEN` |
| **Detect It Easy** (`diec.exe`) | Packer, compiler, and protector identification on PE files | `C:\Program Files\Detect It Easy`, `C:\Program Files\DIE`, `C:\Tools\DIE`, or `PATH` | MIT-licensed portable CLI from `horsicq/DIE-engine` |
| **capa** (`capa.exe`) | Executable capability mapping (opt-in *"Fähigkeits-Analyse"*) | `PATH` / configured paths in `src/malaz/config.py` | Opt-in via the Options dialog because deep capability analysis takes several seconds per binary |
| **Custom EDR / AV Hook** | Enterprise CLI scanner integration | `config.EXTERNAL_SCANNERS` in `src/malaz/config.py` | `{file}` placeholder is passed as a single literal `argv` element (`shell=False`); see `src/malaz/analysis/external_scanner.py` |

### Updating ClamAV Signatures (Offline-First)

- Check local DB age (offline): `python -m malaz --clamav-status`
- Check remote availability (explicit opt-in 64-byte range request): `python -m malaz --clamav-update-check`
- Manual one-shot update via `freshclam`: run `scripts\update_clamav.bat`

---

## 5. Building a Native Standalone `.exe` (Nuitka)

Nuitka compiles the Python codebase to native C/x86_64 binaries (`src/malaz_exe.py` entry point). By default, `scripts\build_nuitka.bat` builds the recommended **Standalone folder** (`dist\Malaz-Standalone\` + `.zip`), avoiding self-extracting one-file stubs that trigger heuristic AV false positives:

```bat
python -m pip install nuitka
scripts\build_nuitka.bat
:: Custom output folder name:
scripts\build_nuitka.bat standalone Malaz-1.0.0
:: Optional single-file executable:
scripts\build_nuitka.bat onefile
```

Every standalone build automatically runs:
1. Nuitka compilation (bundling `pikepdf`/`qpdf`, `XLMMacroDeobfuscator`, and `rules/yara/malaz_*.yar`),
2. CycloneDX 1.5 runtime SBOM generation (`python scripts/make_sbom.py --output dist\Malaz-1.0.0\sbom.json`),
3. End-to-end binary smoke test (`python scripts/smoke_build.py --exe dist\Malaz-1.0.0\Malaz.exe`, verifying `PDF_OBJSTM` parsing with bundled `qpdf`),
4. Release hygiene & OpSec gate (`python scripts/check_release.py --directory ...` and `--archive ...`).

### Authenticode Signing & SBOM Check

Sign **before** creating the final distribution ZIP so the archive contains the signed binary:

```bat
signtool sign /fd sha256 /tr https://timestamp.digicert.com /td sha256 /a ^
  dist\Malaz-1.0.0\Malaz.exe
signtool verify /pa /v dist\Malaz-1.0.0\Malaz.exe

python scripts/make_sbom.py --output dist\Malaz-1.0.0\sbom.json --check
```

Note that Windows 11 **Smart App Control (SAC)** blocks unsigned executables, and Microsoft SmartScreen requires organic download reputation even for newly issued OV/EV certificates (see [VERIFYING_RELEASES.md](VERIFYING_RELEASES.md)). Crashes on end-user machines write tracebacks locally to `%TEMP%\Malaz_crash.log`.

---

## 6. Licensing Summary (`GPL-3.0-or-later`)

Malaz is distributed under **[GPL-3.0-or-later](../LICENSE)**. Because Nuitka standalone builds ship Qt/PySide6 libraries alongside compiled modules, Malaz conveys PySide6/Qt under **GPL-3.0** pursuant to **LGPLv3 Section 3** (`THIRD_PARTY_LICENSES/pyside6*/licenses/LICENSE.GPLv3`). Full dependency tables, upstream source pointers, and the verified non-bundling audit for external feeds are documented in [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
