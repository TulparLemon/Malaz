# Malaz Isolated Real-World Malware Lab Workflow

Malaz pairs synthetic regression benchmarks ([BENCHMARKS.md](BENCHMARKS.md)) with an **offline, isolated real-world malware lab** to measure true detection recall, false-positive rates, and regressions against real samples without ever unpacking decrypted malware on the host machine.

---

## 1. Two Isolation Backends (Clear Responsibility Split)

| Backend | Script | Engine Profile | Intended Use |
| :--- | :--- | :--- | :--- |
| **Windows Sandbox (`.wsb`)** | `scripts/run_lab_sandbox.ps1` + `scripts/sandbox_inner.ps1` | `static_only` (`av_engines: "disabled"`) | Fully automated, networkless throwaway isolation for Malaz static pipelines + YARA (+ optional DIE/capa). Windows Defender real-time protection is off/offline inside Windows Sandbox by design. |
| **Offline Hyper-V VM** | `scripts/run_lab.ps1` *(unchanged)* | `with_av` | Dedicated offline analyzer VM restored from a cold checkpoint with up-to-date Windows Defender / ClamAV signatures for full AV + static evaluation. |

> **Bundle Requirement for Windows Sandbox:** Place `Malaz.exe` together with portable `7z.exe` + `7z.dll` (or standalone `7za.exe`) in a single read-only bundle folder (`-MalazBundleDir`). **7-Zip `>= 25.01` is recommended** for hardened symlink/reparse-point handling; `scripts/sandbox_inner.ps1` also performs a strict `7z l -slt` pre-extract check and never passes `-snld`.

---

## 2. End-to-End Automated Windows Sandbox Workflow (`static_only`)

### Step 1: Zero-Unpack Host Ingest (`scripts/lab_ingest.py`)
Streams password-protected malware ZIPs (AES-256 and ZipCrypto via `pyzipper`) in 64 KiB chunks directly from local staging folders without ever writing decrypted malware to disk or materialising whole files in host RAM:

```powershell
python scripts/lab_ingest.py `
  --bad-zips D:\LabDrop\bad_zips `
  --benign-dir D:\LabDrop\benign `
  --staging-dir D:\MalazLab\staging_2026_11 `
  --corpus-id realworld-2026-11 `
  --password-file D:\LabDrop\zip_pw.txt
```

- **All-or-Nothing ZIP Atomicity:** If any member fails (oversize, member limit, Zip-Slip, Unix symlink, Windows reparse point, corrupt, wrong password, unencrypted), the entire ZIP is discarded and its unpacked bytes are rolled back.
- **Two-Phase Commit:** A SHA-256 `label_conflict` (same file in both malicious and benign) exits with code `1` before writing anything into `<staging-dir>\input_ro\`.
- **Outputs:** `<staging-dir>\input_ro\manifest.json` + `manifest.sha256`, `bad_zips_sha256.json`, `ingest_summary.json` + `ingest_summary.sha256`, staged encrypted ZIPs under `bad_zips\`, and benign files under `benign\`.

### Step 2: Run Isolated Sandbox Evaluation (`scripts/run_lab_sandbox.ps1`)

For a local end-to-end smoke check without starting Windows Sandbox (writes synthetic `dryrun: true` metadata):

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File scripts/run_lab_sandbox.ps1 `
  -StagingDir D:\MalazLab\staging_2026_11 `
  -OutputDir D:\MalazLab\out_dryrun `
  -DryRun
```

For a live isolated Windows Sandbox run (interactive desktop session required; `Networking=Disable`, `vGPU=Disable`, `ProtectedClient=Enable`, `ClipboardRedirection=Disable`, `PrinterRedirection=Disable`, `AudioInput=Disable`, `VideoInput=Disable`, exact 3 `<MappedFolder>` mounts):

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File scripts/run_lab_sandbox.ps1 `
  -StagingDir D:\MalazLab\staging_2026_11 `
  -MalazBundleDir D:\MalazBundle `
  -OutputDir D:\MalazLab\out_run_01 `
  -PasswordFile D:\LabDrop\zip_pw.txt
```

- Inside the guest, `scripts/sandbox_inner.ps1` runs `scripts/lab_guard.ps1 -SandboxGuest -SkipEicar` before writing any log file, verifies ZIP SHA-256s, runs the `7z l -slt` pre-extract check, unpacks each ZIP into a fresh temp directory, verifies full chain-of-custody SHA-256 hashes (malicious + benign), executes `Malaz.exe --evaluate --static-only`, and writes `DONE.json` atomically.
- On the host, `scripts/run_lab_sandbox.ps1` waits until **all** `WindowsSandbox*` processes have exited (fail-closed Exit `4` if any remain alive), validates `<OutputDir>` through the strictly read-only `Test-LabOutputDir` filter (also callable standalone via `-VerifyOutputOnly`: Win32 `FindFirstStreamW` directory/file ADS check, 0 subfolders/reparse points, strict 5-file allowlist, 0 NUL bytes, strict UTF-8/JSON/CSV, `<= 50 MiB`, `guard.json.ok == true`), writes `lab_meta.json`, and runs `scripts/realworld_report.py` + `scripts/triage_misses.py --split dev`.

### Step 3: Compare Runs & Export OpSec-Safe Public Summary (`scripts/lab_compare.py`)

```powershell
python scripts/lab_compare.py `
  --baseline D:\MalazLab\out_baseline `
  --current D:\MalazLab\out_run_01 `
  --split test `
  --json D:\MalazLab\delta.json `
  --markdown D:\MalazLab\delta.md `
  --public-summary D:\MalazLab\public_summary.md `
  --fail-on-regression
```

- **Completeness Denominator:** `missing` and `unchecked` samples are always included in the denominators of `recall_red` and `fp_red`; `--fail-on-regression` exits `1` on any FP increase, recall drop beyond `--max-recall-drop`, or increase in `unchecked`, `missing`, or `ingest_rejected`.
- **DryRun Protection:** `--public-summary` strictly rejects any run with `dryrun: true` (Exit `2`, even if `--allow-dryrun` is passed).
- **OpSec Gate (`src/malaz/lab/opsec.py`):** Before writing `--public-summary`, `find_opsec_leaks()` rejects any hex hash (`>= 32` chars), Windows/UNC/POSIX user path, email, IPv4, URL, or host `COMPUTERNAME`/`USERNAME` leak (Exit `2`, no file written).

---

## 3. Hyper-V `with_av` Runs & `lab_meta.json` Format

`scripts/run_lab.ps1` continues to drive offline Hyper-V full-AV evaluations unchanged (producing `results.report.json` and `results.summary.json`). To compare two Hyper-V `with_av` runs with `scripts/lab_compare.py`, place `report.json` (from `scripts/realworld_report.py`) alongside a `lab_meta.json` with `engine_profile: "with_av"` and `av_engines: "defender,clamav"`:

```json
{
  "schema_version": 1,
  "run_date_utc": "2026-11-26",
  "engine_profile": "with_av",
  "av_engines": "defender,clamav",
  "dryrun": false,
  "manifest_sha256": "<64-char lowercase hex>",
  "ingest_rejected": 0,
  "ingest_rejected_detail": {},
  "sandbox_status": "ok"
}
```

`scripts/lab_compare.py` enforces identical `engine_profile` values across `--baseline` and `--current` so `static_only` and `with_av` results are never mixed silently.
