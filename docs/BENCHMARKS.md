# Benchmarks & Reproducible Quality Metrics

This document records Malaz's measurable detection coverage, false-positive behavior, mutation-testing registry, and scan throughput - along with the exact offline commands to reproduce every number locally.

---

## 1. Methodology & Honest Scope

Malaz evaluates quality across **three deliberately separated layers** so synthetic fixtures are never misrepresented as real-world malware detection rates:

1. **Deterministic Synthetic Corpora (CI-verified, 100% offline):**
   Built from scratch by `scripts/make_test_corpus_extended.py`, `scripts/make_benign_corpus.py`, and `scripts/make_corpus_v2.py` (550+ fixtures covering 40+ file types, attack structures, benign counterexamples, and malformed edge cases). External AV/CLI subprocesses (`windows_defender`, `clamav`, `7zip`, `die`, `capa`) and local user threat-intel feeds are explicitly disabled/pinned via `scripts/corpus_determinism.py` so results are reproducible on any Windows 10/11 machine and verified on every CI run.
   - *Completeness scope note:* Because external tools such as 7-Zip, Windows Defender, ClamAV, DIE, and capa are intentionally disabled in this static-only profile, archive formats requiring 7-Zip (`7z`/`RAR`/`CAB`/`ISO`) and AV signature hits are not credited here.
2. **Throughput & Per-Stage Latency Reference (hardware-dependent):**
   Measured with `scripts/benchmark.py`. Timings depend on CPU speed, filesystem cache, and active engines, so latency figures are documented as reference values rather than hard CI assertions.
3. **Real-World False-Positive & Isolated Live-Malware Evaluation (external / VM-only):**
   - Real-world public benign documents: `scripts/run_fp_check.py` (opt-in download into `%LocalAppData%\Malaz\fp_korpus`, never committed to Git).
   - Live malware samples: `scripts/evaluate_corpus.py`, `scripts/realworld_report.py`, `scripts/lab_guard.ps1`, and `scripts/run_lab.ps1` (strictly inside an isolated offline VM/sandbox; live malware is never stored in this repository).

---

## 2. Deterministic Static Corpus Results (CI-Verified)

The block below is generated and verified automatically by `python scripts/run_corpus.py --check-doc docs/BENCHMARKS.md` in `.github/workflows/ci.yml`:

<!-- BENCHMARK_STATS_START -->
- **Profile:** `deterministic_static_only` (offline, no external AV/CLI subprocesses)
- **Active engines:** `static_pipelines`, `yara_builtin`
- **Intentionally disabled/pinned engines:** `windows_defender`, `clamav`, `7zip`, `die`, `capa`, `user_threat_intel_feeds`
- **Registered mutation checks:** 41 (verified separately in CI via `scripts/check_tests_bite.py`)

| Synthetic Corpus | Files | RED | YELLOW | GREEN | Crashes | Unexpected Incomplete | Key Rates (denominator = all files) |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| Malicious fixtures (`scripts/make_test_corpus_extended.py`) | 69 | 24 | 24 | 21 | 0 | 0 | 69.6% flagged (`RED+YELLOW`), 34.8% `RED` |
| Benign fixtures (`scripts/make_benign_corpus.py`) | 28 | 0 | 0 | 28 | 0 | 0 | 0.0% `RED` FP, 0.0% `YELLOW` |
| Broad corpus v2 - malicious (`scripts/make_corpus_v2.py`) | 283 | 168 | 115 | 0 | 0 | 0 | 100.0% flagged (`RED+YELLOW`), 59.4% `RED` |
| Broad corpus v2 - benign (`scripts/make_corpus_v2.py`) | 136 | 0 | 0 | 136 | 0 | 0 | 0.0% `RED` FP, 0.0% `YELLOW` |
| Broad corpus v2 - edge cases (`scripts/make_corpus_v2.py`) | 37 | 1 | 24 | 12 | 0 | 0 | 67.6% flagged (`RED+YELLOW`), 2.7% `RED` |
<!-- BENCHMARK_STATS_END -->

---

## 3. Throughput & Per-Stage Latency Reference

Reference measurement taken on **Windows 11 x64, Python 3.12** using `scripts/benchmark.py` in **static-only** mode (`Dispatcher()` with external AV subprocesses disabled) across a **1,922-file / 43-type** multi-format benchmark set:

- **Static throughput:** 1,922 files scanned in **283.1 s** (**147 ms/file** mean, 0 crashes).
- **Typical median (`p50`) latency (static-only):** `3-9 ms` for `PNG`/`JSON`/`LNK`/`SWF`/`ZIP`/`TAR`/`GZIP`, `18 ms` for `PDF`, `47-88 ms` for `DOC`/`DOCX`/`XLSX`, `287 ms` warm for `PE` (`notepad.exe`).
- **Optional ClamAV daemon (`scripts/start_clamd.bat` + `scripts/benchmark.py --av`):** Persistent local loopback `clamd` avoids per-file database reload overhead (~18.8 s cold `clamscan` vs. ~41 ms per file with warm `clamd`).

---

## 4. Reproduce Locally

All commands below run from the repository root with `.venv` active:

```bat
REM 1. Verify the deterministic benchmark block above (CI gate, offline)
python scripts/run_corpus.py --check-doc docs/BENCHMARKS.md

REM 2. Export machine-readable JSON for all 5 deterministic synthetic corpora
python scripts/run_corpus.py --json .scratch/benchmarks.json

REM 3. Run the mutation test suite (verifies tests actually catch injected regressions)
python scripts/check_tests_bite.py

REM 4. Measure local scan throughput and per-stage latency
python scripts/benchmark.py

REM 5. Optional: measure false positives on real public documents (opt-in network download)
python scripts/run_fp_check.py

REM 6. Optional (isolated VM only): evaluate known-bad vs. known-good directories
python scripts/evaluate_corpus.py known_bad/ known_good/ --json eval.json
```
