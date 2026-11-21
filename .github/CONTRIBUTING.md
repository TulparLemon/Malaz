# Contributing to Malaz

Thank you for your interest in contributing to **Malaz**! This guide covers local setup on Windows 10/11, core architectural invariants, quality gates, golden snapshots, and fuzzing.

---

## 1. Licensing

Malaz is licensed under **`GPL-3.0-or-later`** ([LICENSE](../LICENSE)). By submitting a pull request, you agree to license your contribution under the same terms. Do not introduce proprietary, non-commercial (`CC BY-NC`), or unverified third-party libraries, YARA rules, or threat-intel feeds into the repository ([THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md)).

---

## 2. Development Setup (Windows 10/11)

Prerequisites: **Windows 10/11** and **Python 3.11 or 3.12** (CI runs on Python 3.12).

```bat
git clone https://github.com/TulparLemon/Malaz.git
cd Malaz

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m pip install --no-build-isolation --no-deps -e .
```

Enable the repository Git hooks so hygiene, architecture, license, lint, type, and mutation gates run automatically before commits:

```bat
git config core.hooksPath scripts/hooks
```

Quick smoke test:

```bat
python -m malaz --version
python -m pytest -q tests/test_magic.py tests/test_scoring.py
```

---

## 3. Core Project Invariants

Every change is reviewed against five non-negotiable rules (see [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) and [docs/SECURITY_MODEL.md](../docs/SECURITY_MODEL.md)):

1. **Completeness Invariant:** *"What was not checked must never look clean."* Missing optional engines, parser failures, size caps, or timeouts must emit visible indicators (`_INCOMPLETE_RULES` in `src/malaz/models.py`) and must never allow unchecked bytes to pass silently as `GREEN`.
2. **Offline by Default:** Standard scan paths open zero network sockets and send zero telemetry. Opt-in network features (signature/feed updates, SHA-256 URL reputation, DNS SPF/DMARC) require explicit user activation and strict host/scheme allowlisting.
3. **Strict 7-Layer Boundaries:** Lower layers (`security`, `core`, `pipelines`, `analysis`, `reporting`) must never import `gui`, `workers`, or `PySide6` (`reporting/pdf_report.py` may use `QtCore`/`QtGui` only for `QPdfWriter`). Verified automatically by `scripts/arch_gate.py`.
4. **Bounded Untrusted-Input Parsing & Safe Outputs:** Every archive extractor, deobfuscator, and parser enforces explicit byte, entry-count, recursion, and wall-clock budgets (`src/malaz/config.py`). Never use `eval`, `exec`, or `shell=True`; escape all untrusted strings in HTML, PDF, and CSV outputs.
5. **No Live Malware in Git, Issues, or PRs:** All tests generate deterministic, benign synthetic fixtures at runtime. Never commit or attach real malware samples.

---

## 4. Quality Gates, Golden Snapshot & Mutation Testing

1. Create a typed feature branch from `main` (`feat/<slug>`, `fix/<slug>`, `sec/<slug>`, `refactor/<slug>`, `docs/<slug>`, `chore/<slug>`, `test/<slug>`).
2. Include a **biting regression test** under `tests/` that fails without your change.
3. Run the local CI gate before opening a pull request (1:1 identical to [.github/workflows/ci.yml](workflows/ci.yml)):

```bat
:: Fast static & governance checks (seconds)
python scripts/repo_hygiene_gate.py --all
python scripts/arch_gate.py
python scripts/license_gate.py
python -m ruff check src tests scripts fuzz conftest.py
python -m mypy src/malaz
python -m bandit -q -ll -r src
python scripts/check_doc_claims.py
python scripts/check_duplicate_logic.py

:: Full 12-step CI gate (pytest >= 70% coverage, 36/36 mutations, 558-file golden snapshot, golden UI images)
python scripts/ci_gate.py
```

- **Golden Snapshot (`tests/data/golden_snapshot.json`):** Tracks verdicts, scores, rule IDs, and notes across **558 synthetic files (43 file types)**. Run `python scripts/make_golden_snapshot.py --check` to inspect scoring shifts. Only regenerate (`python scripts/make_golden_snapshot.py`) when a score/rule change is intentional, and explain every changed entry in your PR description.
- **Mutation Bite Gate (`scripts/check_tests_bite.py`):** Applies **36/36 mutations** to temporary copies of critical security and detection paths and verifies that each targeted test fails.
- **Property-Based & Fuzz Testing:** Hypothesis property tests run as part of `pytest` (`tests/test_properties.py`). Optional parser fuzz harnesses live under `fuzz/` (`requirements-fuzz.txt`) and can be exercised via `python scripts/run_fuzz_smoke.py`.

---

## 5. Security Vulnerabilities

Please report security vulnerabilities privately via [GitHub Private Vulnerability Reporting](https://github.com/TulparLemon/Malaz/security/advisories/new) as described in [SECURITY.md](../SECURITY.md).
