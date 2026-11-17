#!/usr/bin/env python3
"""Malaz quality gate — run before every release/update.

Executes the full open-source toolchain against the project and aggregates
the results into a single pass/fail verdict:

    1. pytest            — unit/integration suite (with coverage)
    2. ruff check        — linting (pyflakes/pycodestyle/upgrade rules)
    3. bandit            — security linting (0 Medium/High required)
    4. mypy              — static type checking (source only)
    5. pip check         — dependency consistency
    6. pip-audit         — known vulnerabilities in the dependency tree
                          (optional: needs the advisory cache; failures due to
                          missing network are reported as warnings, not errors)

Exit code is 0 only when at least one step ran and every enabled step
passed; a run whose --only/--skip selects nothing is an error (1), not a
success. The pytest step carries ``--cov-fail-under=70`` (docs/INSTALLATION.md).
CI/batch usage:
    python scripts\\run_quality_checks.py            # everything
    python scripts\\run_quality_checks.py --skip pip-audit
    python scripts\\run_quality_checks.py --only pytest

Version history:
    1.0  initial release (pytest, ruff, bandit, mypy, pip check, pip-audit)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

VERSION = "1.0"

ROOT = Path(__file__).resolve().parent.parent
PY = ROOT / ".venv" / "Scripts" / "python.exe"
if not PY.is_file():
    PY = sys.executable

STEPS: list[dict] = [
    {
        "name": "pytest (Suite + Coverage)",
        "args": [str(PY), "-m", "pytest", "-q",
                 "--cov=malaz", "--cov-report=term"],
        "cwd": ROOT,
        "min_cover_pct": 70,
    },
    {
        "name": "ruff check (Lint)",
        "args": [str(PY), "-m", "ruff", "check", "src/", "tests/", "conftest.py"],
        "cwd": ROOT,
    },
    {
        "name": "bandit (Security-Lint)",
        # -ll: only Medium+ count as failures. Low issues are the documented
        # defensive try/except/subprocess patterns (see pyproject.toml).
        "args": [str(PY), "-m", "bandit", "-r", "src/malaz", "-q", "-ll"],
        "cwd": ROOT,
        "skip_on_nonzero": False,
    },
    {
        "name": "mypy (Typprüfung)",
        "args": [str(PY), "-m", "mypy", "src/malaz"],
        "cwd": ROOT,
    },
    {
        "name": "pip check (Abhängigkeiten)",
        "args": [str(PY), "-m", "pip", "check"],
        "cwd": ROOT,
    },
    {
        "name": "pip-audit (CVE-Scan)",
        "args": [str(PY), "-m", "pip_audit", "--local"],
        "cwd": ROOT,
        "optional": True,  # network needed for the advisory cache
    },
]


def _step_args(step: dict) -> list[str]:
    """Die tatsaechlich ausgefuehrten Argumente, inklusive Coverage-Schwelle.

    ``min_cover_pct`` stand nur als Deklaration im STEPS-Dict und wurde von
    ``run_step`` nie gelesen — die in docs/INSTALLATION.md zugesagte 70-%-Schwelle war toter
    Code, ein Lauf mit 12 % Coverage meldete „ALLE PRÜFUNGEN BESTANDEN". Die
    Schwelle wird hier an das Kommando gehaengt und damit von pytest-cov
    durchgesetzt (Exit != 0 unter der Grenze).
    """
    args = [str(arg) for arg in step["args"]]
    min_cover = step.get("min_cover_pct")
    if min_cover is not None:
        args.append(f"--cov-fail-under={int(min_cover)}")
    return args


def run_step(
    step: dict, skip: set[str], only: set[str] | None
) -> tuple[str, int, bool]:
    """Run one step; returns ``(name, returncode, executed)``.

    ``executed`` unterscheidet "uebersprungen" (rc 0, nichts getan) von
    "gelaufen und gruen". Ohne diese Unterscheidung meldete ein Lauf, dessen
    ``--only``/``--skip`` auf KEINEN Schritt passt, „ALLE PRÜFUNGEN
    BESTANDEN" mit Exit 0 — ein Gate, das nichts geprueft hat.
    """
    name = step["name"]
    if skip and any(name.startswith(s) for s in skip):
        print(f"[ÜBERSPRUNGEN] {name}")
        return name, 0, False
    if only is not None and not any(name.startswith(o) for o in only):
        print(f"[ÜBERSPRUNGEN] {name} (nur {sorted(only)})")
        return name, 0, False
    print(f"\n=== {name} ===")
    try:
        proc = subprocess.run(
            _step_args(step), cwd=step["cwd"], text=True, check=False
        )
    except FileNotFoundError as exc:
        print(f"[FEHLER] Tool nicht gefunden: {exc}")
        return name, 2, True
    return name, proc.returncode, True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Malaz Quality Gate v{VERSION}"
    )
    parser.add_argument(
        "--skip", nargs="*", default=[],
        help="Steps to skip, e.g. --skip pip-audit",
    )
    parser.add_argument(
        "--only", nargs="*", default=None,
        help="Run only these steps (by name prefix), e.g. --only pytest",
    )
    parser.add_argument("--version", action="version", version=f"quality gate v{VERSION}")
    args = parser.parse_args(argv)

    print(f"Malaz Quality Gate v{VERSION} — {ROOT}")
    print(f"Python: {PY}")

    skip = set(args.skip)
    only = set(args.only) if args.only else None

    failures: list[str] = []
    warnings: list[str] = []
    executed = 0
    for step in STEPS:
        name, rc, ran = run_step(step, skip, only)
        if not ran:
            continue
        executed += 1
        if rc != 0:
            if step.get("optional"):
                warnings.append(f"{name} (Exit {rc})")
                print(f"[WARNUNG] {name} fehlgeschlagen — optional, wird ignoriert")
            else:
                failures.append(f"{name} (Exit {rc})")

    print("\n" + "=" * 60)
    if warnings:
        print("Warnungen (optional):")
        for w in warnings:
            print(f"  - {w}")
    if failures:
        print("FEHLGESCHLAGEN:")
        for f in failures:
            print(f"  - {f}")
        print(f"Quality Gate v{VERSION}: FEHLER — {len(failures)} Schritt(e) rot.")
        return 1
    if executed == 0:
        # Nichts ausgefuehrt ist nicht "alles bestanden": ein Tippfehler in
        # --only (oder ein --skip, das alle Schritte trifft) ergab vorher
        # sechs UEBERSPRUNGEN-Zeilen und Exit 0.
        print(
            f"Quality Gate v{VERSION}: FEHLER — kein Schritt ausgeführt "
            f"(--only {sorted(only) if only else '—'} / --skip "
            f"{sorted(skip) if skip else '—'}).",
            file=sys.stderr,
        )
        return 1
    print(f"Quality Gate v{VERSION}: ALLE PRÜFUNGEN BESTANDEN.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
