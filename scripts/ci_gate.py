#!/usr/bin/env python3
"""Run exactly the checks the hosted CI runs — on this machine.

Why this exists
===============

The CI definition (``.github/workflows/ci.yml``) is the authority for what
"green" means, but it can only be executed by GitHub. A workflow that was
never run is a hypothesis; this runner turns the same step list into a command
an operator can execute before pushing. The step list below is the single
source: ``tests/test_ci_config.py`` asserts every command appears verbatim in
the workflow, and ``--check-workflow`` validates the YAML locally.

Safety
======

No step downloads a sample, starts a VM, or touches the network beyond pip's
own package installation (which happens before this script runs). The corpus
is generated from synthetic fixtures at runtime. Nothing here writes outside
``artifacts/ci`` and ``.pytest-tmp/ci``.

Usage
=====

    python scripts/ci_gate.py                  # full gate, with coverage
    python scripts/ci_gate.py --no-coverage    # faster local loop
    python scripts/ci_gate.py --only ruff --only pytest
    python scripts/ci_gate.py --list
    python scripts/ci_gate.py --check-workflow # validate CI YAML only

Exit code 0 only when every selected step returned 0.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts" / "ci"

# The commands use forward slashes so the same rendered string matches the
# workflow line on Windows and on local Windows machines.
PYTEST_BASE = (
    "-m",
    "pytest",
    "-q",
    "--basetemp=.pytest-tmp/ci",
    "--junitxml=artifacts/ci/junit.xml",
)
PYTEST_COVERAGE = (
    "--cov=malaz",
    "--cov-fail-under=70",
    "--cov-report=xml:artifacts/ci/coverage.xml",
    "--cov-report=term:skip-covered",
)


@dataclass(frozen=True)
class Step:
    name: str
    args: tuple[str, ...]
    # check_tests_bite runs 30 mutated test selections; the 900 s limit inside
    # it applies per mutation, so the outer budget must be larger.
    timeout: int = 1800
    optional: bool = False


STEPS: tuple[Step, ...] = (
    Step("repo-hygiene", ("scripts/repo_hygiene_gate.py", "--all")),
    Step("arch-boundaries", ("scripts/arch_gate.py",)),
    Step("license-gate", ("scripts/license_gate.py",)),
    Step("ruff", ("-m", "ruff", "check", "src", "tests", "scripts", "fuzz", "conftest.py")),
    Step("mypy", ("-m", "mypy", "src/malaz")),
    Step("bandit", ("-m", "bandit", "-q", "-ll", "-r", "src")),
    Step("pytest", (*PYTEST_BASE, *PYTEST_COVERAGE), timeout=3600),
    Step("mutations", ("scripts/check_tests_bite.py",), timeout=10800),
    Step("golden-snapshot", ("scripts/make_golden_snapshot.py", "--check"), timeout=3600),
    Step("golden-images", ("scripts/make_golden_images.py", "--check"), timeout=1800),
    Step("benchmark-doc", ("scripts/run_corpus.py", "--check-doc", "docs/BENCHMARKS.md"), timeout=1800),
    Step("doc-claims", ("scripts/check_doc_claims.py",)),
    Step("duplicate-logic", ("scripts/check_duplicate_logic.py",)),
)


def render(step: Step) -> str:
    """The workflow command line, exactly as it appears in the YAML."""
    return "python " + " ".join(step.args)


def _without_coverage(step: Step) -> Step:
    if step.name != "pytest":
        return step
    return Step(
        step.name,
        tuple(part for part in step.args if not part.startswith("--cov")),
        step.timeout,
        step.optional,
    )


def _env() -> dict[str, str]:
    env = dict(os.environ)
    # Qt widgets are rendered by some checks; the offscreen platform is the
    # only one a headless runner has.
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def _parse_workflow(path: Path) -> dict:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - dependency is declared
        raise SystemExit(
            "PyYAML fehlt (requirements-dev.txt): "
            "python -m pip install -r requirements-dev.txt"
        ) from exc
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path}: kein YAML-Objekt")
    return loaded


def _workflow_commands(jobs: dict) -> list[str]:
    """Every individual command line a job runs, whitespace-normalised.

    A ``run:`` block may carry several commands (the pip install block does).
    String-containment against the joined blocks was the old parity test and
    could not see an EXTENDED command: ``python -m pytest … -k "not security"``
    still *contained* the declared line, so the gate stayed green while the
    hosted CI silently skipped tests. Comparison is therefore per line and
    exact.
    """
    commands: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for item in job.get("steps", []):
            if not isinstance(item, dict):
                continue
            run = item.get("run")
            if not run:
                continue
            for line in str(run).splitlines():
                command = " ".join(line.split())
                if command:
                    commands.append(command)
    return commands


def check_workflow(path: Path | None = None) -> list[str]:
    """Structural checks for the hosted workflow. Empty list = valid.

    This does not pretend to be actionlint. It catches the mistakes that would
    make the file silently do nothing: no Windows runner, wrong Python, a
    missing step, an EXTENDED step (extra arguments change what CI verifies),
    a workflow-only command that would never run locally, job-level
    permissions, or a step that downloads tooling from an unreviewed host.
    """
    path = path or ROOT / ".github" / "workflows" / "ci.yml"
    problems: list[str] = []
    if not path.is_file():
        return [f"{path} fehlt"]

    data = _parse_workflow(path)
    # PyYAML parses the YAML 1.1 key ``on`` as boolean True. GitHub uses 1.2.
    triggers = data.get("on", data.get(True))
    if not triggers:
        problems.append("kein Trigger ('on') definiert")
    permissions = data.get("permissions")
    if permissions != {"contents": "read"}:
        problems.append("permissions müssen auf contents: read stehen")

    jobs = data.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append("keine Jobs definiert")
        return problems

    # Job-Level-`permissions` ueberschreiben den Workflow-Block: ein Job mit
    # `contents: write` bliebe sonst unsichtbar, obwohl die Zusage "least
    # privilege" dann nur noch auf dem Papier steht. Eine Quelle, oben.
    for job_name, job in jobs.items():
        if isinstance(job, dict) and "permissions" in job:
            problems.append(
                f"Job '{job_name}' setzt eigene permissions — nur der "
                "Workflow-Block darf Rechte vergeben"
            )

    commands = _workflow_commands(jobs)
    # Nur fuer die Meldungstexte: die verbotenen Praefixe werden weiterhin im
    # gesamten Text gesucht (auch in Zeilen ohne deklarierten Befehl).
    all_run = " ".join(commands)
    raw = path.read_text(encoding="utf-8")
    if "windows-latest" not in raw and "windows-2022" not in raw:
        problems.append("kein Windows-Runner (runs-on: windows-*)")
    if 'python-version: "3.12"' not in raw and "python-version: '3.12'" not in raw:
        problems.append("Python 3.12 wird im Workflow nicht gesetzt")
    if "QT_QPA_PLATFORM: offscreen" not in raw:
        problems.append("QT_QPA_PLATFORM=offscreen fehlt (headless Qt-Checks)")
    if "actions/upload-artifact" not in raw:
        problems.append("kein Artefakt-Upload (Coverage/JUnit)")

    for step in STEPS:
        if step.optional:
            continue
        wanted = render(step)
        if wanted in commands:
            continue
        extended = [command for command in commands if command.startswith(wanted)]
        if extended:
            problems.append(
                f"Workflow-Schritt mit Zusatzargumenten: {extended[0]} "
                f"(erwartet exakt: {wanted})"
            )
        else:
            problems.append(f"Workflow-Schritt fehlt: {wanted}")

    # Die andere Richtung: ein Befehl, den der Workflow ausfuehrt, aber
    # ``STEPS`` nicht kennt, liefe lokal nie mit (z. B. ein spaeter
    # hinzugefuegter pip-audit-Schritt). Nur die Setup-Zeilen und das
    # Artefaktverzeichnis sind keine Pruefschritte.
    allowed = {render(step) for step in STEPS} | {
        "python -m pip install --upgrade pip",
        "python -m pip install -r requirements.txt -r requirements-dev.txt -c requirements.lock",
        "python -m pip install --no-build-isolation --no-deps -e .",
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        "New-Item -ItemType Directory -Force artifacts/ci | Out-Null",
    }
    for command in commands:
        if command not in allowed:
            problems.append(
                f"Workflow-Befehl ohne Gegenstueck in ci_gate.STEPS: {command}"
            )

    forbidden = (
        "curl ",
        "wget ",
        "Invoke-WebRequest",
        "Start-BitsTransfer",
        "malwarebazaar",
    )
    for needle in forbidden:
        if needle.lower() in all_run.lower():
            problems.append(
                f"unerlaubter Netzwerk-/Probenpfad im Workflow: {needle.strip()}"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="Schritte nur auflisten")
    parser.add_argument(
        "--only", action="append", default=[], help="nur Schritte mit diesem Präfix"
    )
    parser.add_argument(
        "--skip", action="append", default=[], help="Schritte mit diesem Präfix auslassen"
    )
    parser.add_argument(
        "--no-coverage", action="store_true", help="pytest ohne Coverage (schneller)"
    )
    parser.add_argument(
        "--check-workflow", action="store_true", help="nur CI-YAML prüfen"
    )
    args = parser.parse_args(argv)

    if args.check_workflow:
        problems = check_workflow()
        if problems:
            for problem in problems:
                print(f"  !! {problem}")
            return 1
        print("  CI-Workflow strukturell gültig; alle Schritte sind verdrahtet.")
        return 0

    steps = [s for s in STEPS if not s.optional]
    if args.no_coverage:
        steps = [_without_coverage(s) for s in steps]
    if args.only:
        steps = [s for s in steps if any(s.name.startswith(o) for o in args.only)]
    if args.skip:
        steps = [s for s in steps if not any(s.name.startswith(k) for k in args.skip)]
    if not steps:
        print("Keine Schritte ausgewählt.")
        return 1

    if args.list:
        for step in steps:
            print(f"  {step.name:20s} {render(step)}")
        return 0

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    env = _env()
    failures: list[tuple[str, int, float]] = []
    started = time.monotonic()

    for index, step in enumerate(steps, 1):
        print(f"\n=== [{index}/{len(steps)}] {step.name} ===", flush=True)
        print(f"    {render(step)}", flush=True)
        step_started = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, *step.args],
                cwd=ROOT,
                env=env,
                text=True,
                errors="replace",
                timeout=step.timeout,
                check=False,
            )
            code = proc.returncode
        except subprocess.TimeoutExpired:
            print(f"  !! Zeitgrenze ({step.timeout} s) überschritten", flush=True)
            code = 124
        except FileNotFoundError as exc:
            print(f"  !! Werkzeug nicht gefunden: {exc}", flush=True)
            code = 2
        elapsed = time.monotonic() - step_started
        print(f"    -> Exit {code} nach {elapsed:.1f} s", flush=True)
        if code != 0:
            failures.append((step.name, code, elapsed))

    total = time.monotonic() - started
    print("\n=== Ergebnis ===")
    for step in steps:
        mark = "OK " if step.name not in {name for name, _, _ in failures} else "!! "
        print(f"  {mark}{step.name}")
    if failures:
        print(f"\n{len(failures)} Schritt(e) rot nach {total:.1f} s:")
        for name, code, elapsed in failures:
            print(f"  - {name}: Exit {code} ({elapsed:.1f} s)")
        return 1
    print(f"\nAlle {len(steps)} Schritte grün nach {total:.1f} s.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
