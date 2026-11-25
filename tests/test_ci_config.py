"""Ensure the GitHub Actions workflow stays 1:1 synchronized with scripts/ci_gate.py."""

from __future__ import annotations

from pathlib import Path

from scripts import ci_gate

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_workflow_matches_the_gate_steps():
    problems = ci_gate.check_workflow()
    assert problems == [], "\n".join(problems)


def test_gate_includes_governance_and_coverage_threshold():
    step_names = [step.name for step in ci_gate.STEPS]
    assert step_names == [
        "repo-hygiene",
        "arch-boundaries",
        "license-gate",
        "ruff",
        "mypy",
        "bandit",
        "pytest",
        "mutations",
        "golden-snapshot",
        "golden-images",
        "benchmark-doc",
        "doc-claims",
        "duplicate-logic",
    ]
    assert "--cov-fail-under=70" in ci_gate.PYTEST_COVERAGE
    wf_text = WORKFLOW.read_text(encoding="utf-8")
    assert "python -m pip install --no-build-isolation --no-deps -e ." in wf_text


def test_validator_bites_when_a_step_disappears(tmp_path):
    ruff_line = ci_gate.render(
        next(step for step in ci_gate.STEPS if step.name == "ruff")
    )
    broken = WORKFLOW.read_text(encoding="utf-8").replace(ruff_line + "\n", "")
    path = tmp_path / "ci.yml"
    path.write_text(broken, encoding="utf-8")
    problems = ci_gate.check_workflow(path)
    assert any("ruff" in problem for problem in problems), problems


def test_validator_bites_on_write_permissions(tmp_path):
    broken = WORKFLOW.read_text(encoding="utf-8").replace(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: write\n",
    )
    path = tmp_path / "ci.yml"
    path.write_text(broken, encoding="utf-8")
    assert any("permissions" in p for p in ci_gate.check_workflow(path))


def test_validator_bites_on_extra_arguments(tmp_path):
    """TEST-001: a step with extra arguments must be flagged."""
    declared = ci_gate.render(
        next(step for step in ci_gate.STEPS if step.name == "pytest")
    )
    broken = WORKFLOW.read_text(encoding="utf-8").replace(
        declared + "\n", declared + ' -k "not security"\n'
    )
    path = tmp_path / "ci.yml"
    path.write_text(broken, encoding="utf-8")
    problems = ci_gate.check_workflow(path)
    assert any("Zusatzargumenten" in problem for problem in problems), problems


def test_validator_bites_on_job_level_permissions(tmp_path):
    """TEST-001: job-level permissions must not override workflow read-only permissions."""
    broken = WORKFLOW.read_text(encoding="utf-8").replace(
        "  gate:\n    name: Windows / Python 3.12\n",
        "  gate:\n    name: Windows / Python 3.12\n"
        "    permissions:\n      contents: write\n",
    )
    path = tmp_path / "ci.yml"
    path.write_text(broken, encoding="utf-8")
    problems = ci_gate.check_workflow(path)
    assert any("permissions" in problem for problem in problems), problems


def test_validator_bites_on_workflow_only_command(tmp_path):
    """BUG-095: a command present only in ci.yml would never run locally."""
    ruff_line = ci_gate.render(
        next(step for step in ci_gate.STEPS if step.name == "ruff")
    )
    original = f"      - name: Lint (ruff)\n        run: {ruff_line}\n"
    assert original in WORKFLOW.read_text(encoding="utf-8")
    broken_text = WORKFLOW.read_text(encoding="utf-8").replace(
        original,
        original + "      - name: pip-audit\n        run: python -m pip-audit\n",
    )
    path = tmp_path / "ci.yml"
    path.write_text(broken_text, encoding="utf-8")
    problems = ci_gate.check_workflow(path)
    assert any("ohne Gegenstueck" in problem for problem in problems), problems
def test_ci_workflow_uses_requirements_lock_and_checks_exit_codes():
    wf_text = WORKFLOW.read_text(encoding="utf-8")
    expected = (
        "python -m pip install -r requirements.txt -r requirements-dev.txt -c requirements.lock"
    )
    assert expected in wf_text
    assert "requirements.lock" in wf_text
    assert "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }" in wf_text


def test_release_workflow_enforces_tag_lock_gate_and_draft():
    """T13: structural invariants for .github/workflows/release.yml."""
    import yaml

    rel_wf = ROOT / ".github" / "workflows" / "release.yml"
    assert rel_wf.is_file(), "release.yml fehlt"
    raw = rel_wf.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)

    assert data.get("permissions") == {"contents": "read"}
    build_job = data["jobs"]["build"]
    assert build_job["runs-on"] == "windows-latest"
    assert build_job["permissions"] == {"contents": "write"}

    assert 'ref: "refs/tags/${{ env.TAG }}"' in raw
    assert "git fetch --force --tags origin" in raw
    assert "gh release view $env:TAG" in raw
    assert "-c requirements.lock" in raw
    assert r".venv\Scripts\python.exe scripts/ci_gate.py" in raw
    assert r"scripts\build_nuitka.bat standalone Malaz-%VER%" in raw
    assert "scripts/make_release.py --tag $env:TAG" in raw
    assert "--draft --verify-tag" in raw

    for step in build_job["steps"]:
        run_txt = str(step.get("run", "")).strip()
        if step.get("shell") == "pwsh" and "\n" in run_txt:
            if "gh release view" in run_txt:
                assert "$LASTEXITCODE" in run_txt
            else:
                assert "if ($LASTEXITCODE -ne 0)" in run_txt, step.get("name")
