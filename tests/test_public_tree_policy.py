"""Tests for scripts/_public_tree_policy.py and repo_hygiene_gate integration (T1, T2)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts import _public_tree_policy, repo_hygiene_gate


@pytest.mark.parametrize(
    "forbidden_path",
    [
        "AGENTS.md",
        "Malaz-1.0.0/AGENTS.md",
        "GEMINI.md",
        "MOC.md",
        "PROJECT_BOARD.md",
        ".agents/plugins/malaz-governance/plugin.json",
        "./.agents/skills/x.md",
        "Malaz-1.0.0/.agents/skills/x.md",
        "docs/designs/001-spec.md",
        "Malaz-1.0.0/docs/designs/SITEMAP.md",
        "docs/01_architektur.md",
        "docs/25_verifying_releases.md",
        "Malaz-1.0.0/docs/03_risk_scoring.md",
        ".gitlab-ci.yml",
        "./.gitlab-ci.yml",
        "Malaz-1.0.0/.gitlab-ci.yml",
        "scripts/make_public_export.bat",
        "Malaz-1.0.0/scripts/make_public_export.bat",
        "HANDOVER.md",
        "HANDOVER_2026.txt",
        "PROMPT_review.md",
        "msg.txt",
        "msg12.txt",
    ],
)
def test_is_forbidden_public_path_catches_all_twelve_rules(forbidden_path: str):
    assert _public_tree_policy.is_forbidden_public_path(forbidden_path) is True


@pytest.mark.parametrize(
    "allowed_path",
    [
        "README.md",
        "CHANGELOG.md",
        "docs/USAGE.md",
        "docs/RELEASING.md",
        "docs/VERIFYING_RELEASES.md",
        "docs/assets/malaz-ui.png",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        "src/malaz/agents_util.py",
        "scripts/make_release.py",
        "Malaz-1.0.0/docs/USAGE.md",
    ],
)
def test_is_forbidden_public_path_allows_public_files(allowed_path: str):
    assert _public_tree_policy.is_forbidden_public_path(allowed_path) is False


def test_repo_hygiene_gate_rejects_internal_paths_in_git_index(tmp_path: Path):
    git = repo_hygiene_gate._git_exe(tmp_path)
    subprocess.run([git, "init", "-b", "feat/test", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)

    (tmp_path / "docs" / "designs").mkdir(parents=True)
    (tmp_path / "docs" / "designs" / "x.md").write_text("spec\n", encoding="utf-8")
    (tmp_path / ".agents").mkdir()
    (tmp_path / ".agents" / "x.md").write_text("agent\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "msg1.txt").write_text("forbidden\n", encoding="utf-8")

    subprocess.run([git, "-C", str(tmp_path), "add", "."], check=True)

    staged_problems = repo_hygiene_gate.check_secrets(tmp_path, staged_only=True)
    assert any("Interner Pfad im Git-Index: 'docs/designs/x.md'" in p for p in staged_problems)
    assert any("Interner Pfad im Git-Index: '.agents/x.md'" in p for p in staged_problems)
    assert any("Interner Pfad im Git-Index: 'tests/msg1.txt'" in p for p in staged_problems)

    subprocess.run([git, "-C", str(tmp_path), "commit", "-m", "init"], check=True, capture_output=True)

    all_problems = repo_hygiene_gate.check_secrets(tmp_path, staged_only=False)
    assert any("Interner Pfad im Git-Index: 'docs/designs/x.md'" in p for p in all_problems)
    pub_problems = repo_hygiene_gate.check_public_paths(tmp_path)
    assert len(pub_problems) == 3


def test_check_public_paths_fails_closed_outside_git_repo(tmp_path: Path):
    problems = repo_hygiene_gate.check_public_paths(tmp_path)
    assert len(problems) == 1
    assert "fehlgeschlagen" in problems[0]
