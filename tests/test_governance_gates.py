from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"_script_{name}", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _git_exe() -> str:
    portable = ROOT / "tools" / "Git" / "cmd" / "git.exe"
    if portable.is_file():
        return str(portable)
    found = shutil.which("git")
    assert found is not None
    return found



def test_real_repo_passes_hygiene_arch_and_license_gates() -> None:
    hygiene = _load_script("repo_hygiene_gate")
    arch = _load_script("arch_gate")
    lic = _load_script("license_gate")

    assert hygiene.run_checks(ROOT, scan_all=True) == []
    assert arch.check_architecture(ROOT / "src" / "malaz") == []
    assert lic.check_licenses(ROOT / "requirements.txt", ROOT / "THIRD_PARTY_NOTICES.md") == []


def test_arch_gate_catches_direct_aliased_and_relative_imports(tmp_path: Path) -> None:
    arch = _load_script("arch_gate")
    for pkg in ("security", "core", "pipelines", "reporting", "workers", "gui", "lab"):
        d = tmp_path / pkg
        d.mkdir()
        (d / "__init__.py").write_text("", encoding="utf-8")

    (tmp_path / "core" / "bad_from_pkg.py").write_text(
        "from malaz import gui\n",
        encoding="utf-8",
    )
    (tmp_path / "core" / "bad_rel.py").write_text(
        "from .. import workers\n",
        encoding="utf-8",
    )
    (tmp_path / "security" / "bad_lab.py").write_text(
        "from ..lab import manifest\n",
        encoding="utf-8",
    )
    (tmp_path / "workers" / "bad_qtwidgets.py").write_text(
        "from PySide6 import QtWidgets\n",
        encoding="utf-8",
    )
    (tmp_path / "reporting" / "pdf_report.py").write_text(
        "from PySide6 import QtGui\n",
        encoding="utf-8",
    )
    (tmp_path / "reporting" / "pdf_bad.py").write_text(
        "from PySide6 import QtGui\n",
        encoding="utf-8",
    )

    problems = arch.check_architecture(tmp_path)
    joined = "\n".join(problems)
    assert "core/bad_from_pkg.py" in joined
    assert "core/bad_rel.py" in joined
    assert "security/bad_lab.py" in joined
    assert "workers/bad_qtwidgets.py" in joined
    assert "reporting/pdf_bad.py" in joined
    assert not any(p.startswith("reporting/pdf_report.py:") for p in problems)


def test_repo_hygiene_renames_umlauts_branch_and_staged_secrets(tmp_path: Path) -> None:
    hygiene = _load_script("repo_hygiene_gate")
    git = _git_exe()

    subprocess.run([git, "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@example.org"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "Test"], check=True)

    (tmp_path / "README.md").write_text("# Clean\nline2\nline3\nline4\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    key_header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    (tmp_path / "docs" / "ümlaut_geheimnis.txt").write_text(
        f"{key_header}\nabc\n", encoding="utf-8"
    )
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "init"], check=True, capture_output=True
    )

    # --all must scan non-ASCII tracked filenames without core.quotePath skipping them
    all_problems = hygiene.check_secrets(tmp_path, staged_only=False)
    assert any("ümlaut_geheimnis.txt" in p for p in all_problems)

    main_branch_err = hygiene.check_branch(tmp_path)
    assert any("main" in e for e in main_branch_err)

    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "-b", "badbranch"],
        check=True,
        capture_output=True,
    )
    assert hygiene.check_branch(tmp_path)
    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "-b", "feat/clean-feature"],
        check=True,
        capture_output=True,
    )
    assert hygiene.check_branch(tmp_path) == []

    # Staged rename (`git mv` -> diff-filter R) must be caught in --pre-commit mode
    subprocess.run(
        [git, "-C", str(tmp_path), "mv", "README.md", "HANDOVER_RENAMED.md"],
        check=True,
    )
    arch_dir = tmp_path / "docs" / "archive" / "legacy-handovers"
    arch_dir.mkdir(parents=True)
    (arch_dir / "HANDOVER_OLD.md").write_text("historical note\n", encoding="utf-8")
    (tmp_path / "docs" / "custom_secret_blob").write_text(f"{key_header}\nabc\n", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=1\n", encoding="utf-8")
    subprocess.run(
        [
            git,
            "-C",
            str(tmp_path),
            "add",
            "docs/archive/legacy-handovers/HANDOVER_OLD.md",
            "docs/custom_secret_blob",
            ".env",
        ],
        check=True,
    )
    (tmp_path / "docs" / "custom_secret_blob").write_text(
        "innocent working tree\n", encoding="utf-8"
    )

    secret_problems = hygiene.check_secrets(tmp_path, staged_only=True)
    sec_joined = "\n".join(secret_problems)
    assert "HANDOVER_OLD.md" in sec_joined
    assert "HANDOVER_RENAMED.md" in sec_joined
    assert "custom_secret_blob" in sec_joined
    assert ".env" in sec_joined

    (tmp_path / "msg9.txt").write_text("bad", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "leftover.zip").write_bytes(b"PK\x03\x04")
    root_problems = hygiene.check_root_entries(tmp_path)
    root_joined = "\n".join(root_problems)
    assert "msg9.txt" in root_joined
    assert "src/leftover.zip" in root_joined


def test_license_gate_rejects_unknown_proprietary_classifier_and_opaque(tmp_path: Path) -> None:
    lic = _load_script("license_gate")
    req = tmp_path / "requirements.txt"
    notices = tmp_path / "THIRD_PARTY_NOTICES.md"
    req.write_text(
        "numpy>=1.26\npytest>=8.0\nmystery-pkg>=1.0\nprop-pkg>=1.0\nopaque-pkg>=1.0\n",
        encoding="utf-8",
    )
    notices.write_text(
        "# Notices\n\n"
        "## Vollständige Laufzeitkomponenten (SBOM)\n\n"
        "| Komponente | Version | Lizenz |\n"
        "|---|---|---|\n"
        "| numpy | 2.5.1 | BSD-3-Clause |\n"
        "| mystery-pkg | 1.0.0 | MIT |\n"
        "| prop-pkg | 1.0.0 | MIT |\n"
        "| opaque-pkg | 1.0.0 | MIT |\n\n"
        "## Entwicklungswerkzeuge (nicht im Release)\n\n"
        "pytest wird nur fuer Tests genutzt.\n",
        encoding="utf-8",
    )

    problems = lic.check_licenses(
        req,
        notices,
        extra_license_texts={
            "numpy": "BSD-3-Clause",
            "pytest": "MIT",
            "mystery-pkg": "UNKNOWN",
            "prop-pkg": "See LICENSE.txt | License :: Other/Proprietary License",
            "opaque-pkg": "See LICENSE.txt",
        },
    )
    joined = "\n".join(problems)
    assert "Laufzeit-Paket 'pytest'" in joined
    assert "Unbekannte/ungepruefte Lizenz-Metadaten fuer Laufzeit-Paket 'mystery-pkg'" in joined
    assert "Inkompatible/unfreie Lizenzkennung ('proprietary') in Paket 'prop-pkg'" in joined
    assert "Keine verifizierte freie Lizenzkennung fuer Laufzeit-Paket 'opaque-pkg'" in joined



def test_merge_gate_branch_only_spec_missing_tests_and_git_merge(tmp_path: Path) -> None:
    mg = _load_script("merge_gate")
    git = _git_exe()

    subprocess.run([git, "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@example.org"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "Test"], check=True)

    hooks_dir = tmp_path / "scripts" / "hooks"
    hooks_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts" / "hooks" / "pre-merge-commit", hooks_dir / "pre-merge-commit")
    subprocess.run([git, "-C", str(tmp_path), "config", "core.hooksPath", "scripts/hooks"], check=True)

    (tmp_path / ".gitignore").write_text("artifacts/\n", encoding="utf-8")
    (tmp_path / ".gitattributes").write_text("scripts/hooks/* text eol=lf\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Base\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "base"], check=True, capture_output=True
    )
    subprocess.run([git, "-C", str(tmp_path), "tag", "v0.0.1-tag"], check=True)

    # Spec created ONLY on feat/demo (absent from main's working tree!)
    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "-b", "feat/demo"],
        check=True,
        capture_output=True,
    )
    (tmp_path / "docs" / "designs").mkdir(parents=True)
    (tmp_path / "docs" / "designs" / "002-branch-only.md").write_text("# Spec\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "add spec on branch"],
        check=True,
        capture_output=True,
    )
    feat_sha = subprocess.check_output(
        [git, "-C", str(tmp_path), "rev-parse", "HEAD"], text=True, encoding="utf-8"
    ).strip()

    # Switch back to main BEFORE certificate check & merge (real-world caller state!)
    subprocess.run([git, "-C", str(tmp_path), "checkout", "main"], check=True, capture_output=True)
    assert not (tmp_path / "docs" / "designs" / "002-branch-only.md").exists()

    # Tag must be rejected by strict refs/heads/<branch> resolution
    tag_errs, _, _ = mg.verify_branch_ready(tmp_path, "v0.0.1-tag", run_code_gates=False)
    assert any("existiert nicht" in e for e in tag_errs)

    cert_path = mg.expected_review_path(tmp_path, "feat/demo", feat_sha)
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    bad_cert = {
        "reviewer_agent": "malaz-code-reviewer",
        "branch": "feat/demo",
        "base_ref": "develop",
        "commit_sha": feat_sha,
        "spec_ref": "docs/designs/../../README.md",
        "verdict": "PASS",
        "blockers": False,
        "majors": 1,
        "checklist": {k: True for k in mg.REQUIRED_CHECKLIST_KEYS},
    }
    cert_path.write_text(json.dumps(bad_cert), encoding="utf-8")
    errs, _ = mg.validate_review_certificate(tmp_path, "feat/demo", feat_sha)
    assert len(errs) == 4

    good_cert = {
        "reviewer_agent": "malaz-code-reviewer",
        "branch": "feat/demo",
        "base_ref": "main",
        "commit_sha": feat_sha,
        "spec_ref": "docs/designs/002-branch-only.md",
        "verdict": "PASS",
        "blockers": 0,
        "majors": 0,
        "checklist": {k: True for k in mg.REQUIRED_CHECKLIST_KEYS},
        "summary": "Branch-only spec verified",
    }
    cert_path.write_text(json.dumps(good_cert), encoding="utf-8")

    # Missing CORE_MERGE_TESTS on branch must fail closed and restore HEAD to main
    missing_errs, _, _ = mg.verify_branch_ready(tmp_path, "feat/demo", run_code_gates=True)
    assert any("Pflicht-Testdatei(en) fehlen" in e for e in missing_errs)
    head_branch = subprocess.check_output(
        [git, "-C", str(tmp_path), "symbolic-ref", "--short", "HEAD"],
        text=True,
        encoding="utf-8",
    ).strip()
    assert head_branch == "main"

    mg.ensure_no_ff_config(tmp_path)
    env_clean = {k: v for k, v in os.environ.items() if k != "MALAZ_MERGE_GATE_ACTIVE"}
    raw_merge = subprocess.run(
        [git, "-C", str(tmp_path), "merge", "feat/demo", "-m", "unauthorized"],
        env=env_clean,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert raw_merge.returncode != 0
    subprocess.run([git, "-C", str(tmp_path), "merge", "--abort"], capture_output=True, check=False)

    rc = mg.merge_into_main(tmp_path, "feat/demo", delete_branch=True, run_code_gates=False)
    assert rc == 0
    assert (tmp_path / "docs" / "designs" / "002-branch-only.md").is_file()
    branches = subprocess.check_output(
        [git, "-C", str(tmp_path), "branch"], text=True, encoding="utf-8"
    )
    assert "feat/demo" not in branches


def test_repo_hygiene_allows_editable_egg_info_and_build_dir(tmp_path: Path) -> None:
    hygiene = _load_script("repo_hygiene_gate")
    (tmp_path / "build").mkdir()
    egg = tmp_path / "src" / "malaz.egg-info"
    egg.mkdir(parents=True)
    (egg / "SOURCES.txt").write_text("src/malaz/__init__.py\n", encoding="utf-8")
    assert hygiene.check_root_entries(tmp_path) == []


def test_license_gate_blocks_commercial_file_dev_dist_info_and_strict_versions(
    tmp_path: Path,
) -> None:
    lic = _load_script("license_gate")
    assert (
        lic.check_licenses(
            ROOT / "requirements.txt",
            ROOT / "THIRD_PARTY_NOTICES.md",
            strict_venv_versions=True,
        )
        == []
    )

    req = tmp_path / "requirements.txt"
    notices = tmp_path / "THIRD_PARTY_NOTICES.md"
    tpl = tmp_path / "THIRD_PARTY_LICENSES"
    req.write_text("numpy>=1.26\n", encoding="utf-8")
    notices.write_text(
        "# Notices\n\n"
        "## Vollständige Laufzeitkomponenten (SBOM)\n\n"
        "| Komponente | Version | Lizenz |\n"
        "|---|---|---|\n"
        "| numpy | 2.5.4 | BSD-3-Clause |\n"
        "| PySide6 | 6.12.0 | LGPL-3.0-only OR GPL-3.0-only |\n",
        encoding="utf-8",
    )
    (tpl / "numpy-2.0.0.dist-info").mkdir(parents=True)
    (tpl / "numpy-2.0.0.dist-info" / "LICENSE.txt").write_text("BSD", encoding="utf-8")
    (tpl / "pytest-9.2.0.dist-info").mkdir(parents=True)
    (tpl / "pytest-9.2.0.dist-info" / "LICENSE").write_text("MIT", encoding="utf-8")
    (tpl / "pyside6-6.12.0.dist-info" / "licenses").mkdir(parents=True)
    (tpl / "pyside6-6.12.0.dist-info" / "licenses" / "LicenseRef-Qt-Commercial.txt").write_text(
        "Commercial", encoding="utf-8"
    )

    problems = lic.check_licenses(
        req,
        notices,
        extra_license_texts={"numpy": "BSD-3-Clause"},
        licenses_dir=tpl,
    )
    joined = "\n".join(problems)
    assert "Verbotene kommerzielle Lizenzdatei" in joined
    assert "Nicht-Laufzeit-Paket unter THIRD_PARTY_LICENSES/: 'pytest-9.2.0.dist-info'" in joined
    assert "Versions-Drift fuer 'numpy-2.0.0.dist-info'" in joined



def test_merge_gate_rejects_stale_branch_and_prunes_only_merged_branches(
    tmp_path: Path,
) -> None:
    mg = _load_script("merge_gate")
    git = _git_exe()

    subprocess.run([git, "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@example.org"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "Test"], check=True)

    (tmp_path / "README.md").write_text("v1\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "c1"], check=True, capture_output=True
    )

    # Create feat/merged (at c1) and feat/unmerged (diverged from c1)
    subprocess.run([git, "-C", str(tmp_path), "branch", "feat/merged"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "branch", "archive/keep"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "branch", "release/1.0"], check=True)

    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "-b", "feat/unmerged"],
        check=True,
        capture_output=True,
    )
    (tmp_path / "unmerged.txt").write_text("work\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "unmerged"], check=True, capture_output=True
    )

    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "main"], check=True, capture_output=True
    )
    (tmp_path / "README.md").write_text("v2\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "c2"], check=True, capture_output=True
    )

    # feat/unmerged does NOT contain c2 on main -> verify_branch_ready must block!
    stale_errs, _, _ = mg.verify_branch_ready(tmp_path, "feat/unmerged", run_code_gates=False)
    assert any("basiert nicht auf dem aktuellen Stand" in e for e in stale_errs)

    # prune_merged_branch safety checks
    assert mg.prune_merged_branch(tmp_path, "-D") == 1
    assert mg.prune_merged_branch(tmp_path, "main") == 1
    assert mg.prune_merged_branch(tmp_path, "archive/keep") == 1
    assert mg.prune_merged_branch(tmp_path, "release/1.0") == 1
    assert mg.prune_merged_branch(tmp_path, "feat/does-not-exist") == 1
    assert mg.prune_merged_branch(tmp_path, "feat/unmerged") == 1

    # Checked-out branch must not be pruned
    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "feat/merged"], check=True, capture_output=True
    )
    assert mg.prune_merged_branch(tmp_path, "feat/merged") == 1

    # Switch back to main -> feat/merged IS an ancestor of main -> pruned cleanly!
    subprocess.run(
        [git, "-C", str(tmp_path), "checkout", "main"], check=True, capture_output=True
    )
    assert mg.prune_merged_branch(tmp_path, "feat/merged") == 0
    branches = subprocess.check_output(
        [git, "-C", str(tmp_path), "branch"], text=True, encoding="utf-8"
    )
    assert "feat/merged" not in branches
    assert "archive/keep" in branches
    assert "release/1.0" in branches
    assert "feat/unmerged" in branches


def test_license_gate_accepts_and_validates_english_notices(tmp_path: Path) -> None:
    lic = _load_script("license_gate")
    req = tmp_path / "requirements.txt"
    notices = tmp_path / "THIRD_PARTY_NOTICES.md"
    req.write_text("numpy>=1.26\npikepdf>=10.0\n", encoding="utf-8")
    notices.write_text(
        "# Third-Party Notices\n\n"
        "## Included Runtime Dependencies\n\n"
        "| Component | License | Role |\n"
        "|---|---|---|\n"
        "| numpy | BSD-3-Clause | Math |\n\n"
        "## Complete Runtime Components (SBOM)\n\n"
        "| Component | Version | License |\n"
        "|---|---|---|\n"
        "| numpy | 2.5.4 | BSD-3-Clause |\n"
        "| pikepdf | 10.17.0 | MPL-2.0 |\n",
        encoding="utf-8",
    )
    assert (
        lic.check_licenses(
            req,
            notices,
            extra_license_texts={"numpy": "BSD-3-Clause", "pikepdf": "MPL-2.0"},
        )
        == []
    )
    req.write_text("numpy>=1.26\nundocumented-pkg>=1.0\n", encoding="utf-8")
    errs = lic.check_licenses(
        req,
        notices,
        extra_license_texts={"numpy": "BSD-3-Clause", "undocumented-pkg": "MIT"},
    )
    assert any("undocumented-pkg" in e for e in errs)


def test_merge_gate_accepts_local_spec_and_rejects_traversal(tmp_path: Path) -> None:
    mg = _load_script("merge_gate")
    assert mg._validate_spec_ref(tmp_path, "a" * 40, "LOCAL_SPEC:003-english-public-repo.md") is None
    assert mg._validate_spec_ref(tmp_path, "a" * 40, "LOCAL_SPEC:../README.md") is not None
    assert mg._validate_spec_ref(tmp_path, "a" * 40, "LOCAL_SPEC:bad") is not None


def test_repo_hygiene_gate_allows_code_signing_policy_in_root(tmp_path: Path) -> None:
    hygiene = _load_script("repo_hygiene_gate")
    assert "CODE_SIGNING_POLICY.md" in hygiene.ALLOWED_ROOT_FILES

    git = _git_exe()
    subprocess.run([git, "init", "-b", "docs/test", str(tmp_path)], check=True, capture_output=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    subprocess.run([git, "-C", str(tmp_path), "config", "user.email", "t@t"], check=True)
    (tmp_path / "CODE_SIGNING_POLICY.md").write_text("# Policy\n", encoding="utf-8")
    subprocess.run([git, "-C", str(tmp_path), "add", "CODE_SIGNING_POLICY.md"], check=True)
    subprocess.run(
        [git, "-C", str(tmp_path), "commit", "-m", "docs: add policy"],
        check=True,
        capture_output=True,
    )
    assert hygiene.run_checks(tmp_path, scan_all=True) == []
