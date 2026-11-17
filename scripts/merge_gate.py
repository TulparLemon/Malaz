#!/usr/bin/env python3
"""Pre-Merge Gate and Guarded Merger for Malaz.

No branch may be merged into 'main' unless:
1. Working tree is completely clean, protected merge config (--no-ff) is active,
   and <branch> contains the current HEAD of 'main'.
2. repo_hygiene_gate, arch_gate, license_gate, check_doc_claims, check_duplicate_logic,
   ruff, mypy, and all CORE_MERGE_TESTS pass on the target branch HEAD.
3. An isolated Goldfish review certificate exists at
   artifacts/reviews/<safe_branch>_<sha12>.json matching the exact 40-char HEAD SHA of <branch>,
   with base_ref == "main", verdict == "PASS", integer blockers == 0, integer majors == 0,
   confined spec_ref ('TRIVIAL_FIX' or docs/designs/<file>.md present in commit_sha),
   and all 5 checklist keys true.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_CHECKLIST_KEYS = (
    "completeness_invariant",
    "security_bounds",
    "layer_boundaries",
    "tests_bite_verified",
    "doc_sync",
)

SPEC_REF_RE = re.compile(r"^docs/designs/[A-Za-z0-9][A-Za-z0-9._-]*\.md$")
LOCAL_SPEC_RE = re.compile(r"^LOCAL_SPEC:[A-Za-z0-9][A-Za-z0-9._-]*\.md$")

CORE_MERGE_TESTS = (
    "tests/test_governance_gates.py",
    "tests/test_ci_config.py",
    "tests/test_release_gate.py",
    "tests/test_magic.py",
    "tests/test_scoring.py",
    "tests/test_safe_extract.py",
    "tests/test_limits.py",
    "tests/test_escaping.py",
    "tests/test_incomplete_display.py",
)


def _git_exe(repo: Path) -> str:
    portable = repo / "tools" / "Git" / "cmd" / "git.exe"
    if portable.is_file():
        return str(portable)
    found = shutil.which("git")
    if found:
        return found
    raise RuntimeError("git executable not found")


def safe_branch_slug(branch: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", branch)


def expected_review_path(repo: Path, branch: str, commit_sha: str) -> Path:
    return repo / "artifacts" / "reviews" / f"{safe_branch_slug(branch)}_{commit_sha[:12]}.json"


def _is_exact_int(val: object) -> bool:
    return type(val) is int


def _validate_spec_ref(repo: Path, commit_sha: str, spec_ref: str) -> str | None:
    if not spec_ref:
        return "spec_ref fehlt im Review-Zertifikat ('TRIVIAL_FIX' oder Pfad unter docs/designs/)"
    if spec_ref == "TRIVIAL_FIX" or LOCAL_SPEC_RE.match(spec_ref):
        return None
    if not SPEC_REF_RE.match(spec_ref):
        return (
            f"spec_ref '{spec_ref}' ungueltig: muss 'TRIVIAL_FIX', "
            "'LOCAL_SPEC:<datei>.md' oder 'docs/designs/<datei>.md' sein"
        )
    designs_dir = (repo / "docs" / "designs").resolve()
    resolved = (repo / spec_ref).resolve()
    try:
        resolved.relative_to(designs_dir)
    except ValueError:
        return f"spec_ref bricht aus docs/designs/ aus: {spec_ref}"

    git = _git_exe(repo)
    obj_proc = subprocess.run(
        [git, "-C", str(repo), "cat-file", "-t", f"{commit_sha}:{spec_ref}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if obj_proc.returncode != 0 or obj_proc.stdout.strip() != "blob":
        return (
            f"Referenzierte Design-Spec existiert nicht im geprueften Commit "
            f"{commit_sha[:12]}: {spec_ref}"
        )
    return None


def validate_review_certificate(
    repo: Path,
    branch: str,
    commit_sha: str,
    cert_path: Path | None = None,
) -> tuple[list[str], dict]:
    path = cert_path or expected_review_path(repo, branch, commit_sha)
    if not path.is_file():
        rel_cert = path.relative_to(repo).as_posix()
        return (
            [
                (
                    f"Kein Pre-Merge-Review-Zertifikat fuer '{branch}' @ {commit_sha[:12]} "
                    f"gefunden (erwartet: {rel_cert}). Starte zuerst den isolierten Subagenten "
                    "'malaz-code-reviewer'!"
                )
            ],
            {},
        )

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ([f"Review-Zertifikat ungueltiges JSON ({path.name}): {exc}"], {})

    if not isinstance(data, dict):
        return ([f"Review-Zertifikat muss ein JSON-Objekt sein ({path.name})"], {})

    problems: list[str] = []
    if data.get("reviewer_agent") != "malaz-code-reviewer":
        problems.append("reviewer_agent muss exakt 'malaz-code-reviewer' sein")
    if data.get("branch") != branch:
        problems.append(f"Zertifikat gilt fuer Branch {data.get('branch')!r}, nicht {branch!r}")
    if data.get("base_ref") != "main":
        problems.append(f"base_ref muss exakt 'main' sein (gefunden: {data.get('base_ref')!r})")
    if data.get("commit_sha") != commit_sha:
        problems.append(
            f"SHA-Mismatch: Zertifikat ist fuer {data.get('commit_sha')!r}, "
            f"aktueller Branch-HEAD ist {commit_sha!r} (nach Aenderungen neu reviewen!)"
        )
    if data.get("verdict") != "PASS":
        problems.append(f"Review-Urteil ist {data.get('verdict')!r} (erfordert 'PASS')")

    blockers = data.get("blockers")
    if not _is_exact_int(blockers) or blockers != 0:
        problems.append(f"blockers muss die Ganzzahl 0 sein (gefunden: {blockers!r})")

    majors = data.get("majors", 0)
    if not _is_exact_int(majors) or majors != 0:
        problems.append(f"majors muss die Ganzzahl 0 sein (gefunden: {majors!r})")

    spec_err = _validate_spec_ref(repo, commit_sha, str(data.get("spec_ref") or "").strip())
    if spec_err:
        problems.append(spec_err)

    checklist = data.get("checklist")
    if not isinstance(checklist, dict):
        problems.append("checklist fehlt oder ist kein Objekt")
    else:
        for key in REQUIRED_CHECKLIST_KEYS:
            if checklist.get(key) is not True:
                problems.append(f"Pflichtpruefpunkt checklist.{key} ist nicht true")

    return (problems, data)


def _run_cmd_gate(repo: Path, label: str, args: list[str], env: dict[str, str]) -> list[str]:
    proc = subprocess.run(
        args,
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        detail = f"{proc.stdout}\n{proc.stderr}".strip()
        return [f"Gate fehlgeschlagen ({label}):\n{detail}"]
    return []


def ensure_no_ff_config(repo: Path) -> None:
    git = _git_exe(repo)
    for protected in ("main", "stable"):
        subprocess.run(
            [
                git,
                "-C",
                str(repo),
                "config",
                "--local",
                f"branch.{protected}.mergeoptions",
                "--no-ff",
            ],
            capture_output=True,
            check=False,
        )


def verify_branch_ready(
    repo: Path,
    branch: str,
    *,
    run_code_gates: bool = True,
) -> tuple[list[str], str, dict]:
    git = _git_exe(repo)
    ensure_no_ff_config(repo)

    if not branch or branch.startswith("-"):
        return ([f"Ungueltiger Branch-Name: {branch!r}"], "", {})

    status = subprocess.run(
        [git, "-C", str(repo), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if status.returncode != 0 or status.stdout.strip():
        return ([f"Arbeitsbaum ist nicht sauber:\n{status.stdout.strip()}"], "", {})

    if branch in {"main", "stable", "master"}:
        return ([f"'{branch}' ist ein Ziel-Branch, kein Quell-Branch fuer Merge."], "", {})

    rev = subprocess.run(
        [git, "-C", str(repo), "rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if rev.returncode != 0:
        return ([f"Lokaler Arbeits-Branch '{branch}' existiert nicht."], "", {})
    commit_sha = rev.stdout.strip()

    anc = subprocess.run(
        [
            git,
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            "refs/heads/main",
            f"refs/heads/{branch}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if anc.returncode != 0:
        return (
            [
                (
                    f"Branch '{branch}' basiert nicht auf dem aktuellen Stand von 'main' "
                    "(bitte 'main' einpflegen und neu reviewen)."
                )
            ],
            commit_sha,
            {},
        )

    problems, cert = validate_review_certificate(repo, branch, commit_sha)
    if problems or not run_code_gates:
        return (problems, commit_sha, cert)

    sym = subprocess.run(
        [git, "-C", str(repo), "symbolic-ref", "--short", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    restore_ref = (
        sym.stdout.strip()
        if sym.returncode == 0 and sym.stdout.strip()
        else subprocess.check_output(
            [git, "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            encoding="utf-8",
            errors="replace",
        ).strip()
    )
    switched = False
    try:
        if restore_ref != branch:
            subprocess.run([git, "-C", str(repo), "checkout", branch], check=True)
            switched = True

        missing_tests = [t for t in CORE_MERGE_TESTS if not (repo / t).is_file()]
        if missing_tests:
            problems.append(
                f"Pflicht-Testdatei(en) fehlen auf Branch '{branch}': {', '.join(missing_tests)}"
            )
            return (problems, commit_sha, cert)

        env = dict(os.environ)
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        env.setdefault("PYTHONUTF8", "1")

        gate_commands: list[tuple[str, list[str]]] = [
            ("repo_hygiene_gate", [sys.executable, "scripts/repo_hygiene_gate.py", "--all"]),
            ("arch_gate", [sys.executable, "scripts/arch_gate.py"]),
            ("license_gate", [sys.executable, "scripts/license_gate.py"]),
            (
                "ruff",
                [
                    sys.executable,
                    "-m",
                    "ruff",
                    "check",
                    "src",
                    "tests",
                    "scripts",
                    "fuzz",
                    "conftest.py",
                ],
            ),
            ("mypy", [sys.executable, "-m", "mypy", "src/malaz"]),
            ("check_doc_claims", [sys.executable, "scripts/check_doc_claims.py"]),
            ("check_duplicate_logic", [sys.executable, "scripts/check_duplicate_logic.py"]),
            (
                "pytest-core",
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "--basetemp=.pytest-tmp/merge-gate",
                    *CORE_MERGE_TESTS,
                ],
            ),
        ]

        for label, cmd_args in gate_commands:
            problems.extend(_run_cmd_gate(repo, label, cmd_args, env))
            if problems:
                return (problems, commit_sha, cert)
    finally:
        if switched:
            subprocess.run([git, "-C", str(repo), "checkout", restore_ref], check=False)

    return (problems, commit_sha, cert)


def prune_merged_branch(repo: Path, branch: str) -> int:
    if not branch or branch.startswith("-"):
        print(f"PRUNE BLOCKED: Ungueltiger Branch-Name {branch!r}.")
        return 1
    if branch in {"main", "stable", "master"} or branch.startswith(("archive/", "release/")):
        print(
            f"PRUNE BLOCKED: Geschuetzter/historischer Branch '{branch}' "
            "darf nicht geloescht werden."
        )
        return 1

    git = _git_exe(repo)
    rev = subprocess.run(
        [git, "-C", str(repo), "rev-parse", "--verify", f"refs/heads/{branch}^{{commit}}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if rev.returncode != 0:
        print(f"PRUNE BLOCKED: Lokaler Branch '{branch}' existiert nicht.")
        return 1

    sym = subprocess.run(
        [git, "-C", str(repo), "symbolic-ref", "--short", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if sym.returncode == 0 and sym.stdout.strip() == branch:
        print(f"PRUNE BLOCKED: Branch '{branch}' ist aktuell ausgecheckt.")
        return 1

    anc = subprocess.run(
        [
            git,
            "-C",
            str(repo),
            "merge-base",
            "--is-ancestor",
            f"refs/heads/{branch}",
            "refs/heads/main",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if anc.returncode != 0:
        print(f"PRUNE BLOCKED: Branch '{branch}' ist nicht vollstaendig in 'main' gemerged.")
        return 1

    proc = subprocess.run(
        [git, "-C", str(repo), "branch", "-d", "--", branch],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        print(f"PRUNE FAILED fuer '{branch}':\n{proc.stdout}\n{proc.stderr}".strip())
        return 1
    print(f"PRUNE OK: Vollstaendig gemergter Branch '{branch}' geloescht.")
    return 0


def merge_into_main(
    repo: Path,
    branch: str,
    *,
    delete_branch: bool = False,
    run_code_gates: bool = True,
) -> int:
    problems, commit_sha, cert = verify_branch_ready(
        repo, branch, run_code_gates=run_code_gates
    )
    if problems:
        print(f"MERGE BLOCKED fuer '{branch}':")
        for item in problems:
            print(f"  !! {item}")
        return 1

    git = _git_exe(repo)
    spec_ref = cert.get("spec_ref", "TRIVIAL_FIX")
    summary = str(cert.get("summary") or "Verified merge").strip()
    msg = (
        f"merge({branch}): verified via Goldfish review & merge_gate\n\n"
        f"Reviewed-Commit: {commit_sha}\n"
        f"Reviewer-Agent: malaz-code-reviewer (PASS, 0 blockers, 0 majors)\n"
        f"Design-Spec: {spec_ref}\n"
        f"Summary: {summary}\n"
    )

    env = dict(os.environ)
    env["MALAZ_MERGE_GATE_ACTIVE"] = "1"

    subprocess.run([git, "-C", str(repo), "checkout", "main"], env=env, check=True)
    proc = subprocess.run(
        [git, "-C", str(repo), "merge", "--no-ff", branch, "-m", msg],
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        subprocess.run([git, "-C", str(repo), "merge", "--abort"], env=env, check=False)
        print(f"Git-Merge fehlgeschlagen (sauber abgebrochen):\n{proc.stdout}\n{proc.stderr}")
        return 1

    if delete_branch:
        subprocess.run([git, "-C", str(repo), "branch", "-d", "--", branch], env=env, check=True)

    new_head = subprocess.check_output(
        [git, "-C", str(repo), "rev-parse", "--short", "HEAD"],
        text=True,
        encoding="utf-8",
        errors="replace",
    ).strip()
    print(f"MERGE OK: '{branch}' ({commit_sha[:12]}) -> main ({new_head}).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--verify", metavar="BRANCH", help="Prueft alle Merge-Voraussetzungen ohne Merge"
    )
    group.add_argument(
        "--merge", metavar="BRANCH", help="Fuehrt geprueften Merge nach main aus"
    )
    group.add_argument(
        "--prune-merged",
        metavar="BRANCH",
        help="Loescht einen bereits vollstaendig in main gemergten Arbeits-Branch",
    )
    parser.add_argument(
        "--delete-branch",
        action="store_true",
        help="Loescht den gemergten Arbeits-Branch nach erfolgreichem Merge",
    )
    args = parser.parse_args(argv)
    if args.delete_branch and not args.merge:
        parser.error("--delete-branch ist nur zusammen mit --merge erlaubt")
    repo = args.repo.resolve()

    if args.prune_merged is not None:
        return prune_merged_branch(repo, args.prune_merged)

    if args.verify:
        problems, sha, _ = verify_branch_ready(repo, args.verify, run_code_gates=True)
        if problems:
            print(f"MERGE GATE NOT READY fuer '{args.verify}':")
            for item in problems:
                print(f"  !! {item}")
            return 1
        print(f"  Merge-Gate bereit fuer '{args.verify}' @ {sha[:12]}.")
        return 0

    return merge_into_main(repo, args.merge, delete_branch=args.delete_branch)


if __name__ == "__main__":
    raise SystemExit(main())
