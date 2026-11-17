#!/usr/bin/env python3
"""Repository hygiene, secret-leak, and branch-discipline gate for Malaz.

Checks:
1. Root directory allowlist (blocks msg*.txt, PROMPT_*.md, HANDOVER*.md, crash dumps, archives).
2. No stray crash/log/archive artifacts inside src/ or scripts/.
3. Bounded secret & key-file scan on staged index blobs (--pre-commit, including renames R)
   or all tracked files (--all, NUL-delimited UTF-8 so non-ASCII paths are never skipped).
4. Branch discipline in --pre-commit mode: blocks direct commits on main/stable
   unless MALAZ_MERGE_GATE_ACTIVE=1 is set by scripts/merge_gate.py.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAX_SECRET_SCAN_BYTES = 4 * 1024 * 1024  # 4 MiB fail-closed ceiling

ALLOWED_ROOT_FILES = {
    ".coverage",
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "LICENSE",
    "Malaz starten.bat",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "conftest.py",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements-fuzz.txt",
    "requirements.txt",
    "scan.bat",
    "start.bat",
}

ALLOWED_ROOT_DIRS = {
    ".git",
    ".github",
    ".hypothesis",
    ".mimosa",
    ".mypy_cache",
    ".pytest-tmp",
    ".pytest_cache",
    ".ruff_cache",
    ".scratch",
    ".venv",
    "THIRD_PARTY_LICENSES",
    "__pycache__",
    "artifacts",
    "assets",
    "audit",
    "backups",
    "build",
    "dist",
    "docs",
    "fuzz",
    "rules",
    "scripts",
    "src",
    "tests",
    "tools",
}

BRANCH_PATTERN = re.compile(
    r"^(?:feat|fix|sec|refactor|docs|chore|test|release)/[a-z0-9][a-z0-9._-]*$"
)

FORBIDDEN_NAME_PATTERNS = (
    re.compile(r"^msg\d*\.txt$", re.IGNORECASE),
    re.compile(r"^handover.*\.(?:md|txt)$", re.IGNORECASE),
    re.compile(r"^prompt_.*\.(?:md|txt)$", re.IGNORECASE),
    re.compile(r"nuitka-crash-report\.xml$", re.IGNORECASE),
)

FORBIDDEN_TREE_SUFFIXES = {
    ".7z",
    ".bak",
    ".cab",
    ".dmp",
    ".err",
    ".iso",
    ".log",
    ".rar",
    ".rpt",
    ".zip",
}

FORBIDDEN_KEY_FILENAMES = (
    re.compile(r"^id_(?:rsa|dsa|ecdsa|ed25519)(?:\..+)?$", re.IGNORECASE),
    re.compile(r"^\.env(?:\..+)?$", re.IGNORECASE),
    re.compile(r".+\.(?:pem|key|pfx|p12|kdbx)$", re.IGNORECASE),
)

SKIP_BINARY_SUFFIXES = {
    ".dll",
    ".exe",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".otf",
    ".pdf",
    ".png",
    ".pyd",
    ".ttf",
    ".webp",
    ".whl",
    ".woff",
    ".woff2",
    ".yarc",
}

SECRET_PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "github-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "gitlab-token": re.compile(rb"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "aws-access-key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "google-api-key": re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b"),
}


def _git_exe(repo: Path) -> str:
    portable = repo / "tools" / "Git" / "cmd" / "git.exe"
    if portable.is_file():
        return str(portable)
    found = shutil.which("git")
    if found:
        return found
    raise RuntimeError("git executable not found")


def check_root_entries(repo: Path) -> list[str]:
    problems: list[str] = []
    for entry in sorted(repo.iterdir(), key=lambda p: p.name.lower()):
        name = entry.name
        if entry.is_dir():
            if name not in ALLOWED_ROOT_DIRS and not name.startswith(".pytest-tmp"):
                problems.append(
                    f"Root-Verzeichnis nicht erlaubt: '{name}/' "
                    "(nutze .scratch/ fuer Temporaeres oder docs/ fuer Doku)"
                )
        elif name not in ALLOWED_ROOT_FILES:
            problems.append(
                f"Lose Root-Datei nicht erlaubt: '{name}' "
                "(keine msg*.txt, PROMPT_*, HANDOVER* oder Test-Artefakte im Root)"
            )
    for sub in ("src", "scripts"):
        sub_dir = repo / sub
        if not sub_dir.is_dir():
            continue
        for path in sub_dir.rglob("*"):
            if (
                not path.is_file()
                or "__pycache__" in path.parts
                or any(part.endswith(".egg-info") for part in path.parts)
            ):
                continue
            rel = path.relative_to(repo).as_posix()
            if path.suffix.lower() in FORBIDDEN_TREE_SUFFIXES:
                problems.append(f"Verbotenes Archiv-/Log-/Dump-Artefakt im Quellbaum: '{rel}'")
                continue
            for pat in FORBIDDEN_NAME_PATTERNS:
                if pat.search(path.name):
                    problems.append(f"Verbotenes Artefakt im Quellbaum: '{rel}'")
    return problems


def check_branch(repo: Path) -> list[str]:
    if os.environ.get("MALAZ_MERGE_GATE_ACTIVE") == "1":
        return []
    git = _git_exe(repo)
    proc = subprocess.run(
        [git, "-C", str(repo), "symbolic-ref", "--short", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        return ["Detached HEAD: Commits muessen auf einem benannten Arbeits-Branch erfolgen."]
    branch = proc.stdout.strip()
    if branch in {"main", "stable", "master"}:
        return [
            (
                f"Direkte Commits auf '{branch}' sind gesperrt! "
                "Erstelle einen Arbeits-Branch (z. B. 'git checkout -b feat/<name> main') "
                "und merge nach Review ueber 'python scripts/merge_gate.py --merge <branch>'."
            )
        ]
    if not BRANCH_PATTERN.match(branch):
        return [
            (
                f"Branch-Name '{branch}' entspricht nicht dem Schema "
                "'(feat|fix|sec|refactor|docs|chore|test|release)/<slug>'."
            )
        ]
    return []


def _read_candidate_bytes(
    git: str, repo: Path, rel_clean: str, *, staged_only: bool
) -> tuple[bytes | None, str | None]:
    if staged_only:
        size_proc = subprocess.run(
            [git, "-C", str(repo), "cat-file", "-s", f":{rel_clean}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if size_proc.returncode != 0:
            return (None, f"Staged-Blob fuer '{rel_clean}' konnte nicht geprueft werden")
        blob_size = int(size_proc.stdout.strip() or "0")
        if blob_size > MAX_SECRET_SCAN_BYTES:
            return (
                None,
                (
                    f"Datei '{rel_clean}' ueberschreitet das Secret-Scan-Limit "
                    f"({blob_size} > {MAX_SECRET_SCAN_BYTES} Bytes)"
                ),
            )
        blob_proc = subprocess.run(
            [git, "-C", str(repo), "show", f":{rel_clean}"],
            capture_output=True,
            check=False,
        )
        if blob_proc.returncode != 0:
            return (None, f"Staged-Inhalt fuer '{rel_clean}' nicht lesbar")
        return (blob_proc.stdout, None)

    path = repo / rel_clean
    if not path.is_file():
        return (
            None,
            f"Getrackte Datei '{rel_clean}' fehlt im Arbeitsbaum oder ist keine regulaere Datei",
        )
    size = path.stat().st_size
    if size > MAX_SECRET_SCAN_BYTES:
        return (
            None,
            (
                f"Datei '{rel_clean}' ueberschreitet das Secret-Scan-Limit "
                f"({size} > {MAX_SECRET_SCAN_BYTES} Bytes)"
            ),
        )
    return (path.read_bytes(), None)


def check_secrets(repo: Path, *, staged_only: bool) -> list[str]:
    git = _git_exe(repo)
    cmd = (
        [git, "-C", str(repo), "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"]
        if staged_only
        else [git, "-C", str(repo), "ls-files", "-z"]
    )
    proc = subprocess.run(cmd, capture_output=True, check=False)
    if proc.returncode != 0:
        err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
        return [f"git Dateiliste fehlgeschlagen: {err_msg}"]
    problems: list[str] = []
    for raw_entry in proc.stdout.split(b"\x00"):
        if not raw_entry:
            continue
        rel_clean = raw_entry.decode("utf-8", errors="surrogateescape").replace("\\", "/")
        if not rel_clean or rel_clean.startswith(("tests/", "THIRD_PARTY_LICENSES/")):
            continue
        fname = rel_clean.rsplit("/", 1)[-1]
        for pat in FORBIDDEN_NAME_PATTERNS:
            if pat.search(fname):
                problems.append(f"Verbotener Dateiname im Git-Index: '{rel_clean}'")
        for key_pat in FORBIDDEN_KEY_FILENAMES:
            if key_pat.match(fname):
                problems.append(f"Verbotene Key-/Env-Datei im Git-Index: '{rel_clean}'")

        suffix = Path(rel_clean).suffix.lower()
        if suffix in SKIP_BINARY_SUFFIXES:
            continue

        data, read_err = _read_candidate_bytes(git, repo, rel_clean, staged_only=staged_only)
        if read_err is not None:
            problems.append(read_err)
            continue
        if not data:
            continue
        for kind, regex in SECRET_PATTERNS.items():
            if regex.search(data):
                problems.append(f"Secret-Muster ({kind}) gefunden in '{rel_clean}'")
    return problems


def run_checks(repo: Path, *, pre_commit: bool = False, scan_all: bool = False) -> list[str]:
    problems = check_root_entries(repo)
    if pre_commit:
        problems.extend(check_branch(repo))
        problems.extend(check_secrets(repo, staged_only=True))
    elif scan_all:
        problems.extend(check_secrets(repo, staged_only=False))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT, help="Repository-Wurzel")
    parser.add_argument(
        "--pre-commit", action="store_true", help="Pre-Commit-Modus inkl. Branch-Gate"
    )
    parser.add_argument("--all", action="store_true", help="Gesamten getrackten Baum pruefen")
    args = parser.parse_args(argv)

    problems = run_checks(args.repo.resolve(), pre_commit=args.pre_commit, scan_all=args.all)
    if problems:
        print(f"REPO HYGIENE GATE BLOCKED ({len(problems)} Befund(e)):")
        for item in problems:
            print(f"  !! {item}")
        return 1
    print("  Repo-Hygiene-Gate gruen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
