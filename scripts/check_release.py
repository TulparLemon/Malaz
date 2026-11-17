"""Release gate: reject runtime data, secrets, and private paths in artifacts.

This is intentionally dependency-free. It is called by the Nuitka build after
packaging and can also be run against a source ZIP before publication.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_TEXT_SUFFIXES = {
    ".bat", ".cfg", ".cmd", ".ini", ".json", ".md", ".ps1", ".psm1", ".py", ".sh",
    ".toml", ".txt", ".yaml", ".yar", ".yml",
}
_FORBIDDEN_PARTS = {
    ".agents", ".git", ".mimosa", ".pytest_cache", ".pytest-tmp", "__pycache__", "audit", "backups",
}
# The two third-party feeds are runtime downloads and must never ship in binary
# releases. In --source archives only their 5 tracked attribution/license docs
# (and no .yar/.yarc/other files) may appear.
_FEED_DIR_PAIRS = {("yara", "external"), ("yara", "signature_base")}
_ALLOWED_SOURCE_FEED_DOCS = {
    "rules/yara/external/license-mit-reversinglabs.txt",
    "rules/yara/external/readme-externe-regeln.txt",
    "rules/yara/signature_base/license-drl-1.1.txt",
    "rules/yara/signature_base/licenses-einzelregeln.txt",
    "rules/yara/signature_base/readme-signature-base.txt",
}
_ALLOWED_SOURCE_FEED_DIRS = {
    "rules/yara/external",
    "rules/yara/signature_base",
}
_FORBIDDEN_NAMES = {
    ".env",
    ".gitlab-ci.yml",
    "agents.md",
    "gemini.md",
    "handover.backup-2026-09-24.md",
    "handover.md",
    "moc.md",
    "project_board.md",
}
_FORBIDDEN_SUFFIXES = {".pyc", ".pyo", ".log", ".feed", ".part", ".bak"}
_SECRET_PATTERNS = {
    "private-key": re.compile(rb"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
    "github-token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "telegram-token": re.compile(rb"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b"),
    "aws-access-key": re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    "bearer-token": re.compile(rb"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
}
_PRIVATE_PATH_PATTERNS = {
    "developer-path": re.compile(
        rb"(?i)\b[A-Z]:[\\/]{1,2}Users[\\/]{1,2}"
        rb"(?!(?:Public|Default|Default User|All Users|WDAGUtilityAccount"
        rb"|entwickler|alex|runneradmin)(?:[\\/]|$)|<[^>]+>)"
        rb"(?=[A-Za-z0-9._-]*[A-Za-z0-9])[A-Za-z0-9._-]{2,}[\\/]{1,2}"
    ),
    "developer-unix-path": re.compile(
        rb"(?<![:/A-Za-z0-9._-])/(?:Users|home)/"
        rb"(?!(?:alex|runner|ubuntu)(?:/|$)|<[^>]+>)"
        rb"(?=[A-Za-z0-9._-]*[A-Za-z0-9])[A-Za-z0-9._-]{2,}/"
    ),
    "private-lab-ip": re.compile(rb"\b192\.168\.178\.\d{1,3}\b"),
}
_PRIVATE_EMAIL_PATTERNS = {
    "private-email": re.compile(
        rb"(?i)\b[A-Z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|web)\.[A-Z]{2,}\b"
    ),
}


@dataclass(frozen=True)
class Finding:
    path: str
    kind: str
    detail: str


def _git_exe(root: Path) -> str:
    found = shutil.which("git")
    if found:
        return found
    for candidate in (
        root / "tools" / "Git" / "cmd" / "git.exe",
        ROOT / "tools" / "Git" / "cmd" / "git.exe",
    ):
        if candidate.is_file():
            return str(candidate)
    return "git"


def _is_allowed_source_feed_entry(normalized: str) -> bool:
    trimmed = normalized.rstrip("/")
    candidates = [trimmed]
    if "/" in trimmed:
        candidates.append(trimmed.split("/", 1)[1])
    if normalized.endswith("/"):
        return any(c in _ALLOWED_SOURCE_FEED_DIRS for c in candidates)
    return any(
        c in _ALLOWED_SOURCE_FEED_DOCS or c in _ALLOWED_SOURCE_FEED_DIRS
        for c in candidates
    )


def _is_forbidden(path: str, *, source: bool) -> bool:
    normalized = path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    parts = normalized.split("/")
    has_feed_dir = any(pair in _FEED_DIR_PAIRS for pair in pairwise(parts))
    if has_feed_dir and source and _is_allowed_source_feed_entry(normalized):
        has_feed_dir = False
    has_designs_dir = any(pair == ("docs", "designs") for pair in pairwise(parts))
    return (
        bool(set(parts) & _FORBIDDEN_PARTS)
        or name in _FORBIDDEN_NAMES
        or has_designs_dir
        or any(normalized.endswith(suffix) for suffix in _FORBIDDEN_SUFFIXES)
        or has_feed_dir
        or (not source and (normalized.startswith("tests/") or "/tests/" in normalized))
    )


def _scan_bytes(data: bytes, label: str, *, source: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    patterns = {**_SECRET_PATTERNS, **_PRIVATE_PATH_PATTERNS}
    if not source:
        patterns.update(_PRIVATE_EMAIL_PATTERNS)
    for kind, pattern in patterns.items():
        if pattern.search(data):
            findings.append(Finding(label, kind, "redacted match; value not printed"))
    return findings


def _scan_file(path: Path, root: Path, *, source: bool) -> list[Finding]:
    rel = path.relative_to(root).as_posix()
    if _is_forbidden(rel, source=source):
        return [Finding(rel, "forbidden-runtime-file", "must not ship")]
    if path.suffix.lower() not in _TEXT_SUFFIXES:
        return []
    return _scan_bytes(path.read_bytes(), rel, source=source)


def scan_directory(root: Path, *, source: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    # A release gate that cannot check its target must not report "passed":
    # a typo in the build script would otherwise turn the gate into a no-op.
    if not root.is_dir():
        return [Finding(str(root), "invalid-target", "target must be an existing directory")]
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        findings.extend(_scan_file(path, root, source=source))
    return findings


def scan_archive(path: Path, *, source: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    if not path.is_file():
        return [Finding(str(path), "invalid-target", "target must be an existing archive")]
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            if _is_forbidden(name, source=source):
                findings.append(Finding(name, "forbidden-runtime-file", "must not ship"))
                continue
            if Path(name).suffix.lower() not in _TEXT_SUFFIXES:
                continue
            findings.extend(_scan_bytes(archive.read(info), name, source=source))
    return findings


def _parse_history_grep_line(line: str, commit: str) -> Finding | None:
    """Convert one git-grep record without exposing its content."""
    parts = line.split(":", 3)
    if len(parts) != 4:
        return None
    _ref, path, line_number, _content = parts
    if not path or path.startswith("tests/"):
        return None
    return Finding(
        f"{commit[:10]}:{path}:{line_number}",
        "history-secret-pattern",
        "redacted match; value not printed",
    )


def scan_git_history(root: Path, ref: str = "--all") -> list[Finding]:
    """Scan historical runtime/report blobs without printing their contents."""
    git = _git_exe(root)
    findings: list[Finding] = []
    commits = subprocess.check_output(
        [git, "rev-list", ref], cwd=root, text=True
    ).splitlines()
    for commit in commits:
        names = subprocess.check_output(
            [git, "ls-tree", "-r", "--name-only", commit],
            cwd=root,
            text=True,
        ).splitlines()
        for name in names:
            normalized = name.replace("\\", "/").lower()
            basename = normalized.rsplit("/", 1)[-1]
            sensitive = (
                basename.startswith("malaz.log")
                or normalized.startswith((".mimosa/", "audit/", "backups/"))
                or basename in {"handover.md", "handover.backup-2026-09-24.md"}
            )
            if not sensitive:
                continue
            blob = subprocess.check_output(
                [git, "show", f"{commit}:{name}"], cwd=root
            )
            findings.extend(
                _scan_bytes(blob, f"{commit[:10]}:{name}", source=False)
            )
        secret_args = [git, "grep", "-I", "-n", "-i", "-E"]
        for pattern in (
            r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
            r"gh[pousr]_[A-Za-z0-9_]{20,}",
            r"[0-9]{8,12}:[A-Za-z0-9_-]{30,}",
            r"AKIA[0-9A-Z]{16}",
            r"Authorization:[[:space:]]*Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{20,}",
        ):
            secret_args.extend(["-e", pattern])
        secret_args.extend([commit, "--"])
        grep = subprocess.run(
            secret_args, cwd=root, text=True, capture_output=True, check=False
        )
        for line in grep.stdout.splitlines():
            finding = _parse_history_grep_line(line, commit)
            if finding is not None:
                findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--archive", type=Path)
    parser.add_argument(
        "--source", action="store_true", help="allow tests/scripts in a source archive"
    )
    parser.add_argument(
        "--history", action="store_true", help="scan sensitive blobs in Git history"
    )
    parser.add_argument(
        "--history-ref", help="scan sensitive blobs reachable from this Git ref"
    )
    args = parser.parse_args(argv)
    if args.history or args.history_ref:
        if args.directory is not None or args.archive is not None:
            parser.error("history options cannot be combined with directory/archive")
        findings = scan_git_history(Path.cwd(), args.history_ref or "--all")
    elif (args.directory is None) == (args.archive is None):
        parser.error(
            "exactly one of --directory, --archive, --history, or --history-ref is required"
        )
    else:
        findings = (
            scan_directory(args.directory, source=args.source)
            if args.directory is not None
            else scan_archive(args.archive, source=args.source)
        )
    if findings:
        print(f"RELEASE BLOCKED: {len(findings)} finding(s)")
        for finding in findings:
            print(f"- {finding.path}: {finding.kind}: {finding.detail}")
        return 1
    target = "Git history" if (args.history or args.history_ref) else (
        args.directory if args.directory is not None else args.archive
    )
    print(f"Release gate passed: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
