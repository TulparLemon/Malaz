"""Validate documentation claims, rule IDs, file paths, counts, and relative links.

Checks:
1. Rule IDs mentioned in documentation exist in the codebase.
2. `scripts/`, `src/`, and `tests/` paths cited in current docs exist on disk.
3. Mutation counts cited in docs match `scripts/check_tests_bite.py` (at least one
   count claim must be present across CURRENT_DOCS so the check cannot degrade
   into a silent zero-match pass).
4. No proprietary / closed-distribution claims appear anywhere in the GPL-3.0 tree.
5. Relative Markdown links in all root, community, license, and `docs/` files resolve
   inside the repository.
"""

from __future__ import annotations

import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CURRENT_DOCS = (
    "README.md",
    "SECURITY.md",
    "CODE_SIGNING_POLICY.md",
    ".github/CONTRIBUTING.md",
    "docs/INSTALLATION.md",
    "docs/USAGE.md",
    "docs/ARCHITECTURE.md",
    "docs/SECURITY_MODEL.md",
    "docs/VERIFYING_RELEASES.md",
)

HISTORICAL_DOCS = ("CHANGELOG.md",)
DOCS = CURRENT_DOCS + HISTORICAL_DOCS

LINK_CHECK_DOCS = (
    *CURRENT_DOCS,
    "CHANGELOG.md",
    "THIRD_PARTY_NOTICES.md",
    "THIRD_PARTY_LICENSES/README.md",
)

_RULE_PREFIXES = (
    "MAIL_",
    "ARCH_",
    "PE_",
    "PDF_",
    "OFFICE_",
    "GEN_",
    "CORE_",
    "AV_",
    "CLAMAV_",
    "EXT_",
    "IMG_",
    "SCRIPT_",
    "LNK_",
    "YARA_",
    "VBA_",
    "XLM_",
    "EML_",
    "RTF_",
    "SWF_",
    "ZIP_",
    "TAR_",
    "SEVENZIP_",
    "HASH_",
)
_RULE_ID = re.compile(r"\b((?:" + "|".join(_RULE_PREFIXES) + r")[A-Z0-9_]{2,})\b")
_PATH = re.compile(
    r"\b((?:scripts|src|tests)/[\w./-]+\.(?:py|ps1|bat|md|yar|json))\b"
)
_FENCED_CODE = re.compile(r"(?:```[\s\S]*?```|~~~[\s\S]*?~~~)")
_INLINE_CODE = re.compile(r"`[^`\n]+`")
_MD_LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_HTML_LINK = re.compile(
    r"""<(?:img|a)\b[^>]*?\b(?:src|href)\s*=\s*(?:"([^"]+)"|'([^']+)')""",
    re.IGNORECASE,
)
_LINK_TITLE_SUFFIX = re.compile(r"""\s+(?:"[^"]*"|'[^']*')\s*$""")
_URI_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")

CODE_GLOBS = ("src/**/*.py", "scripts/**/*.py", "tests/**/*.py", "rules/**/*")

_SKIPPED_SCAN_DIRS = (
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".git",
    "THIRD_PARTY_LICENSES",
    ".scratch",
    "backups",
    "audit",
)


def _code_text() -> str:
    chunks: list[str] = []
    for pattern in CODE_GLOBS:
        for path in ROOT.glob(pattern):
            if path.is_file() and "__pycache__" not in path.parts:
                try:
                    chunks.append(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
    return "\n".join(chunks)


def check_rule_ids(code: str) -> tuple[list[str], list[str]]:
    """Rule IDs mentioned in documentation must exist in code."""
    problems: list[str] = []
    hints: list[str] = []
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        seen: set[str] = set()
        for match in _RULE_ID.finditer(path.read_text(encoding="utf-8")):
            rule = match.group(1)
            if rule in seen:
                continue
            seen.add(rule)
            if rule in code:
                continue
            line = f"{name}: rule ID '{rule}' not found in codebase"
            (hints if name in HISTORICAL_DOCS else problems).append(line)
    return problems, hints


def check_paths() -> tuple[list[str], list[str]]:
    """Paths cited in CURRENT_DOCS must exist."""
    problems: list[str] = []
    hints: list[str] = []
    seen: set[str] = set()
    for name in CURRENT_DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        for match in _PATH.finditer(path.read_text(encoding="utf-8")):
            target = match.group(1)
            if target in seen:
                continue
            seen.add(target)
            if not (ROOT / target).exists():
                problems.append(f"{name}: path '{target}' does not exist")
    return problems, hints


def check_counts() -> list[str]:
    """Mutation counts cited in DOCS must match scripts/check_tests_bite.py."""
    problems: list[str] = []
    bite = ROOT / "scripts" / "check_tests_bite.py"
    if not bite.exists():
        return problems

    registry = bite.read_text(encoding="utf-8")
    actual = registry.count("    Mutation(\n")
    if actual == 0:
        problems.append(
            "check_tests_bite.py: 0 mutations parsed — registry format changed"
        )
        return problems

    claim = re.compile(
        r"(\d+)\s*(?:/\s*(\d+))?\s+(?:Mutationen|mutations)\b",
        re.IGNORECASE,
    )
    emphasis = re.compile(r"(\*\*|__|`)")
    present_current = sum(1 for name in CURRENT_DOCS if (ROOT / name).exists())
    matches_found = 0

    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        text = emphasis.sub("", path.read_text(encoding="utf-8"))
        for match in claim.finditer(text):
            matches_found += 1
            claimed = int(match.group(1))
            total = int(match.group(2)) if match.group(2) else actual
            if claimed != actual or total != actual:
                problems.append(
                    f"{name} claims {match.group(0)!r}, "
                    f"registry has {actual} (expected {actual}/{actual})"
                )

    if present_current >= 3 and matches_found == 0:
        problems.append(
            "no mutation count claim matched across DOCS — verify check_counts() regex"
        )
    return problems


def check_licence_claims() -> list[str]:
    """Reject contradictory closed-source / proprietary claims in the GPL-3.0 tree."""
    problems: list[str] = []
    forbidden_terms = (
        "closed-source",
        "closed source",
        "geschlossene distribution",
    )
    for pfad in sorted(ROOT.rglob("*")):
        if not pfad.is_file() or pfad.suffix.lower() not in (".md", ".py", ".txt", ".bat"):
            continue
        if any(teil in pfad.parts for teil in _SKIPPED_SCAN_DIRS):
            continue
        try:
            relative_parts = pfad.relative_to(ROOT).parts
        except ValueError:
            relative_parts = pfad.parts
        if any(part.startswith(".pytest-tmp") for part in relative_parts):
            continue
        if pfad.name.startswith(("AUDIT_", "HANDOVER")):
            continue
        if pfad.name == "check_doc_claims.py":
            continue
        try:
            text = pfad.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for nummer, zeile in enumerate(text.splitlines(), 1):
            lowered = zeile.lower()
            if any(term in lowered for term in forbidden_terms):
                problems.append(
                    f"{pfad}:{nummer}: 'Closed Source' / proprietary claim in GPL project "
                    f"- {zeile.strip()[:70]}"
                )
    return problems


def check_markdown_links() -> list[str]:
    """Verify all relative Markdown links across LINK_CHECK_DOCS."""
    problems: list[str] = []
    root_resolved = ROOT.resolve()
    for name in LINK_CHECK_DOCS:
        doc_path = ROOT / name
        if not doc_path.is_file():
            continue
        raw_text = doc_path.read_text(encoding="utf-8")
        stripped = _INLINE_CODE.sub("", _FENCED_CODE.sub("", raw_text))
        raw_targets = [
            _LINK_TITLE_SUFFIX.sub("", m.group(1).strip()).strip()
            for m in _MD_LINK.finditer(stripped)
        ] + [
            (m.group(1) or m.group(2) or "").strip()
            for m in _HTML_LINK.finditer(stripped)
        ]
        for target in raw_targets:
            if target.startswith("<") and target.endswith(">"):
                target = target[1:-1].strip()
            if not target or target.startswith("#") or _URI_SCHEME.match(target):
                continue
            rel_part = target.split("#", 1)[0].split("?", 1)[0].strip()
            if not rel_part:
                continue
            unquoted = urllib.parse.unquote(rel_part)
            try:
                resolved = (doc_path.parent / unquoted).resolve()
            except OSError:
                problems.append(f"{name}: invalid link path '{target}'")
                continue
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                problems.append(
                    f"{name}: relative link '{target}' escapes repository root"
                )
                continue
            if not resolved.exists():
                problems.append(f"{name}: linked target '{target}' does not exist")
    return problems


def main() -> int:
    code = _code_text()
    id_problems, id_hints = check_rule_ids(code)
    path_problems, path_hints = check_paths()
    problems = (
        id_problems
        + path_problems
        + check_counts()
        + check_licence_claims()
        + check_markdown_links()
    )
    hints = id_hints + path_hints

    if hints:
        print(f"  {len(hints)} historical note(s) from CHANGELOG.md:")
        for hint in hints:
            print(f"  · {hint}")
        print()

    if not problems:
        print("  All checked documentation claims and links are valid.")
        return 0
    print(f"  {len(problems)} uncovered documentation claim(s):\n")
    for problem in problems:
        print(f"  !! {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
