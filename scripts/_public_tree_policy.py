"""Shared path policy for public Git trees, staged commits, and release archives."""

from __future__ import annotations

import re

FORBIDDEN_PUBLIC_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(^|/)agents\.md$"),
    re.compile(r"(^|/)gemini\.md$"),
    re.compile(r"(^|/)moc\.md$"),
    re.compile(r"(^|/)project_board\.md$"),
    re.compile(r"(^|/)\.agents(/|$)"),
    re.compile(r"(^|/)docs/designs(/|$)"),
    re.compile(r"(^|/)docs/\d\d_[^/]*\.md$"),
    re.compile(r"(^|/)\.gitlab-ci\.yml$"),
    re.compile(r"(^|/)scripts/make_public_export\.bat$"),
    re.compile(r"(^|/)handover[^/]*\.(md|txt)$"),
    re.compile(r"(^|/)prompt_[^/]*\.(md|txt)$"),
    re.compile(r"(^|/)msg\d*\.txt$"),
)


def is_forbidden_public_path(posix_path: str) -> bool:
    """Return True for internal governance/design/handover paths.

    Matches both root-relative Git paths (``docs/03_x.md``) and archive-prefixed
    paths (``Malaz-1.0.0/docs/03_x.md``). Uses ``removeprefix("./")`` so leading
    dots on ``.agents/...`` and ``.gitlab-ci.yml`` remain intact.
    """
    p = posix_path.replace("\\", "/").lower().removeprefix("./")
    return any(rx.search(p) for rx in FORBIDDEN_PUBLIC_PATTERNS)
