"""Presentation helpers for untrusted URLs.

One source of truth: the mail pipeline and the `.url` shortcut parser both
display attacker-chosen targets in reports. Breaking the scheme is the only
safe rendering — the text must never be clickable — and it has to be
case-insensitive, because `HTTPS://` is the same scheme.
"""

from __future__ import annotations

import re

_HTTP_SCHEME = re.compile(r"(?i)http(s?)://")


def defang_url(url: str) -> str:
    """Replace http(s):// with hxxp(s)://, preserving the original casing."""
    return _HTTP_SCHEME.sub(
        lambda match: "hxxps://" if match.group(1) else "hxxp://", url
    )
