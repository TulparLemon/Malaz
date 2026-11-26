"""OpSec leak detector for public lab summaries and benchmark exports.

Layer: ``lab/`` (UI-free, strictly offline, 100% stdlib — Spec 017 §3.4).
"""

from __future__ import annotations

import os
import re
from collections.abc import Collection

_HEX_LEAK_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_WIN_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[/\\][^\s\"'<>|]*")
_UNC_PATH_RE = re.compile(r"\\\\[^\\\s\"'<>|]+\\[^\s\"'<>|]*")
_POSIX_USER_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[^\s\"'<>|]*")
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"
)
_IPV4_RE = re.compile(
    r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


def find_opsec_leaks(
    text: str, *, allow_terms: Collection[str] = ("malaz",)
) -> list[str]:
    """Return a list of OpSec leak descriptions found in ``text``.

    Blocks MD5/SHA-1/SHA-256 hex strings (>= 32 chars), Windows/UNC/POSIX user
    paths, email addresses, IPv4 addresses, HTTP(S) URLs, and the current host's
    ``COMPUTERNAME`` / ``USERNAME`` (unless matched case-insensitively by
    ``allow_terms``).
    """
    leaks: list[str] = []
    allowed_lower = {term.strip().lower() for term in allow_terms if term and term.strip()}

    for label, pattern in (
        ("hex_hash", _HEX_LEAK_RE),
        ("windows_path", _WIN_PATH_RE),
        ("unc_path", _UNC_PATH_RE),
        ("posix_user_path", _POSIX_USER_PATH_RE),
        ("email", _EMAIL_RE),
        ("ipv4", _IPV4_RE),
        ("url", _URL_RE),
    ):
        for match in pattern.finditer(text):
            token = match.group(0)
            if token.lower() in allowed_lower:
                continue
            leaks.append(f"{label}: {token[:48]}")
            if len(leaks) >= 20:
                return leaks

    for env_key in ("COMPUTERNAME", "USERNAME"):
        raw_val = os.environ.get(env_key)
        if not raw_val:
            continue
        val = raw_val.strip()
        if len(val) < 2 or val.lower() in allowed_lower:
            continue
        env_re = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(val) + r"(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )
        if env_re.search(text):
            leaks.append(f"env_{env_key.lower()}: [redacted]")

    return leaks
