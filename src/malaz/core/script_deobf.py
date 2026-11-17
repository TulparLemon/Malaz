"""Lightweight, purely static deobfuscation helpers for script content.

These are regex-based reconstructions of *constant* string expressions — the
tricks malware uses to hide keywords from naive scanners. Nothing is ever
executed; the goal is only to make obfuscated payloads visible to the
keyword/pattern scanners in the pipelines.

Currently covered:

* VBA string concatenation / ``Chr`` obfuscation, e.g. ``"pow" & "ershell"`` or
  ``Chr(112) & Chr(111) & …`` — both rebuild the hidden literal ``powershell``.
"""

from __future__ import annotations

import base64
import binascii
import re

# A single deobfuscatable VBA token: a string literal ("..." with "" as the
# escaped quote) or a Chr/ChrW/Chr$ call with a plain integer argument. Up to
# five digits: ChrW accepts 0..65535, and obfuscation regularly uses e.g.
# ChrW(8230) — capping at 3 digits silently loses those.
_VBA_TOKEN = re.compile(r'(?:"(?:[^"]|"")*"|\bChr[W$]?\s*\(\s*\d{1,5}\s*\))', re.IGNORECASE)
# A whole Chr-family token, anchored, to read out its numeric argument.
_VBA_CHR_FULL = re.compile(r"Chr[W$]?\s*\(\s*(\d{1,5})\s*\)", re.IGNORECASE)
# The connector between two concatenated tokens: '&', optionally split across a
# VBA line continuation (' _' + newline) and surrounding whitespace.
#
# \A/\Z are explicit because the pattern is ONLY used with ``fullmatch``: an
# unanchored ``\s*...`` is quadratic under ``search`` (tests/test_regex_safety
# measures 6.6 s for 20 000 spaces), and a future call site could hit that.
# fullmatch semantics are unchanged — \A and \Z match the same boundaries.
_VBA_CONNECTOR = re.compile(
    r"\A\s*(?:_[ \t]*\r?\n\s*)?&\s*(?:_[ \t]*\r?\n\s*)?\Z"
)


def _token_value(token: str) -> str:
    """Return the runtime string value of one constant VBA token."""
    token = token.strip()
    m = _VBA_CHR_FULL.fullmatch(token)
    if m:
        code = int(m.group(1))
        # The regex caps the argument at five digits (0..99999), so chr() is
        # always defined here. Non-printable control chars are kept — they
        # rarely matter for keyword scanning and dropping them could merge
        # unrelated fragments.
        return chr(code)
    if len(token) >= 2 and token.startswith('"') and token.endswith('"'):
        return token[1:-1].replace('""', '"')
    return ""


def extract_vba_strings(code: str) -> list[str]:
    """Reconstruct strings assembled via VBA literal/``Chr`` concatenation.

    Scans for maximal runs of string literals and ``Chr()`` calls joined by
    ``&`` (the classic obfuscation) and returns each run's concatenated value.
    Single plain literals are skipped — the raw keyword scan already sees those;
    only runs that involve concatenation or ``Chr`` are returned, since those are
    the potentially obfuscated ones.
    """
    results: list[str] = []
    tokens = list(_VBA_TOKEN.finditer(code))
    i = 0
    n = len(tokens)
    while i < n:
        run = [tokens[i]]
        j = i
        while j + 1 < n:
            between = code[tokens[j].end():tokens[j + 1].start()]
            if _VBA_CONNECTOR.fullmatch(between):
                run.append(tokens[j + 1])
                j += 1
            else:
                break
        involves_chr = any(_VBA_CHR_FULL.fullmatch(t.group(0).strip()) for t in run)
        if len(run) >= 2 or involves_chr:
            value = "".join(_token_value(t.group(0)) for t in run)
            if value.strip():
                results.append(value)
        i = j + 1
    return results


# PowerShell ``-EncodedCommand`` (also the ``-enc``/``-ec`` aliases) followed by
# a base64 blob. The bare ``-e`` short form is intentionally excluded — it is far
# too ambiguous. The blob is the base64 of the UTF-16LE command text.
_PS_ENCODED_RE = re.compile(
    r"(?:-(?:encodedcommand|enc|ec)\b)\s+([A-Za-z0-9+/]{16,}={0,2})",
    re.IGNORECASE,
)


def decode_powershell_encoded(text: str) -> list[str]:
    """Decode PowerShell ``-EncodedCommand`` base64 (UTF-16LE) payloads.

    Returns the decoded command text for every encoded blob that decodes to
    plausible text. Pure decoding — nothing is executed.
    """
    out: list[str] = []
    for m in _PS_ENCODED_RE.finditer(text):
        if len(out) >= 64:  # DoS budget: enough payloads for triage
            break
        blob = m.group(1)
        blob += "=" * (-len(blob) % 4)  # re-pad for base64
        try:
            raw = base64.b64decode(blob, validate=False)
        except (binascii.Error, ValueError):
            continue
        # EncodedCommand is UTF-16LE; fall back to UTF-8 for safety.
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding)
            except (UnicodeError, ValueError):
                continue
            if not decoded.strip():
                continue
            printable = sum(c.isprintable() or c.isspace() for c in decoded)
            if printable >= len(decoded) * 0.85:
                out.append(decoded)
                break
    return out
