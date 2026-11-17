"""Output escaping to prevent XSS / code injection in generated reports.

Every piece of data extracted from a scanned file (VBA source, PDF metadata,
EXIF strings, YARA matches, raw byte excerpts) is *untrusted*. Before any of it
reaches the HTML report it must pass through :func:`escape_html`. Raw binary
excerpts should additionally be passed through :func:`safe_excerpt`.

Untrusted text also carries a second, non-markup risk: **invisible characters**.
Bidi overrides/isolates make a string DISPLAY differently from how it is stored
— a file named ``Rechnung\\u202efdp.exe`` is shown as ``Rechnungexe.pdf`` by Qt
(verified by screenshot) and by any browser. :func:`escape_html` therefore masks
them as visible escapes; :func:`mask_invisible` covers the plain-text surfaces
that do not go through HTML.
"""

from __future__ import annotations

import html

from .. import config

# Characters that change how text is DISPLAYED without being visible themselves:
# the bidi overrides/isolates (LRE RLE PDF LRO RLO, LRI RLI FSI PDI) and NUL.
#
# Measured, not assumed: Qt applies the bidi algorithm to plain text, so a file
# stored as ``Rechnung\u202efdp.exe`` renders as ``Rechnungexe.pdf`` — an
# executable reading as a PDF. (A first probe used ``.exe``, a palindrome, which
# looks identical either way and could not decide the question.) Browsers apply
# it to HTML reports in the same way.
#
# Notably NOT included: genuine RTL letters (Hebrew, Arabic). Those are ordinary
# text and masking them would garble a legitimate subject line — verified.
_INVISIBLE_AND_BIDI = frozenset(
    [chr(0)]
    + [chr(c) for c in range(0x202A, 0x202F)]
    + [chr(c) for c in range(0x2066, 0x206A)]
)


def mask_invisible(text: object) -> str:
    """Spell out invisible/bidi controls so the STORED string is what is read.

    ``Rechnung\\u202efdp.exe`` becomes ``Rechnung\\u202efdp.exe`` — the deception
    becomes visible instead of effective. The characters are neither rendered nor
    dropped: analyses like ``MAIL_ATTACH_NAME_TRICK`` report this trick, and a
    view that silently removed them would hide what the analysis flags.

    Genuine RTL letters are left untouched (a Hebrew subject is not a trick).
    Use for every attacker-controlled string shown to the user: file names,
    subjects, attachment names, indicator details.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    if not any(ch in _INVISIBLE_AND_BIDI for ch in text):
        return text
    return "".join(
        f"\\u{ord(ch):04x}" if ch in _INVISIBLE_AND_BIDI else ch for ch in text
    )


def escape_html(value: object) -> str:
    """Escape a value for safe inclusion in HTML text or attributes.

    ``quote=True`` also escapes ``"`` and ``'`` so the result is safe inside
    quoted attributes as well. ``None`` renders as an empty string.

    Invisible/bidi controls are masked first: escaping alone does not stop them
    from re-ordering the text around them, so a bidi-mangled file name would
    still display as a different name in a browser.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    return html.escape(mask_invisible(value), quote=True)


def safe_excerpt(data: bytes | str, max_len: int | None = None) -> str:
    """Return a capped, escaped, human-readable excerpt of raw data.

    Binary input is rendered with ``repr``-style escaping so that control
    characters and non-printable bytes cannot smuggle markup into the report.
    ``escape_html`` masks bidi controls on top of that.
    """
    if max_len is None:
        max_len = config.MAX_STRING_CAPTURE

    # Decode leniently; undecodable bytes become the replacement char which
    # is then HTML-escaped below.
    text = (
        data[:max_len].decode("utf-8", errors="replace")
        if isinstance(data, bytes)
        else data[:max_len]
    )

    # Strip control characters except common whitespace to keep the report clean.
    cleaned = "".join(
        ch if (ch in "\n\r\t" or ord(ch) >= 32) else "\ufffd" for ch in text
    )
    truncated = len(data) > max_len
    escaped = escape_html(cleaned)
    if truncated:
        escaped += escape_html(f" … [gekürzt, {len(data)} Bytes gesamt]")
    return escaped
