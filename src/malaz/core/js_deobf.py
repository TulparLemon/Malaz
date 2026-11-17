"""Bounded static JavaScript deobfuscation for PDF JS (AP13).

Decodes the common string-hiding primitives WITHOUT executing anything:
``\\xNN``/``\\uNNNN`` escapes, ``unescape('%XX')``, ``String.fromCharCode``
and literal concatenation. Output is capped and the passes are limited, so a
hostile document cannot turn this into an unbounded decoder.
"""

from __future__ import annotations

import json
import re

MAX_INPUT = 200_000
MAX_PASSES = 4
MAX_FROMCHARCODE_ARGS = 512

_HEX_ESCAPE = re.compile(r"(?<!\\)\\x([0-9a-fA-F]{2})")
_UNICODE_ESCAPE = re.compile(r"(?<!\\)\\u([0-9a-fA-F]{4})")
_FROM_CHAR_CODE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(([^()]*)\)", re.IGNORECASE
)
_CONCAT = re.compile(
    r"(['\"])([^'\"\\]*)\1\s*\+\s*(['\"])([^'\"\\]*)\3"
)
_PERCENT_U = re.compile(r"%u([0-9a-fA-F]{4})")
_PERCENT = re.compile(r"%([0-9a-fA-F]{2})")
# UTF-16 surrogate pairs as produced by fromCharCode/%uXXXX, and the lone
# surrogates that must never leave this module (BUG-019).
_SURROGATE_PAIR = re.compile("[\ud800-\udbff][\udc00-\udfff]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def _percent_decode(value: str) -> str:
    value = _PERCENT_U.sub(lambda match: chr(int(match.group(1), 16)), value)
    return _PERCENT.sub(lambda match: chr(int(match.group(1), 16)), value)


def _skip_space(text: str, pos: int) -> int:
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return pos


def _decode_unescape_calls(text: str) -> str:
    """Decode ``unescape('...')`` in ONE forward pass.

    The old pattern was ``unescape\\s*\\(\\s*(['"])(.*?)\\1\\s*\\)`` — a
    non-greedy group plus backreference. On a hostile document (many
    ``unescape(`` prefixes without a closing quote) every start position
    rescanned the remaining text: measured 0.5 s at 25 k, 8 s at 100 k and
    32 s at 200 k characters (PERF-001). This scan never backtracks: the
    cursor only moves forward, each candidate's closing quote is the FIRST
    quote after it (same semantics as the non-greedy group), and a quote type
    that no longer occurs anywhere is not searched again.

    The accepted syntax is unchanged: ``unescape`` + optional whitespace +
    ``(`` + optional whitespace + quote + nearest equal quote + optional
    whitespace + ``)``.
    """
    if "unescape" not in text:
        return text
    out: list[str] = []
    pos = 0
    end = len(text)
    # Per quote character: first position at/after which it no longer occurs.
    exhausted: dict[str, int] = {}
    while pos < end:
        start = text.find("unescape", pos)
        if start < 0:
            out.append(text[pos:])
            break
        open_paren = _skip_space(text, start + len("unescape"))
        if open_paren >= end or text[open_paren] != "(":
            out.append(text[pos:open_paren])
            pos = open_paren
            continue
        quote_at = _skip_space(text, open_paren + 1)
        if quote_at >= end or text[quote_at] not in "'\"":
            out.append(text[pos:quote_at])
            pos = quote_at
            continue
        quote = text[quote_at]
        search = quote_at + 1
        if search >= exhausted.get(quote, end + 1):
            out.append(text[pos:search])
            pos = search
            continue
        close = text.find(quote, search)
        if close < 0:
            exhausted[quote] = search
            out.append(text[pos:search])
            pos = search
            continue
        after = _skip_space(text, close + 1)
        if after < end and text[after] == ")":
            out.append(text[pos:start])
            out.append(_percent_decode(text[search:close]))
            pos = after + 1
            continue
        # The nearest quote does not close a call. The opening quote is copied
        # verbatim and the scan continues right after it, so a call of the
        # other quote type (or one nested inside this span) is still found.
        # Searches for one quote type cannot overlap: the next same-type
        # candidate starts after the nearest same-type quote. That keeps the
        # whole pass linear even on this failure path.
        out.append(text[pos:quote_at + 1])
        pos = quote_at + 1
    return "".join(out)


def _normalise_surrogates(text: str) -> str:
    """Make sure the returned text is valid Unicode.

    ``unescape('%uD800')`` and ``String.fromCharCode(55296)`` produce a lone
    UTF-16 surrogate, and a surrogate PAIR is written as two code points.
    Exporting such text as UTF-8 raised ``UnicodeEncodeError`` and killed the
    whole report (BUG-019). Pairs are combined into the character they stand
    for; lone surrogates become U+FFFD (never silently dropped).
    """

    def _combine(match: re.Match) -> str:
        high, low = match.group(0)
        return chr(0x10000 + ((ord(high) - 0xD800) << 10) + (ord(low) - 0xDC00))

    return _LONE_SURROGATE.sub(
        "\ufffd", _SURROGATE_PAIR.sub(_combine, text)
    )


def _from_char_codes(arguments: str) -> str:
    chars = []
    for part in arguments.split(",")[:MAX_FROMCHARCODE_ARGS]:
        part = part.strip()
        if not part:
            continue
        try:
            code = int(part, 0)
        except ValueError:
            continue
        if 0 <= code <= 0x10FFFF:
            chars.append(chr(code))
    return "".join(chars)


def deobfuscate_js(text: str) -> str:
    """Decode the common hiding primitives, at most ``MAX_PASSES`` times."""
    current = text[:MAX_INPUT]
    for _pass in range(MAX_PASSES):
        before = current
        current = _HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), current)
        current = _UNICODE_ESCAPE.sub(
            lambda match: chr(int(match.group(1), 16)), current
        )
        current = _decode_unescape_calls(current)
        current = _FROM_CHAR_CODE.sub(
            lambda match: _from_char_codes(match.group(1)), current
        )
        current = _CONCAT.sub(
            lambda match: json.dumps(match.group(2) + match.group(4)), current
        )
        if current == before:
            break
    return _normalise_surrogates(current)
