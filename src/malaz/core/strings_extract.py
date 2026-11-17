"""Bounded, deterministic string extraction for binary formats.

AP9 foundation for the PE pipeline (and later ELF/Mach-O): extract printable
ASCII and UTF-16LE runs with hard caps and optional section attribution. This
is deliberately NOT a FLOSS replacement — no decoding, no deobfuscation, no
disassembly, no execution. It answers one question: "which readable strings are
in these bytes, and where?"

Determinism: hits are merged in byte order; duplicates are dropped keeping the
first occurrence. A caller can therefore compare two runs byte-for-byte.
"""

from __future__ import annotations

import heapq
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .. import config


@dataclass(frozen=True)
class SectionSpan:
    """A file region (PE section) used to attribute an offset."""

    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class ExtractedString:
    value: str
    offset: int
    encoding: str  # "ascii" | "utf-16le"
    section: str  # "" when the caller passed no section table


@dataclass(frozen=True)
class StringsResult:
    strings: tuple[ExtractedString, ...]
    scanned_bytes: int
    #: Which caps stopped the extraction: "bytes", "count", "length".
    caps: tuple[str, ...]

    @property
    def capped(self) -> bool:
        return bool(self.caps)


def _section_at(offset: int, sections: tuple[SectionSpan, ...]) -> str:
    for span in sections:
        if span.offset <= offset < span.offset + span.size:
            return span.name
    return ""


def _ascii_hits(buffer: bytes, min_len: int):
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for match in pattern.finditer(buffer):
        yield match.start(), 0, "ascii", match.group()


def _utf16le_hits(buffer: bytes, min_len: int):
    # Two bytes per character; the NUL byte after each printable byte is part
    # of the match, so UTF-16 text never doubles as a shorter ASCII hit.
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    for match in pattern.finditer(buffer):
        start = match.start()
        raw = match.group()
        if start > 0 and 0x20 <= buffer[start - 1] <= 0x7E:
            # A printable byte immediately before the pair is usually the
            # ASCII string that ends in that byte, with its NUL terminator
            # borrowed as the pair's high byte ("...Ascii\0" + UTF-16
            # "World" produced "iWorld"). Drop that first borrowed pair
            # instead of fabricating a cross-boundary string. The rare real
            # case of unaligned ASCII followed by UTF-16 loses one character;
            # inventing text is the worse failure.
            start += 2
            raw = raw[2:]
            if len(raw) < min_len * 2:
                continue
        yield start, 1, "utf-16le", raw


def extract_strings(
    data: bytes,
    *,
    min_len: int | None = None,
    max_strings: int | None = None,
    max_bytes: int | None = None,
    max_string_length: int | None = None,
    sections: Iterable[SectionSpan] | None = None,
) -> StringsResult:
    """Extract ASCII/UTF-16LE strings from ``data`` with hard caps.

    ``sections`` maps file offsets to PE section names; offsets outside every
    span keep an empty ``section`` (headers, overlay, alignment padding).
    """
    min_len = max(1, int(config.STRINGS_MIN_LEN if min_len is None else min_len))
    max_strings = int(config.STRINGS_MAX_COUNT if max_strings is None else max_strings)
    max_bytes = int(config.STRINGS_MAX_SCAN_BYTES if max_bytes is None else max_bytes)
    max_length = int(
        config.STRINGS_MAX_STRING_LEN
        if max_string_length is None
        else max_string_length
    )
    if not data or max_strings <= 0 or max_bytes <= 0:
        return StringsResult((), 0, ())

    buffer = data[:max_bytes]
    caps: set[str] = set()
    if len(data) > len(buffer):
        caps.add("bytes")

    spans = tuple(sections or ())
    seen: set[str] = set()
    out: list[ExtractedString] = []

    merged = heapq.merge(
        _ascii_hits(buffer, min_len),
        _utf16le_hits(buffer, min_len),
    )

    def decoded(encoding: str, raw: bytes) -> str:
        value = (
            raw.decode("ascii")
            if encoding == "ascii"
            else raw.decode("utf-16-le")
        )
        if len(value) > max_length:
            value = value[:max_length]
            caps.add("length")
        return value

    for offset, _order, encoding, raw in merged:
        value = decoded(encoding, raw)
        if value in seen:
            continue
        seen.add(value)
        out.append(
            ExtractedString(
                value=value,
                offset=offset,
                encoding=encoding,
                section=_section_at(offset, spans),
            )
        )
        if len(out) >= max_strings:
            # Only claim the count cap when a further UNIQUE string really
            # exists. Previously the rule fired when the last match exactly
            # filled the limit ("AAAA\0BBBB", max 2), and the PE summary then
            # claimed the rest of the file was not searched.
            for _o, _r, extra_encoding, extra_raw in merged:
                if decoded(extra_encoding, extra_raw) not in seen:
                    caps.add("count")
                    break
            break

    return StringsResult(
        strings=tuple(out),
        scanned_bytes=len(buffer),
        caps=tuple(sorted(caps)),
    )
