"""SWF (Flash) decompression for embedded-content analysis.

Compressed SWF files start with ``CWS`` (zlib) or ``ZWS`` (LZMA) instead of
``FWS``: the bytes from offset 8 on are a compressed stream of the real SWF.
Until now such files only received the generic surface checks (entropy +
YARA), so the decompressed payload — often where malicious ActionScript and
URLs live — was opaque.

This module decompresses the stream in a bounded, defensive way; the dispatcher
feeds the result back into the analysis loop, where the generic pipeline
extracts strings and IOCs from the now-readable payload.

Security notes:
* incremental decompression with a hard output cap — a crafted bomb stream is
  rejected while it expands, never after it has consumed memory;
* malformed/truncated files degrade to an error entry, never a crash.
"""

from __future__ import annotations

import lzma
import zlib
from collections.abc import Iterator

from .. import config

# Header: 3-byte magic + version + 4-byte length, then the compressed stream.
_HEADER_SIZE = 8

_COMPRESSED_MAGICS = frozenset({b"CWS", b"ZWS"})

# SEC-033: a ZWS header carries its LZMA dictionary size as a 4-byte field.
# Dict and decompressor workspace are capped BEFORE lzma allocates anything;
# 85 crafted bytes with a 1-GiB dict otherwise commit ~1 GiB per worker.
_LZMA_DICT_LIMIT = 16 * config.MB
_LZMA_MEM_LIMIT = 32 * config.MB


class _PayloadTooLarge(Exception):
    """Raised when the stream expands beyond the configured output cap."""


def _max_payload() -> int:
    # read at call time so config changes (tests, deployments) take effect
    return config.MAX_EXTRACTED_FILE_SIZE


def _lzma_dict_size(stream: bytes) -> int | None:
    """Dictionary size from a raw LZMA1 property header, or ``None``.

    Real ZWS streams start with the 5-byte LZMA1 property block
    (lc/lp/pb byte + little-endian dictionary size). XZ/ALONE streams do not
    use that layout; their first byte is >= 225 (XZ magic 0xFD) or the value
    is the ALONE header, which the decompressor handles itself. Only a valid
    raw property byte is read as a dictionary size.
    """
    if len(stream) < 5:
        return None
    if stream[0] >= 9 * 5 * 5:  # invalid lc/lp/pb combination
        return None
    return int.from_bytes(stream[1:5], "little")


def _bounded_decompress(
    data: bytes, magic: bytes, limit: int
) -> tuple[bytes, bool]:
    """Decompress up to ``limit`` bytes; raise :class:`_PayloadTooLarge` beyond.

    ``max_length`` is passed on every ``decompress`` call so the decompressor
    stops producing output at the budget. zlib keeps unfed input in
    ``unconsumed_tail``; lzma buffers it internally and is drained with empty
    input calls — anything still pending beyond the budget is detected instead
    of being materialised.

    Returns ``(payload, truncated)``: ``truncated`` is True when the stream
    ended before its declared end (cut-off file) — the caller must surface
    that instead of silently analysing partial data.
    """
    is_zlib = magic == b"CWS"
    # FORMAT_AUTO mirrors plain lzma.decompress(); real ZWS streams use a raw
    # LZMA1 layout that may not decode — that degrades to an error entry in
    # iter_swf_payloads, never a crash.
    zdec = zlib.decompressobj() if is_zlib else None
    ldec = (
        None
        if is_zlib
        else lzma.LZMADecompressor(
            format=lzma.FORMAT_AUTO, memlimit=_LZMA_MEM_LIMIT
        )
    )
    out = bytearray()
    feed = data
    while True:
        budget = limit + 1 - len(out)
        if budget <= 0:
            raise _PayloadTooLarge
        if zdec is not None:
            chunk = zdec.decompress(feed, budget)
            out += chunk
            if len(out) > limit:
                raise _PayloadTooLarge
            feed = zdec.unconsumed_tail
            if not feed:
                return bytes(out), not zdec.eof
        elif ldec is not None:
            chunk = ldec.decompress(feed, budget)
            out += chunk
            if len(out) > limit:
                raise _PayloadTooLarge
            if ldec.eof:
                return bytes(out), False
            if not chunk and not feed:
                # Decompressor wants no more input but has not seen the
                # stream end: the file is cut off mid-stream.
                return bytes(out), True
            feed = b""
        else:  # pragma: no cover - one of the two is always set
            return bytes(out), False


def iter_swf_payloads(data: bytes) -> Iterator[tuple[str, bytes, str | None]]:
    """Yield ``(name, payload, error)`` for the decompressed SWF.

    Only compressed (``CWS``/``ZWS``) files yield a payload; uncompressed
    ``FWS`` files are already readable and are not re-yielded.
    """
    if not data or len(data) < 3 or data[:3] not in _COMPRESSED_MAGICS:
        return
    if len(data) <= _HEADER_SIZE:
        # Header present but the compressed stream is empty/missing — that
        # is a broken file, not a clean one; say so instead of yielding
        # nothing (which would read as "nothing to analyse").
        yield ("", b"", "SWF-Header ohne komprimierten Stream — Datei unvollständig")
        return
    magic = data[:3]
    max_payload = _max_payload()
    stream = data[_HEADER_SIZE:]
    if magic == b"ZWS":
        dict_size = _lzma_dict_size(stream)
        if dict_size is not None and dict_size > _LZMA_DICT_LIMIT:
            yield (
                "",
                b"",
                (
                    f"SWF-LZMA-Wörterbuch zu groß ({dict_size} Bytes > "
                    f"Limit {_LZMA_DICT_LIMIT}) — Stream wird nicht entpackt"
                ),
            )
            return
    try:
        payload, truncated = _bounded_decompress(stream, magic, max_payload)
    except _PayloadTooLarge:
        yield ("", b"", f"SWF-Inhalt zu groß (Limit {max_payload} Bytes überschritten)")
        return
    except (zlib.error, lzma.LZMAError, ValueError) as exc:
        yield ("", b"", f"SWF-Komprimierung nicht lesbar: {exc}")
        return
    if truncated:
        # A cut-off stream must not masquerade as a complete payload — the
        # analysis result would silently cover only the readable prefix.
        yield (
            "",
            b"",
            "SWF-Stream abgeschnitten — Inhalt unvollständig (nur Teil-Payload lesbar)",
        )
        return
    if payload:
        yield ("payload.swf", payload, None)
