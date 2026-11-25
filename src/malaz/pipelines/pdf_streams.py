"""Bounded PDF stream decompression, bomb guards, and PDF text value extraction.

Extracted from :mod:`malaz.pipelines.pdf_pipeline` (Spec 012, Etappe 2) as the
shared low-level foundation for PDF links, JavaScript, layout, and future QR stages.
"""

from __future__ import annotations

import re

from ..models import Indicator

# Exact /AA key token (avoids matching e.g. /AApple). Shared by pdf_pipeline & pdf_javascript.
_AA_KEY_RE = re.compile(rb"/AA(?![A-Za-z])")

# Upper bound for ONE decompressed stream (JS payload / content stream).
# pikepdf's read_bytes() materialises the FULL decompressed stream — a
# FlateDecode bomb (tiny file, gigabytes expanded) would otherwise OOM or
# freeze the worker with a single crafted PDF.
MAX_STREAM_BYTES = 8 * 1024 * 1024


# Worst-case DECODE expansion per filter (output bytes per input byte).
# Flate/LZW reach ~1032:1 on degenerate all-repetitive input; RunLength
# decodes at most 64:1 (1 length byte + up to 128 data bytes per 2 input
# bytes); ASCIIHex and ASCII85 SHRINK on decode. Unknown filters (DCT,
# CCITT, JBIG2, custom) get the Flate-style worst case as a safe default —
# a crafted chain like [/FlateDecode /FlateDecode] multiplies to ~1e6:1
# and is therefore refused before anything is materialised.
_FILTER_EXPANSION: dict[str, float] = {
    "/FlateDecode": 1032,
    "/LZWDecode": 1032,
    "/RunLengthDecode": 64,
    "/ASCIIHexDecode": 0.5,
    "/ASCII85Decode": 0.8,
    "/Crypt": 1.0,
}
_UNKNOWN_EXPANSION = 1032


def chain_expansion(names: list[str]) -> float:
    """Worst-case expansion factor of a filter chain (product of stages)."""
    factor = 1.0
    for name in names:
        factor *= _FILTER_EXPANSION.get(name, _UNKNOWN_EXPANSION)
    return factor


def read_stream_bounded(
    stream,
    pikepdf,
    *,
    max_stream_bytes: int | None = None,
) -> tuple[bytes | None, str | None]:
    """Read a decompressed stream with a hard output cap.

    Returns ``(payload, None)`` on success or ``(None, reason)`` when the
    stream is refused. FlateDecode(-only) streams are decompressed here with
    a bounded loop (the standard case for JS/content streams); any other
    filter chain is guarded by a raw-size x ratio estimate before pikepdf
    materialises it.
    """
    import zlib

    limit = MAX_STREAM_BYTES if max_stream_bytes is None else max_stream_bytes

    try:
        filters = stream.get(pikepdf.Name.Filter)
    except Exception:
        filters = None
    names: list[str] = []
    if filters is not None:
        names = (
            [str(f) for f in filters]
            if isinstance(filters, pikepdf.Array)
            else [str(filters)]
        )
    try:
        decode_parms = stream.get(pikepdf.Name.DecodeParms)
    except Exception:
        decode_parms = None

    if not names:
        # No filter: the raw bytes ARE the payload. Running them through
        # zlib would reject every unfiltered (hand-written / simple
        # generator) stream as "beschädigt" — regression caught in review.
        try:
            payload = stream.read_raw_bytes()
        except Exception as exc:
            return None, f"Stream nicht lesbar ({type(exc).__name__})"
        if len(payload) > limit:
            return None, (
                f"Stream > {limit} Bytes (Dekompressionsbombe-Verdacht)"
            )
        return payload, None

    if names == ["/FlateDecode"] and decode_parms is None:
        try:
            raw = stream.read_raw_bytes()
        except Exception as exc:
            return None, f"Stream nicht lesbar ({type(exc).__name__})"
        dec = zlib.decompressobj()
        out = bytearray()
        chunk_size = 1 << 20
        for pos in range(0, len(raw), chunk_size):
            try:
                out += dec.decompress(
                    raw[pos : pos + chunk_size], limit + 1 - len(out)
                )
            except zlib.error:
                return None, "Flate-Stream beschädigt"
            if len(out) > limit:
                return None, (
                    f"entpackter Stream > {limit} Bytes "
                    "(Dekompressionsbombe-Verdacht)"
                )
        try:
            out += dec.flush(limit + 1 - len(out))
        except zlib.error:
            return None, "Flate-Stream beschädigt"
        if len(out) > limit:
            return None, (
                f"entpackter Stream > {limit} Bytes "
                "(Dekompressionsbombe-Verdacht)"
            )
        if not dec.eof:
            if not raw:
                # Empty raw stream: some generators write empty content
                # streams WITH a filter — nothing is truncated, there is
                # simply no payload.
                return b"", None
            # The zlib stream never reached its end marker: the file is cut
            # off mid-stream. Return the readable prefix but flag it — the
            # analysis must not claim full coverage of a truncated payload.
            return bytes(out), "Flate-Stream unvollständig (abgeschnittene Datei)"
        return bytes(out), None

    # Everything else (exotic filters, Flate with /DecodeParms predictors,
    # filter chains): bound by a per-filter worst-case expansion estimate
    # BEFORE pikepdf materialises anything, then a hard check after.
    try:
        raw_len = len(stream.read_raw_bytes())
    except Exception as exc:
        return None, f"Stream nicht lesbar ({type(exc).__name__})"
    expansion = chain_expansion(names)
    if decode_parms is not None:
        # PNG predictors add one filter byte per row; with 1-byte rows that
        # doubles the data — 6x is a comfortable safety margin. This
        # multiplier is deliberately conservative: LEGITIMATE streams
        # (Flate+Predictor images) can trip the estimate without being
        # bombs, so refusals caused by it report "unpruefbar", NOT bomb
        # suspicion (_warn_is_bomb must not match).
        expansion *= 6
        if raw_len * expansion > limit:
            return None, (
                f"Stream mit Predictor nicht prüfbar: geschätzte Expansion "
                f"{expansion:.0f}:1 übersteigt das Analyse-Limit"
            )
    elif raw_len * expansion > limit:
        # Pure filter-chain product (e.g. [/FlateDecode /FlateDecode] on
        # tiny raw bytes): no legitimate content trips this — treat as
        # bomb suspicion and refuse BEFORE pikepdf materialises anything.
        return None, (
            f"Stream-Filterkette überschreitet Größenlimit "
            f"(geschätzte Expansion {expansion:.0f}:1)"
        )
    try:
        payload = stream.read_bytes()
    except Exception as exc:
        return None, f"Stream nicht lesbar ({type(exc).__name__})"
    if len(payload) > limit:
        return None, f"entpackter Stream > {limit} Bytes"
    return payload, None


def warn_is_bomb(reason: str) -> bool:
    """Classify a _read_stream_bounded refusal as bomb suspicion.

    Matches the actual bomb refusal strings ("Dekompressionsbombe-Verdacht",
    hard-limit messages, the pure filter-chain estimate). The Predictor
    estimate reports "nicht prüfbar" instead — a legitimate stream can trip
    that conservative multiplier without being a bomb, so it stays an
    ordinary INFO warning.
    """
    # Substring checks, not startswith: in the layout forensics the
    # reasons carry a "S. <n>: " prefix that would break any prefix match.
    return (
        "Bombe" in reason
        or "entpackter Stream >" in reason
        or "Stream > " in reason
        or "Größenlimit" in reason
    )


def read_pdf_text_value(
    value,
    pikepdf,
    depth: int,
    chunks: list,
    warnings: list,
    total_ref: list,
    *,
    max_stream_bytes: int | None = None,
) -> None:
    """Render a ``/JS`` value (stream, string or array of those) as text.

    ``total_ref[0]`` tracks the cumulative character count across the
    whole recursion; every append respects the remaining budget.
    """

    limit = MAX_STREAM_BYTES if max_stream_bytes is None else max_stream_bytes

    def _as_text(raw: bytes) -> str:
        # PDF strings may be UTF-16BE with a BOM; decoding those as
        # latin-1 garbles every second character and loses API hits.
        if raw.startswith(b"\xfe\xff"):
            return raw[2:].decode("utf-16-be", errors="ignore")
        return raw.decode("latin-1", "ignore")

    if depth > 4:
        # BUG-023: a bound that silently drops payload is an evasion
        # vector — the caller must be able to say "not examined".
        note = (
            "Verschachteltes /JS jenseits der Analysetiefe 4 wurde NICHT "
            "analysiert — das Ergebnis ist nicht als 'sauber' zu werten."
        )
        if note not in warnings:
            warnings.append(note)
        return
    if total_ref[0] >= limit:
        # defensive: bound recursive structures AND the shared budget
        return
    try:
        if isinstance(value, pikepdf.Stream):
            payload, warn = read_stream_bounded(value, pikepdf, max_stream_bytes=limit)
            if warn is not None:
                warnings.append(warn)
            if payload:
                # Analyse the readable prefix EVEN when warned: a
                # truncated stream still typically contains the whole
                # payload, and discarding it would let an attacker hide
                # JS by simply cutting the stream's last bytes. The
                # warning keeps the "not fully analysed" caveat visible.
                full_text = _as_text(payload)
                budget_left = limit - total_ref[0]
                text = full_text[:budget_left]
                if text:
                    chunks.append(text)
                    total_ref[0] += len(text)
                if len(text) < len(full_text):
                    # Truncatur am Budget: der Rest dieses Streams (und
                    # alle folgenden) werden nicht analysiert — sichtbar
                    # melden statt still verwerfen (Evasions-Vektor,
                    # Hunt-Fund 3.1).
                    warnings.append(
                        f"JS-Gesamtbudget ({limit} Bytes) erschöpft "
                        "— dieser /JS-Stream wurde gekürzt; weitere Inhalte "
                        "wurden nicht analysiert."
                    )
            return
        if isinstance(value, pikepdf.Array):
            for item in value:
                if total_ref[0] >= limit:
                    return
                read_pdf_text_value(
                    item,
                    pikepdf,
                    depth + 1,
                    chunks,
                    warnings,
                    total_ref,
                    max_stream_bytes=limit,
                )
            return
        if isinstance(value, pikepdf.String):
            text = _as_text(bytes(value))[: limit - total_ref[0]]
            if text:
                chunks.append(text)
                total_ref[0] += len(text)
        # Dictionaries/other shapes are not valid JS carriers; ignore.
    except Exception:
        return


def make_pdf_indicator(
    source: str, rule_id: str, title: str, **kwargs
) -> Indicator:
    """Build a PDF pipeline indicator with ``source`` defaulted."""
    kwargs.setdefault("source", source)
    return Indicator(rule_id=rule_id, title=title, **kwargs)
