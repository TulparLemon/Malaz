"""Offline PDF embedded raster-image QR-code & Quishing stage (Spec 015).

Layer 3 submodule of :mod:`malaz.pipelines.pdf_pipeline` (registered in
``scripts/arch_gate.py:FACADE_SUBMODULE_GROUPS``; never imports ``pdf_pipeline``).

Traverses page ``/Resources`` (including inherited ``/Pages /Resources``),
``/Annots[*]/AP/{N,R,D}``, ``/Resources/Pattern`` (tiling ``/PatternType 1``),
and recursive ``/Subtype /Form`` XObjects with strict bomb guards before any
pixel decompression (never calls ``PdfImage(xobj).as_pil_image()`` blindly).
"""

from __future__ import annotations

import contextlib
import zlib
from dataclasses import dataclass, field
from typing import Any

from ..core import qr_scan
from ..models import Indicator
from .pdf_streams import read_stream_bounded

# Hard PDF QR bounds (Spec 015 §5.1)
MAX_PDF_QR_PAGES = 20
MAX_PDF_QR_ANNOTS_PER_PAGE = 256
MAX_PDF_QR_FORMS = 256
MAX_PDF_QR_IMAGES = 32
MAX_PDF_QR_FAILED_IMAGES = 64
MAX_PDF_QR_SKIPPED_TINY = 512
MAX_PDF_QR_RAW_BYTES = 16 * 1024 * 1024
MAX_PDF_QR_DECODED_BYTES = 64 * 1024 * 1024
MAX_PDF_QR_COLORSPACE_BYTES = 4 * 1024 * 1024
MAX_PDF_QR_TOTAL_PIXELS = 32_000_000
MAX_PDF_FORM_DEPTH = 4
MAX_PDF_QR_CONTENT_BYTES = 2 * 1024 * 1024

_DEVICE_CS_NAMES = frozenset(
    {"/DeviceGray", "/DeviceRGB", "/DeviceCMYK", "/G", "/RGB", "/CMYK"}
)
_STREAMLESS_ARRAY_CS = frozenset({"/CalGray", "/CalRGB", "/Lab"})
_AUX_STREAM_FILTERS = frozenset(
    {"/FlateDecode", "/ASCIIHexDecode", "/ASCII85Decode"}
)
_PDF_DELIMS = frozenset(b"()<>[]{}/%")
_PDF_WS = frozenset(b" \t\r\n\x00\x0c")


def _is_strict_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def _objgen_key(obj: Any) -> tuple[int, int] | None:
    try:
        if not getattr(obj, "is_indirect", False):
            return None
        og = obj.objgen
        if isinstance(og, tuple) and len(og) == 2 and og != (0, 0):
            return (int(og[0]), int(og[1]))
    except Exception:
        return None
    return None


def _filter_names(stream: Any, pikepdf: Any) -> list[str] | None:
    try:
        flt = stream.get(pikepdf.Name.Filter)
    except Exception:
        return None
    if flt is None:
        return []
    if isinstance(flt, pikepdf.Array):
        return [str(f) for f in flt]
    return [str(flt)]


def _bounded_flate_check(raw: bytes, cap: int) -> bool:
    """Verify raw Flate stream decompresses cleanly within ``cap`` bytes (no flush())."""
    try:
        dobj = zlib.decompressobj()
        out = dobj.decompress(raw, cap + 1)
    except zlib.error:
        return False
    return not (len(out) > cap or dobj.unconsumed_tail or not dobj.eof)


def _validate_decode_parms(
    obj: Any, pikepdf: Any, *, h: int | None = None
) -> bool:
    """Unpack & validate ``/DecodeParms`` (dict, None, or 1-element array)."""
    try:
        dp = obj.get(pikepdf.Name.DecodeParms)
    except Exception:
        return False
    if dp is None:
        return True
    if isinstance(dp, pikepdf.Array):
        if len(dp) != 1:
            return False
        dp = dp[0]
        if dp is None:
            return True
    if not isinstance(dp, pikepdf.Dictionary):
        return False

    cols: int | None = None
    rows: int | None = None
    for key, lo, hi_lim in (
        ("/Columns", 1, qr_scan.MAX_QR_DIM),
        ("/Rows", 0, qr_scan.MAX_QR_DIM),
        ("/Colors", 1, 5),
    ):
        try:
            raw_v = dp.get(key)
        except Exception:
            return False
        if raw_v is None:
            continue
        try:
            iv = int(raw_v)
        except Exception:
            return False
        if not _is_strict_int(iv) or iv < lo or iv > hi_lim:
            return False
        if key == "/Columns":
            cols = iv
        elif key == "/Rows":
            rows = iv

    try:
        bpc_raw = dp.get("/BitsPerComponent")
    except Exception:
        return False
    if bpc_raw is not None:
        try:
            bpc = int(bpc_raw)
        except Exception:
            return False
        if not _is_strict_int(bpc) or bpc not in (1, 2, 4, 8, 16):
            return False

    if cols is not None:
        eff_h = max(rows or (h or 1), h or 1)
        if cols * eff_h > qr_scan.MAX_QR_PIXELS:
            return False
    return True


def _validate_aux_stream(stream: Any, pikepdf: Any) -> bool:
    """Strict guard for ``/ICCBased`` and ``/Indexed <lookup>`` streams (<= 4 MiB)."""
    if not isinstance(stream, pikepdf.Stream):
        return False
    try:
        if stream.get(pikepdf.Name.DecodeParms) is not None:
            return False
        names = _filter_names(stream, pikepdf)
        if names is None or len(names) > 1:
            return False
        if names and names[0] not in _AUX_STREAM_FILTERS:
            return False
        raw = stream.read_raw_bytes()
    except Exception:
        return False
    if len(raw) > MAX_PDF_QR_COLORSPACE_BYTES:
        return False
    if names == ["/FlateDecode"]:
        return _bounded_flate_check(raw, MAX_PDF_QR_COLORSPACE_BYTES)
    return True


def _validate_colorspace(
    cs: Any,
    pikepdf: Any,
    *,
    allow_none: bool,
    depth: int = 0,
) -> bool:
    """Recursive (max depth 1) strict whitelist for PDF ``/ColorSpace``."""
    if cs is None:
        return allow_none
    if isinstance(cs, pikepdf.Name):
        return str(cs) in _DEVICE_CS_NAMES
    if not isinstance(cs, pikepdf.Array) or len(cs) == 0:
        return False

    head = str(cs[0])
    if len(cs) == 1 and head in _DEVICE_CS_NAMES:
        return True
    if head in _STREAMLESS_ARRAY_CS:
        return True

    if head == "/ICCBased":
        if len(cs) != 2:
            return False
        icc_stream = cs[1]
        if not _validate_aux_stream(icc_stream, pikepdf):
            return False
        try:
            alt = icc_stream.get("/Alternate")
        except Exception:
            return False
        return alt is None or (
            isinstance(alt, pikepdf.Name) and str(alt) in _DEVICE_CS_NAMES
        )

    if head == "/Indexed":
        if depth >= 1 or len(cs) != 4:
            return False
        base_cs = cs[1]
        hival_raw = cs[2]
        lookup = cs[3]
        try:
            if isinstance(hival_raw, bool):
                return False
            hival = int(hival_raw)
        except Exception:
            return False
        if not _is_strict_int(hival) or hival < 0 or hival > 255:
            return False
        if not _validate_colorspace(base_cs, pikepdf, allow_none=False, depth=depth + 1):
            return False
        if isinstance(lookup, pikepdf.String):
            return len(bytes(lookup)) <= MAX_PDF_QR_COLORSPACE_BYTES
        if isinstance(lookup, pikepdf.Stream):
            return _validate_aux_stream(lookup, pikepdf)
        return False

    return False


def _has_pdf_inline_image(content: bytes) -> bool:
    """Linear O(N) PDF token scanner detecting ``BI ... ID`` inline images.

    Skips ``%...`` comments, ``/Name`` tokens (e.g. ``/BI``), and nested
    ``(...)`` literal strings (with backslash escapes); splits on whitespace
    AND PDF delimiters ``()<>[]{}/%`` so ``BI/W 20/H 20...ID`` is caught.
    """
    n = len(content)
    i = 0
    saw_bi = False
    while i < n:
        b = content[i]
        if b in _PDF_WS:
            i += 1
            continue
        if b == 0x25:  # '%' comment to EOL
            nl = content.find(b"\n", i + 1)
            cr = content.find(b"\r", i + 1)
            if nl == -1 and cr == -1:
                break
            if nl == -1:
                i = cr + 1
            elif cr == -1:
                i = nl + 1
            else:
                i = min(nl, cr) + 1
            continue
        if b == 0x28:  # '(' literal string (nested parens + backslash escapes)
            depth = 1
            i += 1
            while i < n and depth > 0:
                c = content[i]
                if c == 0x5C:  # '\\'
                    i += 2
                    continue
                if c == 0x28:
                    depth += 1
                elif c == 0x29:
                    depth -= 1
                i += 1
            continue
        if b == 0x2F:  # '/Name' token — skip whole name so '/BI' never matches
            i += 1
            while i < n and content[i] not in _PDF_WS and content[i] not in _PDF_DELIMS:
                i += 1
            continue
        if b in _PDF_DELIMS:
            i += 1
            continue
        start = i
        while i < n and content[i] not in _PDF_WS and content[i] not in _PDF_DELIMS:
            i += 1
        tok = content[start:i]
        if tok == b"BI":
            saw_bi = True
        elif tok == b"ID" and saw_bi:
            return True
    return False


@dataclass
class _PdfQrState:
    outcome: qr_scan.QrScanOutcome = field(default_factory=qr_scan.QrScanOutcome)
    scanned_images: int = 0
    failed_images: int = 0
    skipped_tiny: int = 0
    raw_bytes_used: int = 0
    total_pixels: int = 0
    form_visits: int = 0
    content_bytes_used: int = 0
    engine_missing_shortcircuit: bool = False
    active_forms: set[tuple[int, int]] = field(default_factory=set)
    visited_form_min_depth: dict[tuple[int, int], int] = field(default_factory=dict)
    image_guard_ok: dict[tuple[tuple[int, int], bool], bool] = field(default_factory=dict)


def _check_stream_inline_images(
    stream: Any, pikepdf: Any, state: _PdfQrState
) -> None:
    if state.content_bytes_used >= MAX_PDF_QR_CONTENT_BYTES:
        state.outcome.add_incomplete(
            "PDF-Content-Stream-Budget für Inline-Bild-Prüfung erreicht"
        )
        return
    remaining = MAX_PDF_QR_CONTENT_BYTES - state.content_bytes_used
    data, err = read_stream_bounded(stream, pikepdf, max_stream_bytes=remaining)
    if err is not None or data is None:
        state.outcome.add_incomplete(
            f"PDF-Content-Stream für QR-Inline-Bild-Prüfung nicht vollständig lesbar ({err or 'Fehler'})"
        )
        state.content_bytes_used = MAX_PDF_QR_CONTENT_BYTES
        return
    state.content_bytes_used += len(data)
    if _has_pdf_inline_image(data):
        state.outcome.add_incomplete(
            "PDF enthält Inline-Bilder (BI/ID), die nicht auf QR-Codes geprüft wurden"
        )


def _check_filter_whitelist(names: list[str], raw: bytes, w: int, h: int) -> str | None:
    """Validate PDF image filter chain against the strict single-filter whitelist."""
    if len(names) > 1:
        return f"Mehrstufige PDF-Bildfilterkette abgelehnt ({','.join(names[:3])})"
    if names == ["/FlateDecode"]:
        cap = min(MAX_PDF_QR_DECODED_BYTES, (w * h * 8) + h + 65_536)
        if not _bounded_flate_check(raw, cap):
            return "PDF-Flate-Bildstream überschreitet Dekompressionslimit"
        return None
    if names == ["/CCITTFaxDecode"]:
        if ((w + 7) // 8) * h > MAX_PDF_QR_DECODED_BYTES:
            return "PDF-CCITT-Bildstream überschreitet Dekompressionslimit"
        return None
    if names == ["/RunLengthDecode"]:
        if len(raw) * 128 > MAX_PDF_QR_DECODED_BYTES:
            return "PDF-RunLength-Bildstream überschreitet Dekompressionslimit"
        return None
    if names in ([], ["/ASCIIHexDecode"], ["/ASCII85Decode"]):
        if len(raw) > MAX_PDF_QR_DECODED_BYTES:
            return "PDF-Bildstream überschreitet Dekompressionslimit"
        return None
    return f"Nicht unterstützter PDF-Bildfilter ({names[0]})"


def _scan_image_xobject(
    xobj: Any,
    pikepdf: Any,
    state: _PdfQrState,
    *,
    source_label: str,
    is_mask: bool = False,
) -> bool:
    """Validate and scan one PDF ``/Image`` stream. Returns True iff guard passed."""
    if state.engine_missing_shortcircuit:
        return False

    # Step 1: Hard mask depth 1 BEFORE any cache lookup (ISO 32000-1 Table 89).
    if is_mask:
        try:
            if xobj.get("/SMask") is not None or xobj.get("/Mask") is not None:
                state.failed_images += 1
                state.outcome.add_incomplete(
                    "Verschachtelte PDF-/SMask-/Mask-Referenz abgelehnt"
                )
                return False
        except Exception:
            state.failed_images += 1
            state.outcome.add_incomplete("PDF-Masken-Header nicht lesbar")
            return False

    # Step 2: Mode-separated guard cache lookup BEFORE counters or read_raw_bytes().
    og = _objgen_key(xobj)
    if og is not None:
        cached = state.image_guard_ok.get((og, is_mask))
        if cached is not None:
            return cached

    def _fail(reason: str) -> bool:
        state.failed_images += 1
        state.outcome.add_incomplete(reason)
        if og is not None:
            state.image_guard_ok[(og, is_mask)] = False
        return False

    # Step 3: Counters & raw stream read (wrapped in try/except).
    if state.scanned_images >= MAX_PDF_QR_IMAGES:
        state.outcome.add_incomplete("PDF überschreitet maximales Bild-Prüfbudget")
        return False
    if state.failed_images >= MAX_PDF_QR_FAILED_IMAGES:
        state.outcome.add_incomplete("PDF überschreitet Fehler-Budget für eingebettete Bilder")
        return False
    if state.skipped_tiny >= MAX_PDF_QR_SKIPPED_TINY:
        state.outcome.add_incomplete("PDF überschreitet Limit für übersprungene Kleinstbilder")
        return False
    if state.total_pixels >= MAX_PDF_QR_TOTAL_PIXELS:
        state.outcome.add_incomplete("PDF überschreitet kumulatives Pixel-Prüfbudget")
        return False

    try:
        names = _filter_names(xobj, pikepdf)
        if names is None:
            return _fail("PDF-Bildfilter nicht lesbar")
        raw = xobj.read_raw_bytes()
    except Exception as exc:
        return _fail(f"PDF-Bildstream nicht lesbar ({type(exc).__name__})")

    if len(raw) > qr_scan.MAX_QR_FILE_BYTES or (
        state.raw_bytes_used + len(raw) > MAX_PDF_QR_RAW_BYTES
    ):
        return _fail("PDF-Bildstream überschreitet Rohbyte-Budget")
    state.raw_bytes_used += len(raw)

    # Helper to pre-validate & scan attached /SMask and /Mask on base images.
    def _validate_attached_masks() -> bool:
        if is_mask:
            return True
        for mkey, mtag in (("/SMask", "smask"), ("/Mask", "mask")):
            try:
                mobj = xobj.get(mkey)
            except Exception:
                return _fail(f"PDF-{mkey} nicht lesbar")
            if mobj is None:
                continue
            if isinstance(mobj, pikepdf.Stream):
                ok_mask = _scan_image_xobject(
                    mobj,
                    pikepdf,
                    state,
                    source_label=f"{source_label}:{mtag}",
                    is_mask=True,
                )
                if not ok_mask:
                    return False
            elif mkey == "/Mask" and isinstance(mobj, pikepdf.Array):
                # Color-key mask array of ints (no stream).
                if not all(_is_strict_int(int(v)) for v in mobj if not isinstance(v, bool)):
                    return _fail("Ungültiges PDF-/Mask-Array")
            else:
                return _fail(f"Unerwarteter Typ für PDF-{mkey}")
        return True

    # Special safe path for single /DCTDecode or /JPXDecode (defeats forged small /Width).
    if names in (["/DCTDecode"], ["/JPXDecode"]):
        if is_mask:
            if not _validate_decode_parms(xobj, pikepdf, h=None):
                return _fail("PDF-Masken-/DecodeParms abgelehnt")
            try:
                cs = xobj.get(pikepdf.Name.ColorSpace)
            except Exception:
                return _fail("PDF-Masken-/ColorSpace nicht lesbar")
            if not _validate_colorspace(cs, pikepdf, allow_none=True):
                return _fail("PDF-Masken-/ColorSpace abgelehnt")

        if not qr_scan.qr_engine_available():
            state.engine_missing_shortcircuit = True
            return _fail(qr_scan._ENGINE_MISSING_REASON)

        rem_px = MAX_PDF_QR_TOTAL_PIXELS - state.total_pixels
        if rem_px <= 0:
            return _fail("PDF überschreitet kumulatives Pixel-Prüfbudget")

        sub = qr_scan.scan_image_bytes(
            raw,
            source_label=source_label,
            max_pixels=min(qr_scan.MAX_QR_PIXELS, rem_px),
        )
        state.outcome.merge(sub)
        state.total_pixels += sub.decoded_pixels
        if sub.scanned_images > 0:
            state.scanned_images += 1
        elif sub.incomplete_reasons:
            state.failed_images += 1
        else:
            state.skipped_tiny += 1

        ok_self = not sub.incomplete_reasons
        if og is not None:
            state.image_guard_ok[(og, is_mask)] = ok_self
        if not is_mask:
            _validate_attached_masks()
        return ok_self

    # All other filters: validate /Width & /Height first.
    try:
        w_raw = xobj.get(pikepdf.Name.Width)
        h_raw = xobj.get(pikepdf.Name.Height)
        if w_raw is None or h_raw is None or isinstance(w_raw, bool) or isinstance(h_raw, bool):
            return _fail("PDF-Bild ohne gültige Dimensionen")
        w, h = int(w_raw), int(h_raw)
    except Exception:
        return _fail("PDF-Bilddimensionen nicht lesbar")

    if w <= 0 or h <= 0:
        return _fail("PDF-Bild mit ungültiger Breite/Höhe")
    if w > qr_scan.MAX_QR_DIM or h > qr_scan.MAX_QR_DIM or (w * h) > qr_scan.MAX_QR_PIXELS:
        return _fail("PDF-Bild überschreitet Pixel-/Dimensionslimit")
    if state.total_pixels + (w * h) > MAX_PDF_QR_TOTAL_PIXELS:
        return _fail("PDF überschreitet kumulatives Pixel-Prüfbudget")

    # Tiny non-mask base image: skip base decode, STILL inspect attached /SMask or /Mask
    # (ISO 32000-1 §11.6.5.3 allows 1x1 solid base image with high-res QR /SMask!),
    # and NEVER poison image_guard_ok[(og, False)] = True.
    if not is_mask and (w < qr_scan.MIN_QR_DIM or h < qr_scan.MIN_QR_DIM):
        state.skipped_tiny += 1
        _validate_attached_masks()
        return True

    # Strict /DecodeParms, /ColorSpace, and single-filter whitelist (always run for masks!).
    if not _validate_decode_parms(xobj, pikepdf, h=h):
        return _fail("PDF-Bild-/DecodeParms abgelehnt")

    try:
        is_image_mask = bool(xobj.get("/ImageMask", False))
        cs = xobj.get(pikepdf.Name.ColorSpace)
    except Exception:
        return _fail("PDF-Bild-/ColorSpace nicht lesbar")

    if not _validate_colorspace(cs, pikepdf, allow_none=(is_image_mask or is_mask)):
        return _fail("PDF-Bild-/ColorSpace nicht unterstützt oder abgelehnt")

    # Strict single-filter whitelist (reject multi-filter chains, JBIG2, LZW, unknown).
    filter_err = _check_filter_whitelist(names, raw, w, h)
    if filter_err is not None:
        return _fail(filter_err)

    # Pre-validate attached /SMask & /Mask BEFORE calling as_pil_image() on base image.
    if not _validate_attached_masks():
        if og is not None:
            state.image_guard_ok[(og, is_mask)] = False
        return False

    # Tiny mask passed all bomb guards — safe for base image, skip zxing on tiny mask itself.
    if is_mask and (w < qr_scan.MIN_QR_DIM or h < qr_scan.MIN_QR_DIM):
        if og is not None:
            state.image_guard_ok[(og, True)] = True
        return True

    if not qr_scan.qr_engine_available():
        state.engine_missing_shortcircuit = True
        return _fail(qr_scan._ENGINE_MISSING_REASON)

    try:
        pdf_img = pikepdf.PdfImage(xobj)
        pil_img = pdf_img.as_pil_image()
    except Exception as exc:
        return _fail(f"PDF-Bild nicht dekodierbar ({type(exc).__name__})")

    try:
        sub = qr_scan.scan_pil_image(pil_img, source_label=source_label)
    finally:
        with contextlib.suppress(Exception):
            pil_img.close()

    state.outcome.merge(sub)
    state.total_pixels += w * h
    if sub.scanned_images > 0:
        state.scanned_images += 1
    elif sub.incomplete_reasons:
        state.failed_images += 1
    ok_res = not sub.incomplete_reasons
    if og is not None:
        state.image_guard_ok[(og, is_mask)] = ok_res
    return ok_res


def _walk_resources(
    resources: Any,
    pikepdf: Any,
    state: _PdfQrState,
    *,
    page_label: str,
    depth: int,
) -> None:
    if not isinstance(resources, pikepdf.Dictionary) or state.engine_missing_shortcircuit:
        return

    # 1. /XObject (/Image and /Form)
    try:
        xobjs = resources.get(pikepdf.Name.XObject)
    except Exception:
        xobjs = None
    if isinstance(xobjs, pikepdf.Dictionary):
        for key in list(xobjs.keys()):
            if state.engine_missing_shortcircuit:
                return
            try:
                obj = xobjs[key]
            except Exception:
                state.outcome.add_incomplete("PDF-XObject nicht lesbar")
                continue
            if not isinstance(obj, pikepdf.Stream):
                continue
            try:
                subtype = str(obj.get(pikepdf.Name.Subtype) or "")
            except Exception:
                continue
            if subtype == "/Image":
                _scan_image_xobject(obj, pikepdf, state, source_label=page_label)
            elif subtype == "/Form":
                _walk_form_stream(obj, pikepdf, state, page_label=page_label, depth=depth)

    # 2. /Pattern (/PatternType == 1 tiling patterns)
    try:
        patterns = resources.get("/Pattern")
    except Exception:
        patterns = None
    if isinstance(patterns, pikepdf.Dictionary):
        for key in list(patterns.keys()):
            if state.engine_missing_shortcircuit:
                return
            try:
                pat = patterns[key]
            except Exception:
                continue
            if not isinstance(pat, pikepdf.Stream):
                continue
            try:
                ptype = pat.get("/PatternType")
            except Exception:
                continue
            if ptype == 1:
                _walk_form_stream(pat, pikepdf, state, page_label=page_label, depth=depth)


def _walk_form_stream(
    form_obj: Any,
    pikepdf: Any,
    state: _PdfQrState,
    *,
    page_label: str,
    depth: int,
) -> None:
    if state.engine_missing_shortcircuit:
        return
    if depth >= MAX_PDF_FORM_DEPTH:
        state.outcome.add_incomplete("PDF-Form-XObject-Rekursionstiefe erreicht")
        return

    og = _objgen_key(form_obj)
    if og is not None:
        if og in state.active_forms:
            state.outcome.add_incomplete("Zyklische PDF-Form-XObject-Referenz erkannt")
            return
        if state.visited_form_min_depth.get(og, 999) <= depth:
            return

    if state.form_visits >= MAX_PDF_QR_FORMS:
        state.outcome.add_incomplete("PDF überschreitet Form-XObject-Limit")
        return
    state.form_visits += 1

    if og is not None:
        state.visited_form_min_depth[og] = depth
        state.active_forms.add(og)

    try:
        _check_stream_inline_images(form_obj, pikepdf, state)
        try:
            res = form_obj.get(pikepdf.Name.Resources)
        except Exception:
            res = None
        if res is not None:
            _walk_resources(res, pikepdf, state, page_label=page_label, depth=depth + 1)
    finally:
        if og is not None:
            state.active_forms.discard(og)


def _collect_inherited_resources(page_obj: Any, pikepdf: Any) -> list[Any]:
    """Collect page ``/Resources`` plus inherited ``/Pages /Resources`` (ISO 32000-1 §7.7.3.4)."""
    found: list[Any] = []
    seen_nodes: set[tuple[int, int]] = set()
    cur = page_obj
    for _ in range(16):
        if not isinstance(cur, pikepdf.Dictionary):
            break
        og = _objgen_key(cur)
        if og is not None:
            if og in seen_nodes:
                break
            seen_nodes.add(og)
        try:
            res = cur.get(pikepdf.Name.Resources)
        except Exception:
            res = None
        if isinstance(res, pikepdf.Dictionary):
            found.append(res)
        try:
            cur = cur.get(pikepdf.Name.Parent)
        except Exception:
            break
    return found


def _walk_page_annots(
    page_obj: Any, pikepdf: Any, state: _PdfQrState, *, page_label: str
) -> None:
    try:
        annots = page_obj.get(pikepdf.Name.Annots)
    except Exception:
        return
    if not isinstance(annots, pikepdf.Array):
        return
    if len(annots) > MAX_PDF_QR_ANNOTS_PER_PAGE:
        state.outcome.add_incomplete("PDF-Seite überschreitet Annotations-Limit")
    for annot in list(annots)[:MAX_PDF_QR_ANNOTS_PER_PAGE]:
        if state.engine_missing_shortcircuit:
            return
        if not isinstance(annot, pikepdf.Dictionary):
            continue
        try:
            ap = annot.get("/AP")
        except Exception:
            continue
        if not isinstance(ap, pikepdf.Dictionary):
            continue
        for ap_key in ("/N", "/R", "/D"):
            try:
                entry = ap.get(ap_key)
            except Exception:
                continue
            if isinstance(entry, pikepdf.Stream):
                _walk_form_stream(entry, pikepdf, state, page_label=page_label, depth=0)
            elif isinstance(entry, pikepdf.Dictionary):
                for sub_key in list(entry.keys())[:32]:
                    try:
                        sub_stream = entry[sub_key]
                    except Exception:
                        continue
                    if isinstance(sub_stream, pikepdf.Stream):
                        _walk_form_stream(
                            sub_stream, pikepdf, state, page_label=page_label, depth=0
                        )


def scan_pdf_qr(pdf: Any) -> list[Indicator]:
    """Scan embedded raster images in ``pdf`` for QR / MicroQR codes."""
    import pikepdf

    state = _PdfQrState()
    try:
        pages = list(pdf.pages)
    except Exception as exc:
        state.outcome.add_incomplete(f"PDF-Seitenbaum für QR-Scan nicht lesbar ({type(exc).__name__})")
        return qr_scan.build_qr_indicators("pdf", state.outcome)

    if len(pages) > MAX_PDF_QR_PAGES:
        state.outcome.add_incomplete(
            f"PDF hat mehr als {MAX_PDF_QR_PAGES} Seiten "
            f"(QR-Prüfung auf erste {MAX_PDF_QR_PAGES} Seiten begrenzt)"
        )

    for page_idx, page in enumerate(pages[:MAX_PDF_QR_PAGES], 1):
        if state.engine_missing_shortcircuit:
            break
        page_label = f"pdf:p{page_idx}"
        page_obj = page.obj

        # 1. Check page /Contents (single Stream or Array of Streams) for BI/ID inline images.
        try:
            contents = page_obj.get(pikepdf.Name.Contents)
        except Exception:
            contents = None
        if isinstance(contents, pikepdf.Stream):
            _check_stream_inline_images(contents, pikepdf, state)
        elif isinstance(contents, pikepdf.Array):
            for stream in contents:
                if isinstance(stream, pikepdf.Stream):
                    _check_stream_inline_images(stream, pikepdf, state)

        # 2. Walk page & inherited /Resources (/XObject and /Pattern).
        for res_dict in _collect_inherited_resources(page_obj, pikepdf):
            _walk_resources(res_dict, pikepdf, state, page_label=page_label, depth=0)

        # 3. Walk /Annots[*]/AP/{N,R,D}.
        _walk_page_annots(page_obj, pikepdf, state, page_label=page_label)

    return qr_scan.build_qr_indicators("pdf", state.outcome)
