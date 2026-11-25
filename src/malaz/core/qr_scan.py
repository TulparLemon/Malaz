"""Offline static QR-code & MicroQR decoding and Quishing analysis (Spec 015).

Layer 2 module (no GUI/worker/PySide6 imports, strictly offline by default).
Reuses ``core.eml_parser.classify_url`` / ``DANGEROUS_URI_SCHEMES``,
``core.binary_iocs.split_blocked_iocs``, ``core.url_reputation.lookup``, and
``core.url_view.defang_url`` without duplicating URL or blocklist logic.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import math
import re
import urllib.parse
import warnings
from dataclasses import dataclass, field
from typing import Any

from .. import config
from ..models import (
    CAT_CONTENT,
    CAT_IOC,
    CAT_SCRIPT,
    Indicator,
    Severity,
)
from .binary_iocs import (
    BLOCKLIST_UNAVAILABLE_TITLE,
    IOC_IPV4,
    IOC_IPV6,
    IOC_URL,
    split_blocked_iocs,
)
from .eml_parser import (
    DANGEROUS_URI_SCHEMES,
    LinkFacts,
    classify_url,
)
from .url_reputation import lookup as url_reputation_lookup
from .url_reputation import url_hash
from .url_view import defang_url

# --------------------------------------------------------------------------- #
# Hard security & DoS bounds (Spec 015 §5.1)
# --------------------------------------------------------------------------- #

MAX_QR_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB compressed raster image
MAX_QR_PIXELS = 16_000_000            # 16 MP per frame (checked before load())
MAX_QR_DIM = 8_192                    # max width or height per frame
MIN_QR_DIM = 11                       # MicroQR M1 minimum (11x11 modules)
MAX_QR_FRAMES = 4                     # animated GIF / WebP / APNG / multi-page TIFF
MAX_QR_CODES_PER_IMAGE = 16           # max decoded QR codes per image
MAX_QR_PAYLOAD_CHARS = 2_048          # max decoded payload length

MAX_QR_DATA_URI_IMAGES = 16
MAX_QR_DATA_URI_TOTAL_BYTES = 16 * 1024 * 1024
MAX_QR_DATA_URI_SKIPPED_TINY = 256
MAX_QR_DATA_URI_FAILED = 64

_HEIC_INCOMPLETE_REASON = "HEIC/AVIF-Bildformat ohne gebündelten Pixel-Decoder"
_ENGINE_MISSING_REASON = "QR-Code-Engine (zxing-cpp) nicht verfügbar"
QR_INCOMPLETE_TITLE = "QR-Code-Prüfung unvollständig"

# Linear O(N) regexes (verified in tests/test_regex_safety.py).
_DATA_URI_IMG_RE = re.compile(
    r"data:image/((?:x-)?png|p?jpe?g|gif|bmp|webp|tiff|heic|avif)"
    r"(?:;[a-z0-9._=-]{1,40}){0,4};base64,([A-Za-z0-9+/=%\r\n\t ]{32,})",
    re.IGNORECASE,
)
_ASCII_WS_RE = re.compile(r"[ \t\r\n]+")
_EMBEDDED_HTTP_RE = re.compile(
    r"https?://(?:\[[0-9A-Fa-f:.]+\][^\s<>\"'\)\]\}]*|[^\s<>\"'\)\]\}]+)",
    re.IGNORECASE,
)
_SCHEME_PREFIX_RE = re.compile(r"^([a-z][a-z0-9+.-]{1,24}):(.*)$", re.IGNORECASE | re.DOTALL)
_DATA_DANGEROUS_PREFIX_RE = re.compile(
    r"^data:(?:text/html|application/|image/svg\+xml)",
    re.IGNORECASE,
)
_EMBEDDED_DANGEROUS_RE = re.compile(
    r"""(?:^|[\s"'<(\[;:])("""
    r"""(?:javascript|vbscript):[ \t]*\S[^\s"'<>)\]]{0,256}|"""
    r"""file:[\\/][^\s"'<>)\]]{0,256}|"""
    r"""data:(?:text/html|application/|image/svg\+xml)[^\s"'<>)\]]{0,256}|"""
    r"""(?:jar|ms-msdt|search-ms|ms-officecmd|smb|mhtml|cmd|powershell):\S[^\s"'<>)\]]{0,256}|"""
    r"""\\\\[A-Za-z0-9._-]{1,128}\\[^\s"'<>)\]]{1,256}"""
    r""")""",
    re.IGNORECASE,
)

# Pre-redaction delete vs space-replace tables (Spec 015 §6.3).
_DELETE_CHARS = (
    "".join(chr(c) for c in range(0x09))
    + "\x0b\x0c"
    + "".join(chr(c) for c in range(0x0E, 0x20))
    + "".join(chr(c) for c in range(0x7F, 0xA0))
    + "\ufeff\u061c"
    + "".join(chr(c) for c in range(0x200B, 0x2010))
    + "".join(chr(c) for c in range(0x202A, 0x202F))
    + "".join(chr(c) for c in range(0x2066, 0x206A))
)
_PRE_REDACT_TABLE = str.maketrans(
    {"\r": " ", "\n": " ", "\t": " ", **{c: "" for c in _DELETE_CHARS}}
)
_BORDER_STRIP_CHARS = " \t\r\n" + _DELETE_CHARS

_OTPAUTH_SECRET_RE = re.compile(
    r"(otpauth://[^\s]{0,512}?[?&]secret=)([^&#\s]+)",
    re.IGNORECASE,
)
_OTPAUTH_MIG_RE = re.compile(
    r"(otpauth-migration://[^\s]{0,512}?[?&]data=)([^&#\s]+)",
    re.IGNORECASE,
)
_URL_USERINFO_PASS_RE = re.compile(
    r"((?:[a-z][a-z0-9+.-]{1,24}:)?//[^/\s:@?#]{0,128}:)([^/\s@?#]+)(@)",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_RE = re.compile(
    r"([?&#](?:token|access_token|id_token|refresh_token|code|secret|password|"
    r"passwd|pwd|api_key|apikey|key|sig|signature|auth|session|jwt)=)([^&#\s]+)",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class QrHit:
    payload: str
    barcode_format: str
    source_label: str
    truncated: bool = False


@dataclass
class QrScanOutcome:
    hits: list[QrHit] = field(default_factory=list)
    incomplete_reasons: list[str] = field(default_factory=list)
    scanned_images: int = 0
    decoded_pixels: int = 0

    def add_hit(self, hit: QrHit) -> None:
        key = (hit.payload, hit.barcode_format)
        if not any((h.payload, h.barcode_format) == key for h in self.hits):
            self.hits.append(hit)

    def add_incomplete(self, reason: str) -> None:
        if reason and reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def merge(self, other: QrScanOutcome) -> None:
        for hit in other.hits:
            self.add_hit(hit)
        for reason in other.incomplete_reasons:
            self.add_incomplete(reason)
        self.scanned_images += other.scanned_images
        self.decoded_pixels += other.decoded_pixels


@dataclass
class DataUriBudget:
    scanned_images: int = 0
    total_bytes: int = 0
    skipped_tiny: int = 0
    failed_images: int = 0
    seen_hashes: set[str] = field(default_factory=set)
    max_images: int = MAX_QR_DATA_URI_IMAGES
    max_total_bytes: int = MAX_QR_DATA_URI_TOTAL_BYTES
    max_skipped_tiny: int = MAX_QR_DATA_URI_SKIPPED_TINY
    max_failed: int = MAX_QR_DATA_URI_FAILED


# --------------------------------------------------------------------------- #
# Engine loading & pure-Pillow normalization
# --------------------------------------------------------------------------- #


def _load_zxing() -> Any | None:
    """Import ``zxingcpp`` without mutable caching (test/monkeypatch friendly)."""
    try:
        import zxingcpp  # type: ignore[import-not-found]
    except Exception:
        return None
    return zxingcpp


def qr_engine_available() -> bool:
    """Return True when the offline ``zxing-cpp`` decoder is importable."""
    return _load_zxing() is not None


def _normalize_to_l(frame: Any) -> Any:
    """Convert any PIL image mode safely to 8-bit grayscale ``'L'`` (no numpy).

    - Transparent modes (``RGBA``, ``LA``, ``PA``, or ``P``/``RGB``/``L`` with
      ``transparency`` info) are alpha-composited onto solid white; if contrast
      is near-flat (``hi - lo < 16``, e.g. white QR modules on transparency),
      falls back to compositing onto solid black.
    - 16-bit / integer / float modes (``I*``, ``F``) convert two-step via ``I``
      to ``F`` and apply an unclamped affine ``Image.point`` scale before
      C-clamped ``.convert('L')``.
    """
    from PIL import Image

    mode = str(getattr(frame, "mode", ""))
    info = getattr(frame, "info", None) or {}
    if mode in ("RGBA", "LA", "PA") or (
        mode in ("P", "RGB", "L") and "transparency" in info
    ):
        rgba = frame.convert("RGBA")
        white_bg = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
        gray = Image.alpha_composite(white_bg, rgba).convert("L")
        lo, hi = gray.getextrema()
        if isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and (hi - lo) < 16:
            black_bg = Image.new("RGBA", rgba.size, (0, 0, 0, 255))
            gray = Image.alpha_composite(black_bg, rgba).convert("L")
        return gray

    if mode == "F" or mode.startswith("I"):
        if mode == "F":
            f_img = frame
        elif mode == "I":
            f_img = frame.convert("F")
        else:
            # Pillow does not support direct I;16* -> F conversion.
            f_img = frame.convert("I").convert("F")
        lo_f, hi_f = f_img.getextrema()
        if (
            not isinstance(lo_f, (int, float))
            or not isinstance(hi_f, (int, float))
            or not (math.isfinite(lo_f) and math.isfinite(hi_f) and hi_f > lo_f)
        ):
            return Image.new("L", f_img.size, 0)
        span = hi_f - lo_f
        if not math.isfinite(span) or span <= 0:
            return Image.new("L", f_img.size, 0)
        scale = 255.0 / span
        if not math.isfinite(scale):
            return Image.new("L", f_img.size, 0)
        return f_img.point(lambda v: (v - lo_f) * scale).convert("L")

    return frame.convert("L")


def _format_name(raw_fmt: Any) -> str:
    txt = str(raw_fmt or "").strip()
    low = txt.lower().replace(" ", "").replace("_", "")
    if "microqr" in low:
        return "MicroQRCode"
    return "QRCode"


# --------------------------------------------------------------------------- #
# Image & Data-URI scanning
# --------------------------------------------------------------------------- #


def scan_pil_image(
    img: Any,
    *,
    source_label: str = "image",
    max_pixels: int = MAX_QR_PIXELS,
) -> QrScanOutcome:
    """Scan a PIL Image (up to ``MAX_QR_FRAMES`` frames) for QR / MicroQR codes."""
    from PIL import Image

    outcome = QrScanOutcome()
    is_tiff = str(getattr(img, "format", "") or "").upper() == "TIFF"
    eof_reached = False
    aborted = False
    zxing: Any = None

    for idx in range(MAX_QR_FRAMES):
        if idx > 0:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", Image.DecompressionBombWarning)
                    img.seek(idx)
            except EOFError:
                eof_reached = True
                break
            except Exception as exc:
                outcome.add_incomplete(
                    f"Bild-Frame {idx + 1} nicht lesbar ({type(exc).__name__})"
                )
                aborted = True
                break

        try:
            w, h = img.size
        except Exception as exc:
            outcome.add_incomplete(f"Bilddimensionen nicht lesbar ({type(exc).__name__})")
            aborted = True
            break

        if w < MIN_QR_DIM or h < MIN_QR_DIM:
            continue
        if w > MAX_QR_DIM or h > MAX_QR_DIM or (w * h) > max_pixels:
            outcome.add_incomplete("Bild überschreitet Pixel-/Dimensionslimit")
            if is_tiff:
                continue
            aborted = True
            break

        if zxing is None:
            zxing = _load_zxing()
            if zxing is None:
                outcome.add_incomplete(_ENGINE_MISSING_REASON)
                return outcome

        try:
            img.load()
            gray = _normalize_to_l(img)
            formats = (
                zxing.BarcodeFormat.QRCode,
                zxing.BarcodeFormat.MicroQRCode,
            )
            raw_results = zxing.read_barcodes(
                gray,
                formats=formats,
                try_rotate=True,
                try_invert=True,
                try_downscale=True,
            )
        except Exception as exc:
            outcome.add_incomplete(
                f"QR-Dekodierung fehlgeschlagen ({type(exc).__name__})"
            )
            aborted = True
            break

        # Account frame ONLY after successful decode/normalization.
        outcome.scanned_images += 1
        outcome.decoded_pixels += w * h

        valid = [r for r in (raw_results or ()) if getattr(r, "valid", True)]
        if len(valid) > MAX_QR_CODES_PER_IMAGE:
            outcome.add_incomplete("Maximale Anzahl QR-Codes pro Bild überschritten")
            valid = valid[:MAX_QR_CODES_PER_IMAGE]

        for r in valid:
            text = str(getattr(r, "text", "") or "")
            if not text:
                continue
            truncated = False
            if len(text) > MAX_QR_PAYLOAD_CHARS:
                text = text[:MAX_QR_PAYLOAD_CHARS]
                truncated = True
                outcome.add_incomplete("QR-Code-Payload übersteigt Zeichenlimit")
            outcome.add_hit(
                QrHit(
                    payload=text,
                    barcode_format=_format_name(getattr(r, "format", "")),
                    source_label=source_label,
                    truncated=truncated,
                )
            )

    if not eof_reached and not aborted:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", Image.DecompressionBombWarning)
                img.seek(MAX_QR_FRAMES)
        except EOFError:
            pass
        except Exception as exc:
            outcome.add_incomplete(
                f"Weitere Bild-Frames nicht lesbar ({type(exc).__name__})"
            )
        else:
            outcome.add_incomplete("Bild enthält mehr Frames als das Prüfbudget")

    return outcome


def scan_image_bytes(
    data: bytes,
    *,
    detected_type: str = "",
    source_label: str = "image",
    max_pixels: int = MAX_QR_PIXELS,
) -> QrScanOutcome:
    """Decode raster image bytes with bomb protection and scan for QR codes."""
    outcome = QrScanOutcome()
    if detected_type in ("heic", "avif"):
        outcome.add_incomplete(_HEIC_INCOMPLETE_REASON)
        return outcome
    if not data:
        return outcome
    if len(data) > MAX_QR_FILE_BYTES:
        outcome.add_incomplete(
            f"Bild übersteigt Rohgrößenlimit ({MAX_QR_FILE_BYTES // (1024 * 1024)} MiB)"
        )
        return outcome
    try:
        from PIL import Image
    except Exception:
        outcome.add_incomplete("Pillow nicht verfügbar für QR-Bildprüfung")
        return outcome

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                return scan_pil_image(
                    img,
                    source_label=source_label,
                    max_pixels=max_pixels,
                )
    except Image.DecompressionBombError:
        outcome.add_incomplete("Bild überschreitet Pixel-/Dimensionslimit")
        return outcome
    except Exception as exc:
        outcome.add_incomplete(
            f"Bild für QR-Prüfung nicht lesbar ({type(exc).__name__})"
        )
        return outcome


def _trim_data_uri_b64(text: str, match: re.Match[str]) -> str:
    """Respect unquoted HTML attribute boundaries and trailing padding cleanly."""
    raw_b64 = match.group(2)
    i = match.start() - 1
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    quoted = i >= 0 and text[i] in ('"', "'")

    if not quoted:
        ws = _ASCII_WS_RE.search(raw_b64)
        if ws is not None:
            raw_b64 = raw_b64[: ws.start()]

    if "%" in raw_b64:
        raw_b64 = urllib.parse.unquote(raw_b64)

    clean = _ASCII_WS_RE.sub("", raw_b64)
    if quoted and "=" in clean:
        eq = clean.find("=")
        pad_end = eq
        while pad_end < len(clean) and clean[pad_end] == "=":
            pad_end += 1
        if pad_end < len(clean) and pad_end % 4 == 0:
            clean = clean[:pad_end]
    return clean


def scan_data_uri_images(
    text: str,
    *,
    budget: DataUriBudget | None = None,
    input_truncated: bool = False,
) -> QrScanOutcome:
    """Scan inline ``data:image/...;base64,...`` raster images linearly (no SVG)."""
    outcome = QrScanOutcome()
    if input_truncated:
        outcome.add_incomplete("HTML-Eingabe wurde am Leselimit gekürzt")
    if not text or "data:image/" not in text.lower():
        return outcome

    b = budget if budget is not None else DataUriBudget()

    for m in _DATA_URI_IMG_RE.finditer(text):
        if (
            b.scanned_images >= b.max_images
            or b.failed_images >= b.max_failed
            or b.skipped_tiny >= b.max_skipped_tiny
            or b.total_bytes >= b.max_total_bytes
        ):
            outcome.add_incomplete("Data-URI-Bildbudget überschritten")
            break

        subtype = m.group(1).lower()
        if subtype in ("heic", "avif"):
            b.failed_images += 1
            outcome.add_incomplete(_HEIC_INCOMPLETE_REASON)
            continue

        clean = _trim_data_uri_b64(text, m)
        if len(clean) < 32:
            continue

        digest = hashlib.sha256(clean.encode("utf-8", "replace")).hexdigest()[:32]
        if digest in b.seen_hashes:
            continue
        b.seen_hashes.add(digest)

        est_bytes = (len(clean) * 3) // 4
        remaining_bytes = b.max_total_bytes - b.total_bytes
        if est_bytes > MAX_QR_FILE_BYTES or est_bytes > remaining_bytes:
            b.failed_images += 1
            outcome.add_incomplete("Data-URI-Bild übersteigt Byte-Budget")
            continue

        rem = len(clean) % 4
        if rem == 1:
            b.failed_images += 1
            outcome.add_incomplete("Ungültige Base64-Bilddaten in Data-URI")
            continue
        padded = clean if rem == 0 else clean + ("=" * (4 - rem))

        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            b.failed_images += 1
            outcome.add_incomplete("Ungültige Base64-Bilddaten in Data-URI")
            continue

        b.total_bytes += len(raw)
        sub = scan_image_bytes(raw, source_label="data-uri")
        outcome.merge(sub)
        if sub.scanned_images > 0:
            b.scanned_images += 1
        elif sub.incomplete_reasons:
            b.failed_images += 1
        else:
            b.skipped_tiny += 1

    return outcome


# --------------------------------------------------------------------------- #
# Target extraction, secret redaction & Indicator builder
# --------------------------------------------------------------------------- #


def _is_dangerous_scheme_target(text: str) -> bool:
    """Unified dangerous-scheme predicate used in both Step 2 and Step 3."""
    if text.startswith("\\\\") and len(text) >= 4:
        return True
    m = _SCHEME_PREFIX_RE.match(text)
    if not m:
        return False
    scheme = m.group(1).lower()
    rest = m.group(2)
    if scheme not in DANGEROUS_URI_SCHEMES:
        return False
    if scheme in ("javascript", "vbscript"):
        return bool(rest.strip())
    if scheme == "file":
        return rest.startswith(("/", "\\"))
    if scheme == "data":
        return bool(_DATA_DANGEROUS_PREFIX_RE.match(text))
    return bool(rest) and not rest[0].isspace()


def _extract_qr_targets(payload: str) -> tuple[list[LinkFacts], list[str]]:
    """Extract classified URLs and dangerous-scheme targets from one QR payload."""
    stripped = payload.strip(_BORDER_STRIP_CHARS)
    if not stripped:
        return [], []

    urls: list[LinkFacts] = []
    dangerous: list[str] = []

    # Step 2: direct full-payload check.
    if _is_dangerous_scheme_target(stripped):
        dangerous.append(stripped)
        return urls, dangerous

    if not any(ch.isspace() for ch in stripped):
        direct = classify_url(stripped, canonicalize=True)
        if direct is not None and direct.host and direct.scheme in ("http", "https"):
            urls.append(direct)
            return urls, dangerous

    # Step 3: embedded targets in structured (vCard/MECARD/SMSTO) or multi-line text.
    seen_urls: set[str] = set()
    for m in _EMBEDDED_HTTP_RE.finditer(stripped):
        if len(urls) >= 16:
            break
        lf = classify_url(m.group(0), canonicalize=True)
        if lf is not None and lf.host and lf.url not in seen_urls:
            seen_urls.add(lf.url)
            urls.append(lf)

    seen_dang: set[str] = set()
    for m in _EMBEDDED_DANGEROUS_RE.finditer(stripped):
        if len(dangerous) >= 16:
            break
        tok = m.group(1)
        if tok not in seen_dang and _is_dangerous_scheme_target(tok):
            seen_dang.add(tok)
            dangerous.append(tok)

    return urls, dangerous


def _redact_wifi_password(text: str) -> str:
    """Linear O(N) redaction of ``P:``/``p:`` field inside ``WIFI:`` QR payloads."""
    if not text.lower().startswith("wifi:"):
        return text
    prefix = text[:5]
    body = text[5:]
    n = len(body)
    out: list[str] = [prefix]
    i = 0
    at_field_start = True
    while i < n:
        if at_field_start and i + 2 <= n and body[i] in ("P", "p") and body[i + 1] == ":":
            out.append("P:[REDACTED]")
            i += 2
            while i < n:
                ch = body[i]
                if ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == ";":
                    out.append(";")
                    i += 1
                    break
                i += 1
            at_field_start = True
            continue
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            out.append(body[i : i + 2])
            i += 2
            at_field_start = False
            continue
        out.append(ch)
        at_field_start = ch == ";"
        i += 1
    return "".join(out)


def _redact_qr_excerpt(raw: str) -> str:
    """Pre-clean BOM/BiDi/controls, redact secrets, defang URLs, and cap length."""
    cleaned = raw.translate(_PRE_REDACT_TABLE).lstrip()
    cleaned = _redact_wifi_password(cleaned)
    cleaned = _OTPAUTH_SECRET_RE.sub(r"\1[REDACTED]", cleaned)
    cleaned = _OTPAUTH_MIG_RE.sub(r"\1[REDACTED]", cleaned)
    cleaned = _URL_USERINFO_PASS_RE.sub(r"\1[REDACTED]\3", cleaned)
    cleaned = _SENSITIVE_QUERY_RE.sub(r"\1[REDACTED]", cleaned)

    # Defang any http(s):// URLs inside the excerpt.
    if "://" in cleaned:
        cleaned = _EMBEDDED_HTTP_RE.sub(lambda m: defang_url(m.group(0)), cleaned)
    elif cleaned.lower().startswith("//"):
        cleaned = defang_url(cleaned)

    max_len = config.MAX_STRING_CAPTURE
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len] + "…"
    return cleaned


def _suspicious_signals(link: LinkFacts) -> tuple[list[str], int, Severity]:
    """Return ``(reasons, weight, severity)`` for one LinkFacts (Spec 015 §6.2)."""
    reasons: list[str] = []
    if link.is_shortener:
        reasons.append("Kurzlink")
    if link.is_ip_literal:
        reasons.append("IP-Adresse")
    if link.is_punycode:
        reasons.append("Punycode/IDN")
    if link.risky_tld:
        reasons.append("Risiko-TLD")
    if link.has_credentials:
        reasons.append("Zugangsdaten in URL")
    if not reasons:
        return [], 0, Severity.INFO
    if len(reasons) >= 2:
        return reasons, 35, Severity.HIGH
    if link.has_credentials:
        return reasons, 30, Severity.HIGH
    return reasons, 25, Severity.MEDIUM


def build_qr_indicators(pipeline_name: str, outcome: QrScanOutcome) -> list[Indicator]:
    """Convert a ``QrScanOutcome`` into Malaz ``Indicator`` objects."""
    indicators: list[Indicator] = []

    if outcome.hits:
        excerpts = [_redact_qr_excerpt(h.payload) for h in outcome.hits[:4]]
        indicators.append(
            Indicator(
                rule_id="QR_CODE_DETECTED",
                title=f"QR-Code erkannt ({len(outcome.hits)})",
                detail="Inhalt (entschärft): " + " | ".join(excerpts),
                severity=Severity.INFO,
                category=CAT_CONTENT,
                weight=0,
                source=pipeline_name,
            )
        )

    all_urls: list[LinkFacts] = []
    seen_url_keys: set[str] = set()
    dangerous_targets: list[str] = []
    seen_dang: set[str] = set()

    for hit in outcome.hits:
        urls, dang = _extract_qr_targets(hit.payload)
        for lf in urls:
            if lf.url not in seen_url_keys:
                seen_url_keys.add(lf.url)
                all_urls.append(lf)
        for d in dang:
            if d not in seen_dang:
                seen_dang.add(d)
                dangerous_targets.append(d)

    # Tier 1: Offline domain/IP blocklists + offline SHA-256 URL blocklist (opt-in online).
    blocked_urls: list[str] = []
    blocked_set: set[str] = set()
    unavailable_rules: list[tuple[str, str]] = []

    if all_urls:
        ioc_tuples: list[tuple[str, str]] = []
        ip_to_urls: dict[str, list[str]] = {}
        for lf in all_urls:
            ioc_tuples.append((IOC_URL, lf.url))
            if lf.is_ip_literal and lf.host:
                ip_kind = IOC_IPV6 if ":" in lf.host else IOC_IPV4
                ioc_tuples.append((ip_kind, lf.host))
                ip_to_urls.setdefault(lf.host, []).append(lf.url)
        blocked_iocs, _plain, unavail = split_blocked_iocs(ioc_tuples)
        unavailable_rules.extend(unavail)
        for kind, val in blocked_iocs:
            if kind == IOC_URL:
                if val not in blocked_set:
                    blocked_set.add(val)
                    blocked_urls.append(val)
            elif kind in (IOC_IPV4, IOC_IPV6):
                for mapped_url in ip_to_urls.get(val, ()):
                    if mapped_url not in blocked_set:
                        blocked_set.add(mapped_url)
                        blocked_urls.append(mapped_url)

        rep = url_reputation_lookup([lf.url for lf in all_urls])
        if rep.error:
            outcome.add_incomplete(f"URL-Reputationsabgleich fehlgeschlagen: {rep.error}")
        if rep.hits:
            for lf in all_urls:
                if url_hash(lf.url) in rep.hits and lf.url not in blocked_set:
                    blocked_set.add(lf.url)
                    blocked_urls.append(lf.url)

    for rule_id, detail in unavailable_rules:
        indicators.append(
            Indicator(
                rule_id=rule_id,
                title=BLOCKLIST_UNAVAILABLE_TITLE,
                detail=detail,
                severity=Severity.INFO,
                category=CAT_IOC,
                weight=0,
                source=pipeline_name,
            )
        )

    if blocked_urls:
        excerpts = [_redact_qr_excerpt(u) for u in blocked_urls[:4]]
        indicators.append(
            Indicator(
                rule_id="QR_BLOCKED_URL",
                title=f"QR-Code verweist auf blockierte Adresse ({len(blocked_urls)})",
                detail=(
                    "Mindestens eine QR-Code-URL steht auf einer lokalen Blockliste "
                    "(oder Reputationsliste): " + " | ".join(excerpts)
                ),
                severity=Severity.CRITICAL,
                category=CAT_IOC,
                weight=60,
                source=pipeline_name,
            )
        )

    # Tier 2: Dangerous URI schemes / UNC paths.
    if dangerous_targets:
        excerpts = [_redact_qr_excerpt(d) for d in dangerous_targets[:4]]
        indicators.append(
            Indicator(
                rule_id="QR_DANGEROUS_SCHEME",
                title=f"QR-Code nutzt gefährliches URI-Schema ({len(dangerous_targets)})",
                detail=(
                    "QR-Code enthält ein aktives oder lokales URI-Schema: "
                    + " | ".join(excerpts)
                ),
                severity=Severity.HIGH,
                category=CAT_SCRIPT,
                weight=40,
                source=pipeline_name,
            )
        )

    # Tier 3: Suspicious URLs (excluding Tier-1 blocked URLs — no 60+25 stacking).
    suspicious_entries: list[str] = []
    max_weight = 0
    max_sev = Severity.MEDIUM
    for lf in all_urls:
        if lf.url in blocked_set:
            continue
        reasons, weight, sev = _suspicious_signals(lf)
        if not reasons:
            continue
        if weight > max_weight:
            max_weight = weight
            max_sev = sev
        suspicious_entries.append(
            f"{_redact_qr_excerpt(lf.url)} ({', '.join(reasons)})"
        )

    if suspicious_entries:
        indicators.append(
            Indicator(
                rule_id="QR_SUSPICIOUS_URL",
                title=f"Verdächtige URL im QR-Code ({len(suspicious_entries)})",
                detail="Phishing-/Quishing-Merkmale: " + " | ".join(suspicious_entries[:4]),
                severity=max_sev,
                category=CAT_IOC,
                weight=max_weight,
                source=pipeline_name,
            )
        )

    # Completeness invariant: always surface unchecked/incomplete states.
    if outcome.incomplete_reasons:
        indicators.append(
            Indicator(
                rule_id="QR_SCAN_INCOMPLETE",
                title=QR_INCOMPLETE_TITLE,
                detail=(
                    "Die QR-Code-Prüfung konnte nicht vollständig abgeschlossen werden: "
                    + "; ".join(outcome.incomplete_reasons[:4])
                    + ". Das Fehlen eines Treffers belegt nicht, dass keine QR-Codes enthalten sind."
                ),
                severity=Severity.INFO,
                category=CAT_CONTENT,
                weight=0,
                source=pipeline_name,
            )
        )

    return indicators
