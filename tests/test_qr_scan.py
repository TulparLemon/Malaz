"""Tests for offline QR-code & MicroQR analysis (Spec 015 / DET-002)."""

from __future__ import annotations

import base64
import io
import socket
import struct
import time
import urllib.request
import warnings
import zlib
from pathlib import Path

import pikepdf
import pytest
import zxingcpp
from PIL import Image

from malaz import config
from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core import qr_scan
from malaz.core.dispatcher import Dispatcher
from malaz.core.email_extract import BUDGET_STOP_PREFIX, iter_email_attachments
from malaz.core.url_reputation import url_hash
from malaz.models import RiskLevel

# --------------------------------------------------------------------------- #
# Synthetic QR / image / PDF / email helpers
# --------------------------------------------------------------------------- #


def _qr_pil(
    payload: str,
    *,
    fmt: zxingcpp.BarcodeFormat = zxingcpp.BarcodeFormat.QRCode,
    scale: int = 5,
    mode: str = "L",
    rotate: int = 0,
    invert: bool = False,
) -> Image.Image:
    bc = zxingcpp.create_barcode(payload, fmt)
    buf = zxingcpp.write_barcode_to_image(bc, scale=scale)
    img = Image.fromarray(buf)
    if invert:
        img = img.point(lambda p: 255 - p)
    if rotate:
        img = img.rotate(rotate, expand=True, fillcolor=255)
    if mode != img.mode:
        img = img.convert(mode)
    return img


def _qr_bytes(
    payload: str,
    image_format: str = "PNG",
    *,
    fmt: zxingcpp.BarcodeFormat = zxingcpp.BarcodeFormat.QRCode,
    scale: int = 5,
    mode: str = "L",
    rotate: int = 0,
    invert: bool = False,
) -> bytes:
    img = _qr_pil(payload, fmt=fmt, scale=scale, mode=mode, rotate=rotate, invert=invert)
    out = io.BytesIO()
    if image_format.upper() == "JPEG" and img.mode not in ("L", "RGB"):
        img = img.convert("RGB")
    img.save(out, format=image_format)
    return out.getvalue()


def _transparent_qr_png(payload: str, *, white_modules: bool = False) -> bytes:
    gray = _qr_pil(payload, scale=5, mode="L")
    w, h = gray.size
    rgba = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gpx = gray.load()
    rpx = rgba.load()
    fg = (255, 255, 255, 255) if white_modules else (0, 0, 0, 255)
    for y in range(h):
        for x in range(w):
            if gpx[x, y] < 128:
                rpx[x, y] = fg
    out = io.BytesIO()
    rgba.save(out, format="PNG")
    return out.getvalue()


def _qr_16bit_png(payload: str, lo: int = 5000, hi: int = 60000) -> bytes:
    """Create a 16-bit grayscale PNG ('I;16') whose values lie in [lo, hi]."""
    gray = _qr_pil(payload, scale=4, mode="L")
    w, h = gray.size
    raw_rows = bytearray()
    gpx = gray.load()
    for y in range(h):
        raw_rows.append(0)  # PNG filter type 0
        for x in range(w):
            val = lo if gpx[x, y] < 128 else hi
            raw_rows.extend(struct.pack(">H", val))
    idat = zlib.compress(bytes(raw_rows), 6)

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w, h, 16, 0, 0, 0, 0)  # 16-bit grayscale
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _png_bomb_bytes(width: int = 10000, height: int = 10000) -> bytes:
    """Tiny valid PNG header declaring 10000x10000 pixels (DecompressionBomb)."""

    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 1, 0, 0, 0, 0)
    idat = zlib.compress(b"\x00" * 16)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def _jpeg_bomb_bytes(width: int = 10000, height: int = 10000) -> bytes:
    """Minimal JPEG SOF0 header claiming width x height pixels (no large allocation)."""
    sof0 = struct.pack(">BHHB", 8, height, width, 1) + b"\x01\x11\x00"
    sof0_seg = b"\xff\xc0" + struct.pack(">H", len(sof0) + 2) + sof0
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x00\xff\xd9"
    return b"\xff\xd8" + sof0_seg + sos


def _make_flate_xobj(
    pdf: pikepdf.Pdf,
    img: Image.Image,
    *,
    colorspace: object | None = None,
    image_mask: bool = False,
    predictor_12: bool = False,
    array_decode_parms: bool = False,
) -> pikepdf.Stream:
    w, h = img.size
    if image_mask:
        bimg = img.convert("1")
        raw = bimg.tobytes()
        d = {
            "/Type": pikepdf.Name("/XObject"),
            "/Subtype": pikepdf.Name("/Image"),
            "/Width": w,
            "/Height": h,
            "/BitsPerComponent": 1,
            "/ImageMask": True,
            "/Filter": pikepdf.Name("/FlateDecode"),
        }
        return pdf.make_stream(zlib.compress(raw), d)

    mode = img.mode
    if mode == "L":
        cs = colorspace or pikepdf.Name("/DeviceGray")
        bpc = 8
        cols = 1
    elif mode == "CMYK":
        cs = colorspace or pikepdf.Name("/DeviceCMYK")
        bpc = 8
        cols = 4
    else:
        img = img.convert("RGB")
        cs = colorspace or pikepdf.Name("/DeviceRGB")
        bpc = 8
        cols = 3

    raw = img.tobytes()
    if predictor_12:
        row_len = w * cols
        prev = bytearray(row_len)
        enc = bytearray()
        for y in range(h):
            row = raw[y * row_len : (y + 1) * row_len]
            enc.append(2)  # PNG Up predictor
            for i in range(row_len):
                enc.append((row[i] - prev[i]) & 0xFF)
            prev = bytearray(row)
        raw = bytes(enc)

    d: dict[str, object] = {
        "/Type": pikepdf.Name("/XObject"),
        "/Subtype": pikepdf.Name("/Image"),
        "/Width": w,
        "/Height": h,
        "/BitsPerComponent": bpc,
        "/ColorSpace": cs,
        "/Filter": pikepdf.Name("/FlateDecode"),
    }
    if predictor_12:
        parms = pikepdf.Dictionary(
            Predictor=12,
            Colors=cols,
            BitsPerComponent=bpc,
            Columns=w,
        )
        d["/DecodeParms"] = pikepdf.Array([parms]) if array_decode_parms else parms
    return pdf.make_stream(zlib.compress(raw), d)


def _pdf_bytes(pdf: pikepdf.Pdf) -> bytes:
    buf = io.BytesIO()
    pdf.save(buf, compress_streams=False, stream_decode_level=pikepdf.StreamDecodeLevel.none)
    return buf.getvalue()


_SHARED_DISPATCHER: Dispatcher | None = None


def _dispatcher() -> Dispatcher:
    global _SHARED_DISPATCHER
    if _SHARED_DISPATCHER is None:
        _SHARED_DISPATCHER = Dispatcher(
            av_scanner=WindowsDefenderScanner(enabled=False),
            clam_scanner=ClamAVScanner(enabled=False),
        )
    return _SHARED_DISPATCHER


def _scan_file(tmp_path: Path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return _dispatcher().scan_path(p)


def _rule_ids(res) -> set[str]:
    return {ind.rule_id for ind in res.all_indicators()}


def _find_ind(res, rule_id: str):
    return [ind for ind in res.all_indicators() if ind.rule_id == rule_id]


@pytest.fixture
def no_network(monkeypatch):
    def _boom(*_a, **_kw):
        raise AssertionError("Unexpected network access during offline QR scan")

    monkeypatch.setattr(socket, "create_connection", _boom)
    monkeypatch.setattr(urllib.request, "urlopen", _boom)


# --------------------------------------------------------------------------- #
# 8.1 True Positives: Quishing URLs, Dangerous Schemes, Blocklists
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "expected_weight"),
    [
        ("https://qrco.de/a", 25),
        ("http://198.51.100.10/login", 25),
        ("https://xn--pypal-4ve.example/id", 25),
        ("https://p\u0430ypal.example/id", 25),  # Cyrillic 'a' raw UTF-8 IDN
        ("https://secure-verify.top/account", 25),
        ("https://user:MyPass@example.org/doc", 30),
        ("https://user:Pw@198.51.100.10/x", 35),
        ("HTTPS://QRCO.DE/UPPER", 25),
        ("qrco.de/login?access_token=Secret123", 25),
        ("\ufeffqrco.de/bomtest", 25),
        ("https://example.org/ok\nhttps://qrco.de/phish", 25),
        ("BEGIN:VCARD\nVERSION:3.0\nFN:Alice\nURL:https://qrco.de/vc\nEND:VCARD", 25),
    ],
)
def test_quishing_url_variants(tmp_path, no_network, payload, expected_weight):
    png = _qr_bytes(payload, "PNG")
    res = _scan_file(tmp_path, "quish.png", png)
    ids = _rule_ids(res)
    assert "QR_CODE_DETECTED" in ids
    assert "QR_SUSPICIOUS_URL" in ids
    sus = _find_ind(res, "QR_SUSPICIOUS_URL")[0]
    assert sus.weight == expected_weight
    for ind in res.all_indicators():
        assert "MyPass" not in ind.detail
        assert "Secret123" not in ind.detail


@pytest.mark.parametrize(
    "payload",
    [
        "javascript:alert(1)",
        "file:///C:/Windows/win.ini",
        "ms-msdt:/id PCWDiagnostic",
        r"\\evil\share\x.exe",
        "\ufeff" + r"\\evil\share\x.exe",
        "smb://admin:Secret@host/share",
    ],
)
def test_dangerous_uri_schemes(tmp_path, no_network, payload):
    png = _qr_bytes(payload, "PNG")
    res = _scan_file(tmp_path, "dang.png", png)
    ids = _rule_ids(res)
    assert "QR_CODE_DETECTED" in ids
    assert "QR_DANGEROUS_SCHEME" in ids
    dang = _find_ind(res, "QR_DANGEROUS_SCHEME")[0]
    assert dang.weight == 40
    for ind in res.all_indicators():
        assert "Secret" not in ind.detail


def test_local_blocklists_domain_ip_and_url_sha256_no_stacking(tmp_path, monkeypatch, no_network):
    dom_bl = tmp_path / "domains.txt"
    ip_bl = tmp_path / "ips.txt"
    url_bl = tmp_path / "urls.sha256"

    idn_ascii = "p\u0430ypal.example".encode("idna").decode("ascii")
    dom_bl.write_text(f"{idn_ascii}\nqrco.de\n", encoding="utf-8")
    ip_bl.write_text("198.51.100.10/32\n", encoding="utf-8")
    url_bl.write_text(url_hash("https://evil-hash.example/drop") + "\n", encoding="utf-8")

    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", dom_bl)
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", ip_bl)
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", url_bl)

    for payload in (
        "https://p\u0430ypal.example/id",
        "qrco.de/login",
        "http://198.51.100.10/p",
        "https://evil-hash.example/drop",
    ):
        res = _scan_file(tmp_path, "blocked.png", _qr_bytes(payload, "PNG"))
        ids = _rule_ids(res)
        assert "QR_BLOCKED_URL" in ids, payload
        assert "QR_SUSPICIOUS_URL" not in ids, f"Tier-1 must not stack with Tier-3: {payload}"
        assert _find_ind(res, "QR_BLOCKED_URL")[0].weight == 60
        assert res.risk_level == RiskLevel.RED


def test_unreadable_blocklists_report_incomplete(tmp_path, monkeypatch, no_network):
    bad_dom = tmp_path / "bad_dom_dir"
    bad_dom.mkdir()
    monkeypatch.setattr(config, "DOMAIN_BLOCKLIST_FILE", bad_dom)
    monkeypatch.setattr(config, "IP_BLOCKLIST_FILE", tmp_path / "missing_ip.txt")
    monkeypatch.setattr(config, "URL_BLOCKLIST_FILE", tmp_path / "missing_url.sha256")

    res = _scan_file(tmp_path, "dom_err.png", _qr_bytes("https://example.org/a", "PNG"))
    assert "DOMAIN_BLOCKLIST_UNAVAILABLE" in _rule_ids(res)
    assert res.is_incomplete is True


# --------------------------------------------------------------------------- #
# 8.1 Image & Transparency Variants + Multi-Frame + MicroQR
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("ext", "pil_fmt"),
    [
        (".png", "PNG"),
        (".jpg", "JPEG"),
        (".gif", "GIF"),
        (".bmp", "BMP"),
        (".webp", "WEBP"),
        (".tiff", "TIFF"),
    ],
)
def test_raster_formats_end_to_end_via_dispatcher(tmp_path, no_network, ext, pil_fmt):
    data = _qr_bytes("https://qrco.de/fmt", pil_fmt)
    res = _scan_file(tmp_path, f"sample{ext}", data)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res)


def test_transparent_black_and_white_modules_and_16bit_png(tmp_path, no_network):
    for name, raw in (
        ("black_alpha.png", _transparent_qr_png("https://qrco.de/ba", white_modules=False)),
        ("white_alpha.png", _transparent_qr_png("https://qrco.de/wa", white_modules=True)),
        ("sixteen.png", _qr_16bit_png("https://qrco.de/16bit", lo=5000, hi=60000)),
    ):
        res = _scan_file(tmp_path, name, raw)
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res), name


def test_rotated_inverted_and_microqr(tmp_path, no_network):
    for name, raw in (
        ("rot90.png", _qr_bytes("https://qrco.de/r90", "PNG", rotate=90)),
        ("inv.png", _qr_bytes("https://qrco.de/inv", "PNG", invert=True)),
        (
            "micro.png",
            _qr_bytes("12345", "PNG", fmt=zxingcpp.BarcodeFormat.MicroQRCode, scale=6),
        ),
    ):
        res = _scan_file(tmp_path, name, raw)
        assert "QR_CODE_DETECTED" in _rule_ids(res), name


def test_multiframe_gif_preserves_frame0_hit_on_corrupt_frame1(no_network):
    f0 = _qr_pil("https://qrco.de/f0", scale=4, mode="P")
    f1 = Image.new("P", f0.size, 0)
    buf = io.BytesIO()
    f0.save(buf, format="GIF", save_all=True, append_images=[f1], duration=100, loop=0)
    raw = buf.getvalue()
    # Replace frame 1 image descriptor area with garbage so frame 0 succeeds and frame 1 fails.
    idx = raw.rfind(b"\x2c")
    assert idx > 10
    corrupt = raw[: idx + 5] + b"\xff" * 4
    outcome = qr_scan.scan_image_bytes(corrupt, source_label="gif")
    assert any("qrco.de/f0" in h.payload for h in outcome.hits)
    assert outcome.incomplete_reasons


# --------------------------------------------------------------------------- #
# 8.1 Container & Document Paths: PDF, EML, HTML, SVG, MSG
# --------------------------------------------------------------------------- #


def test_pdf_qr_xobject_inherited_annot_form_pattern_mask_predictor_dct(tmp_path, no_network):
    qr_img = _qr_pil("https://qrco.de/pdf", scale=4, mode="RGB")
    qr_cmyk = _qr_pil("https://qrco.de/cmyk", scale=4, mode="CMYK")
    qr_gray = _qr_pil("https://qrco.de/mask", scale=4, mode="L")

    # 1. Direct XObject (RGB + CMYK)
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        page = pdf.pages[0]
        page["/Resources"] = pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(
                Im1=_make_flate_xobj(pdf, qr_img),
                Im2=_make_flate_xobj(pdf, qr_cmyk),
            )
        )
        res = _scan_file(tmp_path, "direct.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)
        assert "QR_SCAN_INCOMPLETE" not in _rule_ids(res)

    # 2. Inherited /Pages /Resources (ISO 32000-1 §7.7.3.4)
    from malaz.pipelines import pdf_qr

    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        del pdf.pages[0].obj["/Resources"]
        pdf.pages[0].obj["/Parent"]["/Resources"] = pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(ImInh=_make_flate_xobj(pdf, qr_img))
        )
        inds_inh = pdf_qr.scan_pdf_qr(pdf)
        assert any(ind.rule_id == "QR_SUSPICIOUS_URL" for ind in inds_inh)

    # 3. /Annots[*]/AP/N
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        ap_stream = pdf.make_stream(
            b"q 100 0 0 100 0 0 cm /ImAp Do Q",
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Form"),
                "/BBox": pikepdf.Array([0, 0, 100, 100]),
                "/Resources": pikepdf.Dictionary(
                    XObject=pikepdf.Dictionary(ImAp=_make_flate_xobj(pdf, qr_img))
                ),
            },
        )
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/Stamp"),
                Rect=pikepdf.Array([0, 0, 100, 100]),
                AP=pikepdf.Dictionary(N=ap_stream),
            )
        )
        pdf.pages[0]["/Annots"] = pikepdf.Array([annot])
        res = _scan_file(tmp_path, "annot.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)

    # 4. /Subtype /Form & /Pattern Type 1
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        pat = pdf.make_stream(
            b"q 100 0 0 100 0 0 cm /ImPat Do Q",
            {
                "/Type": pikepdf.Name("/Pattern"),
                "/PatternType": 1,
                "/PaintType": 1,
                "/TilingType": 1,
                "/BBox": pikepdf.Array([0, 0, 100, 100]),
                "/XStep": 100,
                "/YStep": 100,
                "/Resources": pikepdf.Dictionary(
                    XObject=pikepdf.Dictionary(ImPat=_make_flate_xobj(pdf, qr_img))
                ),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(
            Pattern=pikepdf.Dictionary(P1=pat)
        )
        res = _scan_file(tmp_path, "pattern.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)

    # 5. 1-bit /ImageMask without /ColorSpace
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(ImMask=_make_flate_xobj(pdf, qr_gray, image_mask=True))
        )
        res = _scan_file(tmp_path, "imagemask.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)
        assert "QR_SCAN_INCOMPLETE" not in _rule_ids(res)

    # 6. /SMask containing QR attached to solid base image
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        base = _make_flate_xobj(pdf, Image.new("RGB", qr_gray.size, (0, 0, 0)))
        base["/SMask"] = _make_flate_xobj(pdf, qr_gray)
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(ImS=base))
        res = _scan_file(tmp_path, "smask.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)

    # 7. /FlateDecode with /Predictor 12 & Array /DecodeParms
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        im_pred = _make_flate_xobj(pdf, qr_img, predictor_12=True, array_decode_parms=True)
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(ImP=im_pred))
        res = _scan_file(tmp_path, "pred12.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)
        assert "QR_SCAN_INCOMPLETE" not in _rule_ids(res)

    # 8. /DCTDecode with forged tiny /Width 5 /Height 5
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(300, 300))
        jpg = _qr_bytes("https://qrco.de/dct", "JPEG")
        dct = pdf.make_stream(
            jpg,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 5,
                "/Height": 5,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Name("/DCTDecode"),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(ImD=dct))
        res = _scan_file(tmp_path, "dct_forged.pdf", _pdf_bytes(pdf))
        assert "QR_SUSPICIOUS_URL" in _rule_ids(res)


def test_eml_attachment_inline_and_html_data_uri(tmp_path, no_network):
    png_att = _qr_bytes("https://qrco.de/att", "PNG")
    png_inl = _qr_bytes("https://qrco.de/inl", "PNG")
    png_uri = _qr_bytes("https://qrco.de/uri", "PNG")
    b64_uri = base64.b64encode(png_uri).decode("ascii").replace("+", "%2B")

    # 1. Attachment
    eml1 = (
        b"From: a@example.org\r\nTo: b@example.org\r\nSubject: Att\r\n"
        b'Content-Type: multipart/mixed; boundary="B1"\r\n\r\n'
        b"--B1\r\nContent-Type: text/plain\r\n\r\nHi\r\n"
        b'--B1\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename="qr.png"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(png_att)
        + b"\r\n--B1--\r\n"
    )
    res1 = _scan_file(tmp_path, "att.eml", eml1)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res1)

    # 2. Unnamed inline image without Content-Disposition
    eml2 = (
        b"From: a@example.org\r\nTo: b@example.org\r\nSubject: Inline\r\n"
        b'Content-Type: multipart/related; boundary="B2"\r\n\r\n'
        b"--B2\r\nContent-Type: text/html\r\n\r\n<img src='cid:x'>\r\n"
        b"--B2\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        + base64.b64encode(png_inl)
        + b"\r\n--B2--\r\n"
    )
    res2 = _scan_file(tmp_path, "inline.eml", eml2)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res2)

    # 3. HTML body data:image/png;base64 with %2B
    eml3 = (
        b"Received: from mail.example.org (mail.example.org [198.51.100.1]) by mx.example.org\r\n"
        b"Message-ID: <qr-test-1234567890@mail.example.org>\r\n"
        b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\nMIME-Version: 1.0\r\n"
        b"From: sender@example.org\r\nTo: recipient@example.org\r\nSubject: QR Test\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<html><body><img src="data:image/png;base64,'
        + b64_uri.encode("ascii")
        + b'"></body></html>'
    )
    res3 = _scan_file(tmp_path, "datauri.eml", eml3)
    assert res3.detected_type == "eml"
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res3)


def test_html_unquoted_attr_nested_dedup_and_svg(tmp_path, no_network):
    png = _qr_bytes("https://qrco.de/html", "PNG")
    b64 = base64.b64encode(png).decode("ascii")
    inner_html = f"<html><body><img src='data:image/png;base64,{b64}'></body></html>"
    inner_b64 = base64.b64encode(inner_html.encode("utf-8")).decode("ascii")

    html = (
        f"<!doctype html><html><body>"
        f"<img src=data:image/png;base64,{b64} alt=qr>"
        f'<iframe src="data:text/html;base64,{inner_b64}"></iframe>'
        f"</body></html>"
    ).encode()
    res = _scan_file(tmp_path, "quish.html", html)
    assert len(_find_ind(res, "QR_CODE_DETECTED")) == 1
    assert len(_find_ind(res, "QR_SUSPICIOUS_URL")) == 1

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg">'
        f'<image href="data:image/png;base64,{b64}"/></svg>'
    ).encode()
    res_svg = _scan_file(tmp_path, "quish.svg", svg)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res_svg)


def test_msg_attachment_qr(tmp_path, no_network):
    from tests.test_email_rtf import _MSG_PROPS, _build_msg_cfb

    png = _qr_bytes("https://qrco.de/msg", "PNG")
    msg = _build_msg_cfb([("qr.png", png)], properties=_MSG_PROPS)
    res = _scan_file(tmp_path, "quish.msg", msg)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res)


# --------------------------------------------------------------------------- #
# 8.2 Zero Benign FP Drift & Secret Redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("payload", "forbidden_secret"),
    [
        ("https://example.org/docs", None),
        ("BCD\n002\n1\nSCT\nCOBADEFFXXX\nAcme GmbH\nDE89370400440532013000\nEUR12.34", None),
        ("BEGIN:VCARD\nVERSION:3.0\nFN:Max Mustermann\nTEL:+49123456\nEND:VCARD", None),
        ("File: Rechnung.pdf", None),
        ("PowerShell: Get-Date", None),
        ("CMD: ipconfig", None),
        ("data:text/plain,hello", None),
        (r"WIFI:T:WPA;S:LabP:1;P:Top\;Sec\\ret;;", "Top"),
        ("\ufeffWIFI:T:WPA;S:Corp;P:BomSecret;;", "BomSecret"),
        ("wifi:T:WPA;S:Guest;P:NoSemi", "NoSemi"),
        ("otpauth://totp/App:u?sec\u202eret=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
        ("otpauth://totp/App:u?sec\u200bret=JBSWY3DPEHPK3PXP", "JBSWY3DPEHPK3PXP"),
        ("otpauth-migration://offline?data=Cg0KBTopSecretPayload", "Cg0KBTopSecretPayload"),
        ("https://example.org/doc?access_token=Secret123", "Secret123"),
    ],
)
def test_benign_qr_and_secret_redaction(tmp_path, no_network, payload, forbidden_secret):
    res = _scan_file(tmp_path, "benign.png", _qr_bytes(payload, "PNG"))
    ids = _rule_ids(res)
    assert "QR_CODE_DETECTED" in ids
    assert "QR_SUSPICIOUS_URL" not in ids
    assert "QR_DANGEROUS_SCHEME" not in ids
    assert "QR_BLOCKED_URL" not in ids
    assert res.risk_level == RiskLevel.GREEN
    assert res.score == 0
    det = _find_ind(res, "QR_CODE_DETECTED")[0].detail
    if forbidden_secret:
        assert forbidden_secret not in det
        assert "[REDACTED]" in det
    if payload.startswith("https://"):
        assert "hxxps://" in det


def test_benign_html_svg_data_uri_has_no_incomplete(tmp_path, no_network):
    svg_b64 = base64.b64encode(b"<svg xmlns='http://www.w3.org/2000/svg'/>").decode("ascii")
    html = f'<html><body><img src="data:image/svg+xml;base64,{svg_b64}"></body></html>'.encode()
    res = _scan_file(tmp_path, "benign.html", html)
    assert "QR_SCAN_INCOMPLETE" not in _rule_ids(res)


def test_pdf_form_dag_reused_across_pages_is_fast_and_clean(tmp_path, no_network):
    """4x20 DAG (80 forms, depth <= 4) finishes < 0.5s with NO QR_SCAN_INCOMPLETE."""
    with pikepdf.new() as pdf:
        layers: list[list[pikepdf.Stream]] = []
        leaf_forms = [
            pdf.make_stream(
                b"q Q",
                {
                    "/Type": pikepdf.Name("/XObject"),
                    "/Subtype": pikepdf.Name("/Form"),
                    "/BBox": pikepdf.Array([0, 0, 10, 10]),
                },
            )
            for _ in range(20)
        ]
        layers.append(leaf_forms)
        for _depth in range(3):
            prev = layers[-1]
            xobjs = pikepdf.Dictionary({f"/F{i}": prev[i] for i in range(20)})
            cur = [
                pdf.make_stream(
                    b"q Q",
                    {
                        "/Type": pikepdf.Name("/XObject"),
                        "/Subtype": pikepdf.Name("/Form"),
                        "/BBox": pikepdf.Array([0, 0, 10, 10]),
                        "/Resources": pikepdf.Dictionary(XObject=xobjs),
                    },
                )
                for _ in range(20)
            ]
            layers.append(cur)

        top_xobjs = pikepdf.Dictionary({f"/T{i}": layers[-1][i] for i in range(20)})
        for _ in range(10):
            pdf.add_blank_page(page_size=(200, 200))
            pdf.pages[-1]["/Resources"] = pikepdf.Dictionary(XObject=top_xobjs)

        raw = _pdf_bytes(pdf)

    t0 = time.perf_counter()
    res = _scan_file(tmp_path, "dag.pdf", raw)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0
    assert "QR_SCAN_INCOMPLETE" not in _rule_ids(res)


def test_eml_inline_image_quota_never_crowds_out_attachments(no_network):
    small_png = _qr_bytes("ok", "PNG", scale=2)
    assert len(small_png) >= 44

    def _build_mail(inline_count: int) -> bytes:
        parts = [
            b"From: a@example.org\r\nTo: b@example.org\r\nSubject: Quota\r\n",
            b'Content-Type: multipart/mixed; boundary="BQ"\r\n\r\n',
        ]
        b64 = base64.b64encode(small_png)
        for _ in range(inline_count):
            parts.append(
                b"--BQ\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n"
                + b64
                + b"\r\n"
            )
        parts.append(
            b'--BQ\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Disposition: attachment; filename="evil.exe"\r\n\r\nMZ'
            + b"\x00" * 64
            + b"\r\n--BQ--\r\n"
        )
        return b"".join(parts)

    rows16 = list(iter_email_attachments(_build_mail(16), "eml"))
    names16 = [r[0] for r in rows16 if r[2] is None]
    errs16 = [r[2] for r in rows16 if r[2] is not None]
    assert "evil.exe" in names16
    assert names16[0] == "evil.exe"
    assert not errs16

    rows17 = list(iter_email_attachments(_build_mail(17), "eml"))
    names17 = [r[0] for r in rows17 if r[2] is None]
    errs17 = [r[2] for r in rows17 if r[2] is not None]
    assert "evil.exe" in names17
    assert any(e.startswith(BUDGET_STOP_PREFIX) for e in errs17)


# --------------------------------------------------------------------------- #
# 8.3 Completeness & Bomb Guards
# --------------------------------------------------------------------------- #


def test_missing_zxing_engine_reports_incomplete_everywhere(tmp_path, monkeypatch, no_network):
    monkeypatch.setattr(qr_scan, "_load_zxing", lambda: None)
    png = _qr_bytes("https://example.org", "PNG")
    b64 = base64.b64encode(png).decode("ascii")

    res_img = _scan_file(tmp_path, "a.png", png)
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_img)
    assert res_img.is_incomplete is True

    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(Im1=_make_flate_xobj(pdf, _qr_pil("https://example.org", scale=3)))
        )
        res_pdf = _scan_file(tmp_path, "a.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_pdf)
    assert res_pdf.is_incomplete is True

    html = f'<html><body><img src="data:image/png;base64,{b64}"></body></html>'.encode()
    res_html = _scan_file(tmp_path, "a.html", html)
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_html)
    assert res_html.is_incomplete is True

    eml = (
        b"Received: from mail.example.org (mail.example.org [198.51.100.1]) by mx.example.org\r\n"
        b"Message-ID: <qr-test-1234567890@mail.example.org>\r\n"
        b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\nMIME-Version: 1.0\r\n"
        b"From: sender@example.org\r\nTo: recipient@example.org\r\nSubject: QR Test\r\n"
        b"Content-Type: text/html\r\n\r\n" + html
    )
    res_eml = _scan_file(tmp_path, "a.eml", eml)
    assert res_eml.detected_type == "eml"
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_eml)
    assert res_eml.is_incomplete is True


def test_png_bomb_gif_many_frames_corrupt_data_uris_heic_corrupt_png(no_network):
    bomb_png = _png_bomb_bytes(10000, 10000)
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        out_bomb = qr_scan.scan_image_bytes(bomb_png)
    assert out_bomb.incomplete_reasons

    frames = [Image.new("RGB", (32, 32), (i * 40, 255 - i * 40, i * 20)) for i in range(6)]
    buf = io.BytesIO()
    frames[0].save(buf, format="GIF", save_all=True, append_images=frames[1:], duration=50, loop=0)
    out_gif = qr_scan.scan_image_bytes(buf.getvalue())
    assert out_gif.incomplete_reasons

    junk = " ".join(
        f'<img src="data:image/png;base64,{"AAAA" * 12}{i:04d}">' for i in range(1000)
    )
    t0 = time.perf_counter()
    out_junk = qr_scan.scan_data_uri_images(junk)
    assert time.perf_counter() - t0 < 1.0
    assert out_junk.incomplete_reasons

    assert qr_scan.scan_image_bytes(b"\x00\x00\x00\x18ftypheic" + b"\x00" * 32).incomplete_reasons
    assert qr_scan.scan_image_bytes(b"\x89PNG\r\n\x1a\n" + b"corrupt" * 8).incomplete_reasons


def test_pdf_bomb_guards_flate_icc_smask_dct_jbig2_multifilter_lzw_decodeparms_inline_cycle_limits(
    tmp_path, no_network
):
    # 1. Truly decodable multi-filter [/ASCII85Decode /FlateDecode]
    qr_img = _qr_pil("https://example.org/ok", scale=3, mode="L")
    a85_flate = base64.a85encode(zlib.compress(qr_img.tobytes())) + b"~>"
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        im_mf = pdf.make_stream(
            a85_flate,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": qr_img.size[0],
                "/Height": qr_img.size[1],
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/FlateDecode")]
                ),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(ImMF=im_mf))
        res_mf = _scan_file(tmp_path, "multifilter.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_mf)

    # 2. /JBIG2Decode and /LZWDecode rejected fail-closed
    for flt in ("/JBIG2Decode", "/LZWDecode"):
        with pikepdf.new() as pdf:
            pdf.add_blank_page(page_size=(200, 200))
            im = pdf.make_stream(
                b"\x00" * 32,
                {
                    "/Type": pikepdf.Name("/XObject"),
                    "/Subtype": pikepdf.Name("/Image"),
                    "/Width": 32,
                    "/Height": 32,
                    "/BitsPerComponent": 8,
                    "/ColorSpace": pikepdf.Name("/DeviceGray"),
                    "/Filter": pikepdf.Name(flt),
                },
            )
            pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im))
            res = _scan_file(tmp_path, f"flt_{flt[1:]}.pdf", _pdf_bytes(pdf))
        assert "QR_SCAN_INCOMPLETE" in _rule_ids(res), flt

    # 3. /FlateDecode bomb
    bomb_flate = zlib.compress(b"\x00" * (2 * 1024 * 1024), 9)
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        im_fb = pdf.make_stream(
            bomb_flate,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 32,
                "/Height": 32,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Name("/FlateDecode"),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im_fb))
        res_fb = _scan_file(tmp_path, "flate_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_fb)

    # 4. /ICCBased bomb & [/Indexed [/ICCBased ...]] bomb
    icc_bomb_data = zlib.compress(b"\x00" * (5 * 1024 * 1024), 9)
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        icc = pdf.make_stream(icc_bomb_data, {"/N": 3, "/Filter": pikepdf.Name("/FlateDecode")})
        im_icc = _make_flate_xobj(
            pdf, Image.new("RGB", (32, 32)), colorspace=pikepdf.Array([pikepdf.Name("/ICCBased"), icc])
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im_icc))
        res_icc = _scan_file(tmp_path, "icc_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_icc)

    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        icc = pdf.make_stream(icc_bomb_data, {"/N": 3, "/Filter": pikepdf.Name("/FlateDecode")})
        idx_cs = pikepdf.Array(
            [
                pikepdf.Name("/Indexed"),
                pikepdf.Array([pikepdf.Name("/ICCBased"), icc]),
                255,
                pikepdf.String(b"\x00" * 768),
            ]
        )
        im_idx = _make_flate_xobj(pdf, Image.new("L", (32, 32)), colorspace=idx_cs)
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im_idx))
        res_idx = _scan_file(tmp_path, "indexed_icc_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_idx)

    # 5. /SMask bomb prevents base as_pil_image()
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        base = _make_flate_xobj(pdf, Image.new("RGB", (32, 32)))
        smask_bomb = pdf.make_stream(
            bomb_flate,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 4,
                "/Height": 4,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Name("/FlateDecode"),
            },
        )
        base["/SMask"] = smask_bomb
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=base))
        res_sm = _scan_file(tmp_path, "smask_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_sm)

    # 6. /DCTDecode forged /Width 100 /Height 100 with 10000x10000 JPEG bomb header
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        dct_bomb = pdf.make_stream(
            _jpeg_bomb_bytes(10000, 10000),
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 100,
                "/Height": 100,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Name("/DCTDecode"),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=dct_bomb))
        res_dctb = _scan_file(tmp_path, "dct_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_dctb)

    # 7. Forged array /DecodeParms [<< /Columns 8192 /Rows 8192 >>]
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        im_dp = _make_flate_xobj(pdf, Image.new("L", (32, 32)))
        im_dp["/DecodeParms"] = pikepdf.Array([pikepdf.Dictionary(Columns=8192, Rows=8192)])
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im_dp))
        res_dp = _scan_file(tmp_path, "decodeparms_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_dp)

    # 8. Inline image BI/W 20/H 20...ID...EI in /Contents array
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        s1 = pdf.make_stream(b"q 1 0 0 1 0 0 cm ")
        s2 = pdf.make_stream(b"BI/W 20/H 20/BPC 8/CS/G ID \x00\x00 EI Q")
        pdf.pages[0]["/Contents"] = pikepdf.Array([s1, s2])
        res_bi = _scan_file(tmp_path, "inline_bi.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_bi)

    # 9. True /Form cycle
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        form = pdf.make_stream(
            b"q /Self Do Q",
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Form"),
                "/BBox": pikepdf.Array([0, 0, 10, 10]),
            },
        )
        form["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Self=form))
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(F0=form))
        res_cyc = _scan_file(tmp_path, "form_cycle.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_cyc)

    # 10. > 20 pages
    with pikepdf.new() as pdf:
        for _ in range(21):
            pdf.add_blank_page(page_size=(200, 200))
        res_pg = _scan_file(tmp_path, "many_pages.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_pg)


def test_truncated_html_input_reports_incomplete(no_network):
    out = qr_scan.scan_data_uri_images("<html><body>no qr</body></html>", input_truncated=True)
    assert out.incomplete_reasons


# --------------------------------------------------------------------------- #
# 8.4 Dedicated bite-test targets for scripts/check_tests_bite.py
# --------------------------------------------------------------------------- #


def test_bite_qr_suspicious_url(tmp_path, no_network):
    res = _scan_file(tmp_path, "bite_sus.png", _qr_bytes("https://qrco.de/bite", "PNG"))
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res)


def test_bite_qr_engine_missing(tmp_path, monkeypatch, no_network):
    monkeypatch.setattr(qr_scan, "_load_zxing", lambda: None)
    res = _scan_file(tmp_path, "bite_miss.png", _qr_bytes("https://example.org", "PNG"))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res)
    assert res.is_incomplete is True


def test_bite_qr_pdf_multifilter_bomb_guard(tmp_path, no_network):
    qr_img = _qr_pil("https://example.org/ok", scale=3, mode="L")
    a85_flate = base64.a85encode(zlib.compress(qr_img.tobytes())) + b"~>"
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        im_mf = pdf.make_stream(
            a85_flate,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": qr_img.size[0],
                "/Height": qr_img.size[1],
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/FlateDecode")]
                ),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(ImMF=im_mf))
        res = _scan_file(tmp_path, "bite_mf.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res)


def test_pdf_extra_guards_reused_dct_as_smask_annots_forms_depth_images_and_form_inline(
    tmp_path, no_network
):
    """Cover remaining Spec 015 §8.3 guards: cache-key separation, limits, /Form BI..ID."""
    # 1. Reused /DCTDecode with /ICCBased bomb: safe as non-mask (bypassed to Pillow),
    #    MUST be rejected when referenced as /SMask on a second image!
    icc_bomb = zlib.compress(b"\x00" * (5 * 1024 * 1024), 9)
    jpg = _qr_bytes("https://example.org/reused", "JPEG")
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        icc = pdf.make_stream(icc_bomb, {"/N": 1, "/Filter": pikepdf.Name("/FlateDecode")})
        dct_obj = pdf.make_stream(
            jpg,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 32,
                "/Height": 32,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Array([pikepdf.Name("/ICCBased"), icc]),
                "/Filter": pikepdf.Name("/DCTDecode"),
            },
        )
        base = _make_flate_xobj(pdf, Image.new("RGB", (32, 32)))
        base["/SMask"] = dct_obj
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(
            XObject=pikepdf.Dictionary(A_DctFirst=dct_obj, B_BaseWithSmask=base)
        )
        res_reuse = _scan_file(tmp_path, "reused_dct_smask.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_reuse)

    # 2. Inline image BI..ID inside a /Form XObject
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        frm = pdf.make_stream(
            b"q BI /W 20 /H 20 /BPC 8 /CS /G ID \x00\x00 EI Q",
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Form"),
                "/BBox": pikepdf.Array([0, 0, 20, 20]),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(F=frm))
        res_fbi = _scan_file(tmp_path, "form_inline.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_fbi)

    # 3. /Form depth > 4 (chain of 6 nested forms)
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        leaf = pdf.make_stream(
            b"q Q",
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Form"),
                "/BBox": pikepdf.Array([0, 0, 10, 10]),
            },
        )
        cur = leaf
        for i in range(6):
            cur = pdf.make_stream(
                b"q Q",
                {
                    "/Type": pikepdf.Name("/XObject"),
                    "/Subtype": pikepdf.Name("/Form"),
                    "/BBox": pikepdf.Array([0, 0, 10, 10]),
                    "/Resources": pikepdf.Dictionary(XObject=pikepdf.Dictionary({f"/N{i}": cur})),
                },
            )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Top=cur))
        res_dep = _scan_file(tmp_path, "form_deep.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_dep)

    # 4. > 256 /Annots on one page
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        ann = pdf.make_indirect(
            pikepdf.Dictionary(Type=pikepdf.Name("/Annot"), Subtype=pikepdf.Name("/Text"))
        )
        pdf.pages[0]["/Annots"] = pikepdf.Array([ann] * 260)
        res_ann = _scan_file(tmp_path, "many_annots.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_ann)

    # 5. > 32 distinct images
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        xmap = {}
        for i in range(34):
            xmap[f"/I{i}"] = _make_flate_xobj(pdf, Image.new("L", (16, 16), i % 255))
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(xmap))
        res_imgs = _scan_file(tmp_path, "many_imgs.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_imgs)

    # 6. /FlateDecode bomb WITH /Predictor 12
    bomb_flate = zlib.compress(b"\x00" * (2 * 1024 * 1024), 9)
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        im_pb = pdf.make_stream(
            bomb_flate,
            {
                "/Type": pikepdf.Name("/XObject"),
                "/Subtype": pikepdf.Name("/Image"),
                "/Width": 32,
                "/Height": 32,
                "/BitsPerComponent": 8,
                "/ColorSpace": pikepdf.Name("/DeviceGray"),
                "/Filter": pikepdf.Name("/FlateDecode"),
                "/DecodeParms": pikepdf.Dictionary(
                    Predictor=12, Colors=1, BitsPerComponent=8, Columns=32
                ),
            },
        )
        pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im_pb))
        res_pb = _scan_file(tmp_path, "pred_bomb.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_pb)


def test_eml_truncated_html_body_reports_qr_incomplete(tmp_path, no_network):
    big_html = b"<html><body>" + (b"A" * (600 * 1024)) + b"</body></html>"
    eml = (
        b"Received: from mail.example.org (mail.example.org [198.51.100.1]) by mx.example.org\r\n"
        b"Message-ID: <qr-test-1234567890@mail.example.org>\r\n"
        b"Date: Mon, 1 Jan 2024 12:00:00 +0000\r\nMIME-Version: 1.0\r\n"
        b"From: sender@example.org\r\nTo: recipient@example.org\r\nSubject: QR Test\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n" + big_html
    )
    res = _scan_file(tmp_path, "big_html.eml", eml)
    assert res.detected_type == "eml"
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res)


def test_review_r1_regressions_b1_m1_m2_m3_m4_n1_n3(tmp_path, monkeypatch, no_network):
    """Regression tests for all code-review r1 findings (B1, M1, M2, M3, M4, N1, N3)."""
    from malaz.core.eml_parser import classify_url

    # B1: malformed /Mask arrays (/Mask [/Foo], /Mask [true false]), bool /DecodeParms & /Indexed hival
    for name, modifier in (
        ("mask_name.pdf", lambda _p, im: im.__setitem__("/Mask", pikepdf.Array([pikepdf.Name("/Foo")]))),
        ("mask_bool.pdf", lambda _p, im: im.__setitem__("/Mask", pikepdf.Array([True, False]))),
        (
            "dp_bool.pdf",
            lambda _p, im: im.__setitem__("/DecodeParms", pikepdf.Dictionary(Columns=True)),
        ),
        (
            "idx_bool.pdf",
            lambda _p, im: im.__setitem__(
                "/ColorSpace",
                pikepdf.Array(
                    [
                        pikepdf.Name("/Indexed"),
                        pikepdf.Name("/DeviceRGB"),
                        True,
                        pikepdf.String(bytes(3)),
                    ]
                ),
            ),
        ),
    ):
        with pikepdf.new() as pdf:
            pdf.add_blank_page(page_size=(200, 200))
            im = _make_flate_xobj(pdf, Image.new("L", (32, 32)))
            modifier(pdf, im)
            pdf.pages[0]["/Resources"] = pikepdf.Dictionary(XObject=pikepdf.Dictionary(Im=im))
            res = _scan_file(tmp_path, name, _pdf_bytes(pdf))
        assert "QR_SCAN_INCOMPLETE" in _rule_ids(res), name

    # M1a: custom scheme with embedded phishing URL must fall through to Step 3
    res_m1a = _scan_file(
        tmp_path, "custom_scheme.png", _qr_bytes("app://open?next=https://qrco.de/phish", "PNG")
    )
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res_m1a)

    # M1b: otpauth:// must NEVER reach url_reputation_lookup
    seen_rep_calls: list[list[str]] = []

    def _spy_rep(urls):
        seen_rep_calls.append(list(urls))
        return type("R", (), {"error": "", "hits": {}})()

    monkeypatch.setattr(qr_scan, "url_reputation_lookup", _spy_rep)
    res_otp = _scan_file(
        tmp_path, "otp_only.png", _qr_bytes("otpauth://totp/App:u?secret=JBSWY3DPEHPK3PXP", "PNG")
    )
    assert "QR_CODE_DETECTED" in _rule_ids(res_otp)
    assert seen_rep_calls == []

    # M2: Data-URI dedup hash must not collapse non-ASCII %C3%A4 decoy onto real phishing QR
    b64 = base64.b64encode(_qr_bytes("https://qrco.de/dedup", "PNG")).decode("ascii")
    html_m2 = (
        f"<html><body>"
        f'<img src="data:image/png;base64,{b64}%C3%A4">'
        f'<img src="data:image/png;base64,{b64}">'
        f"</body></html>"
    ).encode()
    res_m2 = _scan_file(tmp_path, "dedup_m2.html", html_m2)
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res_m2)

    # M3: /Annots[0]/AP/N state dictionary with > 32 entries reports QR_SCAN_INCOMPLETE
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        states = {}
        for i in range(34):
            states[f"/S{i}"] = pdf.make_stream(
                b"q Q",
                {
                    "/Type": pikepdf.Name("/XObject"),
                    "/Subtype": pikepdf.Name("/Form"),
                    "/BBox": pikepdf.Array([0, 0, 10, 10]),
                },
            )
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/Widget"),
                AP=pikepdf.Dictionary(N=pikepdf.Dictionary(states)),
            )
        )
        pdf.pages[0]["/Annots"] = pikepdf.Array([annot])
        res_m3 = _scan_file(tmp_path, "ap_states_34.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_m3)

    # M4: empty username credential URL https://:MySecretPass@example.org/ must be redacted
    res_m4 = _scan_file(
        tmp_path, "empty_user.png", _qr_bytes("https://:MySecretPass@example.org/x", "PNG")
    )
    assert "QR_SUSPICIOUS_URL" in _rule_ids(res_m4)
    for ind in res_m4.all_indicators():
        assert "MySecretPass" not in ind.detail

    # N1: uppercase scheme canonicalized to lowercase in link.url
    lf = classify_url("HTTPS://QRCO.DE/A", canonicalize=True)
    assert lf is not None
    assert lf.url.startswith("https://")

    # N3: /Contents array > 128 streams reports QR_SCAN_INCOMPLETE
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(200, 200))
        empty_s = pdf.make_stream(b"")
        pdf.pages[0]["/Contents"] = pikepdf.Array([empty_s] * 130)
        res_n3 = _scan_file(tmp_path, "many_contents.pdf", _pdf_bytes(pdf))
    assert "QR_SCAN_INCOMPLETE" in _rule_ids(res_n3)
